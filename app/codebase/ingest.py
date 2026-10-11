# -*- coding: utf-8 -*-
"""代码入库（实施规格 §4.1 接入层 / §5 的 P1）。

## 输入什么、输出什么

输入一份代码（本地目录），输出一个 **codebase**：
`codebase_id` + **受控根**（把源码复制进去，见下）+ 元数据（语言分布 / 构建方式 /
`white_layer` / 文件清单）+ 一条授权记录（写 `data/codebases.json`）。

## 两个刻意的设计决定

### 1. 入库 = **复制进受控根**，而不是「就地登记一个目录」

规格 §4.1 写的是「解压/落盘到受控根」，§9 要求入库数据**可清理**。
所以把源码复制到 `data/codebases/<codebase_id>/`：

- 受控根是**我们自己的目录**，`paths.py` 的「根内」判断才有确定含义；
- 要清理时删这一个目录即可，不会动到用户的原始仓库；
- 代价是占一份磁盘 —— 用上限（文件数/单文件大小）把它框住。

### 2. 自动判定的 `white_layer` **最高只到 `partial`**

§1.2 说层级**决定结论强度上限**，而「全白＝完整源码**且能编译运行**」这句话，
**不能由「看见了 `pom.xml`」推出来** —— 那需要真的构建过一次。
首期又明确不含 `code_run`（用户决策①），所以自动流程**没有能力**验证可运行性。

因此：自动判定只会给 `partial` / `gray`；**`full` 只能由人工标注**
（`layer_override` + 记入记录），这与 §4.3「`verified` 只能来自工具背书或人工确认」是同一条纪律。
**宁可保守，也不要让一个没验证过的「全白」把结论上限抬上去。**
"""
from __future__ import annotations

import hashlib
import fnmatch
import os
import pathlib
import re
import shutil
from collections import Counter
from dataclasses import dataclass, field

from .. import config
from . import paths as P

# ---------------------------------------------------------------- 常量

#: 扩展名 → 语言。**识别**可以认识很多种；**支持**（能索引/分析）只限首批四种。
LANG_BY_EXT = {
    ".php": "php", ".phtml": "php", ".php5": "php",
    ".java": "java", ".jsp": "java", ".jspx": "java",
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rb": "ruby", ".cs": "csharp", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".hpp": "cpp", ".rs": "rust", ".kt": "kotlin",
    ".scala": "scala", ".sh": "shell", ".ps1": "powershell",
    ".sql": "sql", ".vue": "vue", ".html": "html", ".htm": "html",
}

#: 首批支持分析的语言（用户决策②：PHP → Java → Python → JS）
SUPPORTED_LANGS = ("php", "java", "python", "javascript")

#: 构建/依赖清单文件 → 它所代表的语言
BUILD_FILES = {
    "composer.json": "php", "composer.lock": "php",
    "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java",
    "settings.gradle": "java", "build.xml": "java",
    "requirements.txt": "python", "pyproject.toml": "python",
    "setup.py": "python", "Pipfile": "python", "poetry.lock": "python",
    "package.json": "javascript", "yarn.lock": "javascript",
    "package-lock.json": "javascript", "pnpm-lock.yaml": "javascript",
    "go.mod": "go", "Gemfile": "ruby", "Cargo.toml": "rust",
}

#: 索引时跳过的目录（依赖与产物 —— 既大量又无审计价值；
#: 依赖问题走 `sbom.py` 的清单分析，不是逐文件读）
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "bower_components",
    "dist", "build", "target", "out", "bin", "obj", "__pycache__",
    ".venv", "venv", "env", ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
    "coverage", ".next", ".nuxt", "site-packages",
}

#: 「只有字节码/反编译产物」的特征（→ 灰盒）
BINARY_ARTIFACT_EXT = {".class", ".jar", ".war", ".ear", ".dll", ".so", ".dylib",
                       ".pyc", ".exe", ".o", ".a", ".nupkg"}
SOURCE_EXT = {e for e, lang in LANG_BY_EXT.items()}

#: 上限（§9：被测代码可能包含巨量文件，必须框住）
MAX_FILES = 20000
MAX_FILE_BYTES = 2 * 1024 * 1024          # 单文件超过就不进索引（但不影响语言统计）
MAX_TOTAL_BYTES = 512 * 1024 * 1024       # 复制入库的总量上限

#: 入库数据落在这里（**必须在 .gitignore 里** —— 它是被测代码，不是项目资产）
CODEBASE_STORE = config.DATA_DIR / "codebases"


class IngestError(ValueError):
    """入库失败（来源不可用 / 超限 / 记录写入失败）。"""


# ---------------------------------------------------------------- 数据结构

@dataclass
class Scan:
    root: pathlib.Path
    files: list[str] = field(default_factory=list)          # 相对根的 posix 路径
    by_lang: Counter = field(default_factory=Counter)
    build_files: list[str] = field(default_factory=list)
    total_bytes: int = 0
    skipped_dirs: Counter = field(default_factory=Counter)
    oversized: list[str] = field(default_factory=list)
    binary_only_hint: int = 0          # 只有二进制产物、没有对应源码的计数
    truncated: bool = False            # 是否因 MAX_FILES 提前停止
    excluded_dirs: Counter = field(default_factory=Counter)   # 调用方**显式** exclude 掉的目录


@dataclass
class IngestResult:
    codebase_id: str
    root: pathlib.Path
    white_layer: str
    white_layer_reason: str
    file_count: int
    by_lang: dict[str, int]
    build_files: list[str]
    total_bytes: int
    skipped_dirs: dict[str, int]
    oversized: list[str]
    supported: bool                  # 是否含首批支持分析的语言
    truncated: bool = False          # 是否因 MAX_FILES 提前停止（summary 里要显示）
    dry_run: bool = False
    warnings: list[str] = field(default_factory=list)
    excluded_dirs: dict[str, int] = field(default_factory=dict)   # 调用方显式 exclude 掉的目录

    def summary(self) -> str:
        langs = "、".join(f"{k}×{v}" for k, v in
                          sorted(self.by_lang.items(), key=lambda kv: -kv[1])[:6])
        lines = [
            f"codebase_id : {self.codebase_id}",
            f"受控根      : {self.root}",
            f"white_layer : {self.white_layer} —— {self.white_layer_reason}",
            f"文件        : {self.file_count} 个 / {self.total_bytes/1024:.0f} KB",
            f"语言分布    : {langs or '（未识别到已知扩展名）'}",
            f"构建/依赖   : {', '.join(self.build_files) or '（未发现）'}",
            f"首批可分析  : {'是' if self.supported else '否（不在 PHP/Java/Python/JS 内）'}",
        ]
        if self.skipped_dirs:
            lines.append("跳过目录    : " + "、".join(
                f"{k}×{v}" for k, v in sorted(self.skipped_dirs.items())))
        if self.excluded_dirs:
            # 目录与文件都记在这里（v078 起 `exclude` 也支持 `test_*.py` 这类文件模式）
            lines.append("排除项      : " + "、".join(
                f"{k}×{v}" for k, v in sorted(self.excluded_dirs.items())))
            lines.append("              ↑ **这是调用方显式指定的**（不是自动判断）——"
                         "结论只在这份范围内成立，报告里要一起写出来。")
        if self.oversized:
            lines.append(f"超大文件    : {len(self.oversized)} 个不进索引（不影响语言统计）")
        if self.truncated:
            lines.append(f"⚠️ 文件数达到上限 {MAX_FILES}，扫描提前停止（该仓库不应全量读）")
        for w in self.warnings:
            lines.append(f"⚠️ {w}")
        return "\n".join(lines)


# ---------------------------------------------------------------- 扫描

def walk_source(root, *, exclude=(), skipped=None, excluded=None):
    """遍历受控根，产出 `(rel_dir, filename, abs_path)`。**唯一的目录遍历入口。**

    ## 为什么必须收口成一个函数（v076 实测教训）

    「走哪些目录」这条判据以前被**三层各写了一遍** `os.walk` + `SKIP_DIRS`：
    `ingest.scan_tree`（统计）/ `index.build`（建索引）/ `search._collect`（检索）。
    v076 给 `exclude` 加支持时只在 `ingest` 里加了，另两层就漏了 ——
    结果是**入库报告打印「已排除 data/」，而索引和检索里那些文件一个都没少**。
    这比不修更坏：报告在撒谎。

    → **同一个判据只留一份实现**，三层都走这里。

    `skipped` / `excluded`：传入 Counter 就顺手统计跳过的通用噪音目录 / 显式排除的目录。
    """
    root_p = pathlib.Path(root)
    if not root_p.is_dir():
        raise IngestError(f"来源不是目录：{root_p}")
    excl = _norm_exclude(exclude)
    if skipped is None:
        skipped = Counter()
    if excluded is None:
        excluded = Counter()

    for dirpath, dirnames, filenames in os.walk(root_p):
        rel_dir = pathlib.Path(dirpath).relative_to(root_p).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS:
                skipped[d] += 1
            elif _is_excluded(rel_dir, d, excl):
                excluded[(f"{rel_dir}/{d}" if rel_dir else d)] += 1
            else:
                keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):        # 排序：让三层的结果都可复现
            if _file_matches(rel_dir, fn, excl):    # 文件级排除（`test_*.py` 这类）
                excluded[(f"{rel_dir}/{fn}" if rel_dir else fn)] += 1
                continue
            yield rel_dir, fn, pathlib.Path(dirpath) / fn


def _norm_exclude(exclude) -> tuple[str, ...]:
    """把调用方给的 `exclude` 归一化成一组干净的「相对路径 / 裸目录名」。"""
    out: list[str] = []
    for raw in (exclude or ()):
        if not isinstance(raw, str):
            continue
        e = raw.strip().replace("\\", "/").strip("/")
        while e.startswith("./"):
            e = e[2:]
        if e and e not in out:
            out.append(e)
    return tuple(out)


def _has_glob(s: str) -> bool:
    """含通配符 → 这条 `exclude` 是**文件模式**（`test_*.py` / `*.min.js` / `src/gen/*.java`）。"""
    return any(ch in s for ch in "*?[")


def _file_matches(rel_dir: str, fn: str, exclude: tuple[str, ...]) -> bool:
    """文件名是否命中某条 `exclude`（**精确名**或**含通配符的模式**）。

    - 含通配符（`test_*.py` / `*.min.js` / `src/gen/*.java`）→ 按 `fnmatchcase` 匹配；
    - 不含通配符（`_classify_step.py` / `src/gen.py`）→ 按**精确文件名 / 相对路径**匹配。

    匹配同时试**文件名**与**相对路径**：`test_*.py` 能命中任意深度，
    `src/gen/*.java` 则只在那个目录下命中。

    ⚠️ 用 `fnmatchcase`（**大小写敏感**）而非 `fnmatch` —— 后者在 Windows 上
    会按平台做大小写归一，导致同一份代码在 Windows/Linux 上排出不同的文件集合，
    **回归就不可复现了**。大小写敏感是可预期的那一个。

    ⚠️ 一个条目**同时**可能匹配到同名目录与文件 —— 这是刻意的：
    这样「`data` 排掉 data/」与「`_classify_step.py` 排掉那个文件」用同一套语法就够，
    不需要调用方区分「我写的是目录还是文件」。
    """
    if not exclude:
        return False
    rel = f"{rel_dir}/{fn}" if rel_dir else fn
    for e in exclude:
        if _has_glob(e):
            if fnmatch.fnmatchcase(fn, e) or fnmatch.fnmatchcase(rel, e):
                return True
        elif fn == e or rel == e:
            return True
    return False


def _is_excluded(rel_dir: str, name: str, exclude: tuple[str, ...]) -> bool:
    """`rel_dir/name` 是否该被排除。

    两种写法都支持（**都是调用方显式给出的**，不存在自动猜测）：
      · 含 `/` → 按**相对路径前缀**匹配（`data/scripts` 命中 `data/scripts/exec/x.py`）
      · 不含 `/` → 按**目录名**匹配（`help` 命中任意深度的 `help/`）
      · ⚠️ **含通配符的条目不走这里** —— 那是文件模式，见 `_file_matches`
    """
    if not exclude:
        return False
    child = f"{rel_dir}/{name}" if rel_dir else name
    for e in exclude:
        if _has_glob(e):                    # 文件模式（`test_*.py`）不参与目录判定
            continue
        if "/" in e:
            if child == e or child.startswith(e + "/"):
                return True
        elif name == e:
            return True
    return False


def scan_tree(root, *, max_files: int = MAX_FILES, exclude=()) -> Scan:
    """遍历代码树，产出语言分布 / 构建文件 / 大小统计。**只读，不改任何东西。**

    `exclude`：**调用方显式指定**要跳过的**目录**（相对根路径前缀，或裸目录名）
    或**文件**（含通配符，如 `test_*.py` / `*.min.js` / `src/gen/*.java`）。

    为什么**不**加进 `SKIP_DIRS`：那个集合是「**任何项目都该跳**的通用噪音」
    （`.git` / `node_modules` / `__pycache__`），而 `data/`、`help/`、`uploads/`
    这类**是不是源码完全取决于项目** —— 有的项目 `data/` 就是源码目录。
    塞进全局集合会**静默隐藏真实代码**（"没命中"变得不可解释）；
    交给调用方显式给出，才会在 `IngestResult.summary()` 里被打印出来，
    让「这份结论是在什么范围内得出的」有据可查。
    """
    root_p = pathlib.Path(root)
    if not root_p.is_dir():
        raise IngestError(f"来源不是目录：{root_p}")

    s = Scan(root=root_p)
    for _rel_dir, fn, p in walk_source(root_p, exclude=exclude,
                                       skipped=s.skipped_dirs,
                                       excluded=s.excluded_dirs):
        rel = p.relative_to(root_p).as_posix()
        if len(s.files) >= max_files:
            s.truncated = True
            break
        try:
            size = p.stat().st_size
        except OSError:
            continue
        s.files.append(rel)
        s.total_bytes += size
        if size > MAX_FILE_BYTES:
            s.oversized.append(rel)

        ext = p.suffix.lower()
        lang = LANG_BY_EXT.get(ext)
        if lang:
            s.by_lang[lang] += 1
        if fn in BUILD_FILES:
            if fn not in s.build_files:
                s.build_files.append(fn)
        if ext in BINARY_ARTIFACT_EXT:
            s.binary_only_hint += 1
    return s


# ---------------------------------------------------------------- white_layer 判定

def judge_white_layer(scan: Scan, override: str | None = None,
                      override_reason: str = "") -> tuple[str, str]:
    """判定白盒层级（§1.2）。返回 `(layer, reason)`。

    **自动判定最高只给 `partial`** —— 理由见模块 docstring：
    「能编译运行」这句话需要真的构建过，而首期不含 `code_run`。
    `full` 只能通过 `override`（人工标注）给出，且必须带上理由。
    """
    if override:
        lv = override.strip().lower()
        if lv not in P.WHITE_LAYERS:
            raise IngestError(f"white_layer 只能是 {P.WHITE_LAYERS}，收到：{override!r}")
        if lv == "full" and not override_reason.strip():
            # 提高结论上限必须有据可依，否则就是「凭感觉说全白」
            raise IngestError("标 full 必须给出理由（override_reason）—— "
                              "全白意味着结论上限最高，不能无据标注")
        return lv, (f"人工标注：{override_reason.strip()}" if override_reason.strip()
                    else "人工标注")

    has_source = bool(scan.by_lang)
    if not has_source:
        if scan.binary_only_hint:
            return "gray", (f"未识别到源码，但有 {scan.binary_only_hint} 个字节码/二进制产物"
                            "（反编译产物或发布包）→ 灰盒")
        return "gray", "未识别到任何源码文件（可能只是配置/文档/资源）"

    if scan.binary_only_hint and scan.binary_only_hint > sum(scan.by_lang.values()):
        return "gray", (f"二进制/字节码产物（{scan.binary_only_hint} 个）多于源码文件"
                        f"（{sum(scan.by_lang.values())} 个）→ 更像反编译产物，按灰盒处理")

    if scan.build_files:
        return "partial", ("有源码与构建/依赖清单，但**本机未验证可编译运行** → 只能算半白"
                           "（要升 full 需人工标注或后续动态验证）")
    return "partial", ("有源码但**未发现构建/依赖清单**，跑不起来的可能性较高 → 半白"
                       "（无法据此认为可运行）")


# ---------------------------------------------------------------- 入库

_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def make_codebase_id(source, extra: str = "") -> str:
    """由来源名生成稳定 id：`<slug>-<6 位哈希>`。

    带哈希是为了**同一个名字的不同来源不会互相覆盖**（重名仓库很常见）。
    """
    name = pathlib.Path(str(source).rstrip("/\\")).name or "codebase"
    slug = _SLUG_RE.sub("-", name).strip("-.").lower()[:40] or "codebase"
    h = hashlib.sha256((str(source) + "|" + extra).encode("utf-8")).hexdigest()[:6]
    return f"{slug}-{h}"


def _copy_tree(src: pathlib.Path, dst: pathlib.Path, skip: set[str],
               exclude: tuple[str, ...] = ()) -> int:
    """把源码复制进受控根（跳过依赖/产物目录，以及调用方显式排除的目录）。"""
    n = 0
    for dirpath, dirnames, filenames in os.walk(src):
        rel_dir = pathlib.Path(dirpath).relative_to(src).as_posix()
        if rel_dir == ".":
            rel_dir = ""
        dirnames[:] = [d for d in dirnames
                       if d not in skip and not _is_excluded(rel_dir, d, exclude)]
        rel = pathlib.Path(dirpath).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for fn in filenames:
            sp = pathlib.Path(dirpath) / fn
            try:
                shutil.copy2(sp, dst / rel / fn)
                n += 1
            except OSError:
                continue
    return n


def ingest(source, *, codebase_id: str | None = None, source_kind: str = "opensource",
           note: str = "", layer_override: str | None = None,
           override_reason: str = "", dry_run: bool = False,
           register_only: bool = False, exclude=None) -> IngestResult:
    """把一份代码入库。

    - 默认**复制**进受控根 `data/codebases/<id>/`（§4.1「落盘到受控根」）；
    - `register_only=True` 时不复制，只把**来源目录本身**登记为受控根
      —— 给「仓库太大/就在本机且不打算动它」的场景留一条路，但**要自己承担
      "这个目录可能被外部改动「的后果**，所以会在 warnings 里写明；
    - `exclude`：**显式**要跳过的**目录**（相对根路径前缀如 `data/scripts`，或裸目录名如 `help`）
      或**文件模式**（含通配符，如 `test_*.py` / `*.min.js`）。
      审「带数据目录的应用」时用它 —— 否则 `data/`、`logs/`、`uploads/` 会被当源码全扫进来。
      ⚠️ 与 `SKIP_DIRS` 的分工：那个是「所有项目都该跳」，这个是「只有你知道该不该跳」。
      ⚠️ **`test_*.py` 这类**：测试文件里内嵌的代码样本会被当源码命中（实测占噪声大头），
      审计生产代码时应把它们排掉。
    - `dry_run=True` 只扫描并返回元数据，**不复制、不写记录**（先用它预览）。
    """
    src = pathlib.Path(source).expanduser()
    if not src.is_dir():
        raise IngestError(f"来源不是目录：{src}")

    kind = (source_kind or "opensource").strip().lower()
    if kind not in P.SOURCES:
        raise IngestError(f"source 只能是 {P.SOURCES}，收到：{source_kind!r}")

    scan = scan_tree(src, exclude=exclude)
    if not scan.files:
        raise IngestError(f"来源里没有可读文件：{src}"
                          + ("（检查 exclude 是不是把全部内容都排除了）" if exclude else ""))
    if scan.total_bytes > MAX_TOTAL_BYTES and not register_only:
        raise IngestError(
            f"来源总量 {scan.total_bytes/1024/1024:.0f} MB 超过上限 "
            f"{MAX_TOTAL_BYTES/1024/1024:.0f} MB —— 请先用 register_only 评估，"
            f"或先裁剪出要审计的子集")

    cid = (codebase_id or "").strip() or make_codebase_id(src, kind)
    layer, reason = judge_white_layer(scan, layer_override, override_reason)

    warnings: list[str] = []
    if register_only:
        root = src.resolve()
        warnings.append(
            "register_only：受控根就是来源目录本身，白盒只读它；"
            "若该目录会被外部改动（重新编译、切分支），读到的内容可能与入库时不一致。")
    else:
        root = (CODEBASE_STORE / cid).resolve()

    supported = any(l in SUPPORTED_LANGS for l in scan.by_lang)

    res = IngestResult(
        codebase_id=cid, root=root, white_layer=layer, white_layer_reason=reason,
        file_count=len(scan.files), by_lang=dict(scan.by_lang),
        build_files=list(scan.build_files), total_bytes=scan.total_bytes,
        skipped_dirs=dict(scan.skipped_dirs), oversized=scan.oversized[:20],
        supported=supported, truncated=scan.truncated,
        dry_run=dry_run, warnings=warnings,
        excluded_dirs=dict(scan.excluded_dirs))

    if dry_run:
        return res

    # ---- 落盘 ----
    if not register_only:
        dst = CODEBASE_STORE / cid
        if dst.exists():
            # 同一 id 重复入库：先清掉旧的，避免新旧文件混在一起（那会让索引结果无法解释）
            shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir(parents=True, exist_ok=True)
        copied = _copy_tree(src, dst, SKIP_DIRS, _norm_exclude(exclude))
        if copied == 0:
            raise IngestError(f"复制失败：{src} → {dst}（0 个文件）")
        root = dst.resolve()

    # ---- 写授权记录 ----
    items = P.load_codebases()
    items = [c for c in items if c.codebase_id != cid]
    items.append(P.Codebase(
        codebase_id=cid, root=root, source=kind, white_layer=layer,
        note=(note.strip() or "") + (f"｜{override_reason.strip()}" if override_reason else ""),
        added_at=_now(), extra={"file_count": res.file_count,
                                "by_lang": res.by_lang,
                                "build_files": res.build_files,
                                # ⭐ 排除是 **codebase 的属性**，必须落盘 ——
                                # `index.build()` 会自己再走一遍受控根，若读不到这份排除，
                                # 就会出「入库报告说排除了、索引里其实还在」的自相矛盾（v076 实测踩到）。
                                "exclude": list(_norm_exclude(exclude))}))
    P.save_codebases(items)
    return res


def _now() -> str:
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S")
