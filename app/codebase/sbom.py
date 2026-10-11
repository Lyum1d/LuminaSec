# -*- coding: utf-8 -*-
"""依赖清单解析（实施规格 §4.1 检索层 / §7.1 的 `sbom.py`）。

## 为什么白盒要单独看依赖

1. **多数真实漏洞在依赖里**：`dependency-confusion`、投毒、以及「引用了已知有洞的版本」；
2. **变体分析要用它**：读某个 CVE 的修复 commit → 判断本项目引入的版本是否受影响；
3. 它比「逐文件读代码」廉价得多：一个清单文件就能覆盖成千上万行第三方代码。

## 四个刻意的设计决定

**① 只用内置模块解析**（`json` / `xml.etree` / `tomllib`）—— 不为解析清单引入新依赖。
`tomllib` 是 3.11+ 内置，`pom.xml` 用 ElementTree 足够。

**② 「约束」与「实际版本」必须分开**

`composer.json` 里写 `"^6.0"`、Maven 里写 `${spring.version}`、npm 里写 `"latest"` ——
这些**都不是实际装入的版本**。而判断「是否受某 CVE 影响」用的必须是**实际版本**。
所以：只有 **lock 文件**（`composer.lock` / `package-lock.json`）解析出来的才标 `resolved=True`；
其余标 `False`，并在结果里保留原样字符串。**混为一谈会产生「看起来有结论、其实没依据」的判断。**

**③ 解析失败/未支持必须记录，不能静默跳过**

`yarn.lock` / `pnpm-lock.yaml` / `Gemfile.lock` 等暂不支持 → 记进 `unparsed`；
清单里某一条解析不出来 → 记进 `parse_errors`。
**"看起来跑了、其实没查「是本项目最忌讳的形态**（同 `scope.py` 的列表文件校验、`ingest` 的编码问题）。

**④ `risky()` 给的是线索，不是结论**

`*` 版本、明文 `http://` 源、直接从 git/tarball 引入、"名字像某知名包" ——
这些都是**值得人工确认的信号**，不是漏洞。函数名用 `clues` 而不是 `vulnerabilities`
就是为了不让人（和模型）把线索当结论（§1.4）。
"""
from __future__ import annotations

import json
import pathlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from . import ingest as G
from . import paths as P

try:                                                        # 3.11+ 内置
    import tomllib
except ModuleNotFoundError:                                 # pragma: no cover
    tomllib = None                                          # type: ignore[assignment]

#: 一个清单文件最多解析多少条依赖（防病态文件）
MAX_DEPS = 5000

#: 未支持的清单（**要显式记下来**，不能当作「没有依赖」）
UNSUPPORTED = ("yarn.lock", "pnpm-lock.yaml", "Gemfile.lock", "go.sum",
               "Pipfile.lock", "poetry.lock", "packages.config", "gradle.lockfile")


@dataclass
class Dep:
    name: str
    version: str
    ecosystem: str            # composer | maven | pip | npm
    scope: str = "runtime"    # runtime | dev | test | optional | parent | plugin
    source_file: str = ""
    line: int = 0             # 能定位就填（文本类清单行号可靠；JSON/XML 类为 0）
    resolved: bool = False    # 是否来自 lock 文件（= 实际装入的版本）
    clues: list[str] = field(default_factory=list)

    @property
    def loc(self) -> str:
        return f"{self.source_file}:{self.line}" if self.line else self.source_file

    def render(self) -> str:
        v = self.version or "(未声明版本)"
        r = "（实际版本）" if self.resolved else "（版本约束，非实际装入版本）"
        c = ("；线索：" + "、".join(self.clues)) if self.clues else ""
        return f"{self.ecosystem}:{self.name} {v}{r} [{self.scope}] @ {self.loc}{c}"


@dataclass
class Sbom:
    codebase_id: str
    deps: list[Dep] = field(default_factory=list)
    files: list[str] = field(default_factory=list)        # 找到并解析的清单文件
    unparsed: list[str] = field(default_factory=list)     # 找到但不支持的
    parse_errors: list[str] = field(default_factory=list)

    def by_ecosystem(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for d in self.deps:
            out[d.ecosystem] = out.get(d.ecosystem, 0) + 1
        return out

    def find(self, name: str) -> list[Dep]:
        n = (name or "").lower()
        return [d for d in self.deps if n in d.name.lower()]

    def clues(self) -> list[Dep]:
        """带**线索**的依赖（不是漏洞 —— 见模块 docstring 第 ④ 条）。"""
        return [d for d in self.deps if d.clues]

    def stats(self) -> dict:
        return {"deps": len(self.deps), "files": len(self.files),
                "unparsed": len(self.unparsed), "parse_errors": len(self.parse_errors),
                "by_ecosystem": self.by_ecosystem(),
                "resolved": sum(1 for d in self.deps if d.resolved),
                "with_clues": len(self.clues())}


# ---------------------------------------------------------------- 线索判定（不是漏洞）

#: 常见顶层包名 —— 用来提示「可能是仿冒名」（编辑距离近但名字不同）
_COMMON = {
    "npm": ["lodash", "express", "axios", "react", "request", "moment", "jquery",
            "webpack", "debug", "chalk", "commander", "minimist", "validator"],
    "pip": ["requests", "urllib3", "django", "flask", "numpy", "pandas", "pyyaml",
            "cryptography", "jinja2", "pillow", "sqlalchemy"],
    "composer": ["monolog", "guzzle", "symfony", "twig", "doctrine", "phpunit"],
    "maven": ["commons-io", "jackson-databind", "fastjson", "log4j-core",
              "spring-core", "struts2-core", "shiro-core"],
}


def _edit_distance_le1(a: str, b: str) -> bool:
    """a 与 b 的编辑距离是否 ≤1 —— **相邻字母调换也算 1**（Damerau 口径）。

    ⚠️ 为什么必须算调换：**相邻调换是仿冒包名最常见的形态**
    （`lodash`→`lodahs`、`requests`→`reqeusts`），而标准 Levenshtein 会把它算成 2，
    于是这类仿冒**一条都抓不到** —— 本版第一稿就漏了这两个例子，是测试逼出来的。
    """
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diff) == 1:
            return True                                  # 单字符替换
        # 恰好两处不同、且相邻且互为调换 → 记 1
        return (len(diff) == 2 and diff[1] - diff[0] == 1
                and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    diff = 0
    while i < len(s) and j < len(l):
        if s[i] != l[j]:
            diff += 1
            if diff > 1:
                return False
            j += 1
            continue
        i += 1
        j += 1
    return True


def _clues_for(name: str, version: str, ecosystem: str, source: str) -> list[str]:
    out: list[str] = []
    v = (version or "").strip()

    if not v or v in ("*", "latest", "x", "X"):
        out.append("未声明版本约束 —— 装到什么完全取决于当时 registry 的状态")
    if re.search(r"^https?://", v, re.I) or re.search(r"^(git|git\+ssh|git\+https?|file):", v, re.I):
        out.append("直接从 URL/git 引入（绕过 registry 的版本与完整性校验）")
    if re.search(r"^http://", v, re.I):
        out.append("**明文 http** 源（可被中间人替换）")

    short = name.split("/")[-1].lower()
    for known in _COMMON.get(ecosystem, []):
        if short != known and _edit_distance_le1(short, known):
            out.append(f"名字与常见包 `{known}` 高度相似（可能是仿冒名，**需人工确认**）")
            break
    return out


# ---------------------------------------------------------------- 各生态解析

def _dep(name: str, version: str, eco: str, *, scope="runtime", file="",
         line=0, resolved=False) -> Dep:
    return Dep(name=name, version=str(version or "").strip(), ecosystem=eco,
               scope=scope, source_file=file, line=line, resolved=resolved,
               clues=_clues_for(name, version, eco, file))


def _p_composer_json(text: str, rel: str) -> list[Dep]:
    data = json.loads(text)
    out: list[Dep] = []
    for key, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, ver in (data.get(key) or {}).items():
            if name.lower() == "php" or name.startswith("ext-"):
                continue                                     # 平台约束，不是依赖包
            out.append(_dep(name, ver, "composer", scope=scope, file=rel))
    return out


def _p_composer_lock(text: str, rel: str) -> list[Dep]:
    data = json.loads(text)
    out: list[Dep] = []
    for key, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for item in (data.get(key) or []):
            if isinstance(item, dict) and item.get("name"):
                out.append(_dep(item["name"], item.get("version", ""), "composer",
                                scope=scope, file=rel, resolved=True))
    return out


def _p_pom_xml(text: str, rel: str) -> list[Dep]:
    root = ET.fromstring(text)

    def strip(tag: str) -> str:
        return tag.split("}")[-1]

    props: dict[str, str] = {}
    for el in root.iter():
        if strip(el.tag) == "properties":
            for p in el:
                props[strip(p.tag)] = (p.text or "").strip()

    def resolve(v: str) -> tuple[str, bool]:
        """解析 `${prop}`；解析不出来就**明确标出**（不能当成版本号用）。"""
        if not v or "${" not in v:
            return v, True
        m = re.fullmatch(r"\$\{([^}]+)\}", v.strip())
        if m and m.group(1) in props:
            return props[m.group(1)], True
        return v, False

    out: list[Dep] = []
    for el in root.iter():
        if strip(el.tag) != "dependency":
            continue
        g = a = v = ""
        for c in el:
            tag = strip(c.tag)
            if tag == "groupId":
                g = (c.text or "").strip()
            elif tag == "artifactId":
                a = (c.text or "").strip()
            elif tag == "version":
                v = (c.text or "").strip()
            elif tag == "scope":
                sc = (c.text or "").strip()
        if not a:
            continue
        name = f"{g}:{a}" if g else a
        ver, ok = resolve(v)
        d = _dep(name, ver, "maven", file=rel)
        if not ok:
            d.clues.append("版本是**未解析的属性占位符** —— 实际版本要看父 POM 或构建时的属性")
        out.append(d)
    # 父 POM 也记一条：它决定继承来的依赖版本
    for el in root:
        if strip(el.tag) == "parent":
            g = a = v = ""
            for c in el:
                tag = strip(c.tag)
                if tag == "groupId":
                    g = (c.text or "").strip()
                elif tag == "artifactId":
                    a = (c.text or "").strip()
                elif tag == "version":
                    v = (c.text or "").strip()
            if a:
                out.append(_dep(f"{g}:{a}" if g else a, v, "maven",
                                scope="parent", file=rel))
    return out


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\]\s*)?"
                       r"(===|==|>=|<=|~=|!=|>|<)?\s*([^\s;#]*)")


def _p_requirements(text: str, rel: str) -> list[Dep]:
    out: list[Dep] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):                 # -r/-e/--index-url 等选项跳过
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(2) or "", m.group(3) or ""
        version = f"{op}{ver}" if op else ver
        d = _dep(name, version, "pip", file=rel, line=i)
        if op == "==" and ver:
            d.resolved = True                                # 固定版本 ≈ 实际装入
        out.append(d)
    return out


def _p_package_json(text: str, rel: str) -> list[Dep]:
    data = json.loads(text)
    out: list[Dep] = []
    for key, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                       ("peerDependencies", "peer"), ("optionalDependencies", "optional")):
        for name, ver in (data.get(key) or {}).items():
            out.append(_dep(name, ver, "npm", scope=scope, file=rel))
    return out


def _p_package_lock_json(text: str, rel: str) -> list[Dep]:
    data = json.loads(text)
    out: list[Dep] = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):                               # lock v2/v3
        for path, info in pkgs.items():
            if not path or not isinstance(info, dict) or not info.get("version"):
                continue
            name = info.get("name") or path.split("node_modules/")[-1]
            if not name:
                continue
            scope = "dev" if info.get("dev") else "runtime"
            out.append(_dep(name, info["version"], "npm", scope=scope,
                            file=rel, resolved=True))
    else:                                                    # lock v1
        for name, info in (data.get("dependencies") or {}).items():
            if isinstance(info, dict) and info.get("version"):
                out.append(_dep(name, info["version"], "npm",
                                scope="dev" if info.get("dev") else "runtime",
                                file=rel, resolved=True))
    return out


def _p_pyproject_toml(text: str, rel: str) -> list[Dep]:
    if tomllib is None:
        raise RuntimeError("需要 Python 3.11+ 的 tomllib")
    data = tomllib.loads(text)
    out: list[Dep] = []
    proj = data.get("project") or {}
    for spec in (proj.get("dependencies") or []):
        m = _REQ_LINE.match(str(spec))
        if m:
            name, op, ver = m.group(1), m.group(2) or "", m.group(3) or ""
            out.append(_dep(name, f"{op}{ver}" if op else ver, "pip", file=rel))
    for _group, specs in (proj.get("optional-dependencies") or {}).items():
        for spec in (specs or []):
            m = _REQ_LINE.match(str(spec))
            if m:
                name, op, ver = m.group(1), m.group(2) or "", m.group(3) or ""
                out.append(_dep(name, f"{op}{ver}" if op else ver, "pip",
                                scope="optional", file=rel))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for key, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev")):
        for name, spec in (poetry.get(key) or {}).items():
            if name.lower() == "python":
                continue
            ver = spec if isinstance(spec, str) else (
                spec.get("version", "") if isinstance(spec, dict) else "")
            out.append(_dep(name, ver, "pip", scope=scope, file=rel))
    return out


def _p_pipfile_toml(text: str, rel: str) -> list[Dep]:
    if tomllib is None:
        raise RuntimeError("需要 Python 3.11+ 的 tomllib")
    data = tomllib.loads(text)
    out: list[Dep] = []
    for key, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, spec in (data.get(key) or {}).items():
            ver = spec if isinstance(spec, str) else (
                spec.get("version", "") if isinstance(spec, dict) else "")
            out.append(_dep(name, ver, "pip", scope=scope, file=rel))
    return out


#: 文件名 → 解析器（**顺序即优先级**：lock 在后、但会被去重）
PARSERS = {
    "composer.json": _p_composer_json,
    "composer.lock": _p_composer_lock,
    "pom.xml": _p_pom_xml,
    "requirements.txt": _p_requirements,
    "package.json": _p_package_json,
    "package-lock.json": _p_package_lock_json,
    "pyproject.toml": _p_pyproject_toml,
    "Pipfile": _p_pipfile_toml,
}


# ---------------------------------------------------------------- 构建

def _is_requirements(name: str) -> bool:
    return bool(re.fullmatch(r"requirements[\w.-]*\.txt", name, re.I))


def build(codebase_id: str) -> Sbom:
    """扫描已入库 codebase 的依赖清单。**只读受控根**，不联网。"""
    cb = P.get_codebase(codebase_id)
    if cb is None:
        raise P.CodebaseNotFound(f"codebase「{codebase_id}」未入库 —— 请先 code_ingest。")
    root = pathlib.Path(cb.root)
    if not root.is_dir():
        raise P.CodebaseNotFound(f"受控根不存在：{root}")

    sb = Sbom(codebase_id=codebase_id)
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in G.SKIP_DIRS]
        for fn in sorted(filenames):
            rel = (pathlib.Path(dirpath) / fn).relative_to(root).as_posix()
            parser = PARSERS.get(fn)
            if parser is None and _is_requirements(fn):
                parser = _p_requirements
            if parser is None:
                if fn in UNSUPPORTED:
                    sb.unparsed.append(rel)                  # 显式记下「没查」
                continue
            fp = pathlib.Path(dirpath) / fn
            try:
                if fp.stat().st_size > 4 * 1024 * 1024:
                    sb.parse_errors.append(f"{rel}：文件过大（>4MB），未解析")
                    continue
                text = fp.read_text(encoding="utf-8", errors="replace")
                deps = parser(text, rel)
            except Exception as e:                            # noqa: BLE001
                # **不能静默跳过** —— 否则就是「看起来查了依赖、其实这个清单没看」
                sb.parse_errors.append(f"{rel}：{type(e).__name__}: {str(e)[:80]}")
                continue
            sb.files.append(rel)
            sb.deps.extend(deps[:MAX_DEPS])

    # ---- 合并：同一 (生态, 名字) 只留一条，**优先保留 resolved 的那条** ----
    best: dict[tuple[str, str], Dep] = {}
    for d in sb.deps:
        key = (d.ecosystem, d.name.lower())
        cur = best.get(key)
        if cur is None or (d.resolved and not cur.resolved):
            best[key] = d
        elif d.resolved == cur.resolved and d.clues and not cur.clues:
            best[key] = d
    sb.deps = sorted(best.values(), key=lambda d: (d.ecosystem, d.name.lower()))
    sb.files.sort()
    sb.unparsed.sort()
    return sb
