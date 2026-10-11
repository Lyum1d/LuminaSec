# -*- coding: utf-8 -*-
"""代码索引（实施规格 §4.1 检索层 / §5 的 P2~P3 前置）。

## 这一层为什么必须是**确定性**的

§4.1 把「检索（确定性、可穷举、廉价）」与「判定（概率性、需理解、昂贵）」分开，
理由是：写在同一处就**分不清「是工具漏了还是模型想错了」** —— 那是后续无法迭代的根因。

所以这里的输出必须满足：**同一份代码，任何时候跑出同样的结果**（排序 + 去重 + 稳定序列化）。
这样它才能进回归（验收 A8）。

## 抽词方式：Python 用真 AST，其余语言用词法（**并如实标注**）

规格建议 tree-sitter，但**本机未安装、`requirements.txt` 也没有它**。
按「先把主干跑通再扩」的取向，本版：

| 语言 | 方式 | 精度 |
|---|---|---|
| Python | 内置 `ast`（**真 AST**） | 函数/类/方法/import/字符串都准确 |
| PHP / Java / JS 等 | 词法（正则）+ 行号 | **近似**：能稳定定位候选，但会有漏报/误报 |

⚠️ **每条符号都带 `extractor` 字段（`ast` / `lexical`）**，下游据此知道这条信息有多可信。
这不是洁癖：§1.4 说白盒的头号陷阱是「误报被当成发现」，
而「这个词法抽出来的函数名」与「AST 确认过的函数定义」**不是同一强度的事实**。
把强度显式带下去，判定层才能给出恰当的结论强度。

## 每一条都必须带 `文件:行号`

§5 的 P3 明确要求：候选的 `文件:行号` **必须来自工具的真实输出**，禁止模型凭记忆写行号。
所以索引里**每个符号、每个字符串都记录它所在的行**，它就是下游引用的唯一依据。

## 不做的事（避免越界）

- **不做跨文件数据流**：那是判定层的活。索引只做「确定性的检索事实」；
- **不做漏洞判断**：它只提供 sink 候选的位置，**可不可达由模型论证**（§4.1）。
"""
from __future__ import annotations

import ast
import io
import json
import pathlib
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass, field

from .. import config
from . import ingest as G
from . import paths as P

#: 索引产物放在受控根**之外**（它是工具的派生数据，不是被测目标的源码；
#: 放在根内会被 `code_read` 读到、也会干扰「根内即目标代码」的语义）。
INDEX_DIR = config.DATA_DIR / "codebases_index"

SCHEMA = 2

MAX_INDEX_FILES = 20000
MAX_INDEX_FILE_BYTES = 2 * 1024 * 1024


# ---------------------------------------------------------------- 数据结构

@dataclass
class Symbol:
    name: str
    kind: str            # function | method | class | const | interface
    lang: str
    file: str            # 相对受控根的 posix 路径
    line: int
    extractor: str       # ast | lexical
    signature: str = ""

    @property
    def loc(self) -> str:
        """`文件:行号` —— 下游引用代码位置的唯一形式。"""
        return f"{self.file}:{self.line}"


@dataclass
class StrLit:
    value: str
    lang: str
    file: str
    line: int
    extractor: str

    @property
    def loc(self) -> str:
        """字符串同样要能给出 `文件:行号` —— 硬编码密钥这类发现，
        唯一的证据就是「哪一行写了这个串」。"""
        return f"{self.file}:{self.line}"


@dataclass
class Import:
    module: str
    lang: str
    file: str
    line: int
    extractor: str

    @property
    def loc(self) -> str:
        """导入也要能定位 —— 依赖分析（`sbom` / 变体分析）需要指到哪一行引入的。"""
        return f"{self.file}:{self.line}"


@dataclass
class Index:
    codebase_id: str
    root: str
    built_at: str
    file_count: int
    lang_files: dict[str, int] = field(default_factory=dict)
    extractors: dict[str, str] = field(default_factory=dict)   # lang → ast|lexical
    symbols: list[Symbol] = field(default_factory=list)
    strings: list[StrLit] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    schema: int = SCHEMA

    # ---------- 查询（全部是确定性操作，便于回归）----------
    def find_symbols(self, pattern: str, kind: str | None = None,
                     lang: str | None = None, limit: int = 200) -> list[Symbol]:
        """按名字**子串**（大小写不敏感）查符号。"""
        p = (pattern or "").lower()
        out = [s for s in self.symbols
               if (not p or p in s.name.lower())
               and (kind is None or s.kind == kind)
               and (lang is None or s.lang == lang)]
        return out[:limit]

    def find_strings(self, pattern: str, limit: int = 200) -> list[StrLit]:
        rx = _safe_regex(pattern)
        out = [s for s in self.strings if rx.search(s.value)]
        return out[:limit]

    def find_imports(self, pattern: str = "", limit: int = 200) -> list[Import]:
        p = (pattern or "").lower()
        return [i for i in self.imports if p in i.module.lower()][:limit]

    def stats(self) -> dict:
        return {"symbols": len(self.symbols), "strings": len(self.strings),
                "imports": len(self.imports), "files": self.file_count,
                "by_kind": dict(Counter(s.kind for s in self.symbols)),
                "extractors": self.extractors}


# ---------------------------------------------------------------- 工具

def _safe_regex(pat: str) -> re.Pattern:
    try:
        return re.compile(pat or "", re.I)
    except re.error:
        # 用户给的可能是普通串而非正则 —— 退回转义匹配，别让一次误输入把工具打挂
        return re.compile(re.escape(pat or ""), re.I)


def index_path(codebase_id: str) -> pathlib.Path:
    return INDEX_DIR / f"{codebase_id}.json"


# ---------------------------------------------------------------- 各语言的抽取

def _py_extract(text: str, rel: str) -> tuple[list[Symbol], list[StrLit], list[Import]]:
    """Python：用内置 `ast`（真 AST）。"""
    syms: list[Symbol] = []
    strs: list[StrLit] = []
    imps: list[Import] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        # 目标代码语法错是常态（残缺文件/不同 Python 版本）→ 记为跳过，不当作我们的失败
        return [], [], []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # 顶层函数 vs 类内方法
            kind = "function"
            for parent in ast.walk(tree):
                if isinstance(parent, ast.ClassDef) and node in ast.walk(parent):
                    kind = "method"
                    break
            syms.append(Symbol(node.name, kind, "python", rel, node.lineno, "ast",
                               _py_sig(node)))
        elif isinstance(node, ast.ClassDef):
            syms.append(Symbol(node.name, "class", "python", rel, node.lineno, "ast",
                               f"class {node.name}"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= 3:
                strs.append(StrLit(node.value[:500], "python", rel,
                                   getattr(node, "lineno", 0), "ast"))
        elif isinstance(node, ast.Import):
            for a in node.names:
                imps.append(Import(a.name, "python", rel, node.lineno, "ast"))
        elif isinstance(node, ast.ImportFrom):
            imps.append(Import(node.module or "", "python", rel, node.lineno, "ast"))
    return syms, strs, imps


def _py_sig(node) -> str:
    try:
        args = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
        return f"def {node.name}({', '.join(args)})"
    except Exception:                                        # noqa: BLE001
        return f"def {node.name}(...)"


# 词法规则：每种语言一组 (kind, 正则)。**只用行内匹配**，行号即物理行号。
_LEX_RULES: dict[str, list[tuple[str, re.Pattern]]] = {
    "php": [
        ("function", re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", re.I)),
        ("class", re.compile(r"\b(?:class|interface|trait)\s+([A-Za-z_]\w*)", re.I)),
    ],
    "java": [
        ("class", re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_]\w*)")),
        ("method", re.compile(
            r"^\s*(?:public|private|protected|static|final|synchronized|\s)*"
            r"[A-Za-z_][\w<>\[\],\s.?]*\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:throws [\w, ]+)?\{")),
    ],
    "javascript": [
        ("function", re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(")),
        ("function", re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                                r"(?:async\s*)?(?:function\b|\()")),
        ("class", re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")),
        ("method", re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{")),
    ],
    "typescript": [
        ("function", re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(")),
        ("class", re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")),
        ("interface", re.compile(r"\binterface\s+([A-Za-z_$][\w$]*)")),
    ],
}

_STR_RULES: dict[str, re.Pattern] = {
    # 匹配一行里的引号串（含转义），值在后处理时去掉引号
    "*": re.compile(r"""(['"])((?:\\.|(?!\1)[^\\\r\n]){3,300})\1"""),
}

_IMPORT_RULES: dict[str, re.Pattern] = {
    "php": re.compile(r"\b(?:require|require_once|include|include_once)\s*\(?\s*"
                      r"['\"]([^'\"]+)['\"]", re.I),
    "java": re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)"),
    "javascript": re.compile(r"(?:\bfrom\s*['\"]([^'\"]+)['\"])"
                             r"|(?:require\s*\(\s*['\"]([^'\"]+)['\"]\s*\))"),
    "typescript": re.compile(r"\bfrom\s*['\"]([^'\"]+)['\"]"),
}

# 语言 → 注释前缀（用于**跳掉注释行**，减少词法误报）
_COMMENT = {
    "php": ("//", "#", "*", "/*"),
    "java": ("//", "*", "/*"),
    "javascript": ("//", "*", "/*"),
    "typescript": ("//", "*", "/*"),
}


def _lex_extract(text: str, rel: str, lang: str) -> tuple[list[Symbol], list[StrLit], list[Import]]:
    """PHP/Java/JS 等：词法抽取（**近似**，如实标 `lexical`）。"""
    syms: list[Symbol] = []
    strs: list[StrLit] = []
    imps: list[Import] = []
    comment_marks = _COMMENT.get(lang, ())
    rules = _LEX_RULES.get(lang, [])
    srx = _STR_RULES["*"]
    irx = _IMPORT_RULES.get(lang)

    for i, line in enumerate(io.StringIO(text).read().splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(comment_marks):
            continue                      # 注释/空行不产出符号（词法最容易在这里误报）
        for kind, rx in rules:
            for m in rx.finditer(line):
                name = m.group(1)
                if name in ("if", "for", "while", "switch", "catch", "return",
                            "function", "class", "new", "else", "do", "try"):
                    continue              # 关键字不是符号
                syms.append(Symbol(name, kind, lang, rel, i, "lexical",
                                   m.group(0).strip()[:120]))
        for m in srx.finditer(line):
            v = m.group(2)
            if len(v) >= 3:
                strs.append(StrLit(v[:500], lang, rel, i, "lexical"))
        if irx:
            for m in irx.finditer(line):
                mod = next((g for g in m.groups() if g), "")
                if mod:
                    imps.append(Import(mod, lang, rel, i, "lexical"))
    return syms, strs, imps


def extract(text: str, rel: str, lang: str):
    if lang == "python":
        return _py_extract(text, rel)
    return _lex_extract(text, rel, lang)


# ---------------------------------------------------------------- 构建

def build(codebase_id: str, *, persist: bool = True, max_files: int = MAX_INDEX_FILES) -> Index:
    """为已入库的 codebase 建索引。**只读受控根**（走 `paths.guard` 的同一套校验）。"""
    cb = P.get_codebase(codebase_id)
    if cb is None:
        raise P.CodebaseNotFound(
            f"codebase「{codebase_id}」未入库 —— 请先 code_ingest。")

    root = pathlib.Path(cb.root)
    if not root.is_dir():
        raise P.CodebaseNotFound(f"受控根不存在：{root}")

    idx = Index(codebase_id=codebase_id, root=str(root),
                built_at=time.strftime("%Y-%m-%d %H:%M:%S"), file_count=0)

    from collections import Counter as _C
    # ⚠️ 排除是 **codebase 的属性**（`ingest` 时记进 extra），不是一次性参数 ——
    # 不读它就会「入库报告说已排除、索引里其实还在」，那比不修更坏（v076 实测踩到）。
    # 遍历本身走 `ingest.walk_source`：**三层共用同一份「走哪些目录」的判据**
    # （以前 ingest/index/search 各写一遍 os.walk，加 exclude 时漏了两层）。
    for _rel_dir, fn, fp in G.walk_source(root, exclude=cb.extra.get("exclude") or ()):
        if idx.file_count >= max_files:
            idx.skipped.append(f"（达到文件数上限 {max_files}，其余未索引）")
            break
        lang = G.LANG_BY_EXT.get(pathlib.Path(fn).suffix.lower())
        if lang not in G.SUPPORTED_LANGS:
            continue                       # 首批只分析四种语言（决策②）
        try:
            if fp.stat().st_size > MAX_INDEX_FILE_BYTES:
                idx.skipped.append(f"{fp.relative_to(root).as_posix()}（超过单文件上限）")
                continue
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = fp.relative_to(root).as_posix()
        idx.file_count += 1
        idx.lang_files[lang] = idx.lang_files.get(lang, 0) + 1
        idx.extractors[lang] = "ast" if lang == "python" else "lexical"
        s, st, im = extract(text, rel, lang)
        idx.symbols.extend(s)
        idx.strings.extend(st)
        idx.imports.extend(im)

    # ---- 确定性：排序 + 去重（同一份代码任何时候结果相同，才能进回归）----
    idx.symbols.sort(key=lambda x: (x.file, x.line, x.kind, x.name))
    idx.symbols = _dedup(idx.symbols)
    idx.strings.sort(key=lambda x: (x.file, x.line, x.value))
    idx.strings = _dedup(idx.strings)
    idx.imports.sort(key=lambda x: (x.file, x.line, x.module))
    idx.imports = _dedup(idx.imports)

    if persist:
        save(idx)
    return idx


def _dedup(items: list):
    seen, out = set(), []
    for it in items:
        key = tuple(sorted(asdict(it).items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def save(idx: Index) -> pathlib.Path:
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    p = index_path(idx.codebase_id)
    payload = asdict(idx)
    # 原子写 + **不备份**：索引可能很大，且能随时重建（备份它没有意义）
    from .. import config_io
    res = config_io.write_json_atomic(p, payload, backup_first=False)
    if not res.get("ok"):
        raise OSError(f"写入索引失败：{res.get('error')}")
    return p


def load(codebase_id: str) -> Index | None:
    """读回索引；不存在/格式不符返回 `None`（调用方据此提示「先跑 code_index"）。"""
    p = index_path(codebase_id)
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:                                        # noqa: BLE001
        return None
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
        return None                       # schema 变了 → 当作没有，让调用方重建
    try:
        return Index(
            codebase_id=raw["codebase_id"], root=raw.get("root", ""),
            built_at=raw.get("built_at", ""), file_count=raw.get("file_count", 0),
            lang_files=raw.get("lang_files", {}), extractors=raw.get("extractors", {}),
            symbols=[Symbol(**s) for s in raw.get("symbols", [])],
            strings=[StrLit(**s) for s in raw.get("strings", [])],
            imports=[Import(**s) for s in raw.get("imports", [])],
            skipped=raw.get("skipped", []), schema=raw.get("schema", SCHEMA))
    except Exception:                                        # noqa: BLE001
        return None


def is_stale(idx: Index) -> str:
    """索引是否可能过期。返回空串表示「看起来是最新的」。

    ⚠️ 只做**廉价**判断（受控根是否存在）。真正的「代码变没变」无法不重扫就确定 ——
    所以这里的定位是：给下游一句可复述的提示，而不是假装知道答案。
    """
    if not pathlib.Path(idx.root).is_dir():
        return f"受控根已不存在：{idx.root}"
    return ""
