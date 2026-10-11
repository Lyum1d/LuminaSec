# -*- coding: utf-8 -*-
"""代码检索（实施规格 §4.1 检索层 / §5 的 P3「定位候选」）。

## 输出的是**候选**，不是漏洞

§1.4 说白盒头号陷阱是「误报被当成发现」，而静态匹配**天然判不了可达性与净化**。
所以每条命中都**带着规则的 `why`（为什么危险）与 `hint`（还要看什么）**一起返回 ——
让模型拿到的是「这里有个危险调用点，接下来该验证什么」，
而不是「这里有个漏洞」。

## 三条硬要求

1. **每条命中都带 `文件:行号` + 该行原文** —— §5 的 P3 明确要求行号必须来自工具输出，
   禁止模型凭记忆写；原文则让它能直接引用而不用再猜；
2. **读代码一律走 `paths.guard`** —— 这是 v058 那条受控根校验的唯一消费者，
   也是本能力里唯一「做错就泄露本机文件」的环节。**不允许任何绕过**；
3. **代码内容是不可信数据** —— §9：被测代码里可以写任何文字（包括「忽略之前的指令」）。
   这些内容会进上下文，因此**只当数据用，绝不作为指令执行**。

## 与 `index.py` 的分工

`index.py` 记录**定义**（函数/类/字符串在哪），`search.py` 找**用法**（在哪调用了危险函数）。
两者都确定性、都可回归；判定仍全部交给模型（§4.1 的分层意图）。
"""
from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass, field

from . import index as I
from . import ingest as G
from . import paths as P
from . import sink_rules as S
from . import taint as Taint

#: 检索返回条数上限（返回太多既稀释注意力、也吃上下文）
MAX_HITS = 300
#: 单次检索最多扫多少行（防止在大仓库上做无意义的全量扫描）
MAX_SCAN_LINES = 400_000


@dataclass
class Hit:
    file: str            # 相对受控根的 posix 路径
    line: int
    text: str            # 该行原文（**不可信数据**，见模块 docstring 第 3 条）
    lang: str
    kind: str            # 规则类别；正则检索时为 "regex"
    rule_id: str = ""
    why: str = ""
    hint: str = ""
    scope: str = ""      # 所在函数/类（`名字@文件:行号`）—— 判可达性的起点
    extractor: str = ""  # ast | lexical —— 这条命中的抽取精度

    @property
    def loc(self) -> str:
        return f"{self.file}:{self.line}"

    def render(self) -> str:
        """给模型看的单行摘要（紧凑，省上下文）。"""
        head = f"{self.loc}  [{self.kind}] {self.text.strip()[:160]}"
        if self.scope:
            head += f"\n    所在：{self.scope}"
        if self.why:
            head += f"\n    为什么危险：{self.why}"
        if self.hint:
            head += f"\n    还需确认：{self.hint}"
        return head


@dataclass
class _Target:
    root: pathlib.Path
    files: list[pathlib.Path] = field(default_factory=list)
    lang_of: dict[str, str] = field(default_factory=dict)


def _collect(codebase_id: str, langs: set[str] | None) -> _Target:
    """收集待检索的文件。**只读**，且路径全部来自受控根的遍历结果（不经模型输入）。"""
    cb = P.get_codebase(codebase_id)
    if cb is None:
        raise P.CodebaseNotFound(f"codebase「{codebase_id}」未入库 —— 请先 code_ingest。")
    root = pathlib.Path(cb.root)
    if not root.is_dir():
        raise P.CodebaseNotFound(f"受控根不存在：{root}")

    t = _Target(root=root)
    # 遍历走 `ingest.walk_source`（**三层共用同一份判据**）——
    # 排除同样是 codebase 的属性；以前这里自己又写了一遍 os.walk，
    # 于是 `exclude` 漏了这一层（v076 实测：报告说排除了、检索里一个都没少）。
    for _rel_dir, fn, fp in G.walk_source(root, exclude=cb.extra.get("exclude") or ()):
        lang = G.LANG_BY_EXT.get(pathlib.Path(fn).suffix.lower())
        if lang not in G.SUPPORTED_LANGS:
            continue
        if langs and lang not in langs:
            continue
        try:
            if fp.stat().st_size > I.MAX_INDEX_FILE_BYTES:
                continue
        except OSError:
            continue
        rel = fp.relative_to(root).as_posix()
        t.files.append(fp)
        t.lang_of[rel] = lang
    return t


def _enclosing(idx: I.Index | None, rel: str, line: int) -> str:
    """命中行所属的函数/类（取**行号 ≤ 命中行**里最大的那个符号）。

    这是「判可达性」的起点：模型拿到一个 sink，第一步就是找到它所在的函数、
    再看这个函数是谁调的。索引里已经有全部符号的行号，所以这一步是纯计算。
    """
    if idx is None:
        return ""
    cands = [s for s in idx.symbols if s.file == rel and s.line <= line]
    if not cands:
        return ""
    best = max(cands, key=lambda s: s.line)
    return f"{best.kind} {best.name} @ {best.loc}"


def _scan(codebase_id: str, matcher, *, langs=None, limit=MAX_HITS,
          want_scope: bool = True) -> list[Hit]:
    """共用扫描：按行喂给 `matcher(rel, lang, lineno, text, scope) -> Hit | None`。"""
    t = _collect(codebase_id, langs)
    idx = I.load(codebase_id) if want_scope else None
    hits: list[Hit] = []
    scanned = 0
    for fp in t.files:
        rel = fp.relative_to(t.root).as_posix()
        lang = t.lang_of[rel]
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            scanned += 1
            if scanned > MAX_SCAN_LINES:
                return hits
            h = matcher(rel, lang, lineno, line, idx)
            if h is not None:
                hits.append(h)
                if len(hits) >= limit:
                    return hits
    return hits


# ---------------------------------------------------------------- sink 检索

#: 跨行找参数时最多往后看多少行（够覆盖格式化后的多行调用，又不会吃到别处的代码）
#:
#: ⚠️ **v093 实测：不要顺手放大这个窗口。** 配平之后放大到 20 行在 Benchmark 上
#: **一个指标都不变**（`F1w20` = `F1w40` = `F1w80`），但窗口越大、
#: 越可能把**无关代码里的污点变量**算进这次调用的参数区 —— 属于"没买到东西就不要买"。
_CALL_LOOKAHEAD = 6


def _name_in(name: str, text: str) -> bool:
    """`text` 里是否出现**变量 `name`**（容忍 PHP 的 `$` 前缀）。

    `name` 来自污点集（已归一、不带 `$`），而源码里 PHP 变量带 `$` ——
    所以两边都按「可选 `$` + 名字 + 非标识符边界」来比。
    """
    return bool(re.search(rf"\$?{re.escape(name)}(?![A-Za-z0-9_])", text))


def _arg_region(lines: list[str], lineno: int, col: int,
                max_lines: int = _CALL_LOOKAHEAD) -> str | None:
    """从「第 `lineno` 行的第 `col` 列」起，**按括号深度配平**取第一个括号区的内容。

    ## 为什么不用正则（v093 修的正确性缺陷）

    原实现是 `re.compile(r"\\(([^()]*(?:\\([^()]*\\)[^()]*)*)\\)")` —— 它只能配**一层**嵌套。
    遇到**嵌套 lambda / 匿名类**的参数区（Benchmark 的 JdbcTemplate 就是）：

        JDBCtemplate.query(
            sql,
            new org.springframework.jdbc.core.RowMapper<String>() { @Override … });

    正则配不平 → `search()` **退化成匹配到后面那个碰巧闭合的 `()`** →
    `group(1)` 是**空字符串** → 判「括号里没有污点变量」→ **漏报**。
    实测（OWASP BenchmarkJava v1.2）：`BenchmarkTest00431`、`BenchmarkTest00038` 卡在这里。

    ⚠️ 更坏的是那个退化**不只是漏报**：它匹配到的是**别处的括号**，
    若那里恰好出现一个污点变量，就会产出**张冠李戴的命中**。配平后不可能再错配。

    ⚠️ **窗口内配不平就返回 `None`（保守判否）**，绝不退化成"匹配下一对括号"。

    ## 增量（诚实记录）

    单独上这一条，Benchmark 上**指标一个都不变**（918 → 918 条命中）——
    **它修的是正确性，不是召回**。与 v072 的「容器 `add` 通道」（增量 0）同族。
    """
    if lineno < 1 or lineno > len(lines):
        return None
    text = "\n".join([lines[lineno - 1][col:]] + lines[lineno:lineno + max_lines])
    start = text.find("(")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    return None                                              # 窗口内没配平 → 判否


def _tainted_in_args(lines: list[str], lineno: int, col: int,
                     tainted: set[str]) -> bool:
    """从「第 `lineno` 行的第 `col` 列」起，**这次调用的括号区**内是否出现污点变量。

    `col` 由 `call_pattern` 的匹配起点给出 —— 因此判的**一定是这次调用**的括号，
    不会把同一行里无关调用的参数算进来。

    ⚠️ **必须支持跨行**（v069 实测）：Benchmark 里大量写法是

        connection.prepareStatement(
            sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);

    —— 调用名和参数**不在同一行**。只在单行里找括号会直接判否，
    实测 247 个漏报的 sqli 用例里 20 个属于这一类（占「本该命中」的全部）。

    ⚠️ **v093 起括号区按深度配平**（见 `_arg_region`）：嵌套 lambda 也判得了，
    且配不平就判否，不再"退化成匹配后面那对括号"。
    """
    args = _arg_region(lines, lineno, col)
    if args is None:
        return False
    return any(_name_in(v, args) for v in tainted)


def search_sinks(codebase_id: str, *, kinds=None, langs=None,
                 limit: int = MAX_HITS) -> list[Hit]:
    """按危险 sink 规则库检索。`kinds`/`langs` 可缩小范围（如只看 rce）。

    ## 三层匹配（v071）—— 一行可以产出**多条**命中

    1. **行级证据**：规则自己的 `pattern` 命中 —— 「这一行本身就能看出危险」
       （如 `.executeQuery("... " + param)`）。`extractor` 为 `lexical`/`ast`；
    2. **跨行证据**：规则的 `call_pattern` 命中**且**该次调用的括号内出现
       **同一函数内的污点变量**（由 `taint.py` 推出）—— 「危险值在上一行拼好」。
       `extractor` 为 `taint`/`taint(lexical)`，`rule_id` 带 `@taint`；
    3. **执行器变量证据**（v071 新增）：规则的 `runner_pattern` 命中**且**捕获到的
       调用者确实持有命令执行器（`Runtime.getRuntime()` / `new ProcessBuilder(...)`）
       —— 「执行器在别处取得」。`extractor` 为 `runner`，`rule_id` 带 `@runner`。

    ②③ 是**正交**的：② 管「**参数**是变量」，③ 管「**调用者**是变量」。
    实测（OWASP BenchmarkJava）② 缺了会漏掉全部 sqli/pathtraver 主力形态，
    ③ 缺了会漏掉 cmdi 的 **27/35**。

    ## 为什么不是「命中一个就 return」（v069 第一版的错误）

    第一版写成 `if pattern命中: return` / `elif taint命中: return`，**整层成了死代码**：
    两条平行规则的 `pattern` 相同 → 要么行级命中先 return，要么行级不命中时
    「本行根本没有这个调用」，taint 分支判「括号里」无从下手。

    现在改成**三层各跑各的、都收集**：同一行可能同时给出多条线索，
    它们是**不同强度/不同性质**的证据，都该交给模型（`why`/`hint` 已明确区分）。
    为控总量，`limit` 仍然生效（按文件+行号顺序截断）。
    """
    want_kinds = {k.lower() for k in kinds} if kinds else None
    want_langs = {l.lower() for l in langs} if langs else None

    # 按文件缓存：行内容 + 污染分析（一个文件会被逐行问很多次，不缓存会重复解析）
    taint_cache: dict[str, Taint.TaintResult] = {}
    lines_cache: dict[str, list[str]] = {}

    def _tainted_at(rel: str, lineno: int, lang: str) -> set[str]:
        if rel not in taint_cache:
            src = lines_cache.get(rel)
            if src is None:
                return set()
            taint_cache[rel] = Taint.analyze(src, lang)
        return Taint.tainted_names_at(taint_cache[rel], lineno)

    def _runners_at(rel: str, lineno: int, lang: str) -> set[str]:
        """同一份分析结果里的**命令执行器变量**集合（v071）。

        ⚠️ 复用 `taint_cache` —— `TaintResult` 同时带污点与执行器两套信息，
        重算一遍纯属浪费（一个文件会被逐行问很多次）。
        """
        if rel not in taint_cache:
            src = lines_cache.get(rel)
            if src is None:
                return set()
            taint_cache[rel] = Taint.analyze(src, lang)
        return Taint.runner_names_at(taint_cache[rel], lineno)

    def matcher(rel, lang, lineno, line, idx):
        found: list[Hit] = []
        for r in S.rules_for(lang):
            if want_kinds and r.kind not in want_kinds:
                continue
            if r.regex().search(line):
                found.append(Hit(
                    file=rel, line=lineno, text=line, lang=lang, kind=r.kind,
                    rule_id=r.id, why=r.why, hint=r.hint,
                    scope=_enclosing(idx, rel, lineno),
                    extractor="ast" if lang == "python" else "lexical"))
            crx = r.call_regex()
            if crx is not None:
                cm = crx.search(line)
                if cm:
                    names = _tainted_at(rel, lineno, lang)
                    lines = lines_cache.get(rel)
                    if names and lines and _tainted_in_args(lines, lineno, cm.start(), names):
                        found.append(Hit(
                            file=rel, line=lineno, text=line, lang=lang, kind=r.kind,
                            rule_id=r.id + "@taint",
                            why=f"[跨行污染] {r.why} —— 危险值在**本行之外**拼好，"
                                f"这里只是把变量传进来",
                            hint=(f"⚠️ 本行括号内的变量是**污点**（由上方赋值拼入外部输入）。"
                                  f"**先读那个变量的赋值行**确认它确实由外部输入拼成，再判断可达性；"
                                  f"{r.hint}"),
                            scope=_enclosing(idx, rel, lineno),
                            extractor="taint" if lang == "python" else "taint(lexical)"))
            # ---- 第三层：调用者变量（v071）----
            # 「执行器在别处取得」—— 与跨行污染正交（那里是「参数在别处拼好」）。
            # 判据是**类型信息**（调用者是不是命令执行器），不是宽度。
            rrx = r.runner_regex()
            if rrx is not None:
                rm = rrx.search(line)
                if rm and rm.groups():
                    caller = Taint._norm(rm.group(1))
                    runners = _runners_at(rel, lineno, lang)
                    if caller in runners:
                        found.append(Hit(
                            file=rel, line=lineno, text=line, lang=lang, kind=r.kind,
                            rule_id=r.id + "@runner",
                            why=f"[执行器变量] {r.why} —— 本行用的是**变量形式的执行器**"
                                f"（`{caller}` 由上方 `Runtime.getRuntime()` / "
                                f"`new ProcessBuilder(...)` 取得），"
                                f"旧的字面量 pattern 结构上匹配不到",
                            hint=(f"⚠️ `{caller}` 已确认是命令执行器（不是任意对象的同名方法）。"
                                  f"**往上读那个变量的赋值行**确认来源，再判断参数是否可控；"
                                  f"{r.hint}"),
                            scope=_enclosing(idx, rel, lineno),
                            extractor="runner"))
        return found or None

    # 预读文件内容供污染分析用（_scan 自己也会读，但两者互不干扰）
    t = _collect(codebase_id, want_langs)
    for fp in t.files:
        rel = fp.relative_to(t.root).as_posix()
        try:
            lines_cache[rel] = fp.read_text(encoding="utf-8",
                                            errors="replace").splitlines()
        except OSError:
            continue

    hits: list[Hit] = []
    idx = I.load(codebase_id)
    scanned = 0
    for fp in t.files:
        rel = fp.relative_to(t.root).as_posix()
        lang = t.lang_of[rel]
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            scanned += 1
            if scanned > MAX_SCAN_LINES:
                break
            got = matcher(rel, lang, lineno, line, idx)
            if got:
                hits.extend(got)
                if len(hits) >= limit:
                    break
        if scanned > MAX_SCAN_LINES or len(hits) >= limit:
            break
    # 稳定排序：同一行内**行级证据排在前**（强度更高），再按规则 id
    hits.sort(key=lambda h: (h.file, h.line, h.rule_id.endswith("@taint"), h.rule_id))
    return hits

# ---------------------------------------------------------------- 正则检索

def search_regex(codebase_id: str, pattern: str, *, langs=None,
                 ignore_case: bool = True, limit: int = MAX_HITS) -> list[Hit]:
    """按正则检索（用户/模型给的模式）。**非法正则退化为转义匹配**，不把工具打挂。"""
    try:
        rx = re.compile(pattern or "", re.I if ignore_case else 0)
        note = ""
    except re.error as e:
        rx = re.compile(re.escape(pattern or ""), re.I if ignore_case else 0)
        note = f"（模式非法正则，已按字面量匹配：{e}）"

    def matcher(rel, lang, lineno, line, idx):
        if not rx.search(line):
            return None
        return Hit(file=rel, line=lineno, text=line, lang=lang, kind="regex",
                   rule_id="", why=note, hint="",
                   scope=_enclosing(idx, rel, lineno),
                   extractor="ast" if lang == "python" else "lexical")

    hits = _scan(codebase_id, matcher, langs=langs, limit=limit)
    hits.sort(key=lambda h: (h.file, h.line))
    return hits


# ---------------------------------------------------------------- 读上下文（走 guard）

def read_context(codebase_id: str, rel: str, line: int,
                 before: int = 5, after: int = 5) -> dict:
    """取某处代码的上下文片段。

    ⚠️ **路径必经 `paths.guard`** —— 这是本能力里唯一「做错就泄露本机文件」的入口。
    `rel` 来自检索结果（相对受控根），但**不能因此信任**：它最终可能被模型改写，
    所以这里一律当外部输入处理。

    返回的 `text` 是**不可信数据**（§9）：只当数据看，绝不作为指令执行。
    """
    if before < 0 or after < 0 or before + after > 400:
        raise ValueError("上下文行数不合理（单个不超过 400 行）")
    if line < 1:
        raise ValueError("行号必须 ≥ 1")

    p = P.guard(codebase_id, rel)              # ← fail-closed，越界直接抛
    if not p.is_file():
        raise P.PathEscapeError(f"不是文件：{rel}")
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        raise P.PathEscapeError(f"读取失败：{e}") from e

    lo = max(1, line - before)
    hi = min(len(lines), line + after)
    numbered = [f"{i:>5} | {lines[i - 1]}" for i in range(lo, hi + 1)]
    idx = I.load(codebase_id)
    return {"file": rel, "line": line, "range": [lo, hi],
            "scope": _enclosing(idx, rel, line),
            "text": "\n".join(numbered),
            "untrusted": True}


def search_symbols(codebase_id: str, name: str = "", *, kind=None, lang=None,
                   limit: int = 200):
    """按名字查符号（委托索引 —— 它已经记了全部定义与行号）。"""
    idx = I.load(codebase_id)
    if idx is None:
        raise P.CodebaseNotFound(
            f"codebase「{codebase_id}」还没有索引 —— 请先跑 code_index。")
    return idx.find_symbols(name, kind=kind, lang=lang, limit=limit)


def search_strings(codebase_id: str, pattern: str, *, limit: int = 200):
    """按内容查字符串（委托索引；密钥类候选常从这里出）。"""
    idx = I.load(codebase_id)
    if idx is None:
        raise P.CodebaseNotFound(
            f"codebase「{codebase_id}」还没有索引 —— 请先跑 code_index。")
    return idx.find_strings(pattern, limit=limit)
