r"""变体分析（实施规格 §1.3 第 5 条 / §5 的 **P5** 阶段 / §7.1 最后一块）。

## 这个文件解决什么

规格 §1.3 第 5 条原话：

> **变体分析是可复现的工程方法**（最高价值）：读历史 CVE 的修复 commit →
> 理解根因 → **全库搜同模式**。同类错误几乎总会重复出现。
> 这条不依赖运气，是白盒 0day 的主要来源。

§5 把它定义为 **P5** 阶段：**P4 有发现** 之后走「查历史 CVE → 读修复 commit →
提取根因模式 → 全库搜同模式」，产出**同类未修复点**。

它同时是验收标准 **A4**（「产出至少 1 个不在已知 CVE 列表里的新候选」）
唯一可能的达成路径 —— §7.1 的其它六个模块都只能**复现已知**问题。

## ⚠️ 为什么要**离线优先**（本版的核心取舍）

规格写的是「读**历史 CVE** 的修复 commit」，字面隐含联网抓 NVD / GitHub API。
本版**刻意不把联网放进核心路径**，理由有两条，都是本项目已实测出来的：

1. **可用性**：本机到 GitHub 的链路需要四段回退（直连 → 代理 → 代理+关校验 → 直连+关校验），
   把一条「产出 0day 候选」的主流程挂在这样的链路上，等于让它经常性地什么都不产出；
2. **可回归性**：§8 的硬门槛 **A8** 要求「有固定基准，能回答这次改动让召回涨了还是跌了」。
   **联网数据的输入每次都不一样 → 无法回归 → 这条能力无法迭代**（本项目的既有教训：
   没有回归，改动就是盲改）。

所以本模块把「历史 CVE」拆成**可离线表达的形式**：

    已知根因模式（正则 + 语言 + 一句话根因说明 + 已知点坐标）
        ↓  全库搜同模式（复用 search.py 的三层匹配）
    命中点
        ↓  按「是不是已知点本身」分组
    ┌── 已知点（本就在 CVE 里）→ 用来**验证模式写对了**（命中它说明复现成功）
    └── **其它位置** → **同类未修复点候选**（A4 的产出）

「读修复 commit → 提取根因模式」这一步**留在模型/人**手里：它能读 diff、
能理解根因，然后把模式**喂进来**。本模块负责的是**它做不了的那部分** ——
确定性、可回归、覆盖全库的搜索与分组。

联网抓取保留为**可选适配器**（`fetch_fixed_commit_patterns()`），可优雅降级。

## ⚠️ 候选 ≠ 漏洞（§1.4 头号陷阱的第三次重申）

变体分析**天然制造误报**：一个模式在全库命中的大多数位置其实是安全的
（那里恰好走了净化、或输入本来就不可控）。所以：

- **每条候选都带 `reasons`（为什么算同类）与 `must_check`（还要确认什么）**；
- **已知点被显式排除并单列** —— 不排除的话，「新候选」里全是你已经知道的那个点；
- **候选数不是战果**。一个模式命中 50 处不等于 50 个漏洞，
  要判的是「去掉已知点之后，**还有几处是真的**」。本模块把这句话写进 `summary()`。

## 有意不做（与 `taint.py` 的边界一致）

- **不判可达性**：那是 §5 的 P4，要读代码追数据流。本模块只给**候选 + 起点**；
- **不做跨文件链路**：模式命中的是本文件内的形态。跨文件链路是判定层的活
  （v065~v068 反复确认的结论：真实基准的期望值要按 sink 在哪写，
  不能靠放宽规则硬凑）；
- **不做语义等价**：`charAt(2)` 与 `charAt(1)` 在正则层面无法区分
  （v072 实测：合并控制流分支净收益近零，要判对需**常量折叠**，属判定层）。
  本模块会**明确指出**这一局限，而不是假装能判。

## 模块 docstring 必须是 raw string

正文里写了大量正则片段（点号转义的 exec、词边界等），
普通字符串会**每次 import 都刷 SyntaxWarning**（v072.1 在 `taint.py` 踩过）。
"""
from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field

from . import index as I
from . import paths as P
from . import search as Q

# ---------------------------------------------------------------- 上限

#: 单次变体分析最多产出多少条候选（超过就截断并**显式说明**截断了）
MAX_VARIANTS = 200

#: 单个模式在全库最多扫多少命中就停（防宽模式打爆）
MAX_HITS_PER_PATTERN = 400

#: 一个模式最多接受多少个「已知点」用于自校验
MAX_KNOWN_POINTS = 50

#: 用户给的模式长度上限（正则太长多半是误用）
MAX_PATTERN_LEN = 500


class VariantError(ValueError):
    """变体分析的输入不合法。**调用方必须转成可读文字**（见 `tools.py` 的契约）。"""


# ---------------------------------------------------------------- 数据结构

@dataclass
class KnownPoint:
    """一个**已知**的脆弱点（通常来自某个 CVE 的修复点 / 人工确认点）。

    它的唯一用途是：**验证模式确实描述了这个根因**。
    模式若连已知点都命中不了，说明模式写错了，此时产出的「候选」毫无意义 ——
    所以本模块在 `reproduced` 为空时会**显式警告**，而不是照常输出候选。
    """
    file: str
    line: int = 0
    note: str = ""

    @property
    def loc(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class Pattern:
    """一个「根因模式」—— 变体分析的输入单位。

    刻意**不**做成 `sink_rules` 里的一条规则：规则库是**产品资产**（要被回归、
    要被 KB 文档描述、改动有明确副作用），而这里的模式是**一次性的分析输入**
    （针对某个 CVE 根因临时写的）。两者生命周期完全不同，混在一起会污染规则库统计。
    """
    pattern: str                      # 正则（在单行上匹配）
    lang: str = "*"                   # php | java | python | javascript | *（不限）
    kind: str = ""                    # 可选：归类（用于报告分组），不参与匹配
    root_cause: str = ""              # 一句话说清根因（必填，见下）
    source: str = ""                  # 出处：CVE 编号 / commit hash / 人工
    known: list[KnownPoint] = field(default_factory=list)
    ignore_case: bool = True
    must_check: str = ""              # 命中后还要确认什么（写进候选）

    def key(self) -> str:
        return f"{self.lang}:{self.pattern}"


@dataclass
class Variant:
    """一条**候选**（不是漏洞）。"""
    pattern: str                      # 所属模式的 key
    file: str
    line: int
    text: str                         # 命中行原文（**不可信数据**）
    lang: str
    scope: str = ""
    is_known: bool = False            # 是否就是已知点本身
    reasons: list[str] = field(default_factory=list)
    must_check: str = ""

    @property
    def loc(self) -> str:
        return f"{self.file}:{self.line}"

    def render(self) -> str:
        tag = "已知点" if self.is_known else "**新候选**"
        head = f"[{tag}] {self.loc}  {self.text.strip()[:150]}"
        if self.scope:
            head += f"\n    所在：{self.scope}"
        if self.reasons:
            head += "\n    为什么算同类：" + "；".join(self.reasons[:3])
        if self.must_check:
            head += f"\n    还需确认：{self.must_check}"
        return head


@dataclass
class PatternResult:
    """单个模式的执行结果。"""
    pattern: Pattern
    hits: list[Variant] = field(default_factory=list)
    #: 命中的已知点（`reproduced`）与**没命中的**已知点（`missed_known`）。
    #: 后者非空 = 模式写错了，属**必须报给模型**的信号。
    reproduced: list[KnownPoint] = field(default_factory=list)
    missed_known: list[KnownPoint] = field(default_factory=list)
    error: str = ""                   # 模式非法 / 超限等；非空时其余字段无意义
    truncated: bool = False

    @property
    def candidates(self) -> list[Variant]:
        """**去掉已知点**之后的候选 —— 这才是「新发现」。"""
        return [v for v in self.hits if not v.is_known]


@dataclass
class VariantReport:
    codebase_id: str
    results: list[PatternResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def candidate_count(self) -> int:
        return sum(len(r.candidates) for r in self.results)

    def summary(self) -> str:
        lines = [f"【变体分析】codebase `{self.codebase_id}`"]
        for w in self.warnings:
            lines.append(f"⚠️ {w}")
        for r in self.results:
            p = r.pattern
            head = f"\n— 模式 `{p.pattern}`"
            if p.lang != "*":
                head += f"（lang={p.lang}）"
            if p.source:
                head += f"  出处：{p.source}"
            lines.append(head)
            if r.error:
                lines.append(f"    ⚠️ 模式未执行：{r.error}")
                continue
            if p.root_cause:
                lines.append(f"    根因：{p.root_cause}")
            lines.append(
                f"    命中 {len(r.hits)} 处：已知点 {len(r.reproduced)} 个，"
                f"**新候选 {len(r.candidates)} 个**")
            if r.missed_known:
                lines.append(
                    "    ⚠️ **模式没命中这些已知点**（说明模式没覆盖到这个根因，"
                    "下面列出的候选**不可信**）："
                    + "、".join(k.loc for k in r.missed_known[:5]))
            if r.truncated:
                lines.append(f"    ⚠️ 命中数达到上限 {MAX_HITS_PER_PATTERN}，已截断")
        lines.append(
            "\n⚠️ **候选数不是战果**：模式在全库命中的大多数位置其实是安全的"
            "（走了净化、或输入不可控）。逐条判可达性（§5 的 P4）才知道有几个是真的。"
            "\n⚠️ 本模块**不做语义等价判定**：`charAt(2)` 与 `charAt(1)` 在正则层面"
            "无法区分（v072 实测：要判对需常量折叠，属判定层）。")
        return "\n".join(lines)


# ---------------------------------------------------------------- 模式校验

def _compile(p: Pattern) -> re.Pattern:
    """编译模式。**非法正则不静默退化** —— 与 `search_regex` 不同：

    `search_regex` 是模型现场试模式，退化比报错有用；
    而变体分析的模式是**承载根因的**，写错了产出的候选全是噪声，
    所以这里**明确报错**，让模式必须写对。
    """
    pat = (p.pattern or "").strip()
    if not pat:
        raise VariantError("模式为空")
    if len(pat) > MAX_PATTERN_LEN:
        raise VariantError(f"模式过长（{len(pat)} > {MAX_PATTERN_LEN} 字符）")
    try:
        return re.compile(pat, re.I if p.ignore_case else 0)
    except re.error as e:
        raise VariantError(f"模式不是合法正则：{e}") from e


def _normalize_variants(pats: list[Pattern] | list[dict] | list[str]) -> list[Pattern]:
    """接受三种写法：`Pattern` / dict / 裸字符串（裸串只当模式，根因为空）。

    宽松接受是为了**让工具好用**（模型经常只会给一个正则字符串），
    但**不做任何猜测性填充** —— 缺什么就是缺什么。
    """
    out: list[Pattern] = []
    for raw in pats or []:
        if isinstance(raw, Pattern):
            out.append(raw)
        elif isinstance(raw, str):
            out.append(Pattern(pattern=raw))
        elif isinstance(raw, dict):
            known = [k if isinstance(k, KnownPoint) else KnownPoint(**k)
                     for k in (raw.get("known") or [])]
            out.append(Pattern(
                pattern=str(raw.get("pattern") or ""),
                lang=str(raw.get("lang") or "*"),
                kind=str(raw.get("kind") or ""),
                root_cause=str(raw.get("root_cause") or ""),
                source=str(raw.get("source") or ""),
                known=known,
                ignore_case=bool(raw.get("ignore_case", True)),
                must_check=str(raw.get("must_check") or "")))
        else:
            raise VariantError(f"不认识模式写法：{type(raw).__name__}")
    if not out:
        raise VariantError("至少要给一个模式")
    return out


def _same_loc(file: str, line: int, k: KnownPoint) -> bool:
    """判断命中点是否**就是**某个已知点。

    路径比较按 posix 相对路径、大小写不敏感（Windows）。行号为 0 的已知点
    表示「只约束文件」，此时文件相同即算命中 —— 这是刻意的宽松：写 CVE 时
    经常只记得文件名。
    """
    if file.replace("\\", "/").lower() != k.file.replace("\\", "/").lower():
        return False
    return k.line == 0 or k.line == line


# ---------------------------------------------------------------- 主流程

def run_pattern(codebase_id: str, p: Pattern,
                *, langs: set[str] | None = None) -> PatternResult:
    """跑单个模式：全库搜 → 标注已知点 → 分组。**不抛异常**（错误进 `error`）。"""
    res = PatternResult(pattern=p)
    try:
        rx = _compile(p)
    except VariantError as e:
        res.error = str(e)
        return res

    if len(p.known) > MAX_KNOWN_POINTS:
        res.error = f"已知点过多（{len(p.known)} > {MAX_KNOWN_POINTS}）"
        return res

    want_langs = {l.lower() for l in langs} if langs else None
    if p.lang and p.lang != "*":
        want_langs = ({p.lang.lower()} if want_langs is None
                      else want_langs & {p.lang.lower()})

    # 复用 `search._scan`：它与 sink 检索共用同一套「只读受控根 + 行号来自工具」的
    # 扫描逻辑。**不自己再写一遍遍历** —— v072 的教训是「同一个盲区会在多层各犯一次」，
    # 多一份遍历就多一份「有人改了一处、另一处没改」的风险。
    try:
        hits = Q._scan(codebase_id, _make_matcher(rx, p),
                       langs=want_langs, limit=MAX_HITS_PER_PATTERN)
    except P.CodebaseNotFound:
        raise
    except P.PathEscapeError:
        raise
    except Exception as e:                                # noqa: BLE001
        res.error = f"扫描失败（{type(e).__name__}）：{e}"
        return res

    res.truncated = len(hits) >= MAX_HITS_PER_PATTERN
    matched_known: set[int] = set()
    for h in hits:
        for i, k in enumerate(p.known):
            if _same_loc(h.file, h.line, k):
                matched_known.add(i)
                res.reproduced.append(k)
                res.hits.append(Variant(
                    pattern=p.key(), file=h.file, line=h.line, text=h.text,
                    lang=h.lang, scope=h.scope, is_known=True,
                    reasons=[f"与已知点 {k.loc} 位置相同"
                             + (f"（{k.note}）" if k.note else "")],
                    must_check=p.must_check))
                break
        else:
            res.hits.append(Variant(
                pattern=p.key(), file=h.file, line=h.line, text=h.text,
                lang=h.lang, scope=h.scope, is_known=False,
                reasons=_why_same(p, h), must_check=p.must_check))

    res.missed_known = [k for i, k in enumerate(p.known) if i not in matched_known]
    # 已知点单列：`reproduced` 不去重的话，同一已知点被多行命中会重复计数
    seen: set[str] = set()
    res.reproduced = [k for k in res.reproduced
                      if not (k.loc in seen or seen.add(k.loc))]
    return res


def _make_matcher(rx: re.Pattern, p: Pattern):
    """构造 `search._scan` 要的 matcher（返回 `Hit | None`）。

    ⚠️ 刻意**不**在变体层判污点/可达性：那会让「模式命中」这个人人都能复核的
    事实，混进「我认为它危险」的判断。变体分析的产物必须是**可复核的**：
    任何人拿同一个正则重跑，必须得到同一批位置。
    """
    def matcher(rel, lang, lineno, line, idx):
        if not rx.search(line):
            return None
        return Q.Hit(file=rel, line=lineno, text=line, lang=lang, kind="variant",
                     rule_id="", why="", hint="",
                     scope=Q._enclosing(idx, rel, lineno),
                     extractor="regex")
    return matcher


def _why_same(p: Pattern, hit) -> list[str]:
    """给候选写「为什么算同类」—— **不编造理由**。

    能给的事实只有三条：匹配了同一个模式、语言一致、以及模式自身的根因描述。
    刻意不写「疑似 SQL 注入」这类**由模式推测**的话 —— 那是模型的活。
    """
    out = [f"匹配根因模式 `{p.pattern}`"]
    if p.lang and p.lang != "*":
        out.append(f"语言一致（{p.lang}）")
    if p.root_cause:
        out.append(f"根因描述：{p.root_cause}")
    return out


def analyze(codebase_id: str, patterns, *,
            langs: set[str] | None = None,
            max_total: int = MAX_VARIANTS) -> VariantReport:
    """变体分析主入口：一批模式 → 一份报告。

    **不抛异常之外的任何东西**：`VariantError` 只在**输入完全不合法**时抛
    （空模式列表、未知写法）；单个模式的问题进该模式的 `error` 字段，
    其余模式照常执行 —— 一条写坏的 CVE 不该让整次分析归零。
    """
    if not codebase_id:
        raise VariantError("缺少 codebase_id")
    pats = _normalize_variants(patterns)
    rep = VariantReport(codebase_id=codebase_id)

    total = 0
    for p in pats:
        if total >= max_total:
            rep.warnings.append(
                f"候选总数达到上限 {max_total}，剩余 {len(pats)} 个模式未执行")
            break
        r = run_pattern(codebase_id, p, langs=langs)
        rep.results.append(r)
        total += len(r.candidates)

    # ---- 报告级警告：三种「别信结果」的情况，必须显式说 ----
    if not any(r.hits for r in rep.results if not r.error):
        rep.warnings.append(
            "**所有模式都没有命中任何东西**。这通常说明模式写得不对（太具体 / "
            "语言猜错 / 索引是空的），而不是「这个项目是安全的」。")
    for r in rep.results:
        if r.missed_known and not r.error:
            rep.warnings.append(
                f"模式 `{r.pattern.pattern}` **没能命中它自己的已知点**"
                f"（{r.missed_known[0].loc}）—— 该模式产出的候选不可信，"
                f"请先修正模式。")
    if not any(r.pattern.root_cause for r in rep.results):
        rep.warnings.append(
            "没有提供 `root_cause` —— 变体分析的产出靠根因描述才可复核，"
            "建议补上（形如：`未过滤的 param 直接拼进 JDBC 查询`）。")
    return rep


# ---------------------------------------------------------------- 从 diff 提模式（离线）

#: 修复 commit 的删除行里，哪些形态**通常就是被修掉的不安全写法**。
#: 只做**提示**，不自动生成模式 —— 见 `patterns_from_diff` 的说明。
_DIFF_SMELLS = (
    ("拼接进查询", re.compile(
        r"""(?i)(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^;'"]*['"][^'"]*['"]?\s*\+""")),
    ("字符串拼接进命令", re.compile(r"(?i)(?:exec|system|Runtime\s*\.\s*getRuntime)"
                                   r"[^;]*\+")),
    ("路径拼接", re.compile(r"(?i)(?:File|FileInputStream|open|include|require)"
                            r"\s*\([^)]*\+")),
    ("反序列化", re.compile(r"(?i)(?:readObject|unserialize|pickle\.loads|yaml\.load"
                            r"|ObjectInputStream)\s*\(")),
    ("弱算法/不安全随机", re.compile(r"(?i)\b(?:MD5|SHA1|DES|RC4|Math\.random"
                                     r"|rand\s*\(\s*\)|random\.random)\b")),
)


@dataclass
class DiffHint:
    """从 diff 里提出来的一条**线索**（不是模式）。"""
    file: str
    text: str
    smell: str
    confidence: str = "低"

    def render(self) -> str:
        return f"- {self.file}  [{self.smell}]  {self.text.strip()[:140]}"


def patterns_from_diff(diff_text: str) -> tuple[list[DiffHint], list[str]]:
    """从**修复 commit 的 diff** 里抠出候选根因行，返回 `(线索, 警告)`。

    ## ⚠️ 刻意**不自动生成正则**

    「diff 的删除行 = 不安全写法」这个推断**经常是错的**：修复 commit 里还有
    重构、改名、格式化、加日志。自动把删除行变成全库正则，等于把噪声放大到全库 ——
    这是 §1.4「误报被当成发现」的批量版。

    所以这里**只做到「指出哪几行像根因」**，把「提取模式」这一步留给模型/人：
    它们能读 commit message、能看上下文，判得比正则靠谱。

    输入的 diff 由调用方提供（`git show <commit>` / `git log -p` / GitHub patch）。
    **本函数不联网。**
    """
    if not isinstance(diff_text, str) or not diff_text.strip():
        return [], ["diff 为空"]

    hints: list[DiffHint] = []
    warns: list[str] = []
    cur_file = ""
    del_count = 0
    add_count = 0

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            cur_file = raw[4:].strip()
            if cur_file.startswith("b/"):
                cur_file = cur_file[2:]
            continue
        if raw.startswith("--- "):
            continue
        if raw.startswith("-"):
            del_count += 1
            body = raw[1:]
            for smell, rx in _DIFF_SMELLS:
                if rx.search(body):
                    hints.append(DiffHint(file=cur_file or "?", text=body, smell=smell))
                    break
        elif raw.startswith("+"):
            add_count += 1

    if del_count == 0:
        warns.append("diff 里没有删除行 —— 可能不是修复 commit，或者格式不对"
                     "（需要 unified diff，即 `git show` 的默认输出）")
    if len(hints) > 30:
        warns.append(f"候选根因行多达 {len(hints)} 条，**建议人工筛**："
                     f"修复 commit 通常只修 1~3 处根因，其余是重构/格式化的噪声")
    if add_count and del_count and abs(add_count - del_count) > 5 * max(del_count, 1):
        warns.append("新增行远多于删除行 —— 这个 commit 更像**功能开发**而非修复，"
                     "从中提根因的可靠性低")
    return hints, warns


# ---------------------------------------------------------------- 联网适配器（可选）

#: 抓取 GitHub commit 的 API（**只在这里定义一次**）
_GITHUB_COMMIT_API = "https://api.github.com/repos/{repo}/commits/{sha}"
_FETCH_TIMEOUT = 15


def fetch_fixed_commit_patterns(repo: str, sha: str,
                                *, token: str = "",
                                timeout: int = _FETCH_TIMEOUT
                                ) -> tuple[list[DiffHint], list[str]]:
    """**可选**联网适配器：从 GitHub 拉一个 commit 的 diff 再转线索。

    ## 为什么它是「适配器」而不是主流程

    见模块 docstring：联网让**结果不可回归**（A8 硬门槛）。所以：

    - 它**不在** `analyze()` 的调用链上，必须显式调用；
    - **任何失败都返回 `([], [原因])`，绝不抛异常** —— 网络不通是本机常态
      （push 要四段回退），让它把一次分析打挂是本末倒置；
    - 返回的线索仍然要经 `patterns_from_diff` 的同一套怀疑（那是提示不是模式）。
    """
    if not repo or "/" not in repo:
        return [], ["repo 需要 `owner/name` 形式"]
    if not sha:
        return [], ["sha 为空"]
    try:
        import urllib.request

        url = _GITHUB_COMMIT_API.format(repo=repo, sha=sha)
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github.v3.diff",
            "User-Agent": "src-agent-variants",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as e:                                # noqa: BLE001
        # 刻意捕获**全部**异常：URLError / HTTPError / 超时 / SSL / 解码
        # —— 「服务不可达」比「HTTP 4xx」更基础，只捕 HTTPError 会漏掉最常见的那种
        # （v073 的教训：`test_llm_providers.py` 就是因此整个 import 阶段崩掉）。
        return [], [f"联网抓取失败（{type(e).__name__}）：{str(e)[:160]}"
                    f" —— 这是**环境问题**，请改用离线方式喂 diff"]
    hints, warns = patterns_from_diff(body)
    return hints, [f"已从 GitHub 拉取 {repo}@{sha[:8]}（{len(body)} 字节）"] + warns


def load_patterns(path) -> tuple[list[Pattern], list[str]]:
    """从 JSON 文件读模式（离线，便于回归与复用）。

    格式（列表，或 `{"patterns": [...]}`）：

        [{"pattern": "executeQuery\\\\s*\\\\(\\\\s*[\\"'][^\\"']*[\\"']\\\\s*\\\\+",
          "lang": "java", "kind": "sqli",
          "root_cause": "未过滤的输入直接拼进 JDBC 查询",
          "source": "CVE-2020-XXXX",
          "known": [{"file": "src/Dao.java", "line": 42}],
          "must_check": "确认 param 是否来自请求参数、有无预编译"}]

    **读文件走受控根**（若传的是相对路径则相对 codebase 根）——
    与 `code_read` 同一条fail-closed 防线。
    """
    warns: list[str] = []
    p = pathlib.Path(str(path)).expanduser()
    if not p.is_file():
        return [], [f"模式文件不存在：{p}"]
    try:
        raw = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        return [], [f"模式文件解析失败（{type(e).__name__}）：{e}"]
    items = raw.get("patterns") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return [], ["模式文件格式不对：应为列表，或 {\"patterns\": [...]}"]
    try:
        pats = _normalize_variants(items)
    except VariantError as e:
        return [], [str(e)]
    if not any(x.root_cause for x in pats):
        warns.append("模式文件里没有 `root_cause` —— 建议补上，否则产出不可复核")
    return pats, warns


# ---------------------------------------------------------------- 与既有能力的衔接

def suggest_from_sinks(codebase_id: str, *, kinds=None, langs=None,
                       limit: int = 5) -> tuple[list[Pattern], list[str]]:
    """从**已命中的 sink** 反推可用的变体模式 —— 让 P4→P5 衔接起来（§5）。

    ## 为什么需要这一步

    §5 规定 P5 的**进入条件是「P4 有发现」**。但 P4 的发现是「某个 `文件:行号`
    很可疑」，而 P5 要的是「一个能全库搜的模式」—— **两者形态不同**，
    中间这一步没人做的话，模型到了 P5 会发现自己拿着一个位置却搜不了库。

    本函数做的是**形态转换**：把「`java.sqli` 在 `Dao.java:42` 命中」
    变成「按该规则的 `call_pattern` / `pattern` 搜全库，已知点在 `Dao.java:42`」。

    ⚠️ 产出的模式**直接复用规则库的正则**，因此**继承规则库的全部局限**
    （这是好事：局限是已知的、被回归覆盖的）。**不在这里发明新正则。**
    """
    warns: list[str] = []
    try:
        hits = Q.search_sinks(codebase_id, kinds=kinds, langs=langs,
                              limit=Q.MAX_HITS)
    except (P.CodebaseNotFound, P.PathEscapeError):
        raise
    if not hits:
        return [], ["没有 sink 命中 —— P5 的进入条件是「P4 有发现」，"
                    "先让 P4 跑出结果（或直接用 `variant_search` 手工给模式）。"]

    from . import sink_rules as S

    seen: dict[str, Pattern] = {}
    for h in hits:
        base_id = h.rule_id.split("@")[0]
        if base_id in seen:
            # 同一个规则在多处命中 → 把后续位置都记成已知点
            seen[base_id].known.append(KnownPoint(file=h.file, line=h.line))
            continue
        r = S.by_id(base_id)
        if r is None:
            continue
        # 优先用 `call_pattern`（覆盖「参数在别处拼好」的间接形态 —— 那正是
        # CVE 修复点最常见的样子）；没有则退回 `pattern`。
        rx = r.call_pattern or r.pattern
        seen[base_id] = Pattern(
            pattern=rx, lang=r.lang, kind=r.kind, root_cause=r.why,
            source=f"规则库 {r.id}",
            known=[KnownPoint(file=h.file, line=h.line)],
            must_check=r.hint or "确认该处的输入是否可控、有无净化")
        if len(seen) >= limit:
            break

    pats = list(seen.values())
    if pats:
        warns.append(
            f"从 {len(hits)} 处 sink 命中里归纳出 {len(pats)} 个模式"
            f"（**只用了规则库已有的正则**，未新造）。"
            f"这些模式目前把**首个命中点**当作已知点 —— 若你要拿它找别的项目的"
            f"同类问题，请把已知点改成**真正的 CVE 修复点**，否则"
            f"「新候选」里会混进当前项目本来就已知的位置。")
    return pats, warns
