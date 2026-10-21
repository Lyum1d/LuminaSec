# -*- coding: utf-8 -*-
"""批量基准：**真实仓库 + 官方标注**，算「按类别的真实召回 / 精确性」。

## 为什么单独一个模块（与 `recall.py` 的分工）

`recall.py` 的 `Case` 是**单点模型**：一条用例 = 「在某个 `文件:行号` 命中某条规则」。
它对**手工写的小样本**很合适（内置语料、DVWA 的几个已知点），但表达不了评测集的语言：

> 「这个仓库里 272 个 SQL 注入用例，你打中了几个？」

那是**批量**的：用例 = **一个测试文件**，标注 = **官方给的（真漏洞 / 安全 + CWE）**。
两者粒度不同，硬塞进 `Case` 只会两边都别扭 —— 所以这里另起一条路径，
`recall.py` 的单点路径**原样保留**（内置语料仍靠它卡硬阈值）。

## ⚠️ 为什么必须这么做：DVWA 的 100% 是假的

v066/v067 用 DVWA 跑出 100% 召回。**那个数字不能信**：DVWA 是我们**手工挑的点**，
而且规则就是**照着那个形态调的**（拼接与 sink 同行）。真实项目里形态完全不同：

- **跨行污染**：`String sql = "... " + param;` 在上一行、`prepareStatement(sql)` 在下一行
  → **单行正则在结构上必然漏**（v069 已用 `call_pattern` + 污点分析补上，见 `taint.py`）；
- **全限定名**：`new java.io.FileInputStream(` —— 规则若只写短名，**522 处漏 500 处**；
- **跨行参数区**：`prepareStatement(\n    sql, ...)` —— 调用名与参数不同行。

**要回答「规则在真实项目上到底行不行」，只有一条路：拿带官方标注的评测集跑。**
本模块就是跑它的机器。首个接入的是 **OWASP BenchmarkJava v1.2**：
`expectedresults-1.2.csv` 有 **2740 条**逐用例标注，是**唯一可信的标尺**。

## ⚠️ v071 之二：**精确性会被「别的 kind」污染**（实测量化）

归属模型是「命中文件的 stem ∈ 用例名」。于是**任何**规则在某个用例文件里命中，
都会把这个用例记成「被命中」。问题在于——**规则是按 kind 分组的**：

    BenchmarkTest00009 是标注为「hash 安全」的用例，
    但它的代码里有 `new java.io.File(...)`（读输入用的）→ `java.path.file` 命中它。
    于是这个命中被算进 **hash 的误报**。

实测（OWASP BenchmarkJava，2026-10-04）：

| 类别 | 文件级精确性（旧） | kind 级精确性（新） |
|---|---|---|
| cmdi | 35/64 = 55% | 35/64 = 55%（**不变**） |
| crypto | 37/72 = 51% | **19/19 = 100%** |
| hash | 38/64 = 59% | **28/28 = 100%** |
| pathtraver | 38/65 = 58% | 38/65 = 58%（**不变**） |
| sqli | 28/44 = 64% | 22/33 = 67% |
| **合计** | **176/309 = 57.0%** | **142/209 = 67.9%** |

**为什么这条重要**：`crypto` 的精确性从 51% 跳到 100%，不是因为规则变了，
而是因为原来那 35 个「误报」**根本就不是 crypto 规则报的** —— 是别的规则在同一个文件里报的。
把别人的命中算成自己的误报，会让**每个类别的精确性都趋同**（都变成「这个文件里有没有任何 sink」），
既看不出哪条规则在裸奔，也看不出哪条规则很准。

**这是 v067「没测 ≠ 0 分」的同族问题**：那个是「把没测显示成 0 分」，
这个是「**把别类的命中显示成本类的误报**」—— 都是**用一个不成立的归属**去算指标。

**修法**：命中的归属改成按 **kind** 归因（`hit_kind_cases`），
`Category.kindhit_*` 是「本类别对应 kind 的命中」，`crosshit_*` 是「别的 kind 蹭进来的」。
两个精确性都算、都显示，**不丢掉任何一个** —— 因为文件级那个也有意义
（它回答「这个文件里有没有可疑代码」，只是**不回答**「本规则准不准」）。

### 三条纪律（沿用 `recall.py` 的同族约定）

1. **读不到就返回空、绝不抛异常** —— 没配评测集是**正常状态**，不该让基准报错；
2. **不做环境相关的硬卡点** —— 有没有那份检出取决于本机，**只报数，不卡阈值**
   （能卡阈值的只有 `recall.py` 的内置语料）；
3. **「没测」不是「0 分」** —— 精确性在无负样本时返回 `None` 而不是 `0.0`
   （这条在 v067 踩过：真实用例全是正样本时报告显示「精确性 0%」，
   看的人会以为规则在疯狂误报，而事实是**根本没测**）。

## ⚠️ v071：**标尺本身也会错** —— 分母必须用「可命中」

v069/v070 的召回分母用的是**官方标注的全部条数**。这个口径**系统性低估**了真实召回。
实测（OWASP BenchmarkJava v1.2，2026-10-04）：

    官方标注 CSV         2740 条（编号 00001–02740）
    本机检出 java 文件    669 个（编号 00001–00669）
    标注 ∩ 检出           669     ← **只有这些「可命中」**
    标注但无源码         2071     ← 幽灵用例：结构上不可能被命中
    有源码但无标注          0     ← 反过来说，检出就是标注的前 669 个

**真漏洞标注 1415 条里有 1039 条（73%）没有对应源码**，却被算进了召回分母
→ 分母虚高约 4 倍，真实召回被压成原来的四分之一：

| 类别 | 旧口径（全部标注） | 新口径（仅可命中） |
|---|---|---|
| cmdi | 20/126 = 15.9% | **20/35 = 57.1%** |
| crypto | 37/130 = 28.5% | **37/37 = 100.0%**（文件级）|
| hash | 38/129 = 29.5% | **38/38 = 100.0%**（文件级）|
| pathtraver | 38/133 = 28.6% | **38/38 = 100.0%** |
| sqli | 28/272 = 10.3% | **28/64 = 43.8%** |
| **小计** | 161/790 = 20.4% | **161/212 = 75.9%** |

⚠️ **v072 补注**：上表「新口径」里的 crypto/hash 是**文件级**召回。
按**本类别规则**（两者都映射到 `weak_crypto`）算，只有 **19/37 = 51.4%** 与 **28/38 = 73.7%** ——
那多出来的是**别的 kind 在同一个文件里的命中**，不是 `weak_crypto` 规则的功劳。
一类两 kind（crypto/hash 共用 `weak_crypto`）时这个差尤其大。
**所以 v072 起 `render()` 的召回也改成 kind 级为主**（与精确性对称），见 `Category.render`。

**为什么当时没发现**：本机那份检出是**部分检出**（大概率是分批 clone 或只取了前一段），
而评测集的标注是**全量**的。两边条数不一样这个事实，在只看百分比时**完全看不出来**
（`20/126 = 15.9%` 和 `20/35 = 57.1%` 都是「一个百分比」）。

**因此本模块的规矩（v071 起）**：

- 召回分母 = **可命中**（标注 ∩ 检出）的用例数，**不是**标注总条数；
- 「标注但无源码」的用例**单列**在 `Category.vuln_missing` / `safe_missing`，
  **不进任何分母**（它们既不算漏报，也不算命中 —— 本机根本没测到它们）；
- 报告里**显式打印这个缺口**。否则数字变了但没人知道为什么变 ——
  这类「静默改口径」比不改更坏。

⚠️ **一个反直觉的推论**：如果某类别的 `vuln_total == 0`（标注里的真漏洞在本机全无源码），
那这个类别**没有被测到**，报「召回 0%」是**错的**（那是把「没测」显示成「0 分」，
同族错误 v067 已经踩过一次）。这类类别按「无源码」单列，不参与小计。

## 归属模型：命中 → 用例

评测集按**文件**组织（`BenchmarkTest00001.java`）。一条 sink 命中落在哪个用例里，
就看它的 `file` 路径的 stem —— 与官方 CSV 的**第一列**同名即算这个用例被打了。
（所以这里**不是**「命中行号对不对」，而是「这个漏洞用例你有没有碰到」——
碰不到 = 漏报，这本来就是召回率的定义。）
"""
from __future__ import annotations

import csv
import io
import json
import pathlib
import tempfile
from dataclasses import dataclass, field

from .. import config

#: 本机评测集配置（**不入库**：含本机检出目录的绝对路径，带用户名）。
#: 与 `data/scope.json` / `data/codebases.json` / `data/recall_real.json` 同一套约定：
#: **机制入库（本模块 + `*.example` 模板），本机路径写在被 gitignore 的 json 里。**
BATCH_FILE = config.DATA_DIR / "recall_batch.json"


@dataclass
class Category:
    """一个类别在官方标注下的统计 + 本 Agent 的命中结果。

    ## 两套分母，别混（v071）

    `vuln_total` / `safe_total` 是 **可命中** 的条数（标注 ∩ 检出）——
    **召回/误报的分母只能用它们**。
    `vuln_missing` / `safe_missing` 是同类别里「标注有、本机没源码」的条数，
    单列出来**供报告显示缺口**，**不进任何分母**。

    `annotated_*` 属性 = 可命中 + 无源码，只是给报告算「官方一共标了多少」用的。
    """
    name: str                       # 官方类别名（如 sqli / pathtraver）
    kind: str = ""                  # 本 Agent 的规则 kind（空 = 能力外）
    vuln_total: int = 0             # 真漏洞用例数 —— **可命中**（分母）
    safe_total: int = 0             # 安全用例数 —— **可命中**（分母）
    vuln_hit: int = 0               # 真漏洞用例里被命中的
    safe_hit: int = 0               # 安全用例里被命中的（= 误报）
    vuln_missing: int = 0           # 真漏洞标注里「本机无源码」的条数（不进分母）
    safe_missing: int = 0           # 安全标注里「本机无源码」的条数（不进分母）
    # --- v071：按 kind 归因（去掉「跨 kind 污染」，见模块 docstring）--------------
    kindhit_vuln: int = 0           # 可命中真漏洞里，**本类别 kind** 命中了的（⊆ vuln_hit）
    kindhit_safe: int = 0           # 可命中安全用例里，本类别 kind 命中的（⊆ safe_hit）

    @property
    def crosshit_vuln(self) -> int:
        """真漏洞里被命中、但**不是本类别 kind** 报的 —— 别的规则的功劳，不算本规则的召回。"""
        return max(0, self.vuln_hit - self.kindhit_vuln)

    @property
    def crosshit_safe(self) -> int:
        """安全用例里被命中、但**不是本类别 kind** 报的 —— **不算本规则的误报**。"""
        return max(0, self.safe_hit - self.kindhit_safe)

    @property
    def vuln_annotated(self) -> int:
        """官方标注的真漏洞总条数（可命中 + 无源码）。"""
        return self.vuln_total + self.vuln_missing

    @property
    def safe_annotated(self) -> int:
        """官方标注的安全用例总条数（可命中 + 无源码）。"""
        return self.safe_total + self.safe_missing

    @property
    def recall(self) -> float:
        return (self.vuln_hit / self.vuln_total) if self.vuln_total else 0.0

    @property
    def recall_kind(self) -> float:
        """**只看本类别 kind** 的召回。与 `recall` 相等或更低（跨 kind 命中不计入）。

        ⚠️ 这两个值**都**有意义：`recall` 回答「这类用例我们能不能碰到」，
        `recall_kind` 回答「**我们为这类专门写的规则**碰到了几个」。
        真实评估规则质量应当看后者；前者衡量的是整体覆盖度。
        """
        return (self.kindhit_vuln / self.vuln_total) if self.vuln_total else 0.0

    @property
    def precision(self) -> float | None:
        """打中的里面有多少是真漏洞（**文件级**口径）。**一次都没打中时返回 `None`（未测）**。

        注意与 `recall.py` 的 `precision_of()`（负样本通过率）**口径不同**：
        那里是「安全样本没被误报的比例」，这里是「命中的判为正的比例」。
        两者数值上互补但基准不同，报告里分别标注，不要混用。

        ⚠️ 这是**文件级**口径 —— 会把别的 kind 在同一文件里的命中算进来，
        于是每个类别都趋同。**要评估规则质量请用 `precision_kind`。**
        """
        seen = self.vuln_hit + self.safe_hit
        return (self.vuln_hit / seen) if seen else None

    @property
    def precision_kind(self) -> float | None:
        """**只看本类别 kind** 的精确性（去掉跨 kind 污染）。

        实测这条能差出一倍：`crypto` 51% → 100%、`hash` 59% → 100%
        （原来那些「误报」其实是别的规则在同一个文件里报的）。
        同样，**一次都没打中时返回 `None`（未测）**，不是 0。
        """
        seen = self.kindhit_vuln + self.kindhit_safe
        return (self.kindhit_vuln / seen) if seen else None

    def render(self, width: int = 14) -> str:
        """渲染一行。**召回与精确性都必须 kind 级为主**（v072 修正）。

        ## ⚠️ 原来混了口径（v071 遗留缺陷）

        原写法是「文件级召回 + kind 级精确性」：

            f"召回 {self.vuln_hit}/{self.vuln_total} = {self.recall:.1%} ... 精确性 {kind 级}"

        于是**同一行里两个口径**。后果被实测抓出来：`crypto` 显示「召回 100%」，
        但那 100% 是**文件级**的（靠别的 kind 在同一文件里命中凑的）；
        按本类别规则（`weak_crypto`）算只有 **51.4%**。
        报告里两个数字并排，读者会默认它们同口径 —— **比只显示一个更误导**。

        现在改为**两边都以 kind 级为主**，文件级在括号里（与 `_fmt_prec_pair` 对称）。
        """
        s = (f"  {self.name:<{width}} 召回 " + self._fmt_recall()
             + f"   误报 {self.safe_hit:4d}/{self.safe_total:4d}   精确性 "
             + self._fmt_prec())
        # 缺口只在真的存在时补一句 —— 本机是全量检出时这一行不该出现（别加噪音）
        miss = self.vuln_missing + self.safe_missing
        if miss:
            s += f"   [标注另有 {miss} 条无源码，已排除]"
        return s

    def _fmt_recall(self) -> str:
        """召回渲染：**kind 级为主，文件级在括号里**。

        两者相等时（cmdi/pathtraver 这种「一类一 kind、规则的 shape 也专一」）不重复显示。
        """
        kf, lf = self.recall_kind, self.recall
        bar = f"{self.kindhit_vuln:4d}/{self.vuln_total:4d}" if self.vuln_total else "   0/   0"
        if self.vuln_total == 0:
            return f"{bar} =（未测）"
        if abs(kf - lf) < 5e-4:
            return f"{bar} = {kf:5.1%}"
        return f"{bar} = {kf:5.1%}（文件级 {self.vuln_hit}/{self.vuln_total} = {lf:.1%}）"

    def _fmt_prec(self) -> str:
        """精确性渲染：**kind 级为主，文件级在括号里**（见模块级 `_fmt_prec_pair`）。"""
        return _fmt_prec_pair(self.precision_kind, self.precision)


@dataclass
class BatchReport:
    """跑一批评测集的结果。"""
    name: str = ""
    root: str = ""
    csv: str = ""                    # 实际读的标注文件（出问题时要能指出读了哪个）
    codebase_id: str = ""
    file_count: int = 0
    hits_total: int = 0
    cases_total: int = 0             # 官方标注条数
    cases_hit: int = 0               # 被命中的用例文件数（含安全样本的误报）
    cases_present: int = 0           # 标注 ∩ 检出（**真正可命中**的条数）
    cases_missing: int = 0           # 标注但本机无源码（缺口，不进分母）
    cases_unannotated: int = 0       # 有源码但无标注（正常应为 0）
    categories: list[Category] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def partial_checkout(self) -> bool:
        """本机检出是否**不完整**（标注比检出的用例多）。

        为真时报告顶部会显式提示 —— 这个标志存在的唯一目的，
        就是防止「分母悄悄变小、百分比悄悄变大」而没人知道为什么。
        """
        return self.cases_missing > 0

    # ---- 汇总：只算「本 Agent 有能力」的类别 ----
    @property
    def covered(self) -> list[Category]:
        return [c for c in self.categories if c.kind]

    @property
    def uncovered(self) -> list[Category]:
        return [c for c in self.categories if not c.kind]

    def total(self, cats: list[Category]) -> dict[str, int | float | None]:
        """把一组类别合并成一个总数。

        ⚠️ 这个聚合**只能**这么算：分子分母都是**用例数**。
        不要用「命中总数」当指标 —— 一次误报能贡献几十条命中，
        把「命中数」拿来比大小会被单条宽口径规则带偏（v069 实测：删掉一条
        宽口径 `.load(` 后 deserialization 命中从 45 掉到 0，**数字变难看但更真**）。

        ⚠️ 分母是**可命中**（`vuln_total`，已排除无源码用例），**不是**标注总数。
        传进来的 `cats` 若含 `vuln_total == 0` 的类别（本机全无源码 → 没测到），
        它贡献 0 分子 0 分母，不会把召回稀释成假象 —— 但调用方应优先**不传**它们
        （见 `render()` 里对「未测到」类别的单列处理）。
        """
        v = sum(c.vuln_total for c in cats)
        s = sum(c.safe_total for c in cats)
        vh = sum(c.vuln_hit for c in cats)
        sh = sum(c.safe_hit for c in cats)
        kvh = sum(c.kindhit_vuln for c in cats)
        ksh = sum(c.kindhit_safe for c in cats)
        seen = vh + sh
        kseen = kvh + ksh
        return {"vuln_total": v, "safe_total": s, "vuln_hit": vh, "safe_hit": sh,
                "vuln_missing": sum(c.vuln_missing for c in cats),
                "safe_missing": sum(c.safe_missing for c in cats),
                "kindhit_vuln": kvh, "kindhit_safe": ksh,
                "recall": (vh / v) if v else 0.0,
                "recall_kind": (kvh / v) if v else 0.0,
                "precision": (vh / seen) if seen else None,
                "precision_kind": (kvh / kseen) if kseen else None}

    def _gap_lines(self) -> list[str]:
        """把「标注 vs 本机检出」的缺口写成几行。缺口为 0 时返回空表（不加噪音）。"""
        if not self.partial_checkout:
            return []
        pct = self.cases_missing / self.cases_total if self.cases_total else 0.0
        return [
            "",
            f"  ⚠️ **本机检出是部分的**：官方标注 {self.cases_total} 条，"
            f"本机只有 {self.cases_present} 条有源码；",
            f"     另有 {self.cases_missing} 条（{pct:.0%}）**结构上不可能被命中** —— "
            f"它们**不进召回分母**。",
            f"     召回分母 = 标注 ∩ 检出 = {self.cases_present}；"
            f"无源码用例在各类别后以 `[标注另有 N 条无源码，已排除]` 标注。",
            "     （口径变更见本模块 docstring：v069/v070 用全部标注当分母，"
            "**系统性低估**了真实召回。）",
        ]

    def render(self) -> str:
        lines = ["=" * 72]
        lines.append(f"批量基准：{self.name or '(未命名)'}")
        lines.append("=" * 72)
        if self.errors:
            for e in self.errors:
                lines.append(f"  ⚠️ {e}")
            return "\n".join(lines + ["=" * 72])
        lines.append(f"  仓库      = {self.root}")
        lines.append(f"  入库 id   = {self.codebase_id}"
                     f"（文件 {self.file_count} 个；sink 命中 {self.hits_total} 处）")
        lines.append(f"  官方标注  = {self.cases_total} 条；本机有源码 {self.cases_present} 条；"
                     f"被命中的用例文件 {self.cases_hit} 个")
        lines.extend(self._gap_lines())
        lines.append("")

        # ---- 拆三组：有能力且有源码 / 有能力但本机无源码（= 没测到） / 能力外 ----
        covered = [c for c in self.covered if c.vuln_total or c.safe_total]
        untested = [c for c in self.covered
                    if not (c.vuln_total or c.safe_total) and c.vuln_missing]

        lines.append("【本 Agent 有对应规则的类别】")
        t = self.total(covered)
        for c in covered:
            lines.append(c.render())
        lines.append("")
        lines.append("  小计（{n} 个类别）：**召回（本类别 kind）** {kv}/{v} = {kr:.1%}"
                     "   误报 {sh}/{s}   精确性 {p}".format(
                         n=len(covered), kv=t["kindhit_vuln"], v=t["vuln_total"],
                         kr=t["recall_kind"], sh=t["safe_hit"], s=t["safe_total"],
                         p=_fmt_prec_pair(t["precision_kind"], t["precision"])))
        if covered and abs(t["recall_kind"] - t["recall"]) > 1e-9:
            lines.append(f"     （文件级召回 {t['vuln_hit']}/{t['vuln_total']}"
                         f" = {t['recall']:.1%} —— 比 kind 级多出的 "
                         f"{t['vuln_hit'] - t['kindhit_vuln']} 个是**别类规则在同一文件里命中的**，"
                         f"不是本类别规则的功劳）")
        # ⚠️ 这些类别**有规则但本机没有可测的源码** → 报「召回 0%」是把「没测」
        # 说成「0 分」（v067 同族错误）。单列并写明原因。
        if untested:
            lines.append("")
            lines.append("【有规则、但本机无源码可测的类别】—— "
                         "**没测到，不是 0 分**（别把它们读成漏报）")
            for c in untested:
                lines.append(f"  {c.name:<14} 标注 {c.vuln_annotated:4d} 条真漏洞，"
                             f"本机 0 条有源码")
        if self.uncovered:
            lines.append("")
            lines.append("【能力外类别（无对应规则）】—— 低召回属预期，不是缺陷")
            for c in self.uncovered:
                lines.append(f"  {c.name:<14} 命中 {c.vuln_hit:4d}/{c.vuln_total:4d}")
        lines.append("")
        lines.append("  ⚠️ 这不是判决书，是**被测物的体检表**：")
        lines.append("     低召回 = 规则还没覆盖这个形态（多数是**跨行/跨函数**，检索层结构上做不到）；")
        lines.append("     精确性低 = 宽口径规则在裸奔。**两者都要看，只看召回会掩盖误报。**")
        lines.append("")
        lines.append("  口径说明（v071）：")
        lines.append("     · 召回分母 = **可命中**（标注 ∩ 检出），无源码用例已排除；")
        lines.append("     · 精确性主值是 **kind 级**（只算本类别对应的规则）——")
        lines.append("       文件级会把别类规则在同一文件里的命中算成误报，实测差出一倍；")
        lines.append("     · 但 kind 级仍**不判数据流**：安全变体与漏洞变体常常只差"
                     "「参数是否真的可控」，")
        lines.append("       规则命中它们**是对的**（纪律③ sink 命中≠漏洞），要模型往上读才能定论。")
        lines.append("=" * 72)
        return "\n".join(lines)


CANONICAL_NAME = "expectedresults-1.2.csv"


def _fmt_prec_pair(pk: float | None, pa: float | None) -> str:
    """精确性渲染：**kind 级为主**，文件级不一致时在括号里补。

    ⚠️ 为什么 kind 级在前（v071 实测）：文件级口径会把**别的 kind**在同一文件里
    的命中算成本类别的误报，实测把 `crypto` 从 100% 拖到 51%、`hash` 从 100% 拖到 59%。
    把它当主指标会让人得出「规则在疯狂误报」的错误结论。
    文件级仍然保留（它回答「这个文件里有没有可疑代码」，只是**不回答**「本规则准不准」），
    但一致时不重复显示 —— 免得成为噪音。
    """
    if pk is None and pa is None:
        return "（未测）"
    if pk is None:
        return f"文件级 {pa:.1%}"
    if pa is None or abs(pk - pa) < 1e-9:
        return f"{pk:.1%}"
    return f"{pk:.1%}（文件级 {pa:.1%}）"


def load_ground_truth(path: pathlib.Path) -> dict[str, tuple[str, bool, str]]:
    """解析评测集标注 CSV → `{用例名: (类别, 是否真漏洞, CWE)}`。

    约定（OWASP Benchmark 格式，一行一条）：
        BenchmarkTest00001,pathtraver,true,22
    以 `#` 开头的是注释行。**任何坏行跳过而不是报错** —— 标注文件格式漂了
    不该让整批跑不动（宁少不错）。
    """
    out: dict[str, tuple[str, bool, str]] = {}
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) < 3 or not parts[0]:
            continue
        name, cat = parts[0], parts[1]
        if not cat:
            continue
        is_vuln = parts[2].lower() == "true"
        cwe = parts[3] if len(parts) > 3 else ""
        out[name] = (cat, is_vuln, cwe)
    return out


def _csv_of(raw: dict) -> pathlib.Path:
    """定位标注文件：给了文件名就用，否则在仓库根下找 `expectedresults*.csv`。"""
    root = pathlib.Path(raw["dir"])
    name = str(raw.get("ground_truth") or "").strip()
    if name:
        return root / name
    cands = sorted(root.glob("expectedresults*.csv"))
    return cands[0] if cands else root / CANONICAL_NAME


def _case_index(root) -> tuple[set[str], set[str]]:
    """仓库里的文件 → `(全部 stem, 用例候选 stem)`。

    ⚠️ 复用 `ingest.scan_tree` 而**不是**自己 glob。理由：
    `scan_tree` 已经实现了 `SKIP_DIRS` / `MAX_FILES` 等一整套挑选规则 ——
    自己 glob 出来的集合会和**实际入库的集合**不一致，于是分母又错了
    （这类「两处各写一遍同一规则」的错误在本项目已发生多次）。
    用同一个函数，分母就**定义上**等于「入库时真正拿到的文件」。

    为什么取 stem 而不是整路径：官方 CSV 第一列是**用例名**（`BenchmarkTest00001`），
    不含路径。取名 stem 与它对齐；`src/main/java/.../testcode/` 这类目录结构不参与比较。

    ## 两个集合的分工（v071 实测修正）

    - **全部 stem** → 用来算 `cases_unannotated`（**诊断**用）；
    - **用例候选 stem** → 用来算 `cases_present` / `cases_missing`（**分母**用）。

    ⚠️ **为什么必须分开**：实测 OWASP Benchmark 的仓库里有 140 个**非用例**文件
    （`.gitignore`、`results/*.xml`、`scorecard/*.html`、`pom.xml` ……）。
    如果 `cases_unannotated` 拿「全部 stem − 标注」算，它会**恒为 140 左右**，
    于是一个本该是「标注与检出版本不一致」的报警**每轮都响** ——
    假警报比没警报更坏（看的人学会忽略它，真出问题时也看不见了）。

    用例候选的判定：**文件名以 `BenchmarkTest` 开头**。这是 OWASP Benchmark 的
    命名约定，写死在这里是有意的 —— 需要通用化时应当由配置提供（`case_pattern` 字段），
    而不是放宽成「任何 java 文件」（那会让上面那个假警报复活）。
    """
    try:
        from . import ingest as G
        scan = G.scan_tree(root)
    except Exception:                                         # noqa: BLE001
        return set(), set()                                   # 读不到 → 空集（不抛异常）
    all_stems = {pathlib.Path(f).stem for f in scan.files}
    cases = {s for s in all_stems if s.startswith("BenchmarkTest")}
    return all_stems, cases


def load_batches(path: pathlib.Path | None = None) -> list[dict]:
    """读本机评测集配置。文件不存在/解析失败一律返回**空表**（不抛异常）。

    返回空表是正常状态：没配评测集时，报告里那一段直接不出现 —— 不该因此报错。
    """
    p = pathlib.Path(path) if path else BATCH_FILE
    try:
        if not p.exists():
            return []
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:                                        # noqa: BLE001
        return []
    items = raw.get("batches") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict) or not it.get("dir"):
            continue                                        # 缺字段直接忽略（宁少不错）
        raw_dir = pathlib.Path(str(it["dir"]))
        if not raw_dir.is_dir():
            continue                                        # 目录不在（换机器了）→ 跳过
        item = dict(it)
        item["csv"] = str(_csv_of(item))                    # 解析好的标注文件路径
        out.append(item)
    return out


# ---------------------------------------------------------------- 跑分

def run_batch(raw: dict, workspace: pathlib.Path,
              *, register_only: bool = True) -> BatchReport:
    """跑一个评测集：入库 → 建索引 → sink 检索 → 按官方标注算数。

    **只读被测仓库**；入库/索引的落盘位置改到 workspace 下（不碰真实 store）。

    ## v071：分母用「可命中」

    标注里有一部分用例**在本机检出里根本没有源码**（部分检出的评测集）。
    它们结构上不可能被命中，**不计入召回分母**，单列在 `Category.*_missing`。
    可命中的判定靠 `_case_index()`：把检出文件在**仓库内的相对路径 stem 集合**
    与标注名求交 —— 不是靠「路径猜对了没有」。
    """
    from . import ingest as G
    from . import index as I
    from . import search as Q
    from .recall import _patched

    root = pathlib.Path(raw["dir"])
    rep = BatchReport(name=str(raw.get("name") or root.name), root=str(root))

    # `csv` 通常由 `load_batches()` 解析好；直接调用本函数时自己补（少一个必填字段，
    # 少一个「配置里漏写就崩」的坑）。
    csv_path = pathlib.Path(raw["csv"]) if raw.get("csv") else _csv_of(raw)
    rep.csv = str(csv_path)
    truth = load_ground_truth(csv_path)
    if not truth:
        rep.errors.append(f"读不到标注文件（{csv_path}）→ 该批跳过。"
                          f"OWASP Benchmark 的标注在仓库根下 expectedresults-1.2.csv。")
        return rep
    rep.cases_total = len(truth)

    # 类别 → 本 Agent 的 kind。写在配置里（各评测集用词不同，不该硬编码进代码）。
    cat_kind: dict[str, str] = {str(k): str(v)
                                for k, v in (raw.get("category_kind") or {}).items()}

    with _patched(workspace / "_store", workspace):
        r = G.ingest(str(root), codebase_id=f"batch-{rep.name}",
                     source_kind=str(raw.get("source_kind") or "opensource"),
                     register_only=register_only)
        I.build(r.codebase_id)
        hits = Q.search_sinks(r.codebase_id, limit=500_000)

        rep.codebase_id = r.codebase_id
        rep.file_count = r.file_count
        rep.hits_total = len(hits)

        # ---- 可命中集合：标注名 ∩ 检出里的**用例候选**文件 ----
        # ⚠️ 用 `cases`（BenchmarkTest*）而不是 `all_stems`：仓库里还有 140 个
        # 非用例文件（.gitignore / results/*.xml / scorecard/*.html …），
        # 它们既不该进分母、也不该被当成「无标注的用例」报警。详见 `_case_index`。
        all_stems, cases = _case_index(root)
        # `hit_cases` = 被**任何** kind 命中的用例文件（文件级口径）
        # `hit_kind_*` = 被**本类别 kind** 命中的用例文件（kind 级口径）
        # ⚠️ 两个都要：前者回答「这个文件里有没有可疑代码」，
        # 后者回答「**我们为这类专门写的规则**碰到了几个」。缺后者会让精确性趋同、
        # 也让「别类规则的命中」被误读成「本类规则的误报」（v071 实测，见 docstring）。
        hit_cases = {pathlib.Path(h.file).stem for h in hits}
        hit_kinds: dict[str, set[str]] = {}
        for h in hits:
            hit_kinds.setdefault(pathlib.Path(h.file).stem, set()).add(h.kind)

        rep.cases_present = len(set(truth) & cases)
        rep.cases_missing = len(set(truth) - cases)
        rep.cases_unannotated = len(cases - set(truth))
        rep.cases_hit = len(hit_cases & set(truth))

        # 「有用例文件但无标注」正常应为 0。不为 0 说明**标注与检出版本不一致**
        # （比如拿 1.2 的 CSV 配 1.1 的检出）—— 那时召回分子分母都不可信。
        # 不报错（不做环境硬卡点），但必须让看的人知道。
        if rep.cases_unannotated:
            rep.errors.append(
                f"[口径提示] 检出里有 {rep.cases_unannotated} 个用例文件**没有标注**"
                f"（正常应为 0）→ 标注与检出可能不是同一版本，本轮数字仅供参考。")

        by_cat: dict[str, Category] = {}
        for name, (cat, is_vuln, _cwe) in truth.items():
            c = by_cat.setdefault(cat, Category(name=cat, kind=cat_kind.get(cat, "")))
            in_tree = name in cases                        # 本机有没有这个用例的源码
            kind_hit = bool(c.kind) and c.kind in hit_kinds.get(name, ())
            if is_vuln:
                if in_tree:
                    c.vuln_total += 1                      # ← 只有它进分母
                    if name in hit_cases:
                        c.vuln_hit += 1
                    if kind_hit:
                        c.kindhit_vuln += 1
                else:
                    c.vuln_missing += 1                    # 幽灵用例：单列，不进分母
            else:
                if in_tree:
                    c.safe_total += 1
                    if name in hit_cases:
                        c.safe_hit += 1
                    if kind_hit:
                        c.kindhit_safe += 1
                else:
                    c.safe_missing += 1

        # 有规则的排前面（这才是可读的那部分），同类按名字稳定排序
        rep.categories = sorted(by_cat.values(), key=lambda c: (not c.kind, c.name))
    return rep


def evaluate_batches(batches: list[dict] | None = None,
                     workspace: pathlib.Path | None = None) -> list[BatchReport]:
    """跑全部评测集。默认读 `data/recall_batch.json`，没有就返回空表。"""
    if batches is None:
        batches = load_batches()
    tmp = pathlib.Path(workspace) if workspace else pathlib.Path(
        tempfile.mkdtemp(prefix="batch_"))
    tmp.mkdir(parents=True, exist_ok=True)
    out: list[BatchReport] = []
    for b in batches:
        try:
            out.append(run_batch(b, tmp))
        except Exception as e:                                # noqa: BLE001
            r = BatchReport(name=str(b.get("name") or ""), root=str(b.get("dir") or ""))
            r.errors.append(f"该批执行出错：{type(e).__name__}: {e}")
            out.append(r)
    return out


def render_all(reports: list[BatchReport]) -> str:
    if not reports:
        return ("（未配置批量基准 —— 见 data/recall_batch.json.example。"
                "这是**正常状态**：评测集取决于本机有没有检出那份代码。）")
    return "\n\n".join(r.render() for r in reports)
