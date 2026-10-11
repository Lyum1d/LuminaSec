# -*- coding: utf-8 -*-
"""白盒证据闸门（实施规格 §4.3 的**主闸门** / §6 的 `NO_EVIDENCE`·`UNREACHABLE`）。

## 这个文件解决什么

§1.4 说白盒的头号陷阱是「误报被当成发现」，而三种失败模式里**最危险的是纯编造**：
模型直接说出一个不存在的函数、行号或不存在的漏洞。

挡它的机制不是"提醒模型别编"，而是**校验**：

> 模型引用的代码位置，必须能在**白盒工具的历史输出**里被检回。
> 检不回 → 这条只能是候选，并**明确回喂**「你引用的代码没有工具输出背书」。

## ⚠️ 为什么这**不能**做在 `_attribute_failure()` 里

规格 §6 建议把 `NO_EVIDENCE` / `UNREACHABLE` 加进那套归因档位。但它们**没有"工具失败"这个触发点**：

- `NO_EVIDENCE` 的触发点是**记事实时**（模型声称了一条发现，要校验它的依据）——
  属 `add_fact` 链路，不是工具失败；
- `UNREACHABLE` 更是**模型自己声明的判定结果**（"这条路径走不到"），它是 §5 的 P4 产出。

在归因函数里加两个**永远不会被触发的分支**，等于制造「看起来做了、其实没做」的假象。
所以它们落在这里：一个**可测的校验函数** + 一个**有明确格式的标记**。

## 一条容易搞错的地方（本版真踩到）

`agent.attribute_source_step()` 原先把**整个** `BUILTIN_STEP_TOOLS` 排除在"可当证据的步骤"之外，
理由是"内置步骤的 output 是知识库正文/操作回执"。但**白盒工具的输出恰恰是真证据**
（`文件:行号` + 该处代码原文）—— 它被排除后，代码类事实**要么没有溯源、要么被挂到无关的网络步骤上**
（后者更糟：因果图会连出错误的边）。
所以现在把集合拆成两个：路由用的 `BUILTIN_STEP_TOOLS` 与"输出不能当证据"的
`NON_EVIDENCE_BUILTIN_TOOLS`。**同一个集合被两处用、而两处的目的已经分叉** —— 这种情况下必须拆。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: 「不可达」标记前缀 —— **只在这里定义一次**（判定与渲染都用它，
#: 免得两处各写一个字符串、日后改一处漏一处）
UNREACHABLE_PREFIX = "[白盒不可达]"

#: 引用代码位置的形式：`文件:行号`。
#: 路径允许带目录与常见扩展名；行号是纯数字。
CITATION_RE = re.compile(r"([A-Za-z0-9_][\w./\\-]{0,200}?\.[A-Za-z0-9]{1,8}):(\d{1,7})")


@dataclass
class Verdict:
    """校验结果。`status` 为**空串**表示"本条不适用白盒校验"，调用方保持原行为。"""
    status: str = ""                      # "" | candidate | no_evidence
    reason: str = ""
    citations: list[tuple[str, int]] = field(default_factory=list)
    unbacked: list[tuple[str, int]] = field(default_factory=list)

    @property
    def feedback(self) -> str:
        """给模型的回喂（只在检不回时需要）。"""
        if self.status != "no_evidence":
            return ""
        locs = "、".join(f"{p}:{n}" for p, n in self.unbacked[:5])
        return (f"⚠️ **你引用的代码没有工具输出背书**：{locs}\n"
                f"这条已记为**候选**（不是已证事实）。请先用 code_search / code_read "
                f"真正读到这些位置，引用**工具输出里的**原文与行号；"
                f"补不出证据的话，就把它当未证实的线索，不要写进结论。")


def extract_citations(text: str) -> list[tuple[str, int]]:
    """从一段文字里抽出所有 `文件:行号` 引用（去重、保序）。"""
    out: list[tuple[str, int]] = []
    for m in CITATION_RE.finditer(text or ""):
        item = (m.group(1), int(m.group(2)))
        if item not in out:
            out.append(item)
    return out


def backing_texts(steps) -> list[str]:
    """取出可作为证据的**白盒工具输出**。

    ⚠️ 只认 `code_*` 的输出：它们是从受控根里读出来的真实代码内容。
    知识库正文、操作回执、以及网络工具的输出都不算（前者是示例、后者与代码无关）。
    """
    from .tools import ALIASES as CODE_ALIASES
    out = []
    for st in steps or []:
        if getattr(st, "tool_alias", "") in CODE_ALIASES:
            out.append(getattr(st, "output", "") or "")
    return out


def _is_backed(cite: tuple[str, int], texts: list[str]) -> bool:
    """该引用是否被某段工具输出背书。

    两种可接受的形态：
    1. 原样出现 `文件:行号`（`code_search` 的输出就是这个格式）；
    2. 出现**文件名**，且同一段输出里有 `行号`（`code_read` 的输出是
       `   42 | 代码原文` 这种带行号前缀的形式）。
    """
    path, line = cite
    exact = f"{path}:{line}"
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    for t in texts:
        if exact in t:
            return True
        if path in t or base in t:
            if f"| {line} " in t or f"{line} |" in t or f"{line}\t" in t:
                return True
    return False


def verify(content: str, steps) -> Verdict:
    """§4.3 主闸门：校验一条事实里的代码引用能否被工具输出检回。

    **注意它不会把任何东西升成 `verified`** —— 这是刻意的：
    按 §4.3 的表，「模型给出代码片段且确实来自工具输出」**仍然是 candidate**，
    因为**代码存在 ≠ 可达**。能升 verified 的只有：
      · 人工复核（`source=manual`），或
      · 工具输出证实了**完整数据流**（那是判定层的产出，不是这里能判的）。

    所以本函数的职责是**挡住编造**，而不是发通过证。
    """
    cites = extract_citations(content)
    if not cites:
        return Verdict(status="", reason="本条未引用代码位置，不适用白盒证据校验")

    texts = backing_texts(steps)
    if not texts:
        return Verdict(
            status="no_evidence",
            reason="引用了代码位置，但本轮**没有任何白盒工具输出**（没跑过 code_search / code_read）",
            citations=cites, unbacked=list(cites))

    unbacked = [c for c in cites if not _is_backed(c, texts)]
    if unbacked:
        return Verdict(
            status="no_evidence",
            reason=f"{len(unbacked)}/{len(cites)} 处引用在工具输出里检不回",
            citations=cites, unbacked=unbacked)
    return Verdict(
        status="candidate",
        reason=f"{len(cites)} 处引用都能被工具输出检回；"
               f"但**代码存在 ≠ 可达**，仍记候选（要升已证需人工复核或完整数据流证据）",
        citations=cites)


# ---------------------------------------------------------------- UNREACHABLE

def format_unreachable(loc: str, reason: str = "") -> str:
    """把"这条路径走不到"写成一条**可检索、可注入**的事实正文。

    用事实库本身承载它（而不是另建一套状态）：事实本来就会被注入下一轮提示词，
    于是"别再挖这个点"这条信息自动生效 —— **复用既有机制，不另造**。
    """
    r = (reason or "").strip()
    return f"{UNREACHABLE_PREFIX} {loc.strip()} —— {r}" if r else f"{UNREACHABLE_PREFIX} {loc.strip()}"


def is_unreachable(content: str) -> bool:
    return (content or "").lstrip().startswith(UNREACHABLE_PREFIX)


def unreachable_loc(content: str) -> str:
    """从不可达记录里取回位置（供提醒/统计用）。"""
    body = (content or "").strip()
    if not is_unreachable(body):
        return ""
    rest = body[len(UNREACHABLE_PREFIX):].strip()
    return rest.split("——")[0].strip()
