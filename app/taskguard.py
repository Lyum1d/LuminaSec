# -*- coding: utf-8 -*-
"""任务级约束闸门（v048）。

## 要解决的问题（2026-09-25 某企业站实战）

任务书里明确写了「**不做字典爆破**」，Agent 仍然调用了 OneForAll：
**95247 词**字典 + massdns，实测跑出 14 个子域。

为什么拦不住：OneForAll 是 L0/L1 → **闸门自动放行**。
而风险闸门只看「工具的静态风险等级」，**完全不知道这次任务的约束是什么**。

结果是**双输**：纪律上违反公益 SRC「最小必要」；收益上 OneForAll 的输出还被截断，
14 个子域最终只拿到 HTML 里实引用的 3 个 —— **代价付了，收益没拿到。**

## 与 v047「交互式工具」问题的区别（值得分清）

| | 谁的问题 | 怎么解 |
|---|---|---|
| v047 交互式工具 | **工具属性**：它交给人用，模型用不了 | 从模型可见清单里剔除 |
| v048 任务约束 | **任务属性**：工具能用，但这次不该用 | 任务侧声明 + 闸门处兑现 |

前者一次修好永久有效；后者**每个任务都可能不同**，所以必须是运行期的机制。

## 设计

1. 从任务文本里解析**显式禁令** —— 只有明确写出来的才算，**不猜**；
2. 禁令映射到**能力标签**（caps）。标签是**工具属性**，在 `data/tool_overrides.json`
   里**显式声明**（与 `network_control` 同一套做法：配置即文档、可复核、
   改 JSON 要留注释）。**刻意不用「工具名/描述关键词」去猜能力** ——
   那会双向出错：`goon` 名字里有「爆破」好办，`fscan` 名字里没有却同样是扫描器；
3. 任何具备被禁能力的工具：**直接拒绝执行**，给出可执行替代，并在每轮提醒里重申。

## 为什么是「拒绝」而不是「降级为需确认」

约束来自操作者自己写下的指令。降级为确认的话，无人值守时审批器会等满宽限期再拒绝
—— **同一个结果，多烧一步 + 90 秒**（该轮实测每次宽限 90s）。
如果的确需要该能力，操作者改任务书即可，不需要模型去试探。

## 假阳性的处理

最容易被误判的是这类**提醒句**：「禁止扫描/访问未授权主机或内网」——
它是在划范围，不是在禁止扫描本身。故匹配后会检查上下文，
命中「未授权 / 授权范围 / 范围外 / 越权 / 内网」则跳过（见 `_NEG_CONTEXT`）。
宁可漏拦（回到今天的行为），不可误拦（会把整类工具废掉）。
"""
from __future__ import annotations

import re
from typing import Any

# 能力标签。**新增标签时必须同时在 data/tool_overrides.json 的 _说明 里登记**，
# 否则守卫测试会红（见 test_048_fixes.py 的 [C] 组）。
CAP_BRUTEFORCE = "bruteforce"   # 字典爆破 / 枚举：子域、目录、口令
CAP_SCAN = "scan"               # 主动批量扫描（对一个目标发起成规模的探测）

CAP_LABEL = {
    CAP_BRUTEFORCE: "字典爆破/枚举",
    CAP_SCAN: "主动批量扫描",
}

# 禁令句式 → 能力标签。**只认明确的否定句**，不做语义推断。
# 每条都写成宽松的「动词 + 对象」形态，配合 _NEG_CONTEXT 排除「划范围」的提醒句。
_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # 「不做/禁止/不要/不得/不使用 …… 爆破」：覆盖「不做字典爆破」「不做目录爆破式扫描」
    (re.compile(r"(?:不做|不进行|不采用|不使用|禁止|不要|不得|不搞|skip)"
                r"[^\n。；，]{0,8}?(?:爆破|暴力破解|暴破)"), CAP_BRUTEFORCE, "爆破"),
    # 「不做 …… 枚举」（子域枚举、目录枚举）
    (re.compile(r"(?:不做|不进行|不采用|不使用|禁止|不要|不得)"
                r"[^\n。；，]{0,8}?枚举"), CAP_BRUTEFORCE, "枚举"),
    # 「不跑/不用 大字典」（该任务书里的原话之一）
    (re.compile(r"不(?:跑|用|使用|加载|依赖)[^\n。；，]{0,4}?(?:大)?字典"),
     CAP_BRUTEFORCE, "字典"),
    # 「不做/禁止 …… 扫描 / 探测」
    (re.compile(r"(?:不做|不进行|不采用|不使用|禁止|不要|不得)"
                r"[^\n。；，]{0,8}?(?:扫描|探测)"), CAP_SCAN, "扫描"),
    # 「不并发」（对应的工具能力标签暂未建立，仅登记，不参与拦截）
    (re.compile(r"不(?:要|做)?并发"), CAP_SCAN, "并发"),
]

# 命中「划范围」语境的就跳过：这些句子的重点在**范围**，不在禁止动作本身。
# 例：「代码内 HTTP 请求只允许发往当前授权目标及其资产，禁止扫描/访问未授权主机或内网」
_NEG_CONTEXT = ("未授权", "授权范围", "范围外", "越权", "内网", "超范围", "非授权")
_NEG_WINDOW = 14


def parse(text: str) -> dict[str, str]:
    """从任务文本解析显式禁令。返回 {能力标签: 命中的原文片段}。

    同一标签多次命中只留第一条（越靠前越可能是「本任务的要求」，
    而不是后面的补充说明）。
    """
    out: dict[str, str] = {}
    src = text or ""
    for pat, cap, _kind in _PATTERNS:
        if cap in out:
            continue
        for m in pat.finditer(src):
            lo = max(0, m.start() - _NEG_WINDOW)
            hi = min(len(src), m.end() + _NEG_WINDOW)
            ctx = src[lo:hi]
            if any(k in ctx for k in _NEG_CONTEXT):
                continue                     # 划范围的提醒句，不算禁令
            out[cap] = m.group(0).strip()
            break
    return out


def merge(a: dict[str, str] | None, b: dict[str, str] | None) -> dict[str, str]:
    """合并两组约束（后续消息不会把先前声明的禁令抹掉）。a 优先。"""
    out: dict[str, str] = dict(b or {})
    out.update(a or {})
    return out


def violation(constraints: dict[str, str] | None,
              caps: list[str] | None) -> tuple[str, str] | None:
    """工具是否违反任务级约束。违反返回 (能力标签, 命中的原文片段)，否则 None。"""
    if not constraints or not caps:
        return None
    for cap, hit in constraints.items():
        if cap in caps:
            return cap, hit
    return None


def describe(constraints: dict[str, str] | None) -> str:
    """给模型看的一行约束说明（空串表示无约束）。"""
    if not constraints:
        return ""
    items = []
    for cap, hit in constraints.items():
        items.append(f"{CAP_LABEL.get(cap, cap)}（任务原话「{hit}」）")
    return "、".join(items)


def refusal_message(tool_name: str, cap: str, hit: str) -> str:
    """拒绝时回给模型的话。必须**给出可执行替代**，否则模型只会重试。"""
    label = CAP_LABEL.get(cap, cap)
    alternatives = {
        CAP_BRUTEFORCE: ("改用被动来源：目标页面 HTML / JS 里实引用的域名与路径、"
                         "证书透明度（crt.sh）类公开数据、`sitemap.xml`、`robots.txt`；"
                         "或先用 `py_exec` + `safe_http_request` 对**已知**入口做单点确认。"
                         "**不要**换成另一个爆破类工具重试。"),
        CAP_SCAN: ("改用点对点确认：`httpreplay` 或 `py_exec` + `safe_http_request`，"
                   "对**已发现的具体路径**逐个验证，每次请求都能解释为什么发。"
                   "**不要**换成另一个扫描器重试。"),
    }
    return (f"未执行：{tool_name} 具备「{label}」能力，而本任务已声明禁用"
            f"（任务原话「{hit}」）。\n{alternatives.get(cap, '请改用手工的、可解释的替代做法。')}")
