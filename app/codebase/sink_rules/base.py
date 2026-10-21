# -*- coding: utf-8 -*-
"""sink 规则的数据结构与构造器。

单独成文件是为了**避免循环导入**：`sink_rules/__init__.py` 要汇总各语言模块，
而各语言模块又需要 `SinkRule` 类型 —— 类型放这里，两边都只依赖它。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SinkRule:
    id: str                 # 规则标识（稳定，进报告用）
    lang: str               # php | java | python | javascript | *
    kind: str               # rce | sqli | ssrf | path_traversal | deserialization | …
    pattern: str            # 正则（在**单行**上匹配）—— 第一层：行级证据
    why: str                # 为什么危险（帮模型判断影响面）
    hint: str = ""          # 要证明可利用还需看什么（可达性/净化）
    # --- v069：跨行污染（可选）-----------------------------------------------
    #
    # ## 为什么必须分成**两个** pattern
    #
    # `pattern` 只在**单行**匹配，因此「先拼到局部变量、再传给 sink」这种写法
    # 在结构上必漏：
    #
    #     String sql = "{call " + param + "}";      // ← 危险在这里
    #     stmt = conn.prepareCall(sql);             // ← 本行括号内只有变量名
    #
    # 实测 OWASP Benchmark：sqli 类别 272 个真漏洞，只靠 `pattern` 命中 **0** 个。
    #
    # ## 踩过的坑（v069 第一版是死代码）
    #
    # 第一版把「taint 判据」挂在 `pattern` **不匹配**的 else 分支上，并新增了一条
    # 平行规则 `java.sqli.tainted_var`（pattern = 只匹配调用名、不要求 `+`）。
    # 结果是**整层从未生效**，而且暴露了两个问题：
    #
    # 1. **逻辑自相矛盾**：`pattern` 不匹配本行 → 本行压根没有这个调用 → 无从判「括号里」。
    #    taint 分支永远不会被正确触发；
    # 2. **平行规则裸奔**：那条「故意写宽的 pattern」变成了第一层的宽口径规则，
    #    于是 `executeQuery(任何东西)` 全部命中（实测 112 处，extractor 全是 `lexical`
    #    而不是 `taint`）—— **看着像 taint 在干活，其实完全没有**。
    #
    # ## 正确做法：`call_pattern` + 一行产出「最多两条命中」
    #
    # - `call_pattern`：**只描述「哪次调用危险」**（调用名本身），不含参数要求；
    # - 第一层用 `pattern`（严格：调用 + 参数里就有危险成分）→ 命中即 **行级证据**；
    # - 第二层用 `call_pattern` 命中 + **括号内含污点变量**（由 `taint.py` 推出）
    #   → 命中即 **跨行证据**，`why`/`hint` 明确标注这是间接形态。
    #
    # 两层**在同一行上可以并存**（行级命中不再吞掉 taint 命中），
    # 因为它们是**证据强度不同**的两条线索，都应交给模型。
    call_pattern: str = ""
    """只匹配「危险调用的调用名」的正则；**不要求**参数里有危险成分。

    留空表示本规则不参与跨行污染检测（默认）—— **不要滥用**：
    每开一条就多一类命中，且放进来的是**间接形态**（更弱，需要模型往上追）。
    """
    # --- v071：调用者变量（可选）---------------------------------------------
    #
    # ## 第三类结构性漏报：sink 的**调用者本身**是个变量
    #
    #     Runtime r = Runtime.getRuntime();
    #     Process p = r.exec（cmd + param）;      // ← `_CMD_CALL` 完全匹配不到
    #
    # ⚠️ 上面刻意用**全角括号**：规则文件本身是 `.py`，写半角 `(` 会被 `py.rce.eval`
    # 自己命中（v079 实测踩到）。`test_079` 里加了「规则库自命中必须为 0」的守卫。
    #
    # `call_pattern` 解决的是「**参数**是变量」（值在别处拼好）；
    # 这里解决的是「**调用者**是变量」（执行器在别处取得）。两者正交：
    # 前者靠「括号里有没有污点变量」判，后者靠「调用者是不是执行器变量」判。
    #
    # ⚠️ 为什么不放宽 `pattern`：把带 `Runtime.getRuntime()` 前缀的写法改成裸方法名
    # 会匹配任意对象的 `exec` 方法 → 裸奔（v069 删宽口径 `.load` 的同族教训）。
    # 正确做法是**变量层面的类型判定** —— 由 `search.py` 配合 `taint.py` 的
    # `runners` 集合完成。
    runner_pattern: str = ""
    """匹配「调用者是变量」的危险调用，**第一个捕获组必须是调用者名**。

    命中后由 `search.py` 查 `taint.runners`：只有当那个变量确实持有命令执行器
    （`Runtime.getRuntime()` / `new ProcessBuilder(...)`）时才产出命中。
    """
    _rx: re.Pattern | None = field(default=None, compare=False, repr=False)
    _crx: re.Pattern | None = field(default=None, compare=False, repr=False)
    _rrx: re.Pattern | None = field(default=None, compare=False, repr=False)

    def regex(self) -> re.Pattern:
        if self._rx is None:
            # 大小写**敏感**：`Exec` 与 `exec` 在多数语言里是不同的东西，不能一律放宽。
            # 需要忽略大小写的地方在 pattern 里显式写 `(?i)`。
            object.__setattr__(self, "_rx", re.compile(self.pattern))
        return self._rx

    def call_regex(self) -> re.Pattern | None:
        """跨行污染专用的「调用名」正则；未配置时为 `None`。"""
        if not self.call_pattern:
            return None
        if self._crx is None:
            object.__setattr__(self, "_crx", re.compile(self.call_pattern))
        return self._crx

    def runner_regex(self) -> re.Pattern | None:
        """调用者变量专用的正则（**必须含一个捕获组** = 调用者名）；未配置为 `None`。"""
        if not self.runner_pattern:
            return None
        if self._rrx is None:
            object.__setattr__(self, "_rrx", re.compile(self.runner_pattern))
        return self._rrx


def rule(rid: str, lang: str, kind: str, pattern: str, why: str, hint: str = "",
         call_pattern: str = "", runner_pattern: str = "") -> SinkRule:
    return SinkRule(rid, lang, kind, pattern, why, hint, call_pattern, runner_pattern)
