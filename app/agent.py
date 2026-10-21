# -*- coding: utf-8 -*-
"""Agent 编排层：ReAct 单步决策循环。

为什么是「单步」而不是「一次规划全部步骤」：
  实测 qwen3.5:9b 在被要求一次规划多步时，只输出文字方案、不产生 tool_calls。
  因此这里每次只让模型决定「下一步用哪个工具」，执行完把结果回喂，再问下一步。
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import config, store
from . import skillpack                                # v120：提示词条款改为从技能包/文件加载
from . import graph
from . import kb, fofa
from .codebase import tools as codebase_tools          # v063 白盒 code_* 的执行体
from .codebase import evidence as codebase_evidence    # v064 白盒证据主闸门
from .codebase.tools import ALIASES as CODE_TOOL_ALIASES
from . import pyexec
from . import pyexec_grade
from . import taskguard
from . import replayer
from . import burp_tools
from . import mcp_client
from .executor import executor
from .intel import format_intel, update_intel_from_steps
from .llm import (auto_route_candidate, failover_backend, get_backend,
                  is_retryable_error, parse_tool_arguments)
from .registry import registry
# 主机形态识别（域名/IP/URL 判定）与「假 TLD」清单统一收敛在 app/scope.py：
# 与 py_exec 的 target 校验共用同一套口径，避免「一边认、一边不认」的静默缺口。
from .scope import FAKE_TLDS as _FAKE_TLDS

logger = logging.getLogger(__name__)

# 「记忆类」内置工具：它们不走风险闸门，但**必须留下步骤记录**。
# 否则「读了哪篇知识库 / 记了哪条事实 / 搜了什么关键词」在 steps 表里完全不可见：
#   ① 不进「本轮已尝试过的工具」提醒 → 模型可能反复读同一篇、反复搜同一个词；
#   ② search_history 只搜 steps 表 → 这些动作检索不到；
#   ③ 审计层面没有任何痕迹（只有 SSE 里一闪而过的 reasoning）。
# 这个集合决定「走不走风险闸门」（旁路、但必须留痕）。
# ⚠️ 它**不再**兼任「输出能不能当证据」的判据 —— 那个用途已拆到下面的
# `NON_EVIDENCE_BUILTIN_TOOLS`（两者目的不同，混用会让白盒事实挂错溯源）。
BUILTIN_STEP_TOOLS = frozenset({
    "note_fact", "search_history", "propose_branch", "split_task",
    "kb_search", "kb_read", "fofa_search",
    # 白盒 code_*（v063）：纯本地只读，同样走旁路但**必须留痕**。
    # 别名从 `app/codebase/tools.py` 的 ALIASES 取 —— **只定义一次**，
    # 免得 registry 的 specs、这里的集合、以及 handler 的分派三处各写一份、迟早漂移。
    *CODE_TOOL_ALIASES,
})

#: 「输出**不能**当工具执行证据」的内置工具。
#:
#: 白盒 `code_*` **刻意不在此列**：它们的输出是从受控根里读出来的**真实代码**
#: （含 `文件:行号` 与原文），是货真价实的工具执行证据；
#: 而 `kb_read` 的正文是知识库示例、`note_fact`/`search_history` 的回执是操作记录。
#:
#: ⚠️ 这两个集合的**用途不同，别混用**：
#:   · `BUILTIN_STEP_TOOLS`（12 个）→ 决定「走不走风险闸门」（都走旁路、都留痕）；
#:   · `NON_EVIDENCE_BUILTIN_TOOLS`（7 个）→ 决定「它的输出能不能当证据」。
#: 同一个集合被两处用、而目的已经分叉 —— 这种情况必须拆，否则白盒事实要么没有溯源、
#: 要么被挂到无关的网络步骤上（因果图会连出错误的边）。
NON_EVIDENCE_BUILTIN_TOOLS = BUILTIN_STEP_TOOLS - frozenset(CODE_TOOL_ALIASES)

# 白盒 NO_EVIDENCE 计数（v064）。
# 规格 §6 建议把它**计入统计** —— 「模型编了」从一句无从衡量的直觉，
# 变成一条结构化、可计数的事件，用来判断白盒能力是否在退化。
# 用单元素列表而非全局 int：便于在函数里原地自增（Python 的闭包/全局语义在这容易写错）。
_NO_EVIDENCE_COUNT = [0]


# 记忆注入上限（值在 config 里，可用环境变量调；超限会在注入块尾部写明未展示条数）
FACT_INJECT_MAX = config.FACT_INJECT_MAX
RECORD_INJECT_MAX = config.RECORD_INJECT_MAX
BRANCH_INJECT_MAX = config.BRANCH_INJECT_MAX

_OUTPUT_GAP = "\n…（中略 {n} 字符；落库版本保留了首尾，细节可用 search_history 检索）…\n"


def clip_output(text: str) -> str:
    """步骤输出落库前的裁剪：**保留头 + 尾**，中间折叠。

    此前只存尾部（`output[-2000:]`），于是工具开头的关键结果永久丢失 ——
    而命中统计、存活清单首屏恰恰常在输出最前面；同时上下文压缩又告诉模型
    「可用 search_history 检索」，等于给了一张兑不了现的空头支票。
    """
    s = text or ""
    head, tail = config.STEP_OUTPUT_HEAD, config.STEP_OUTPUT_TAIL
    if len(s) <= head + tail:
        return s
    return s[:head] + _OUTPUT_GAP.format(n=len(s) - head - tail) + s[-tail:]


def restore_messages(sid: str) -> list[dict]:
    """把落库的对话原文还原成「可续聊的 messages」。

    为什么需要：`adopt()` 重建会话时原先只搬 steps/target/summary/records，
    唯独漏了 messages —— 于是「继续聊」时模型对之前所有轮次零记忆，
    而前端仍能从 chat_messages 看到完整对话，人和模型看到的历史不一致。

    只还原对话层（用户原话 + 模型说明/结论）。工具输出不在 chat_messages 里，
    由 steps 表、情报库、已证事实库另行注入，这里不重复搬运。
    """
    try:
        rows = store.list_chat_messages(sid)
    except Exception:
        logger.exception("续聊记忆恢复失败")
        return []
    out: list[dict] = []
    for m in rows[-config.RESTORE_CHAT_MAX:]:
        text = (m.get("content") or "").strip()
        if not text:
            continue
        role = "assistant" if m.get("role") == "assistant" else "user"
        text = text[: config.RESTORE_CHAT_CHARS]
        # 相邻同角色合并：还原出的历史里常出现连续多条 assistant（reasoning + answer），
        # 严格的 OpenAI 兼容端点对这种序列不接受，合成一条最稳。
        if out and out[-1]["role"] == role:
            out[-1]["content"] += "\n" + text
            continue
        out.append({"role": role, "content": text})
    return out


# ============================================================================
# 系统提示词：按「职责」拆成片段，再由 compose_system_prompt() 拼装。
#
# 为什么拆：原来是一整块 60 多行的常量，改任何一处都只能整块动，容易误伤别的段落；
# 而且「红线 / SOP / 工具纪律」这些职责边界在源码里根本看不见，审查时无从判断
# 改动的性质。拆开之后每段有名字、可单独 review、也可按需增删（见 compose 的 extra）。
#
# 【重要】默认拼装结果与拆分前**逐字一致**（test_agent_smoke 有断言守着），
# 即这次拆分对模型行为零影响——重构不改变任何提示内容，只改变代码组织方式。
# ============================================================================

# 角色 + 工作原则：一步一动、事实纪律、工具名不许编造
# ── 提示词条款加载（v120：条款已从源码搬到 data/prompt/*.md + 技能包）──
# ⚠️ 条款**不再是源码里的字面量** —— 它们是产品最核心的打法 IP。
#    发布版只放加密技能包（data/skills.pack），源码里 grep 不到任何条款原文。
def _clause_candidates(name: str) -> list[Path]:
    """条款的可选来源（按优先级）。**目录在调用时才算**，不能在导入时固化。

    ⚠️ 踩过的坑（2026-10-21）：最初写成模块级 `_CLAUSES_DIR = config.DATA_DIR / "prompt"`，
    于是一批测试在**导入 agent 之前**把 `config.DATA_DIR` 改道到临时目录做隔离
    ⇒ 条款找不到 ⇒ 直接拒绝启动，3 个套件连锁红。
    ⇒ 候选里必须包含**包根目录**（`config.APP_DIR/data/prompt`），它不随运行时改道变化。
    """
    yield config.DATA_DIR / "prompt" / f"{name}.md"
    yield config.APP_DIR / "data" / "prompt" / f"{name}.md"


def _clause(name: str) -> str:
    """取一段条款：**技能包优先 → data/prompt/<name>.md（开发版）→ 拒绝启动**。

    两者都没有就**拒绝启动**：宁可起不来，也不能让合规红线悄悄变空
    （没有红线的 agent 比不能启动的 agent 危险得多）。
    """
    txt = skillpack.get(f"prompt/{name}.md")
    if txt is None:
        for p in _clause_candidates(name):
            if p.exists():
                txt = p.read_text(encoding="utf-8")
                break
    if txt is None or not txt.strip():
        raise RuntimeError(skillpack.missing_clause_hint()
                           + f"（缺失条款：{name}；已找过："
                           + " / ".join(str(p) for p in _clause_candidates(name)) + "）")
    # ⚠️ 两条来源的**尾换行必须统一剥掉**：文件来源在打包时补过一个 "\n"，
    # 包来源里也带着它。若只对其中一条 strip，同一个条款在「工程库(读文件)」与
    # 「发布版(读包)」下会差 1 个字符 —— 拼出的提示词不再逐字一致
    # （2026-10-21 实测踩到：redlines 3141 vs 3142）。
    return txt.rstrip("\n")


_P_ROLE_PRINCIPLES = _clause("role_principles")

# 合规红线：优先级最高的硬闸门，触线即停手
# v035：按补天「公益 SRC」规则重写并扩写——原 6 条保留内核，补齐「最小影响 / 轻量测试 /
#       禁止核心业务接口自动化遍历与并发 / 拿到即停 / 禁止保存数据」这几处缺口。
_P_REDLINES = _clause("redlines")

# 对话树：开分支 / 检索历史 / 任务分片并行
_P_BRANCH = _clause("branch")

# 知识库与测绘：打法索引、安全红线、FOFA 种子闭环、报告闸门
_P_KB_FOFA = _clause("kb_fofa")

# Web 站点渗透 SOP：先手工后工具，不可跳步
_P_WEB_SOP = _clause("web_sop")

# 工具清单占位符 + 风险等级说明（tool_list 由 registry 注入）
_P_TOOLS = _clause("tools")


_P_CODEBASE = _clause("codebase")


# 片段的排列顺序 = 提示词里的出现顺序，改动顺序等于改动提示语义，不要随手调
_SYSTEM_FRAGMENTS = (
    _P_ROLE_PRINCIPLES,
    _P_REDLINES,
    _P_BRANCH,
    _P_KB_FOFA,
    _P_WEB_SOP,
    _P_CODEBASE,
    _P_TOOLS,
)


def compose_system_prompt(*extra: str) -> str:
    """按顺序拼装系统提示词；可在末尾追加可选片段（按模式或场景启用）。

    片段之间用空行分隔；结尾保留一个换行（与拆分前的字面量逐字一致）。
    追加的 extra 请自带开头换行，例如 "\n\n【X】..."。
    """
    return "\n\n".join(_SYSTEM_FRAGMENTS) + "\n" + "".join(extra)


SYSTEM_PROMPT = compose_system_prompt()


# ---------------------------------------------------------------------------
# v102：工作模式片段
# ---------------------------------------------------------------------------
# 用 compose_system_prompt 的 **extra** 位置追加，**不动 _SYSTEM_FRAGMENTS 的顺序**
# —— 那个顺序等于提示语义，动它会牵连全部既有行为（见上方注释）。
# 约定：extra 自带开头换行（"\n\n"）。
_P_MODE_BLACKBOX = _clause("mode_blackbox")

_P_MODE_WHITEBOX = _clause("mode_whitebox")


def mode_fragment(mode: str) -> str:
    """按模式返回要追加到系统提示末尾的片段（未知模式返回空串）。"""
    if mode == "whitebox":
        return _P_MODE_WHITEBOX
    if mode == "blackbox":
        return _P_MODE_BLACKBOX
    return ""


# 目标参数中出现这些特征，说明模型把说明文字当成了目标。
# 注意（v023.6 修）：`?`/`？` 这类单字符模式**只对非 URL 目标**检查——
# URL 的查询串天然含 `?`，此前带参 URL 一律被判「说明性文字」而无法执行
# （实测 httpreplay 带 `?attguid=...` 的完整 URL 被拒，被误记为「长度上限」）。
_BAD_TARGET_PATTERNS = ("请提供", "请用户", "请确认", "请输入", "未知", "待定", "？", "?", "示例")


def _budget_note(budget: dict) -> str:
    # 预算感知（2026-09-16）：把「已用/剩余步数 + 已跑时长」明确写进上下文。
    # 不写这段时，模型不知道自己还剩几步，常把预算耗在重复试探上，最后在上限处被硬截断——
    # 结论没拿到，工具调用也白花。剩余步数不多时切换成「强制收敛」口径。
    total = int(budget.get("total") or 0)
    step_no = int(budget.get("step_no") or 0)
    done = max(step_no - 1, 0)
    left = max(total - done, 0)
    mins, secs = divmod(int(budget.get("elapsed") or 0), 60)
    elapsed = f"{mins} 分 {secs} 秒" if mins else f"{secs} 秒"
    head = (f"\n\n【执行预算】第 {step_no}/{total} 步（已完成 {done} 步，含本步尚余 {left} 步），"
            f"本轮已运行 {elapsed}。")
    tok = int(budget.get("tokens") or 0)
    tok_cap = int(budget.get("token_budget") or 0)
    tok_warn = False
    if tok and tok_cap:
        head += f"累计 token {tok:,}/{tok_cap:,}。"
        # v041：**token 预算也要预警**（原实现只按步数预警）。
        # 实测教训（某高校 第三轮）：步数还有余（17/30）但 token 先超（811,983/800,000），
        # 预警根本没触发 → 直接硬熔断 → **测绘做完了却没输出任何结论**。
        # 现在达到预警比例就先要求收敛，给模型一个「先把结论写出来」的机会。
        tok_warn = tok >= tok_cap * config.TOKEN_BUDGET_WARN_RATIO
    # v041：给出「已发目标请求数」的确数（目标流量是合规纪律里最敏感的额度）
    req = int(budget.get("requests") or 0)
    if req:
        head += f"本轮已发出目标请求 {req} 次。"
    if (total and left <= config.BUDGET_REMIND_AT) or tok_warn:
        why = "步数" if (total and left <= config.BUDGET_REMIND_AT) else "token"
        return head + (
            f"预算即将耗尽（{why}口径），必须立刻收敛：优先把手上已有证据整理成结论并调用 halt_task 收尾；"
            "不要再开启新的扫描面，也不要再发起长耗时的工具调用。"
            "若确有未完成的关键动作，只保留最重要的一个，做完立即给结论。"
        )
    return head + "预算充足，按最优顺序推进即可。"


def _facts_note(session) -> str:
    """v023.7：把项目**已证实事实**注入每轮上下文，供跨线索复用。

    为什么必须有（某企业站 实战）：第一轮已证实的事实（CMS 后端入口、免权限
    控制器可达…）在第二轮只能靠**人工写进任务书**复述——平台不注入，模型要么
    重新发现（浪费预算与流量），要么在压缩后彻底失忆。这里把 verified 事实
    自动带上，candidate（未经确认）不注入，避免把猜测当既定前提。
    """
    if not config.INJECT_FACTS or not getattr(session, "project", ""):
        return ""
    try:
        facts = store.list_facts(session.project)
    except Exception:
        logger.debug("注入事实失败", exc_info=True)
        return ""
    if not facts:
        return ""
    verified = [f for f in facts if (f.get("status") or "") == "verified"]
    if not verified:
        return ""
    # 最近的在前（list_facts 已按时间倒序），限制条数与单条长度
    items = verified[: config.INJECT_FACTS_MAX]
    lines = []
    for f in items:
        c = (f.get("content") or "").strip().replace("\n", " ")
        if not c:
            continue
        lines.append(f"- {c[:config.INJECT_FACTS_CHARS]}")
    if not lines:
        return ""
    more = len(verified) - len(items)
    tail = f"（另有 {more} 条见项目事实库）" if more > 0 else ""
    return ("\n\n【项目已证实事实（前序线索产出，可直接采信，**不要重复验证**）】\n"
            + "\n".join(lines) + tail)


def _traffic_note(target: str) -> str:
    """v023.4 目标流量预算提示：把「目标还剩多少请求额度、是否被防护拦截」
    写进上下文。

    理由与 _budget_note 同源：模型不知道自己还能发多少请求，就会持续扩大
    测试面——直到预算耗尽被强制暂停（甚至触发目标封禁）。把余量摆在眼前，
    模型才能主动收敛（计划 11.1 第 8 条：追加探测必须消耗可见的请求预算）。
    """
    try:
        from . import traffic as _traffic
        root = _traffic.governor.root_domain_of(target or "")
        if not root:
            return ""
        st = _traffic.governor.stats(root)
        state = st.get("state", _traffic.ST_NORMAL)
        remaining = st.get("remaining", 0)
        used = st.get("used", 0)
        win = int(st.get("window_seconds", 600) // 60)
        line = (f"\n\n【目标流量预算】{root}：{win} 分钟窗口内已用 {used}/"
                f"{st.get('max_requests')} 请求，剩余 {remaining}。")
        if state != _traffic.ST_NORMAL:
            return line + (f"**当前状态 {state}（{st.get('reason', '')[:80]}）——"
                           "已停止自动请求，不要换参数/换工具/换子域名继续尝试；"
                           "请保存证据并等待人工恢复。**")
        if remaining <= max(2, int(st.get("max_requests", 30)) * 0.2):
            return line + ("剩余额度很低，必须收敛：只做最能验证当前假设的少量请求，"
                           "不要开启新扫描面，不要并行拆分。")
        return line + "请保持低频、单变量推进。"
    except Exception:
        logger.debug("流量预算提示构造失败", exc_info=True)
        return ""


def _budget_exhausted_note(session, total: int) -> str:
    # 步数耗尽时的收尾：给出「跑到哪了」的归因，而不是一句干巴巴的「已达最大步数」。
    ok = sum(1 for st in session.steps if st.status == "done")
    bad = sum(1 for st in session.steps if st.status == "error")
    attr: dict = {}
    for st in session.steps:
        if st.attribution:
            attr[st.attribution] = attr.get(st.attribution, 0) + 1
    dist = "、".join(f"{k} {v} 次" for k, v in sorted(attr.items())) or "未归类"
    if attr.get("SCOPE"):
        tail = ("注意：本轮出现过 SCOPE 拒绝（授权白名单拦截），属授权边界问题，"
                "不要靠把该目标加进白名单来重试，除非已取得新的书面授权。")
    else:
        tail = ("未完成的部分建议开新线索继续，或调大环境变量 AGENT_MAX_STEPS 后重跑；"
                "调大只放宽步数上限，不改动风险闸门与限速。")
    return (f"已达到最大步数 {total}，停止执行。本次共执行 {len(session.steps)} 个步骤"
            f"（成功 {ok} / 失败 {bad}），失败归因分布：{dist}。\n{tail}")



# 目标串两端可能粘上的「装饰字符」。
# 为什么需要：用户常把目标写在 Markdown 行内代码或强调里 —— `` `https://a.com/` ``、
# `**https://a.com/**`。正则的字符集排除的是空白与中文标点，反引号与星号都是
# **合法的 URL 字符**，于是会被吞进匹配结果。
# 实测代价（2026-09-22，DB 里 5 个会话中招）：
#   'https://www.tgt-e.test/`'  /  '**https://www.tgt-e.test/**'  /  'https://`（得到'
# 这些串**能通过** `validate_target` 与 `_is_host_like`（主机部分仍解析得出来），
# 于是一路流到执行层：请求变成对路径 `` /` `` 的访问 → 404 → 模型据此得出
# 「该路径不存在」的**错误结论**。脏数据比报错更危险。
#
# 关键取舍：**ASCII 的 `(` `)` 不放进终止符集**。它们是合法 URL 字符
# （`/p(1)` 这种路径真实存在），一旦当终止符就会把正确输入截断 ——
# 我第一版就是这么写的，自测立刻抓到 `https://a.test/p(1)` → `https://a.test/p`。
# Markdown 链接 `](url)` 造成的多余右括号，改由下面的「配对剥离」处理。
_TARGET_TERMINATORS = "".join([
    r"\s", "，。；、",
    "（）【】「」『』《》〈〉“”‘’",     # 全角标点：URL 里不可能出现，可安全终止
    "`*\"'<>",                        # 装饰/引号：同上
])
_TARGET_TAIL_STRIP = "`*\"'“”‘’「」『』【】《》〈〉"
# 末梢配对标点：只有当「右括号多于左括号」时才从尾部剥掉。
# 这样 `](https://a.com/)` → 剥掉多余的 `)`；而 `https://a.test/p(1)` 保持不动。
_TARGET_PAIRS = {")": "(", "]": "[", "}": "{"}


def _clean_target(s: str) -> str:
    """剥掉目标串两端的装饰字符与多余的末梢右括号。"""
    t = (s or "").strip().strip(_TARGET_TAIL_STRIP).strip()
    while t:
        last = t[-1]
        left = _TARGET_PAIRS.get(last)
        if not left:
            break
        # 右括号多于左括号 → 这个右括号是外层的语法符号，不是 URL 的一部分
        if t.count(last) > t.count(left):
            t = t[:-1]
        else:
            break
    return t.strip().strip(_TARGET_TAIL_STRIP).strip()


def extract_target(text: str) -> str:
    """从用户任务描述中提取目标（URL / IP / 域名）。

    本地小模型在工具执行失败后常「忘记」目标并反问用户，
    因此这里主动提取一次，在每轮决策时重申。
    """
    if not text:
        return ""

    # 终止字符集要点：中文标点要**左右两侧都排**（早期只排了 `）)`，于是
    # '`https://a.com/`（apex' 会把 `（apex` 一起吞进来）；装饰字符也要排
    # （反引号、成对书名号/引号）—— 详见 _TARGET_TERMINATORS 说明。
    m = re.search(r"https?://[^" + _TARGET_TERMINATORS + r"]+", text)
    if m:
        cand = _clean_target(m.group(0))
        # 剥完装饰后若已不成形（例如原文只有 "https://`（得到"），
        # 不要返回半截串 —— 继续往下试 IP / 域名两个分支。
        if cand:
            return cand

    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", text)
    if m:
        return m.group(0)

    for m in re.finditer(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", text):
        cand = m.group(0)
        tld = cand.rsplit(".", 1)[-1].lower()
        if tld in _FAKE_TLDS:
            continue
        return cand
    return ""


def _is_host_like(target: str) -> bool:
    """判断目标是否像 URL / IP / 域名（而非企业名等自由文本）。

    复用 extract_target 的域名/假 TLD 规则（该规则现已与 app/scope.py 的
    主机判定共用同一份 FAKE_TLDS），保证「从消息提取目标」与「执行前授权校验」
    对同一个串的看法一致：「test.json」这类文件扩展名会被判为 False，不会被误当域名。
    """
    t = (target or "").strip()
    if not t:
        return False
    return extract_target(t) == t


def validate_target(target: str) -> str | None:
    """校验目标参数。返回 None 表示合法，否则返回原因。

    本地小模型常见问题：把「请用户提供目标域名或IP」这类说明文字当作 target 传进命令行。
    """
    if not target:
        return "目标为空"
    # v023.6（实战反馈）：带查询串的完整 URL 很容易超过 120 字符，被误判为
    # 「目标过长」而无法执行（实测 httpreplay 被挡）。URL 形态放宽到 2000，
    # 非 URL 目标保持 120 的严格上限（防小模型把自然语言当目标）。
    if "://" in target:
        if len(target) > 2000:
            return (f"URL 过长（{len(target)} 字符 > 2000）。"
                    "请把查询串拆到工具的 -d/--data 参数里，而不是塞进 target。")
    elif len(target) > 120:
        return f"目标过长（{len(target)} 字符）"
    if target.count(" ") >= 2:
        return "目标包含多个空格，疑似自然语言句子"
    # URL 形态：跳过 `?`/`？` 与「示例」以外的单字符模式（查询串合法含 ?）
    _is_url = "://" in target
    _patterns = (("请提供", "请用户", "请确认", "请输入", "未知", "待定", "示例")
                 if _is_url else _BAD_TARGET_PATTERNS)
    if any(p in target for p in _patterns):
        return f"目标包含说明性文字「{target[:30]}」"
    # URL 形态的目标不允许任何空白（审计 P0-3）：'https://授权域/ evil.com' 这类
    # 夹带会绕过 target_host（空格落在 path 里）并在渲染后被 shlex 切成第二个目标。
    # 企业名等非 URL 目标不受影响（中文企业名天然无空白；含空格的英文名仍可走
    # 企业名扩展工具，此处仅拦 URL 形态）。
    if "://" in target and re.search(r"\s", target):
        return "URL 目标中包含空白字符，疑似夹带多个目标"
    return None


# ---------- markdown 代码块兜底解析 ----------
# 背景：qwen3.5:9b 有时把工具调用写成 ```bash 代码块而不产生真正的 tool_calls，
# 或产生 name="tool_call" 的畸形调用（被拦截报「不存在的工具」）。
# 这里从输出文本里做文本级恢复，能救回一轮决策，避免空转催促。

_CODE_FENCE_RE = re.compile(r"```[a-zA-Z]*[ \t]*\r?\n(.*?)```", re.S)
_TARGET_FLAGS = {"-u", "--url", "-t", "--target"}

# 上下文压缩标记：已压缩过的消息不再重复压缩（保证幂等）
_COMPRESSED_PREFIX = "〔已压缩〕"

# 关键命中行特征（v023.6）：压缩时优先保留这些行，而不是只留输出首行。
# 背景（某企业站 实战）：ehole 的指纹命中位于输出中后部，压缩只留首行后
# **证据不可再引用**，模型只能把指纹记为「候选」。这里改成按特征挑行 +
# 自动落一条**候选**事实（带 step_id 溯源），压缩后仍可回查。
_KEY_LINE_PATTERNS = (
    r"CVE-\d{4}-\d+",
    r"\b(nginx|apache|iis|tomcat|jetty|spring|struts|shiro|weblogic|jboss|"
    r"php|jsp|aspx|layui|jquery|vue|react|bootstrap|ace|jqgrid|ztree|"
    r"bws|safedog|waf|cdn)\b",
    r"(?i)(fingerprint|识别|指纹|命中|匹配|powered by|x-powered-by|server)",
    r"<title>.{0,80}</title>",
    r"HTTP[/ ]?\d\.\d|\b(200|301|302|403|404|500)\b",
    r"\.(js|json|do|action|jsp|php|aspx|xml|txt)(\?|$|\s|')",
    r"\b(v?\d+\.\d+(\.\d+)?)\b",
)
_COMPRESS_KEY_MAX = 3          # 每步最多保留的关键行数
_COMPRESS_KEY_CAP = 220        # 单行最多字符

# 失败归因分层用的特征词（借鉴 LuaN1ao 的 L0–L5 递进归因，此处只取 L1/L3/L4 三档）
# L1 = 工具根本没跑起来（措辞取自 executor / pyexec / replayer 的实际报错文案）
_L1_HINTS = ("超时", "超过总时长", "已终止", "无法启动", "启动异常", "执行异常",
             "无法连接", "请求失败", "找不到指定的文件")
# L3 = 连得上但被环境或权限拦下
_WAF_HINTS = ("403", "401", "429", "waf", "forbidden", "unauthorized", "access denied",
              "blocked", "captcha", "验证码", "拦截", "速率限制", "too many requests")


def _parse_tool_from_markdown(content: str) -> dict | None:
    """从模型输出的 markdown 代码块里恢复工具调用。

    支持 ```bash / ```json 两种形式；第一个 token 必须能解析为真实工具，
    否则返回 None（防止把普通说明性代码块误当成调用）。
    返回 {"name": alias, "arguments": {"target": ..., "args": ...}}。
    target/args 交给 build_command 管线清洗（剥重复旗标、剥非法 flag、剥引号）。
    """
    if not content or "```" not in content:
        return None
    for m in _CODE_FENCE_RE.finditer(content):
        block = m.group(1).strip()
        if not block:
            continue

        # --- json 形式：{"name": ..., "arguments": ...} 或 {"function": {...}} ---
        if block.lstrip().startswith("{"):
            try:
                data = json.loads(block)
                fn = data.get("function") or data
                name = fn.get("name") or fn.get("tool")
                if name:
                    tool, _ = registry.resolve(str(name))
                    if tool is not None:
                        args = fn.get("arguments") or fn.get("args") or {}
                        if isinstance(args, str):
                            args = parse_tool_arguments(args)
                        return {"name": tool.alias, "arguments": args if isinstance(args, dict) else {}}
            except Exception:
                pass
            continue

        # --- bash / shell 形式：第一个 token 视为工具名 ---
        tokens = [t for t in block.split() if not t.startswith("#")]
        # 去掉 shell 提示符（"$ oneforall ..." / "$ domain.com ..."）
        while tokens and tokens[0] in ("$", "#"):
            tokens = tokens[1:]
        if not tokens:
            continue
        name = tokens[0].lstrip("$").strip()
        if not name or name.startswith("-"):
            continue
        tool, _ = registry.resolve(name)
        if tool is None:
            continue

        rest = tokens[1:]
        target = ""
        for i, t in enumerate(rest):
            if t in _TARGET_FLAGS and i + 1 < len(rest):
                target = rest[i + 1].strip("'\"")
                break
            mt = re.match(r"^(?:-u|--url|--target)=(.+)$", t)
            if mt:
                target = mt.group(1).strip("'\"")
                break
        if not target:
            target = extract_target(block)
        return {
            "name": tool.alias,
            "arguments": {"target": target or "", "args": " ".join(rest)},
        }
    return None


@dataclass
class Step:
    id: str
    tool_alias: str
    tool_name: str
    target: str
    args: str
    risk: dict
    status: str = "pending"  # pending | running | done | denied | error | cancelled
    output: str = ""
    # 失败归因档位。**成功时为空**。
    #   · 执行失败（status=error）走 `_attribute_failure` 的分层：
    #     SCOPE | WAF_BLOCKED | WAF_CAUTION | NETWORK | L1 | L3 | L4
    #   · 被闸门拒绝（status=denied）走 v111 新增的三档，用于区分是**哪道闸门**：
    #     GATE_SUBTASK（并行子任务禁 L2/L3）| GATE_CONSTRAINT（任务级约束）|
    #     GATE_RISK（人工未确认）
    #     ⚠️ v111 之前的旧数据这一栏是空的 —— 控制台会把它单独归成
    #     「闸门拒绝·未标注」，不要当成"没归因"。
    attribution: str = ""
    started_at: float | None = None
    finished_at: float | None = None


@dataclass
class Session:
    id: str
    project: str = ""
    messages: list[dict] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    events: asyncio.Queue = field(default_factory=asyncio.Queue)
    control: asyncio.Queue = field(default_factory=asyncio.Queue)
    # 当前正在等待人工确认的步骤登记项：{"step_id","token","double_confirm"}。
    # /confirm 必须先比对它——否则超时未被取走的、或用户连点产生的确认会落到
    # 「下一次」确认上，等于用户没看过的高危步骤被静默放行。
    pending_confirm: dict | None = None
    state: str = "idle"  # idle | running | awaiting_confirm | done | error
    target: str = ""     # 从任务描述中提取的目标，每轮重申防止模型遗忘
    nudges: int = 0      # 已催促次数，防止无限追问
    think_streak: int = 0  # 连续「只想不做」（think）的轮数，防止用思考代替动手
    created_at: float = field(default_factory=time.time)
    # ---- 对话树（线索分支）----
    parent_id: str = ""              # 父会话 id，根线索为 ''
    title: str = ""                  # 线索名
    records: list[str] = field(default_factory=list)  # 开分支时打包带来的记录
    summary: str = ""                # 最近一轮结论摘要（写回父对话/供其他线索引用）
    subtask: bool = False            # 是否由 split_task 派生的并行子任务（子任务内禁 L2/L3）
    # v102 工作模式：blackbox | whitebox。决定两件事：
    #   （a）模型可见的工具集（registry.mode_allows —— 白盒只放 code_*，黑盒排除 code_*）
    #   （b）系统提示末尾追加哪个模式片段（见 _P_MODE_*）
    # **必须落库**：与 subtask / constraints 同理 —— adopt 续聊或服务重启后模式若丢失，
    # 白盒会话会突然拿到黑盒的 197 个工具（反之亦然），而库表上看不出任何异常。
    mode: str = "blackbox"
    builtin_calls: list[str] = field(default_factory=list)  # 用过的内置工具（不产生 Step 的也要留痕）
    # 当前正在等待用户确认的步骤 id。确认通道是「一次一步」的交互式，
    # 必须有归属才能拒绝「陈旧/伪造/重复」的确认指令（详见 _await_confirm）。
    pending_step_id: str = ""
    # ---- 取消（v011 P1-5 / v012 后半硬终止）----
    # 软取消：在步骤边界与确认等待处响应。正在执行的工具步骤让它跑完
    # （单步本就有总时长上限），不中途硬杀——硬终止需要把取消信号穿透
    # 执行器进程管理，另行迭代。
    # ⚠️ 必须用 threading.Event 而不是 asyncio.Event：Session 可能在某个
    # 事件循环里创建、在另一个循环里运行（adopt 恢复/测试多次 asyncio.run），
    # asyncio.Event 跨循环 wait 会抛 "bound to a different event loop"
    # （实测踩中）。threading.Event 的 is_set/set 无循环绑定，执行器侧
    # 只需轮询 is_set()，完全等价。
    cancel_event: "threading.Event" = field(default_factory=threading.Event)
    # ---- 任务级约束（v048）----
    # 从任务文本里解析出的**显式禁令** → 能力标签，如 {"bruteforce": "不做字典爆破"}。
    # 为什么挂在会话上：约束是**每个任务各不相同**的，系统提示里写不了；
    # 而闸门每步都要读它（见 app/taskguard.py 的实测复盘：L0 的 OneForALL 自动放行，
    # 任务书写了「不做字典爆破」也拦不住）。必须落库，否则 adopt 续聊后闸门静默失效。
    constraints: dict = field(default_factory=dict)
    # 事件落库游标：emit 时由 store.save_event 返回并回填到事件里（_seq），
    # 供 SSE 断线重放去重（Last-Event-ID 之后只发增量）。
    last_seq: int = 0

    async def emit(self, event: dict) -> None:
        # 事件同步落库（v011 P1-5）：断线/刷新后可按 Last-Event-ID 重放。
        # 落库失败不阻断实时流（数据库异常时退化为旧行为，只丢重放能力）。
        try:
            seq = store.save_event(self.id, event)
            if seq:
                self.last_seq = max(self.last_seq, seq)
                event = {**event, "_seq": seq}
        except Exception:
            pass
        await self.events.put(event)


def _exc_brief(e: Exception) -> str:
    """把模型调用异常压缩成一行可读摘要（事件流/日志用，别把堆栈甩给用户）。"""
    s = str(e or "").strip()
    s = re.sub(r"\s+", " ", s)
    if len(s) > 120:
        s = s[:117] + "…"
    return s or type(e).__name__


def attribute_source_step(session: "Session", content: str) -> str:
    """给一条「已证事实」找它**真正的来源步骤**。

    原实现是 `session.steps[-1].id` —— 取「当前最后执行的那一步」，而不是「产出这条事实的那一步」。
    同一步内连记多条事实没问题，但只要模型是「执行 A → B 之后才回头记 A 的产出」，
    事实就会挂到 B 上，因果图随之连出 `Evidence(B) --REVEALS--> KeyFact(其实来自 A)` 的错误边。
    实测上一轮侥幸正确（两条事实确实都源自 ehole），那是巧合，不是机制保证。

    这里改成**按内容回查找证**：事实正文里的 token 能在哪一步的输出里找到，就归到那一步
    （从最近往前找）；找不到再回退到「最近的一个非内置步骤」，语义与原来一致但更贴近事实。
    """
    if not session.steps:
        return ""
    # 不能当证据的内置步骤（知识库正文 / 操作回执）要排除；
    # ⚠️ 但**白盒 code_* 不排除**（v064）—— 它们的输出是从受控根读出的真实代码，
    # 正是白盒事实该有的溯源依据。用 `NON_EVIDENCE_BUILTIN_TOOLS` 而不是
    # `BUILTIN_STEP_TOOLS`，否则代码类事实会挂到无关的网络步骤上、因果图连错边。
    steps = [st for st in session.steps if st.tool_alias not in NON_EVIDENCE_BUILTIN_TOOLS]
    if not steps:
        # v064：这里原先回退到 `session.steps[-1].id`，但上面那句注释写的是
        # 「回退到最近的一个**非内置**步骤」—— 代码与注释不一致，而后果正是注释警告的事：
        # 把事实挂到知识库/操作类步骤上，因果图连出 `Evidence(kb_read) → KeyFact` 的错误边；
        # 更麻烦的是它会因「有 step_id」而让这条事实被判成 **verified**（冒充已证）。
        # 没有可用作证据的步骤时**宁缺勿错**：不给溯源，事实自然落到 candidate。
        return ""
    tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9._:/-]{3,}", content or "")[:8]
    if tokens:
        for st in reversed(steps):
            out = st.output or ""
            if out and all(t in out for t in tokens):
                return st.id
        for st in reversed(steps):
            out = st.output or ""
            if out and sum(1 for t in tokens if t in out) >= 2:
                return st.id
    return steps[-1].id


class SessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}

    def create(self, project: str = "", parent_id: str = "", title: str = "",
               records: list[str] | None = None, subtask: bool = False,
               mode: str = "blackbox") -> Session:
        sid = uuid.uuid4().hex[:12]
        s = Session(id=sid, project=project, parent_id=parent_id,
                    title=title, records=list(records or []), subtask=subtask,
                    mode=(mode or "blackbox"))
        self.sessions[sid] = s
        return s

    def adopt(self, sid: str) -> Session | None:
        """从持久化层恢复已有会话（对话树切换线索/服务重启后续聊）。

        内存里已有则直接返回；store 里也没有返回 None。
        历史步骤一并装回：续聊时「已尝试过的工具」提醒、开分支的记录挑选都依赖它。
        **对话原文也一并装回**（见下方 restore_messages）——否则「继续聊」就是一个失忆的会话。
        """
        s = self.sessions.get(sid)
        if s:
            return s
        rec = store.get_session(sid)
        if not rec:
            return None
        row = rec["session"]
        try:
            records = json.loads(row.get("context") or "[]")
        except Exception:
            records = []
        s = Session(
            id=sid,
            project=row.get("project_id") or "",
            parent_id=row.get("parent_id") or "",
            title=row.get("title") or "",
            records=records if isinstance(records, list) else [],
            # 必须恢复：subtask=True 时 run() 会拒绝 L2/L3（并行子任务无人应答确认框）。
            # 丢了标记等于让「子任务内禁高危操作」这道闸门失效。
            subtask=bool(row.get("subtask") or 0),
            # v102：模式也必须装回（同理且更要紧）—— 丢了它，白盒会话会突然拿到
            # 黑盒的 197 个工具、并带上黑盒的系统提示，而库表上看不出异常。
            mode=row.get("mode") or "blackbox",
        )
        s.target = row.get("target") or ""
        s.state = "idle"
        s.summary = row.get("summary") or ""
        # v048：任务级约束必须装回 —— 它是**闸门依据**，丢了闸门就静默失效
        # （与上面 subtask 同一个道理，见 store.py 的 subtask 注释）。
        try:
            s.constraints = json.loads(row.get("constraints") or "{}")
        except Exception:                                # noqa: BLE001
            s.constraints = {}
        # 续聊记忆：把落库的对话原文装回 messages。
        # 少了这一步，「切回线索继续聊」等于失忆 —— 模型看不到任何历史轮次（用户原话、
        # 自己的判断、结论全丢），而前端依然能从 chat_messages 回放完整对话，
        # 于是人和模型看到的历史不一致，用户会以为「它记得」。
        s.messages = restore_messages(sid)
        for st in rec["steps"]:
            s.steps.append(Step(
                # 剥掉 store.save_step 为防主键撞号加过的「会话id:」前缀，
                # 还原成原始 tool_call_id —— 上下文压缩要靠它与 role=tool 消息配对。
                id=(st.get("id") or uuid.uuid4().hex[:12]).removeprefix(f"{sid}:"),
                tool_alias=st.get("tool_alias") or "",
                tool_name=st.get("tool_name") or "",
                target=st.get("target") or "",
                args=st.get("args") or "",
                risk={"level": st.get("risk_level") or ""},
                status=st.get("status") or "done",
                output=st.get("output") or "",
                attribution=st.get("attribution") or "",
                # 库里存的是 finished_at(=created_at) 与 elapsed，用差值反推 started_at，
                # 这样 _step_dict 还原出来的耗时与原次一致。
                started_at=(st.get("created_at") or 0) - float(st.get("elapsed") or 0),
                finished_at=st.get("created_at"),
            ))
        self.sessions[sid] = s
        return s

    def get(self, sid: str) -> Session | None:
        return self.sessions.get(sid)

    def remove(self, sid: str) -> Session | None:
        """从内存中移除会话（彻底删除分支时同步清理）。"""
        return self.sessions.pop(sid, None)


sessions = SessionManager()


def l4_no_output_feedback(tool_name: str, raw_output: str) -> str:
    """「执行成功但无任何输出」时回喂给模型的内容（归因 L4）。

    v053（审计 §2.1）修 + **抽成纯函数**：
      · 原实现直接赋值覆盖，把原始输出整条丢掉 —— 退出码 0 但输出全是 `[错误]` 行时，
        执行器的真实报错被吞，模型只看到「这面不存在」而换方向（正确动作是修参数/换工具）；
      · 抽出来的理由是可测：这段逻辑原本内联在约 750 行的 `run()` 里，
        审计方只能**复刻**一段等价代码来举证（那证明不了真实代码的行为）。
        现在测试可以直接断言「原文必须出现在回喂内容里」。
    """
    raw = raw_output or "（工具无输出）"
    return (
        f"【{tool_name} 执行成功但无任何输出｜归因 L4】"
        f"原始输出：\n{raw}\n"
        "（若上面出现 `[错误]` 行，那是执行器在报错而**不是**「目标不存在该测试面」——"
        "先按报错原文修参数或换工具。）\n"
        "若确实没有任何输出，这可能说明目标不存在该测试面。"
        "不要用同样参数重复调用，换一个方向或换一种手法再验证。"
    )


class Agent:
    def __init__(self, backend_name: str | None = None) -> None:
        # 不在初始化时钉死后端：留 None，run() 时取运行时当前后端，
        # 这样前端切换模型后无需重启服务即对新任务生效。
        self.backend_name = backend_name
        # v044：MCP（Burp）可用性探测时间戳。0 表示「还没探过」——不能用
        # 默认的「很久以前」来初始化，否则第一次会被 20 秒缓存窗口挡掉。
        self._mcp_probe_at: float = 0.0

    # ---------- 主循环 ----------
    async def run(self, session: Session, user_message: str,
                  max_steps: int | None = None, allow_split: bool = True) -> None:
        session.state = "running"
        session.messages.append({"role": "user", "content": user_message})
        # 对话历史落库：切线索回放时可见用户原始消息
        try:
            store.save_chat_message(session.id, "user", user_message)
        except Exception:
            logger.exception("用户消息落库失败")
        session.target = extract_target(user_message)
        # ---- 任务级约束解析（v048）----
        # 从任务文本里读**显式禁令**（只有明确写出来的才算，不猜），映射成能力标签，
        # 供闸门在每步之前核对。merge 而非覆盖：用户可能分几条消息说要求，
        # 后面的补充不该把先前声明的禁令抹掉。
        if config.TASK_CONSTRAINTS_ENABLED:
            session.constraints = taskguard.merge(
                session.constraints, taskguard.parse(user_message))
            if session.constraints:
                logger.info("本任务生效的约束：%s", session.constraints)
        # 项目里显式填写的「目标」优先：用户建项目时填的常是纯企业名/域名，
        # 而任务描述往往只说「做信息收集」之类，模型从消息里识别不出目标。
        proj = store.get_project(session.project) if session.project else None
        proj_target = (proj.get("target") or "").strip() if proj else ""
        if proj_target and not session.target:
            # 项目 target 由用户在界面手填，可能混入「待定」「请提供」这类说明文字。
            # 原先直接赋值，问题要拖到工具执行前才以「目标参数无效」的形式暴露，
            # 打断模型决策。这里先过一遍格式校验，让它在任务开始时就失败得明明白白。
            # 注意：这是「提前失败」，不替代下方工具执行前的 validate_target 兜底，
            # 两处调用的是同一个函数、同一套参数，不存在任何放宽。
            bad_proj_target = validate_target(proj_target)
            if bad_proj_target:
                logger.warning("项目目标未采用（%s）：%r", bad_proj_target, proj_target)
            else:
                session.target = proj_target
        # 立即落库，避免中途关闭页面导致整轮记录丢失（树字段一并带上，
        # 分支线索在首次运行后就出现在小地图上）
        # ⚠️ v115 修：**必须带 `mode`**。此前这里传了 parent_id/title/subtask/constraints
        # 却漏了 mode —— 而这是**首次**落库（`sessions.create` 只建内存对象），
        # 所以 INSERT 分支永远写默认值 ⇒ **白盒会话在库里被存成 blackbox**。
        # 后果是双重的：① 重启后 `adopt()` 读回 blackbox，白盒会话拿到黑盒的 197 个工具
        # 与黑盒提示词；② 控制台「项目/会话」列表按 mode 过滤时看不到它。
        # 全程不报错 —— 与 `constraints`/`subtask` 是同一类「闸门依据没落库」的静默失效。
        store.save_session(session.id, session.project, user_message, session.target,
                           "running", parent_id=session.parent_id, title=session.title,
                           subtask=session.subtask, constraints=session.constraints,
                           mode=session.mode)
        await session.emit({"type": "session_start", "session_id": session.id})
        backend = get_backend(self.backend_name)
        # 漏洞验证类任务自动路由云端：本地小模型在多步推理上明显吃力，
        # 云端模型（已验证 function calling）决策质量高一个量级。未配 Key 时自动回退。
        # 路由目标可在「设置 → 模型供应商」里改（默认 deepseek），也可关闭自动路由。
        if self.backend_name is None and config.AUTO_ROUTE_VULN:
            cloud = auto_route_candidate(backend.name)
            if cloud and any(k in user_message.lower() for k in config.VULN_KEYWORDS):
                backend = cloud
                await session.emit({
                    "type": "reasoning",
                    "data": f"检测到漏洞验证类任务，本次决策自动路由到「{cloud.label}」"
                            "（可在设置 → 模型供应商里关闭自动路由）",
                })
        await session.emit({
            "type": "model",
            "data": {
                "backend": backend.name,
                "model": getattr(backend, "model", ""),
                "label": getattr(backend, "label", backend.name),
                "local": bool(getattr(backend, "local", backend.name == "ollama")),
            },
        })
        if session.target:
            await session.emit({"type": "target", "data": session.target})
        # v102：工具清单按模式过滤（与 build_schemas 同源，保证「清单里写了」=「schema 里给了」），
        # 并在末尾追加模式片段（走 compose_system_prompt 的 extra 机制）。
        system = SYSTEM_PROMPT.format(tool_list=registry.alias_reference(session.mode))
        system += mode_fragment(session.mode)
        # v022（整改报告 P2-5）：schema 因配额被截断的工具，明确告知模型
        # 「它们存在但本轮不可用」——否则模型会凭空否认工具存在或臆造调用格式。
        omitted = list(registry.last_omitted_aliases)
        if omitted:
            system += ("\n\n【配额省略说明】以下工具因本轮 schema 配额限制未列出详情，"
                       f"如需使用请先说明需求由用户确认：{', '.join(omitted)}。"
                       "不要假设它们的参数格式，更不要声称它们不存在。")
        # 注入项目上下文（名称/目标/备注），让模型在首轮就明确目标，无需再向用户索要
        if proj:
            ctx_lines: list[str] = []
            if proj.get("name"):
                ctx_lines.append(f"项目名称：{proj['name']}")
            if proj.get("target"):
                ctx_lines.append(f"项目目标：{proj['target']}")
            if proj.get("note"):
                ctx_lines.append(f"项目备注：{proj['note']}")
            if ctx_lines:
                system += (
                    "\n\n【当前项目上下文】\n" + "\n".join(ctx_lines) + "\n"
                    "以上「项目目标」即本次任务的默认目标，直接使用，不要再向用户索要目标；"
                    "若用户任务里另有更具体的域名/IP/URL，则以任务里的为准。"
                    "目标是企业名时用可用工具（如 app_info）扩展资产，不要调用已禁用的 enscan。"
                )
        # 注入项目情报库：历史会话沉淀的子域/API/技术栈，避免重复收集
        if session.project:
            system += format_intel(store.get_intel(session.project))

            # 注入已证事实库（note_fact / 人工登记），已证实内容无需重复验证。
            # v012 P1-1：只注入 verified——candidate（AI 记录且无溯源背书）不能
            # 冒充「已证」喂回给模型自我强化；数量附在提示里供 review。
            try:
                _all_facts = store.list_facts(session.project)
                _facts = [f for f in _all_facts
                          if (f.get("status") or "verified") == "verified"]
                _cand_n = sum(1 for f in _all_facts
                              if f.get("status") == "candidate")
                if _facts:
                    _fl = "\n".join(f"- {f['content']}" for f in _facts[:FACT_INJECT_MAX])
                    if len(_facts) > FACT_INJECT_MAX:
                        # 超出上限原先是无提示的：模型既不知道「还有更多」，
                        # 也没动机去检索，于是会重复收集已经查过的东西。
                        _fl += (f"\n（另有 {len(_facts) - FACT_INJECT_MAX} 条未展示；"
                                f"需要时用 search_history 按关键词检索事实库）")
                    if _cand_n:
                        _fl += (f"\n（另有 {_cand_n} 条候选事实待人工复核，"
                                f"不得直接当作已证结论引用）")
                    system += (
                        "\n\n【已证事实库（工具输出已证实，可直接引用、不得推翻或重复验证；"
                        "报告中基于这些事实组织结论）】\n" + _fl
                    )
            except Exception:
                logger.exception("已证事实注入失败")
        # 注入对话树上下文：①本线索开局打包记录 ②同项目其他线索的进展摘要。
        # 目的：单对话过长会遗忘细节，把方向拆到独立线索里深挖，跨线索信息按需取用。
        if session.records:
            rec_lines = "\n".join(f"- {r}" for r in session.records[:RECORD_INJECT_MAX])
            if len(session.records) > RECORD_INJECT_MAX:
                rec_lines += f"\n（另有 {len(session.records) - RECORD_INJECT_MAX} 条未展示）"
            system += (
                "\n\n【本线索开局背景（从上级对话打包带来的已查记录，可直接引用，"
                "不要重复验证，也不要质疑其真实性）】\n" + rec_lines
            )
        if session.project:
            try:
                _others = [t for t in store.list_tree(session.project)
                           if t["id"] != session.id and (t.get("summary") or t.get("task"))]
                if _others:
                    _ol = []
                    for t in _others[:BRANCH_INJECT_MAX]:
                        name = t.get("title") or (t.get("task") or "")[:24] or "未命名线索"
                        brief = t.get("summary") or (t.get("task") or "")[:80]
                        _ol.append(f"- 线索《{name}》（{t.get('status', 'active')}）：{brief}")
                    if len(_others) > BRANCH_INJECT_MAX:
                        _ol.append(f"（另有 {len(_others) - BRANCH_INJECT_MAX} 条线索未展示）")
                    system += (
                        "\n\n【同项目其他线索的进展（并行推进的其他对话，详情可用 "
                        "search_history 工具按关键词检索，不要臆测其内容）】\n" + "\n".join(_ol)
                    )
            except Exception:
                logger.exception("线索树上下文注入失败")
        consecutive_failures = 0
        tokens_used = 0        # 本次任务累计 token（成本熔断用）
        failover_count = 0     # 本次任务已自动切换供应商次数（防雪崩上限）
        tried_backends: list[str] = []   # 已失败过的供应商（故障转移排除名单）
        switch_nudged = False  # 「换策略」提醒是否已发过（成功一次后重新武装）
        tools_used = False     # 本次任务是否已实际执行过工具（收尾免催促的依据）
        halted_answer: str | None = None  # halt_task 的结论；非 None 表示模型主动收尾
        session.nudges = 0     # 催促计数按轮重置：催促防护对每轮任务独立生效
        step_budget = max_steps or config.MAX_STEPS
        run_started = time.time()  # 本轮墙钟起点：只用于预算提示，不作为闸门

        for step_no in range(1, step_budget + 1):

            # ---- 取消检查（v011 P1-5 软取消）----
            # 步骤边界处响应：正在跑的那一步让它跑完（单步有总时长上限），
            # 取消后走 persist_interrupted 留半程摘要，成果不归零。
            if session.cancel_event.is_set():
                await session.emit({"type": "reasoning", "data": "（已收到取消请求，正在收尾…）"})
                self._persist_intel(session)
                self.persist_interrupted(session, reason="用户取消")
                session.state = "done"
                await session.emit({"type": "cancelled", "data": "任务已被用户取消"})
                await session.emit({"type": "done", "state": "done"})
                return
            # ---- 时间预算熔断（v011 P1-6）----
            # token 预算管钱、步数管轮次，都不管墙钟时间：一个死循环式的
            # 「工具失败→重试→再失败」任务能无限烧下去。超时按中断处理。
            if getattr(config, "RUN_TIME_BUDGET", 0) and \
                    time.time() - run_started > config.RUN_TIME_BUDGET:
                self._persist_intel(session)
                self.persist_interrupted(session, reason=f"时间预算耗尽（>{config.RUN_TIME_BUDGET}s）")
                session.state = "done"
                await session.emit({"type": "reasoning",
                                    "data": f"任务运行超过时间预算（{config.RUN_TIME_BUDGET}s），已停止。"
                                            "半程成果已沉淀，可开新线索继续。"})
                await session.emit({"type": "done", "state": "done"})
                return
            # 先做上下文压缩：长任务里 session.messages 会一路膨胀，把较早的工具输出
            # 压成一行摘要，避免小模型被早期细节淹没（详见 docs/LuaN1ao对比分析.md §2）。
            self._compress_history(session)
            # 每轮重建提醒：小模型在工具失败后容易「忘记」目标并反问用户，
            # 而且会反复调用同一个刚失败的工具，必须显式告诉它试过了什么。
            # v041：把「本轮已发目标请求数」也带进上下文 —— 模型原本不知道自己花了
            # 几次目标请求，只能靠估算自我约束（实测自述「贴近上限是估的」）。
            # 目标流量是合规纪律里最敏感的额度，应当给出确数而非估算。
            try:
                _sent_total = int(
                    (store.traffic_summary(session.project) or {}).get("total_sent") or 0
                ) if session.project else 0
            except Exception:
                _sent_total = 0
            reminder = self._build_reminder(session, budget={
                "step_no": step_no,
                "total": step_budget,
                "elapsed": time.time() - run_started,
                "tokens": tokens_used,
                "token_budget": config.RUN_TOKEN_BUDGET,
                "requests": _sent_total,
            })
            # v044：每轮刷新「依赖外部服务的工具」可用性 —— Burp 可能中途被关掉
            # 或刚被启动。失败即视为不可用（build_schemas 会把它们摘掉），
            # 避免模型在必然失败的工具上空转掉步数。
            await self._refresh_external_tools()
            messages = [{"role": "system", "content": system + reminder}] + session.messages

            await session.emit({"type": "thinking", "step": step_no,
                                "data": f"第 {step_no} 步：正在决策…"})
            _t0 = time.time()
            # ---- 调用模型：指数退避重试 + 供应商故障转移（v011 P1-6）----
            # 可重试错误（连接失败/超时/429/5xx）按指数退避重试；重试耗尽且
            # 还有备用供应商时自动切换（切换原因进事件流，模型决策不中断）。
            # 不可重试错误（Key 无效/请求错误）原样上抛，重试只是原样再错。
            result = None
            try:
                for attempt in range(config.LLM_RETRY_MAX + 1):
                    try:
                        result = await backend.chat(messages, tools=registry.build_schemas(mode=session.mode))
                        break
                    except Exception as e:
                        if session.cancel_event.is_set():
                            raise
                        if attempt >= config.LLM_RETRY_MAX or not is_retryable_error(e):
                            raise
                        delay = config.LLM_RETRY_BASE_DELAY * (2 ** attempt)
                        await session.emit({
                            "type": "reasoning",
                            "data": f"（模型调用失败：{_exc_brief(e)}；{delay:.0f}s 后重试"
                                    f" {attempt + 1}/{config.LLM_RETRY_MAX}）"})
                        await asyncio.sleep(delay)
            except Exception as e:
                # 重试耗尽：尝试故障转移到其他可用供应商
                failover = None
                if is_retryable_error(e) and failover_count < config.LLM_FAILOVER_MAX:
                    failover = failover_backend([backend.name] + tried_backends)
                if failover is None:
                    await session.emit({"type": "error", "data": f"模型调用失败：{e}"})
                    session.state = "error"
                    await session.emit({"type": "done", "state": "error"})
                    return
                tried_backends.append(backend.name)
                failover_count += 1
                await session.emit({
                    "type": "reasoning",
                    "data": f"供应商「{backend.label}」重试 {config.LLM_RETRY_MAX} 次后仍不可用"
                            f"（{_exc_brief(e)}），已自动切换到「{failover.label}」继续任务。",
                })
                logger.warning("供应商故障转移：%s -> %s（session=%s）",
                               backend.name, failover.name, session.id)
                backend = failover
                await session.emit({
                    "type": "model",
                    "data": {"backend": backend.name,
                             "model": getattr(backend, "model", ""),
                             "label": getattr(backend, "label", backend.name),
                             "local": bool(getattr(backend, "local", False)),
                             "failover": True},
                })
                # 换了供应商后本步重试一次（不再嵌套重试循环：失败走原异常路径）
                try:
                    result = await backend.chat(messages, tools=registry.build_schemas(mode=session.mode))
                except Exception as e2:
                    await session.emit({"type": "error", "data": f"模型调用失败：{e2}"})
                    session.state = "error"
                    await session.emit({"type": "done", "state": "error"})
                    return
            # token 用量落库（仅成功且端点返回 usage 的调用；额度耗尽等失败不计）
            try:
                _u = result.get("usage") or {}
                tokens_used += int(_u.get("prompt") or 0) + int(_u.get("completion") or 0)
                if _u.get("prompt") or _u.get("completion"):
                    store.save_usage(
                        provider_id=backend.name,
                        model=getattr(backend, "model", ""),
                        prompt_tokens=_u.get("prompt", 0),
                        completion_tokens=_u.get("completion", 0),
                        session_id=session.id, project_id=session.project,
                        duration_ms=int((time.time() - _t0) * 1000),
                    )
            except Exception:
                logger.exception("token 用量落库失败")

            # ---- 成本熔断：本次任务累计 token 超预算即停止 ----
            # 本地 Ollama 不返回 usage，所以不会触发；云端供应商超限即停，
            # 避免一个失控任务无声烧钱（原实现只有事后统计、没有运行中的闸门）。
            if config.RUN_TOKEN_BUDGET and tokens_used > config.RUN_TOKEN_BUDGET:
                budget_msg = (
                    f"本次任务累计消耗 token 已达 {tokens_used:,}，超过预算上限 "
                    f"{config.RUN_TOKEN_BUDGET:,}，为避免继续消耗已停止。"
                    f"如需继续，可调大环境变量 AGENT_RUN_TOKEN_BUDGET，或改用本地模型。"
                )
                await self._write_back(session, budget_msg)
                await session.emit({"type": "answer", "data": budget_msg})
                self._persist_intel(session)
                session.state = "done"
                await session.emit({"type": "done", "state": "done"})
                return

            # ---- 模型给出思考/说明 ----
            if result.get("content"):
                await session.emit({"type": "reasoning", "data": result["content"]})
                # 对话历史落库：模型说明（reasoning）
                try:
                    store.save_chat_message(session.id, "assistant", result["content"], kind="reasoning")
                except Exception:
                    logger.exception("模型说明落库失败")

            tool_calls = result.get("tool_calls") or []

            # ---- 没有工具调用：先尝试从 markdown 代码块兜底恢复 ----
            if not tool_calls:
                recovered = _parse_tool_from_markdown(result.get("content") or "")
                if recovered:
                    await session.emit({
                        "type": "reasoning",
                        "data": f"模型未产生 tool_calls，但输出文本中包含可识别的工具调用，"
                                f"已自动恢复：{recovered['name']}",
                    })
                    tool_calls = [{
                        "id": f"call_{step_no}_fallback",
                        "function": {
                            "name": recovered["name"],
                            "arguments": json.dumps(recovered["arguments"], ensure_ascii=False),
                        },
                    }]

            # ---- 仍没有工具调用 = 任务结束 ----
            if not tool_calls:
                # 本地小模型两种常见退化：① 反问用户要目标 ② 只描述计划不调用工具。
                # 两者都催促一次，仍不动手就认定它已给出结论。
                #
                # 收尾免催促（2026-09-16）：本次任务已经实际执行过工具的话，
                # 模型此刻给的就是正常结论——直接收尾。原实现一律催促 2 次，
                # 每个会话收尾多付 2 次 LLM 调用，split_task 多子任务场景成倍放大。
                # 只有「整轮没碰过任何工具、纯嘴上输出」时才需要催促。
                if session.nudges < 2 and not tools_used:
                    session.nudges += 1
                    session.messages.append({
                        "role": "user",
                        "content": "请立即调用一个工具继续执行；如果任务确实已完成，"
                                   f"就直接给出最终结论。不要只描述计划。本次任务：{user_message}",
                    })
                    await session.emit({
                        "type": "reasoning",
                        "data": f"（模型未调用工具，第 {session.nudges} 次催促其执行或收尾）",
                    })
                    continue

                answer = result.get("content") or "（模型未给出结论）"
                session.messages.append({"role": "assistant", "content": answer})
                await self._write_back(session, answer)
                await session.emit({"type": "answer", "data": answer})
                session.state = "done"
                await session.emit({"type": "done", "state": "done"})
                return

            # ---- 有工具调用：执行模式的消融开关 ----
            # react（默认）：只执行本轮第一个 tool_call，执行完立刻回到模型重新决策。
            #   必须同时把 assistant 消息里的 tool_calls 裁到只剩这一个——否则落进历史后，
            #   会出现「assistant 声明了 N 个调用、却只有 1 个 role=tool 回应」的失配，
            #   OpenAI 兼容接口会直接报 400。
            # plan：保留全部调用，一轮批量跑完（适合云端强模型）。
            if config.EXECUTION_MODE == "react" and len(tool_calls) > 1:
                dropped = [tc.get("function", {}).get("name", "?") for tc in tool_calls[1:]]
                tool_calls = tool_calls[:1]
                await session.emit({
                    "type": "reasoning",
                    "data": f"（react 单步模式：本轮只执行第一个调用，已略过 "
                            f"{len(dropped)} 个后续调用 {'、'.join(dropped)}；"
                            f"想批量执行可设 AGENT_EXECUTION_MODE=plan）",
                })

            # ---- 有工具调用：逐步执行 ----
            assistant_msg: dict[str, Any] = {"role": "assistant", "content": result.get("content") or ""}
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.get("id", f"call_{step_no}_{i}"),
                    "type": "function",
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": tc["function"]["arguments"],
                    },
                }
                for i, tc in enumerate(tool_calls)
            ]
            session.messages.append(assistant_msg)

            for tc in assistant_msg["tool_calls"]:
                fn = tc["function"]
                alias = fn["name"]
                params = parse_tool_arguments(fn.get("arguments", "{}"))
                target = str(params.get("target", "")).strip()
                args = str(params.get("args", "") or "").strip()
                # 本轮发生过任何工具调用交互（含内置工具/被拒调用）即视为「模型在动手」，
                # 后续给出结论时直接收尾、不再催促（收尾免催促的判定依据）。
                # 例外：think / halt_task 是元认知工具，不是「干活」——think 只是整理思路，
                # halt_task 本身就是收尾，二者都不该把本轮标成「已产出」。
                if alias not in ("think", "halt_task"):
                    tools_used = True
                    session.think_streak = 0   # 真动手了，思考计数归零

                # ---- 校验工具名（模型会拼错甚至编造） ----
                tool, fuzzy = registry.resolve(alias)
                if tool is None:
                    # 兜底恢复路径 1：name="tool_call" 之类畸形调用，
                    # 真实调用可能嵌在 arguments 的 JSON 里
                    inner = parse_tool_arguments(fn.get("arguments", "{}"))
                    if isinstance(inner, dict):
                        inner_fn = inner.get("function") or inner
                        inner_name = inner_fn.get("name") or inner_fn.get("tool")
                        if inner_name:
                            resolved, _ = registry.resolve(str(inner_name))
                            if resolved is not None:
                                await session.emit({
                                    "type": "reasoning",
                                    "data": f"tool_calls 畸形（name={alias!r}），"
                                            f"已从 arguments 中恢复真实调用：{resolved.alias}",
                                })
                                tool, fuzzy = resolved, False
                                params = inner_fn.get("arguments") or inner_fn.get("args") or {}
                                if isinstance(params, str):
                                    params = parse_tool_arguments(params)
                                target = str(params.get("target", "")).strip()
                                args = str(params.get("args", "") or "").strip()
                    # 兜底恢复路径 2：真实调用写在输出文本的 markdown 代码块里
                if tool is None:
                    recovered = _parse_tool_from_markdown(result.get("content") or "")
                    if recovered:
                        await session.emit({
                            "type": "reasoning",
                            "data": f"工具名 `{alias}` 不存在，但输出文本中包含可识别的调用，"
                                    f"已自动恢复：{recovered['name']}",
                        })
                        tool, fuzzy = registry.resolve(recovered["name"])[0], False
                        params = recovered["arguments"]
                        target = str(params.get("target", "")).strip()
                        args = str(params.get("args", "") or "").strip()
                if tool is None:
                    msg = (
                        f"工具 `{alias}` 不存在。请从可用工具清单中选择真实存在的工具，"
                        f"不要编造工具名。可用工具：{', '.join(t.alias for t in registry.usable_scriptable(session.mode))}"
                    )
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": msg})
                    # 记录 repr：模型返回的名字常带不可见字符，只打印原文会看不出问题
                    logger.warning("拦截不存在的工具：alias=%r 原始=%r", alias, fn.get("name"))
                    await session.emit({"type": "error", "data": f"已拦截不存在的工具：{alias}"})
                    continue
                if fuzzy:
                    await session.emit({
                        "type": "reasoning",
                        "data": f"工具名 `{alias}` 不存在，已自动纠正为 `{tool.alias}`（{tool.name}）",
                    })

                # ---- 模式闸门（v102）：跨模式工具名必须挡在**执行之前** ----
                # 位置：三条取值路径（正常解析 / 畸形调用恢复 / markdown 恢复）全部汇合之后。
                # 为什么必须有：`registry.resolve()` 是**不看模式**的查表，而系统提示词
                # 是所有模式共用的（不按模式裁剪）。于是模型完全可能从提示词或旧记忆里
                # 拿到另一个模式的工具名 —— 只过滤 schema 挡不住这种情况，白盒会话照样
                # 能被点名去调 `httpreplay`/`py_exec` 这类**会向外部发流量/执行代码**的工具，
                # 与「白盒只做源码审计、不发目标流量」的结构性保险自相矛盾。
                # 宁可在这里多拦一次并说明原因，也不让模式只是一层"界面上不给看"。
                if not registry.mode_allows(session.mode, tool.alias):
                    other = "黑盒" if session.mode == "whitebox" else "白盒"
                    session.messages.append({
                        "role": "tool", "tool_call_id": tc["id"],
                        "content": (f"工具 `{tool.alias}` 在当前工作模式（{session.mode}）"
                                    f"下不可用 —— 它属于{other}侧工具集。"
                                    "请只使用本模式清单里列出的工具。要换模式请回到起始页"
                                    "另建对应模式的项目/会话（模式在会话创建时定死、不会中途更改）。"),
                    })
                    await session.emit({
                        "type": "error",
                        "data": f"已拦截跨模式工具：{tool.alias}（当前模式 {session.mode}）",
                    })
                    logger.warning("拦截跨模式工具：alias=%r mode=%r",
                                   tool.alias, session.mode)
                    continue

                # ---- 交互式工具：不交给模型（v047）----
                # 位置：必须在风险闸门之前，否则会走到「弹出确认 → 人放行 → 卡 120 秒」。
                # 为什么单列一道：这类工具**只服务于人**。它的输出是一条等着输入的菜单，
                # 模型既读不懂（半个菜单），也无法提供后续输入 —— 交回一句明确的
                # 「别用它、改用 X」远比让它白烧一步 + 两分钟 + 一次人工确认有用。
                # 实测来源：2026-09-22 tgt-e.test 第三轮，某个加密小工具（分级 L0，
                # 即自动执行）就这么卡满 TOOL_IDLE_TIMEOUT。
                # 这类工具已从可用清单剔除，所以正常情况跑到这里的是「模型记住了旧清单」
                # 或「别名模糊命中」——两种都值得留痕。
                if getattr(tool, "interactive", False):
                    why = getattr(tool, "interactive_reason", "") or "该工具为交互式菜单程序"
                    msg = (f"{tool.name} 是交互式菜单程序，不能由你调用：{why}。"
                           "请改用非交互的等价做法（哈希/编码类计算用 py_exec 的 "
                           "`import hashlib` / `import base64`，它们在只读白名单内）。")
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"],
                                             "content": msg})
                    await session.emit({
                        "type": "error",
                        "data": f"已拦截交互式工具：{tool.alias}（{tool.name}）",
                    })
                    logger.warning("拦截交互式工具：alias=%r name=%r", tool.alias, tool.name)
                    continue

                # ---- 元认知工具 think / halt_task（L0，纯本地，不走风险闸门）----
                # think：给模型一个显式的「只想不做」出口，避免它为了整理线索而被迫
                #        产出一个没用的工具调用；halt_task：给模型一个显式的收尾出口，
                #        比「不调用工具」语义明确（借鉴 LuaN1ao 的元认知工具设计）。
                if tool.alias == "think":
                    # 返回非空字符串 = 空转熔断：由系统收尾，理由随结论一起给出
                    think_abort = await self._think(session, tc, args)
                    if think_abort:
                        halted_answer = think_abort
                        break
                    continue
                if tool.alias == "halt_task":
                    halted_answer = await self._halt_task(session, tc, args)
                    break

                # 内置工具留痕：它们不产生 Step（见 _BUILTIN_ALIASES 说明），
                # 但汇总/提醒需要知道「这条线索用过哪些内置能力」。
                # ---- 内置「记忆类」工具：不走风险闸门，但要留下步骤记录 ----
                # 原先这几条直接 continue，于是「读过哪篇知识库 / 记了哪条事实 / 搜了什么词」
                # 在 steps 表里完全不可见：不在「本轮已尝试过的工具」提醒里（会重复读），
                # search_history 也搜不到，审计上更是无痕。
                # 注意顺序：先执行、后补记。执行时 steps[-1] 仍是上一条真实工具步骤，
                # 事实溯源要用它；反过来先入列会让 note_fact 把事实挂到自己头上。
                if tool.alias in BUILTIN_STEP_TOOLS:
                    if tool.alias == "note_fact":
                        note = await self._note_fact(session, tc, target, args)
                    elif tool.alias == "search_history":
                        note = await self._search_history(session, tc, args or target)
                    elif tool.alias == "propose_branch":
                        note = await self._propose_branch(session, tc, args)
                    elif tool.alias == "split_task":
                        note = await self._split_task(session, tc, args, allow_split)
                    elif tool.alias.startswith("code_"):
                        # v063 白盒：本地只读检索/阅读/入库，不过 scope 与风险闸门。
                        # 执行体在 app/codebase/tools.py（**内部已把一切异常转成文字回执**，
                        # 不会打断这里的循环）。
                        note = codebase_tools.handle(tool.alias, target, args)
                        # ⚠️ v115 修：**必须自己回灌 role=tool 消息**。
                        # 其余 5 个内置 handler（_note_fact / _search_history /
                        # _propose_branch / _split_task / _kb_fofa_tool）都在**各自函数里**
                        # append 过了，只有 `code_*` 走的是无状态的
                        # `codebase_tools.handle()`（它拿不到 session，也没法自己补）
                        # ⇒ 回来之后没人补这一条。
                        # 后果：messages 里 assistant 声明了 tool_calls、却没有对应的
                        # role=tool 回复，**OpenAI 兼容端点直接 400**
                        # （tool_call_id ... has no response）——
                        # 表现为白盒会话**第二轮必挂**，而第一轮看起来完全正常。
                        # 放在这里而不是 `_record_builtin_step` 里：那个函数是四条分支
                        # **共用**的，加在那儿会让另外 5 个变成双重回灌。
                        session.messages.append({"role": "tool", "tool_call_id": tc["id"],
                                                 "content": note})
                    else:  # kb_search / kb_read / fofa_search
                        note = await self._kb_fofa_tool(session, tool.alias, tc, args)
                    session.builtin_calls.append(tool.alias)
                    self._record_builtin_step(session, tc, tool, target, args, note)
                    continue

                # ---- 校验目标（模型会把中文句子当目标传入） ----
                bad_target = validate_target(target)
                if bad_target:
                    msg = f"目标参数无效：{bad_target}。target 必须是域名、IP、URL 或企业名称，不能是说明性文字。请从用户任务中提取真实目标后重试。"
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": msg})
                    await session.emit({"type": "error", "data": f"已拦截无效目标：{target[:40]}"})
                    continue

                # 风险等级必须用「纠正后」的规范别名查，否则模型拼错工具名
                # （如 ddddd_scan）时 risk_of 会查不到，等级变成 ? 被默认拒绝。
                risk = registry.risk_of(tool.alias) or {}

                # ---- py_exec 静态能力分档（v047）----
                # 位置：必须在 Step 构造**之前**。`Step.risk` 会落库、`_await_confirm`
                # 读的是 `risk["double_confirm"]`、前端弹窗文案也取这一份 —— 改晚了
                # 就会出现「库里记 L3、实际按 L2 放行」的分叉，审计时无从解释。
                #
                # 为什么在语法预检之前也没关系：分档器遇到语法错误一律返回 opaque
                # （不降级），随后 v045 的语法预检会给出更友好的信息并 `continue`。
                grade_note = ""
                if tool.alias == "py_exec":
                    risk, grade_note = pyexec_grade.apply_to(args, risk)

                step = Step(
                    id=tc["id"],
                    tool_alias=tool.alias,
                    tool_name=tool.name,
                    target=target,
                    args=args,
                    risk=risk,
                )
                session.steps.append(step)

                # 分档降级必须**留痕**：这步不再弹确认框（或只弹一轮），
                # 操作者需要知道「为什么这次没问我」。同时写日志便于事后审计
                # 「哪些 py_exec 是自动放行的」。
                if grade_note:
                    # 注意 `risk` 此处已是**降级后**的 dict，原等级在 note 里，
                    # 所以日志只打印 note（否则会打出「L0 → L0」这种无信息量的行）。
                    logger.info("py_exec 能力分档降级：%s", grade_note)
                    await session.emit({"type": "reasoning", "data": grade_note})

                # ---- 并行子任务：禁止需要人工确认的工具 ----
                # split_task 派生的子任务是并发跑的，而确认通道是「一次一步」的交互式，
                # 且前端只订阅当前会话的 SSE —— 并行时无法逐个弹确认。因此子任务内只放行
                # L0/L1 自动执行类；L2/L3 直接拒绝，并提示回主线索由人工确认后执行。
                if session.subtask and not risk.get("auto", False):
                    msg = (f"子任务内不允许执行需要人工确认的工具（{tool.name}，风险等级 "
                           f"{risk.get('level')}）。请改用 L0/L1 的只读/探测类工具；"
                           f"这一步留给主线索，由人工确认后单独执行。")
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": msg})
                    step.status = "denied"
                    # v111：**记下是哪道闸门拦的**。`denied` 对应三道不同的闸门
                    # （子任务闸门 / 任务级约束闸门 / 风险确认闸门），不记的话
                    # 控制台「失败归因分布」里只能画出一个说不清的大桶，
                    # 而"哪道闸门最容易误伤"恰恰是看板最该回答的问题。
                    step.attribution = "GATE_SUBTASK"
                    await session.emit({"type": "step_denied", "step": self._step_dict(step)})
                    try:
                        store.save_step(session.id, self._step_dict(step))
                    except Exception:
                        pass
                    continue

                # ---- py_exec 语法预检（v045）----
                # 位置很关键：必须在风险闸门**之前**。
                # py_exec 是 L3，人工要连续确认两轮；而实测 Agent 会连续产出
                # 无法编译的代码（`unmatched ')'`、`unterminated string literal`）。
                # 原流程下每一条都先弹确认、人工放行后才在子进程里报 SyntaxError，
                # 于是：① 白耗两轮人工确认；② 归因把「语法错误」混进「用户拒绝 /
                # 连续失败」里，掩盖真实原因，连带影响熔断与降级判断。
                # 提到闸门前，语法错误就退化成一条普通工具反馈——模型立刻重写，
                # 人工一次都不用点。
                if tool.alias == "py_exec":
                    syn = pyexec.syntax_error(args)
                    if syn:
                        step.status = "error"
                        step.output = syn
                        session.messages.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": ("未提交人工确认（语法预检不通过）：" + syn +
                                        "\n说明：语法错误在执行前就地拦下，"
                                        "不消耗确认次数，也无需用户处理。"),
                        })
                        # 用 step_done 而不是新造事件类型：前端与落库已经处理
                        # step_done + status=error 这条路径（见 _run_step 收尾），
                        # 新增事件类型只会让消费方漏处理。
                        await session.emit({"type": "step_done",
                                            "step": self._step_dict(step)})
                        try:
                            store.save_step(session.id, self._step_dict(step))
                        except Exception:
                            pass
                        continue

                # ---- 任务级约束闸门（v048）----
                # 位置：风险闸门**之前**，而且对 L0/L1 也生效 —— 这正是本闸门存在的理由。
                # 2026-09-25 某企业站实战：任务书写明「不做字典爆破」，Agent 仍调了
                # OneForALL（95247 词字典）。它是 **L0 → 风险闸门自动放行**，
                # 整条链上没有任何环节能拦住 —— 风险闸门只知道「工具多危险」，
                # 不知道「本次任务不允许什么」。
                # 这里**拒绝**而不是降级为需确认：约束是操作者自己写下的指令，
                # 降级的话无人值守时审批器会等满宽限期再拒，同一个结果多烧一步 + 90 秒。
                viol = taskguard.violation(session.constraints,
                                           getattr(tool, "caps", None))
                if viol:
                    cap, hit = viol
                    msg = taskguard.refusal_message(tool.name, cap, hit)
                    step.status = "denied"
                    # v111：与子任务闸门区分开（见 GATE_SUBTASK 处的说明）
                    step.attribution = "GATE_CONSTRAINT"
                    step.output = msg
                    session.messages.append({"role": "tool",
                                             "tool_call_id": tc["id"], "content": msg})
                    await session.emit({"type": "step_denied",
                                        "step": self._step_dict(step)})
                    try:
                        store.save_step(session.id, self._step_dict(step))
                    except Exception:
                        pass
                    logger.info("任务级约束拦下 %s（能力 %s，任务声明「%s」）",
                                tool.alias, cap, hit)
                    await session.emit({
                        "type": "reasoning",
                        "data": f"已按任务级约束拒绝 {tool.name}：任务声明「{hit}」，"
                                f"而该工具具备「{taskguard.CAP_LABEL.get(cap, cap)}」能力。",
                    })
                    continue

                # ---- 风险闸门 ----
                if not risk.get("auto", False):
                    approved, edited_args = await self._await_confirm(session, step)
                    if not approved:
                        step.status = "denied"
                        # v111：与子任务闸门区分开（见 GATE_SUBTASK 处的说明）
                        step.attribution = "GATE_RISK"
                        # v023.6（实战反馈）：拒绝后要给**可执行的替代路径**，
                        # 否则模型只能自己猜怎么降级（实测 py_exec 被拒后，
                        # 模型多花一步才想到改用 httpreplay 单发）。
                        hint = ""
                        if tool.alias == "py_exec":
                            hint = ("可用替代：①内置 `httpreplay` 单发一次请求（args 用 "
                                    "`-X GET --timeout 15`，只读、L2）；②若要多次取数，"
                                    "改用受控接口 `from srcagent import safe_http_request` "
                                    "且**不要**写 for/while 循环（展开为顺序调用）。")
                        elif risk.get("level") == "L3":
                            hint = ("可用替代：改用同功能的 L0/L1 只读工具，或把范围收窄后"
                                    "再说明为什么必须用该高风险通道。")
                        session.messages.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": (f"用户拒绝执行 {tool.name}（风险等级 {risk.get('level')}）。"
                                        f"请改用其他更低风险的方式，或说明为什么必须执行。"
                                        + (f"\n{hint}" if hint else "")),
                        })
                        await session.emit({"type": "step_denied", "step": self._step_dict(step)})
                        try:
                            store.save_step(session.id, self._step_dict(step))
                        except Exception:
                            pass
                        continue
                    # 用户在确认框里改过参数：以改后的为准执行。
                    # 注意这里只替换 args——真正拼命令仍旧走 executor 的清洗管线
                    # （剥非法 flag、剥引号、白名单校验），改参数不等于绕过闸门。
                    if edited_args is not None and edited_args.strip() != step.args.strip():
                        step.args = edited_args.strip()
                        await session.emit({
                            "type": "reasoning",
                            "data": f"（用户修改了 {tool.name} 的参数，按修改后的参数执行）",
                        })

                # ---- 执行 ----
                await self._execute(session, step, tc["id"])
                # 执行成功即重置连续失败计数；失败则累加
                if step.status == "done":
                    consecutive_failures = 0
                    switch_nudged = False   # 成功一次后，「换策略」提醒重新武装
                elif step.status == "error":
                    consecutive_failures += 1

            # ---- 提前收尾（优先于止损判定）----
            # 两种来源：① 模型调用 halt_task 主动结束；② think 空转熔断，由系统结束。
            # 变量名沿用 halted_answer，因为两者走的是同一条收尾通路（写回+推送+落库）。
            if halted_answer is not None:
                session.messages.append({"role": "assistant", "content": halted_answer})
                await self._write_back(session, halted_answer)
                await session.emit({"type": "answer", "data": halted_answer})
                self._persist_intel(session)
                session.state = "done"
                await session.emit({"type": "done", "state": "done"})
                return

            # 失败止损分两档（借鉴 LuaN1ao EXECUTOR_FAILURE_THRESHOLD 的语义）：
            # 连续失败先「要求换策略」再继续，只有在更高阈值上仍连续失败才停止。
            # 原实现连续 3 次即停，但连续三次失败常常只是「同一思路被环境挡住」——
            # 换策略还有得挖，这也是「没到最大步数就停」的主要原因。
            if consecutive_failures >= config.FAILURE_STOP_THRESHOLD:
                # 停止时把归因分布一并说清：是工具跑不起来(L1)、被环境拦(L3)，
                # 还是假设本身不成立(L4)。含糊的「执行失败」帮不了用户判断下一步。
                attr = {}
                for st in session.steps:
                    if st.attribution:
                        attr[st.attribution] = attr.get(st.attribution, 0) + 1
                dist = "、".join(f"{k} {v} 次" for k, v in sorted(attr.items())) or "未归类"
                stop_msg = (
                    f"连续 {consecutive_failures} 次执行失败，已停止（已先尝试要求换策略，仍失败）。"
                    f"失败归因分布：{dist}。\n"
                    f"L1=工具没跑起来（换参数/放大超时）、L3=被环境或权限拦下（换编码或换手法）、"
                    f"L4=假设可能不成立（换测试思路）、SCOPE=授权白名单拒绝（属授权边界，必须停手）。\n"
                    f"请检查目标可达性、工具参数或授权范围。"
                )
                await self._write_back(session, stop_msg)
                await session.emit({
                    "type": "answer",
                    "data": stop_msg,
                })
                self._persist_intel(session)
                session.state = "done"
                await session.emit({"type": "done", "state": "done"})
                return
            if consecutive_failures >= config.FAILURE_SWITCH_THRESHOLD and not switch_nudged:
                switch_nudged = True
                session.messages.append({
                    "role": "user",
                    "content": (
                        f"你已经连续 {consecutive_failures} 次执行失败。"
                        "现在必须【换策略】，而不是继续换工具重试："
                        "① 换测试面（换接口、换参数、换相邻资产）；"
                        "② 换手法（换漏洞类型，或改用「只读差分」的方式取证）；"
                        "③ 若判断目标当前不可达、或已超出授权白名单，直接给出结论结束，"
                        "并在结论里说明失败原因与已证实的部分。"
                        "不要重复调用刚失败过的工具，也不要换汤不换药地调同一类工具。"
                    ),
                })
                await session.emit({
                    "type": "reasoning",
                    "data": f"（连续 {consecutive_failures} 次失败：已要求模型换策略而非继续重试）",
                })

        max_steps_msg = _budget_exhausted_note(session, step_budget)
        await self._write_back(session, max_steps_msg)
        await session.emit({"type": "answer", "data": max_steps_msg})
        self._persist_intel(session)
        session.state = "done"
        await session.emit({"type": "done", "state": "done"})

    # ---------- 元认知工具（L0，纯本地，无任何网络行为） ----------
    async def _think(self, session: Session, tc: dict, args: str) -> str | None:
        """think：给模型一个显式的「只想不做」出口。

        为什么需要它：小模型一旦不调工具，就会被催促逻辑当成「忘了动手」，
        于是它为了显得在干活会随手挑一个工具调用——这正是「瞎猜工具」的主要来源。
        开一个合法的纯推理出口，比逼它产出垃圾调用更好。
        因此 think 不算「干过活」（不置 tools_used），不占用执行步数。

        防滥用分两级：到第 THINK_STREAK_MAX 轮时把「必须动手」推进上下文；
        若它下一轮仍然只推理，就判定为空转并返回一段说明，由 run() 收尾结束本轮——
        不这么做的话，一个「只想不做」的模型会把整个步数预算全烧在思考上，
        而每一轮思考都是一次真实的 LLM 调用。
        """
        session.think_streak += 1
        body = (args or "").strip()
        if body:
            await session.emit({"type": "reasoning", "data": f"（模型思考一轮）{body[:600]}"})
            try:
                store.save_chat_message(session.id, "assistant", f"（思考）{body}", kind="reasoning")
            except Exception:
                logger.exception("think 记录落库失败")
        if session.think_streak > config.THINK_STREAK_MAX:
            session.messages.append({
                "role": "tool", "tool_call_id": tc["id"],
                "content": "已记录。连续推理已达上限，本轮到此结束。",
            })
            await session.emit({"type": "reasoning",
                                "data": f"（连续 {session.think_streak} 轮只推理不动手：判定空转，结束本轮）"})
            return ("模型连续多轮只推理、没有执行任何工具，本轮已停止。\n"
                    "最后一条推理没有推进任务；请把任务描述得更具体"
                    "（指明目标、想用哪个工具、要拿到什么结果）后重试。")
        if session.think_streak == config.THINK_STREAK_MAX:
            session.messages.append({
                "role": "tool", "tool_call_id": tc["id"],
                "content": "已记录。但你已经连续多轮只推理不动手了——现在必须从可用清单里"
                           "挑一个真实工具执行，或者调用 halt_task 给出结论。不要再继续思考。",
            })
            await session.emit({"type": "reasoning",
                                "data": f"（连续 {session.think_streak} 轮只思考不动手：已要求立即执行）"})
            return None
        session.messages.append({
            "role": "tool", "tool_call_id": tc["id"],
            "content": "推理已记录。请基于它立即调用一个真实工具推进；"
                       "若判断已无可推进方向，调用 halt_task 给出结论。",
        })
        return None

    async def _halt_task(self, session: Session, tc: dict, args: str) -> str:
        """halt_task：模型显式收尾，返回结论文本（由 run() 统一落库、写回与推送）。

        为什么需要它：原来模型想结束只能「不调用工具」，而这个信号与「模型退化、
        忘了调工具」长得一模一样，只能靠催促次数去猜。给一个显式的结束动作之后，
        「该不该收尾」就从猜测变成了读取。
        """
        answer = (args or "").strip() or "（模型主动结束，但未给出结论）"
        session.messages.append({
            "role": "tool", "tool_call_id": tc["id"],
            "content": "已收到结束指令，本轮到此结束。",
        })
        await session.emit({"type": "reasoning", "data": "（模型主动结束本轮并给出结论）"})
        return answer


    # ---------- 情报沉淀 ----------
    def _persist_intel(self, session: Session) -> None:
        """把本轮工具输出沉淀进项目情报库，供下轮注入；可重复调用（merge_intel 按类去重）。

        调用点有两处：run() 的正常收尾，以及 `_run_agent` 的 finally。
        加 finally 那次是有原因的：原先只在「正常收尾」沉淀，模型调用一旦报错就直接
        return，整轮产出在记忆层面归零 —— 实测上一轮 3 步全部成功、产出 57 条存活子域，
        情报库仍然是 0 行，而且没有任何提示。

只取**真实外部工具**的输出：内置 kb_read 的正文里全是 target.com 这类占位示例，
一起抽进来会往情报库灌假主机。

⚠️ 白盒 code_* 也**一并排除**（这里用整个 `BUILTIN_STEP_TOOLS`，与
`attribute_source_step` 刻意不同）：情报库抽的是**主机/域名**，而代码正文里
"看起来像域名"的字符串更多（示例、注释、依赖名），灌进来只会更脏。
两处用途不同，所以用的集合也不同 —— 这是**有意的**，不是漏改。
"""
        if not session.project:
            return
        try:
            outputs = [st.output for st in session.steps
                       if st.tool_alias not in BUILTIN_STEP_TOOLS]
            update_intel_from_steps(session.project, outputs)
        except Exception:
            logger.exception("项目情报沉淀失败")

    def persist_interrupted(self, session: Session, reason: str = "") -> None:
        """异常结束时兜一层「部分成果」摘要，让中断也留下可复用的记忆。

        与 `_write_back` 的区别：那条只走「给出最终结论」的路径，异常时不会触发。
        这里用步骤清单拼一句可注入的摘要（其他线索的上下文注入会展它），
        并以「【中断】」开头，让读到的人能分辨这是完整结论还是半程快照。
        """
        if not session.project or session.summary:
            return          # 已有正式结论就别用半程快照盖掉它
        try:
            done = [st for st in session.steps if st.status == "done"]
            tools = list(dict.fromkeys(
                st.tool_name or st.tool_alias for st in done)) or ["（无）"]
            head = (session.target or "").strip()
            msg = (f"【中断】线索未跑完（{reason or '执行中断'}）；共 {len(session.steps)} 步、"
                   f"其中 {len(done)} 步成功。已用工具：{'、'.join(tools[:8])}。"
                   f"目标：{head or '未识别'}。")
            if session.id:
                msg += f"（会话 {session.id}，详情可在该线索内查看或检索）"
            session.summary = msg
            store.save_summary(session.id, msg)
            logger.info("已写入中断摘要：%s", session.id)
        except Exception:
            logger.exception("中断摘要写入失败")


    # ---------- 已证事实记录 ----------
    @staticmethod
    def _record_builtin_step(session: Session, tc: dict, tool, target: str,
                             args: str, note: str) -> None:
        """把一次内置「记忆类」工具调用补记成步骤（只留痕，不影响风险闸门）。

        它们本来就是 L0、无外部动作，所以不走闸门；但必须留痕 —— 否则
        「读了哪篇知识库 / 记了哪条事实 / 搜了什么关键词」既不在「本轮已尝试过的工具」
        提醒里（模型会反复读同一篇），也搜不到、审计不到。
        顺序上必须在处理函数**之后**调用：note_fact 的事实溯源会用非内置步骤回退，
        先入列会让它把事实挂到自己头上。
        """
        now = time.time()
        # 风险元数据回退：registry 未 load（如单测直接 import）时 risk_of 会返回 None，
        # 那样落库的 risk_level 会变成空串。内置记忆类工具本身就不过闸门，
        # 这里至少把等级据实填上，别在库里留一个「未知等级」。
        risk = registry.risk_of(tool.alias) or {
            "level": getattr(tool, "risk_level", "") or "L0",
            "name": "", "auto": True, "double_confirm": False,
            "reason": getattr(tool, "risk_reason", "") or "",
            "tool": tool.name,
        }
        session.steps.append(Step(
            id=tc["id"],
            tool_alias=tool.alias,
            tool_name=tool.name,
            target=target or "",
            args=args or "",
            risk=risk,
            status="done",
            output=clip_output(note or ""),
            started_at=now,
            finished_at=now,
        ))

        # 与「真实工具步骤」同口径落库：否则「内存里 N 步 / 库中 0 步」会对不上，
        # 线索树（list_tree 的 step_count）与 subtask_merged 的 steps 显示会不一致；
        # 而「可检索、可审计」本就是这套机制的目的（此前 kb_read/note_fact 完全无痕）。
        try:
            store.save_step(session.id, {
                "id": tc["id"],
                "tool_alias": tool.alias,
                "tool_name": tool.name,
                "target": target or "",
                "args": args or "",
                "risk": risk,
                "status": "done",
                "output": clip_output(note or ""),
                "attribution": "",
                "elapsed": None,
            })
        except Exception:
            logger.exception("内置工具步骤落库失败")

    async def _note_fact(self, session: Session, tc: dict, target: str, args: str) -> str:
        """note_fact 内置工具执行：写入项目事实库并回馈模型。"""
        content = (args or "").strip() or (target or "").strip()
        if not session.project:
            note = "当前会话未关联项目，无法保存事实。请先创建/选择项目后再执行。"
        elif not content:
            note = "事实内容为空：args 应填要记录的事实正文（一句一事）。"
        else:
            try:
                # 带上会话与**真正的来源步骤**：因果图靠这个溯源把
                # 「某次工具执行 —揭示→ 该事实」连成边，否则事实会成孤点。
                # 来源步骤按事实正文回查（见 attribute_source_step），
                # 不再无脑取 steps[-1]——那会把 A 的产出挂到后执行的 B 上。
                src_step = attribute_source_step(session, content)
                # ---- 白盒证据主闸门（v064，实施规格 §4.3）----
                # 引用了**代码位置**的事实必须能被白盒工具输出检回：
                #   · 检不回 → 记候选 + 回喂明确要求补证据（NO_EVIDENCE，防编造的主闸门）；
                #   · 检得回 → **仍然是候选** —— §4.3 的表写得很清楚：
                #     「模型给出代码片段且确实来自工具输出」仍为 candidate，因为**代码存在 ≠ 可达**。
                #     能升 verified 的只有人工复核，或工具证实了完整数据流（那是判定层的产出）。
                # 不涉及代码引用时 `v.status` 为空串，**保持原行为不变**。
                v = codebase_evidence.verify(content, session.steps)
                if v.status == "no_evidence":
                    _NO_EVIDENCE_COUNT[0] += 1
                    logger.warning("白盒事实缺证据 NO_EVIDENCE #%d：%s（内容：%s）",
                                   _NO_EVIDENCE_COUNT[0], v.reason, content[:120])
                rec = store.add_fact(session.project, content[:500], source="agent",
                                 session_id=session.id, step_id=src_step,
                                 status="candidate" if v.status else "")
                graph.on_fact_added(session.project, rec)
                if v.status:
                    note = f"已记录**候选**事实 #{rec.get('id','')}：{content[:120]}"
                    note += f"\n（白盒证据校验：{v.reason}）"
                    if v.feedback:
                        note += "\n" + v.feedback
                else:
                    note = f"已记录已证事实 #{rec.get('id','')}：{content[:120]}"
            except Exception as e:
                note = f"记录事实失败：{e}"
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
        await session.emit({"type": "reasoning", "data": f"（{note}）"})
        return note

    # ---------- 对话树：跨线索检索 ----------
    async def _search_history(self, session: Session, tc: dict, keyword: str) -> str:
        """search_history 内置工具：在项目内的工具执行 / 已证事实 / 项目情报里检索关键词。"""
        kw = (keyword or "").strip()[:80]
        hits: list[dict] = []
        if not session.project:
            note = "当前会话未关联项目，无法检索历史线索。"
        elif not kw:
            note = "搜索关键词为空：args 应填要检索的关键词（域名、路径、工具名、端口等）。"
        else:
            err = ""
            try:
                hits = store.search_history(session.project, kw)
            except Exception as e:
                err = str(e)
                logger.exception("检索历史线索失败")
            if err:
                # 原实现里这条错误会被紧随其后的「未检索到」覆盖，模型只能看到
                # 「没搜到」而看不到真实原因，这里显式区分优先级。
                note = f"检索失败：{err}"
            elif not hits:
                note = (f"未检索到包含「{kw}」的历史记录"
                        f"（检索范围：工具执行输出、已证事实、项目情报库）。"
                        f"可换更具体的关键词（如具体路径、子域名、端口）。")
            else:
                lines = []
                for h in hits:
                    if h.get("kind") == "fact":
                        lines.append(f"【已证事实】{h.get('snippet', '')}")
                        continue
                    if h.get("kind") == "intel":
                        lines.append(f"【项目情报·{h.get('key')}】{h.get('snippet', '')}"
                                     f"（该类共 {h.get('total')} 条）")
                        continue
                    src = h.get("title") or (h.get("task") or "")[:24] or "未命名线索"
                    lines.append(
                        f"【线索《{src}》· {h.get('tool_name') or h.get('tool_alias')} → {h.get('target') or '-'}】\n"
                        f"{h.get('snippet', '')}"
                    )
                note = (f"检索到 {len(hits)} 条包含「{kw}」的历史记录"
                        f"（工具输出 / 已证事实 / 项目情报，均可直接引用）：\n\n" + "\n\n".join(lines))
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
        await session.emit({"type": "reasoning", "data": f"（检索历史线索：{kw} → {len(hits)} 条）"})
        return note

    # ---------- 对话树：建议开辟新线索 ----------
    async def _propose_branch(self, session: Session, tc: dict, args: str) -> str:
        """propose_branch 内置工具：向用户展示「开新线索」卡片，用户确认后才真正创建。

        卡片候选记录 = 本会话最近的工具步骤摘要（前端可勾选打包带走）。
        """
        text = (args or "").strip()
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        title = (lines[0] if lines else "新线索")[:60]
        reason = "\n".join(lines[1:]) if len(lines) > 1 else ""
        candidates = [self._step_dict(st) for st in session.steps[-6:]]
        await session.emit({
            "type": "branch_proposal",
            "data": {
                "title": title,
                "reason": reason,
                "candidates": candidates,
            },
        })
        note = (f"已把「开新线索」卡片展示给用户，建议标题《{title}》。"
                f"用户确认后新对话会自动携带相关记录独立推进；"
                f"请继续当前任务，或在当前方向确实告一段落时给出结论结束。")
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
        await session.emit({"type": "reasoning", "data": f"（已发出开新线索建议：《{title}》，等待用户确认）"})
        return note

    # ---------- 任务分片并行（拆小份 → 并发跑 → 合并） ----------
    async def _split_task(self, session: Session, tc: dict, args: str, allow_split: bool) -> str:
        """split_task 内置工具：把当前任务拆成若干子任务并发执行，跑完汇总回本线索。

        设计取舍：
        · 复用「线索树」基础设施 —— 子任务就是带 parent_id 的子会话，天然出现在小地图上，
          结论也会经 _write_back 回流（子线索跑完会给父会话发 branch_update 事件）。
        · 子任务内禁止 L2/L3（落实在 run() 的风险闸门）：确认通道是「一次一步」的交互式，
          且前端只订阅当前会话的 SSE，并行时弹不出确认，硬跑只会得到无人确认的悬空步骤。
        · 并发用 asyncio 而不是多进程：本工作负载是 I/O 密集（等模型、等工具），单进程足够；
          多进程反而要重建事件流与确认通道，收益不抵复杂度。
        · 并发上限刻意保守（默认 3）：并行 = 对目标同时发更多请求，平台规则禁止影响业务
          可用性的高并发，云端供应商那边也会推高 token 消耗。
        """
        text = (args or "").strip()
        subs = [ln.strip(" -•*、.\t") for ln in text.splitlines() if ln.strip(" -•*、.\t")]
        if not allow_split:
            note = "子任务内不允许再次拆分（避免任务数指数膨胀）。请直接完成你负责的这一份。"
            session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
            return note
        if len(subs) < 2:
            note = ("拆分至少需要 2 个子任务：args 每行填一个，每行要具体到目标与动作。"
                    "若这个任务本身不需要拆分，就不要调用本工具，直接继续做。")
            session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": note})
            await session.emit({"type": "reasoning", "data": "（split_task：子任务不足 2 个，未拆分）"})
            return note
        subs = subs[: config.SUBTASK_MAX_COUNT]

        # v023.4 同目标背压：并行子任务 = 对同一目标同时发更多请求的放大器
        # （计划 7.3：目标并发上限优先于 SUBTASK_MAX_CONCURRENCY）。预算不足、
        # 目标处于防护状态时**拒绝拆分**——不拆就不会有 N 路并发叠加。
        try:
            from . import traffic as _traffic
            root = _traffic.governor.root_domain_of(session.target or "")
            if root:
                st = _traffic.governor.stats(root)
                if st.get("state") != _traffic.ST_NORMAL:
                    note = (f"目标 {root} 当前状态 {st.get('state')}"
                            f"（{st.get('reason', '')[:60]}）：**不允许拆分并发子任务**——"
                            "并行只会加重目标防护反应。请先单独、低频地完成最关键的一步。")
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"],
                                             "content": note})
                    await session.emit({"type": "reasoning", "data": "（split_task 被目标防护状态阻止）"})
                    return note
                if st.get("remaining", 999) < config.SUBTASK_MIN_BUDGET:
                    note = (f"目标 {root} 剩余请求预算不足（{st.get('remaining')} 次 < "
                            f"拆分下限 {config.SUBTASK_MIN_BUDGET} 次）：不能拆分并发子任务，"
                            "否则预算会在并行中被瞬间耗尽。请串行完成、优先收敛。")
                    session.messages.append({"role": "tool", "tool_call_id": tc["id"],
                                             "content": note})
                    await session.emit({"type": "reasoning", "data": "（split_task 被预算背压阻止）"})
                    return note
        except Exception:
            logger.debug("split_task 背压检查失败（放行）", exc_info=True)

        parent_task = next((str(m.get("content") or "") for m in session.messages
                            if m.get("role") == "user"), "") or session.target
        started_at = time.time()
        children: list[Session] = []
        for i, sub in enumerate(subs, 1):
            c = sessions.create(
                project=session.project, parent_id=session.id,
                title=sub[:60] or f"子任务{i}", subtask=True,
                records=[f"上级任务：{parent_task[:200]}", f"你负责的子任务：{sub}"],
                # v102：子任务**继承父会话模式** —— 否则白盒会话拆出的子任务会拿到
                # 黑盒的 197 个工具，等于把「只放 code_*」这道保险从旁路绕开。
                mode=session.mode,
            )
            c.target = session.target
            children.append(c)

        await session.emit({
            "type": "reasoning",
            "data": (f"（已拆分为 {len(children)} 个子任务并发执行，完成后自动汇总："
                     + "；".join(x.title for x in children) + "）"),
        })
        sem = asyncio.Semaphore(max(1, config.SUBTASK_MAX_CONCURRENCY))

        async def _run_child(c: Session, sub: str) -> None:
            async with sem:
                try:
                    await self.run(c, sub,
                                   max_steps=config.SUBTASK_MAX_STEPS, allow_split=False)
                except Exception:
                    logger.exception("子任务执行异常：%s", sub)

        await asyncio.gather(*[_run_child(c, s) for c, s in zip(children, subs)])

        # ---- 合并：结论摘要 + 用过的工具 + 期间新增的已证事实 ----
        blocks: list[str] = []
        for c in children:
            # 成功的外部工具 + 用过的内置工具（内置工具不产生 Step，单独记在 builtin_calls）
            done_tools = list(dict.fromkeys(
                [st.tool_alias for st in c.steps if st.status == "done"]
                + list(c.builtin_calls))) or ["（无）"]
            blocks.append(
                f"【子任务《{c.title}》· {len(c.steps)} 步 · 用过的工具：{'、'.join(done_tools)}】\n"
                f"{(c.summary or '（未给出结论）').strip()[:1200]}"
            )
        facts_line = ""
        if session.project:
            try:
                fresh = [f for f in store.list_facts(session.project)
                         if (f.get("created_at") or 0) >= started_at]
                if fresh:
                    facts_line = ("\n\n【子任务期间新增的已证事实（可直接引用）】\n"
                                  + "\n".join(f"- {str(f.get('content'))[:200]}"
                                              for f in fresh[: config.SUBTASK_MERGE_FACTS]))
            except Exception:
                logger.exception("读取子任务新增事实失败")

        merged = ("【任务分片并行结果汇总（已完成，可直接引用，不要重复验证）】\n\n"
                  + "\n\n".join(blocks) + facts_line
                  + "\n\n请基于以上汇总继续推进：把还没覆盖的面补齐，或按已证事实组织结论与报告。")
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": merged})
        await session.emit({"type": "subtask_merged", "data": {
            "count": len(children),
            "children": [{"id": c.id, "title": c.title, "steps": len(c.steps),
                          # 内置工具不产生 Step，单独给一份：否则「只记了事实」的子任务
                          # 会被界面显示成「0 步」，看起来什么都没干。
                          "builtins": list(c.builtin_calls),
                          "summary": (c.summary or "")[:300]} for c in children],
        }})
        await session.emit({"type": "reasoning",
                            "data": f"（{len(children)} 个子任务已完成并汇总回本线索）"})
        return merged

    # ---------- 知识库 / FOFA 测绘 ----------
    async def _kb_fofa_tool(self, session: Session, alias: str, tc: dict, args: str) -> str:
        """kb_search / kb_read / fofa_search 内置工具执行。"""
        arg = (args or "").strip()
        try:
            if alias == "kb_search":
                if arg.lower() == "list" or not arg:
                    topics = kb.list_topics()
                    body = "\n".join(f"- [{t['category']}] {t['file']}  {t['title']}" for t in topics)
                    note = f"知识库共 {len(topics)} 篇（kb=漏洞类型打法，rules=工作流/报告规则）：\n{body}"
                else:
                    hits = kb.search(arg)
                    if not hits:
                        note = f"知识库中未检索到「{arg}」。可用 args='list' 查看全部篇目名。"
                    else:
                        body = "\n".join(
                            f"- [{h['category']}] {h['file']}（命中 {h['score']}）\n  {h['snippet'][:200]}"
                            for h in hits
                        )
                        note = f"「{arg}」命中 {len(hits)} 篇，用 kb_read 读全文：\n{body}"
            elif alias == "kb_read":
                r = kb.read(arg)
                note = f"【{r.get('file', arg)}】\n{r.get('content') or r.get('error', '')}"
            else:  # fofa_search
                # v012 P2-3：FOFA 是全网测绘，查询词里没有任何授权主机就等于
                # 在授权范围外收集资产。要求查询语句至少包含一个授权白名单
                # 内的主机（domain="..." 里的种子），否则拒绝执行该次查询。
                from .scope import check_scope, find_hosts
                _q_hosts = [h for h in find_hosts(arg)
                            if check_scope(h) is None and h not in
                            ("localhost", "0.0.0.0")]
                if not _q_hosts:
                    note = ("FOFA 查询被拒绝：查询语句中未包含任何授权白名单内的主机。"
                            "请在 domain/host 参数中使用已获书面授权的目标"
                            "（见项目授权信息），不要查询授权范围之外的资产。")
                else:
                    r = await fofa.search(arg)
                    if r.get("error"):
                        note = f"FOFA 查询失败：{r['error']}"
                    else:
                        body = "\n".join(
                            f"- {x.get('host', '')} | {x.get('ip', '')}:{x.get('port', '')}"
                            f" | {(x.get('title') or '')[:40]} | {(x.get('server') or '')[:30]}"
                            for x in r.get("results", [])
                        )
                        note = (f"FOFA 查询「{r['query']}」返回 {r['count']} 条（消耗 F点：{r.get('consumed_fpoint', '?')}）：\n{body}"
                            "\n按「一种子闭环」：把这些活面挖完再查下一个种子。"
                            "\n（注意：返回结果仅授权域名的资产可直接测试，其他资产仅作参考）")
        except Exception as e:
            note = f"{alias} 执行异常：{e}"
            logger.exception("%s 执行异常", alias)
        body = note[: config.MAX_OUTPUT_CHARS + 2000]
        session.messages.append({"role": "tool", "tool_call_id": tc["id"], "content": body})
        await session.emit({"type": "reasoning", "data": f"（{alias} → {'OK' if '失败' not in note and '异常' not in note else '见结果'}）"})
        return body

    # ---------- 对话树：结论回流 ----------
    async def _write_back(self, session: Session, answer: str) -> None:
        """会话给出最终结论后：①摘要落库（供其他线索的上下文注入与小地图展示）
        ②父会话在线时实时推送 branch_update 通知。"""
        text = (answer or "").strip()
        if not text:
            return
        # 对话历史落库：最终结论（answer）
        try:
            store.save_chat_message(session.id, "assistant", text, kind="answer")
        except Exception:
            logger.exception("结论消息落库失败")
        session.summary = text[:1000]
        try:
            store.save_summary(session.id, session.summary)
        except Exception:
            logger.exception("结论摘要落库失败")
        if session.parent_id:
            # 父会话不在内存时（服务重启过、或父线索从未被打开）原先直接丢弃事件，
            # 且不留任何痕迹。改成从持久化层把它装回内存：事件会留在它的队列里，
            # 用户下次打开父线索时随 SSE 补投。摘要本身早已落库，内容不会真丢，
            # 这里补的是「实时通知」这条通路。
            parent = sessions.get(session.parent_id) or sessions.adopt(session.parent_id)
            if parent:
                await parent.emit({
                    "type": "branch_update",
                    "data": {
                        "child": session.id,
                        "title": session.title or "子线索",
                        "summary": text[:300],
                    },
                })

    # ---------- 上下文压缩（机械式，零 token 成本） ----------
    _STATUS_CN = {"done": "成功", "error": "失败", "denied": "被拒",
                  "running": "执行中", "pending": "待执行"}

    def _compress_history(self, session: Session) -> None:
        """把较早的工具输出压成一行「工具｜目标｜结果」，控制上下文膨胀。

        三个刻意的设计决定：
        1. **不做 LLM 摘要**。借鉴 LuaN1ao 的「摘要压缩」思路，但只借思路不借实现：
           本地小模型写摘要本身就会幻觉，等于用一个不可靠环节去修另一个不可靠环节；
           而这里要压的恰恰是「已证实的工具输出」，被幻觉污染后比不压更糟。
        2. **零 token 成本**。摘要信息全部来自 `_step_dict()` 已经算好的字段
           （工具名 / 目标 / 状态 / 归因）加上输出首行的纯裁剪，一行就是一次字符串拼接，
           不产生任何模型调用。
        3. **绝不删消息**。只改 role=tool 消息的 content。删消息会破坏
           assistant.tool_calls 与 role=tool 的 tool_call_id 配对，协议会直接报错。

        归因档位一并写进压缩行：模型回看到的是「某工具在某目标上因被拦(L3)失败」，
        而不是一句模糊的「执行失败」——否则它会换个工具在同一堵墙上再撞一次。
        """
        msgs = session.messages
        if len(msgs) <= config.HISTORY_COMPRESS_AFTER_MESSAGES:
            return
        keep_from = max(0, len(msgs) - config.HISTORY_KEEP_RECENT)
        by_call = {st.id: st for st in session.steps if st.id}
        excerpt_cap = config.HISTORY_EXCERPT_CHARS
        # 已有事实内容集合：压缩落事实前先查一次，避免重复落库
        seen_facts: set[str] = set()
        if session.project:
            try:
                seen_facts = {(f.get("content") or "").strip()
                              for f in store.list_facts(session.project)}
            except Exception:
                seen_facts = set()
        changed = 0
        for m in msgs[:keep_from]:
            if m.get("role") != "tool":
                continue
            text = m.get("content") or ""
            if text.startswith(_COMPRESSED_PREFIX):
                continue                    # 幂等：压过的绝不重复压
            st = by_call.get(m.get("tool_call_id") or "")
            if st is None:
                # 没有对应步骤记录（工具名被拦截、子任务内被拒等）：只做长度裁剪
                if len(text) <= config.HISTORY_SUMMARY_CHARS:
                    continue
                m["content"] = (f"{_COMPRESSED_PREFIX}（无执行记录）"
                                f"{self._first_line(text, config.HISTORY_SUMMARY_CHARS)}")
                changed += 1
                continue
            d = self._step_dict(st)
            mark = self._STATUS_CN.get(d["status"], d["status"] or "未知")
            if d.get("attribution"):
                mark += f"/{d['attribution']}"
            parts = [f"{_COMPRESSED_PREFIX}{d['tool_name'] or d['tool_alias']}"]
            if d.get("target"):
                parts.append(f"目标 {d['target']}")
            parts.append(mark)
            # v023.6：优先保留**关键命中行**（指纹/版本/状态码/标题），
            # 而不是只留首行——否则证据进压缩后无法再引用（实测痛点）
            key = self._key_lines(st.output or "")
            brief = key[0] if key else self._first_line(st.output or "", excerpt_cap)
            if brief:
                parts.append(brief)
            if len(key) > 1:
                parts.append(" / ".join(key[1:]))
            fid = self._save_compressed_evidence(session, st, key, seen_facts)
            if fid:
                parts.append(f"证据#{fid}（候选，可 search_history 回查原文）")
            m["content"] = "｜".join(parts)
            changed += 1
        if changed:
            logger.info("上下文压缩：%d 条历史工具输出已压成一行（保留最近 %d 条原文）",
                        changed, config.HISTORY_KEEP_RECENT)

    # ---------- 防呆提醒 ----------
    # 压缩辅助：取首个非空行（确定性裁剪，零 token）
    @staticmethod
    def _key_lines(text: str, max_lines: int = 0, cap: int = 0) -> list[str]:
        """从工具输出里挑「关键命中行」（确定性、零 token）。

        只在输出中按特征扫描（指纹/版本/状态码/标题/接口路径），命中即收，
        最多 max_lines 行。**不做任何概括**——摘出来的就是原文，因此不会
        引入幻觉；模型拿到的是可核对的原始行。
        """
        max_lines = max_lines or _COMPRESS_KEY_MAX
        cap = cap or _COMPRESS_KEY_CAP
        out: list[str] = []
        for line in (text or "").splitlines():
            s = line.strip()
            if len(s) < 6 or len(s) > 400:
                continue
            if any(re.search(p, s, re.IGNORECASE) for p in _KEY_LINE_PATTERNS):
                if s not in out:
                    out.append(s[:cap])
            if len(out) >= max_lines:
                break
        return out

    def _save_compressed_evidence(self, session: Session, step: Step,
                                  key_lines: list[str],
                                  seen: set[str]) -> str:
        """把压缩时摘出的关键命中落成**候选**事实，保证压缩后仍可回查。

        纪律：自动摘录一律 status=candidate（AI 只能产候选，不能自证已确认）；
        带 session_id/step_id 以便因果图连边；内容去重（同一条只落一次）。
        """
        if not key_lines or not session.project or not step.id:
            return ""
        content = (f"[自动摘录·待确认] {step.tool_name or step.tool_alias} 对 "
                   f"{step.target or '目标'} 的输出命中：" + "；".join(key_lines))[:500]
        if content in seen:
            return ""
        try:
            rec = store.add_fact(session.project, content, source="agent",
                                 session_id=session.id, step_id=step.id,
                                 status="candidate")
            seen.add(content)
            return str(rec.get("id") or "")
        except Exception:
            logger.debug("压缩落候选事实失败（不影响压缩）", exc_info=True)
            return ""

    @staticmethod
    def _first_line(text: str, cap: int) -> str:
        """取首个非空行并截断——纯裁剪，不做任何概括，因此不会引入幻觉。"""
        for line in (text or "").splitlines():
            line = line.strip()
            if line:
                return line[:cap] + ("…" if len(line) > cap else "")
        return ""

    @staticmethod
    def _build_reminder(session: Session, budget: dict | None = None) -> str:
        """每轮注入目标 + 已尝试工具，抑制「遗忘目标」与「重复调同一失败工具」。"""
        parts: list[str] = []
        if budget:
            parts.append(_budget_note(budget))
        if session.target:
            # v023.4：目标流量预算/防护状态提示（与步数预算提示并列）
            tnote = _traffic_note(session.target)
            if tnote:
                parts.append(tnote)
        if session.target:
            if _is_host_like(session.target):
                note = (f"所有工具的 target 参数都必须填 `{session.target}`，"
                        f"除非用户明确要求更换目标。")
            else:
                # 企业名（如「腾讯」）不能直接当扫描工具的目标
                note = (f"`{session.target}` 看起来是企业名称而非域名/IP。"
                        f"请先用可用工具（如 app_info 按名称收集 APP/资产）扩展出域名，"
                        f"拿到域名后再把域名作为 target 使用其余工具；"
                        f"不要把企业名直接塞进扫描/探测类工具的 target，也不要调用已禁用的 enscan。")
            parts.append(
                f"\n\n【本次任务目标：{session.target}】\n{note}"
                f"不要向用户索要目标，也不要把说明文字填进 target。"
            )
        # v048：任务级约束注入。放在目标之后、事实之前 ——
        # 模型先知道「打哪」，再知道「这次不许做什么」，最后才是「已经确认过什么」。
        # 必须每轮重申：v048 之前 Agent 在**第一步**就调了被任务书明令禁止的 OneForALL，
        # 说明光写在任务书开头挡不住（长上下文里它会被淹没）。
        cnote = taskguard.describe(session.constraints)
        if cnote:
            parts.append(
                f"\n\n【本次任务已声明的禁令（硬约束，不要试探）】{cnote}。"
                f"具备对应能力的工具（如 oneforall / dirsearch / goon 之于爆破，"
                f"各类 scan 工具之于扫描）**会被直接拒绝执行**，不是「需要确认」。"
                f"请改用不违反约束的做法；被拒后**不要换成另一个同类工具重试**。"
            )
        # v023.7：项目已证实事实注入（放在目标之后——模型先知道「打哪」，
        # 再看到「已经确认过什么」，避免把预算重复花在已证实的结论上）
        fnote = _facts_note(session)
        if fnote:
            parts.append(fnote)
        if session.steps:
            tried: dict[str, list[str]] = {}
            for st in session.steps:
                tried.setdefault(st.tool_alias, []).append(st.status)
            items = []
            for alias, statuses in tried.items():
                mark = "失败" if all(s != "done" for s in statuses) else "已执行"
                items.append(f"{alias}({mark}x{len(statuses)})")
            parts.append(
                "\n【本轮已尝试过的工具】" + "、".join(items)
                + "\n不要用同样的参数重复调用其中标记为「失败」的工具；"
                  "换用其他工具或换参数。重复调用失败工具是最严重的错误。"
            )
        return "".join(parts)

    # ---------- 确认流程 ----------
    async def _await_confirm(self, session: Session, step: Step) -> tuple[bool, str | None]:
        """等待用户确认，返回 (是否放行, 用户改过的 args)。

        两套闸门机制合流（各取所长）：
          · 一次性令牌（本机 A 组方案）：need_confirm 下发 token，/confirm 必须原样回传，
            令牌不符一律丢弃 —— 彻底堵住「上一次的确认」被这一步消费。
          · step_id 归属校验 + L3 后端强制两轮（009 审计修复）：L3（risk.double_confirm）
            必须连续两轮 approved 才真正放行，任一轮拒绝/超时即视为拒绝；此前服务端
            一次 approved 即放行，「二次确认」只是前端勾选框 UX。
        第二个返回值是「可改参数后执行」的落点：闸门不该只有「放行 / 拒绝」二选一，
        用户常知道该怎么改（换参数位置、去掉危险开关、缩小范围）却只能整个否掉。
        返回 None 表示用户没改参数。
        """
        approved, edited = await self._confirm_round(session, step, second=False)
        if not approved:
            return False, None
        # L3 二次确认：第一轮放行后**由后端强制**再确认一轮（前端只是渲染弹窗）。
        if step.risk.get("double_confirm"):
            again, _ = await self._confirm_round(session, step, second=True)
            if not again:
                return False, None
        return True, edited

    async def _confirm_round(self, session: Session, step: Step,
                             second: bool) -> tuple[bool, str | None]:
        """单轮确认等待（双闸门合并版）。

        融合两侧各修了一遍的确认协议：
          · 一次性令牌（006 血统）：need_confirm 下发 token，/confirm 必须原样回传；
          · step_id 归属校验（009/013 血统）：必须与本步一致，缺 step_id 一律不放行；
          · 取消感知（013 v011/v012）：等待期间轮询 cancel_event，收到取消按拒绝处理；
          · 超时 fail-closed：超时按「拒绝」处理（现象可见且可排查），绝不接受来源不明的放行。
        返回 (是否放行, 用户改过的 args)；args 为 None 表示未修改。
        """
        # 1) 排空上一轮遗留：超时未被取走、或用户连点留下的确认，若不清掉会被本步立刻消费。
        while not session.control.empty():
            try:
                session.control.get_nowait()
            except Exception:
                break

        # 2) 本轮一次性令牌 + 归属登记：/confirm 必须先比对 pending_confirm 才允许入队。
        token = uuid.uuid4().hex[:12]
        session.pending_confirm = {
            "step_id": step.id,
            "token": token,
            "double_confirm": bool(step.risk.get("double_confirm")),
        }
        session.pending_step_id = step.id
        session.state = "awaiting_confirm"
        await session.emit({
            "type": "need_confirm",
            "step": self._step_dict(step),
            "risk": step.risk,
            "token": token,          # 前端必须原样回传
            "second": second,        # 供前端区分「首次 / 二次确认」文案
        })
        if second:
            await session.emit({
                "type": "reasoning",
                "data": f"（{step.tool_name} 为 L3 高危操作：已收到第一次确认，"
                        "请再次确认以完成二次授权）",
            })
        approved = False
        edited: str | None = None
        try:
            deadline = time.monotonic() + config.CONFIRM_TIMEOUT
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                # 等待确认的同时响应取消请求：cancel_event 是 threading.Event
                # （无循环绑定），不能进 asyncio.wait——用 0.1s 分片轮询：
                # 每片等确认队列，片间查取消标志。取消按拒绝处理（fail-closed）。
                try:
                    resp = await asyncio.wait_for(session.control.get(),
                                                  timeout=min(remaining, 0.1))
                except asyncio.TimeoutError:
                    if session.cancel_event.is_set():
                        logger.info("确认等待期间收到取消请求（session=%s）", session.id)
                        approved = False
                        break
                    continue
                # 严格模式：step_id 必须存在且与本步一致才认，否则丢弃并继续等。
                # 缺 step_id 的回应一律不放行——宁可等到超时按「拒绝」处理（fail-closed，
                # 现象可见且可排查），也不接受一条来源不明的放行（fail-open，危险且无声）。
                rid = str(resp.get("step_id") or "")
                if rid != step.id:
                    logger.warning("忽略与当前步骤不匹配的确认：step_id=%r 当前=%r", rid, step.id)
                    continue
                if resp.get("token") != token:
                    logger.warning("忽略令牌不匹配的确认（可能来自上一轮或伪造）")
                    continue
                approved = bool(resp.get("approved"))
                raw = resp.get("args")
                edited = raw if isinstance(raw, str) else None
                break
        except asyncio.TimeoutError:
            # v022 修复（测试组 021 整改报告 P2-4）：超时不能静默——只写 logger
            # 前端会一直停在「执行中」，用户无法区分「在跑」与「已卡死」。
            # 实测 021 整改时静默卡死 4 分钟靠翻日志才定位。emit 后前端立即可见。
            await session.emit({
                "type": "reasoning",
                "data": f"（确认超时（{config.CONFIRM_TIMEOUT}s）：已按拒绝处理该步骤，"
                        f"如需执行请重新发起任务）",
            })
            logger.warning("确认超时（session=%s step=%s）：按拒绝处理", session.id, step.id)
            approved = False
        finally:
            session.pending_confirm = None
            session.pending_step_id = ""
            # 复位状态机：历史实现只在成功路径复位，超时后 state 会永远停在
            # awaiting_confirm（前端一直显示「执行中」，落库也是脏状态）。
            session.state = "running"
            # 排空残留：超时/异常后队列里可能还压着用户此前的点击，留着会被下一步白白消费掉。
            while not session.control.empty():
                try:
                    session.control.get_nowait()
                except Exception:
                    break
        return approved, (edited if approved else None)

    # ---------- 失败归因分层 ----------
    @staticmethod
    def _attribute_failure(step: Step, exit_code: int | None) -> tuple[str, str]:
        """判定失败性质，并给出与之一一对应的调整方向。

        借鉴 LuaN1ao 的 L0–L5 递进归因（core/prompts/.../failure_attribution_levels.jinja2），
        只保留不依赖图谱、也不依赖强模型的三档：
          L1  工具没跑起来      → 换参数 / 放大超时 / 换同类工具
          L3  被环境或权限拦下  → 换编码、换参数位置、换手法（换工具通常无效）
          L4  跑通了但没结果    → 该换测试思路，别在原假设上继续加码
        多一档 SCOPE：被授权白名单拒绝，属于授权边界，必须停手而不是绕过。

        原实现把三种情况压成同一句「执行失败」，模型分不清是工具坏了还是自己想错了，
        于是反复换工具、每条都失败——这是「连续失败就停」的根因之一。
        """
        out = step.output or ""
        low = out.lower()
        # 授权边界：executor / pyexec 均用 126 表示被白名单拒绝
        if exit_code == 126:
            return "SCOPE", ("该目标被授权白名单拒绝，属于授权边界：不要换参数或换工具绕过，"
                             "直接停止对该目标的测试并向用户说明。")
        # v023.3：目标防护状态优先判——WAF 封禁必须与普通失败分开，
        # 绝不能把它解释成「换编码/换参数继续试」（实测事故教训）。
        try:
            from . import traffic as _traffic
            root = _traffic.governor.root_domain_of(step.target or "")
            st = _traffic.governor.state_of(root) if root else {}
            state = (st or {}).get("state", "")
            if state in (_traffic.ST_BLOCKED, _traffic.ST_COOLDOWN,
                         _traffic.ST_PAUSED, _traffic.ST_MANUAL_PROBE):
                return "WAF_BLOCKED", (
                    f"目标已进入 {state} 状态（{(st or {}).get('reason', '')[:80]}）："
                    "**立即停止对该目标的任何自动请求——不要换参数、换编码、换工具或"
                    "换子域名继续尝试**。保存已有证据并向用户说明，等待人工恢复"
                    "（恢复需用户手动发起单次只读探测并确认）。")
        except Exception:
            logger.debug("目标流量状态查询失败（按普通归因继续）", exc_info=True)
        # 网络层封禁特征（RST/连接拒绝/超时）单独归因，不当作「工具坏了」
        try:
            from . import wafsignal as _ws
            sig = _ws.classify_text(out)
            if sig in (_ws.SIG_NET_RST, _ws.SIG_NET_REFUSED):
                return "WAF_CAUTION", (
                    f"检测到网络层异常（{_ws.signal_label(sig)}）：可能是目标防护或网络问题。"
                    "**停止加速与扩大测试面**，不要换编码/参数反复重试；"
                    "如需继续，先降低请求频率并观察是否恢复。")
            if sig == _ws.SIG_NET_TIMEOUT:
                return "NETWORK", (
                    "网络超时/连接不畅：可能是目标防护或本机网络问题。"
                    "不要连续重试；先确认本机网络，再考虑以更低频率少量验证。")
        except Exception:
            pass
        # L1：进程没起来 / 超时 / 异常终止
        if exit_code in (124, 137) or any(h in out for h in _L1_HINTS):
            return "L1", "工具本身没能正常执行：换参数、放大超时，或改用功能相近的其他工具。"
        # L3：连得上但被拦
        if any(h in low for h in _WAF_HINTS):
            return "L3", ("目标可达但被环境或权限拦下：换编码或换参数位置再试，"
                          "或换成不需要该权限的手法；这类拦截换工具通常无效。")
        # L4：其余情况都排除后，视为假设可能不成立
        return "L4", ("工具执行了但没拿到可用结果：这个假设可能不成立。"
                      "先换一个测试思路或换一个攻击面，不要在原假设上继续加码。")

    # ---------- 执行并收集输出 ----------
    async def _refresh_external_tools(self) -> None:
        """刷新依赖外部服务的工具可用性（v044，当前仅 Burp MCP）。

        设计要点：
          · **探测失败不抛异常、不中断任务**。Burp 没开是常态，不是故障。
          · 探测结果缓存 20 秒，避免每轮都去连一次（MCP 连不上时 TCP 拒绝很快，
            但仍是无谓开销；更关键的是避免「每轮都刷一条同样的日志」）。
          · 任何异常都吞掉——这个函数的唯一副作用是「让工具清单更准」，
            绝不能因为它自己出错而把任务带偏。
        """
        if not config.MCP_ENABLED:
            registry.unavailable_aliases = {"burp_replay", "burp_history"}
            return
        now = time.time()
        if now - self._mcp_probe_at < 20 and self._mcp_probe_at > 0:
            return
        self._mcp_probe_at = now
        try:
            ok, _note, _tools = await mcp_client.availability()
        except Exception:       # noqa: BLE001
            ok = False
        registry.unavailable_aliases = (
            set() if ok else {"burp_replay", "burp_history"})

    async def _execute(self, session: Session, step: Step, tool_call_id: str) -> None:
        tool = registry.get_by_alias(step.tool_alias)
        if tool is None:
            # v053（审计 §2.2 修）：**不能静默 return**。
            # 原实现这里什么都不做就返回，于是三件事同时发生：
            #   ① `tool_calls`（assistant 消息里声明的调用列表）与 `role=tool` 回复
            #      **失配** —— OpenAI 兼容端点会直接 400，整轮对话卡死；
            #   ② `step.status` 停在构造时的 `"pending"`，而调用方只认 done/error
            #      （见 `if step.status == "done" … elif "error"`）→ **失败计数不累加**，
            #      连续失败熔断形同虚设；
            #   ③ 不发事件、不落库 → 事件流里这一步凭空消失，界面看起来「卡住了」。
            # 主路径已在 `registry.resolve(alias)` 处校验过，正常到不了这里；
            # 但别名来自落库字段（adopt 续聊 / 外部构造都可能与当前清单不符），
            # 属于纵深防御位点 —— 这里应该**响铃**而不是静默。
            # 处理方式与上面「工具不存在」分支（`if tool is None:` 那处）保持一致。
            step.status = "error"
            step.finished_at = time.time()
            step.output = (f"[错误] 工具别名 {step.tool_alias} 在当前工具清单中不存在"
                           "（可能是历史会话留下的旧别名，或工具清单已变更）。本步未执行。")
            await session.emit({"type": "step_start", "step": self._step_dict(step)})
            await session.emit({"type": "error",
                                "data": f"已拦截不存在的工具别名：{step.tool_alias}"})
            session.messages.append({
                "role": "tool", "tool_call_id": tool_call_id,
                "content": step.output + " 请从当前可用工具清单中重新选择工具，不要沿用这个别名。",
            })
            logger.warning("拦截不存在的工具别名（_execute 纵深防御）：alias=%r",
                           step.tool_alias)
            try:
                store.save_step(session.id, self._step_dict(step))
            except Exception:
                pass
            await session.emit({"type": "step_done", "step": self._step_dict(step)})
            return

        step.status = "running"
        step.started_at = time.time()
        await session.emit({"type": "step_start", "step": self._step_dict(step)})

        chunks: list[str] = []
        exit_code = None
        step_cancelled = False
        # 内置工具走 app/replayer.py 托管运行器（不 spawn 工具箱子进程）；
        # v012 后半：四个通道全部接入取消硬终止（cancel_event 由用户
        # /api/sessions/{sid}/cancel 置位）。
        # v023.6：把项目/会话上下文透传到每个出网入口——否则流量事件的
        # project_id 为空，项目维度的流量审计（面板/报告）查不到任何数据
        # （某企业站 实战暴露：442 条事件全部落在空项目桶）。
        _ctx = {"project_id": session.project or "", "session_id": session.id}
        if tool.alias == "httpreplay":
            gen = replayer.run_replay(step.target, step.args,
                                      cancel_event=session.cancel_event, **_ctx)
        elif tool.alias == "nuclei_cli":
            gen = replayer.run_nuclei(tool, step.target, step.args,
                                      cancel_event=session.cancel_event, **_ctx)
        elif tool.alias == "py_exec":
            gen = pyexec.run_py_exec(step.args, step.target,
                                     cancel_event=session.cancel_event, **_ctx)
        elif tool.alias == "burp_replay":
            # v044：经 Burp MCP 发包。出网前会过 TrafficGovernor + scope（见
            # app/burp_tools.py），与 httpreplay 同一套治理，不是绕过闸门的后门。
            gen = burp_tools.run_burp_replay(step.target, step.args,
                                             cancel_event=session.cancel_event, **_ctx)
        elif tool.alias == "burp_history":
            # v044：读 Burp Proxy history。纯本地读取，不出网，故不接流量治理。
            gen = burp_tools.run_burp_history(step.args, **_ctx)
        else:
            gen = executor.run(tool, step.target, step.args,
                               cancel_event=session.cancel_event, **_ctx)
        async for ev in gen:
            etype = ev.get("type")
            if etype == "cancelled":
                step_cancelled = True
                chunks.append(f"[取消] {ev['data']}")
                await session.emit({"type": "output", "step_id": step.id,
                                    "data": f"[取消] {ev['data']}"})
                continue
            if etype == "output":
                chunks.append(ev["data"])
                await session.emit({"type": "output", "step_id": step.id, "data": ev["data"]})
            elif etype == "command":
                await session.emit({"type": "command", "step_id": step.id, "data": ev["data"]})
            elif etype == "error":
                chunks.append(f"[错误] {ev['data']}")
                await session.emit({"type": "output", "step_id": step.id, "data": f"[错误] {ev['data']}"})
            elif etype == "exit":
                exit_code = ev.get("code")
                await session.emit({"type": "exit", "step_id": step.id, "code": exit_code})

        step.output = "\n".join(chunks)
        step.finished_at = time.time()
        # 授权边界（退出码 126）必须无条件算失败，且**不受 ignore_exit_code 影响**。
        # 为什么单独拎出来：126 的「输出」是 executor/pyexec 写的那行 `[错误] 目标不在
        # 授权白名单内…`，它会让「有实质输出即算成功」的启发式判定成立。对开了
        # ignore_exit_code 的工具（如 EHole），这会把「越权被拦」误判成「执行成功」，
        # 于是 _attribute_failure 里那档 SCOPE（要求停手、别换参数绕过）永远送不到模型，
        # 模型就会一直换参数去撞授权墙——与设计意图正好相反。
        denied_by_scope = exit_code == 126
        # v012 后半：被取消的步骤不算失败也不回喂模型——外层循环的取消检查
        # 会立即收尾（persist_interrupted），这里只保证状态落库正确。
        if step_cancelled:
            step.status = "cancelled"
            await session.emit({"type": "step_done", "step": self._step_dict(step)})
            try:
                store.save_step(session.id, self._step_dict(step))
            except Exception:
                pass
            return
        # 部分工具退出码不可信（如 EHole：没命中「重点资产」就返回 1，
        # 但其实已经把指纹打出来了）。有实质输出就按成功算，否则会把成功误判为失败。
        # 注意：`[错误]` 开头的行是执行器自己的报错，不算「实质输出」。
        meaningful = any(ln.strip() and not ln.lstrip().startswith("[错误]")
                         for ln in step.output.splitlines())
        ok = (not denied_by_scope) and (exit_code == 0 or (tool.ignore_exit_code and meaningful))
        step.status = "done" if ok else "error"
        await session.emit({"type": "step_done", "step": self._step_dict(step)})
        # 每步即时落库
        try:
            store.save_step(session.id, self._step_dict(step))
        except Exception:
            pass

        # 回喂给模型（截断，防止撑爆上下文）
        content = step.output or "（工具无输出）"
        if not ok:
            level, guidance = self._attribute_failure(step, exit_code)
            step.attribution = level
            content = (
                f"【{step.tool_name} 执行失败｜归因 {level}】退出码 {exit_code}。输出如下：\n{content}\n"
                f"禁止用同样参数再次调用 {step.tool_name}。{guidance}"
            )
        elif not meaningful:
            step.attribution = "L4"
            # 退出码 0 但完全没有输出：多数情况说明「这个面不存在」，
            # 明确告诉模型这本身算一种结论，别重复调用同一工具同一参数。
            #
            # v053（审计 §2.1 修）：**必须回填原始输出**。原实现这里写的是
            # `content = (...)` —— 直接赋值覆盖，把上面刚算好的 content（= step.output）
            # 整条丢掉。后果不是「少显示一段」：退出码 0 但输出**全是 `[错误]` 行**的场景
            # （执行器自身报错、被前置逻辑拦下等），原始报错原文被吞掉，
            # 模型只看到「这可能说明目标不存在该测试面」→ **误判成「这面不用做」而换方向**，
            # 而正确动作是修参数或换工具。这与 `_attribute_failure` 分层归因的目的正好相反。
            # 现在与上面 `if not ok:` 分支统一为「追加原文，而非替换」。
            content = l4_no_output_feedback(step.tool_name, content)
        if len(content) > config.MAX_OUTPUT_CHARS:
            content = content[: config.MAX_OUTPUT_CHARS] + f"\n…（输出过长已截断，共 {len(step.output)} 字符）"
        session.messages.append({"role": "tool", "tool_call_id": tool_call_id, "content": content})

    def _step_dict(self, step: Step) -> dict:
        return {
            "id": step.id,
            "tool_alias": step.tool_alias,
            "tool_name": step.tool_name,
            "target": step.target,
            "args": step.args,
            "risk": step.risk,
            "status": step.status,
            # 失败归因档位（006 保留字段）：落库与复盘统计都依赖它
            "attribution": step.attribution,
            # 落库/回前端前统一裁剪：头 + 尾都保留（原来只留尾部 output[-2000:]，
            # 会把工具开头的关键结果永久丢掉，而上下文压缩又提示模型「可检索」）。
            "output": clip_output(step.output),
            "elapsed": round(step.finished_at - step.started_at, 1) if step.finished_at and step.started_at else None,
        }


agent = Agent()
