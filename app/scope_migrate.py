# -*- coding: utf-8 -*-
"""`data/scope.json` 结构化迁移（v050 配置控制台 P1）。

## 背景：现在为什么不够用

`scope.json` 目前是「`domains: [...]` 数组 + `_说明:` 一大段自由文本」。
真正有信息量的授权细节（补天项目号 cid、授权主体、确认日期、「主域含子域」、限制条件）
**全写在 `_说明` 那段文本里**，只有人能读：

    【授权留痕】xxx.com 主域含子域：某某公司，补天公益 SRC 项目 cid=64586
    （用户 2026-09-09 确认在测）。……

后果有三个，都是本项目反复吃过亏的形状：

1. **机器读不到** —— 没法做「这条授权到期了没」「哪些域还没有 cid」这类校验，
   全靠人记得；
2. **人改易错** —— 加一个域要同时改 `domains` 和 `_说明` 两处，漏一处就出现
   「白名单里有、留痕里没有」的静默不一致；
3. **控制台没法安全地编辑它** —— 不知道结构就没法做字段级校验。

## 本模块做什么

把「`domains` + `_说明` 文本」反解成结构化 `targets`，**解得出的才填，解不出的留空并标
`needs_review`**。绝不猜：猜错的授权信息比缺失的更危险（缺失会提示人来看，
猜错会让人以为已经核对过）。

## 一条硬约束：仓库里不得硬编码「域名 → cid/主体」映射

`data/scope.json` 是 gitignored 的（含真实授权靶标），而本模块**是入库的**。
所以解析逻辑只能**从文件现读现解**，不允许在代码里写任何 `"某域名": "cid=xxxxx"` 之类的表 ——
那等于把交战数据抄进公开仓库，正是 v045/v046 两版在治的病。
"""
from __future__ import annotations

import copy
import re
from typing import Any

# 句子切分：中文句号/分号/换行。用 `_说明` 的自然断句，避免正则跨条吞并。
_SPLIT = re.compile(r"[。；\n]+")

# cid 取法：`cid=64586` 这种带等号的最可靠；`cid 待补` 视为「有 cid 字段但值缺失」
_CID_EQ = re.compile(r"cid\s*=\s*(\d{1,10})", re.I)
_CID_PENDING = re.compile(r"cid\s*(待补|待定|待确认|未知|未提供|缺)", re.I)
# 授权确认日期：形如 2026-09-25（也容忍 2026/09/25）
_DATE = re.compile(r"(20\d{2})[-/](\d{1,2})[-/](\d{1,2})")
# 「主域含子域」这一句是**唯一**能表明子域授权的地方（闸门目前一律含子域，见设计文档第 4.3 节）
_SUBDOMAIN_STMT = re.compile(r"主域含子域|含子域|及其子域")
# 主体名：取「：」之后到第一个「，」或「（」之前
_OWNER = re.compile(r"[：:]\s*([^，,（(。；;]+)")
# 限制条件：末尾「，仅只读轻量测试」这类
_RESTRICT = re.compile(r"[，,]\s*(仅[^。；]*)")
# 「该项目」这类代词不是主体名
_OWNER_STOP = ("补天", "该项目", "上述", "此项目", "用户")


def _sentences(note: str) -> list[str]:
    return [s.strip() for s in _SPLIT.split(note or "") if s.strip()]


def _find_sentence(sents: list[str], host: str) -> str:
    """找提到该 host 的句子。

    匹配用的是 host 的**词干**（去掉首个标签）而不是全串，理由：`_说明` 里写的是
    `a.test`，而 `domains` 里同时有 `www.a.test` 这种带前缀的写法 ——
    用词干才能让 `www.a.test` 也认到 `a.test` 那条留痕。
    但**必须带点边界**：`nota.test` 不该命中 `a.test`（v046 的靶标词干
    检查踩过同类问题）。
    """
    h = (host or "").strip().lower()
    if not h:
        return ""
    stem = h.split(".", 1)[1] if h.count(".") >= 2 else h
    for cand in (h, stem):
        for s in sents:
            if re.search(r"(?<![\w.-])" + re.escape(cand) + r"(?![\w-])", s, re.I):
                return s
    return ""


def parse_authorization_notes(note_text: str,
                             hosts: list[str]) -> dict[str, dict]:
    """从 `_说明` 文本反解每个 host 的授权信息。

    返回 `{host: {include_subdomains, cid, owner, authorized_at, scope_note,
    needs_review, source_sentence}}`。**找不到留痕的 host 也会返回一条**
    （`needs_review=True`），因为「这个域没有留痕」本身就是需要人看的信息。

    刻意不做的事：不猜主体（宁可空）、不把「cid 待补」当成有效 cid。

    **cid 的来源包含 URL 形式**：`https://www.butian.net/Loo/submit?cid=64586` 里的
    `cid=` 也会被取到 —— 因为它出现在**点名了这个域的那一句**里，归属是明确的。
    真正的把关交给 `needs_review`：只要 cid 或主体缺一个就标待复核，
    所以「从 URL 取到的 cid 配上缺失的主体」照样会进人工复核清单，不会被静默当成已核对。
    """
    sents = _sentences(note_text)
    out: dict[str, dict] = {}
    for h in hosts:
        host = (h or "").strip().lower()
        if not host:
            continue
        sent = _find_sentence(sents, host)
        info: dict[str, Any] = {
            "include_subdomains": bool(sent and _SUBDOMAIN_STMT.search(sent)),
            "cid": "",
            "owner": "",
            "authorized_at": "",
            "scope_note": "",
            "needs_review": True,
            "source_sentence": sent,
        }
        if sent:
            m = _CID_EQ.search(sent)
            if m:
                info["cid"] = m.group(1)
            # 「cid 待补」→ 明确标记待补，而不是当成「没写」
            if _CID_PENDING.search(sent) and not info["cid"]:
                info["scope_note"] = "cid 待补"
            m = _DATE.search(sent)
            if m:
                info["authorized_at"] = (f"{m.group(1)}-{int(m.group(2)):02d}-"
                                         f"{int(m.group(3)):02d}")
            m = _OWNER.search(sent)
            if m:
                ow = m.group(1).strip()
                if ow and not any(k in ow for k in _OWNER_STOP):
                    info["owner"] = ow
            m = _RESTRICT.search(sent)
            if m:
                rst = m.group(1).strip()
                info["scope_note"] = (info["scope_note"] + "；" + rst).strip("；")
            # 只有 cid 与主体都拿到，才算「不需要人复核」
            info["needs_review"] = not (info["cid"] and info["owner"])
            if not sent.strip():
                info["needs_review"] = True
        out[host] = info
    return out


def plan(scope: dict, *, added_by: str = "migration") -> tuple[dict, dict]:
    """生成迁移后的 scope 与一份报告。**不写盘**（调用方决定何时落盘）。

    保留策略（按用户 2026-09-27 的决定）：
      · `_说明` **原文保留**，一味不动 —— 它是人工可读的授权依据，结构化替代不了它；
        只在末尾追加一行指向 `targets` 的说明，方便后来人知道去哪看结构；
      · `domains` **保留并按 targets 重新生成**（顺序：先原 domains 的顺序，
        再补 targets 里新增的）—— 保证任何直接读 `domains` 的既有代码行为不变；
      · 既有 `targets`（若已存在）**不覆盖**，只补缺失字段。

    报告包含：新增/已存在条数、`needs_review` 清单、`domains` 与 `targets` 是否一致。
    """
    orig = copy.deepcopy(scope) if isinstance(scope, dict) else {}
    domains = [d for d in (orig.get("domains") or []) if isinstance(d, str) and d.strip()]
    note = str(orig.get("_说明") or "")
    existing = {str(t.get("host", "")).lower(): t
                for t in (orig.get("targets") or []) if isinstance(t, dict)}

    hosts: list[str] = []
    for h in list(domains) + list(existing.keys()):
        hl = h.strip().lower()
        if hl and hl not in hosts:
            hosts.append(hl)

    parsed = parse_authorization_notes(note, hosts)

    targets: list[dict] = []
    for host in hosts:
        prev = dict(existing.get(host) or {})
        info = parsed.get(host) or {}
        entry = {
            "host": host,
            # 已有显式值优先（人工写过的胜过从文本猜的）
            "include_subdomains": prev.get("include_subdomains",
                                           info.get("include_subdomains", True)),
            "ports": prev.get("ports", None),
            "schemes": prev.get("schemes", None),
            "cid": str(prev.get("cid") or info.get("cid") or ""),
            "owner": str(prev.get("owner") or info.get("owner") or ""),
            "authorized_at": str(prev.get("authorized_at")
                                 or info.get("authorized_at") or ""),
            "scope_note": str(prev.get("scope_note") or info.get("scope_note") or ""),
            "added_by": str(prev.get("added_by") or added_by),
        }
        if bool(prev.get("needs_review")) or info.get("needs_review", True) \
                or not (entry["cid"] and entry["owner"]):
            entry["needs_review"] = True
        targets.append(entry)

    new = dict(orig)
    new["_说明"] = note + (
        "\n\n【结构化条目】上表之上的 `targets` 是同一批授权的结构化视图"
        "（host / 是否含子域 / 端口 / 协议 / 补天 cid / 授权主体 / 确认日期 / 限制条件），"
        "由配置控制台 `/console` 维护。`domains` 由控制台自动同步，两者不一致时"
        "控制台总览页会告警。此段文本是人工可读的授权依据，控制台不会改写它。")
    new["domains"] = hosts
    new["targets"] = targets

    review = [t["host"] for t in targets if t.get("needs_review")]
    report = {
        "hosts": len(hosts),
        "with_cid": sum(1 for t in targets if t.get("cid")),
        "with_owner": sum(1 for t in targets if t.get("owner")),
        "needs_review": review,
        "note_preserved": bool(note),
        "domains_synced": sorted(new["domains"]) == sorted(hosts),
    }
    return new, report


def validate(scope: dict) -> list[str]:
    """结构校验，返回问题列表（空 = 通过）。控制台提交前调它，迁移脚本也调。"""
    problems: list[str] = []
    if not isinstance(scope, dict):
        return ["scope 顶层必须是 JSON 对象"]
    targets = scope.get("targets")
    if targets is None:
        return []                                        # 旧写法（只有 domains）合法
    if not isinstance(targets, list):
        return ["targets 必须是数组"]
    seen: set[str] = set()
    for i, t in enumerate(targets):
        if not isinstance(t, dict):
            problems.append(f"targets[{i}] 不是对象")
            continue
        host = str(t.get("host") or "").strip().lower()
        if not host:
            problems.append(f"targets[{i}] 缺 host")
            continue
        if host in seen:
            problems.append(f"host 重复：{host}")
        seen.add(host)
        if _HOST_BAD.search(host):
            problems.append(f"host 含非法字符：{host}")
        ports = t.get("ports")
        if ports is not None:
            if not isinstance(ports, list) or not ports:
                problems.append(f"{host} 的 ports 必须是非空数组或 null")
            elif any((not isinstance(p, int)) or isinstance(p, bool)
                     or not (1 <= p <= 65535) for p in ports):
                problems.append(f"{host} 的 ports 取值非法（1-65535）")
        schemes = t.get("schemes")
        if schemes is not None:
            if not isinstance(schemes, list) or not schemes:
                problems.append(f"{host} 的 schemes 必须是非空数组或 null")
            elif any(str(x).lower() not in ("http", "https") for x in schemes):
                problems.append(f"{host} 的 schemes 只允许 http/https")
    if targets and not scope.get("domains"):
        problems.append("domains 为空但 targets 非空（控制台会自动同步，请重跑提交）")
    return problems


_HOST_BAD = re.compile(r"[\s/\\:?#@]|\.\.")
