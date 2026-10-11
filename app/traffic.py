# -*- coding: utf-8 -*-
"""统一流量调度器（v023.1）：所有可控出网请求的唯一入口。

为什么需要它：v022 的 ratelimit 只是「两次请求之间 sleep」，挡不住三类真实风险
（见 v023 计划与 tgt-f.edu.cn 实测事故）：
  1. 脚本/分支在等待窗口内并发排队，累计突发；
  2. 多个会话/子任务各算各的计时，对同一目标的实际速率是各分量之和；
  3. 出了事没有任何审计，无法回答「到底发了多少请求、什么时候、谁发的」。

本模块提供：滑动窗口预算 + 目标/根域名并发限制 + 可取消等待 + 请求指纹
+ 流量事件落库 + 目标状态（暂停/封禁，为 v023.3 状态机预留）。

安全边界：
- scope 校验仍以 app/scope.py 为准（本模块只做兜底复核）；
- 本模块**不做** WAF 绕过、不做代理/IP 轮换；预算耗尽即拒绝，不自动提高；
- 暂停/封禁状态持久化（落 SQLite），服务重启不清除；
- 等待是可取消的：任务取消或目标暂停后，排队请求不得再发出。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import time
from collections import deque
from urllib.parse import urlsplit

from . import config, scope, wafsignal

logger = logging.getLogger("src_agent.traffic")

# 目标状态常量（v023.1 只有 NORMAL/PAUSED；v023.3 扩充 CAUTION/COOLDOWN/BLOCKED）
ST_NORMAL = "NORMAL"
ST_PAUSED = "PAUSED"          # 人工或预算触发的暂停
ST_CAUTION = "CAUTION"        # 疑似防护信号：降速、停止扩张
ST_COOLDOWN = "COOLDOWN"      # 强信号：不再自动发请求
ST_BLOCKED = "BLOCKED"        # 确认/高度疑似封禁：人工恢复
ST_MANUAL_PROBE = "MANUAL_PROBE"   # 用户手动发起单次恢复探测中
ST_RECOVERED = "RECOVERED"    # 探测成功，等待用户确认恢复

# 自动请求被拒绝的状态（人工探测/确认是唯一出口）。
# 含 RECOVERED：探测成功只说明「目标可能已恢复」，在用户 confirm_resume 之前
# 不得恢复自动请求（计划 9.2：成功后显示证据但不自动恢复所有任务）。
BLOCKING_STATES = {ST_PAUSED, ST_COOLDOWN, ST_BLOCKED, ST_MANUAL_PROBE, ST_RECOVERED}
# 这些都禁止自动发请求
AUTO_BLOCKED = BLOCKING_STATES

# 信号判定窗口与阈值（v023.3）——用时间窗而非累计计数，避免长期分散的
# 偶发网络抖动被累加成「封禁」（例：一小时里 3 次无关超时 ≠ 被封）
SIGNAL_WINDOW = float(os.getenv("AGENT_WAF_SIGNAL_WINDOW", "120"))
RST_TO_COOLDOWN = 2        # 窗口内 2 次 RST → COOLDOWN
REFUSED_TO_BLOCK = 2       # 窗口内 2 次拒绝 → BLOCKED
TIMEOUT_TO_BLOCK = 3       # 窗口内 3 次超时 → BLOCKED
WAF_PAGE_TO_COOLDOWN = 2   # 窗口内 2 次 WAF 页 → COOLDOWN

# 自动化业务测试的只读方法白名单（v023.2 起在此集中定义，供调度器与
# py_exec 受控通道共用；写操作必须走 L2/L3 人工双闸门）
READONLY_METHODS = ("GET", "HEAD", "OPTIONS")


class TrafficError(Exception):
    """调度拒绝（统一基类，调用方按需细分处理）。"""


class TrafficPaused(TrafficError):
    """目标处于暂停/封禁状态。"""


class TrafficBudgetExceeded(TrafficError):
    """滑动窗口请求预算耗尽。"""


class TrafficCancelled(TrafficError):
    """等待许可期间任务被取消。"""


class TrafficScopeDenied(TrafficError):
    """scope 兜底校验未通过。"""


def _is_loopback_or_private(host: str) -> bool:
    """私有/回环地址判定（用于审计标注，不作为放行依据）。"""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.startswith(("10.", "192.168.", "127.")):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False


class TrafficGovernor:
    """目标级流量调度器（进程内单例，状态落库）。"""

    def __init__(self) -> None:
        # 聚合键 → 已发送时间戳（滑动窗口）。进程内热数据，落库用于重启恢复
        self._sent: dict[str, deque] = {}
        self._fingerprints: dict[str, dict] = {}     # fp → {at, status}
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._root_locks: dict[str, asyncio.Lock] = {}
        self._global_lock: asyncio.Lock | None = None
        self._loop = None                            # 检测事件循环变化（测试/多循环场景）
        self._inflight: dict[str, int] = {}          # root → 在途请求数
        self._queued: dict[str, int] = {}            # root → 排队数
        self._states: dict[str, dict] = {}           # root → 状态（DB 为权威，内存为缓存）
        self._ip_cache: dict[str, tuple[float, str]] = {}
        self._window_loaded: set[str] = set()        # 已从 DB 恢复过窗口的 key
        self._policy_cache: dict[str, dict] = {}     # root → DB 策略覆盖
        self._signals: dict[str, deque] = {}         # root → 窗口内防护信号 (ts, sig)
        self._queue_cleared: dict[str, float] = {}   # root → 人工清空排队的标记时刻
        self._peak_inflight: dict[str, int] = {}     # root → 峰值并发（审计用）
        self._ip_resolve_enabled = True

    # ---------- 事件循环与锁管理 ----------
    def _ensure_loop(self) -> None:
        """检查事件循环是否变化；变化则重建所有 asyncio 原语。

        背景（v013 教训）：asyncio 原语绑定创建时的事件循环，跨循环使用会抛
        「bound to a different event loop」。服务是单循环，但测试里 asyncio.run()
        每次新建循环——原语必须跟着重建。
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._loop is not loop:
            self._loop = loop
            self._host_locks.clear()
            self._root_locks.clear()
            self._global_lock = asyncio.Lock()

    def _lock(self, store: dict, key: str) -> asyncio.Lock:
        lock = store.get(key)
        if lock is None:
            lock = asyncio.Lock()
            store[key] = lock
        return lock

    # ---------- 聚合键 ----------
    @staticmethod
    def root_domain_of(host: str) -> str:
        """聚合键：域名取根域名（近似），IP 原样返回。

        取末两段；两段式后缀（.com.cn 等）取末三段。
        **IP 地址必须原样返回**——末两段切分会把 127.0.0.1 变成 "0.1"，
        造成 pause/acquire 的聚合键不一致（v023.2 自测踩坑：暂停后仍放行）。
        """
        raw = (host or "").strip().lower()
        if raw.startswith("[") and "]" in raw:      # [::1]:8080
            return raw[1:raw.index("]")]
        if raw.count(":") >= 2:                     # 裸 IPv6（::1 / fe80::1）
            return raw
        h = raw.split(":")[0]                       # 去掉端口
        if not h:
            return ""
        # IPv4：四段纯数字（**必须原样返回**——末两段切分会把 127.0.0.1
        # 变成 "0.1"，造成 pause/acquire 聚合键不一致：v023.2 自测踩坑）
        parts = h.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return h
        if len(parts) <= 2:
            return h
        two_level = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk",
                     "com.hk", "com.tw", "co.jp", "com.au"}
        if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def resolve_ip(self, host: str) -> str:
        """解析主机 IP（带缓存）。解析失败返回空串——此时按根域名聚合。"""
        if not self._ip_resolve_enabled or not host:
            return ""
        now = time.time()
        cached = self._ip_cache.get(host)
        if cached and now - cached[0] < 300:
            return cached[1]
        try:
            ip = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]
        except Exception:
            ip = ""
        self._ip_cache[host] = (now, ip)
        return ip

    # ---------- 状态（DB 权威 + 内存缓存） ----------
    def _load_state(self, root: str, project_id: str) -> dict:
        if root in self._states:
            return self._states[root]
        rec = None
        try:
            from . import store
            rec = store.get_traffic_state(root)
        except Exception:
            logger.debug("读取流量状态失败（首次运行/表未建）", exc_info=True)
        st = rec or {"root_domain": root, "state": ST_NORMAL, "reason": "", "cooldown_until": 0}
        self._states[root] = st
        return st

    def state_of(self, root: str, project_id: str = "") -> dict:
        root = self.root_domain_of(root) or root
        return self._load_state(root, project_id)

    def pause(self, root: str, reason: str, *, project_id: str = "") -> dict:
        """暂停某根域名（人工操作或预算熔断）。持久化——重启不清除。

        入参统一经 root_domain_of 归一化：调用方传 "127.0.0.1" 还是
        "127.0.0.1:8080" 都落到同一个聚合键（v023.2 修）。
        """
        root = self.root_domain_of(root) or root
        st = self._load_state(root, project_id)
        st.update({"state": ST_PAUSED, "reason": reason, "cooldown_until": 0})
        self._persist_state(st, project_id)
        self._audit(root, "", "paused", reason=reason, project_id=project_id)
        return st

    def resume(self, root: str, *, project_id: str = "") -> dict:
        """恢复（人工操作）。v023.1 直接回 NORMAL；v023.3 起需经 MANUAL_PROBE。"""
        root = self.root_domain_of(root) or root
        st = self._load_state(root, project_id)
        st.update({"state": ST_NORMAL, "reason": "人工恢复"})
        self._persist_state(st, project_id)
        self._audit(root, "", "resumed", reason="人工恢复", project_id=project_id)
        return st

    def _persist_state(self, st: dict, project_id: str) -> None:
        try:
            from . import store
            store.upsert_traffic_state(project_id, st)
        except Exception:
            logger.warning("持久化流量状态失败（内存状态仍生效）", exc_info=True)

    # ---------- 防护信号与状态机（v023.3） ----------
    def note_signal(self, root: str, sig: str, *, status_code: int | None = None,
                    os_error_code: int = 0, url: str = "", project_id: str = "",
                    detail: str = "") -> dict:
        """登记一个防护信号并推进状态机。返回更新后的状态记录。

        转移规则（时间窗内计数，窗口见 SIGNAL_WINDOW）：
          NORMAL + 1×RST/超时/拒绝      → CAUTION（降速，不算封禁）
          NORMAL/CAUTION + 2×RST        → COOLDOWN（停止自动请求）
          窗口内 3×TIMEOUT              → BLOCKED（人工恢复）
          429/挑战页                    → COOLDOWN
          2×WAF 页                      → COOLDOWN
          成功响应（无新信号）          → CAUTION 回 NORMAL

        ⚠️ v040 修正 —— **ConnectRefused（10061）不再升级到任何阻断态**：
        它表示 **TCP 层根本没建链**（端口未监听 / 协议选错），目标零负载，
        与「被 WAF 封禁」语义不同（后者表现为 **RST(10054) 或静默丢包**，即"能连上但被打断"）。
        实测教训（某高校 第三轮）：对两个未开 HTTPS 的子域各打一次 `https://`，
        2 次 10061 就把**整个根域名**判为 BLOCKED，**连累其余 7 个子域（含最有价值的那个）
        全部无法测绘** —— 一次协议选错被放大成全目标停摆。
        """
        if not sig:
            return self._load_state(root, project_id)
        root = self.root_domain_of(root) or root
        now = time.time()
        dq = self._signals.setdefault(root, deque())
        dq.append((now, sig))
        horizon = now - SIGNAL_WINDOW
        while dq and dq[0][0] < horizon:
            dq.popleft()
        counts: dict[str, int] = {}
        for _, s in dq:
            counts[s] = counts.get(s, 0) + 1
        st = self._load_state(root, project_id)
        cur = st.get("state", ST_NORMAL)
        new = cur
        # v040（某高校 第三轮实测）：**ConnectRefused（10061）不再触发熔断**。
        #
        # 语义区分（这是本次修正的核心）：
        #   · RST（10054）/ 静默丢包（timeout）→ 说明「**能连上但被打断**」，是封禁的典型特征；
        #   · ConnectionRefused（10061）→ 说明「**TCP 层根本没建链**」，目标零负载，
        #     通常是**协议/端口选错**（例如对没开 HTTPS 的站打 https），**与封禁无关**。
        # 实测代价：对两个未开 HTTPS 的子域各打一次 https，2 次 10061 就把**整个根域名**
        # 判为 BLOCKED，**连累其余 7 个子域（含最有价值的那个）全部无法测绘** ——
        # 一次探测错误被放大成全目标停摆。故降级为 CAUTION（**只提示、不阻断**）。
        if sig == wafsignal.SIG_NET_TIMEOUT and counts.get(sig, 0) >= TIMEOUT_TO_BLOCK:
            new = ST_BLOCKED
        elif sig == wafsignal.SIG_NET_RST and counts.get(sig, 0) >= RST_TO_COOLDOWN:
            new = ST_BLOCKED if cur == ST_COOLDOWN else ST_COOLDOWN
        elif sig in (wafsignal.SIG_HTTP_429, wafsignal.SIG_HTTP_CHALLENGE,
                     wafsignal.SIG_HTTP_RETRY_AFTER):
            new = ST_COOLDOWN
        elif sig == wafsignal.SIG_HTTP_WAF_PAGE and \
                counts.get(sig, 0) >= WAF_PAGE_TO_COOLDOWN:
            new = ST_COOLDOWN
        elif sig == wafsignal.SIG_NET_REFUSED:
            # 仅提示「可能是协议/端口不对」，不升级为阻断态
            if cur == ST_NORMAL:
                new = ST_CAUTION
        elif sig == wafsignal.SIG_NET_RST and cur == ST_NORMAL:
            new = ST_CAUTION
        elif sig == wafsignal.SIG_NET_TIMEOUT and cur == ST_NORMAL:
            new = ST_CAUTION
        # 状态只升不降：人工暂停/探测/已确认恢复等人工态不被普通信号改写，
        # 已 BLOCKED 也不会被新信号降级（解除只看人工探测 + 确认）
        if cur in (ST_PAUSED, ST_MANUAL_PROBE):
            new = cur
        elif cur == ST_BLOCKED and new != ST_BLOCKED:
            new = ST_BLOCKED
        elif cur == ST_RECOVERED and new not in (ST_BLOCKED,):
            new = ST_RECOVERED
        st["signal_count"] = int(st.get("signal_count") or 0) + 1
        st["last_error_at"] = now
        st["last_error_type"] = sig
        st["last_error_code"] = os_error_code or 0
        if new != cur:
            st["state"] = new
            st["reason"] = (f"{wafsignal.signal_label(sig)}"
                            f"（窗口 {int(SIGNAL_WINDOW)}s 内 {counts.get(sig, 0)} 次）：{detail}"[:300])
            if new in (ST_COOLDOWN, ST_BLOCKED):
                # 同 IP 聚合：同一出口 IP 下的兄弟主机一起暂停（实测封禁是 IP 级）
                self._pause_same_ip(root, st, project_id)
            self._audit(root, url, "state_changed", reason=st["reason"], project_id=project_id)
            logger.warning("目标 %s 状态 %s → %s（%s）", root, cur, new, sig)
        self._persist_state(st, project_id)
        return st

    def _pause_same_ip(self, root: str, st: dict, project_id: str) -> None:
        """把解析到同一 IP 的其他根域名一并置为同状态（IP 级封禁的聚合暂停）。"""
        ip = self._ip_cache.get(root.split(":")[0], (0, ""))[1] if root in self._ip_cache \
            else ""
        if not ip:
            # 内存没有就现解析（失败则跳过——聚合暂停是增强而非必需）
            ip = self.resolve_ip(root)
        if not ip:
            return
        st["resolved_ip"] = ip
        peers: set[str] = set()
        try:
            from . import store
            for rec in store.list_traffic_states(project_id):
                if rec.get("resolved_ip") == ip and rec.get("root_domain") != root:
                    peers.add(rec["root_domain"])
        except Exception:
            logger.debug("同 IP 兄弟主机查询失败", exc_info=True)
        for peer in peers:
            pst = self._load_state(peer, project_id)
            if pst.get("state") in (ST_BLOCKED,):
                continue
            pst["state"] = st["state"]
            pst["reason"] = f"与 {root} 共享出口 IP {ip}，随之进入 {st['state']}"
            pst["resolved_ip"] = ip
            self._persist_state(pst, project_id)
            self._audit(peer, "", "state_changed", reason=pst["reason"],
                        project_id=project_id)

    def note_success(self, root: str, project_id: str = "") -> None:
        """成功响应：CAUTION 自动回 NORMAL（降速解除），其他状态不动。"""
        root = self.root_domain_of(root) or root
        st = self._load_state(root, project_id)
        now = time.time()
        st["last_success_at"] = now
        if st.get("state") == ST_CAUTION:
            st["state"] = ST_NORMAL
            st["reason"] = "后续请求恢复正常"
            self._signals.pop(root, None)
            self._audit(root, "", "state_changed", reason=st["reason"],
                        project_id=project_id)
        self._persist_state(st, project_id)

    async def manual_probe(self, root: str, url: str, *, project_id: str = "") -> dict:
        """用户手动发起的**单次**低风险只读探测（计划 9.2）。

        - 只允许一次 GET（不经状态检查——探测本身就是用来验证状态的手段）；
        - 仍然走 scope 校验与限速；
        - 成功 → RECOVERED（等用户 confirm_resume 才回 NORMAL）；
        - 失败 → BLOCKED（不连续重试）。
        """
        root = self.root_domain_of(root) or root
        denied = scope.check_scope(url)
        if denied:
            return {"ok": False, "error": f"探测 URL 不在授权范围内：{denied}"}
        self._load_state(root, project_id)          # 确保状态已加载
        st = self._states[root]
        prev = st.get("state", ST_NORMAL)
        st["state"] = ST_MANUAL_PROBE
        st["reason"] = f"用户手动恢复探测（原状态 {prev}）"
        self._persist_state(st, project_id)
        self._audit(root, url, "manual_probe", reason=f"原状态 {prev}",
                    project_id=project_id)
        import httpx
        try:
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                         timeout=15.0) as client:
                r = await client.get(url)
            status_code = r.status_code
            head = r.text[:2048]
        except Exception as e:
            sig, code = wafsignal.classify_network(e)
            st2 = self.note_signal(root, sig or wafsignal.SIG_NET_TIMEOUT,
                                   os_error_code=code, url=url,
                                   project_id=project_id,
                                   detail=f"手动探测失败：{type(e).__name__}")
            st2["state"] = ST_BLOCKED
            st2["reason"] = f"手动探测仍失败（{type(e).__name__}）——目标仍不可用"
            self._persist_state(st2, project_id)
            return {"ok": False, "state": ST_BLOCKED, "error": str(e)[:200]}
        sig = wafsignal.classify_http(status_code, dict(r.headers), head)
        if sig or status_code >= 500:
            st2 = self.note_signal(root, sig or wafsignal.SIG_HTTP_WAF_PAGE,
                                   status_code=status_code, url=url,
                                   project_id=project_id,
                                   detail=f"手动探测返回 HTTP {status_code}")
            st2["state"] = ST_BLOCKED
            st2["reason"] = f"手动探测仍被拦截（HTTP {status_code}）"
            self._persist_state(st2, project_id)
            return {"ok": False, "state": ST_BLOCKED, "status_code": status_code}
        st["state"] = ST_RECOVERED
        st["reason"] = f"手动探测成功（HTTP {status_code}）——等待用户确认恢复"
        self._persist_state(st, project_id)
        self._audit(root, url, "probe_ok", reason=f"HTTP {status_code}",
                    project_id=project_id)
        return {"ok": True, "state": ST_RECOVERED, "status_code": status_code}

    def confirm_resume(self, root: str, *, project_id: str = "") -> dict:
        """用户确认恢复：RECOVERED → NORMAL（v023.3 起恢复需两步：探测 + 确认）。"""
        root = self.root_domain_of(root) or root
        st = self._load_state(root, project_id)
        prev = st.get("state")
        st["state"] = ST_NORMAL
        st["reason"] = f"用户确认恢复（原状态 {prev}）"
        st["signal_count"] = 0
        self._signals.pop(root, None)
        self._persist_state(st, project_id)
        self._audit(root, "", "resumed", reason=st["reason"], project_id=project_id)
        return st

    def clear_state(self, root: str, *, project_id: str = "", reason: str = "") -> dict:
        """人工强制清除状态（仅前端人工操作，Agent 工具不可调用）。"""
        root = self.root_domain_of(root) or root
        st = self._load_state(root, project_id)
        prev = st.get("state")
        st.update({"state": ST_NORMAL, "reason": f"人工清除（原状态 {prev}）：{reason}"[:300],
                   "signal_count": 0})
        self._signals.pop(root, None)
        self._persist_state(st, project_id)
        self._audit(root, "", "state_cleared", reason=st["reason"], project_id=project_id)
        return st

    def recent_signals(self, root: str) -> list[dict]:
        """窗口内的信号列表（供状态 API 展示「已触发的 WAF 信号」）。"""
        root = self.root_domain_of(root) or root
        now = time.time()
        dq = self._signals.get(root) or deque()
        return [{"at": t, "signal": s, "label": wafsignal.signal_label(s)}
                for t, s in dq if now - t <= SIGNAL_WINDOW]

    # ---------- 排队清空（v023.5） ----------
    def clear_queue(self, root: str, *, project_id: str = "") -> dict:
        """清空某目标的待发（排队）请求。

        实现：打一个「清空标记」，正卡在锁等待里的请求拿到锁前会发现标记
        （且自身未获得许可）→ 抛 TrafficCancelled，不再发出。标记在下一次
        成功取许可时自动失效。已发出的请求无法撤回（计划：不能撤回但记录审计）。
        """
        root = self.root_domain_of(root) or root
        self._queue_cleared[root] = time.time()
        cleared = self._queued.get(root, 0)
        self._audit(root, "", "queue_cleared",
                    reason=f"人工清空排队请求（当时排队 {cleared} 个）",
                    project_id=project_id)
        return {"root_domain": root, "queued_at_clear": cleared,
                "note": "排队中的请求将在取得许可前被取消；已发出的请求无法撤回（已计入审计）"}

    # ---------- 窗口与预算 ----------
    def _recover_window(self, key: str) -> None:
        """首次访问某 key 时从 DB 恢复最近窗口内的发送时间戳（重启恢复）。"""
        if key in self._window_loaded:
            return
        self._window_loaded.add(key)
        dq = self._sent.setdefault(key, deque())
        if dq:
            return
        try:
            from . import store
            rows = store.recent_traffic_sends(key, config.TRAFFIC_WINDOW_SECONDS)
            dq.extend(rows)
        except Exception:
            logger.debug("窗口恢复失败（新库/表未建）", exc_info=True)

    def _prune(self, key: str, now: float) -> deque:
        dq = self._sent.setdefault(key, deque())
        horizon = now - config.TRAFFIC_WINDOW_SECONDS
        while dq and dq[0] < horizon:
            dq.popleft()
        return dq

    def _limits(self, root: str = "") -> dict:
        """有效策略：DB 里该根域名的覆盖（若有）优先，否则用 config 保守默认。

        任何来源都只能更低——测试模式是唯一放大通道且由环境变量显式开启，
        生产环境不设即保守。
        """
        mult = config.TRAFFIC_TEST_MULTIPLIER if config.TRAFFIC_TEST_MODE else 1
        concurrency_bonus = 4 if config.TRAFFIC_TEST_MODE else 1
        lim = {
            "window": config.TRAFFIC_WINDOW_SECONDS,
            "max_requests": config.TRAFFIC_MAX_REQUESTS,
            "burst": config.TRAFFIC_BURST,
            "host_conc": max(1, config.TRAFFIC_HOST_CONCURRENCY),
            "root_conc": max(1, config.TRAFFIC_ROOT_CONCURRENCY),
        }
        if root:
            if root not in self._policy_cache:
                pol = None
                try:
                    from . import store
                    pol = store.get_traffic_policy(root)
                except Exception:
                    logger.debug("读取流量策略失败（用默认档）", exc_info=True)
                self._policy_cache[root] = pol or {}
            pol = self._policy_cache[root] or {}
            if pol.get("window_seconds"):
                lim["window"] = int(pol["window_seconds"])
            if pol.get("max_requests"):
                lim["max_requests"] = int(pol["max_requests"])
            if pol.get("burst_limit"):
                lim["burst"] = int(pol["burst_limit"])
            if pol.get("host_concurrency"):
                lim["host_conc"] = max(1, int(pol["host_concurrency"]))
            if pol.get("root_concurrency"):
                lim["root_conc"] = max(1, int(pol["root_concurrency"]))
        lim["max_requests"] *= mult
        lim["burst"] *= mult
        lim["host_conc"] = max(1, lim["host_conc"] * concurrency_bonus)
        lim["root_conc"] = max(1, lim["root_conc"] * concurrency_bonus)
        # v023.3：CAUTION 降速——疑似防护信号后主动收缩（预算减半、突发归 1、
        # 并发 1），不等到 COOLDOWN 才动手（计划 8.4：CAUTION 要降速并暂停扩张）
        if root and (self._states.get(root, {}).get("state") == ST_CAUTION):
            lim["max_requests"] = max(1, lim["max_requests"] // 2)
            lim["burst"] = 1
            lim["host_conc"] = 1
            lim["root_conc"] = 1
        return lim

    # ---------- 指纹 ----------
    @staticmethod
    def fingerprint(method: str, url: str, *, body: str = "", identity_id: str = "",
                    variant_id: str = "", headers: dict | None = None) -> str:
        """请求指纹：方法 + 规范化 URL + 敏感头哈希 + body 哈希 + 身份 + 变体。

        只哈希不落原文——指纹表不含凭据内容。
        """
        from .importers.common import normalize_url
        h = {"m": (method or "GET").upper(), "u": normalize_url(url),
             "b": hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest()[:16],
             "i": identity_id or "", "v": variant_id or "",
             "h": hashlib.sha256(json.dumps(sorted((headers or {}).items()),
                                            ensure_ascii=False).encode()).hexdigest()[:16]}
        return hashlib.sha256(json.dumps(h, sort_keys=True).encode()).hexdigest()[:32]

    def cached_observation(self, fp: str) -> dict | None:
        """TTL 内是否已有同指纹成功观察（TTL=0 时永远返回 None）。

        v023.4：缓存里存的是**完整脱敏响应**（供差分/流程直接复用，避免重复请求）；
        命中时调用方应把 cached=True 标进返回，便于审计区分「真实请求」与「复用」。
        """
        if config.TRAFFIC_FP_TTL <= 0 or not fp:
            return None
        rec = self._fingerprints.get(fp)
        if rec and time.time() - rec["at"] < config.TRAFFIC_FP_TTL:
            return dict(rec)
        return None

    def put_observation(self, fp: str, status_code: int, response: dict | None = None) -> None:
        """登记一次观察。response 为可复用的完整响应（已截断，不含凭据）。"""
        if config.TRAFFIC_FP_TTL > 0 and fp:
            self._fingerprints[fp] = {"at": time.time(), "status": status_code,
                                      "response": dict(response or {})}

    # ---------- 许可（核心） ----------
    async def acquire(self, url: str, *, project_id: str = "", session_id: str = "",
                      identity_id: str = "", tool_alias: str = "", method: str = "GET",
                      fingerprint: str = "", cancel_event=None) -> dict:
        """取得一次出网许可。未取得许可前不得发起网络请求。

        阻塞点全部可取消：等待期间若 cancel_event 置位、目标进入暂停/封禁状态，
        立即抛出对应异常（排队请求不会在暂停后继续发出）。
        """
        self._ensure_loop()
        # 1) scope 兜底（授权边界的第一责任方仍是 scope.py；这里防绕过）
        denied = scope.check_scope(url)
        if denied:
            self._audit_raw(url, "rejected", reason=denied, project_id=project_id,
                            session_id=session_id, tool_alias=tool_alias)
            raise TrafficScopeDenied(denied)

        parts = urlsplit(url)
        host = (parts.netloc or "").split("@")[-1]
        root = self.root_domain_of(host)
        ip = self.resolve_ip(host.split(":")[0])
        lim = self._limits(root)

        def _cancelled() -> bool:
            return bool(cancel_event is not None and cancel_event.is_set())

        def _check_state():
            st = self._load_state(root, project_id)
            if st.get("state") in BLOCKING_STATES:
                raise TrafficPaused(
                    f"目标 {root} 当前状态 {st.get('state')}（{st.get('reason') or '无原因'}）——"
                    f"已停止自动请求，需人工恢复")
            if _cancelled():
                raise TrafficCancelled("任务已取消，排队请求不再发出")

        _check_state()
        root_lock = self._lock(self._root_locks, root or "default")
        host_lock = self._lock(self._host_locks, host or "default")

        self._queued[root] = self._queued.get(root, 0) + 1
        try:
            # 2) 根域名串行（同时最多 root_conc 个在途；v023.1 默认 1）
            async with root_lock:
                self._check_pause_during_wait(root, project_id, _cancelled)
                async with host_lock:
                    self._check_pause_during_wait(root, project_id, _cancelled)
                    # 3) 预算：滑动窗口 + 突发
                    self._enforce_budget(root, lim, project_id, session_id,
                                         tool_alias, url)
                    now = time.time()
                    self._prune(root, now).append(now)
                    # 注意：不要对 host 维度重复 append——root 与 host 相同时
                    # setdefault 返回的是同一个 deque，会双计数（v023.1 自测踩坑）
                    if config.TRAFFIC_FP_TTL > 0 and fingerprint:
                        self.put_observation(fingerprint, -1)
                    self._inflight[root] = self._inflight.get(root, 0) + 1
                    self._peak_inflight[root] = max(self._peak_inflight.get(root, 0),
                                                    self._inflight[root])
                    self._queue_cleared.pop(root, None)   # 取到许可 → 清空标记失效
                    permit = {"root": root, "host": host, "resolved_ip": ip,
                              "sent_at": now, "fingerprint": fingerprint,
                              "project_id": project_id, "session_id": session_id,
                              "tool_alias": tool_alias, "url": url, "method": method}
                    self._audit_raw(url, "sent", project_id=project_id,
                                    session_id=session_id, tool_alias=tool_alias,
                                    fingerprint=fingerprint, host=host, root=root, ip=ip)
                    return permit
        finally:
            self._queued[root] = max(0, self._queued.get(root, 0) - 1)

    def _check_pause_during_wait(self, root: str, project_id: str, cancelled) -> None:
        """拿到锁后、真正发送前，再查一次状态、取消与「清空排队」标记
        （计划 5.4：暂停后不得发出；人工清空后排队请求不得继续）。"""
        if cancelled():
            raise TrafficCancelled("任务已取消，排队请求不再发出")
        cleared_at = self._queue_cleared.get(root)
        if cleared_at:
            # 标记只对「清空之前就已排队的请求」生效：本请求尚未取得许可 → 取消
            self._queue_cleared.pop(root, None)
            raise TrafficCancelled("排队请求已被人工清空（未发出）")
        st = self._load_state(root, project_id)
        if st.get("state") in BLOCKING_STATES:
            raise TrafficPaused(f"目标 {root} 已进入 {st.get('state')}，排队请求终止")

    def _enforce_budget(self, root: str, lim: dict, project_id: str, session_id: str,
                        tool_alias: str, url: str) -> None:
        self._recover_window(root)
        now = time.time()
        dq = self._prune(root, now)
        if len(dq) >= lim["max_requests"]:
            reason = (f"目标 {root} 在 {lim['window']}s 窗口内已发 {len(dq)} 个请求，"
                      f"达到预算上限 {lim['max_requests']}——已暂停，不会自动提高额度")
            self.pause(root, reason, project_id=project_id)
            self._audit_raw(url, "rejected", reason=reason, project_id=project_id,
                            session_id=session_id, tool_alias=tool_alias)
            raise TrafficBudgetExceeded(reason)
        recent_burst = sum(1 for t in dq if now - t < 10.0)
        if recent_burst >= lim["burst"]:
            reason = (f"10 秒内已发 {recent_burst} 个请求，达到突发上限 {lim['burst']}"
                      f"（防脚本爆发式请求）")
            self._audit_raw(url, "rejected", reason=reason, project_id=project_id,
                            session_id=session_id, tool_alias=tool_alias)
            raise TrafficBudgetExceeded(reason)

    # ---------- 结果登记与审计 ----------
    async def release(self, permit: dict, *, status_code: int | None = None,
                      bytes_in: int = 0, error_type: str = "", os_error_code: int = 0,
                      response_head: str = "") -> None:
        """请求结束后登记结果：并发递减 + **防护信号自动分类与状态机推进** + 事件落库。

        v023.3 起这里承担「网络层封禁感知」：网络异常按 wafsignal 分类成
        RST/REFUSED/TIMEOUT 信号交给状态机；HTTP 响应按 429/挑战页/WAF 页分类。
        单次错误只降速（CAUTION），窗口内累计才升级到 COOLDOWN/BLOCKED——
        避免把本机抖动误判为封禁。
        """
        if not permit:
            return
        root = permit.get("root", "")
        self._inflight[root] = max(0, self._inflight.get(root, 0) - 1)
        now = time.time()
        st = self._load_state(root, permit.get("project_id", ""))
        st["resolved_ip"] = permit.get("resolved_ip") or st.get("resolved_ip", "")
        proj = permit.get("project_id", "")
        url = permit.get("url", "")

        sig = wafsignal.SIG_NONE
        if error_type:
            # 从异常名/errno 归类（调用方传的是 type(e).__name__ 与 errno）
            sig = self._signal_from_error(error_type, os_error_code)
            st = self.note_signal(root, sig or wafsignal.SIG_NONE,
                                  os_error_code=os_error_code, url=url,
                                  project_id=proj,
                                  detail=f"{error_type}" + (f" (errno={os_error_code})"
                                                            if os_error_code else ""))
            if not sig:
                st["last_error_at"] = now
                st["last_error_type"] = error_type
                st["last_error_code"] = os_error_code or 0
                self._persist_state(st, proj)
        elif status_code is not None:
            sig = wafsignal.classify_http(status_code, None, response_head)
            if sig in (wafsignal.SIG_HTTP_WAF_PAGE, wafsignal.SIG_HTTP_CHALLENGE,
                       wafsignal.SIG_HTTP_429, wafsignal.SIG_HTTP_RETRY_AFTER):
                st = self.note_signal(root, sig, status_code=status_code, url=url,
                                      project_id=proj,
                                      detail=f"HTTP {status_code}")
            elif 200 <= status_code < 400:
                self.note_success(root, proj)
                st = self._load_state(root, proj)
            elif status_code >= 500:
                st["last_error_at"] = now
                st["last_error_type"] = f"HTTP {status_code}"
                self._persist_state(st, proj)
        if config.TRAFFIC_FP_TTL > 0 and permit.get("fingerprint") and status_code:
            self.put_observation(permit["fingerprint"], status_code)
        self._audit_raw(url, "settled",
                        project_id=proj,
                        session_id=permit.get("session_id", ""),
                        tool_alias=permit.get("tool_alias", ""),
                        fingerprint=permit.get("fingerprint", ""),
                        host=permit.get("host", ""), root=root,
                        ip=permit.get("resolved_ip", ""),
                        status_code=status_code, bytes_in=bytes_in,
                        error_type=error_type, os_error_code=os_error_code)

    @staticmethod
    def _signal_from_error(error_type: str, os_error_code: int) -> str:
        """把调用方传来的异常名/errno 映射为网络层信号（不依赖异常对象）。"""
        et = (error_type or "").lower()
        if "connectionreset" in et or os_error_code == 10054:
            return wafsignal.SIG_NET_RST
        if "connectionrefused" in et or os_error_code == 10061:
            return wafsignal.SIG_NET_REFUSED
        if "timeout" in et or os_error_code in (10060, 110):
            return wafsignal.SIG_NET_TIMEOUT
        if "gaierror" in et or "nameresolution" in et:
            return wafsignal.SIG_NET_DNS
        if "connect" in et:          # httpx.ConnectError 之类（底层未暴露）
            return wafsignal.SIG_NET_REFUSED
        return wafsignal.SIG_NONE

    # ---------- 统计（供状态 API / 前端） ----------
    def stats(self, root: str) -> dict:
        lim = self._limits(root)
        now = time.time()
        self._recover_window(root)
        dq = self._prune(root, now)
        st = self._load_state(root, "")
        return {
            "root_domain": root,
            "state": st.get("state", ST_NORMAL),
            "reason": st.get("reason", ""),
            "resolved_ip": st.get("resolved_ip", ""),
            "window_seconds": lim["window"],
            "max_requests": lim["max_requests"],
            "used": len(dq),
            "remaining": max(0, lim["max_requests"] - len(dq)),
            "requests_last_60s": sum(1 for t in dq if now - t < 60),
            "requests_last_600s": sum(1 for t in dq if now - t < 600),
            "inflight": self._inflight.get(root, 0),
            "queued": self._queued.get(root, 0),
            "tests_mode": config.TRAFFIC_TEST_MODE,
            "last_success_at": st.get("last_success_at"),
            "last_error_at": st.get("last_error_at"),
            "last_error_type": st.get("last_error_type", ""),
            "last_error_label": wafsignal.signal_label(st.get("last_error_type", "")),
            "signal_count": st.get("signal_count", 0),
            "recent_signals": self.recent_signals(root),
        }

    def roots_seen(self) -> list[str]:
        keys = set(self._sent.keys())
        try:
            from . import store
            keys.update(store.distinct_traffic_roots())
        except Exception:
            pass
        return sorted(k for k in keys if k)

    # ---------- 审计落库（失败不阻断请求） ----------
    def _audit(self, root: str, url: str, event_type: str, reason: str = "",
               project_id: str = "") -> None:
        self._audit_raw(url or root, event_type, reason=reason, project_id=project_id,
                        root=root)

    def _audit_raw(self, url: str, event_type: str, *, reason: str = "",
                   project_id: str = "", session_id: str = "", tool_alias: str = "",
                   fingerprint: str = "", host: str = "", root: str = "",
                   ip: str = "", status_code: int | None = None, bytes_in: int = 0,
                   error_type: str = "", os_error_code: int = 0) -> None:
        try:
            from . import store
            if not host:
                parts = urlsplit(url)
                host = (parts.netloc or "").split("@")[-1]
            if not root:
                root = self.root_domain_of(host)
            port = 0
            if "://" in url:
                try:
                    port = urlsplit(url).port or (443 if url.startswith("https") else 80)
                except ValueError:
                    port = 0
            store.add_traffic_event({
                "project_id": project_id, "session_id": session_id,
                "root_domain": root, "host": host, "resolved_ip": ip, "port": port,
                "tool_alias": tool_alias, "identity_label": "",
                "request_fingerprint": fingerprint, "event_type": event_type,
                "status_code": status_code, "error_type": error_type,
                "os_error_code": os_error_code, "bytes_in": bytes_in,
                "redaction_summary": reason[:300],
            })
        except Exception:
            logger.debug("流量事件落库失败（不影响请求）", exc_info=True)

    # ---------- 测试支持 ----------
    def reset(self) -> None:
        """清空进程内状态（仅测试用；不动数据库）。"""
        self._sent.clear()
        self._fingerprints.clear()
        self._host_locks.clear()
        self._root_locks.clear()
        self._global_lock = None
        self._inflight.clear()
        self._queued.clear()
        self._states.clear()
        self._window_loaded.clear()
        self._ip_cache.clear()
        self._policy_cache.clear()
        self._signals.clear()


# 进程内单例
governor = TrafficGovernor()
