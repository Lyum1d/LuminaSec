# -*- coding: utf-8 -*-
"""防护信号分类器（v023.3）：HTTP 层 + 网络层。

背景（tgt-f.edu.cn 实测）：目标 WAF 的封禁**没有任何 HTTP 层信号**——先是
远程 RST（WinError 10054），再是 ConnectionRefused（10061），最后静默丢包
（TimeoutError）。只盯 429/验证码的状态机对这类封禁完全失明。

因此本模块把「网络层特征」提升为一等信号，同时保留 HTTP 层识别：

  HTTP 层：429 / Retry-After / 挑战页 / 验证码 / 封禁提示文本 / 连续 WAF 403
  网络层：RST(10054) / ConnectionRefused(10061) / 连续超时 / DNS 失败

判定纪律：单次网络错误**不直接**认定为 WAF（本机抖动、目标重启都可能造成），
状态机（app/traffic.py）按时间窗累计后才升级状态。
"""
from __future__ import annotations

import re

# ---- 信号常量 ----
SIG_NONE = ""
SIG_HTTP_429 = "HTTP_429"
SIG_HTTP_RETRY_AFTER = "HTTP_RETRY_AFTER"
SIG_HTTP_WAF_PAGE = "HTTP_WAF_PAGE"
SIG_HTTP_CHALLENGE = "HTTP_CHALLENGE"
SIG_NET_RST = "NET_RST"                 # 远程重置（WinError 10054）
SIG_NET_REFUSED = "NET_REFUSED"         # 连接被拒（WinError 10061）
SIG_NET_TIMEOUT = "NET_TIMEOUT"         # 超时/静默丢包
SIG_NET_DNS = "NET_DNS"                 # DNS 解析失败

# 强信号（可直接进 COOLDOWN 的）
STRONG_SIGNALS = {SIG_HTTP_429, SIG_HTTP_CHALLENGE, SIG_HTTP_WAF_PAGE}

# HTTP 响应体里的防护特征（小写匹配）
_WAF_PAGE_HINTS = (
    "访问频繁", "请求过于频繁", "ip 已被", "ip地址已被", "已被封禁", "封禁",
    "access denied by", "request blocked", "blocked by", "security policy",
    "your request has been blocked", "waf", "cloudflare", "mod_security",
    "safedog", "安全狗", "拦截",
)
_CHALLENGE_HINTS = (
    "captcha", "验证码", "challenge", "cf-challenge", "jschl", "turnstile",
    "请完成验证", "人机验证", "verify you are human",
)
# 工具输出文本里的网络层特征 → 信号（用于 shell 工具/脚本输出归因）
_TEXT_SIGNALS: tuple[tuple[str, str], ...] = (
    ("10054", SIG_NET_RST), ("connectionreseterror", SIG_NET_RST),
    ("connection reset by peer", SIG_NET_RST), ("connection aborted", SIG_NET_RST),
    ("10061", SIG_NET_REFUSED), ("connectionrefusederror", SIG_NET_REFUSED),
    ("connection refused", SIG_NET_REFUSED),
    ("etimedout", SIG_NET_TIMEOUT), ("timed out", SIG_NET_TIMEOUT),
    ("timeouterror", SIG_NET_TIMEOUT), ("readtimeout", SIG_NET_TIMEOUT),
    ("max retries exceeded", SIG_NET_TIMEOUT),
    ("name or service not known", SIG_NET_DNS), ("gaierror", SIG_NET_DNS),
    ("getaddrinfo failed", SIG_NET_DNS), ("no address associated", SIG_NET_DNS),
    ("too many requests", SIG_HTTP_429), ("429 too many", SIG_HTTP_429),
    ("retry-after", SIG_HTTP_RETRY_AFTER),
)


def classify_http(status_code: int | None, headers: dict | None = None,
                  body_head: str = "") -> str:
    """从 HTTP 响应判信号（优先级：429 > Retry-After > 挑战 > WAF 页面）。"""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if status_code == 429:
        return SIG_HTTP_429
    if "retry-after" in h:
        return SIG_HTTP_RETRY_AFTER
    text = (body_head or "")[:4096].lower()
    if text:
        if any(k in text for k in _CHALLENGE_HINTS):
            return SIG_HTTP_CHALLENGE
        if any(k in text for k in _WAF_PAGE_HINTS):
            return SIG_HTTP_WAF_PAGE
    return SIG_NONE


def classify_network(exc: BaseException | None) -> tuple[str, int]:
    """从异常判网络层信号。返回 (signal, os_error_code)。

    沿异常链（httpx 会包装底层 OSError）找最具体的那一层。
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    code = 0
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        name = type(cur).__name__
        errno = getattr(cur, "errno", None) or 0
        if isinstance(cur, ConnectionResetError) or name == "ConnectionResetError" \
                or errno == 10054:
            return SIG_NET_RST, int(errno or 10054)
        if isinstance(cur, ConnectionRefusedError) or name == "ConnectionRefusedError" \
                or errno == 10061:
            return SIG_NET_REFUSED, int(errno or 10061)
        if isinstance(cur, TimeoutError) or "Timeout" in name \
                or errno in (10060, 110, 10054):
            return SIG_NET_TIMEOUT, int(errno or 0)
        try:
            import socket
            if isinstance(cur, socket.gaierror):
                return SIG_NET_DNS, int(errno or 0)
        except Exception:
            pass
        if "NameResolution" in name or "ConnectError" in name:
            code = code or int(errno or 0)
        cur = cur.__cause__ or cur.__context__
    if code:
        return SIG_NET_REFUSED, code
    return SIG_NONE, int(code or 0)


def classify_text(text: str) -> str:
    """从工具/脚本输出文本判信号（网络层特征优先于 HTTP 层）。"""
    low = (text or "")[-8192:].lower()
    if not low:
        return SIG_NONE
    for needle, sig in _TEXT_SIGNALS:
        if needle in low:
            return sig
    return SIG_NONE


def is_strong(sig: str) -> bool:
    return sig in STRONG_SIGNALS


def signal_label(sig: str) -> str:
    """给用户/模型看的中文说明。"""
    return {
        SIG_HTTP_429: "服务端限流（HTTP 429）",
        SIG_HTTP_RETRY_AFTER: "服务端要求等待（Retry-After）",
        SIG_HTTP_WAF_PAGE: "疑似 WAF 拦截页",
        SIG_HTTP_CHALLENGE: "人机验证/挑战页",
        SIG_NET_RST: "连接被远程重置（WinError 10054）",
        SIG_NET_REFUSED: "连接被拒绝（WinError 10061）",
        SIG_NET_TIMEOUT: "连接超时/静默丢包",
        SIG_NET_DNS: "DNS 解析失败",
    }.get(sig, sig or "无信号")
