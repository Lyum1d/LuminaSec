# -*- coding: utf-8 -*-
"""云端外发脱敏（v010 P0-4）：工具输出进云端 LLM 前清洗敏感内容。

背景与策略见 config.CLOUD_EGRESS_MODE 的注释。本模块只做一件事：
把 messages 里「看起来是凭据/隐私」的片段替换为占位符，返回**副本**
（绝不就地修改 session.messages——落库与回放的原文必须保留）。

设计取舍：
- 覆盖的是「漏洞挖掘场景高频出现」的形态：Cookie/凭据请求头、Bearer/JWT、
  password=xxx 形态键值对、邮箱、手机号。不做语义级机密识别（做不到也不可靠），
  模型提示词里的合规红线仍负责「别把凭据写进结论」这一层。
- 只处理发往非本地供应商的请求。local_only 模式下根本不发，不进本模块。
"""
from __future__ import annotations

import copy
import json
import re

from . import config

# 模式常量（与 config.CLOUD_EGRESS_MODE 的取值一一对应）
MODE_LOCAL_ONLY = "local_only"
MODE_REDACT = "redact"
MODE_ALLOW = "allow"


def egress_mode() -> str:
    """当前外发模式（config 里归一化过；未知值按 redact 处理，宁严不松）。"""
    m = (config.CLOUD_EGRESS_MODE or "").strip().lower()
    return m if m in (MODE_LOCAL_ONLY, MODE_REDACT, MODE_ALLOW) else MODE_REDACT


def cloud_allowed() -> bool:
    """local_only 模式下云端供应商不可用（路由层与切换接口都用它判断）。"""
    return egress_mode() != MODE_LOCAL_ONLY


# ---------- 脱敏规则 ----------
# 每条规则：(编译好的正则, 替换文本)。按序执行，命中即替换。
# 占位符保留「这里曾有凭据」的语义，模型仍能理解上下文，只是拿不到原文。
_REDACT_RULES: list[tuple[re.Pattern, str]] = [
    # Cookie / Set-Cookie 请求头：冒号后的值整体打码
    (re.compile(r"(?i)\b(cookie\s*:\s*)(?!\[REDACTED)[^\r\n]{4,}"),
     r"\1[REDACTED_COOKIE]"),
    # Authorization: Bearer/Basic/Token xxx
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)"
                r"[^\s'\";,，；）)]{4,}"),
     r"\1[REDACTED_AUTH]"),
    # JWT：eyJ 开头的三段式（header.payload.signature），Base64URL 字符集
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}\b"),
     "[REDACTED_JWT]"),
    # 邮箱：打码本地部分，保留域名便于模型理解上下文（如「管理员邮箱」）
    (re.compile(r"\b[A-Za-z0-9._%+-]{2,}@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
     r"[REDACTED_EMAIL]@\1"),
    # 中国大陆手机号（1 开头 11 位，前后不能是数字，避免误伤端口/时间戳）
    (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "[REDACTED_PHONE]"),
    # v043 —— 加密**密钥材料**（真实的合规缺口，实测踩过）：
    # 现场：目标前端 JS 里明文硬编码了 RSA 私钥。该材料被写进本地事实库，
    # 而事实库会**注入每轮上下文**、上下文会**外发到云端模型**（model-studio）——
    # 原有 `_SECRET_RE` 只认 `private_key` 这类关键词，**不匹配 `private_exponent`**，
    # 于是私钥会原样出网。违反「不得外传测试中获取的任何数据」。
    # ① PEM 私钥块整体打码
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?"
                r"-----END [A-Z ]*PRIVATE KEY-----"),
     "[REDACTED_PEM_PRIVATE_KEY]"),
    # ② 密钥字段的键值形态（私钥指数 / 模数 / 各类 key 字段）
    (re.compile(r"(?i)\b(private[_-]?exponent|modulus|private[_-]?key|"
                r"secret[_-]?key|signing[_-]?key|encryption[_-]?key)\b"
                r"[\"']?(\s*[:=]\s*)[\"']?[0-9a-fA-F]{16,}[\"']?"),
     r"\1\2[REDACTED_KEY_MATERIAL]"),
    # ③ 超长 hex 串：**阈值取 128 字符**是刻意的 ——
    #    md5(32) / sha1(40) / sha256(64) 这些**取证用摘要值必须原样保留**（否则证据链断），
    #    而 RSA 1024 的私钥指数为 256 字符、模数 258 字符，全都远在阈值之上。
    (re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{128,}(?![0-9a-fA-F])"),
     "[REDACTED_LONG_HEX]"),
]

# 键值对形态的凭据：password=xxx / "api_key": "xxx" / access_token: xxx 等。
# 值取到空白/引号/常见分隔符为止；JSON 双引号包裹形态一并覆盖。
# 替换引用第 1/2 组（键名与分隔符），单独定义以保证规则表可读。
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token"
    r"|refresh[_-]?token|auth[_-]?token|private[_-]?key)\b[\"']?"
    r"(\s*[:=]\s*)[\"']?[^\s'\"&,;，；&]{3,}"
)
_SECRET_REPL = r"\1\2[REDACTED_SECRET]"

# 最终执行序
_RULES: list[tuple[re.Pattern, str]] = (
    _REDACT_RULES[:3] + [(_SECRET_RE, _SECRET_REPL)] + _REDACT_RULES[3:]
)


def redact_text(text: str) -> tuple[str, int]:
    """对一段文本执行全部脱敏规则。

    返回 (脱敏后的文本, 命中次数)。空文本原样返回。
    """
    s = text or ""
    if not s:
        return s, 0
    hits = 0
    for pat, repl in _RULES:
        s, n = pat.subn(repl, s)
        hits += n
    return s, hits


def _redact_part(part: dict) -> int:
    """递归脱敏一个消息部件里的字符串字段（content / text / arguments）。"""
    hits = 0
    content = part.get("content")
    if isinstance(content, str) and content:
        part["content"], n = redact_text(content)
        hits += n
    text = part.get("text")
    if isinstance(text, str) and text:
        part["text"], n = redact_text(text)
        hits += n
    for tc in part.get("tool_calls") or []:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        args = fn.get("arguments")
        if isinstance(args, str) and args:
            fn["arguments"], n = redact_text(args)
            hits += n
        elif isinstance(args, dict):
            try:
                blob = json.dumps(args, ensure_ascii=False)
            except Exception:
                blob = ""
            if blob:
                blob, n = redact_text(blob)
                hits += n
                try:
                    fn["arguments"] = json.loads(blob)
                except Exception:
                    fn["arguments"] = args
    return hits


def egress_messages(messages: list[dict]) -> tuple[list[dict], int]:
    """深拷贝并脱敏一份 messages（发往云端前调用）。

    返回 (脱敏后的副本, 命中总次数)。system 消息同样处理——它包含
    情报库/事实注入，同样可能带凭据。多段 content（OpenAI 视觉/分段形态）
    逐段处理。
    """
    total = 0
    out: list[dict] = []
    for m in messages or []:
        m2 = copy.deepcopy(m)
        if isinstance(m2, dict):
            total += _redact_part(m2)
            blocks = m2.get("content")
            if isinstance(blocks, list):
                for blk in blocks:
                    if isinstance(blk, dict):
                        total += _redact_part(blk)
        out.append(m2)
    return out, total
