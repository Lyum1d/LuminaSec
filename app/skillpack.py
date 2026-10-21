# -*- coding: utf-8 -*-
"""技能包（skills.pack）：把 KB / rules / 提示词条款**打成一个加密包**，运行时解密到内存。

═══ 这个模块"能防什么、不能防什么"（先读这段，别误解它的强度）═══

**能防**：拿到发布包的人用编辑器/`cat`/`grep`/打包转发，看不到内容；
        连**篇名**都不暴露（单包，不是逐文件加密）。
**不能防**：会改代码的人。密钥就在本进程里，他可以：
        · 在 `decrypt()` 上打一行 `print(payload)`；
        · 在 `agent.py` 里把拼好的提示词打出来；
        · 直接抓 LLM 请求（KB 内容本来就要喂进提示词）。
        ⇒ **这是"混淆级"，不是"密码学级"。** 用户已知并接受此强度（2026-10-21 明确选择
        「钥匙随包混淆」；在线取密钥的方案被否）。

**加密构造**（标准库实现，发布版不能引入新依赖）：
        zlib 压缩 → SHA-256 计数器模式生成密钥流 XOR → HMAC-SHA256 认证。
        密码学上它不如 AES-GCM（没有形式化安全证明），但**在本场景下无实际区别**：
        密钥一旦泄露，AES 也一样被解。选它是因为零依赖 + 能挡住"直接读文件"。

═══ 文件格式（大端）═══
        magic  9 字节  b"SRCSKILL1"
        nonce 16 字节  构建时随机，一次性使用（包里只加密一次，不存在 nonce 复用）
        clen   4 字节  密文长度
        ct     clen 字节
        tag   32 字节  HMAC-SHA256(magic|nonce|clen|ct)，密钥与加密密钥**分开派生**

═══ 载荷结构 ═══
        {"meta":  {"built_at": "...", "count": N, ...},
         "files": {"kb/xxx.md": "正文", "rules/yyy.md": "正文",
                   "prompt/role_principles.md": "正文", ...}}
        键一律用**相对路径**（`kb/`、`rules/`、`prompt/` 三个前缀），与磁盘目录同构。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import zlib
from pathlib import Path
from typing import Any

from . import config

logger = logging.getLogger("src_agent")

MAGIC = b"SRCSKILL1"
VERSION = 1
PACK_NAME = "skills.pack"
_NONCE_LEN = 16
_TAG_LEN = 32

# ── 密钥（混淆存放：分段 + 每段过一次变换，避免被一次 grep 命中）──
# ⚠️ 强度说明见模块头：这是**防手滑**，不是防逆向。要真正保护，唯一的路是
#    「密钥在线取」或「服务端执行」，两者都在 2026-10-21 的讨论中被否。
_K1 = bytes([0x6D, 0x75, 0x6C, 0x74, 0x69])          # b"multi"
_K2 = bytes([0x2D, 0x74, 0x65, 0x6E, 0x61, 0x6E, 0x74])  # b"-tenant"
_SALT = bytes([0x53, 0x52, 0x43, 0x2D, 0x4B, 0x42])     # b"SRC-KB"


def _master_key() -> bytes:
    """拼出主密钥（分段拼接 → 与 salt 一起过 KDF）。"""
    raw = _K1 + b"\x00" + _K2 + b"\x00" + _SALT
    return hashlib.sha256(b"skillpack-v1\x00" + raw).digest()


def _subkey(label: bytes) -> bytes:
    return hmac.new(_master_key(), label, hashlib.sha256).digest()


_ENC_KEY = _subkey(b"enc")
_MAC_KEY = _subkey(b"mac")


# ── 密钥流（SHA-256 计数器模式）──
def _keystream(nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(_ENC_KEY + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


# ── 打包 / 解包 ──
def build(files: dict[str, str], meta: dict[str, Any] | None = None) -> bytes:
    """把 {相对路径: 正文} 打成加密包。构建期用。"""
    payload = {"version": VERSION, "meta": meta or {}, "files": dict(files)}
    plain = zlib.compress(
        json.dumps(payload, ensure_ascii=False).encode("utf-8"), 9)
    nonce = __import__("os").urandom(_NONCE_LEN)
    ks = _keystream(nonce, len(plain))
    ct = bytes(a ^ b for a, b in zip(plain, ks))
    tag = hmac.new(_MAC_KEY, MAGIC + nonce + len(ct).to_bytes(4, "big") + ct,
                   hashlib.sha256).digest()
    return MAGIC + nonce + len(ct).to_bytes(4, "big") + ct + tag


def open_pack(blob: bytes) -> dict[str, str]:
    """解开一个包，返回 {相对路径: 正文}。校验失败抛 ValueError（绝不返回半截数据）。"""
    if len(blob) < len(MAGIC) + _NONCE_LEN + 4 + _TAG_LEN:
        raise ValueError("技能包损坏：长度不足")
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("技能包损坏：magic 不匹配（可能不是本程序的包）")
    pos = len(MAGIC)
    nonce = blob[pos:pos + _NONCE_LEN]
    pos += _NONCE_LEN
    clen = int.from_bytes(blob[pos:pos + 4], "big")
    pos += 4
    ct = blob[pos:pos + clen]
    tag = blob[pos + clen:pos + clen + _TAG_LEN]
    if len(ct) != clen or len(tag) != _TAG_LEN:
        raise ValueError("技能包损坏：长度字段与实际不符")
    want = hmac.new(_MAC_KEY, MAGIC + nonce + clen.to_bytes(4, "big") + ct,
                    hashlib.sha256).digest()
    if not hmac.compare_digest(want, tag):
        raise ValueError("技能包校验失败：内容被改动或密钥不匹配")
    plain = zlib.decompress(bytes(a ^ b for a, b in zip(ct, _keystream(nonce, clen))))
    payload = json.loads(plain.decode("utf-8"))
    files = payload.get("files") or {}
    if not isinstance(files, dict):
        raise ValueError("技能包结构异常：files 不是字典")
    return {str(k): str(v) for k, v in files.items()}


# ── 运行时读取（带缓存）──
_cache: dict[str, str] | None = None
_cache_mtime: float | None = None


def pack_path() -> Path:
    return config.DATA_DIR / PACK_NAME


def available() -> bool:
    return pack_path().exists()


def _load() -> dict[str, str]:
    global _cache, _cache_mtime
    p = pack_path()
    if not p.exists():
        _cache, _cache_mtime = {}, None
        return _cache
    try:
        mtime = p.stat().st_mtime
    except OSError:
        mtime = None
    if _cache is not None and mtime is not None and mtime == _cache_mtime:
        return _cache
    try:
        data = open_pack(p.read_bytes())
    except Exception as e:                     # noqa: BLE001
        # 包坏了不能让程序**静默**跑成"没有知识库"——那会看起来像功能正常但全是瞎猜。
        logger.error("技能包解包失败（%s）：%s ⇒ 知识库将不可用", p, e)
        data = {}
    _cache, _cache_mtime = data, mtime
    return data


def get(rel: str) -> str | None:
    """按相对路径取一篇（如 "kb/打穿短表.md"）。没有则 None。"""
    return _load().get(rel)


def names(prefix: str) -> list[str]:
    """列出某个前缀下的文件名（不含前缀），已排序。"""
    p = prefix.rstrip("/") + "/"
    return sorted(k[len(p):] for k in _load() if k.startswith(p))


def meta() -> dict[str, Any]:
    """包的元信息（篇数等）。只读，不含正文。"""
    files = _load()
    return {"available": available(), "count": len(files),
            "path": str(pack_path()) if available() else ""}


def collected_plaintext(data_dir: Path | None = None) -> list[str]:
    """收集磁盘上**仍为明文**的官方文件相对路径（用于"该删未删"的提示）。

    只**报告**，不删除 —— 2026-10-21 用户明确选择"不删，只提示"。
    """
    root = data_dir or config.DATA_DIR
    out: list[str] = []
    for sub in ("kb", "rules", "prompt"):
        d = root / sub
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.md")):
            out.append(f"{sub}/{f.name}")
    return out


def missing_clause_hint() -> str:
    return ("缺少提示词条款（既不在地盘 %s，也无法从技能包解出）。"
            "发布版必须带 skills.pack；开发环境应有 data/prompt/*.md。"
            % config.DATA_DIR)
