# -*- coding: utf-8 -*-
"""凭据受保护存储（v017.2）：Windows DPAPI（CurrentUser 作用域）。

设计约束（v017 计划 5.1 / 第 2 节红线）：
- 明文凭据只存在于内存；落盘一律 CryptProtectData 加密（CurrentUser，
  只有同一 Windows 账户能解——换了用户/拷到别的机器密文即废）；
- 本模块是**唯一**的凭据加解密出入口，store/main 都不直接碰明文持久化；
- 解密失败（损坏/换用户/被拷贝）返回 None，由调用方把身份标记为 invalid，
  绝不把解密失败静默吞掉继续用旧凭据跑批量测试。

无第三方依赖：ctypes 直接调 crypt32.dll。
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os

_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob_from_bytes(data: bytes) -> _DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))


def _bytes_from_blob(blob: _DATA_BLOB) -> bytes:
    out = ctypes.string_at(blob.pbData, blob.cbData)
    ctypes.windll.kernel32.LocalFree(blob.pbData)
    return out


def dpapi_protect(plaintext: bytes) -> bytes | None:
    """加密；失败返回 None。"""
    if not plaintext:
        return None
    in_blob = _blob_from_bytes(plaintext)
    out_blob = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None,
        _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob))
    if not ok:
        return None
    return _bytes_from_blob(out_blob)


def dpapi_unprotect(ciphertext: bytes) -> bytes | None:
    """解密；失败（损坏/换用户）返回 None——调用方必须处理为身份失效。"""
    if not ciphertext:
        return None
    in_blob = _blob_from_bytes(ciphertext)
    out_blob = _DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None,
        _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob))
    if not ok:
        return None
    return _bytes_from_blob(out_blob)


def seal_dict(d: dict) -> str | None:
    """dict → DPAPI 密文的 base64（供 SQLite TEXT 列存储）。失败返回 None。"""
    import base64
    import json
    if not d:
        return None
    try:
        raw = json.dumps(d, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        return None
    enc = dpapi_protect(raw)
    if enc is None:
        return None
    return base64.b64encode(enc).decode("ascii")


def unseal_dict(sealed: str | None) -> dict | None:
    """base64 密文 → dict；解密失败返回 None（=凭据不可用，调用方标记身份失效）。"""
    import base64
    import json
    if not sealed:
        return None
    try:
        enc = base64.b64decode(sealed)
    except Exception:
        return None
    raw = dpapi_unprotect(enc)
    if raw is None:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def available() -> bool:
    """DPAPI 是否可用（Windows 下恒 True；非 Windows 恒 False——凭据功能禁用）。"""
    return os.name == "nt"
