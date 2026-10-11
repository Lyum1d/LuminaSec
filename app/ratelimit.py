# -*- coding: utf-8 -*-
"""出网限速（唯一实现）。

背景：节流此前只存在于 HTTP 重放器（app/replayer.py 的 _rate_limit / REPLAY_MIN_INTERVAL），
而命令行扫描器（app/executor.py）与 split_task 的并发完全没有速率上限。两条路径各算各的
计时，对同一目标的实际请求速率是两者之和，与项目「禁止高频扫描、不得影响业务可用性」
的红线不匹配。这里收敛为唯一实现，重放与扫描共用同一把锁、同一份计时。

设计取舍：
  · 按 key（主机名）各持一把锁：同一目标串行，不同目标之间仍可并发，
    不至于把整个平台降级成单线程。
  · 另有一道全局闸（GLOBAL_MIN_INTERVAL）限制整机出网动作的频率，
    防止「多目标 × 多子任务」叠出瞬时高峰。
  · 计时状态放在模块级：进程内共享，不随调用方变化。

注意：本模块只做「速率」控制，不做授权判断——授权边界在 app/scope.py。
"""
from __future__ import annotations

import asyncio
import time

# key -> 该目标自己的锁与上次动作时刻
_key_locks: dict[str, asyncio.Lock] = {}
_key_last: dict[str, float] = {}

# 整机出网闸
_global_lock = asyncio.Lock()
_global_last = 0.0


async def acquire(key: str, min_interval: float, global_interval: float = 0.0) -> None:
    """兼容入口（v023.1 起推荐直接用 app/traffic.governor）。

    保留原因：历史调用点与测试按 (key, min_interval, global_interval) 签名断言。
    实现仍是本地节流（按 key 串行 + 最小间隔 + 整机闸）——**预算/并发/暂停状态
    等 v023 能力在 TrafficGovernor 里**，新代码请走 governor.acquire(url, ...)。
    """
    global _global_last

    if global_interval > 0:
        async with _global_lock:
            wait = global_interval - (time.time() - _global_last)
            if wait > 0:
                await asyncio.sleep(wait)
            _global_last = time.time()

    if min_interval <= 0:
        return

    lock = _key_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _key_locks[key] = lock
    async with lock:
        wait = min_interval - (time.time() - _key_last.get(key, 0.0))
        if wait > 0:
            await asyncio.sleep(wait)
        _key_last[key] = time.time()


def reset() -> None:
    """清空计时状态（仅供测试使用）。"""
    global _global_last
    _key_locks.clear()
    _key_last.clear()
    _global_last = 0.0
