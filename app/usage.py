# -*- coding: utf-8 -*-
"""Token 用量统计：聚合汇总 + 模型单价表（人民币/百万 token）。

- 单价表存 data/usage_prices.json（可入库，无敏感信息）；预填常见模型价，用户可在
  用量弹窗里修改/增删。未配置单价的模型只统计 token、费用按 0 计。
- 价格匹配：优先「provider/model」全名，其次 model 名包含匹配（如 qwen3.7-plus 匹配
  qwen3.7 前缀条目），都未命中则视为未配置单价。
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

from . import config, store

PRICES_FILE = config.DATA_DIR / "usage_prices.json"

# 预填单价（人民币 元 / 百万 token；公开价近似值，可按账单校准）
DEFAULT_PRICES: dict[str, dict[str, float]] = {
    "qwen3.7-plus": {"input": 0.8, "output": 2.0},
    "qwen-plus": {"input": 0.8, "output": 2.0},
    "deepseek-chat": {"input": 2.0, "output": 8.0},
    "deepseek-reasoner": {"input": 4.0, "output": 16.0},
    "claude-sonnet": {"input": 22.0, "output": 110.0},
    "ollama": {"input": 0.0, "output": 0.0},
}


def _load_prices() -> dict[str, dict[str, float]]:
    if PRICES_FILE.exists():
        try:
            data = json.loads(PRICES_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return dict(DEFAULT_PRICES)


def save_prices(prices: dict[str, dict[str, float]]) -> None:
    clean: dict[str, dict[str, float]] = {}
    for k, v in (prices or {}).items():
        key = str(k).strip()
        if not key or not isinstance(v, dict):
            continue
        try:
            clean[key] = {"input": float(v.get("input") or 0),
                          "output": float(v.get("output") or 0)}
        except (TypeError, ValueError):
            continue
    PRICES_FILE.write_text(json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8")


def reset_prices() -> dict[str, dict[str, float]]:
    save_prices(DEFAULT_PRICES)
    return dict(DEFAULT_PRICES)


def _price_for(provider_id: str, model: str) -> tuple[float, float, str]:
    """返回 (input价, output价, 匹配到的单价键)；未匹配返回 (0,0,'')。"""
    prices = _load_prices()
    full = f"{provider_id}/{model}"
    if full in prices:
        return prices[full]["input"], prices[full]["output"], full
    if model in prices:
        return prices[model]["input"], prices[model]["output"], model
    for k, v in prices.items():
        if k and (model.startswith(k) or k.startswith(model)):
            return v["input"], v["output"], k
    return 0.0, 0.0, ""


def _day_start(ts: float) -> float:
    dt = datetime.fromtimestamp(ts)
    return datetime(dt.year, dt.month, dt.day).timestamp()


def _bucket() -> dict[str, Any]:
    return {"calls": 0, "prompt": 0, "completion": 0,
            "tokens": 0, "cost": 0.0}


def _accumulate(bucket: dict[str, Any], row: dict) -> None:
    """累加一条调用记录（token 与费用一起算）。

    费用顺带在这里算，避免 summary() 对「分模型 / 分项目」各自再回扫一遍全部记录。
    注意：cost 累计时**不四舍五入**，全部累加完再统一 round —— 逐步 round 会累积
    舍入误差，结果与「整体求和后 round 一次」不一致（实测把 0.0061 算成了 0.006）。
    """
    p, c = row["prompt_tokens"], row["completion_tokens"]
    pin, pout, _ = _price_for(row["provider_id"], row["model"])
    bucket["calls"] += 1
    bucket["prompt"] += p
    bucket["completion"] += c
    bucket["tokens"] += p + c
    bucket["cost"] += (p * pin + c * pout) / 1_000_000


def _pack(rows: list[dict]) -> dict[str, Any]:
    b = _bucket()
    for r in rows:
        _accumulate(b, r)
    b["cost"] = round(b["cost"], 4)
    return b


def summary() -> dict[str, Any]:
    """三档汇总（今日/本月/累计）+ 分模型 + 分项目聚合。费用按单价表估算。"""
    rows = store.list_usage(limit=5000)
    now = time.time()
    today_start = _day_start(now)
    month_start = _day_start(now) - (datetime.fromtimestamp(now).day - 1) * 86400

    today_rows = [r for r in rows if r["ts"] >= today_start]
    month_rows = [r for r in rows if r["ts"] >= month_start]

    by_model: dict[str, dict] = {}
    by_project: dict[str, dict] = {}
    for r in rows:
        _accumulate(by_model.setdefault(f"{r['provider_id']}:{r['model']}", _bucket()), r)
        _accumulate(by_project.setdefault(r["project_id"] or "", _bucket()), r)
    for b in (*by_model.values(), *by_project.values()):
        b["cost"] = round(b["cost"], 4)

    return {
        "today": _pack(today_rows),
        "month": _pack(month_rows),
        "total": _pack(rows),
        "by_model": by_model,
        "by_project": by_project,
        "generated_at": now,
    }


def daily(days: int = 30) -> list[dict]:
    """按天聚合（tokens/calls/cost），返回最近 N 天（含空天补 0，便于画趋势）。"""
    rows = store.list_usage(days=days, limit=5000)
    out: dict[str, dict] = {}
    now = time.time()
    start = _day_start(now) - (days - 1) * 86400
    day = start
    while day <= _day_start(now):
        key = datetime.fromtimestamp(day).strftime("%m-%d")
        out[key] = {"day": key, "calls": 0, "tokens": 0, "cost": 0.0}
        day += 86400
    for r in rows:
        key = datetime.fromtimestamp(r["ts"]).strftime("%m-%d")
        if key not in out:
            continue
        pin, pout, _ = _price_for(r["provider_id"], r["model"])
        out[key]["calls"] += 1
        out[key]["tokens"] += r["prompt_tokens"] + r["completion_tokens"]
        out[key]["cost"] = round(out[key]["cost"] +
                                 (r["prompt_tokens"] * pin + r["completion_tokens"] * pout) / 1_000_000, 4)
    return list(out.values())
