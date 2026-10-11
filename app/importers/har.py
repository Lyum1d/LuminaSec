# -*- coding: utf-8 -*-
"""HAR 1.2 导入（v017.1）：浏览器/抓包工具导出的标准 HTTP Archive JSON。"""
from __future__ import annotations

import json

from .common import split_cookies


def parse(text: str) -> list[tuple[dict, int | None]]:
    """解析 HAR JSON，返回 [(parsed_request, status_code), ...]。

    单条解析失败跳过不中断。
    """
    out: list[tuple[dict, int | None]] = []
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return out
    entries = (data.get("log") or {}).get("entries") or []
    for e in entries:
        try:
            req = e.get("request") or {}
            method = (req.get("method") or "GET").upper()
            url = req.get("url") or ""
            if not url:
                continue
            headers = {h.get("name", ""): h.get("value", "")
                       for h in (req.get("headers") or []) if h.get("name")}
            # HAR 的 cookies 数组与 Cookie 头并存；统一从头拆（更接近真实线上形态）
            cookies = {}
            for h in (req.get("headers") or []):
                if (h.get("name") or "").lower() == "cookie":
                    cookies = split_cookies(h.get("value", ""))
                    break
            qs = {q.get("name", ""): q.get("value", "")
                  for q in (req.get("queryString") or []) if q.get("name")}
            post = req.get("postData") or {}
            body = (post.get("text") or "")[:4096]
            resp = e.get("response") or {}
            status = resp.get("status")
            status_code = int(status) if isinstance(status, int) else None
            from urllib.parse import urlsplit, parse_qsl
            if "?" in url and not qs:
                qs = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            out.append(({
                "method": method,
                "url": url,
                "headers": headers,
                "cookies": cookies,
                "query": qs,
                "body": body,
                "content_type": post.get("mimeType") or "",
            }, status_code))
        except Exception:
            continue
    return out
