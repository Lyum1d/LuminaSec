# -*- coding: utf-8 -*-
"""Burp Suite「Save items」XML 导入（v017.1）。

只支持 items XML（每项含 base64 的原始 HTTP 请求报文），不解析 .burp 项目库。
"""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET

from .common import parse_raw_http


def parse(text: str) -> list[tuple[dict, int | None]]:
    """解析 items XML，返回 [(parsed_request, status_code), ...]。

    单条解析失败跳过不中断（坏条目不影响整批导入）。
    """
    out: list[tuple[dict, int | None]] = []
    # 去掉可能存在的 BOM 与命名空间前缀
    text = re.sub(r"<(/?)\w+:", r"<\1", text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    items = root.findall(".//item") if root.tag != "item" else [root]
    for item in items:
        req_el = item.find("request")
        status_el = item.find("status")
        if req_el is None or not (req_el.text or "").strip():
            continue
        b64 = (req_el.get("base64") or "false").lower() == "true"
        raw_text = (req_el.text or "").strip()
        try:
            raw = base64.b64decode(raw_text) if b64 else raw_text.encode("utf-8")
        except Exception:
            continue
        parsed = parse_raw_http(raw)
        if not parsed:
            continue
        status_code = None
        if status_el is not None and (status_el.text or "").strip().isdigit():
            status_code = int(status_el.text.strip())
        out.append((parsed, status_code))
    return out
