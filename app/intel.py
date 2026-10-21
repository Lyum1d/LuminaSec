# -*- coding: utf-8 -*-
"""项目情报库：从工具输出中提取结构化情报，跨会话注入决策上下文。

解决的核心问题：Agent 每轮任务都从零开始，上一轮摸清的子域、API、
技术栈全部丢失，导致重复劳动和无效步数。情报在会话结束后自动沉淀，
下一轮任务开始时注入系统提示词。
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from . import config, store

# 每类情报上限，防止撑爆上下文（默认 150，可用环境变量 INTEL_CAP 调整）
_CAP = config.INTEL_CAP
_URL_RE = re.compile(r"https?://[^\s\"'<>（）()【】\[\]{}|\\]+")
_API_PATH_RE = re.compile(r"[\"'](/(?:api|v[0-9]|admin|actuator)[^\"'\s\\]{1,90})[\"']")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TITLE_RE = re.compile(r"title[「:：\s]+([^\」」\"']{1,40})")
_TECH_KEYWORDS = (
    "vue", "react", "angular", "spring boot", "actuator", "shiro", "struts",
    "thinkphp", "fastjson", "log4j", "nginx", "apache tomcat", "iis", "weblogic",
    "jeecg", "ruoyi", "codeigniter", "laravel", "django", "flask", "php",
    "webpack", "vite", "swagger", "druid", "nacos",
)


def extract_from_text(text: str) -> dict[str, list[str]]:
    """从一段工具输出中提取结构化情报。"""
    if not text:
        return {}
    out: dict[str, list[str]] = {"hosts": [], "api_paths": [], "ips": [], "tech": []}

    for u in _URL_RE.findall(text):
        try:
            h = urlparse(u).hostname
        except Exception:
            continue
        if h and re.match(r"^[a-zA-Z0-9.:-]+$", h) and not _looks_like_file(h):
            out["hosts"].append(h.lower())
        p = urlparse(u).path
        if p and len(p) > 1:
            out["api_paths"].append(p)

    for m in _API_PATH_RE.findall(text):
        out["api_paths"].append(m)

    out["ips"] = _IP_RE.findall(text)

    low = text.lower()
    out["tech"] = [kw for kw in _TECH_KEYWORDS if kw in low]

    for k in out:
        out[k] = sorted(set(v.strip().rstrip(".,;、，。") for v in out[k] if v.strip()))[:_CAP]
    return {k: v for k, v in out.items() if v}


def _looks_like_file(host: str) -> bool:
    tld = host.rsplit(".", 1)[-1].lower()
    return tld in {"png", "jpg", "js", "css", "json", "txt", "md", "pdf"}


def update_intel_from_steps(project_id: str, outputs: list[str]) -> dict:
    """会话结束后调用：合并本轮所有工具输出中的情报。"""
    patch: dict[str, list[str]] = {}
    for text in outputs:
        for k, vals in extract_from_text(text or "").items():
            patch.setdefault(k, []).extend(vals)
    if not patch:
        return store.get_intel(project_id)
    return store.merge_intel(project_id, patch)


def format_intel(intel: dict, limit: int = 1200) -> str:
    """把情报渲染成注入系统提示词的文本块。"""
    if not intel:
        return ""
    lines = ["\n\n【项目情报库（历史会话沉淀，直接可用，不要重复收集）】"]
    label = {"hosts": "已知主机/子域", "api_paths": "已知 API 路径",
             "ips": "已知 IP", "tech": "已知技术栈", "notes": "人工备注"}
    for k, vals in intel.items():
        if not vals:
            continue
        show = "、".join(str(v) for v in vals[:40])
        if len(vals) > 40:
            show += f" …等共 {len(vals)} 条"
        lines.append(f"- {label.get(k, k)}：{show}")
    block = "\n".join(lines)
    if len(block) > limit:
        block = block[:limit] + "\n…（情报过长已截断）"
    return block
