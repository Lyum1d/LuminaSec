# -*- coding: utf-8 -*-
"""SRC 漏洞挖掘知识库（kb）与工作流规则（rules）检索。

来源：外部开源 SRC 方法论包（6kskill/clown-src-6k-skill，经安全审查后移植），
知识库 = 按漏洞类型的测试指南（49 篇）；rules = 挖掘工作流与报告取舍规则（11 篇）。
通过内置工具 kb_search / kb_read（L0）供 Agent 按需查询，避免整包撑爆上下文。

注意：知识库中的测试示例均以 target.com 等占位目标书写，实际使用受
config.ENFORCE_SCOPE 授权白名单约束（与其它工具一致）。
"""
from __future__ import annotations

import re
from pathlib import Path

from . import config

KB_DIR = config.DATA_DIR / "kb"        # 漏洞类型测试指南
RULES_DIR = config.DATA_DIR / "rules"  # 挖掘工作流 / 报告取舍规则


def _dirs() -> list[tuple[str, Path]]:
    return [("kb", KB_DIR), ("rules", RULES_DIR)]


def _safe_name(name: str) -> str:
    """只允许字母数字中文下划线连字符点，防路径穿越。"""
    return re.sub(r"[^\w\u4e00-\u9fff.\-]", "_", name).strip("_")


def list_topics() -> list[dict]:
    """列出全部篇目（kb + rules），含标题行摘要。"""
    out: list[dict] = []
    for cat, d in _dirs():
        if not d.exists():
            continue
        for p in sorted(d.glob("*.md")):
            title = p.stem
            try:
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith(("---", "|--", "+--")):
                        title = f"{p.stem} · {line.lstrip('# ')[:60]}"
                        break
            except Exception:
                pass
            out.append({"category": cat, "file": p.name, "title": title})
    return out


def search(keyword: str, limit: int = 6) -> list[dict]:
    """在知识库与规则中按关键词检索，返回命中篇目与片段。"""
    kw = (keyword or "").strip()
    if not kw:
        return []
    like = re.compile(re.escape(kw), re.I)
    hits: list[dict] = []
    for cat, d in _dirs():
        if not d.exists():
            continue
        for p in sorted(d.glob("*.md")):
            if p.name.startswith("_"):
                continue
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            score = 0
            snippet = ""
            # 文件名命中加权
            if like.search(p.stem):
                score += 10
            for i, line in enumerate(lines):
                if like.search(line):
                    score += 1
                    if not snippet:
                        start = max(0, i - 1)
                        snippet = " / ".join(x.strip() for x in lines[start:i + 3] if x.strip())[:300]
            if score:
                hits.append({"category": cat, "file": p.name, "score": score,
                             "snippet": snippet or f"{p.stem}（文件名命中）"})
    hits.sort(key=lambda x: -x["score"])
    return hits[:max(1, limit)]


def read(name: str, max_chars: int = 8000) -> dict:
    """读取一篇知识库/规则全文（截断）。name 可省略 .md 后缀，支持 kb/rules 前缀消歧。"""
    raw = _safe_name((name or "").strip())
    if not raw:
        return {"error": "篇目名为空。可用 kb_search 列出/检索篇目，或用 args='list' 看目录。"}
    if not raw.endswith(".md"):
        raw += ".md"
    for cat, d in _dirs():
        p = d / raw
        if p.exists():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return {"error": f"读取失败：{e}"}
            truncated = len(text) > max_chars
            return {"file": f"{cat}/{p.name}", "total_chars": len(text),
                    "content": text[:max_chars] + ("\n…（已截断）" if truncated else "")}
    # 模糊：按子串匹配一次
    for cat, d in _dirs():
        if not d.exists():
            continue
        for p in sorted(d.glob("*.md")):
            if raw.rstrip(".md").lower() in p.stem.lower() or p.stem.lower() in raw.lower():
                text = p.read_text(encoding="utf-8", errors="replace")
                return {"file": f"{cat}/{p.name}", "total_chars": len(text),
                        "content": text[:max_chars] + ("\n…（已截断）" if len(text) > max_chars else "")}
    return {"error": f"未找到篇目「{name}」。用 args='list' 查看全部篇目名。"}
