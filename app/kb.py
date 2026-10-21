# -*- coding: utf-8 -*-
"""SRC 漏洞挖掘知识库（kb）与工作流规则（rules）检索。

来源：外部开源 SRC 方法论包（6kskill/clown-src-6k-skill，经安全审查后移植）。
知识库 = 按漏洞类型的测试指南；rules = 挖掘工作流与报告取舍规则。
通过内置工具 kb_search / kb_read（L0）供 Agent 按需查询，避免整包撑爆上下文。

═══ v120：内容改为「加密技能包优先」═══

发布版**不再带明文 .md**，只带 `data/skills.pack`（见 `app/skillpack.py`）。
读取顺序：

  官方类别（kb / rules）
    ① `data/skills.pack` 里有 ⇒ **用包里的**（发布版就是这个）
    ② 没有包 ⇒ 读磁盘明文（工程库 / 未打包的本地运行）
       ⚠️ **包存在时磁盘明文一律不生效** —— 否则老用户升级后盘上残留的旧明文
          会把加密绕过（更新器只新增/覆盖、不删文件）。残留只会**提示**，不删
          （2026-10-21 用户明确选择「不删，只提示」）。
  用户类别（kb_user / rules_user）
    纯磁盘明文，用户自己写；与官方**合并**（官方在前），可同名覆盖。

⚠️ **这里刻意不写死篇数**：原先钉着两个数字（49 与 11），后来篇数涨到 58/12
也没人回来改，反而成了错的 —— 而且那个数字还在工具描述与 README 里各抄了一份，
五处互不同步。篇目清单与合计一律以 `data/kb/README.md` 的索引为准。

注意：知识库中的测试示例均以 target.com 等占位目标书写，实际使用受
config.ENFORCE_SCOPE 授权白名单约束（与其它工具一致）。
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from . import config, skillpack

logger = logging.getLogger("src_agent")

KB_DIR = config.DATA_DIR / "kb"        # 漏洞类型测试指南（官方；发布版无明文）
RULES_DIR = config.DATA_DIR / "rules"  # 挖掘工作流 / 报告取舍规则（官方；发布版无明文）
KB_USER_DIR = config.DATA_DIR / "kb_user"      # 用户自写（明文，始终可读可改）
RULES_USER_DIR = config.DATA_DIR / "rules_user"

OFFICIAL = ("kb", "rules")
USER_DIRS = {"kb_user": KB_USER_DIR, "rules_user": RULES_USER_DIR}

_hinted = False


def _dirs() -> list[tuple[str, Path]]:
    """(类别, 目录)：官方两类 + 用户两类。官方两类可能没有磁盘目录（发布版）。"""
    return [("kb", KB_DIR), ("rules", RULES_DIR),
            ("kb_user", KB_USER_DIR), ("rules_user", RULES_USER_DIR)]


def _warn_stale_plaintext() -> None:
    """包存在但盘上还留着官方明文 ⇒ 只提示一次（**不删**）。"""
    global _hinted
    if _hinted or not skillpack.available():
        return
    stale = [x for x in skillpack.collected_plaintext() if x.startswith(("kb/", "rules/", "prompt/"))]
    if stale:
        logger.warning(
            "检测到 %d 个旧版明文技能文件（如 %s）已被加密技能包取代，当前**不生效**。"
            "它们是可以手动删除的旧版本残留 —— 程序不会自动删除。",
            len(stale), stale[0])
    _hinted = True


def entries(cat: str, d: Path) -> list[tuple[str, str]]:
    """某类别下的全部篇目 [(文件名, 正文)]，已按文件名排序。

    官方类别：包优先；无包才读磁盘（写盘编辑只对**没有包**的开发环境生效）。
    用户类别：只读磁盘明文。
    """
    items: dict[str, str] = {}
    if cat in OFFICIAL:
        if skillpack.available():
            _warn_stale_plaintext()
            for name in skillpack.names(cat):
                txt = skillpack.get(f"{cat}/{name}")
                if txt is not None:
                    items[name] = txt
            return sorted(items.items())
    if d.is_dir():
        for p in sorted(d.glob("*.md")):
            try:
                items[p.name] = p.read_text(encoding="utf-8", errors="replace")
            except Exception:                                    # noqa: BLE001
                continue
    return sorted(items.items())


def _safe_name(name: str) -> str:
    """只允许字母数字中文下划线连字符点，防路径穿越。"""
    return re.sub(r"[^\w\u4e00-\u9fff.\-]", "_", name).strip("_")


def list_topics() -> list[dict]:
    """列出全部篇目（kb + rules + 用户目录），含标题行摘要。"""
    out: list[dict] = []
    for cat, d in _dirs():
        for fname, text in entries(cat, d):
            stem = fname[:-3] if fname.endswith(".md") else fname
            title = stem
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("---", "|--", "+--")):
                    title = f"{stem} · {line.lstrip('# ')[:60]}"
                    break
            out.append({"category": cat, "file": fname, "title": title})
    return out


def search(keyword: str, limit: int = 6) -> list[dict]:
    """在知识库与规则中按关键词检索，返回命中篇目与片段。"""
    kw = (keyword or "").strip()
    if not kw:
        return []
    like = re.compile(re.escape(kw), re.I)
    hits: list[dict] = []
    for cat, d in _dirs():
        for fname, text in entries(cat, d):
            if fname.startswith("_"):
                continue
            stem = fname[:-3] if fname.endswith(".md") else fname
            lines = text.splitlines()
            score = 0
            snippet = ""
            # 文件名命中加权
            if like.search(stem):
                score += 10
            for i, line in enumerate(lines):
                if like.search(line):
                    score += 1
                    if not snippet:
                        start = max(0, i - 1)
                        snippet = " / ".join(x.strip() for x in lines[start:i + 3] if x.strip())[:300]
            if score:
                hits.append({"category": cat, "file": fname, "score": score,
                             "snippet": snippet or f"{stem}（文件名命中）"})
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
        for fname, text in entries(cat, d):
            if fname == raw:
                truncated = len(text) > max_chars
                return {"file": f"{cat}/{fname}", "total_chars": len(text),
                        "content": text[:max_chars] + ("\n…（已截断）" if truncated else "")}
    # 模糊：按子串匹配一次
    key = raw[:-3].lower() if raw.endswith(".md") else raw.lower()
    for cat, d in _dirs():
        for fname, text in entries(cat, d):
            stem = fname[:-3] if fname.endswith(".md") else fname
            if key in stem.lower() or stem.lower() in key:
                return {"file": f"{cat}/{fname}", "total_chars": len(text),
                        "content": text[:max_chars] + ("\n…（已截断）" if len(text) > max_chars else "")}
    return {"error": f"未找到篇目「{name}」。用 args='list' 查看全部篇目名。"}
