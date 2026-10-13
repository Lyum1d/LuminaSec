# -*- coding: utf-8 -*-
"""本机自备工具：用户指定一个目录 → 自动识别里面的工具 → 并入工具箱。

## 这个模块解决什么

原来「有哪些工具」只有一个来源：`<TOOLBOX_ROOT>/config/tools.json`（某个第三方
工具箱的清单）。于是没用那个工具箱的人**一个外部工具都没有**，也没法把自己的
常用脚本/工具加进来。本模块让用户在本机挑一个目录，由程序**自己认出**里面哪些
文件是可用的工具，无需手写清单。

## 为什么单独成一个模块（而不是塞进 registry.py）

  · `registry.py` 已近千行，职责是「把清单变成 Tool 对象」；
    「从目录树里认出哪些文件是工具」是另一件事（文件系统遍历 + 按扩展名判定）。
  · 扫描必须在**不载入 registry 的前提下单独跑** —— 控制台的「识别预览」就是
    在正式纳入之前先跑一次扫描给人看。所以它必须是可以独立调用的纯逻辑。
  · `local_tools` **只依赖 config**，不依赖 registry ⇒ registry 单向 import 它，
    不构成循环。

## 数据文件

`data/local_tools.json`（**本机路径，gitignore**；模板见 `local_tools.json.example`）。

## 两条设计取舍（与项目既有约定对齐）

1. **只存「根目录 + 少量覆写」，工具条目每次重新扫描。**
   用户在目录里增删工具后不需要回来同步清单，重启即跟随。代价是 `registry.load()`
   时要走一次目录树 —— 已用「深度上限 + 条数上限 + 跳过目录黑名单 + 拒绝盘符根」
   四条兜底，实测可控。

2. **这里不存风险分级、不存闸门参数。**
   那是 `data/risk_grades.json`（按**工具名**）与 `data/tool_overrides.json`
   （按 **alias**）的职责。只要自备工具进了 `registry.tools`，控制台「工具与分级」
   页就自动能管它们 —— 所以「与外部工具同一套闸门」是靠**复用同一条链路**保证的，
   而不是在这里再实现一遍（本项目反复踩过"同一原理落两份实现、迟早漂移"的坑）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator

from . import config

#: 本机自备工具配置（gitignore）。模板见同目录的 `.example`。
CONFIG_FILE = config.DATA_DIR / "local_tools.json"
EXAMPLE_FILE = config.DATA_DIR / "local_tools.json.example"

#: 扩展名 → 工具类型。**集中在一处**，且由控制台回显给用户 ——
#: 「为什么这个文件没被识别」要能当场查到，不能是黑箱。
#: 判定用的是 `registry.config.SCRIPTABLE_TYPES`：值必须落在那个集合里，
#: 否则工具会被当成「仅可启动」而不进 Agent 清单（`test_local_tools` 守着这条）。
EXT_TYPES: dict[str, str] = {
    ".exe": "命令行",
    ".com": "命令行",
    ".bat": "批处理",
    ".cmd": "批处理",
    ".vbs": "批处理",   # build_command 对 .vbs 走 wscript
    ".py": "Python",
    ".jar": "JAVA8",    # java 大版本认不出来，默认 JAVA8；可在根或条目里覆写
}

#: 书签类：只当「网页工具」收进来（点了用浏览器打开），**不进 Agent 清单**。
#: 支持它的理由：一个工具目录里常常混着几个 .url 快捷方式，认不出来会显得很蠢。
BOOKMARK_EXTS = {".url"}

#: **认出但刻意不纳入**的扩展名。目前只有 Windows 快捷方式 `.lnk`。
#:
#: 为什么不做：`.lnk` 是二进制格式，正确解析要读 LinkTargetIDList / LinkInfo 结构。
#: 曾在字节流里用正则找 `X:\...` 片段来"尽力而为"，但**这是错的** ——
#: 一个 .lnk 里同时存在图标路径、工作目录、目标路径等多个绝对路径串，
#: 猜错的那个会让工具指向一个毫不相干的 exe，而且**不报任何错**（本项目最怕的失败形态）。
#: 所以这里只统计数量并提示"请改选快捷方式目标所在的目录"，让人自己决定。
SHORTCUT_EXTS = {".lnk"}

#: 扫描时跳过的目录名（小写比对）。这些目录里几乎不会有可执行工具，
#: 但数量往往极大（node_modules / __pycache__），扫进去只会拖慢并淹没真正的工具。
SKIP_DIRS = {
    "__pycache__", "node_modules", ".git", ".svn", ".hg", ".idea", ".vscode",
    ".venv", "venv", "env", "site-packages", "dist-info",
    "docs", "doc", "readme", "changelog",
    "帮助", "说明", "文档", "教程", "使用说明", "配置说明", "开源说明", "汉化说明",
    "license", "licenses", "licence",
}

MAX_DEPTH = 4         # 相对根目录的最大层数
MAX_ENTRIES = 1500    # 单个根最多识别多少个（防"选错目录"把一大片盘翻个遍）


# ------------------------------------------------------------------ 配置读写
def empty_config() -> dict[str, Any]:
    return {"version": 1, "roots": []}


def load_config() -> dict[str, Any]:
    """读本机配置。

    **缺失/损坏一律退化为空，不抛异常** —— 这个文件是"锦上添花"的输入，
    它坏了不该让整个 registry 载入失败（那会让所有工具都用不了）。
    """
    p = CONFIG_FILE
    if not p.exists():
        return empty_config()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:                                     # noqa: BLE001
        return empty_config()
    if not isinstance(data, dict):
        return empty_config()
    roots = data.get("roots")
    return {
        "version": int(data.get("version") or 1),
        "roots": [r for r in roots if isinstance(r, dict)] if isinstance(roots, list) else [],
    }


def root_id(path: str) -> str:
    """由绝对路径派生**稳定** id。

    不用时间戳/自增：那些在"移除后再加回来"时会变，前端行身份与审计记录都对不上。
    同一路径永远得到同一 id，人也好读（`rt_3f2a91c4`）。
    """
    norm = os.path.normcase(os.path.normpath(str(path or ""))).encode("utf-8")
    return "rt_" + hashlib.sha1(norm).hexdigest()[:8]


def is_drive_root(p: Path) -> bool:
    """是不是盘符根（`E:\\` / `/`）。"""
    try:
        return p.resolve() == Path(p.anchor)
    except OSError:
        return False


def validate_root_path(raw_path: str) -> tuple[Path | None, str]:
    """校验用户给的目录。返回 (绝对路径, 错误说明)；错误说明非空即失败。

    刻意收紧的三条，各自对应一种真实的误用：

      · **必须是绝对路径** —— 相对路径的含义取决于服务进程的当前目录，
        用户以为是"我打开的那个文件夹"，实际是别的，识别结果会莫名其妙；
      · **必须已存在且是目录** —— 打错一个字母就给出明确报错，而不是"识别到 0 个工具"
        这种让人以为机制坏了的结果；
      · **拒绝盘符根** —— 从 `E:\\` 按深度 4 扫下去会把整块盘翻一遍，
        1500 条上限会先被无关的 .exe 占满，用户看到的结果全是噪声。
        与其扫出垃圾，不如直接说清楚「要选具体的工具目录」。
    """
    s = str(raw_path or "").strip().strip('"').strip("'")
    if not s:
        return None, "目录不能为空。"
    p = Path(s)
    if not p.is_absolute():
        return None, (f"必须是**绝对路径**（如 `E:\\我的工具`），"
                      f"当前给的是相对路径：{s}")
    if is_drive_root(p):
        return None, (f"不要直接选整个盘符（{p}）—— 会把整块盘扫一遍，"
                      "识别结果全是噪声。请选**具体的工具目录**。")
    if not p.exists():
        return None, f"目录不存在：{p}"
    if not p.is_dir():
        return None, f"这不是目录（是文件）：{p}"
    return p, ""


def normalize_root(raw: dict[str, Any]) -> dict[str, Any]:
    """把一个根条目规整成内部统一形状（缺字段补默认，非法值收敛）。

    容错是刻意的：这个文件允许用户手工编辑（它就在 `data/` 下、很好找），
    手写时少一两个字段是常态，不该因此让整个目录识别不出来。
    """
    path = str(raw.get("path") or "").strip()
    label = str(raw.get("label") or "").strip() or Path(path).name or path
    cat = str(raw.get("category") or "").strip() or label
    return {
        "id": str(raw.get("id") or root_id(path)),
        "path": path,
        "label": label,
        "category": cat,
        "enabled": bool(raw.get("enabled", True)),
        "python": str(raw.get("python") or "").strip(),
        "java": str(raw.get("java") or "JAVA8").strip().upper(),
        "note": str(raw.get("note") or "").strip(),
        "excluded": [str(x) for x in (raw.get("excluded") or [])],
        "overrides": {str(k): v for k, v in (raw.get("overrides") or {}).items()
                      if isinstance(v, dict)},
    }


def save_config(roots: list[dict[str, Any]]) -> dict[str, Any]:
    """把根列表规整后落成完整的配置文件内容（**不写盘**，由调用方原子写）。"""
    return {
        "_note": ("本机自备工具目录。**不入库**（见 .gitignore）。"
                  "工具条目每次重新扫描得到，这里只存根目录与少量覆写。"
                  "风险分级/闸门请到控制台「工具与分级」页改 "
                  "risk_grades.json / tool_overrides.json。"),
        "version": 1,
        "roots": [normalize_root(r) for r in roots if str(r.get("path") or "").strip()],
    }


# ------------------------------------------------------------------ 扫描
def _walk_files(root_path: Path, cap: int = MAX_ENTRIES) -> tuple[list[Path], bool]:
    """深度受限地遍历目录，返回 (文件列表, 是否被上限截断)。

    用 `os.scandir` 而不是 `Path.rglob`：scandir 复用目录项缓存，
    在几万个文件量级下差距明显；而且能在**每个条目上**做失败容忍
    （权限不足的目录在 Windows 上很常见，不该让整次扫描挂掉）。

    `follow_symlinks=False` 是有意的：目录联接（junction）在 Windows 上很常见，
    跟随它们既可能绕出去扫到无关目录，也可能撞上循环。
    """
    out: list[Path] = []
    stack: list[tuple[Path, int]] = [(root_path, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if depth + 1 > MAX_DEPTH:
                        continue
                    nm = e.name.lower()
                    if nm in SKIP_DIRS or e.name.startswith("."):
                        continue
                    stack.append((Path(e.path), depth + 1))
                elif e.is_file(follow_symlinks=False):
                    out.append(Path(e.path))
                    if len(out) >= cap:
                        return out, True
            except OSError:
                continue
    return out, False


def _read_url_bookmark(p: Path) -> str:
    """从 `.url` 快捷方式里取出目标 URL（取不到就返回空串）。"""
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().lower().startswith("url="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def classify(p: Path) -> tuple[str, str] | None:
    """按扩展名判定工具类型。返回 (type, ext)；不是工具的文件返回 None。"""
    ext = p.suffix.lower()
    if ext in EXT_TYPES:
        return EXT_TYPES[ext], ext
    if ext in BOOKMARK_EXTS:
        return "网页", ext
    return None


def _resolve_java(root: dict[str, Any], ttype: str) -> str:
    """.jar 的 Java 大版本：**根级 `java` 字段要真的生效**。

    优先级：条目级 `type` 覆写（在调用处处理）> 根级 `java` > 默认 `JAVA8`。

    ⚠️ v115 修：`normalize_root()` 一直把根级 `java` 存下来、控制台也有入口，
    但**没有任何地方读它** ⇒ 用户把某个目录设成 JAVA11，程序仍静默用 JAVA8 跑 `.jar`。
    `executor` 早就支持 `JAVA8_BIN`/`JAVA11_BIN` 两条路径，缺的只是这一环。
    """
    if ttype not in ("JAVA8", "JAVA11"):
        return ttype
    want = str(root.get("java") or "").strip().upper()
    return want if want in ("JAVA8", "JAVA11") else ttype


#: 别名推导退化成占位名的形态（`_make_alias` 在文件名推不出 ASCII 时的兜底）。
_PLACEHOLDER_ALIAS_RE = re.compile(r"^tool(_\d+)?$")


def alias_looks_placeholder(alias: str) -> bool:
    """这个别名是不是"没意义的占位名"（`tool` / `tool_2` / `tool_17`）。

    什么时候会发生：文件名是纯中文（`扫描器.exe`）或全符号，`_make_alias`
    推不出 ASCII 名字，只能兜底成 `tool`，再因重名升级成 `tool_2`、`tool_3`…
    **对中文用户来说这几乎是常态**，而一串 `tool_2` / `tool_3` 对模型的工具选择
    毫无帮助（模型只能靠 description 猜），还不如让人当场起个名字。

    所以识别出这种形态后**必须显式提示用户改**（控制台在识别结果里标出来），
    而不是让它悄悄混进工具清单。
    """
    return bool(_PLACEHOLDER_ALIAS_RE.match(str(alias or "").strip().lower()))


def scan_root(root: dict[str, Any]) -> dict[str, Any]:
    """扫描一个根目录，返回识别结果。**只读文件系统，绝不执行任何程序。**

    返回结构（控制台直接消费）：
        {id, path, label, category, enabled, exists, problem,
         tools: [{rel_path, abs_path, name, type, category, size, url,
                  excluded, override, note}],
         stats: {...}, truncated: bool}
    """
    r = normalize_root(root)
    raw_path = r["path"]
    base = Path(raw_path) if raw_path else None
    out: dict[str, Any] = {
        "id": r["id"], "path": raw_path, "label": r["label"],
        "category": r["category"], "enabled": r["enabled"], "note": r["note"],
        "exists": False, "problem": "", "tools": [], "truncated": False,
        "stats": {"found": 0, "included": 0, "excluded": 0, "by_type": {}},
    }

    # 路径校验与"已存在的目录"校验分开：这里**不做盘符根检查** ——
    # 那条是"新增时"的输入校验（validate_root_path），而一个已经存进配置的根
    # 若恰好是盘符根（比如用户手工改的），扫描时应当照常工作并给出结果，
    # 而不是突然报错让工具全消失。
    if not base or not base.exists() or not base.is_dir():
        out["problem"] = f"目录不存在或不是目录：{raw_path}"
        return out
    out["exists"] = True

    files, truncated = _walk_files(base)
    out["truncated"] = truncated
    excluded = set(r["excluded"])
    overrides = r["overrides"]
    by_type: dict[str, int] = {}
    shortcuts = 0

    for f in files:
        kind = classify(f)
        if not kind:
            if f.suffix.lower() in SHORTCUT_EXTS:
                shortcuts += 1
            continue
        ttype, _ext = kind
        try:
            rel = f.relative_to(base)
        except ValueError:
            continue
        rel_posix = rel.as_posix()
        ov = overrides.get(rel_posix) or {}

        # 分类：根级工具用根的分类；子目录里的补上"子目录名"，
        # 让「爆破/」「信息收集/」这类分门别类的工具目录天然带上类别。
        cat = str(ov.get("category") or "").strip()
        if not cat:
            cat = r["category"] if len(rel.parts) <= 1 else f"{r['category']} · {rel.parts[0]}"

        url = _read_url_bookmark(f) if f.suffix.lower() in BOOKMARK_EXTS else ""
        item = {
            "rel_path": rel_posix,
            "abs_path": str(f),
            "name": str(ov.get("name") or f.stem),
            # 条目级 `type` 覆写优先；否则 `.jar` 按**根级 java** 定（v115 修，见 _resolve_java）
            "type": str(ov.get("type") or _resolve_java(r, ttype)),
            "category": cat,
            "description": str(ov.get("description") or ""),
            "size": (f.stat().st_size if f.exists() else 0),
            "url": url,
            "excluded": rel_posix in excluded,
            "overridden": bool(ov),
        }
        out["tools"].append(item)
        by_type[ttype] = by_type.get(ttype, 0) + 1

    out["tools"].sort(key=lambda x: (x["rel_path"].lower(),))
    out["stats"] = {
        "found": len(out["tools"]),
        "included": sum(1 for x in out["tools"] if not x["excluded"]),
        "excluded": sum(1 for x in out["tools"] if x["excluded"]),
        "by_type": by_type,
        "shortcuts": shortcuts,
    }
    # 快捷方式单独给一句提示：用户看到一个 .lnk 却没被识别，会以为机制漏了。
    if shortcuts:
        out["hint"] = (
            f"目录里还有 {shortcuts} 个 Windows 快捷方式（.lnk），**未纳入** —— "
            "快捷方式指向的目标不在本目录内，把它当工具注册会让路径难以追踪。"
            "如果那些才是你要的工具，请改选它们**目标所在的目录**。")
    return out


def iter_included(root: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """遍历一个根里"已纳入"的工具条目（供 registry 注册）。"""
    scan = scan_root(root)
    if not scan["exists"]:
        return
    for t in scan["tools"]:
        if t["excluded"]:
            continue
        yield t


def scan_all(conf: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """扫描全部根目录（含未启用的，`enabled` 原样回显，由调用方决定用不用）。"""
    c = conf if conf is not None else load_config()
    return [scan_root(r) for r in c["roots"]]
