# -*- coding: utf-8 -*-
"""执行器抽象层。

设计要点：
1. Executor 是抽象基类，当前只有 LocalExecutor（Windows 宿主）。
   以后接 Kali 虚拟机只需实现 SSHExecutor，上层代码不用动。
2. 工作目录必须切到工具自身目录（工具箱原程序就是这么做的），
   否则依赖同目录配置文件的工具会失败。
3. 输出按流实时产出，供 SSE 推送到前端。
4. Windows 中文环境工具输出常为 GBK，解码需容错。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
import time
from abc import ABC, abstractmethod

# v052 补：本模块此前**没有 logger**，而模板校验需要在加载期留一条可追溯的告警
# （丢弃缺 {exe} 的模板这件事必须说出来，否则就是静默改行为）。
logger = logging.getLogger(__name__)
from pathlib import Path
from typing import AsyncIterator

from . import config, ratelimit, traffic
from .registry import Tool
from .scope import check_scope, first_unauthorized_host_in_argv
from .scope import first_unauthorized_target_list_in_argv
# v053：列表文件大小上限定义在 scope.py（不在 config），这里按需引入 ——
# 写 config.TARGET_LIST_MAX_BYTES 编译能过但运行 AttributeError。
from .scope import TARGET_LIST_MAX_BYTES
from .scope import load_scope
# 向后兼容别名：白名单逻辑已收敛到 app/scope.py（唯一实现），
# 但 test_scope.py / test_replayer.py 等既有套件是按历史名字导入的，
# 这里保留同名入口，避免为了改名而改动（进而弱化）那些安全断言。
from .scope import host_in_scope as _host_in_scope  # noqa: F401
from .scope import target_host as _target_host      # noqa: F401

# 模板渲染时 {exe} 的占位符：exe 路径可能含空格，直接渲染进模板再 shlex.split
# 会被拆成多个 token（审计 P2-1），故用占位符过 split 后再还原为真实路径
_EXE_TOKEN = "__SRC_AGENT_EXE__"


def _check_target_type(target_type: str, target: str) -> str | None:
    """校验 target 是否符合声明的形态（v012 P2-2）。

    返回 None=通过；否则返回给用户/模型看的错误说明。
    声明为空或不认识的值一律放行（渐进采用：只有显式声明的工具才受校验）。
    """
    t = (target or "").strip()
    tt = (target_type or "").strip().lower()
    if not tt or not t:
        return None
    if tt == "url":
        if not re.match(r"^https?://", t, re.IGNORECASE):
            return "target 必须是完整 URL（以 http:// 或 https:// 开头，如 https://example.com/）"
        return None
    if tt == "domain":
        if "://" in t or "/" in t or ":" in t:
            return "target 必须是裸域名（不带协议 http://、不带路径、不带端口）"
        return None
    if tt == "host":
        if "://" in t or "/" in t:
            return "target 必须是域名或 IP（不带协议与路径）"
        return None
    return None


def _kill_tree(proc) -> None:
    """终止工具进程树（v012 后半，取消硬终止用）。

    proc.kill 只杀直接子进程；工具箱脚本（python/bat）常会再起子进程，
    taskkill /T /F 才能把整棵树带走。兜底失败时至少直接子进程已被 kill。
    """
    try:
        proc.kill()
    except Exception:
        pass
    try:
        import subprocess as _sp
        _sp.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True, timeout=10,
                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


# ---------- 授权范围（白名单）校验 ----------
# 实现已收敛到 app/scope.py（唯一实现），本模块只负责在执行前调用 check_scope。
# 背景：此前 executor 与 replayer 各写了一份 _load_scope，语义还分叉——
#   replayer 版本会在 scope.json 缺失时静默写入 example.com 再放行，
#   executor 版本则视为空白名单直接拒绝。同一个「授权范围」出现两套行为是隐患，
#   故统一到 scope.py：fail-closed（白名单为空一律拒绝），且不擅自创建默认文件。
# 开关：config.ENFORCE_SCOPE（ENFORCE_SCOPE=0 仅供临时排查，默认强制开启）。


# 模板文件的校验问题（`load_templates` 每次调用都会重置）。
# 为什么要有它：文件是入库的，可能被**直接改写**而绕过控制台的 preview 校验。
# 加载期丢弃模板只留在日志里，没人看日志就等于没发现 —— 所以把问题记下来
# 让控制台的调用模板页直接显示。
_TEMPLATE_PROBLEMS: list[tuple[str, str]] = []


def template_problems() -> list[dict]:
    """最近一次加载发现的模板问题（别名 + 原因）。"""
    return [{"alias": a, "why": w} for a, w in _TEMPLATE_PROBLEMS]


def load_templates() -> dict[str, dict]:
    """加载调用模板。兼容两种写法：
        "ehole": "{exe} finger -u {target} {args}"            （旧，无目标形式）
        "ehole": {"cmd": "...", "target": "url"}              （新，带目标形式）
    """
    _TEMPLATE_PROBLEMS.clear()
    p = config.DATA_DIR / "invocation_templates.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for k, v in data.items():
        if k.startswith("_"):
            continue
        if isinstance(v, str):
            cmd, tgt = v, "raw"
        else:
            cmd, tgt = v.get("cmd", ""), v.get("target", "raw")
        # v052（复审报告 P2-B，纵深防御）：**加载期**也强制要求 {exe}。
        # 控制台的 preview 已经要求了（`templates_preview`），但那是**入口之一** ——
        # 这个文件是入库的，被直接改写（或将来别的写入路径）就绕过了那道检查。
        # 缺 {exe} 的后果不是「报错」而是**静默换掉要执行的二进制**：
        # `_from_template` 用 `_EXE_TOKEN` 占位符还原 `tool.executable`，
        # 没有占位符时首个 token 就是模板里写的任意字符串（例如 `sh`），
        # 而 `tool.executable`（受信任的 TOOLBOX_ROOT 路径）被完全忽略。
        # 这里**丢弃**该模板并留日志 —— 丢弃后走默认拼接（`{exe} {args} {target}`），
        # 用的仍是受信任路径，行为可预期。
        if "{exe}" not in (cmd or ""):
            logger.warning("调用模板 %r 缺少 {exe} 占位符，已忽略该模板（走默认拼接）：%r",
                           k, cmd)
            _TEMPLATE_PROBLEMS.append((k, "缺少 {exe} 占位符"))
            continue
        out[k] = {"cmd": cmd, "target": tgt}
    return out


def normalize_target(target: str, form: str) -> str:
    """把目标归一化为工具期望的形式。

    不把格式负担甩给模型——小模型最常在这里出错，
    而错了往往只是静默失败（如 ehole 传裸域名直接返回空）。
    """
    t = (target or "").strip()
    if not t:
        return t

    # 去掉 scheme、路径与查询串，拿到 host。
    # 注意保留 CIDR：192.168.1.0/24 被截断成 192.168.1.0 会让扫描器只打一个 IP。
    def to_host(s: str) -> str:
        s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", s)
        s = s.split("?")[0].strip()
        head, sep, tail = s.partition("/")
        if sep and re.fullmatch(r"[\d.]+", tail):   # CIDR 掩码，保留
            return head + sep + tail
        return head

    if form == "url":
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", t):
            return t
        return "https://" + t.lstrip("/")

    if form == "host":
        return to_host(t)

    if form == "domain":
        h = to_host(t)
        # 子域名工具要裸域名：带端口无法作为根域名，必须去掉
        if re.fullmatch(r"[\d.]+", h):   # 纯 IP / CIDR 原样返回
            return h
        h = h.split(":")[0]
        return re.sub(r"^www\.", "", h, flags=re.IGNORECASE)

    return t  # raw


def _target_flag(tmpl: str) -> str | None:
    """从模板里取出紧跟 {target} 前面的参数旗标，如 `-u` / `-t` / `--target`。"""
    # 旗标后必须是空白或模板占位符，避免误把 `--target-extra` 这种长旗标截断
    m = re.search(r"(-{1,2}[\w-]+)(?![-\w])\s*=?\s*\{target\}", tmpl)
    return m.group(1) if m else None


def _strip_target_arg(args: str, flag: str | None, target: str | None = None) -> str:
    """删掉模型在 args 里**重复填写的目标旗标**（含其值），避免与模板冲突。

    例：模板 `dirsearch.py -u {target} {args}`，模型却传入 args=`-u "http://x/-"`，
    拼出来变成 `-u https://x -u "http://x/-"`，dirsearch 直接栈溢出崩溃（0xC0000004）。
    这里把重复的那个 `-u ...` 整段剥掉，只保留真正「额外」的参数。

    ## v053（审计 §2.3 修）：判据从「第几个」改成「**取值是不是本步的 target**」

    原实现是对 args 里**每一个** `{flag} {value}` 形态都替换（无 `count`），
    于是无法区分「重复填的目标旗标」（要剥）与「工具确实需要、位置在 args 中段的同名旗标」
    （不能剥）—— 例如模板 `foo {target} {args}`、模型传 `args="-x --url http://a/ -y"`，
    中间的 `--url http://a/` 会被删掉，**改写的是真正要执行的命令**。

    ⚠️ 先说清一个容易走偏的点：只加 `count=1` **并不能**修好上面那个例子 ——
    args 里 `--url` 只出现一次，它本来就是「第一个匹配」，照样被剥。
    真正的判据只能是**值是否等于本步 target**（那才叫"重复填写"）：
      · 值归一化后与本步 target 相同 → 是重复 → 剥掉；
      · 值不同（例如工具真要额外打另一个 URL）→ **保留**，交给出网前的
        argv 逐 token 复核把关（未授权主机会被拦下）。
    `target` 为 None 时（旧调用点）退化为「只剥第一个」，保守且不改变既有行为。
    """
    if not flag or not args:
        return args
    esc = re.escape(flag)
    # 旗标后不能是 - 或单词字符，避免误伤 `--target-extra` 这类长旗标
    # 匹配：flag[=值] 或 flag 值（值可带引号）；值可选，顺带剥掉孤立的 flag
    pat = re.compile(
        r"(?P<lead>\s|^)" + esc + r"(?![-\w])"
        r"(?:(?:=(?P<v1>\"[^\"]*\"|'[^']*'|\S+))"
        r"|(?:\s+(?P<v2>\"[^\"]*\"|'[^']*'|\S+)))?"
    )

    def _same_target(v: str) -> bool:
        """旗标取值是否就是本步 target（按主机级比较，容忍引号/路径/尾斜杠差异）。"""
        a = _strip_one_layer_quotes(v or "").strip()
        b = (target or "").strip()
        if not a or not b:
            return False
        if a == b:
            return True
        try:
            return normalize_target(a, "host") == normalize_target(b, "host")
        except Exception:                                    # noqa: BLE001
            return False

    if target:
        def repl(m):
            val = m.group("v1") or m.group("v2") or ""
            # 值不像本步 target → 原样保留（可能是工具真正需要的另一个目标参数）
            return m.group("lead") if _same_target(val) else m.group(0)
        return pat.sub(repl, args).strip()
    # 未给 target：保守地只剥第一个（保持既有调用点的行为不变）
    return pat.sub(r"\g<lead>", args, count=1).strip()


def _strip_one_layer_quotes(tok: str) -> str:
    """递归去掉 token 最外层所有成对的匹配引号（" 或 '）。

    模型常把路径多包若干层引号（如 `'"C:/a/b.txt"'`：外层单引号 + 内层双引号），
    逐层剥掉直到没有外层引号，避免工具收到带字面引号的路径而找不到文件。
    """
    while len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
        tok = tok[1:-1]
    return tok


def _strip_args_quotes(args: str) -> str:
    """剥掉每个参数 token 最外层的一层引号。

    小模型常把路径多包一层引号（如 `-w '"C:/a/b.txt"'`），
    shlex 会保留内部那层字面引号，工具收到带引号路径而找不到文件。
    这里统一去掉最外层引号，让路径第一次就能被正确识别。
    """
    if not args:
        return args
    try:
        toks = shlex.split(args, posix=False)
    except ValueError:
        return args
    return shlex.join(_strip_one_layer_quotes(t) for t in toks)


def _filter_unknown_flags(args: str, allowed: list[str], value_flags: list[str]) -> str:
    """按工具白名单剥掉模型臆造的非法旗标（含其值）。

    小模型常给工具编出不存在的参数（如给 dirsearch 传 `--depth`），
    工具会直接报错退出。这里把不在 allowed 里的旗标整段丢弃，只保留
    合法旗标与其取值，让工具按预期运行而不是失败。

    - allowed 为空列表表示「不校验」，原样返回。
    - value_flags 标记哪些旗标会吞掉下一个 token（取值旗标）；
      布尔旗标不带值，不吞下一个 token，避免误删真正的位置参数。
    """
    if not args or not allowed:
        return args
    allowed_set = set(allowed)
    value_set = set(value_flags or [])
    try:
        toks = shlex.split(args, posix=False)
    except ValueError:
        return args
    out: list[str] = []
    i, n = 0, len(toks)
    while i < n:
        tok = _strip_one_layer_quotes(toks[i])
        if tok.startswith("-"):
            flag = tok.split("=", 1)[0]
            if flag in allowed_set:
                out.append(tok)
                # 空格形式的取值旗标：若下一个 token 不像旗标则吞掉它
                if "=" not in tok and i + 1 < n and not _strip_one_layer_quotes(toks[i + 1]).startswith("-"):
                    if flag in value_set:
                        out.append(_strip_one_layer_quotes(toks[i + 1]))
                        i += 1
                # 否则视为布尔旗标，不吞下一个 token
            else:
                # 非法旗标：若有 `=` 整段丢弃；否则连同下一个非旗标值一起丢弃
                if "=" not in tok and i + 1 < n and not _strip_one_layer_quotes(toks[i + 1]).startswith("-"):
                    i += 1
            # 非法旗标本身不加入 out
        else:
            out.append(tok)
        i += 1
    return shlex.join(out) if out else ""


def _strip_disallowed_flags(args: str, disallowed: list[str]) -> str:
    """按黑名单精确剔除旗标（v012 P2-2）。

    与 _filter_unknown_flags（白名单，为空=不校验）方向相反：disallowed_flags
    里列出的旗标**无论白名单是否启用都剔除**（含其取值）——用于表达
    「这工具支持这个参数，但在这个部署里不许用」（如 nuclei 的 -lmi 上传
    中间报告、naabu 的 -Pn 组合行为）。未配置黑名单时原样返回。
    """
    if not args or not disallowed:
        return args
    banned = set(disallowed)
    try:
        toks = shlex.split(args, posix=False)
    except ValueError:
        return args
    out: list[str] = []
    i, n = 0, len(toks)
    while i < n:
        tok = _strip_one_layer_quotes(toks[i])
        if tok.startswith("-"):
            flag = tok.split("=", 1)[0]
            if flag in banned:
                # 命中黑名单：`=` 形式整段丢弃；空格取值形式连同下一个值丢弃
                if "=" not in tok and i + 1 < n and not _strip_one_layer_quotes(toks[i + 1]).startswith("-"):
                    i += 1
                i += 1
                continue
        out.append(tok)
        i += 1
    return shlex.join(out) if out else ""


def _decode(raw: bytes) -> str:
    """Windows 中文环境下工具输出可能是 GBK，逐个尝试常见编码。"""
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _apply_network_control(tool, args: str) -> tuple[str, list[str]]:
    """按 network_control 声明注入保守速率/并发参数（v023.2）。

    规则：工具已声明 supports_rate/supports_concurrency 且 args 里**未出现**
    对应旗标时，追加系统默认保守值（SCANNER_DEFAULT_RATE/THREADS）。
    用户或模型显式给出的旗标不覆盖——显式值仍会在 argv 复核与白名单清洗里
    过一遍；要更强约束请把旗标写进 disallowed_flags。
    """
    nc = getattr(tool, "network_control", None) or {}
    notes: list[str] = []
    text = args or ""

    def _inject(flag: str, value: int, label: str) -> None:
        nonlocal text
        if not flag or flag in text:
            return
        text = (text + f" {flag} {value}").strip()
        note = f"（已注入{label} {flag} {value}）"
        if tool.allowed_flags and flag not in tool.allowed_flags:
            # 白名单会剔除不在册的旗标——不静默失败，明确提示补白名单
            note += (f" 注意：{flag} 不在该工具 allowed_flags 白名单中，"
                     f"可能被参数清洗剔除；请在 overrides 里把 {flag} 加入 allowed_flags")
        notes.append(note)

    if nc.get("supports_rate"):
        for flag in (nc.get("rate_flags") or [])[:1]:
            _inject(flag, config.SCANNER_DEFAULT_RATE, "速率限制")
    if nc.get("supports_concurrency"):
        for flag in (nc.get("concurrency_flags") or [])[:1]:
            _inject(flag, config.SCANNER_DEFAULT_THREADS, "并发上限")
    if not notes:
        notes.append(f"（{tool.name} 已声明速率能力；本次未注入参数——"
                     f"请确认 args 中已有速率/并发限制）")
    return text, notes


class Executor(ABC):
    """执行器抽象：子类需实现 run（取回输出）与 launch（仅启动）。"""

    @abstractmethod
    async def run(self, tool: Tool, target: str, args: str = "",
                  cancel_event=None, project_id: str = "", session_id: str = "") -> AsyncIterator[dict]:
        """执行工具并流式产出输出行。

        cancel_event（v012 后半）：取消硬终止——调用方传入 asyncio.Event，
        输出循环每块检查，置位即终止整棵进程树并停止执行。
        """
        ...

    @abstractmethod
    async def launch(self, tool: Tool) -> dict:
        """仅启动工具（用于图形界面工具，不取回输出）。"""
        ...


class LocalExecutor(Executor):
    """在 Windows 宿主机上本地执行。"""

    def __init__(self) -> None:
        self.templates = load_templates()

    def reload_templates(self) -> int:
        """重新载入调用模板并返回条数。

        v052（复审报告 P2-F）：模板在 `__init__` 只载入一次，而 `executor` 是模块级单例
        （`executor = LocalExecutor()`）—— 于是控制台改完模板，**运行中的实例仍用旧模板**，
        直到重启。这正是本项目反复出现的「改了没生效」。控制台的
        `reload_for("invocation_templates")` 现在会调它。
        """
        self.templates = load_templates()
        return len(self.templates)

    # ---------- 命令构造 ----------
    def build_command(self, tool: Tool, target: str, args: str = "") -> list[str]:
        """按工具类型构造命令行。

        - Python：用工具箱内置 python3/python.exe
        - JAVA8 / JAVA11：用对应版本的 java.exe -jar
        - 命令行 / 批处理：直接执行（.vbs 走 wscript）
        """
        exe = tool.executable
        ttype = tool.type

        if ttype == "Python":
            python_exe = str(config.TOOLBOX_PYTHON)
            if not Path(python_exe).exists():
                python_exe = "python"
            return self._from_template(tool, target, args, prefix=[python_exe])

        if ttype in ("JAVA8", "JAVA11"):
            java_bin = config.JAVA8_BIN if ttype == "JAVA8" else config.JAVA11_BIN
            java_exe = java_bin / "java.exe"
            if not java_exe.exists():
                java_exe = Path("java")
            return self._from_template(tool, target, args, prefix=[str(java_exe), "-jar"])

        if ttype == "批处理":
            ext = Path(exe).suffix.lower()
            if ext == ".vbs":
                return ["wscript", exe, *(shlex.split(args, posix=False) if args else [])]
            return self._from_template(tool, target, args)

        # 命令行
        return self._from_template(tool, target, args)

    def _tmpl(self, tool: Tool) -> dict | None:
        return self.templates.get(tool.alias)

    def _from_template(self, tool: Tool, target: str, args: str, prefix: list[str] | None = None) -> list[str]:
        cmd = list(prefix or [])
        entry = self.templates.get(tool.alias)
        tmpl = entry.get("cmd") if entry else None
        if tmpl:
            # 按工具声明的形式归一化目标，避免「参数明明对却静默失败」
            norm = normalize_target(target, (entry or {}).get("target", "raw"))
            # 剥掉模型在 args 里重复填写的目标旗标（如 dirsearch 传了 -u "x"，
            # 模板本身已有 -u {target}，拼出来 -u a -u b 会让工具栈溢出崩溃）
            flag = _target_flag(tmpl)
            # v053：把本步 target 传进去 —— 只有「取值等于本步 target」的才算重复填写，
            # 值不同的同名旗标要保留（那是工具真正需要的参数，交给 argv 复核把关）。
            clean_args = _strip_target_arg(args, flag, norm)
            # 按工具白名单剥掉模型臆造的非法旗标（如 dirsearch 的 --depth）
            clean_args = _filter_unknown_flags(clean_args, tool.allowed_flags, tool.value_flags)
            # v012 P2-2：黑名单旗标精确剔除（allowed_flags 为空时也能用）
            clean_args = _strip_disallowed_flags(clean_args, tool.disallowed_flags)
            rendered = tmpl.format(exe=_EXE_TOKEN, target=norm, args=clean_args or "")
            # 模板里的 {args} 可能为空，需清理多余空白
            parts = [p for p in shlex.split(rendered, posix=False) if p]
            # {exe} 用占位符还原：exe 路径可能含空格，进 shlex 会被拆碎（审计 P2-1）
            cmd.extend([tool.executable if p == _EXE_TOKEN else p for p in parts])
        else:
            cmd.append(tool.executable)
            if args:
                args = _strip_args_quotes(args)
                args = _filter_unknown_flags(args, tool.allowed_flags, tool.value_flags)
                args = _strip_disallowed_flags(args, tool.disallowed_flags)
                cmd.extend(shlex.split(args, posix=False))
            if target:
                cmd.append(target)
        return cmd

    # ---------- 执行 ----------
    async def run(self, tool: Tool, target: str, args: str = "",
                  cancel_event=None, project_id: str = "", session_id: str = "") -> AsyncIterator[dict]:
        # ---- 授权范围校验（执行前最后一道闸门）----
        # 命令行工具此前只校验 target 格式、不校验是否授权，
        # 配合「项目 target 自动注入」后目标来源变多，越权路径更短，故在此兜底。
        # 开关见 config.ENFORCE_SCOPE；白名单与 HTTP 重放器共用 data/scope.json。
        if config.ENFORCE_SCOPE:
            denied = check_scope(target)
            if denied:
                yield {"type": "error", "data": denied}
                yield {"type": "exit", "code": 126}  # 126 = 命令不可执行（约定沿用 shell 语义）
                return

        if not tool.executable:
            yield {"type": "error", "data": f"工具文件不存在：{tool.name}（{tool.rel_path}）"}
            return

        # v023.2：扫描器内部速率能力声明（network_control）。**注意（v023.6 修）**：
        # 未声明提示已移到工具清单描述里（registry.build_schemas）——实战发现
        # 每次执行前都 yield 一遍会让同一段长警告刷屏，污染输出与上下文。
        # 这里只保留：严格模式拒绝 + 审计留痕（不再输出提示文本）。
        nc = tool.network_control or {}
        if not nc.get("declared"):
            if config.SCANNER_REQUIRE_DECLARATION:
                yield {"type": "error", "data": (
                    f"已拒绝执行（严格模式）：「{tool.name}」未声明内部速率/并发能力"
                    f"（network_control.declared），其内部请求量不可观测。"
                    f"请在 data/tool_overrides.json 补齐声明，或关闭 "
                    f"AGENT_SCANNER_REQUIRE_DECLARATION。")}
                yield {"type": "exit", "code": 126}
                return
        else:
            # 已声明能力：自动注入保守速率/并发值（args 里用户已显式给出则不覆盖）
            args, injected = _apply_network_control(tool, args)
            for note in injected:
                yield {"type": "output", "data": note}

        cmd = self.build_command(tool, target, args)

        # ---- target 形态校验（v012 P2-2 manifest 渐进版）----
        # 工具在 overrides 里声明 target_type 后，形态不符直接拒绝并说明
        # 正确形态（fail-closed、报错可读），而不是让工具拿错形态静默失败。
        tt_bad = _check_target_type(tool.target_type, target)
        if tt_bad:
            yield {"type": "error", "data": (
                f"target 形态不符合「{tool.name}」的要求：{tt_bad}"
                f"（该工具要求 target_type={tool.target_type}）。"
                "请按说明调整后重试。")}
            yield {"type": "exit", "code": 1}
            return

        # ---- 最终 argv 主机级复核（审计 P0-2/P0-3 的根治层）----
        # 白名单此前只覆盖 target：args 可走私 --url evil.com（dirsearch 里与 -u 同义，
        # 后者覆盖前者）；url 型 target 可用「授权域/+空格」夹带第二个目标。此处对
        # 最终 argv 逐 token 抽主机复核，无论走私走 target、args 还是模板，spawn 前必拦。
        if config.ENFORCE_SCOPE:
            bad = first_unauthorized_host_in_argv(cmd)
            if bad:
                idx, host = bad
                yield {"type": "error", "data": (
                    f"命令行第 {idx + 1} 个参数包含不在授权白名单内的目标「{host or '（无法解析）'}」，"
                    f"已拒绝执行。args 中不得夹带未授权目标"
                    f"（当前白名单：{', '.join(load_scope())}）。")}
                yield {"type": "exit", "code": 126}
                return
            # ---- 目标列表文件内容复核（v010）----
            # argv 逐 token 复核看不到 -l/--list/--urls/--input 指向的文件**内容**；
            # 列表里写 evil.com 即可绕过上面的全部校验。这里对列表文件逐行过白名单。
            bad_list = first_unauthorized_target_list_in_argv(cmd)
            if bad_list:
                flag, host = bad_list
                # v053（审计 §2.4）：返回的第二个元素可能是**哨兵**而不是主机名，
                # 必须分开措辞 —— 否则会输出「文件中包含目标「<unreadable>」」这种
                # 指向错误方向的报错（`<oversized>` 原本就有这个问题）。
                if host == "<oversized>":
                    why = (f"目标列表参数 {flag} 指向的文件超过大小上限"
                           f"（{TARGET_LIST_MAX_BYTES} 字节），未做内容校验，已拒绝执行。"
                           "请改用更小的列表文件，或把目标拆分后分次执行。")
                elif host == "<unreadable>":
                    why = (f"目标列表参数 {flag} 指向的文件**存在但无法读取/解码**，"
                           "无法校验其内容，已拒绝执行（fail-closed）。"
                           "请确认文件可读、且编码为 UTF-8 / GBK / 带 BOM 的 UTF-16。")
                else:
                    why = (f"目标列表参数 {flag} 指向的文件中包含不在授权白名单内的目标"
                           f"「{host}」，已拒绝执行。目标列表文件内的每个目标都必须在"
                           f"授权白名单内（当前白名单：{', '.join(load_scope())}）。")
                yield {"type": "error", "data": why}
                yield {"type": "exit", "code": 126}
                return

        yield {"type": "command", "data": " ".join(f'"{c}"' if " " in c else c for c in cmd)}

        env = os.environ.copy()
        # 注入工具箱运行时，避免依赖系统环境
        if config.TOOLBOX_PYTHON.exists():
            env["PATH"] = str(config.TOOLBOX_PYTHON.parent) + os.pathsep + env.get("PATH", "")
            env.pop("PYTHONHOME", None)
            env.pop("PYTHONPATH", None)

        # 防御性补全 Windows 关键环境变量：服务可能从精简环境的 shell 启动，
        # 缺 APPDATA 会让 pyfiglet（dirsearch 依赖）等直接 KeyError 崩溃。
        home = str(Path.home())
        env.setdefault("APPDATA", home + os.sep + "AppData" + os.sep + "Roaming")
        env.setdefault("LOCALAPPDATA", home + os.sep + "AppData" + os.sep + "Local")
        env.setdefault("TEMP", env.get("TEMP") or home + os.sep + "AppData" + os.sep + "Local" + os.sep + "Temp")
        env.setdefault("TMP", env["TEMP"])

        # 出网许可（v023.1）：统一走 TrafficGovernor——滑动窗口预算、目标/根域名
        # 并发、暂停状态检查与流量事件落库。扫描器**内部**的并发请求当前无法逐条
        # 统计（v023.2 的 manifest 速率治理解决），此处先把它计为一次出网配额并
        # 在目标已暂停/预算耗尽时直接拒绝启动（不启动就不会有内部并发）。
        host_for_traffic = _target_host(target) or target or ""
        if host_for_traffic:
            probe_url = host_for_traffic if "://" in host_for_traffic \
                else f"https://{host_for_traffic}/"
            try:
                permit = await traffic.governor.acquire(
                    probe_url, tool_alias=tool.alias or tool.name, method="GET",
                    project_id=project_id, session_id=session_id)
                await traffic.governor.release(permit)
            except traffic.TrafficError as e:
                yield {"type": "error", "data": f"出网调度拒绝（不启动扫描器）：{e}"}
                yield {"type": "exit", "code": 126}
                return


        try:
            # 需要喂入 stdin 绕开交互式 input() 提问时，才挂 PIPE；否则保持 None
            # 以免无谓占用管道。喂入后立刻关闭，让子进程的 input() 拿到 EOF。
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=tool.workdir or None,
                stdin=asyncio.subprocess.PIPE if tool.stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
        except FileNotFoundError as e:
            yield {"type": "error", "data": f"无法启动：{e}"}
            return
        except Exception as e:
            yield {"type": "error", "data": f"启动异常：{e}"}
            return

        # 异步喂入 stdin（如 packerfuzzer 的两处 input() 提问），与 stdout 读取
        # 流水线并行，避免互相阻塞造成死锁。写入后关闭以触发 EOF。
        if tool.stdin_input and proc.stdin is not None:
            async def _feed_stdin() -> None:
                try:
                    proc.stdin.write(tool.stdin_input.encode("utf-8", errors="ignore"))
                    await proc.stdin.drain()
                    proc.stdin.close()
                except Exception:
                    pass
            asyncio.create_task(_feed_stdin())

        # 双重超时：
        #  - idle：单块输出的等待上限，卡死无输出时能兜底
        #  - 总时长：工具从启动到结束的绝对上限。
        #    仅靠 idle 是不够的——像 enscan 这类工具会每 10 秒刷一行
        #    "需要安全验证"，输出不断流，idle 永不触发，进程将无限跑下去。
        total = tool.tool_timeout or config.TOOL_TIMEOUT
        deadline = time.time() + total
        truncated = False
        lines = 0
        limit = config.MAX_OUTPUT_LINES

        try:
            buf = ""
            while True:
                # ---- 取消硬终止（v012 后半）----
                # 用户点了取消：立刻终止整棵进程树（含工具自己起的子进程），
                # 不再等本步跑完。检查间隔 = 输出块间隔（≤ idle 超时，秒级响应）。
                if cancel_event is not None and cancel_event.is_set():
                    _kill_tree(proc)
                    yield {"type": "cancelled", "data": "已收到取消请求，工具进程已终止"}
                    break
                remaining = deadline - time.time()
                if remaining <= 0:
                    proc.kill()
                    yield {"type": "error",
                           "data": f"工具执行超过总时长上限（{total}s），已终止"}
                    break
                # 按块读取而不是 readline：dirsearch 等工具用 \r 刷新进度条，
                # 积压成超长行会把 readline 的 64KB 缓冲打爆（Separator not found）。
                try:
                    chunk = await asyncio.wait_for(
                        proc.stdout.read(4096),
                        timeout=min(remaining, config.TOOL_IDLE_TIMEOUT),
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    yield {"type": "error",
                           "data": f"工具超过 {config.TOOL_IDLE_TIMEOUT}s 无输出，已终止"}
                    break
                if not chunk:
                    break
                buf += _decode(chunk)
                # 按 \r\n / \n / \r 切行，进度条也能实时流出
                while True:
                    m = re.search(r"\r\n|\n|\r", buf)
                    if not m:
                        break
                    line, buf = buf[: m.start()], buf[m.end():]
                    if not line.strip():
                        continue
                    lines += 1
                    if lines > limit:
                        # 只丢弃多余行，保留已回传的部分，避免撑爆上下文
                        truncated = True
                        continue
                    yield {"type": "output", "data": line}
            # 进程结束后冲刷残余缓冲（最后一行可能不带换行符）
            if buf.strip():
                lines += 1
                if lines <= limit:
                    yield {"type": "output", "data": buf}
                else:
                    truncated = True
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
            if truncated:
                yield {"type": "output",
                       "data": f"（输出超过 {limit} 行，已截断，仅保留前 {limit} 行）"}
            yield {"type": "exit", "code": proc.returncode}
        except Exception as e:
            yield {"type": "error", "data": f"执行异常：{e}"}
            try:
                proc.kill()
            except Exception:
                pass

    # ---------- 图形界面工具启动 ----------
    async def launch(self, tool: Tool) -> dict:
        """启动图形界面工具。完全复刻工具箱原有分派逻辑，不取回输出。"""
        if not tool.executable:
            return {"ok": False, "message": f"工具文件不存在：{tool.name}"}

        ttype = tool.type
        exe = tool.executable
        cwd = tool.workdir

        try:
            if ttype == "Python":
                python_exe = str(config.TOOLBOX_PYTHON)
                proc = await asyncio.create_subprocess_exec(
                    python_exe, exe, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            elif ttype.startswith("JAVA"):
                is_gui = "图形化" in ttype
                java_bin = config.JAVA8_BIN if "8" in ttype else config.JAVA11_BIN
                java_exe = java_bin / ("javaw.exe" if is_gui else "java.exe")
                if not java_exe.exists():
                    java_exe = Path("javaw" if is_gui else "java")
                args = ["-jar", exe]
                proc = await asyncio.create_subprocess_exec(
                    str(java_exe), *args, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            elif Path(exe).suffix.lower() == ".vbs":
                proc = await asyncio.create_subprocess_exec(
                    "wscript", exe, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    exe, cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            return {"ok": True, "pid": proc.pid, "message": f"已启动 {tool.name}"}
        except Exception as e:
            return {"ok": False, "message": f"启动失败：{e}"}


executor = LocalExecutor()
