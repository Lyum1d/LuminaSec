# -*- coding: utf-8 -*-
"""Burp Suite MCP 工具层（v044）：把 Burp 的 MCP 工具接进 Agent 的治理体系。

为什么单独一个模块而不是塞进 replayer.py：
  replayer.py 的定位是「不依赖外部进程的原生能力」（它自己的 docstring 第一句）。
  Burp 是**外部进程**，且是一条独立的出网通道——把两者混在一个文件里，日后
  「到底有几条出网通道」会说不清，而本项目所有安全策略（限速/预算/WAF 状态机/
  失败归因）都以「出网通道可枚举」为前提。

本模块与既有通道的关系：
  · httpreplay（app/replayer.py）：Agent 自己直连目标。范围窄（只读方法）、
    快、不依赖任何外部进程。**默认通道。**
  · burp_replay（本模块）：请求交给 Burp 发。需要 Burp 在线 + 人工批准
    （可配 auto-approve）；换取到的是 Burp 的 TLS 栈与上游代理链、
    以及请求原样经 Burp 的手工/插件链路。
  · 两者**互补而非替代**：拿不准目标是否喜欢被 Burp 代理时用 httpreplay；
    需要请求走 Burp 的代理链、或要与 Burp 里的会话保持同一出口时用 burp_replay。

⚠️ **重要事实（2026-09-22 真机实测纠正）**：
    `send_http1_request` **不会把请求写进 Burp Proxy history**。
    它是在扩展内部直接构造并发出请求，不经 Proxy 监听器，因此
    `get_proxy_http_history` 读不到它。实测对照：经本通道发出一个真实 GET，
    目标回了 301，而同一次会话里 `get_proxy_http_history` /
    `get_organizer_items` / `get_proxy_websocket_history` 三个历史区**全为空**。
    所以「发请求 → 回读 history 形成闭环」这个设想**不成立**，
    `burp_history` 读到的是**用户自己在 Burp 里手工抓的包**，两者互补：
      · burp_replay → 拿到本次交互的请求与响应（响应已在工具返回值里）
      · burp_history → 读取人工浏览/测试过程中积累的流量

安全边界（按项目纪律逐条落实）：
  ① 出网前必须过 TrafficGovernor.acquire()，与其它通道同一套限速与预算。
     Acquire 失败（scope 拒绝 / 预算耗尽 / 目标被暂停）→ 直接返回失败，
     **绝不发出网请求**，且把原因原样回传给模型（让它知道是授权问题而非网络问题）。
  ② raw HTTP 文本里声明的 host 必须能被 scope 校验。注意这里有个陷阱：
     MCP 的 send_http1_request 是「你说打到哪就打哪」——targetHostname 由调用方
     指定，与 raw 文本里的 Host 头可以不一致。**以 targetHostname 为准做校验**，
     因为它才是真正决定连接目标的值。
  ③ 不做 WAF 绕过、不自动重试被拦请求。Burp 返回什么就回传什么。
"""
from __future__ import annotations

import os
import re
import time
from urllib.parse import urlsplit

from . import config, mcp_client, pyexec, scope, traffic

# 允许经 Burp 发送的方法。
# 与 httpreplay 的差异说明：httpreplay 硬禁写入方法（它没有人工闸门）；Burp 这条
# 通道背后有**人工批准弹窗**（requireHttpRequestApproval 默认开），所以可以放开
# POST/PUT。但 DELETE 仍然禁止——删除类操作在 SRC 场景下几乎只有破坏性，
# 没有任何验证价值，属于「收益为负」的请求。
_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}

_REQUEST_LINE_RE = re.compile(r"^([A-Z]{3,7})\s+(\S+)\s+HTTP/(\d(?:\.\d)?)\s*$", re.M)


class BurpRequestError(Exception):
    """本地参数/授权校验失败（还没走到发请求那一步）。"""


def parse_raw_request(raw: str) -> dict:
    """从 raw HTTP 文本里解析出方法、路径、协议版本。

    官方扩展要求 content 是**完整 raw 请求**（含请求行、头、空行、体），且
    换行建议用 CRLF。这里只解析我们关心的部分——方法用于闸门判定，路径用于
    日志与 URL 拼装。头的解析交给 Burp，不重复实现一套 HTTP 解析器。
    """
    raw = (raw or "").replace("\r\n", "\n")
    m = _REQUEST_LINE_RE.search(raw)
    if not m:
        raise BurpRequestError(
            "raw 请求缺少合法的起始行。需形如 `GET /path HTTP/1.1`（第一行），"
            "并且要包含 Host 头与末尾空行。")
    method, path, ver = m.group(1).upper(), m.group(2), m.group(3)
    return {"method": method, "path": path, "http_version": ver, "raw": raw}


def split_target(target: str) -> tuple[str, int, bool]:
    """把 target 解析成 (hostname, port, uses_https)。

    官方 MCP 的三个参数是分开传的（targetHostname / targetPort / usesHttps），
    所以这里必须把 Agent 习惯的完整 URL 拆开。默认端口按 scheme 推断。
    """
    t = (target or "").strip()
    if not t:
        raise BurpRequestError("target 为空：需要完整 URL，如 https://example.com/api")
    if "://" not in t:
        t = "https://" + t
    parts = urlsplit(t)
    host = parts.hostname or ""
    if not host:
        raise BurpRequestError(f"target 解析不出主机名：{target!r}")
    https = parts.scheme.lower() != "http"
    port = parts.port or (443 if https else 80)
    return host, int(port), https


def _method_allowed(method: str) -> str | None:
    if method in _ALLOWED_METHODS:
        return None
    return (f"方法 {method} 不允许经 burp_replay 发送。"
            f"允许：{'/'.join(sorted(_ALLOWED_METHODS))}。"
            "删除类操作在授权测试中属破坏性行为，请改用手工确认或其它验证方式。")


def _persist_response(text: str) -> str:
    """把大响应正文落盘，返回追加在输出尾部的提示行（小响应返回空串）。

    复用 py_exec 的会话级持久目录：**这是有意的**——落盘文件都可能含目标站点
    的敏感响应正文，必须与 py_exec 的落盘文件受同一条保留期约束
    （cleanup_persist_dirs 按 AGENT_PY_EXEC_PERSIST_KEEP_DAYS 清理）。
    如果给 Burp 单开一个目录，清理逻辑就要写第二份，迟早漏掉一个。

    用 write_bytes 写原始字节（v033 教训）：文本模式写盘在 Windows 上会把 \n
    变成 \r\n，导致取回的正文与真实响应字节不一致——差分/哈希取证会出错。
    所以落盘一律走 bytes，读回也一律用 rb。
    """
    if len(text) < config.PY_EXEC_SAVE_THRESHOLD:
        return ""
    try:
        day = pyexec.persist_dir_for("")
        day.mkdir(parents=True, exist_ok=True)
        path = day / f"burp_{time.strftime('%H%M%S')}_{os.getpid()}.bin"
        path.write_bytes(text.encode("utf-8", errors="replace"))
    except Exception as e:      # noqa: BLE001 - 落盘失败不影响把响应回传给模型
        return f"\n（响应正文落盘失败：{type(e).__name__}: {e}；正文仍在下方）"
    return (f"\n（响应正文 {len(text)} 字符已落盘：{path}。"
            f"需要离线分析或做字节级差分时用 rb 读该文件，不要为了拿正文重发请求。）")


def build_replay_payload(parsed: dict) -> dict:
    """把解析结果拼成 ``send_http1_request`` 的参数。

    单独抽成纯函数是为了**可测**：工具参数名一旦与 Burp 扩展的实际 schema
    对不上，运行期只会拿到一句 "Encountered an unknown key ..."（真机实测过），
    很难归因。抽出来后回归测试能直接在本地断言键名集合。

    参数名与官方扩展 v1.3.0 的 inputSchema 严格一致（2026-09-22 真机 tools/list
    读出，非文档抄写）：
        content(required) / targetHostname(required)
        targetPort(required) / usesHttps(required)
    """
    return {
        "content": parsed["raw"],
        "targetHostname": parsed["host"],
        "targetPort": parsed["port"],
        "usesHttps": parsed["https"],
    }


def history_tool_name(params: dict) -> str:
    """按有无 regex 选择工具变体（真机上两个是独立工具，不是可选参数）。"""
    return ("get_proxy_http_history_regex" if "regex" in params
            else "get_proxy_http_history")


async def run_burp_replay(target: str, args: str, *, project_id: str = "",
                          session_id: str = "", cancel_event=None):
    """经 Burp 发送一个 raw HTTP 请求。产出与其它内置工具一致的事件流。

    args 约定：**整段就是 raw HTTP 请求文本**（不做旗标解析）——因为 raw 请求
    本身包含任意头与体，再用旗标语法包一层只会制造转义地狱。模型要改哪个头，
    直接改 raw 文本里那一行即可。

    事件流：output / error / exit。exit code 约定：
      0  成功
      126 授权边界拒绝（与 executor/pyexec 同一约定，agent 侧据此判定 SCOPE 失败）
      1  其它失败（MCP 不可用 / Burp 报错 / 参数非法）
    """
    # ---- 1) 本地解析（先于任何出网动作）----
    try:
        parsed = parse_raw_request(args)
        host, port, uses_https = split_target(target)
    except BurpRequestError as e:
        yield {"type": "error", "data": str(e)}
        yield {"type": "exit", "code": 1}
        return

    denied = _method_allowed(parsed["method"])
    if denied:
        yield {"type": "error", "data": denied}
        yield {"type": "exit", "code": 1}
        return

    # ---- 2) 授权边界（第一责任人仍是 scope.py）----
    # 用真实连接目标（targetHostname）做校验，而不是 raw 文本里的 Host 头：
    # 两者可以不一致，而决定「包发到哪」的是 targetHostname。
    probe_url = f"{'https' if uses_https else 'http'}://{host}:{port}{parsed['path']}"
    scope_denied = scope.check_scope(probe_url)
    if scope_denied:
        yield {"type": "error",
               "data": f"目标不在授权白名单内，拒绝经 Burp 发送：{scope_denied}"}
        yield {"type": "exit", "code": 126}
        return

    # ---- 3) 流量治理（与其它出网通道同一套闸门）----
    # 关键：这一步必须在真正发出请求**之前**。Burp 拿到请求就会立刻出网，
    # 所以治理不能放在「调用之后再补记」——那样限速与预算形同虚设。
    try:
        await traffic.governor.acquire(
            probe_url,
            tool_alias="burp_replay",
            method=parsed["method"],
            project_id=project_id,
            session_id=session_id,
            cancel_event=cancel_event,
        )
    except traffic.TrafficScopeDenied as e:
        yield {"type": "error", "data": f"流量调度器拒绝出网（授权）：{e}"}
        yield {"type": "exit", "code": 126}
        return
    except Exception as e:      # noqa: BLE001 - 含 TrafficPaused / 预算耗尽 / 取消
        yield {"type": "error", "data": f"流量调度器拒绝出网：{type(e).__name__}: {e}"}
        yield {"type": "exit", "code": 1}
        return

    # ---- 4) 经 MCP 调用 Burp ----
    client = mcp_client.get_client()
    try:
        payload = build_replay_payload(
            {"raw": parsed["raw"], "host": host, "port": port, "https": uses_https})
        ok, text = await client.call_tool("send_http1_request", payload)
    except mcp_client.McpUnavailable as e:
        yield {"type": "error", "data": f"Burp MCP 不可用：{e}"}
        yield {"type": "exit", "code": 1}
        return
    except mcp_client.McpError as e:
        yield {"type": "error", "data": f"Burp MCP 调用失败：{e}"}
        yield {"type": "exit", "code": 1}
        return

    if not ok:
        # 官方扩展在用户点 Deny 时返回 "Send HTTP request denied by Burp Suite"，
        # 这不是错误而是**用户行使了否决权**，措辞要与之匹配，避免模型以为要重试。
        if "denied by Burp Suite" in text:
            yield {"type": "error",
                   "data": "用户在 Burp 侧拒绝了本次请求（Deny）。"
                           "这是人工闸门的正常结果，不要重复尝试同一请求。"}
        else:
            yield {"type": "error", "data": f"Burp 返回错误：{text[:2000]}"}
        yield {"type": "exit", "code": 1}
        return

    yield {"type": "command",
           "data": f"[Burp] {parsed['method']} {probe_url} (经 Burp 发出，已计入流量预算)"}
    yield {"type": "output", "data": text + _persist_response(text)}
    yield {"type": "exit", "code": 0}


# ---------- 只读：读取 Burp Proxy history ----------
def parse_history_args(args: str) -> tuple[dict, str]:
    """解析 burp_history 的参数。返回 (调用参数, 错误说明)。

    只支持三个键（regex / count / offset），故意不做成通用旗标解析：
    模型在这里容易过度发挥（塞进 sort、filter、header 之类不存在的参数），
    解析失败时明确报错比静默忽略更能收敛行为。
    """
    params: dict = {}
    text = (args or "").strip()
    if not text:
        return {"count": config.MCP_HISTORY_PAGE, "offset": 0}, ""
    for token in text.split():
        if "=" not in token:
            return {}, (f"args 里出现无法识别的片段 {token!r}。"
                        "只支持 `regex=<正则>`、`count=<条数>`、`offset=<起始>` 三种写法，"
                        "多个用空格分隔；读最近记录可直接留空。")
        key, _, val = token.partition("=")
        key = key.strip().lower()
        if key == "regex":
            params["regex"] = val
        elif key == "count":
            if not val.isdigit():
                return {}, f"count 必须是数字，收到 {val!r}"
            params["count"] = max(1, min(int(val), config.MCP_HISTORY_MAX))
        elif key == "offset":
            if not val.isdigit():
                return {}, f"offset 必须是数字，收到 {val!r}"
            params["offset"] = int(val)
        else:
            return {}, (f"不支持的参数 {key!r}。"
                        "只支持 regex / count / offset。")
    params.setdefault("count", config.MCP_HISTORY_PAGE)
    params.setdefault("offset", 0)
    return params, ""


async def run_burp_history(args: str, *, project_id: str = "", session_id: str = ""):
    """读取 Burp Proxy history（或 WebSocket 历史）。**纯本地读取，不出网。**

    因此这条路径**不调用 TrafficGovernor**——它不向目标发任何请求，占用流量预算
    反而是错的（会让「读自己的抓包记录」挤占真正的测试额度）。
    但数据访问本身由 Burp 侧一次性授权闸门控制（requireDataAccessApproval），
    这不是我们能绕过的，也不应该绕过。

    ⚠️ 读到的是**用户在 Burp 里手工抓的包**。经 `burp_replay` 发出的请求
    **不会**出现在这里（实测确认，见模块 docstring 的说明）。
    因此别指望「发一个请求再回读历史」这种闭环——`burp_replay` 的响应
    已经在它自己的返回值里了。

    配合 `burp_replay` 的正确用法：让操作者在 Burp 里手工浏览目标 →
    Agent 用本工具读取那些流量做分析 → 挑出值得验证的请求 → 用 `burp_replay`
    改包重放。即「人抓包 + Agent 分析重放」的协作模式，而非纯自动化闭环。
    """
    params, err = parse_history_args(args)
    if err:
        yield {"type": "error", "data": err}
        yield {"type": "exit", "code": 1}
        return

    tool_name = history_tool_name(params)
    client = mcp_client.get_client()
    try:
        ok, text = await client.call_tool(tool_name, params)
    except mcp_client.McpUnavailable as e:
        yield {"type": "error",
               "data": f"Burp MCP 不可用：{e}"}
        yield {"type": "exit", "code": 1}
        return
    except mcp_client.McpError as e:
        yield {"type": "error", "data": f"读取 Burp 历史失败：{e}"}
        yield {"type": "exit", "code": 1}
        return

    if not ok:
        yield {"type": "error", "data": f"Burp 返回错误：{text[:2000]}"}
        yield {"type": "exit", "code": 1}
        return

    # 官方扩展在越界时返回这个固定串。这是**正常分页边界**而非错误，
    # 直接回传会让模型以为「读取失败」并重试；转成明确语义。
    # 注意：历史为空时也会走这里（offset=0 就没有条目），所以措辞要覆盖两种情况，
    # 否则模型会以为「offset 没调对」而反复重试——真机实测空历史正是返回这一串。
    if text.strip() == "Reached end of items":
        yield {"type": "output",
               "data": ("Burp 历史里没有更多条目（可能是 offset 超出范围，"
                        "也可能是该区历史本来就是空的——例如从没在 Burp 里抓过包）。"
                        "注意：经 burp_replay 发出的请求不会落进 Proxy history。"
                        "若确实预期有数据，请把 offset 调小重读。")}
        yield {"type": "exit", "code": 0}
        return

    yield {"type": "command", "data": f"[Burp] 读取历史：{tool_name} {params}"}
    yield {"type": "output", "data": text + _persist_response(text)}
    yield {"type": "exit", "code": 0}
