# -*- coding: utf-8 -*-
"""MCP 客户端层（v044）：让 Agent 能通过 Model Context Protocol 调用外部工具服务。

首个（也是当前唯一）对接的服务是 **Burp Suite 官方 MCP Server 扩展**
（PortSwigger/mcp-server，v1.3.0，Kotlin 实现）。它在 Burp 进程内起一个
SSE 服务，默认监听 ``http://127.0.0.1:9876``，MCP 路由为 ``/mcp``：

    GET  /mcp              -> SSE 长连接（服务端推送；首个 event 是 ``endpoint``，
                              给出后续 POST 的相对地址，通常带 sessionId 查询参数）
    POST /mcp?sessionId=x  -> 客户端发送 JSON-RPC 请求

为什么不直接用第三方 MCP SDK：
  1. 本项目所有出网能力都必须过 TrafficGovernor（app/traffic.py）。用 SDK 会把
     传输层包在库里，无法在「真正发出请求」那一刻插入治理与审计。
  2. 本机是隔离环境，每加一个依赖就多一份供应链面；MCP 的 JSON-RPC 部分本身
     很小（initialize / tools/list / tools/call 三个方法），手写比调试 SDK 便宜。
  3. 客户端必须能「优雅降级」——Burp 没开 MCP、端口没监听、扩展没 Start，
     这些是常态而不是异常。自研可以把降级语义写死成「工具不可用」，而不是抛栈。

安全边界（与项目既有纪律一致）：
  - 本模块**只负责传输**，不做任何 scope/风险判断。所有经 MCP 出网的动作
    必须在调用方（app/burp_tools.py）过 TrafficGovernor 与 scope 双重闸门。
  - 连接默认限回环地址（``MCP_ALLOW_REMOTE=0``）。MCP 服务是「本机工具服务」，
    没有理由监听在别的机器上；允许远程等于把 Agent 的出网能力交给第三方。
  - 不跟随环境代理（``trust_env=False``）：Burp 自身就是代理，若 MCP 的连接
    走了本机代理，会出现「代理连代理」甚至成环。与 app/replayer.py 中 httpx
    必须 ``trust_env=False`` 是同一条教训。
  - 不发送浏览器 UA：官方扩展有反 DNS-rebinding 检查，带 Mozilla/Chrome 之类
    关键字的 UA 会被它直接 403（见 KtorServerManager.isBrowserRequest）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import config

logger = logging.getLogger("src_agent.mcp")

# 客户端标识：不带任何浏览器关键字（否则被官方扩展的反 rebinding 检查拦掉）
_CLIENT_UA = "src-agent-mcp/1.0"
_PROTOCOL_VERSION = "2024-11-05"     # 官方扩展基于此版本的 Kotlin SDK


def _local_version() -> str:
    """读取本机 VERSION.txt（app/config.py 未暴露版本常量，这里直读）。"""
    try:
        return (config.APP_DIR / "VERSION.txt").read_text(encoding="utf-8").strip() or "0"
    except Exception:       # noqa: BLE001 - 版本号读不到不影响握手
        return "0"


class McpError(Exception):
    """MCP 层错误基类。"""


class McpUnavailable(McpError):
    """MCP 服务不可用（没启动 / 端口没监听 / 连不上）。

    这是**预期状态**而非故障：Burp 没开、扩展没加载、没点 Start 都会走到这里。
    调用方应当把它转成「工具不可用」的提示，而不是让任务失败。
    """


class McpToolError(McpError):
    """MCP 服务返回了错误（工具不存在 / 参数不合法 / 服务端内部异常）。"""


class _SSEReader:
    """常驻 SSE 读流器：**同时充当 MCP 会话的持有者**。

    为什么必须常驻一条流（而不是「一次调用开一次流」）：
      · MCP 的 SSE 传输里，POST 只负责投递（回 202 + 空体），**响应经这条长连接
        回推**。不常驻读流就永远拿不到结果。
      · sessionId 与「那条流」绑定。如果探测时开一条、调用时再开一条，服务端
        会把它们当成两个会话，第二条流拿到的 endpoint 有新的 sessionId，而先前
        投递的请求可能落在已关闭的会话上。
    因此**路径探测、endpoint 解析、消息投递全部集中在这里**，一条流贯穿会话，
    断开时自动重连（重连会拿到新的 sessionId，_post_url 随之更新）。

    异常策略：读流在独立任务里跑，异常**不抛出**——只记到 ``self.error``，
    由 ``_await_response`` 的等待超时兜底报错。否则后台任务的异常会无声消失。
    """

    def __init__(self, owner: "McpClient"):
        self.owner = owner
        self.queue: asyncio.Queue = asyncio.Queue()
        self.error: str = ""
        self.opened: asyncio.Event = asyncio.Event()   # 首次拿到 endpoint 即置位
        self._task: asyncio.Task | None = None
        self._stopping = False

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="mcp-sse-reader")

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):   # noqa: BLE001
                pass
            self._task = None

    async def wait_opened(self, timeout: float) -> bool:
        """等首次会话建立。返回 False 表示超时（调用方据此报「不可用」）。"""
        try:
            await asyncio.wait_for(self.opened.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def _run(self) -> None:
        client = await self.owner._http()
        while not self._stopping:
            try:
                # 路径探测结果由 owner 给出：显式配置带路径时只试那一个，
                # 否则按候选优先级逐个试（官方扩展 v1.3.0 实测在 "/"）。
                for path in self.owner._sse_candidates():
                    if self._stopping:
                        return
                    url = f"{self.owner.base_url}{path}"
                    try:
                        async with client.stream(
                                "GET", url,
                                headers={"Accept": "text/event-stream"},
                                timeout=httpx.Timeout(None, connect=5.0),
                        ) as resp:
                            if resp.status_code != 200:
                                self.error = f"{path} → HTTP {resp.status_code}"
                                continue
                            ctype = resp.headers.get("content-type", "")
                            if "text/event-stream" not in ctype:
                                # 200 但不是 SSE：多半是扩展未 Start 时的静态页
                                self.error = (f"{path} → 200 但 "
                                              f"content-type={ctype!r}，非 SSE")
                                continue
                            # 这条就是本会话的流：读它直到断开或停止
                            await self._consume(path, resp)
                            if self._stopping:
                                return
                            # 流断了（服务端重启/网络抖动）→ 走重连
                            self.error = self.error or f"{path} → SSE 流已结束"
                    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                        self.error = (f"连不上 MCP 服务 {url}（{type(e).__name__}）。"
                                      "请确认 Burp Suite 已启动、MCP Server 扩展"
                                      "已加载，并在 MCP 标签页点了 Start。")
                        await asyncio.sleep(2.0)
                        break       # 服务没起来，换路径也没用，直接进外层次重试
                    except asyncio.CancelledError:
                        raise
                    except httpx.HTTPError as e:
                        self.error = f"{path} → {type(e).__name__}: {e}"
            except asyncio.CancelledError:
                raise
            except Exception as e:      # noqa: BLE001
                self.error = f"{type(e).__name__}: {e}"
            if not self._stopping:
                logger.debug("MCP SSE 读流中断，2s 后重连", exc_info=True)
                await asyncio.sleep(2.0)

    async def _consume(self, path: str, resp: httpx.Response) -> None:
        """读一条已建立的 SSE 流，直到它结束。"""
        event_name = ""
        async for line in resp.aiter_lines():
            line = line.rstrip("\r")
            if line == "":
                event_name = ""
                continue
            if line.startswith(":"):
                continue        # SSE 注释/心跳
            if line.startswith("event:"):
                event_name = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                data = line.split(":", 1)[1].strip()
                if event_name == "endpoint":
                    # 会话建立/重建：确定 SSE 路径并更新 POST 地址
                    self.owner._sse_path = path
                    self.owner._post_url = self.owner._absolutize(data)
                    self.owner._session_id = (urlsplit(self.owner._post_url).query
                                              or "").split("sessionId=")[-1]
                    self.opened.set()
                    logger.info("MCP SSE 会话建立于 %s", path)
                elif event_name == "message":
                    try:
                        await self.queue.put(json.loads(data))
                    except Exception:      # noqa: BLE001
                        logger.debug("SSE message 非 JSON，已跳过")
                # 事件块结束：SSE 规范里 data 后可跟多个字段，
                # 但对 MCP 而言一条 event 只有一个 data，收到即复位
                event_name = ""


class McpClient:
    """极简 MCP 客户端：initialize 握手 + tools/list 发现 + tools/call 调用。

    一个实例对应一个 MCP 服务端点。生命周期：
        client = McpClient()
        ok, note = await client.probe()      # 探测可用性（不抛异常）
        tools     = await client.list_tools()
        result    = await client.call_tool("send_http1_request", {...})
    """

    def __init__(self, name: str = "burp", base_url: str = "", timeout: float = 0.0):
        self.name = name
        self.base_url = (base_url or config.MCP_BURP_URL).rstrip("/")
        self.timeout = float(timeout or config.MCP_CALL_TIMEOUT)
        self._client: httpx.AsyncClient | None = None
        self._session_id: str = ""
        self._post_url: str = ""
        self._tools: list[dict] = []
        self._tool_names: set[str] = set()
        self._initialized = False
        self._last_error: str = ""
        # SSE 路径在运行时由探测确定（官方扩展实测在 "/"，规范示例在 "/mcp"）
        self._sse_path: str = ""
        # SSE 建连阶段单次读取的等待上限。必须**远小于** MCP_CALL_TIMEOUT：
        # 该值默认 120s 是留给「等用户在 Burp 弹窗点 Allow」的，若拿它去等
        # endpoint 事件，服务没起来时每个候选路径都要干等两分钟。
        self._sse_probe_timeout: float = 8.0
        # 常驻读流器（兼会话持有者）。懒创建：只有真正要用 MCP 时才起。
        self._reader: _SSEReader | None = None
        # reader / http client 绑定的那个事件循环。asyncio 的对象**不能跨循环使用**：
        # 若在循环 A 里建了连接，却在循环 B 里 await 它，会得到
        # "Event loop is closed" 或 "attached to a different loop"。
        # 生产环境里这出现在 worker 重启；测试里出现在每次 asyncio.run()。
        # 一律靠「发现循环变了就整体重连」来兜住，而不是要求调用方小心。
        self._bound_loop: Any = None
        # 「同步返回 JSON」的实现直接把响应放在 POST 体里；有的话优先用它，
        # 免得再去 SSE 流里等一条永远不来的响应。
        self._sync_result: dict | None = None
        self._rpc_id: int = 0

    def _loop_changed(self) -> bool:
        """当前事件循环是否与已建立连接时的不一致。"""
        try:
            cur = asyncio.get_running_loop()
        except RuntimeError:
            return False
        return self._bound_loop is not None and self._bound_loop is not cur

    # ---------- 生命周期 ----------
    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            # trust_env=False 见模块 docstring：绝不能让 MCP 连接走环境代理
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=min(5.0, self.timeout)),
                trust_env=False,
                headers={"User-Agent": _CLIENT_UA},
            )
            self._bound_loop = asyncio.get_running_loop()
        return self._client

    async def _reset_session(self) -> None:
        """丢弃会话状态并重建连接（用于事件循环变更后的恢复）。

        为什么不能只清状态：httpx.AsyncClient 与 reader 的 asyncio 任务都绑在
        旧循环上，留着它们会在下一个循环里抛 "Event loop is closed"。
        """
        if self._reader is not None:
            await self._reader.stop()
            self._reader = None
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:      # noqa: BLE001
                pass
            self._client = None
        self._initialized = False
        self._session_id = ""
        self._post_url = ""
        self._sse_path = ""
        self._sync_result = None
        self._tools = []
        self._tool_names = set()

    async def aclose(self) -> None:
        # 先停读流再关 http 客户端：reader 内部持有 stream，顺序反了会报
        # 「client has been closed」这类噪音异常。
        if self._reader is not None:
            await self._reader.stop()
            self._reader = None
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:      # noqa: BLE001 - 关闭失败不影响任何语义
                pass
            self._client = None
        self._initialized = False
        self._session_id = ""
        self._post_url = ""
        self._sync_result = None
        self._bound_loop = None

    # ---------- 探测 ----------
    def _guard_loopback(self) -> str:
        """回环地址守卫。返回空串表示通过，否则返回拒绝原因。"""
        if config.MCP_ALLOW_REMOTE:
            return ""
        host = self.base_url.split("//", 1)[-1].split("/")[0].split(":")[0]
        if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
            return (f"MCP 端点 {self.base_url} 不是回环地址。"
                    "MCP 服务是本机工具服务，禁止连远程端点；"
                    "确需如此请显式设置 MCP_ALLOW_REMOTE=1。")
        return ""

    def _tcp_reachable(self, timeout: float = 0.6) -> bool:
        """MCP 端点端口是否有人监听（便宜的前置检查）。

        为什么需要（2026-09-23 实测）：Burp 没开时，`probe()` 会走
        `_SSEReader.wait_opened(_sse_probe_timeout=8.0)` —— **白等满 8 秒**才
        返回不可用。而这个 8 秒会传导到 `/api/health`：健康检查变成 8 秒，
        前端每次打开页面都要等，回归 harness 的 2 秒探测直接超时、误判成
        「端口被别的程序占用」并**静默跳过两个端到端套件**。

        一个 TCP connect 探活只要零点几毫秒，能把「Burp 没开」这个**最常见**
        的情形从 8 秒压到 0 毫秒。解析不出主机/端口时返回 True，
        把判断交回原有流程（宁可慢，不可误判为不可用）。
        """
        try:
            u = urlsplit(self.base_url)
            host = u.hostname or "127.0.0.1"
            port = u.port or (443 if u.scheme == "https" else 80)
        except Exception:                            # noqa: BLE001
            return True
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    async def probe(self) -> tuple[bool, str]:
        """探测 MCP 服务可用性。**不抛异常**，返回 (是否可用, 说明)。

        这是给 Agent 每轮工具清单用的：Burp 没开时应当静默把工具摘掉，
        而不是让整个任务因为「工具连接失败」而中断。
        """
        denied = self._guard_loopback()
        if denied:
            self._last_error = denied
            return False, denied
        # 端口没人监听 → 立刻返回（最常见的「Burp 没开」路径，见 _tcp_reachable）。
        # 放在 loopback 守卫之后：远程端点的拒绝理由比「端口不通」更该报给用户。
        if not self._tcp_reachable():
            note = (f"连不上 MCP 服务 {self.base_url}（端口未监听）。"
                    "请确认 Burp Suite 已启动、官方扩展已加载，"
                    "并在扩展的 MCP 页点过 Start。")
            self._last_error = note
            return False, note
        try:
            if self._loop_changed():
                await self._reset_session()
            await self._ensure_initialized()
            return True, f"MCP 服务可用（{self.name}），发现 {len(self._tools)} 个工具"
        except McpUnavailable as e:
            self._last_error = str(e)
            return False, str(e)
        except McpError as e:
            self._last_error = str(e)
            return False, f"MCP 握手失败：{e}"

    # ---------- SSE 会话建立 ----------
    async def _ensure_initialized(self) -> None:
        if self._loop_changed():
            # 事件循环换了：旧连接与旧读流都失效，整体重连
            logger.info("MCP 事件循环已变更，重建会话")
            await self._reset_session()
        if self._initialized:
            return
        if self._reader is None:
            self._reader = _SSEReader(self)
            await self._reader.start()
        if not self._post_url:
            await self._wait_session()
        await self._rpc("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "src-agent", "version": _local_version()},
        })
        # 握手完成后按规范发 initialized 通知（无需等响应）
        await self._notify("notifications/initialized", {})
        self._initialized = True
        await self.list_tools()

    async def _wait_session(self) -> None:
        """等 reader 建立好 SSE 会话（拿到 endpoint 事件）。

        超时/失败一律转成 ``McpUnavailable``：Burp 没开、扩展没 Start 是本工具的
        **常态**，调用方需要的是「不可用 + 人话原因」，而不是一个栈回溯。
        """
        assert self._reader is not None
        ok = await self._reader.wait_opened(self._sse_probe_timeout)
        if ok:
            return
        raise McpUnavailable(self._probe_failure_note())

    def _probe_failure_note(self) -> str:
        """把 reader 的失败态翻译成一句可执行的提示。"""
        err = (self._reader.error if self._reader else "") or "未知原因"
        if "连不上" in err:
            return err
        tried = ", ".join(self._sse_candidates())
        return (f"MCP 端点 {self.base_url} 上找不到可用的 SSE 路径（试过 {tried}）。"
                f"最后错误：{err}。"
                "若扩展已点 Start，可用 AGENT_MCP_BURP_URL 指定带路径的地址。")

    def _sse_candidates(self) -> list[str]:
        """SSE 路径候选。显式配置带路径时只试那一个；否则按优先级探测。

        为什么默认第一个是 ``/``：官方扩展 v1.3.0 实测端点就在根路径
        （Kotlin SDK 的 ``Server.mcp(path=...)`` 默认 path="/"），而 MCP 规范
        文档与部分实现用 ``/mcp``。任何一个写死都会在另一种实现上 404。
        """
        parts = urlsplit(self.base_url)
        if parts.path and parts.path not in ("", "/"):
            return [parts.path]     # 用户显式给了路径，尊重它
        return ["/", "/mcp", "/sse"]

    def _absolutize(self, url_or_path: str) -> str:
        """把 SSE 下发的 endpoint 转成可直接 POST 的绝对地址。

        实测官方扩展（v1.3.0，Burp Pro 2025.12）下发的 data 形态是**裸查询串**：
            data: ?sessionId=c5728a2f-...
        既没有路径也没有主机——即「就用你刚才 GET 的那个路径」。SDK 的
        `mcp(path=...)` 默认 path="/"，所以真实端点是 `GET /`（**不是 /mcp**），
        POST 要打回同一个 `/?sessionId=...`。

        三种形态都要兼容（不同版本/不同 SDK 默认路径会变）：
            "?sessionId=x"           → 相对「当前 SSE 路径」
            "/mcp?sessionId=x"       → 相对 base_url 的绝对路径
            "http://host/mcp?s=x"    → 已是绝对地址
        """
        s = (url_or_path or "").strip()
        if s.startswith("http://") or s.startswith("https://"):
            return s
        if s.startswith("?"):
            return f"{self.base_url}{self._sse_path}{s}"
        if not s.startswith("/"):
            s = "/" + s
        return self.base_url + s

    # ---------- JSON-RPC ----------
    async def _post(self, payload: dict) -> None:
        """把 JSON-RPC 报文 POST 到会话地址。

        **重要：这里不返回响应体。** MCP 的 SSE 传输语义是「POST 只负责投递」：
        服务端回 ``202 Accepted``（空体），真正的 JSON-RPC 响应经**长连接的 SSE 流**
        以 ``event: message`` 回推。实测官方扩展正是如此：
            POST /?sessionId=x  → 202 'Accepted'
            SSE  → event: message / data: {"id":1,"result":{...},"jsonrpc":"2.0"}
        早先的实现把 POST 的响应体当结果解析，会拿到字符串 'Accepted' 并在
        json.loads 处报错——这不是服务端异常，而是我对传输语义理解错了。
        """
        client = await self._http()
        try:
            resp = await client.post(
                self._post_url, json=payload,
                headers={"Accept": "application/json, text/event-stream",
                         "Content-Type": "application/json"},
            )
        except httpx.HTTPError as e:
            raise McpUnavailable(f"MCP 请求发送失败：{type(e).__name__}: {e}") from e
        if resp.status_code >= 400:
            raise McpToolError(
                f"MCP 返回 HTTP {resp.status_code}：{resp.text[:400]}")
        # 兼容「同步返回 JSON」的实现（部分 MCP 服务直接回 200 + JSON 体）。
        # 有 JSON 体就记下来当响应，没有就等 SSE 推。
        body = (resp.text or "").strip()
        if body.startswith("{"):
            try:
                self._sync_result = json.loads(body)
            except Exception:       # noqa: BLE001
                self._sync_result = None

    async def _rpc(self, method: str, params: dict) -> Any:
        """发一次 JSON-RPC 请求并等响应。响应可能来自 POST 体，也可能来自 SSE 流。"""
        self._rpc_id += 1
        rid = self._rpc_id
        self._sync_result = None
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        await self._post(payload)
        data = self._sync_result
        if data is None:
            data = await self._await_response(rid)
        if data.get("error"):
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else err
            raise McpToolError(f"{method} 失败：{msg or err}")
        return data.get("result")

    async def _await_response(self, rid: int) -> dict:
        """从 SSE 事件流里等到 id == rid 的那条响应。

        reader 是常驻的（见 _SSEReader docstring），这里只负责按 id 匹配。
        """
        if self._reader is None:
            raise McpUnavailable("MCP 会话尚未建立（读流器不在运行）")
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise McpUnavailable(
                    f"等 MCP 响应超时（{self.timeout:.0f}s，method id={rid}）。"
                    "若该动作需要在 Burp 弹窗人工批准，请调大 "
                    "AGENT_MCP_CALL_TIMEOUT 或配置 auto-approve targets。")
            try:
                msg = await asyncio.wait_for(self._reader.queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("id") == rid:
                return msg
            # 不是我们要的（可能是通知或其它响应），丢掉继续等

    def _sse_url(self) -> str:
        return f"{self.base_url}{self._sse_path or '/'}"

    async def _notify(self, method: str, params: dict) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        try:
            await self._post(payload)
        except McpError as e:
            # 通知失败不致命，但要留痕
            logger.warning("MCP 通知 %s 失败：%s", method, e)

    # ---------- 工具发现与调用 ----------
    async def list_tools(self) -> list[dict]:
        result = await self._rpc("tools/list", {})
        tools = (result or {}).get("tools") or []
        self._tools = tools
        self._tool_names = {t.get("name", "") for t in tools}
        return tools

    def tool_names(self) -> set[str]:
        return set(self._tool_names)

    def get_tool(self, tool_name: str) -> dict | None:
        for t in self._tools:
            if t.get("name") == tool_name:
                return t
        return None

    async def call_tool(self, tool_name: str, arguments: dict) -> tuple[bool, str]:
        """调用一个 MCP 工具。返回 (是否成功, 文本结果)。

        MCP 的 ``tools/call`` 结果结构是 ``{"content": [{"type":"text","text":...}], "isError": bool}``。
        这里把多个 content 块拼成一段纯文本——与项目里其它工具「回传一段文本」
        的约定保持一致，避免给模型引入第二种结果形态。
        """
        if not self._initialized or self._loop_changed():
            await self._ensure_initialized()
        payload = {"name": tool_name, "arguments": arguments or {}}
        result = await self._rpc("tools/call", payload)
        result = result or {}
        parts: list[str] = []
        for block in result.get("content") or []:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                else:
                    parts.append(json.dumps(block, ensure_ascii=False))
            else:
                parts.append(str(block))
        text = "\n".join(p for p in parts if p)
        is_error = bool(result.get("isError"))
        if is_error and not text:
            text = f"MCP 工具 {tool_name} 执行失败（服务端未给出详情）"
        return (not is_error), text


# ---------- 单例与状态回显 ----------
_client: McpClient | None = None


def get_client() -> McpClient:
    """取得 MCP 客户端单例。"""
    global _client
    if _client is None:
        _client = McpClient()
    return _client


async def availability() -> tuple[bool, str, list[str]]:
    """探测可用性并回传 (是否可用, 说明, 工具名列表)。供健康检查与面板使用。"""
    if not config.MCP_ENABLED:
        return False, "MCP 已通过 AGENT_MCP_ENABLED=0 关闭", []
    client = get_client()
    ok, note = await client.probe()
    return ok, note, sorted(client.tool_names()) if ok else []


# ---------- 代理配置体检（v044） ----------
# 为什么需要这个：Burp 自己就是代理（本机 8080），而 Burp 又支持配「上游代理」。
# 配错会静默出问题，且症状（请求超时/连接拒绝）看起来很像「目标挂了」：
#   ① Burp 的上游代理填了自己的监听地址（127.0.0.1:8080）→ 套娃成环，
#      请求在 Burp 内部无限循环，最终超时。
#   ② Burp 的上游代理填了 WorkBuddy 的会话代理 → Burp 又把包转回宿主，链路混乱。
# 注意 WorkBuddy 的代理端口**每次会话都不同**（实测见过 62063、58637），
# 所以不能硬编码黑名单去比，只能「发现可疑就提示人来判断」。
async def check_proxy_sanity() -> list[str]:
    """检查 Burp 侧的代理配置是否有成环/回流风险。返回告警文本列表（空=没问题）。

    只读：调用官方扩展的 output_user_options 拿配置快照，不做任何修改。
    配置编辑在 Burp 侧默认关闭（configEditingTooling=false），这里也不试图打开。
    """
    warns: list[str] = []
    if not config.MCP_ENABLED:
        return warns
    client = get_client()
    try:
        ok, text = await client.call_tool("output_user_options", {})
    except McpError:
        return warns
    if not ok or not text.strip():
        return warns
    try:
        cfg = json.loads(text)
    except Exception:       # noqa: BLE001 - 拿不到结构化配置就不做判断
        return warns

    # 在 Burp 的 user_options JSON 里找上游代理相关字段。结构随版本会变，
    # 因此走「宽松遍历」而不是写死路径——写死路径在版本升级后会静默失效。
    # 关键：Burp 把上游代理存成 **proxy_host / proxy_port 两个独立字段**
    #   （实测结构：{"proxy":{"upstream":[{"destination_host":"",
    #    "proxy_host":"127.0.0.1","proxy_port":8080}]}}），
    # 所以不能拿 "127.0.0.1:8080" 整串去匹配——那样永远匹配不到。
    def _walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from _walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from _walk(v, f"{path}[{i}]")
        else:
            yield path, node

    # 先按「父路径 → 字段」聚合，才能把 host/port 配成对
    buckets: dict[str, dict] = {}
    for path, val in _walk(cfg):
        key = path.lower()
        if "proxy" not in key:
            continue
        parent, _, leaf = path.rpartition(".")
        buckets.setdefault(parent, {})[leaf.lower()] = val

    _LOOP_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
    for parent, fields in buckets.items():
        host = str(fields.get("proxy_host", "")).strip()
        port = fields.get("proxy_port")
        if not host or port in (None, "", 0):
            continue
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        if host.lower() in _LOOP_HOSTS and port_i in (8080, 8443):
            warns.append(
                f"Burp 上游代理疑似指向 Burp 自身（{parent} → {host}:{port_i}）"
                "→ **会套娃成环**，请求将在 Burp 内部死循环直至超时。"
                "请到 Burp → Settings → Network → Connections → Upstream Proxy Servers "
                "删除或修正这条规则。")
    return warns
