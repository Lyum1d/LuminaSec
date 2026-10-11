# -*- coding: utf-8 -*-
"""内置工具层：不依赖工具箱子进程的 Agent 原生能力。

1. run_replay   —— HTTP 重放器：对授权目标发起受控 HTTP 请求并回传完整响应。
                  默认只读（GET/HEAD/OPTIONS），写入方法硬禁用；域名白名单
                  （data/scope.json）强制生效；全局限速。
2. run_nuclei   —— 官方 nuclei CLI 的托管运行器（若已安装到 data/bin/nuclei.exe）。

设计原则：这是 Agent 目前唯一能「对单个 URL 精确发请求」的工具，
是把挖洞能力从信息收集推进到漏洞验证的关键。
"""
from __future__ import annotations

import asyncio
import json
import re
import shlex
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import httpx

from . import config, ratelimit, scope, traffic

_UA = "SRC-Agent-Replay/1.0 (authorized bug-bounty test)"
_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}


# ---------- 域名白名单 ----------
# 实现统一在 app/scope.py，与命令行执行器（app/executor.py）、py_exec 共用同一份判断。
# 行为变化：此前本模块在 scope.json 缺失时会静默写入 example.com 兜底并据此放行，
# 现在改为 fail-closed——缺配置即视为「没有授权目标」，直接拒绝，
# 避免使用者误以为「已经配好授权」。
#
# 下面两个别名只是为了保留历史入口名（test_replayer.py 按老名字做「两份实现不能漂移」
# 的一致性断言）。它们**直接指向 scope.py 的函数对象**，因此不是第二份实现，
# 而是同一份实现的另一个名字——任何人都无法只改其中一处造成判定分叉。
_host_allowed = scope.host_in_scope
_load_scope = scope.load_scope

# ---------- 出网许可（v023.1：统一走 TrafficGovernor） ----------
async def _rate_limit(url: str = "", method: str = "GET",
                      project_id: str = "", session_id: str = "") -> dict:
    """取得一次出网许可。调度器内已含 scope 兜底、滑动窗口预算、
    目标/根域名并发限制、暂停状态检查与流量事件落库。"""
    return await traffic.governor.acquire(url, tool_alias="httpreplay", method=method,
                                          project_id=project_id, session_id=session_id)


# ---------- 参数解析 ----------
def _parse_args(args: str) -> tuple[str, list[tuple[str, str]], dict[str, str], int, str | None]:
    """解析 curl 风格参数。返回 (method, extra_query, headers, timeout, error)。"""
    method, headers, query = "GET", [], []
    timeout = 12
    try:
        tokens = shlex.split(args or "")
    except ValueError:
        return method, query, {}, timeout, "args 引号不匹配，无法解析"
    i = 0
    while i < len(tokens):
        t = tokens[i]
        # 方法旗标：必须大小写不敏感，且要覆盖 --request / --method / -X=POST 等写法。
        # 此前只匹配 "^-X[ A-Z]"（仅空格与大写），于是 `-Xpost`、`--request POST`、
        # `-X=POST` 全都解析不出来 → method 静默保持默认的 GET。因为 GET 本身是允许的，
        # 不会报任何错，模型以为在测 POST 型接口、实际发的是 GET，直接造成假阴性漏报。
        if t in ("-X", "--method", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
        elif t in ("-X", "--method", "--request"):
            return method, query, {}, timeout, f"{t} 缺少方法名"
        elif t.startswith("-X") and len(t) > 2 and not t.startswith("-X="):
            method = t[2:].upper()
            i += 1
        elif t.startswith(("-X=", "--method=", "--request=")):
            method = t.split("=", 1)[1].upper()
            i += 1
        elif t in ("-H", "--header") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if ":" in raw:
                k, v = raw.split(":", 1)
                headers.append((k.strip(), v.strip()))
            i += 2
        elif t in ("-d", "--data", "--param") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if "=" in raw:
                k, v = raw.split("=", 1)
                query.append((k.strip(), v.strip()))
            i += 2
        elif t == "--timeout" and i + 1 < len(tokens):
            try:
                timeout = min(max(int(re.sub(r"[^0-9]", "", tokens[i + 1]) or 12), 2), 20)
            except Exception:
                pass
            i += 2
        elif t.startswith("-"):
            # 未知旗标：跳过但不报错（模型偶尔臆造）
            i += 2 if (i + 1 < len(tokens) and not tokens[i + 1].startswith("-")) else 1
        else:
            i += 1
    return method, query, dict(headers), timeout, None


# ---------- 主入口 ----------
async def run_replay(url: str, args: str = "", cancel_event=None,
                     project_id: str = "", session_id: str = "") -> AsyncIterator[dict]:
    """HTTP 重放器事件流。事件格式与 executor.run 一致。

    v023.6：project_id/session_id 透传到流量事件——缺了它们，项目维度的
    流量审计查不到数据（某企业站 实战暴露：事件全落在空项目桶）。
    """
    url = (url or "").strip().strip("'\"")
    # v012 后半：取消硬终止——发请求前检查，置位即放弃本次请求
    if cancel_event is not None and cancel_event.is_set():
        yield {"type": "cancelled", "data": "已收到取消请求，已跳过本次请求"}
        yield {"type": "exit", "code": 0}
        return
    yield {"type": "tool", "data": "HTTP 重放器"}

    # 1. URL 合法性
    if not re.match(r"^https?://", url):
        yield {"type": "error", "data": "target 必须是完整 URL（带 http:// 或 https://）"}
        yield {"type": "exit", "code": 1}
        return

    parsed = urlparse(url)
    denied = scope.check_scope(url)
    if denied:
        yield {"type": "error",
               "data": denied + " 重放器仅允许请求已获书面授权且在 data/scope.json 内的目标。"}
        yield {"type": "exit", "code": 1}
        return

    method, extra_query, headers, timeout, err = _parse_args(args)
    if err:
        yield {"type": "error", "data": err}
        yield {"type": "exit", "code": 1}
        return
    if method not in _ALLOWED_METHODS:
        yield {"type": "error",
               "data": f"方法 {method} 已禁用：重放器只允许只读方法 {'/'.join(sorted(_ALLOWED_METHODS))}。"
                       f"写入类请求必须人工确认后在控制台外执行。"}
        yield {"type": "exit", "code": 1}
        return

    # 2. 追加查询参数
    if extra_query:
        q = parse_qsl(parsed.query, keep_blank_values=True) + extra_query
        url = urlunparse(parsed._replace(query=urlencode(q)))

    req_headers = {"User-Agent": _UA, **headers}
    shown = f"{method} {url}"
    if headers:
        shown += " | " + " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
    yield {"type": "command", "data": shown}

    # 3. 发请求（出网许可 + 信任环境关闭，防系统代理劫持）
    try:
        permit = await _rate_limit(url, method, project_id, session_id)
    except traffic.TrafficError as e:
        yield {"type": "error", "data": str(e)}
        yield {"type": "exit", "code": 1}
        return
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                     timeout=float(timeout)) as client:
            r = await client.request(method, url, headers=req_headers)
    except Exception as e:
        await traffic.governor.release(permit, error_type=type(e).__name__,
                                       os_error_code=getattr(e, "errno", 0) or 0)
        yield {"type": "error", "data": f"请求失败：{e}"}
        yield {"type": "exit", "code": 1}
        return
    await traffic.governor.release(permit, status_code=r.status_code,
                                  bytes_in=len(r.content))

    # 4. 结构化回传
    # 长度口径（v045）：**必须以实际解码后的正文为准**。
    # 原实现写的是 r.headers.get('content-length', len(r.content)) —— 优先取头里的
    # 声明值，但 gzip 下那只是**压缩后**长度。实测某站点首页：
    #   Content-Length 头 18182  /  解码后 90482 字符  /  105723 字节（差 5 倍）
    # 模型看到一个 18182 会判断「页面很小、没什么内容」，或与 py_exec 报的 90482
    # 对比后误判「响应变了」。同一文件 174 行的审计字段用的是 len(r.content)——
    # 也就是说修之前同一个模块对外报一个数、对内记另一个数。
    # 现在统一报解码后长度，头部值只在**与正文不一致时**作为附注给出并说明原因。
    n_chars, n_bytes = len(r.text), len(r.content)
    hdr_cl = r.headers.get("content-length") or ""
    length_txt = f"{n_chars} chars / {n_bytes} bytes"
    if hdr_cl.isdigit() and int(hdr_cl) != n_bytes:
        enc = r.headers.get("content-encoding", "")
        length_txt += (f"  (Content-Length 头 {hdr_cl}"
                       + (f"，Content-Encoding: {enc}" if enc else "")
                       + "，为传输态长度，不是正文长度)")
    lines = [
        f"HTTP {r.status_code} {r.reason_phrase}",
        f"Content-Type: {r.headers.get('content-type', '-')}  "
        f"Length: {length_txt}  "
        f"Server: {r.headers.get('server', '-')}",
    ]
    interesting = ("location", "www-authenticate", "allow", "access-control-allow-origin",
                   "x-powered-by", "content-security-policy")
    for k in interesting:
        if r.headers.get(k):
            lines.append(f"{k}: {r.headers[k]}")
    set_cookies = [v.split(";")[0] for k, v in r.headers.items() if k.lower() == "set-cookie"]
    if set_cookies:
        lines.append("set-cookie: " + " | ".join(set_cookies[:6]))

    body = r.text
    is_json = "json" in (r.headers.get("content-type") or "").lower()
    if is_json:
        try:
            body = json.dumps(r.json(), ensure_ascii=False, indent=1)
        except Exception:
            pass
    if len(body) > config.REPLAY_MAX_BODY:
        body = body[: config.REPLAY_MAX_BODY] + f"\n…（响应体共 {len(r.text)} 字符，已截断）"
    lines.append("--- response body ---")
    lines.append(body if body.strip() else "（空响应体）")

    for ln in "\n".join(lines).splitlines():
        yield {"type": "output", "data": ln}
    # HTTP 4xx/5xx 是测试结果而非执行失败，退出码仍为 0
    yield {"type": "exit", "code": 0}


# ---------- nuclei 托管运行 ----------
async def run_nuclei(tool, target: str, args: str = "", cancel_event=None,
                     project_id: str = "", session_id: str = ""):
    """运行 data/bin/nuclei.exe（若存在）。与 executor 相同的事件流格式。"""
    exe = tool.executable
    yield {"type": "tool", "data": "Nuclei CLI"}
    if not exe:
        yield {"type": "error", "data": "nuclei 未安装：请将 nuclei.exe 放到 data/bin/ 下"}
        yield {"type": "exit", "code": 1}
        return
    target = (target or "").strip().strip("'\"")
    # ---- 授权白名单（与 run_replay 对齐）：nuclei_cli 是 L2 通道，此前完全没有
    # check_scope，target 填任意未授权主机即可直接跑 PoC 模板（审计 P0-1）----
    denied = scope.check_scope(target)
    if denied:
        yield {"type": "error", "data": denied}
        yield {"type": "exit", "code": 126}
        return
    if not re.match(r"^https?://", target):
        yield {"type": "error", "data": "target 必须是完整 URL（带 http:// 或 https://）"}
        yield {"type": "exit", "code": 1}
        return
    try:
        extra = shlex.split(args or "")
    except ValueError:
        yield {"type": "error", "data": "args 引号不匹配"}
        yield {"type": "exit", "code": 1}
        return

    cmd = [exe, "-u", target, "-silent", "-no-color"] + extra
    yield {"type": "command", "data": " ".join(cmd)}

    # v023.6：nuclei 扫描器启动前取一次出网许可（预算/并发/暂停态），并带上
    # 项目/会话上下文——否则事件归属为空，项目流量审计看不到这次扫描。
    try:
        permit = await traffic.governor.acquire(
            target, tool_alias=tool.alias or "nuclei_cli", method="GET",
            project_id=project_id, session_id=session_id)
        await traffic.governor.release(permit)
    except traffic.TrafficError as e:
        yield {"type": "error", "data": f"出网调度拒绝（不启动 nuclei）：{e}"}
        yield {"type": "exit", "code": 126}
        return

    total = tool.tool_timeout or config.TOOL_TIMEOUT
    deadline = time.time() + total
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as e:
        yield {"type": "error", "data": f"无法启动 nuclei：{e}"}
        yield {"type": "exit", "code": 1}
        return

    buf = ""
    lines = 0
    truncated = False
    while True:
        # v012 后半：取消硬终止（与 executor.run 相同语义）
        if cancel_event is not None and cancel_event.is_set():
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
            yield {"type": "cancelled", "data": "已收到取消请求，nuclei 进程已终止"}
            break
        remaining = deadline - time.time()
        if remaining <= 0:
            proc.kill()
            yield {"type": "error", "data": f"nuclei 超过总时长上限（{total}s），已终止"}
            break
        try:
            chunk = await asyncio.wait_for(proc.stdout.read(4096),
                                           timeout=min(remaining, config.TOOL_IDLE_TIMEOUT))
        except asyncio.TimeoutError:
            proc.kill()
            yield {"type": "error", "data": f"nuclei 超过 {config.TOOL_IDLE_TIMEOUT}s 无输出，已终止"}
            break
        if not chunk:
            break
        buf += chunk.decode("utf-8", errors="replace")
        while True:
            m = re.search(r"\r\n|\n|\r", buf)
            if not m:
                break
            line, buf = buf[: m.start()], buf[m.end():]
            if not line.strip():
                continue
            lines += 1
            if lines > config.MAX_OUTPUT_LINES:
                truncated = True
                continue
            yield {"type": "output", "data": line}
    if buf.strip():
        yield {"type": "output", "data": buf}
    try:
        await asyncio.wait_for(proc.wait(), timeout=10)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
    if truncated:
        yield {"type": "output", "data": f"（输出超过 {config.MAX_OUTPUT_LINES} 行，已截断）"}
    yield {"type": "exit", "code": proc.returncode or 0}
