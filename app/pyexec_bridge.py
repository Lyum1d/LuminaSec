# -*- coding: utf-8 -*-
"""py_exec 受控网络通道（v023.2）：脚本 ↔ 宿主的请求代理桥。

背景（v023 实测事故）：封禁由 `py_exec` 脚本内部 `for` 循环直接发请求造成——
外层限速管不住脚本进程里的循环。治理思路是**把网络能力从脚本进程收回宿主**：

    脚本进程                          宿主进程（本模块）
    ─────────                        ─────────────────
    safe_http_request(url)  ──写请求文件──▶  扫描请求队列
                                            → TrafficGovernor 许可
                                              （scope/预算/并发/暂停态）
                                            → httpx 实际发送
    读响应文件（同步轮询）  ◀─写响应文件──  写脱敏结果

为什么用文件队列而不是管道/HTTP：
  · 脚本是同步代码，`await` 不可用；文件轮询零依赖、跨进程稳；
  · 宿主与脚本只需共享一个工作目录（本来就是 py_exec 的沙箱 workdir）；
  · 请求文件原子改名出现（tmp → 正式名），避免读到半个文件。

诚实说明局限：脚本进程**仍可**自行 `import requests` 直连目标——本模块是
「防误触」而不是「防对抗」：静态检测拒绝最危险模式（网络库 + 循环），
真实的使用者是 Agent 而非攻击者。彻底阻断需要防火墙级隔离（超出本版本范围）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

import httpx

from . import config, traffic

logger = logging.getLogger("src_agent.pyexec_bridge")

# 桥接目录名（在工作目录内）
BRIDGE_DIR = ".srcagent_traffic"
REQ_DIR = "req"
RESP_DIR = "resp"

# 脚本侧模块源码：写入沙箱 workdir，脚本 `import srcagent` 或直接调用即可。
# 注意：这里必须是**同步**实现——py_exec 跑的是普通 Python 脚本。
SCRIPT_MODULE_SOURCE = '''# -*- coding: utf-8 -*-
"""src-agent 受控网络接口（由宿主自动注入，勿手工修改）。

用法（**返回 dict 字段表见下，属性访问与下标访问都支持**）：
    from srcagent import safe_http_request
    r = safe_http_request("https://authorized.example/api", method="GET")
    print(r["status_code"], r["text"][:200])     # 下标访问
    print(r.status_code, r.headers)              # 属性访问（等价）

返回字段（成败都是同一个 dict，**先查 error**）：
    status_code : int | None    HTTP 状态码（请求未完成时为 None）
    headers     : dict          响应头（小写键）
    text        : str           响应正文（超过 AGENT_PY_EXEC_TEXT_LIMIT，默认
                                131072 字符会截断，此时另有 truncated=True、
                                total_chars 与 saved_text_path）
    error       : str           非空表示请求**没有完成**（超时/被调度拒绝等）
    elapsed     : float         耗时（秒）
    truncated   : bool          正文是否被截断（可选）
    total_chars : int           正文原始长度（被截断时提供）
    total_bytes : int           正文原始字节数（被截断时提供）
    saved_text_path : str       **被截断时提供：完整正文的本地文件路径。**

取全文的正确姿势（v031/v034/v045.2，重要）：
    看到 `saved_text_path` 时，**不要**为了拿正文再向目标发请求（Range 分片会额外
    消耗目标流量与预算）。直接读落盘文件 —— 注意它是**原始字节**：
        from srcagent import load_bytes, load_text     # 受控接口，本地读、不出网
        raw = load_bytes(r["saved_text_path"])         # 逐字节可信（绝对路径可直接用）
        full = raw.decode("utf-8", "replace")          # 需要文本时再解码
    需要摘要（md5/sha）时用 `file_md5(path)`；只要判断是不是图片/压缩流用
    `file_info(path)`（返回 (字节数, 前 8 字节 hex)）。
    **不要**用 `open()` —— 那会被判定为具备文件读写能力，反而需要额外人工确认；
    受控接口同样是本地读，但属白名单内。
    **切勿**用文本模式读回来再与 `r.text` 比长度或算 md5 —— 文本模式会把 `\r\n`
    归一化成 `\n`，两者不是同一个东西（v033 修的正是这类口径混用造成的伪差异）。

字节口径自检（v034）：
    每个响应都带 `total_chars`（正文原始字符数）与 `total_bytes`（原始字节数），
    可与 `len(r.text)` 及响应头 `content-length` 交叉核验，判断有无截断/异常。

判空纪律（重要）：
    `error` **恒存在**（成功时为空串），所以 `if r["error"]:` 永远安全 —— 不会再
    出现「文档教你查 error、成功路径却抛 KeyError」的崩溃（v032 修的就是这条）。
    但**不要**用「text 为空」推断目标返回空内容：必须先看 error 与 status_code。
    写错字段名（属性或下标都一样）会抛出**带可用字段列表**的错误，并把常见误用
    直接指向正确键名（如 `body` → 提示 `text`、`status` → 提示 `status_code`）。
    因此不会出现「字段名写错却静默拿到空值」的假阴性，也不会出现「只报一个
    KeyError('body') 却不知道正确名字是什么」的死胡同（v045 补的下标报错）。

跨脚本交换数据：
    用 `from srcagent import tmpdir`（**是函数，要加括号**）或 `TMPDIR`（**是常量，
    直接当路径用**）拿到**会话级持久目录**（多次 py_exec 之间保持稳定）。不要写
    `/tmp` 或其它系统绝对路径（本机沙箱的 TEMP 是一次性的，且写系统盘不受管控、
    不会清理）。两种写法示例：
        from srcagent import TMPDIR      # 常量：os.path.join(TMPDIR, "a.txt")
        from srcagent import tmpdir      # 函数：os.path.join(tmpdir(), "a.txt")

    **推荐直接用下面这对受控接口**（v045 新增）——它们把路径锁在 tmpdir() 内，
    不需要 import os、也不需要自己 open：
        from srcagent import save_text, load_text, list_tmpdir
        save_text("home.html", r["text"])     # 落盘，返回完整路径
        html = load_text("home.html")         # 下次 py_exec 里读回来
        print(list_tmpdir())                  # 确认上一步落了什么
    （落盘/读盘都用原始字节口径，不做换行归一，可与 r.text 直接比长度。）

流量调度的**硬约束（写脚本前必看）**：
    所有请求都经宿主调度器，除了 scope / 预算 / 并发 / 暂停态，还有**突发上限**：
    **10 秒窗口内只放行 1 个请求**（防脚本爆发式请求）。所以
        for u in urls: safe_http_request(u)          # ✗ 第 2 个请求就会被拒
    会拿到 {"error": "TRAFFICBUDGETEXCEEDED"} 并在脚本级终止。
    正确做法是把请求**展开为顺序调用并接受节流**，或分成多次 py_exec 调用；
    不要试图用循环「多打几个」—— 那正是这条限制要防的行为。

大响应与脚本崩溃（v032/v033）：
    正文达到阈值（默认 8192 字符）就会**自动落盘**，响应里给出 `saved_text_path`。
    这意味着即使脚本随后崩溃，已取回的正文仍留在磁盘上、可按路径找回 ——
    **不要**为了重取内容再向目标发一次请求（那会白白消耗目标流量与预算）。

    落盘文件是**原始响应字节**（`.bin`），与网络层收到的逐字节一致。请这样读：
        from srcagent import load_bytes, file_md5, file_info
        raw  = load_bytes(r["saved_text_path"])   # 逐字节可信，md5/差分用这个
        text = raw.decode("utf-8", "replace")     # 需要文本时再解码
        file_md5(r["saved_text_path"])            # 直接拿摘要，省得自己 import hashlib
    做**差分或指纹比对**时，务必两边用同一口径：拿 `r.text` 比就都拿 `r.text`，
    拿落盘字节比就都拿落盘字节。**不要**把文本模式读出来（`\r\n` 已被归一化成
    `\n`）的内容去和 `r.text` 比 —— 那是两个东西，会产生伪差异（v033 修的正是
    这类「口径混用」）。

所有请求都由宿主进程的流量调度器发出：scope 白名单、滑动窗口预算、
目标并发与暂停状态全部生效。脚本自身的循环不会绕过这些限制——
预算耗尽时返回 {"error": "TRAFFIC_BUDGET_EXCEEDED"}。
"""
import json as _json
import os as _os
import time as _time
import uuid as _uuid

_BRIDGE = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".srcagent_traffic")
_REQ = _os.path.join(_BRIDGE, "req")
_RESP = _os.path.join(_BRIDGE, "resp")


class Resp(dict):
    """响应对象：同时支持下标与属性访问。

    为什么需要它：模型（和人）很容易把返回的 dict 当成响应对象来用
    （写 `r.status_code` 而实际只有 `r["status_code"]`）。旧实现下这种误用
    **不会报错**，只是静默返回空值——实测导致 3 次真实请求被误读成
    「目标返回空内容」，差点写进结论。这里让属性访问等价于下标访问，
    字段不存在时直接抛错（并列出可用字段），把静默错误变成显式错误。

    v045（实战）：补上 `__getitem__`。原先只有 `__getattr__` 做了解释性
    报错，下标访问走 dict 原生的 `__getitem__`，未知键只抛裸的 `KeyError('body')`
    —— **没有任何线索指向正确字段名**。而模型恰恰更常用下标（`r["text"]`）：
    实测 Agent 用 `r["body"]` 读正文，拿到 KeyError 后只能白烧一步去内省 API
    才发现字段叫 `text`。两个访问方式必须给同等质量的错误。
    """

    # 常见误用 → 正确字段名。这张表就是「省掉一次白烧步数」的全部成本，
    # 加的每一对都来自实测踩过的坑。
    _FIELD_HINT = {
        "body": "text", "content": "text", "data": "text", "resp": "text",
        "raw": "text", "html": "text", "response": "text", "json": "text",
        "status": "status_code", "code": "status_code", "statuscode": "status_code",
        "header": "headers", "hdr": "headers", "time": "elapsed",
        "len": "total_chars", "length": "total_chars", "size": "total_bytes",
    }

    def _explain(self, key):
        hint = self._FIELD_HINT.get(str(key).lower())
        tip = "（是否想取 %r？）" % hint if hint else ""
        return ("响应对象没有字段 %r%s。可用字段：%s"
                % (key, tip, ", ".join(sorted(self.keys()))))

    def __getitem__(self, key):
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            raise KeyError(self._explain(key)) from None

    def __getattr__(self, name):
        # 注意用 dict.__getitem__ 而不是 self[name]：虽然本类已定义
        # __getitem__，但显式走基类可以保证「属性/下标」两条错误路径
        # 不会互相调用成环（__getattr__ → __getitem__ → ...）。
        try:
            return dict.__getitem__(self, name)
        except KeyError:
            raise AttributeError(self._explain(name)) from None

    def __bool__(self):
        # 空 dict 仍按 dict 语义（False）；这里显式写出避免误解
        return bool(dict(self))


def tmpdir():
    """返回**会话级持久目录**（跨多次 py_exec 调用保持稳定，自动创建）。

    用途：把大响应落盘后离线解析（避免灌进上下文），或在上一步取数、
    下一步解析。宿主会在会话结束后按保留期清理。
    """
    d = _os.environ.get("SRC_AGENT_TMPDIR")
    if not d:
        d = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "script_tmp")
    try:
        _os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


# v032（第四轮实战）：再导出一个**常量**形式的持久目录路径。
# 实测踩坑：`from srcagent import tmpdir` 之后写成 `os.path.join(tmpdir, "x")`
# 会抛 TypeError（tmpdir 是函数而非路径），白耗一步。给一个显然是路径的名字，
# 两种用法都能work：tmpdir() 取值、TMPDIR 直接用。
TMPDIR = tmpdir()


def _wrap(data):
    """包装宿主响应：加属性访问 + 空响应显式告警。

    v032（第四轮实战）：**总是补齐 `error` 键**（默认空串）。
    原实现只在失败时才有 `error`，于是文档推荐的 `if r["error"]:` 在成功路径上
    直接抛 `KeyError: 'error'` —— 实测让脚本崩了两次、白烧 2 次真实目标请求。
    「恒存在的键」比「按需出现的键」更不容易误用；判断失败仍应优先看 `error`
    或 `status_code`，但**不会再因为键不存在而崩**。
    """
    try:
        r = Resp(data or {})
    except (TypeError, ValueError):
        return Resp({"error": "宿主响应格式异常", "raw": repr(data)[:200]})
    r.setdefault("error", "")
    if not r.get("error") and not r.get("status_code"):
        # 宿主没报错、也没有状态码 → 这不是「目标返回空」，而是响应本身缺失
        r["warning"] = ("宿主返回的响应缺少 status_code："
                        "请勿据此判断目标内容为空；请检查调用参数或改用受控接口")
    return r


def safe_http_request(url, method="GET", headers=None, cookies=None,
                      body="", timeout=25):
    """受控 HTTP 请求（同步）。返回 Resp（dict 子类，属性/下标访问均可）：

        status_code / headers / text / error / elapsed
        [truncated, total_chars, total_bytes, saved_text_path]

    **先查 error**：error 非空表示请求未完成（超时/被调度拒绝/目标暂停），
    此时不要用 text 判空。**error 恒存在**（成功时为空串），可直接 `if r["error"]:`。
    字段名写错会抛 AttributeError（列出可用字段），不会静默返回空值。示例：

        r = safe_http_request("https://目标/接口")
        if r["error"]:
            print("未完成：", r["error"], r.get("hint", ""))
        else:
            print(r.status_code, len(r.text), r.headers.get("content-type"))
    """
    rid = _uuid.uuid4().hex[:12]
    payload = {
        "id": rid, "url": url, "method": (method or "GET").upper(),
        "headers": headers or {}, "cookies": cookies or {},
        "body": body or "", "created_at": _time.time(),
    }
    tmp = _os.path.join(_REQ, rid + ".tmp")
    final = _os.path.join(_REQ, rid + ".json")
    with open(tmp, "w", encoding="utf-8") as f:
        _json.dump(payload, f, ensure_ascii=False)
    _os.replace(tmp, final)          # 原子出现，宿主不会读到半个文件
    resp_path = _os.path.join(_RESP, rid + ".json")
    deadline = _time.time() + float(timeout)
    while _time.time() < deadline:
        if _os.path.exists(resp_path):
            try:
                with open(resp_path, "r", encoding="utf-8") as f:
                    data = _json.load(f)
            except (OSError, ValueError):
                data = {"error": "响应文件读取失败"}
            try:
                _os.remove(resp_path)
            except OSError:
                pass
            return _wrap(data)
        _time.sleep(0.1)
    return _wrap({"error": "TIMEOUT_WAITING_HOST_BRIDGE",
                  "hint": "宿主未在超时内响应；目标可能已暂停或预算耗尽"})


def get(url, **kw):
    """便捷封装：GET。"""
    return safe_http_request(url, method="GET", **kw)


def post(url, body="", **kw):
    """便捷封装：POST（写方法需人工确认闸门放行后才会由宿主执行）。"""
    return safe_http_request(url, method="POST", body=body, **kw)


# ---------- 会话内落盘（v045） ----------
# 为什么要有这两个函数（v045，实战实测）：
#   模块 docstring 一直推荐「大响应落盘后离线解析（避免灌进上下文）」，
#   但**落盘只能用裸 `open()`** —— 而 `open()` 是文件写入，与「只读脚本」的
#   静态判定直接冲突。实测 Agent 因此连续写了 3 次带 `open()` 的落盘脚本，
#   每一步都要 L3 双轮人工确认，卡在闸门上推不动。
#   一个被文档推荐的标准动作，不该需要走后门。这里给一对受控读写接口：
#   路径强制锁在 `tmpdir()` 内（防目录穿越），读写都显式 `newline=""`
#   （v033 的换行污染教训：不指定时 Windows 上会把 LF 写成 CRLF）。
#   【注意】本模块源码是**三引号字符串**，注释里不要出现反斜杠转义
#   （写 \\n 会被解释成真换行，直接把源码撕成两半 —— 这个坑本次已经踩过一次）。
def _in_tmpdir(name):
    base = _os.path.abspath(tmpdir())
    p = _os.path.abspath(_os.path.join(base, str(name)))
    if p != base and not p.startswith(base + _os.sep):
        raise ValueError(
            "name 必须是 tmpdir() 内的相对路径，禁止越出目录：%r" % (name,))
    d = _os.path.dirname(p)
    if d:
        _os.makedirs(d, exist_ok=True)
    return p


def save_text(name, text):
    """把文本写入会话持久目录，返回落盘路径。

        p = save_text("home.html", r["text"])
        print(p)          # 下次 py_exec 可以直接 load_text("home.html")
    """
    p = _in_tmpdir(name)
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(text if isinstance(text, str) else str(text))
    return p


def load_text(name, encoding="utf-8"):
    """读回 save_text 落盘的文本。"""
    with open(_in_tmpdir(name), "r", encoding=encoding, newline="") as f:
        return f.read()


# ---------- 原始字节读取（v045.2） ----------
# 为什么必须有（实战实测的**文档与判定自相矛盾**）：
#   平台把大响应落盘成 `.bin`（**原始字节**，见 v033 的换行污染教训），
#   而模块 docstring 与 saved_text_path 的说明都写着「用 open(path,"rb").read() 读回来」。
#   但 v045 引入的能力分档器把 `open()` 判为「非只读」——于是**文档推荐的标准动作
#   被判定器拦掉**。实测第三轮：Agent 要算「key 是否等于图片字节的 md5」，
#   被 `open()` 卡了两次，退而用工具箱的交互式 md5_tool（非交互调用只打印菜单），
#   一连白烧三步。
#   补一对受控接口把这条路打通，判定的白名单也跟着放宽（见 _classify_step.py）。
def _resolve_in_tmpdir(name_or_path):
    """把「文件名」或「tmpdir 内的绝对路径」解析成可读路径。

    两种入参都要支持：`save_text` 返回的是绝对路径，而 `list_tmpdir()` 给的是文件名，
    Agent 两种都会传给下游。绝对路径只放行 tmpdir 内的，越界一律拒绝。
    """
    s = str(name_or_path)
    base = _os.path.abspath(tmpdir())
    if _os.path.isabs(s):
        p = _os.path.abspath(s)
        if p == base or p.startswith(base + _os.sep):
            return p
        raise ValueError("只允许读取 tmpdir() 内的文件：%r" % (s,))
    return _in_tmpdir(s)


def load_bytes(name_or_path):
    """读回**原始字节**（`.bin` 落盘文件、图片、任意二进制）。纯本地读，不出网。

        raw = load_bytes(r["saved_text_path"])     # 落盘文件给的绝对路径可直接用
        raw = load_bytes("resp_ab12cd34.bin")      # 或 tmpdir 里的文件名
    """
    with open(_resolve_in_tmpdir(name_or_path), "rb") as f:
        return f.read()


def file_md5(name_or_path, algo="md5"):
    """对文件的**原始字节**算摘要，返回十六进制串。

    为什么单独给一个函数而不是让脚本 import hashlib 自己算：
    算摘要**必须走字节口径** —— 用 `r["text"]`（有损解码，二进制里会出现 U+FFFD）
    算出来的哈希是无意义的。这个函数把它固化成「读原始字节 → 算摘要」，
    省得每次都要先解释一遍口径（v033/v034 就是被这类口径混用坑过的）。

        file_md5(r["saved_text_path"])        # 与响应头/服务端 key 比对
        file_md5("logo.png", algo="sha256")
    """
    import hashlib as _hashlib
    h = _hashlib.new(algo)
    h.update(load_bytes(name_or_path))
    return h.hexdigest()


def file_info(name_or_path):
    """返回 (size_bytes, 前 8 字节的 hex)，用于快速判断落盘文件是不是二进制/是否为图片。

    实测痛处：分不清 `.bin` 里到底是「gzip 解压后的 JPEG 原文」还是「压缩流」，
    导致 Agent 白花一步去猜编码。给个只看头部的轻量探针，一眼定性：
        JPEG 以 ffd8ff 开头、PNG 以 89504e47 开头、gzip 以 1f8b 开头。
    """
    raw = load_bytes(name_or_path)
    return len(raw), raw[:8].hex()


def list_tmpdir():
    """列出会话持久目录里的文件名（便于确认上一步落盘成功）。"""
    try:
        return sorted(_os.listdir(tmpdir()))
    except OSError:
        return []
'''


def prepare_workdir(workdir: Path) -> Path:
    """在工作目录里铺好桥接目录与脚本侧模块，返回模块路径。"""
    bridge = workdir / BRIDGE_DIR
    (bridge / REQ_DIR).mkdir(parents=True, exist_ok=True)
    (bridge / RESP_DIR).mkdir(parents=True, exist_ok=True)
    mod = workdir / "srcagent.py"
    mod.write_text(SCRIPT_MODULE_SOURCE, encoding="utf-8")
    return mod


class ScriptBridge:
    """宿主侧桥接任务：服务脚本发出的受控请求。"""

    def __init__(self, workdir: Path, *, project_id: str = "", tool_alias: str = "py_exec",
                 max_requests: int = 0, session_id: str = "") -> None:
        self.workdir = Path(workdir)
        self.req_dir = self.workdir / BRIDGE_DIR / REQ_DIR
        self.resp_dir = self.workdir / BRIDGE_DIR / RESP_DIR
        self.project_id = project_id
        self.session_id = session_id
        self.tool_alias = tool_alias
        self.max_requests = max_requests or config.PY_EXEC_MAX_REQUESTS
        self.count = 0
        self.blocked_reason = ""      # 目标暂停/封禁时置位 → 主循环终止脚本树
        self.notes: asyncio.Queue = asyncio.Queue()   # 给主 generator 的输出事件
        self._stop = asyncio.Event()
        self._seen: set[str] = set()

    async def run(self) -> None:
        """轮询请求目录。0.2s 粒度——脚本侧单次请求 25s 超时，足够宽裕。

        注意：本任务在后台跑，异常若逃逸会**静默终止桥接**（脚本侧只会看到
        一直超时）——因此每轮 drain 都包 try/except 并记日志，绝不退出循环。
        """
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=0.2)
                break
            except asyncio.TimeoutError:
                pass
            except Exception:
                logger.exception("桥接等待异常（继续）")
            try:
                await self._drain_once()
            except Exception:
                logger.exception("桥接处理请求异常（继续下一轮）")

    async def _drain_once(self) -> None:
        try:
            names = sorted(p.name for p in self.req_dir.iterdir()
                           if p.name.endswith(".json"))
        except OSError:
            return
        for name in names:
            if name in self._seen:
                continue
            self._seen.add(name)
            path = self.req_dir / name
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            await self._handle(payload)

    async def _handle(self, payload: dict) -> None:
        rid = payload.get("id") or ""
        url = payload.get("url") or ""
        method = (payload.get("method") or "GET").upper()
        resp: dict
        # 预算：脚本级上限（宿主侧计数，脚本无法自增绕过）
        if self.count >= self.max_requests:
            resp = {"error": "TRAFFIC_BUDGET_EXCEEDED",
                    "hint": f"单脚本请求上限 {self.max_requests} 已用尽；"
                            "请拆分脚本或改用受控命令工具"}
            await self._write_resp(rid, resp)
            self.blocked_reason = self.blocked_reason or "脚本请求预算耗尽"
            await self.notes.put(
                f"（脚本请求预算耗尽：{self.count}/{self.max_requests}，"
                f"后续 safe_http_request 一律拒绝）")
            return
        if traffic.READONLY_METHODS and method not in traffic.READONLY_METHODS:
            # 写方法：脚本通道不自动放行（计划 4.4：写操作必须走 L2/L3 人工闸门）
            resp = {"error": "WRITE_METHOD_NOT_ALLOWED_IN_SCRIPT",
                    "hint": f"脚本通道只允许 {'/'.join(traffic.READONLY_METHODS)}；"
                            "写操作请用命令行工具走人工确认闸门"}
            await self._write_resp(rid, resp)
            await self.notes.put(f"（脚本尝试 {method} 被拒：写操作须走人工确认闸门）")
            return
        # 调度器许可（scope / 预算 / 并发 / 暂停态 / 审计）
        try:
            permit = await traffic.governor.acquire(
                url, project_id=self.project_id, session_id=self.session_id,
                tool_alias=self.tool_alias, method=method)
        except traffic.TrafficError as e:
            kind = type(e).__name__
            resp = {"error": kind.upper(), "hint": str(e)}
            await self._write_resp(rid, resp)
            self.blocked_reason = self.blocked_reason or str(e)
            await self.notes.put(f"（受控请求被调度拒绝：{e}）")
            return
        self.count += 1
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                         timeout=config.PY_EXEC_REQUEST_TIMEOUT) as client:
                r = await client.request(
                    method, url,
                    headers=payload.get("headers") or {},
                    cookies=payload.get("cookies") or None,
                    content=(payload.get("body") or "").encode("utf-8") or None)
        except Exception as e:
            await traffic.governor.release(permit, error_type=type(e).__name__,
                                           os_error_code=getattr(e, "errno", 0) or 0)
            resp = {"error": f"{type(e).__name__}: {e}"}
            await self._write_resp(rid, resp)
            return
        await traffic.governor.release(permit, status_code=r.status_code,
                                      bytes_in=len(r.content))
        # v023.6（实战反馈）：截断必须显式告知——否则脚本以为自己拿到了完整
        # 响应体，可能漏掉位于页尾的关键证据（实战中 serverPath 就在 64KB 之后）。
        # v031（第三轮实战）：光是「告知」不够，还得**给得出全文**。原实现硬截断
        # 65536 且无任何取回途径，脚本只能改用 Range 头再打一次目标（实测门户页
        # 110762 字节被截掉 40%，直接导致「首页无外链 JS」的错误判定）。现在：
        # ① 上限提高到 config.PY_EXEC_TEXT_LIMIT（默认 128KB，覆盖常见门户页）；
        # ② 仍超限时把**完整正文落盘**并回 saved_text_path，脚本离线读取即可，
        #    0 次额外目标请求。
        full_len = len(r.content)
        text = r.text
        limit = config.PY_EXEC_TEXT_LIMIT
        resp = {"status_code": r.status_code,
                "headers": {k: v for k, v in list(r.headers.items())[:20]},
                "text": text[:limit],
                "elapsed": round(time.monotonic() - t0, 3),
                # v034：字节/字符元数据**总是给出**，不再只在截断或落盘时才有。
                "total_chars": len(text),
                "total_bytes": full_len,
                # v040（某高校 第三轮反馈）：补跳转相关字段。此前脚本想取跳转时访问
                # `r.history` / `r.redirect_url` 都会 AttributeError 报废一步（实测发生）。
                # 本通道 `follow_redirects=False`，故 `final_url` 即请求 URL，
                # 跳转目标请看 `location`（响应头 Location）。
                "final_url": str(r.url),
                "location": r.headers.get("location", ""),
                # v042（某高校 第四轮反馈）：`truncated` **恒存在**（未截断时为 False）。
                # 原实现只在被截断时才加这个键，于是脚本不主动检查时**根本不知道有这回事** ——
                # 实测出现在 128KB 截断的 JS 包上「靠长度巧合才发现」的情况，存在假阴性风险。
                # 与 v032 给 `error` 补默认值同源：**恒存在的键比按需出现的键更不容易误用**。
                "truncated": False}
        # v032（第四轮实战）：**大响应一律落盘**，不再只在截断时落。
        # 理由：脚本崩溃时内存里的 Resp 会连同已成功取回的正文一起丢失 —— 实测
        # 同一路径被迫重请（既违反「不重复请求」纪律，又白烧目标请求）。落盘后
        # 即使脚本挂了，正文仍留在磁盘上，脚本可按 tmpdir()/TMPDIR 找回。
        saved = None
        if len(text) >= config.PY_EXEC_SAVE_THRESHOLD:
            # 落盘**原始字节**（r.content 而不是 text）：保证与响应体逐字节一致，
            # 避免 Windows 文本模式把 \n 改写成 \r\n 污染差分基线（v033）
            saved = _dump_full_text(rid, r.content)
            if saved is not None:
                resp["saved_text_path"] = str(saved)
                resp["total_chars"] = len(text)
                resp["total_bytes"] = full_len
        if len(text) > limit:
            resp["truncated"] = True
            resp["total_chars"] = len(text)
            resp["total_bytes"] = full_len
            if saved is not None:
                resp["saved_text_path"] = str(saved)
                resp["truncation_note"] = (
                    f"响应体已截断：text 只含前 {limit} 字符（原始 {len(text)} 字符 / "
                    f"{full_len} 字节）。**完整正文已落盘（原始字节）**，用 "
                    "open(r['saved_text_path'], 'rb').read() 取全文即可 —— "
                    "不要为了拿正文再向目标发请求（Range 分片会额外消耗目标流量）。")
            else:
                resp["truncation_note"] = (
                    f"响应体已截断：仅返回前 {limit} 字符（原始 {len(text)} 字符 / "
                    f"{full_len} 字节），且完整正文落盘失败。"
                    "如需页尾内容，请用 Range 头分片获取。")

        await self._write_resp(rid, resp)

    async def _write_resp(self, rid: str, resp: dict) -> None:
        path = self.resp_dir / f"{rid}.json"
        tmp = self.resp_dir / f"{rid}.tmp"
        try:
            tmp.write_text(json.dumps(resp, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            logger.debug("写响应文件失败（脚本可能已退出）", exc_info=True)

    def stop(self) -> None:
        self._stop.set()


def _dump_full_text(rid: str, data: bytes) -> Path | None:
    """把完整响应体（**原始字节**）落盘到会话级持久目录（与脚本侧 `tmpdir()` 同目录）。

    为什么落盘而不是继续抬高上限：正文可能有数 MB，直接塞进桥接 JSON 既拖慢
    文件轮询、又会顺带撑爆模型上下文。落盘 + 回路径让脚本「按需读全文」，
    代价是 0 次额外目标请求。

    v033（第五轮实战）：**必须写原始字节，不能用 `write_text()`。**
    Windows 上 `Path.write_text()`（newline=None）会把正文里的每个 `\\n` 改写成
    `\\r\\n`，且**落盘文件本身看不出任何异常** —— 实测把 10741 字节的响应写成
    11046 字节，脚本读回来凭空多出 305 个 `\\r`，与 `r.text` 对不上。而 Agent 恰
    恰被要求「基于落盘全文做差分」，**差点把这种换行污染伪差异当成 IDOR 差分写进
    结论**。写原始字节后：落盘文件与响应体逐字节一致，还能直接与流量审计的
    `bytes_in` 对照核验。

    读取方式（脚本侧）：
        raw  = open(r["saved_text_path"], "rb").read()   # 原始字节，逐字节可信
        text = raw.decode("utf-8", "replace")            # 需要文本时再解码

    目录口径必须与 `pyexec.persist_dir_for()` 保持一致（两处都取自
    `config.PY_EXEC_TMP_ROOT`），否则脚本拿 `tmpdir()` 找不到文件。
    """
    try:
        day = time.strftime("%Y%m%d")
        d = Path(config.PY_EXEC_TMP_ROOT) / "persist" / day
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"resp_{rid}.bin"
        p.write_bytes(data)
        return p
    except OSError:
        logger.debug("完整正文落盘失败", exc_info=True)
        return None


def detect_direct_network(code: str) -> dict:
    """静态检测脚本里的直接网络访问。

    返回 {"has_net_lib", "has_loop", "has_url", "risky", "single_shot"}：
      risky       = 网络库 + 循环 + URL（事故模式：脚本循环直连，外层限速无效）
      single_shot = 网络库 + URL 但**无循环**（v023.6 新增：这类请求同样绕过了
                    调度器——不可审计、不受预算与暂停态约束，必须提示）

    定位说明：这是**防误触**检查（阻止 Agent 写出外层管不住的脚本），
    可被刻意绕过（如 __import__ 动态导入）——不是对抗性安全边界。
    """
    import re
    c = code or ""
    net_lib = bool(re.search(r"\b(import\s+(requests|httpx|aiohttp|http\.client)|"
                             r"from\s+(requests|httpx|aiohttp|http)\s+import|"
                             r"urllib\.request|socket\.socket|import\s+socket)\b", c))
    loop = bool(re.search(r"^\s*(for|while)\s", c, re.MULTILINE))
    url = bool(re.search(r"https?://[^\s\"']+", c))
    return {"has_net_lib": net_lib, "has_loop": loop, "has_url": url,
            "risky": net_lib and loop and url,
            "single_shot": net_lib and url and not loop}
