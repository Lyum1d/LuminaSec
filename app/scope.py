# -*- coding: utf-8 -*-
"""授权白名单（data/scope.json）唯一实现。

背景：白名单此前在三个地方各写了一份，且语义已经分叉——
  · app/executor.py  的 _load_scope：只读文件，缺失返回空（进而 fail-closed 拒绝）
  · app/replayer.py  的 _load_scope：文件缺失时会**静默写入** example.com 再放行
  · app/pyexec.py     直接复用 executor 的 check_scope
同名函数两套行为，安全边界的实际效果取决于走哪条路径，属于隐患。
这里收敛为唯一实现：三处调用方（命令行执行器 / HTTP 重放器 / py_exec）共用。

设计取舍（沿用 executor 原有约定，不放宽任何闸门）：
  · 白名单为空（含 scope.json 不存在或解析失败）一律视为「未授权」，由调用方拒绝执行。
    宁严不松：静默放行会让这道校验形同虚设。
  · 不擅自创建默认 scope.json。此前重放器会写入 example.com 兜底，容易让人误以为
    「已经配好了授权」，故一律只读、不写。
  · 子域匹配：条目可写域名或 IP；example.com 同时匹配 a.example.com。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from . import config

# ---------- 主机形态识别 ----------
# 为什么放在这里：py_exec 的 target 与 Agent 的「从任务描述提取目标」都在判断
# 「这个字符串到底是不是主机」，两处规则一旦分叉就会出现「一边认、一边不认」的
# 静默缺口（此前 py_exec 用「不含点就跳过」的粗判，加个空格即可绕过白名单）。
# 现收敛为唯一实现，agent.py 与 pyexec.py 共用。
#
# 文件名后缀列表：这些其实不是 TLD，是模型把文件名当域名填进来的常见误判。
# 公开命名：agent.py 的「从任务描述提取目标」也用这一份，避免两处列表分叉。
FAKE_TLDS = {
    "json", "exe", "jar", "py", "txt", "log", "md", "bat", "vbs", "vbe",
    "yaml", "yml", "ini", "csv", "xlsx", "xls", "dll", "sys", "cfg", "conf",
}
_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
_URL_RE = re.compile(r"https?://[^\s，。；）)\"'<>]+")
_DOMAIN_RE = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")

# 只回环 / 明确指向本机的名字：任何授权场景下都不该成为 SRC 测试目标，
# 且它们「不含点」不会自然落入主机判定，需单独点名拦截（防「代码里打本机」）。
# **仅用于 argv 复核层的**加固黑名单：这些名字从命令行文本里"抽"出来时一律不认。
#
# ⚠️ v052 结论（复审报告 P2-C **不采纳**，附实证）：
#   复审报告建议把 loopback / 私网 / 云元数据地址也列进来，并让主闸门 `check_scope`
#   也查这个集合（认为"两层口径不一致"）。**实测：那样会破坏项目自身依赖的合法能力。**
#   · `test_replayer.py` 的设计说明原文：「不碰任何真实目标。唯一真发请求的一节打的是
#     **本机临时 HTTP 服务（127.0.0.1）**，白名单临时写成 127.0.0.1，跑完即恢复。」
#     —— 也就是说「按需授权 loopback」是**已经在用**的能力。
#   · 实测把 loopback 列入 + 主闸门也查它 → **7 个套件 29 项失败**
#     （HTTP 重放器 / 只读身份差分 / 流程绕过检测 / py_exec 与扫描器治理 /
#      网络层 WAF 状态机 / 低流量测试策略 / 实战缺陷修复）。
#   所以：**删除一项真实能力不是加固**。白名单本身就是边界，
#   「没写进白名单就拒」已经由 `host_in_scope` 保证（fail-closed）。
#
# 关于「两层口径不一致」——这是**有意的**，不是待修的缺陷：
#   · argv 复核层处理的是从命令行文本里**启发式抽取**出来的主机
#     （可能来自 `--url`、列表文件、甚至被拼进自由文本），来源不可信 → 用更严的黑名单；
#   · 主闸门处理的是操作者**显式声明的目标**，它已经过「写进 data/scope.json」这一步
#     人工授权确认 → 只受白名单约束。
#   把这个差异写成注释而不是"修平"它，是因为修平会破坏上面那条测试约定。
_DENY_HOSTS = {"localhost", "localhost.localdomain", "0.0.0.0"}


def _is_host_like(token: str) -> bool:
    """单个 token 是否像 URL / IPv4 / 域名（而非企业名、版本号等自由文本）。"""
    t = (token or "").strip().strip("'\"<>()[]")
    if not t:
        return False
    if _URL_RE.match(t):
        return True
    if _IPV4_RE.fullmatch(t):
        return True
    m = _DOMAIN_RE.fullmatch(t)
    if not m:
        return False
    # 排除「v1.2.3」这类末段是数字的串，以及把文件名当域名的情况
    return m.group(0).rsplit(".", 1)[-1].lower() not in FAKE_TLDS


def find_hosts(text: str) -> list[str]:
    """从自由文本里抽出所有「像主机」的片段，按出现顺序去重返回。

    用于「target 里可能混着说明文字/多个主机」的场景：逐个校验，
    只要有一个不在白名单就拒绝——不能让一个空格把整串带去跳过校验。
    """
    s = (text or "").strip()
    if not s:
        return []
    out: list[str] = []
    for m in _URL_RE.finditer(s):
        h = target_host(m.group(0))
        if h and h not in out:
            out.append(h)
    for m in _IPV4_RE.finditer(s):
        tok = m.group(0)
        if tok not in out:
            out.append(tok)
    for m in _DOMAIN_RE.finditer(s):
        tok = m.group(0)
        tld = tok.rsplit(".", 1)[-1].lower()
        if tld in FAKE_TLDS:
            continue
        if tok not in out:
            out.append(tok)
    # 只回环 / 指向本机的名字单独兜一层
    for tok in re.split(r"[\s,;、]+", s):
        tok = tok.strip().strip("'\"<>()[]").lower()
        if tok in _DENY_HOSTS and tok not in out:
            out.append(tok)
    # 「像主机」的片段才返回；纯自由文本（企业名/版本号）返回空
    return [h for h in out if h in _DENY_HOSTS or _is_host_like(h) or _IPV4_RE.fullmatch(h)]


def load_scope() -> list[str]:
    """读取授权白名单的**主机合并视图**：domains 数组 + targets[].host 合并去重。

    v012 P2-3 起支持结构化 targets 写法——所有既有的主机级校验
    （check_scope / argv 逐 token 复核 / 目标列表文件 / py_exec）都消费本函数，
    因此结构化条目的 host 自动获得与 domains 同等的白名单资格；
    端口/协议细粒度限制由 check_scope 额外处理。
    文件缺失或解析失败返回空列表（长度 0 = 未配置任何授权）。
    """
    entries = _read_scope_raw()
    if entries is None:
        return []
    hosts: list[str] = []
    for e in entries:
        if e["host"] not in hosts:
            hosts.append(e["host"])
    return hosts


def _read_scope_raw() -> list[dict] | None:
    """读原始 scope.json 并归一化为结构化条目；文件缺失/解析失败返回 None。"""
    p = config.SCOPE_FILE
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    out: list[dict] = []
    domains = data.get("domains", [])
    if isinstance(domains, list):
        for d in domains:
            if isinstance(d, str) and d.strip():
                out.append({"host": d.strip().lower(), "ports": None, "schemes": None})
    for t in (data.get("targets") or []):
        if not isinstance(t, dict):
            continue
        host = str(t.get("host") or "").strip().lower()
        if not host:
            continue
        ports = t.get("ports")
        schemes = t.get("schemes")
        try:
            ports_set = {int(x) for x in ports} if isinstance(ports, list) and ports else None
        except (TypeError, ValueError):
            ports_set = None
        out.append({
            "host": host,
            "ports": ports_set,
            "schemes": {str(x).strip().lower() for x in schemes}
                       if isinstance(schemes, list) and schemes else None,
        })
    return out


def load_scope_targets() -> list[dict]:
    """读取结构化授权条目（v012 P2-3）。

    scope.json 支持两种写法（可混用）：
      {"domains": ["example.com", ...]}                     —— 旧写法，主机级，端口/协议不限
      {"targets": [{"host": "example.com", "ports": [80, 443],
                    "schemes": ["https"]}, ...]}            —— 新写法，可限定端口/协议
    归一化输出：[{host, ports(set|None), schemes(set|None)}]；
    ports/schemes 未声明 = 不限（向后兼容：旧 domains 的效果）。
    """
    entries = _read_scope_raw()
    return entries if entries is not None else []


def target_host(target: str) -> str:
    """从 target 提取主机名：去协议、端口、路径、查询串与凭据。

    支持 URL / 纯域名 / IPv4 三种形态。无法解析时回退为去掉端口的原文，
    保证「解析不出来」不会变成「绕过校验」——回退值照样要过白名单。
    """
    t = (target or "").strip().lower()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    try:
        host = urlparse(t).hostname or ""
    except Exception:
        host = ""
    if host:
        # 尾点 FQDN（'www.target.test.'）会被 urlparse 原样保留，导致子域匹配失败；
        # 统一去掉尾点（审计 P2-3，方向仍是 fail-closed）
        return host.rstrip(".")
    # 解析失败：至少去掉端口，避免 "example.com:8080" 这类绕过精确匹配
    return t.split("/", 1)[0].split("@")[-1].split(":")[0]


def host_in_scope(host: str, scope: list[str]) -> bool:
    """精确匹配或子域匹配。白名单条目可直接写 IP（IP 走精确匹配）。"""
    if not host:
        return False
    for d in scope:
        if not d:
            continue
        if host == d or host.endswith("." + d):
            return True
    return False


def check_scope(target: str) -> str | None:
    """校验 target 是否在授权白名单内。返回 None 表示放行，否则返回拒绝原因。

    v012 P2-3：scope.json 里条目声明了 ports/schemes 时，target 里的端口与
    协议也一并校验（host 命中但端口/协议不在授权列表 → 拒绝）；
    条目未声明则不限制（完全向后兼容旧的 domains 写法）。
    无法从 target 解析出端口/协议时按「未指定」放行（工具会在连接层报错，
    授权层不做猜测——猜错方向的授权比不授权更危险）。
    """
    host = target_host(target)
    scope = load_scope()
    if not scope:
        return ("授权白名单为空（data/scope.json 未配置或解析失败），已拒绝执行。"
                "请先在 data/scope.json 的 domains 中填写已获书面授权的目标，"
                "或设置环境变量 ENFORCE_SCOPE=0 临时关闭本校验（不建议）。")
    # 注意：这里**刻意不查 `_DENY_HOSTS`** —— 那一层只用于 argv 复核（理由见其注释：
    # 按需授权 loopback 是测试/靶场场景的既有能力，主闸门只受白名单约束）。
    if not host_in_scope(host, scope):
        return (f"目标「{host or target}」不在授权白名单内，已拒绝执行。"
                f"当前白名单：{', '.join(scope)}。"
                f"新增授权目标请编辑 data/scope.json。")
    # ---- 端口/协议细粒度校验（仅当 host 命中的条目声明了 ports/schemes）----
    #
    # ⚠️ v050 修（配置控制台暴露出来的）：原实现是「遍历所有匹配条目，**任一**条命中限制
    # 就拒绝」。当同一个 host 同时存在两条记录时 —— 一条声明了 ports、一条未声明
    # （`ports=None` 表示不限）—— 那条「不限」的会把已声明的限制**静默放开**：
    # 操作者在控制台把端口限制设成 [443]、界面显示「已保存」，
    # 而实际上 80 端口照样放行。**这正是本项目最怕的一类错：配了、看起来生效、其实没生效。**
    # 「不限」的重复条目从哪来：`domains` 兼容视图与 `targets` 结构化条目都写同一个 host 时
    # 就会各生成一条（配置控制台的迁移与保存都会这样做）。
    #
    # 修法：先收集**全部**匹配条目，再按「显式声明优先」判定 ——
    # 只要有任何一条声明了 ports/schemes，该 host 就受声明约束；
    # 允许多条各声明一部分时取**并集**（白名单语义：被任一条授权即为授权）。
    port, scheme = _parse_port_scheme(target)
    if port is not None or scheme is not None:
        matched = [e for e in load_scope_targets()
                   if host_in_scope(host, [e["host"]])]
        declared_ports = [e["ports"] for e in matched if e["ports"] is not None]
        declared_schemes = [e["schemes"] for e in matched if e["schemes"] is not None]
        if declared_ports and port is not None:
            allowed = set().union(*declared_ports)
            if port not in allowed:
                return (f"目标「{host}:{port}」的端口不在授权范围内"
                        f"（授权端口：{sorted(allowed)}），已拒绝执行。")
        if declared_schemes and scheme is not None:
            allowed_s = set().union(*declared_schemes)
            if scheme not in allowed_s:
                return (f"目标「{scheme}://{host}」的协议不在授权范围内"
                        f"（授权协议：{sorted(allowed_s)}），已拒绝执行。")
    return None


def _parse_port_scheme(target: str) -> tuple[int | None, str | None]:
    """从 target 提取 (端口, 协议)。解析不出返回 (None, None)。

    ⚠️ 只认**显式声明**：协议仅在 target 显式含 "://" 时返回（裸域名不做
    默认 http 推断——域名型工具可能走任意协议/只做 DNS，凭推断去拒绝
    会误杀大量正常请求）；端口仅在显式写出（URL 带端口或裸 host:port）时返回。
    """
    t = (target or "").strip().lower()
    if not t:
        return None, None
    scheme = None
    port = None
    if "://" in t:
        scheme = t.split("://", 1)[0] or None
    try:
        u = urlparse(t if "://" in t else "http://" + t)
        if u.port:
            port = int(u.port)
    except ValueError:
        # host:port 形态：urlparse 对裸 host:port 的 .port 会抛 ValueError
        if ":" in t and "/" not in t:
            tail = t.rsplit(":", 1)[-1]
            if tail.isdigit():
                port = int(tail)
    except Exception:
        pass
    return port, scheme


def first_unauthorized_host_in_argv(tokens: list[str]) -> tuple[int, str] | None:
    """对最终 argv 逐 token 抽主机并过白名单（审计 P0-2/P0-3 的根治层）。

    白名单此前只覆盖 target：args 可走私 --url evil.com，url 型 target 可用
    「授权域/+空格」夹带第二个目标。本函数对 spawn 前的最终 argv 逐 token
    复核，无论走私走 target、args 还是模板渲染，都会被拦下。

    返回第一个含越权主机的 (下标, 主机)；全部放行返回 None。
    argv[0]（解释器/exe 路径）与本地路径形态的 token（盘符/绝对路径）跳过。
    白名单为空时返回 (1, '')，由调用方按 fail-closed 处理。
    """
    scope_list = load_scope()
    if not scope_list:
        return 1, ""
    for i, tok in enumerate(tokens):
        if i == 0:
            continue
        t = (tok or "").strip()
        if not t:
            continue
        # 本地路径形态（盘符 + 斜杠，或以 / 开头的绝对路径）不是测试目标。
        # ⚠️ 必须 re.match 锚定 token 开头：用 re.search 会把 URL scheme 里的
        # 's:/'（http**s:/**）误判成盘符，导致所有 http(s) URL token 被跳过、
        # argv 复核形同虚设（此坑在首次实现时真实踩中）。
        if re.match(r"[A-Za-z]:[\\/]", t) or t.startswith("/"):
            continue
        for h in find_hosts(t):
            if h in _DENY_HOSTS or not host_in_scope(h, scope_list):
                return i, h
    return None


# ---------- 目标列表文件校验（v010，P0-2 收窄后的剩余真空） ----------
# argv 逐 token 复核（上方）只能看到命令行上写出的主机；nuclei/httpx/naabu 等
# 工具的 -l/--list/--urls/--input 参数指向的目标列表文件，其**文件内容**完全不
# 经过 argv —— 文件里写 evil.com 即可绕过全部校验。这里把「列表文件内容」
# 纳入同一套白名单口径。
TARGET_LIST_FLAGS = {"-l", "--list", "--list-", "--urls", "--input", "-l/", "-L"}

# 列表文件读取上限：防止把超大文件当目标清单喂进来拖垮校验（正常目标列表
# 远小于此；超过上限按「拒绝」处理而不是硬读，方向仍是 fail-closed）。
TARGET_LIST_MAX_BYTES = 1 * 1024 * 1024


def _first_unauthorized_host_in_text(text: str, scope_list: list[str]) -> str:
    """逐行抽主机过白名单，返回第一个未授权主机；全部授权返回空串。

    列表文件常见形态：裸域名、URL、host:port、注释行（# 开头）与空行。
    抽取复用 find_hosts（与 argv 复核同一套口径，避免规则分叉）。
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for h in find_hosts(line):
            if h in _DENY_HOSTS or not host_in_scope(h, scope_list):
                return h
    return ""


def _looks_like_text(s: str) -> bool:
    """解码"成功"了但结果不像文本 → 判定为解码失败（v054，审计 §3.2 复核发现）。

    为什么"严格解码"还不够：**能"成功"解出二进制的编码不止一个**。
      · 无 BOM 的 `utf-16` 能解出任意偶数长度字节串 —— 已用「仅带 BOM 才试」挡住；
      · **带 BOM 的 `utf-16`** 同样危险：文件恰好以 `FF FE`/`FE FF` 开头时，
        后面哪怕是二进制也会被"成功"解出来（实测：`ff fe 00 81 99 ab cd ef`
        → `'脀ꮙ\uefcd'`）；
      · `gbk` 是双字节编码，**绝大多数**字节对都合法，性质相同。
    于是「解码失败 → fail-closed」这条防线在这些编码上会被绕过：解出乱码 →
    `find_hosts` 抽不出主机名 → **静默放行**（正是本项目最忌讳的形态）。

    判据用**字符类**而不是"控制字符占比"：上面那个例子解出来 0 个控制字符，
    但含**私有使用区**码位（U+E000–U+F8FF）—— 那是误码的典型落点，
    而正常的目标列表（ASCII 主机名 / 中文注释）不会出现它。
    """
    if not s:
        return True                     # 空文件不算"不像文本"
    bad = 0
    for ch in s:
        o = ord(ch)
        if (ch == "\ufffd"                                  # 替换字符
                or (o < 32 and ch not in "\t\r\n")           # 控制字符（保留制表/换行）
                or o == 0x7F
                or 0xE000 <= o <= 0xF8FF                     # 私有使用区
                or 0xFFF0 <= o <= 0xFFFF):                   # 特殊区（含 FFFD 之外的非字符）
            bad += 1
    # 容忍 1%：正常文本里偶尔会出现罕见的合法码位，但不会成片出现
    return bad / max(len(s), 1) <= 0.01


def _read_text_multi_encoding(p: Path) -> str | None:
    """多编码尝试读取目标列表文件；**全部失败返回 None**（调用方按 fail-closed 拒绝）。

    v053（审计 §2.4 修）：原来固定 `encoding="utf-8", errors="replace"` ——
    对 GBK / UTF-16LE（Windows 上很常见）会解出一堆替换字符，
    `find_hosts` 可能一个主机都抽不出来，于是**校验看起来跑了、其实什么都没查**：
    正是本项目最忌讳的「配了看起来生效、其实没生效」。

    两条刻意的取舍：
      · **严格解码，不用 `errors="replace"`** —— 宁可拒绝，也不要带着乱码继续查；
      · **UTF-16 仅在带 BOM 时才试** —— 无 BOM 时 `utf-16` 能"成功"解出任意偶数长度
        字节串（多半是乱码），那等于把上面那个坑换个地方重挖。
    顺序按命中率排：UTF-8（带/不带 BOM）→ GBK → 带 BOM 的 UTF-16。

    v054（审计 §3.2 复核）：解码成功后**再加一道字符类判据**（见 `_looks_like_text`）——
    因为能"成功"解出二进制的编码不止一个，"解码没抛异常"并不等于"解出来的是文本"。
    """
    try:
        raw = p.read_bytes()
    except OSError:
        return None
    if not raw:
        return ""                       # 空文件：交给调用方按"内容为空"处理
    encs = ["utf-8-sig", "utf-8", "gbk"]
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encs.append("utf-16")
    for enc in encs:
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if not _looks_like_text(text):
            # 解"成功"了但不像文本（二进制/未知编码）→ 继续试下一种；全都不行就返回 None
            continue
        return text
    return None


def first_unauthorized_target_list_in_argv(tokens: list[str]) -> tuple[str, str] | None:
    """扫描 argv 中「目标列表旗标 + 文件路径」，校验文件内容是否含未授权主机。

    返回 (旗标, 未授权主机) 或 None。第二个元素可能是**哨兵值**而非主机名：
      · `"<oversized>"`  —— 文件超过 TARGET_LIST_MAX_BYTES
      · `"<unreadable>"` —— 文件存在但读取/解码失败（fail-closed）
    调用方必须对哨兵值单独措辞（不要再拼成「文件中包含目标「<oversized>」」）。

    - 旗标后无值（下一个 token 以 - 开头或不存在）→ 交由工具自行报错，放行；
    - **文件不存在** → 放行（执行时工具会因文件缺失而失败，不是授权问题）；
    - 文件存在但没有读权限 / 解码失败 → **拒绝**（见 _read_text_multi_encoding）；
    - 文件超过 TARGET_LIST_MAX_BYTES → 拒绝。
    白名单为空时返回 ('', '')，由调用方按 fail-closed 处理。
    """
    scope_list = load_scope()
    if not scope_list:
        return "", ""
    for i, tok in enumerate(tokens):
        if i == 0 or tok not in TARGET_LIST_FLAGS:
            continue
        if i + 1 >= len(tokens):
            continue
        path = (tokens[i + 1] or "").strip()
        if not path or path.startswith("-"):
            continue
        p = Path(path)
        try:
            # v054（审计 §3.1 复核）：**存在但不是普通文件 → 拒绝**。
            # 原来只有一句 `if not p.is_file(): continue`，而它对**目录**同样成立 ——
            # 于是 `-l <目录>` 会在读取之前就 continue 掉、**静默放行**；
            # 我 v053 写的注释「路径其实是目录等都会落到这里（OSError 分支）」
            # **与代码不符**（`is_file()` 先返回 False 就跳走了，那条分支对目录不可达）。
            # 现在把「不存在」与「存在但不是普通文件」分开：
            #   · 不存在 → 放行（工具自己会报错，不是授权问题）；
            #   · 存在但不是普通文件（目录/设备/命名管道…）→ 无法校验内容 → fail-closed。
            if not p.exists():
                continue
            if not p.is_file():
                return tok, "<unreadable>"
            if p.stat().st_size > TARGET_LIST_MAX_BYTES:
                return tok, "<oversized>"
            text = _read_text_multi_encoding(p)
        except OSError:
            # 存在但读不了（权限被改、被独占锁定等）→ 拒绝
            return tok, "<unreadable>"
        if text is None:
            return tok, "<unreadable>"
        bad = _first_unauthorized_host_in_text(text, scope_list)
        if bad:
            return tok, bad
    return None
