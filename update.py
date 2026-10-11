# -*- coding: utf-8 -*-
"""SRC Agent 更新工具（update.exe 源码）。

功能：
  1. 版本比对：本地 VERSION.txt vs 远端 main 的 VERSION.txt
     （同一仓库的多个等价入口**并行竞速**：raw / api.github.com / CDN。
       单一域名不可达或 hosts 被改时仍能取到；且不再把「取不到」当成「已是最新」）
  2. 更新：下载 GitHub zipball → 解压临时目录 → 迁移本机保留项
     （data 用户数据合并 / config.yaml / .venv / 桌面壳 exe）→ 旧文件备份 → 原子切换
  3. 首次安装：本机没有 src-agent 时直接安装到 exe 所在目录（可选自动建 venv 装依赖）
  4. 回滚：恢复上次更新前状态
  5. 网络：默认走系统代理，可在界面填写代理地址；纯标准库，零依赖

打包（用带 tkinter 的 Python）：
  pyinstaller --onefile --windowed --name update update.py
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import sys
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

VERSION_FILE = "VERSION.txt"
UPDATER_STATE = "update_state.json"
BACKUP_PREFIX = "update_backup_"
SERVICE_PORT = 8770

# ---------- 更新源（发布库）----------
# 为什么做成可配置：本项目有两类库——
#   · **工程测试库**（日常迭代、带全套回归脚本）：`Lyum1d/MY-AGENT`
#   · **正式发布库**（只放运行组件，供对外分发）：另建仓库，由 release_repo.txt 指定
# 更新器必须知道该从哪一个拉。仓库名按下面的顺序解析（越靠前越优先）：
#   1) 环境变量 `SRC_AGENT_REPO`（owner/repo）—— 临时切换与排障用，不落盘
#   2) 同目录 `release_repo.txt` 的第一行有效内容 —— **发布时只改这一行，
#      不需要重新打包 update.exe**（网址是运行时拼的）
#   3) 内置默认值 —— 文件缺失/内容非法时的回退，保持原行为（工程测试库）
# 这样同一份 update.py 在两类库里都正确，**不必维护两个分支**。
DEFAULT_REPO = "Lyum1d/MY-AGENT"
REPO_FILE = "release_repo.txt"
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent


def resolve_repo(root: Path | None = None) -> tuple[str, str]:
    """解析更新源仓库，返回 (owner/repo, 来源说明)。绝不抛异常。"""
    env = (os.environ.get("SRC_AGENT_REPO") or "").strip()
    if env:
        if _REPO_RE.match(env):
            return env, "环境变量 SRC_AGENT_REPO"
    f = (root or ROOT) / REPO_FILE
    if f.exists():
        try:
            for raw in f.read_text(encoding="utf-8-sig").splitlines():
                ln = raw.strip()
                if not ln or ln.startswith("#"):
                    continue
                if _REPO_RE.match(ln):
                    return ln, REPO_FILE
                break        # 第一行有效内容不合法 ⇒ 不继续往下猜，直接回退
        except OSError:
            pass
    return DEFAULT_REPO, "内置默认值"


REPO, REPO_SOURCE = resolve_repo()
RAW_VERSION_URL = f"https://raw.githubusercontent.com/{REPO}/main/VERSION.txt"
ZIPBALL_URL = f"https://codeload.github.com/{REPO}/zip/refs/heads/main"

# 更新时原样保留、绝不覆盖的本机内容（相对项目根）。
# 这些路径不在 GitHub 仓库里（或属于本机专有数据），zip 中不出现，天然不被触碰；
# 唯一例外是 config.yaml：首次安装时由 config.yaml.example 生成。
KEEP_PATHS = ("config.yaml", ".venv", "SRC控制台.exe", "dist", "logs")
# data/ 内「以新版为准」的目录（知识库/规则要随版本更新）
DATA_NEW_WINS = ("kb", "rules")
# data/ 内「以本机为准」的文件/目录（zip 里的同名模板绝不覆盖本机数据）
DATA_KEEP_WINS = ("projects.db", "scope.json", "usage_prices.json",
                  "artifacts", "scripts", "llm_providers.json")

# 注：`ROOT` 已在文件上半部分、与更新源一起定义（网址要在那时就拼出来）。


# ---------- 网络 ----------
def _opener(proxy: str):
    if proxy.strip():
        handler = urllib.request.ProxyHandler({
            "http": proxy.strip(), "https": proxy.strip(),
        })
        return urllib.request.build_opener(handler)
    return urllib.request.build_opener()  # 默认（跟随系统代理）


def http_get(url: str, proxy: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "src-agent-updater/1.0"})
    with _opener(proxy).open(req, timeout=timeout) as r:
        return r.read()


def http_get_stream(url: str, proxy: str, on_progress, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "src-agent-updater/1.0"})
    chunks: list[bytes] = []
    with _opener(proxy).open(req, timeout=timeout) as r:
        total = int(r.headers.get("Content-Length") or 0)
        got = 0
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
            if on_progress:
                on_progress(got, total)
    return b"".join(chunks)


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ---------- 多源获取（v104 修复：取不到库版本 / 界面无响应）----------
# 2026-10-11 实测的故障链（本机复现）：
#   · hosts 把 raw.githubusercontent.com 钉到 127.0.0.1（Steam++ 加速器的屏蔽段）；
#   · 127.0.0.1:443 上那个本地加速器对该 SNI **只挂住、不响应**（同一端口对
#     api.github.com 却 0.3s 秒回）⇒ 任何走 raw 的请求都要等满超时；
#   · 原来的「检查更新」把这次网络调用放进了 Tk 的 `after()` 回调里，等于在**主线程**
#     做网络 I/O ⇒ 30 秒窗口冻结（"无响应"），异常又被 Tk 吞掉、日志还打印旧值；
#   · 更隐蔽：SHA256SUMS.txt 也走 raw ⇒ 取不到清单被 verify_extracted 当成
#     "远端没有清单"，打一行警告就**静默跳过完整性校验**（安全降级）。
# 处置：同一个仓库准备多个等价入口，**并行竞速**取第一个有效结果。
#   任一可达即可用；最坏耗时 = 单源超时，而不是各源超时之和（串行时排在前面的
#   死源会把每次检查都拖满——而 raw 恰恰是最"名正言顺"该排第一的官方源）。
_SOURCE_TIMEOUT = 8.0     # 单源超时（秒）
_SOURCE_DEADLINE = 9.0    # 竞速总闸（秒）：兜住 DNS 解析等不受 socket 超时约束的慢路径
_MAX_VERSION_LEN = 32


def _fetch_text(url: str, proxy: str, timeout: float) -> str:
    return http_get(url, proxy, timeout=int(timeout)).decode("utf-8", "replace").strip()


def _fetch_api_content(url: str, proxy: str, timeout: float) -> str:
    """GitHub contents API：文件正文在 JSON 的 `content` 字段里，且是 base64。"""
    import base64
    d = json.loads(_fetch_text(url, proxy, timeout))
    if not isinstance(d, dict) or not d.get("content"):
        raise ValueError("API 响应里没有 content 字段")
    return base64.b64decode(d["content"]).decode("utf-8", "replace").strip()


def _api_contents_url(path: str) -> str:
    return f"https://api.github.com/repos/{REPO}/contents/{path}?ref=main"


def fetch_first(sources: list, proxy: str, decode=None,
                prefer: tuple | None = None, grace: float = 0.0) -> tuple[str, str]:
    """并行请求多个等价入口，返回 (内容, 源名)。全部失败抛 RuntimeError（附各源原因）。

    decode(u, proxy, timeout)：自定义响应解析（如 API 的 base64）。
    prefer + grace：给「官方源」一个 grace 秒的独占窗口。CDN 有 12 小时缓存，
      内容可能滞后——版本号滞后会误报「已是最新」，因此不该抢在官方源前面；
      只有官方源在窗口内全都无响应时，才采用 CDN 的结果。
    第一个可用的优先源（或窗口用尽后的第一个成功者）立即返回，不串行等死源。
    """
    decode = decode or _fetch_text
    prefer = tuple(prefer or ())
    results: dict = {}
    errors: dict = {}

    def worker(name: str, url: str) -> None:
        try:
            text = decode(url, proxy, _SOURCE_TIMEOUT)
            if not text:
                raise ValueError("响应为空")
            results[name] = text
        except Exception as e:                                   # noqa: BLE001
            errors[name] = f"{type(e).__name__}: {e}"

    workers = [threading.Thread(target=worker, args=(n, u), daemon=True)
               for n, u in sources]
    for t in workers:
        t.start()
    t0 = time.time()
    while True:
        if results:
            for n in prefer:
                if n in results:
                    return results[n], n
            # 优先源还有在途的 ⇒ 再等一会儿；都结束了 ⇒ 立刻用兜底源
            pending = [n for n in prefer if n not in results and n not in errors]
            if not pending or time.time() - t0 >= grace:
                n = next(iter(results))
                return results[n], n
        if len(results) + len(errors) >= len(workers):
            break
        if time.time() - t0 >= _SOURCE_DEADLINE:
            break
        time.sleep(0.05)
    if results:
        n = next(iter(results))
        return results[n], n
    detail = "；".join(f"{n} → {e}" for n, e in errors.items()) or "全部超时"
    raise RuntimeError(f"所有更新源都不可用（{detail}）")


def network_hint() -> str:
    """取不到远端内容时的可操作提示（把本机实测踩过的坑直接写出来）。"""
    return ("提示：若上面几条都是超时，优先排查这两处 ——\n"
            "  ① C:\\Windows\\System32\\drivers\\etc\\hosts 中是否有把 github 相关域名\n"
            "     指向 127.0.0.1 的行（加速器/去广告工具的屏蔽段会让请求被"
            "\"挂住\"而不是快速失败）；有则删掉或注释掉该行。\n"
            "  ② 在本工具「网络」栏填写可用代理后重试（如 http://127.0.0.1:7890）。")


# ---------- 版本 ----------
def local_version(root: Path) -> str:
    f = root / VERSION_FILE
    return f.read_text(encoding="utf-8").strip() if f.exists() else "未安装/未知"


# 「官方源」= 内容永远实时（不会被 CDN 缓存）。CDN 只当兜底，见 fetch_first 的 prefer/grace。
_OFFICIAL_SOURCES = ("raw.githubusercontent.com", "api.github.com", "github.com/raw")
_VERSION_GRACE = 2.0      # 给官方源的独占窗口（秒）


def version_sources() -> list[tuple[str, str]]:
    """VERSION.txt 的多个等价入口（清单顺序仅用于排障展示，实际是并行竞速）。"""
    return [
        ("raw.githubusercontent.com", RAW_VERSION_URL),
        ("api.github.com", _api_contents_url(VERSION_FILE)),
        ("github.com/raw", f"https://github.com/{REPO}/raw/main/{VERSION_FILE}"),
        ("cdn.jsdelivr.net", f"https://cdn.jsdelivr.net/gh/{REPO}@main/{VERSION_FILE}"),
    ]


def _decode_version(url: str, proxy: str, timeout: float) -> str:
    """解析版本响应并做形态校验 —— 防止把 HTML 错误页/多行内容当成版本号。"""
    fetch = _fetch_api_content if "api.github.com" in url else _fetch_text
    text = (fetch(url, proxy, timeout) or "").strip()
    if (not text or len(text) > _MAX_VERSION_LEN
            or any(c.isspace() for c in text) or "<" in text):
        raise ValueError(f"内容不像版本号：{text[:32]!r}")
    return text


def remote_version_detail(proxy: str) -> tuple[str, str]:
    """返回 (远端版本号, 来源名)。取不到时抛 RuntimeError。"""
    return fetch_first(version_sources(), proxy, decode=_decode_version,
                       prefer=_OFFICIAL_SOURCES, grace=_VERSION_GRACE)


def remote_version(proxy: str) -> str:
    return remote_version_detail(proxy)[0]


# ---------- 包完整性校验（v010 P2-4）----------
# 背景：更新器此前对下载包零校验（纯靠 HTTPS），GitHub 账号失守或传输被篡改时
#   恶意代码会被静默铺到所有成员机器——更新器是整条供应链的入口。
# 方案：仓库根的 SHA256SUMS.txt（发布入口在 bump 版本的同一 commit 内生成），
#   每行「<sha256>  <仓库相对路径>」。为什么校验**解压后的逐文件**而不是下载包
#   整体哈希：codeload 的 zipball 内容含目录时间戳等，字节不具确定性，整体哈希
#   任何一次下载都可能不同；逐文件哈希同样能捕获「任何一个文件被篡改」，
#   且对 .bat/.cmd/.ps1（更新器会做 CRLF 归一，落盘后内容必然与仓库不同）
#   跳过校验。远端暂无清单（010 之前的版本）时警告并跳过——不做硬失败，
#   避免升级链路被自己掐断。
# 注：URL 与 `REPO` 一起解析（见文件上半部分「更新源」），改 release_repo.txt 即生效。
RAW_SHA_URL = f"https://raw.githubusercontent.com/{REPO}/main/SHA256SUMS.txt"
_SHA_LINE_RE = re.compile(r"^[0-9a-fA-F]{64}\s+\S")


def sum_sources() -> list[tuple[str, str]]:
    """SHA256SUMS.txt 的多个等价入口（v104）。

    与版本同因同治：只走 raw 时，取不到清单会被当成「远端没有清单」而**静默跳过校验**，
    那是比"取不到版本"更严重的安全降级。
    ⚠️ 这里**不列入 CDN 源**：jsDelivr 对 @main 有 12 小时缓存，可能返回旧清单，
    与刚发布的 zip 逐文件比对必然全红 ⇒ 使用者直接装不上（比跳过校验更糟）。
    """
    return [
        ("raw.githubusercontent.com", RAW_SHA_URL),
        ("api.github.com", _api_contents_url("SHA256SUMS.txt")),
        ("github.com/raw", f"https://github.com/{REPO}/raw/main/SHA256SUMS.txt"),
    ]


def _decode_sums(url: str, proxy: str, timeout: float) -> str:
    """解析清单响应，并做形态校验——避免把 HTML 错误页当成空清单。"""
    fetch = _fetch_api_content if "api.github.com" in url else _fetch_text
    text = fetch(url, proxy, timeout) or ""
    if not any(_SHA_LINE_RE.match(l.strip()) for l in text.splitlines()):
        raise ValueError("内容不像 SHA256SUMS 清单（没有 <64位hex> 行）")
    return text


def _load_sums(proxy: str, log=None) -> dict[str, str]:
    """拉取远端 SHA256SUMS.txt → {相对路径: sha256}。全部源失败时返回空 dict。"""
    try:
        sums, src = fetch_first(sum_sources(), proxy, decode=_decode_sums)
        if log:
            log(f"完整性清单来源：{src}")
    except Exception as e:                                       # noqa: BLE001
        if log:
            log(f"[警告] 完整性清单获取失败：{e}")
        return {}
    out: dict[str, str] = {}
    for line in sums.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            out[parts[1].strip().replace("\\", "/")] = parts[0].strip().lower()
    return out


def verify_extracted(tmp_root: Path, extracted: list[str], proxy: str, log) -> bool:
    """对照 SHA256SUMS.txt 逐文件校验解压结果。返回 False = 必须中止安装。"""
    import hashlib
    sums = _load_sums(proxy, log)
    if not sums:
        # 这里原先只有一句「远端未提供清单」——实测恰恰相反：清单一直在，是网络取不到。
        # 把「取不到」说成「没有」会让人放弃排查，也会把安全降级藏起来。
        log("[警告] 未能获取远端 SHA256SUMS.txt，本次跳过完整性校验。")
        log("[警告] 注意：发布库自 1.001 起必带该清单，取不到通常是网络/域名问题"
            "（失败原因见上一行），不代表远端没有清单。")
        log(network_hint())
        return True
    bad: list[str] = []
    checked = 0
    for rel in extracted:
        if rel.lower().endswith((".bat", ".cmd", ".ps1")):
            continue    # CRLF 归一已改写内容，哈希必然不同（见 normalize_crlf）
        expected = sums.get(rel)
        if not expected:
            log(f"[警告] 清单中没有 {rel} 的条目，跳过该文件校验。")
            continue
        p = tmp_root / rel
        try:
            actual = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError as e:
            bad.append(f"{rel}（读取失败：{e}）")
            continue
        checked += 1
        if actual != expected:
            bad.append(rel)
    log(f"完整性校验：{checked} 个文件与发布清单比对。")
    if bad:
        log("[严重] 以下文件与发布清单不匹配：")
        for r in bad[:20]:
            log(f"    ✗ {r}")
        log("下载内容可能被篡改，已中止安装。请勿重试覆盖校验，先核实网络环境。")
        return False
    log("完整性校验通过。")
    return True


def _safe_zip_rel(rel: str) -> bool:
    """Zip Slip 防护：相对路径不得含 .. 段、盘符、绝对路径前缀。

    CPython 的 zipfile 对绝对路径有一定净化，但这里是逐成员自写落盘，
    必须自己把关——`..\\evil.py` 拼出来就是 tmp_root 之外的任意写。
    """
    if not rel or rel.strip() != rel:
        return False
    if re.match(r"^[A-Za-z]:", rel) or rel.startswith(("/", "\\")):
        return False
    parts = re.split(r"[\\/]+", rel)
    return ".." not in parts and "" not in parts


# ---------- data 合并策略 ----------
def zip_data_plan(zf: zipfile.ZipFile, root: Path) -> tuple[list[str], list[str]]:
    """返回 (新版要覆盖的 data 相对路径, 本机已有则跳过的 data 相对路径)。"""
    overwrite, skip_if_exists = [], []
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        parts = name.split("/", 1)
        if len(parts) < 2 or parts[1] == "":
            continue
        rel = parts[1]  # zip 顶层目录去掉后的相对路径
        if not rel.startswith("data/"):
            continue
        rest = rel[len("data/"):]
        top = rest.split("/", 1)[0] if "/" in rest else rest
        if top in DATA_NEW_WINS:
            overwrite.append(rel)
        elif top in DATA_KEEP_WINS:
            skip_if_exists.append(rel)
        else:
            # 其它 data 文件：本机有则保留，没有则补入
            (skip_if_exists if (root / rel).exists() else overwrite).append(rel)
    return overwrite, skip_if_exists


def is_first_install(root: Path) -> bool:
    return not (root / "app").exists()


# ---------- 换行符归一（批处理必须 CRLF，否则启动器被打坏）----------
# 为什么必须在这里兜：更新包在 Linux 侧打包，zip 里的 .bat 是 LF。
# cmd.exe 解析 LF 批处理时，遇到多字节字符（中文提示）会算错行偏移，
# 把脚本切碎执行，表现为双击后满屏「'xx' 不是内部或外部命令」——启动器彻底不可用。
# 这个故障每更新一次就会复现一次（已实测：v004/v006 两个版本落盘的 .bat 都是 LF + 中文），
# 所以不能只靠修包里的那一个文件，必须在落盘这一步强制归一。
CRLF_REQUIRED_EXT = (".bat", ".cmd", ".ps1")


def normalize_crlf(data: bytes) -> bytes:
    """把任意换行（CRLF / 裸 LF / 裸 CR）统一成 CRLF。"""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")


# ---------- 更新核心 ----------
def do_update(root: Path, proxy: str, log, progress) -> None:
    """执行更新（在工作线程中调用）。抛异常即失败。"""
    if port_in_use(SERVICE_PORT):
        raise RuntimeError(f"服务正在运行（端口 {SERVICE_PORT}）。请先关闭 src-agent 再更新。")

    try:
        remote_v = remote_version(proxy)
    except Exception as e:                                       # noqa: BLE001
        # 取不到远端版本时给可操作的话，而不是把 urllib 的超时原文糊到界面上
        raise RuntimeError(f"获取远端版本失败：{e}\n{network_hint()}") from e
    local_v = local_version(root)
    if remote_v == local_v:
        log(f"已是最新版本（{local_v}），无需更新。")
        return

    log(f"发现新版本：{local_v} → {remote_v}")
    progress(0.02)
    log("正在下载最新代码包…")
    data = http_get_stream(ZIPBALL_URL, proxy, lambda got, total: progress(
        0.05 + 0.45 * got / total if total else 0.25))
    log(f"下载完成（{len(data) / 1024 / 1024:.1f} MB），解压中…")
    progress(0.55)

    import io
    zf = zipfile.ZipFile(io.BytesIO(data))
    overwrite, skip_if_exists = zip_data_plan(zf, root)

    tmp_root = root / f"_update_tmp_{int(time.time())}"
    tmp_root.mkdir(exist_ok=True)
    # 解压（去掉 zip 顶层目录；v010：Zip Slip 防护，含 .. / 盘符 / 绝对路径的
    # 成员一律跳过并告警——绝不写到 tmp_root 之外）
    extracted = []
    for name in zf.namelist():
        if name.endswith("/"):
            continue
        parts = name.split("/", 1)
        if len(parts) < 2 or parts[1] == "":
            continue
        rel = parts[1]
        if not _safe_zip_rel(rel):
            log(f"[警告] 跳过可疑压缩成员（路径不安全）：{name}")
            continue
        target = tmp_root / rel
        # resolve 后仍在 tmp_root 内，双保险
        try:
            if not str(target.resolve()).startswith(str(tmp_root.resolve())):
                log(f"[警告] 跳过越界压缩成员：{name}")
                continue
        except OSError:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = zf.read(name)
        if rel.lower().endswith(CRLF_REQUIRED_EXT):
            payload = normalize_crlf(payload)
        target.write_bytes(payload)
        extracted.append(rel)
    log(f"解压完成：{len(extracted)} 个文件")
    progress(0.60)
    # v010：对照发布清单逐文件校验（在替换任何本机文件之前）
    if not verify_extracted(tmp_root, extracted, proxy, log):
        shutil.rmtree(tmp_root, ignore_errors=True)
        raise RuntimeError("完整性校验失败，已中止安装（本机文件未被改动）。")
    progress(0.68)

    # 备份目录：记录被替换的旧文件（支持回滚）
    backup = root / f"{BACKUP_PREFIX}{int(time.time())}"
    backup.mkdir(exist_ok=True)
    manifest = {"version_from": local_v, "version_to": remote_v,
                "replaced": [], "added": [], "kept": []}

    # 1) data 合并：新版 kb/rules 覆盖（保证知识库能随版本更新）；
    #    本机专有文件（db/scope 等）只在缺失时补入，绝不覆盖；
    #    本机已有的一般文件（config.yaml 之外的非知识库数据）保留本机版本。
    for rel in overwrite:
        src = tmp_root / rel
        if not src.exists():
            continue
        dst = root / rel
        if dst.exists():
            bak = backup / rel
            bak.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dst, bak)
            manifest["replaced"].append(rel)
        else:
            manifest["added"].append(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    for rel in skip_if_exists:
        dst = root / rel
        src = tmp_root / rel
        if not dst.exists() and src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            manifest["added"].append(rel)
            log(f"已补入新文件：{rel}")

    # 2) 其余文件（app/web/run.py 等）：旧文件入备份，新文件就位。
    #    KEEP_PATHS（config.yaml/.venv/桌面壳等）不在 zip 中，天然不被触碰。
    for rel in extracted:
        if rel.startswith("data/"):
            continue
        if rel in KEEP_PATHS or rel.startswith(tuple(p + "/" for p in KEEP_PATHS)):
            continue
        src = tmp_root / rel
        dst = root / rel
        if dst.exists():
            bak = backup / rel
            bak.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dst, bak)
            manifest["replaced"].append(rel)
        else:
            manifest["added"].append(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    # 3) 首次安装：补 config.yaml
    if is_first_install(root) and (root / "config.yaml.example").exists() \
            and not (root / "config.yaml").exists():
        shutil.copy2(root / "config.yaml.example", root / "config.yaml")
        log("已生成默认 config.yaml（本机路径与授权白名单需自行核对）")

    # 4) 落 manifest（回滚依据）并清理临时
    (backup / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    shutil.rmtree(tmp_root, ignore_errors=True)
    progress(0.98)
    log(f"✔ 更新完成：{local_v} → {remote_v}（旧文件备份于 {backup.name}）")
    log("双击「启动控制台.bat」即可使用新版本。")
    progress(1.0)


def do_rollback(root: Path, log, progress) -> None:
    """回滚：按 manifest 把备份的旧文件放回，删除更新新增的文件。"""
    backups = sorted(root.glob(f"{BACKUP_PREFIX}*"), reverse=True)
    if not backups:
        raise RuntimeError("没有可回滚的备份。")
    backup = backups[0]
    manifest_path = backup / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("备份缺少 manifest.json，无法自动回滚。")
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    progress(0.1)
    for rel in m.get("added", []):
        p = root / rel
        if p.exists():
            p.unlink()
            log(f"已移除新增文件：{rel}")
    for rel in m.get("replaced", []):
        bak = backup / rel
        dst = root / rel
        if bak.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bak, dst)
            log(f"已还原：{rel}")
    # 版本号回写
    (root / VERSION_FILE).write_text(m.get("version_from", ""), encoding="utf-8")
    shutil.rmtree(backup, ignore_errors=True)
    progress(1.0)
    log(f"✔ 已回滚到版本 {m.get('version_from')}（备份已清除）")


def do_venv(root: Path, log, progress, py_exe: str) -> None:
    """首次安装辅助：创建 .venv 并安装依赖。"""
    import subprocess
    if (root / ".venv").exists():
        log(".venv 已存在，跳过。")
        return
    log(f"用 {py_exe} 创建虚拟环境 .venv …")
    progress(0.2)
    subprocess.run([py_exe, "-m", "venv", str(root / ".venv")], check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
    pip = root / ".venv" / "Scripts" / "python.exe"
    log("安装 requirements.txt 依赖（可能需要几分钟）…")
    progress(0.4)
    r = subprocess.run([str(pip), "-m", "pip", "install", "-r", str(root / "requirements.txt"),
                        "-i", "https://pypi.tuna.tsinghua.edu.cn/simple"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        log("依赖安装失败：\n" + (r.stderr or r.stdout)[-600:])
        raise RuntimeError("pip install 失败，请查看日志")
    progress(1.0)
    log("✔ 虚拟环境与依赖安装完成，可双击「启动控制台.bat」启动。")


# ---------- GUI ----------
class App:
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk
        self.root = tk.Tk()
        self.root.title("SRC Agent 更新工具")
        self.root.geometry("720x520")
        self.root.minsize(640, 460)
        self.proxy = tk.StringVar(value=self._load_proxy())
        self.local_v = tk.StringVar(value=local_version(ROOT))
        self.remote_v = tk.StringVar(value="（未检查）")
        self._build()
        self.root.after(300, self.thread_check)

    # -- 状态持久化（代理地址） --
    def _load_proxy(self) -> str:
        f = ROOT / UPDATER_STATE
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8")).get("proxy", "")
            except Exception:
                return ""
        return ""

    def _save_proxy(self) -> None:
        try:
            (ROOT / UPDATER_STATE).write_text(
                json.dumps({"proxy": self.proxy.get().strip()}, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    # -- 界面 --
    def _build(self) -> None:
        tk, ttk = self.tk, self.ttk  # 延迟导入的模块从实例取
        f = ttk.Frame(self.root, padding=14)
        f.pack(fill="both", expand=True)

        head = ttk.Frame(f)
        head.pack(fill="x")
        ttk.Label(head, text="SRC Agent 更新工具", font=("Microsoft YaHei", 15, "bold")).pack(side="left")
        ttk.Label(head, text=f"  目录：{ROOT}", foreground="#888").pack(side="left", padx=8)

        ver = ttk.LabelFrame(f, text=" 版本 ", padding=10)
        ver.pack(fill="x", pady=(10, 6))
        ttk.Label(ver, text="当前版本：").grid(row=0, column=0, sticky="w")
        ttk.Label(ver, textvariable=self.local_v, font=("Consolas", 11, "bold")).grid(row=0, column=1, sticky="w")
        ttk.Label(ver, text="GitHub 最新：").grid(row=1, column=0, sticky="w")
        ttk.Label(ver, textvariable=self.remote_v, font=("Consolas", 11, "bold")).grid(row=1, column=1, sticky="w")
        # 把「更新源」显式摆出来：换库后"点了更新却没反应/拉回旧库"最常见的原因
        # 就是不知道该看哪里 —— 这里直接告诉使用者当前从哪个仓库拉、值从哪来。
        ttk.Label(ver, text="更新源：").grid(row=2, column=0, sticky="w")
        ttk.Label(ver, text=f"{REPO}（{REPO_SOURCE}）",
                  foreground="#7a8899").grid(row=2, column=1, columnspan=2, sticky="w")
        ttk.Button(ver, text="检查更新", command=self.thread_check).grid(row=0, column=2, rowspan=2, padx=8)

        net = ttk.LabelFrame(f, text=" 网络（可选） ", padding=8)
        net.pack(fill="x", pady=4)
        ttk.Label(net, text="代理地址（连不上 GitHub 时填，如 http://127.0.0.1:7890）：").pack(side="left")
        ttk.Entry(net, textvariable=self.proxy, width=32).pack(side="left", padx=6)
        ttk.Button(net, text="保存", command=self._save_proxy).pack(side="left")

        self.progress = ttk.Progressbar(f, mode="determinate", maximum=1.0)
        self.progress.pack(fill="x", pady=8)

        btns = ttk.Frame(f)
        btns.pack(fill="x", pady=4)
        self.btn_update = ttk.Button(btns, text="更新到最新版本", command=self.thread_update)
        self.btn_update.pack(side="left")
        self.btn_rollback = ttk.Button(btns, text="回滚上次更新", command=self.thread_rollback)
        self.btn_rollback.pack(side="left", padx=8)
        self.venv_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(btns, text="首次安装后自动创建虚拟环境并装依赖（需本机已装 Python）",
                        variable=self.venv_var).pack(side="left", padx=8)

        ttk.Label(f, text="日志：").pack(anchor="w")
        self.logbox = tk.Text(f, height=14, state="disabled", font=("Consolas", 9),
                              background="#101418", foreground="#cfe3cf")
        self.logbox.pack(fill="both", expand=True)

    # -- 工具 --
    def log(self, msg: str) -> None:
        def _append():
            self.logbox.configure(state="normal")
            self.logbox.insert("end", time.strftime("[%H:%M:%S] ") + msg + "\n")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        self.root.after(0, _append)

    def set_progress(self, v: float) -> None:
        self.root.after(0, lambda: self.progress.configure(value=max(0, min(1, v))))

    def _busy(self, busy: bool) -> None:
        def _set():
            for b in (self.btn_update, self.btn_rollback):
                b.configure(state="disabled" if busy else "normal")
        self.root.after(0, _set)

    def _run_bg(self, fn, *args):
        def worker():
            self._busy(True)
            try:
                fn(*args)
            except Exception as e:
                self.log(f"✘ 失败：{e}")
                self.set_progress(0)
            finally:
                self._busy(False)
                self.root.after(0, lambda: self.local_v.set(local_version(ROOT)))
        threading.Thread(target=worker, daemon=True).start()

    # -- 动作 --
    def thread_check(self):
        def job():
            # ⚠️ 网络调用必须留在**本工作线程**里。旧写法是
            #   `self.root.after(0, lambda: self.remote_v.set(remote_version(...)))`
            # —— 取值被塞进了 Tk 回调，等于在主线程做网络 I/O：
            #   · 主循环被占住 ⇒ 窗口假死（超时多长就冻多久，表现为"无响应"）；
            #   · 回调里抛的异常被 Tk 吞掉 ⇒ 版本栏永远停在「（未检查）」；
            #   · 紧随其后的 log 读到的还是旧值 ⇒ 日志"显示"旧版本，看着像已是最新。
            self.root.after(0, lambda: self.remote_v.set("检查中…"))
            self.log(f"正在检查最新版本（{len(version_sources())} 个入口并行竞速）…")
            try:
                v, src = remote_version_detail(self.proxy.get())
            except Exception as e:                               # noqa: BLE001
                self.root.after(0, lambda: self.remote_v.set("获取失败（见日志）"))
                self.log(f"✘ 获取远端版本失败：{e}")
                self.log(network_hint())
                return                      # 就地消化，别让 _run_bg 再报一次
            self.root.after(0, lambda: self.remote_v.set(v))
            self.log(f"最新版本：{v}（来源：{src}）")
            if v == local_version(ROOT):
                self.log("已是最新版本，无需更新。")
            else:
                self.log(f"发现新版本（{local_version(ROOT)} → {v}），"
                         "点「更新到最新版本」即可。")
        self._run_bg(job)

    def thread_update(self):
        def job():
            do_update(ROOT, self.proxy.get(), self.log, self.set_progress)
            if is_first_install(ROOT) and self.venv_var.get():
                py = shutil.which("python") or shutil.which("py")
                if py:
                    self.log(f"检测到本机 Python：{py}")
                    do_venv(ROOT, self.log, self.set_progress, py)
                else:
                    self.log("未检测到本机 Python，无法自动创建虚拟环境；"
                             "请先安装 Python 3.10+ 再重跑本工具，"
                             "或手动准备 .venv 并执行 pip install -r requirements.txt。")
        self._run_bg(job)

    def thread_rollback(self):
        self._run_bg(do_rollback, ROOT, self.log, self.set_progress)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
