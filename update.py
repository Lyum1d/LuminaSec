# -*- coding: utf-8 -*-
"""SRC Agent 更新工具（update.exe 源码）。

功能：
  1. 版本比对：本地 VERSION.txt vs GitHub main 的 VERSION.txt
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


# ---------- 版本 ----------
def local_version(root: Path) -> str:
    f = root / VERSION_FILE
    return f.read_text(encoding="utf-8").strip() if f.exists() else "未安装/未知"


def remote_version(proxy: str) -> str:
    return http_get(RAW_VERSION_URL, proxy).decode("utf-8").strip()


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


def _load_sums(proxy: str) -> dict[str, str]:
    """拉取远端 SHA256SUMS.txt → {相对路径: sha256}。失败/不存在返回空 dict。"""
    try:
        sums = http_get(RAW_SHA_URL, proxy, timeout=15).decode("utf-8")
    except Exception:
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
    sums = _load_sums(proxy)
    if not sums:
        log("[警告] 远端未提供 SHA256SUMS.txt，本次跳过完整性校验（建议尽快升级到带清单的版本）。")
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

    remote_v = remote_version(proxy)
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
            self.log("正在检查 GitHub 最新版本…")
            self.root.after(0, lambda: self.remote_v.set(remote_version(self.proxy.get())))
            self.log(f"最新版本：{self.remote_v.get()}")
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
