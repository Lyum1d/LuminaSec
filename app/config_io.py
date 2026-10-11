# -*- coding: utf-8 -*-
"""配置文件的读写基础设施（v050 配置控制台）。

控制台要改的都是**关系到授权红线**的文件（授权白名单、工具分级、闸门开关）。
手工编辑这几个文件时最怕的不是写错内容，而是：

  · **写坏文件**：`scope.json` 写一半中断 → JSON 解析失败 → `load_scope()` 返回空 →
    **所有工具被拒**（现象是「Agent 突然什么都做不了」，而原因是文件坏了）；
  · **改完没生效**：`tool_overrides.json` 改了但 `registry` 有缓存，
    服务继续用旧分级 → 操作者以为「禁用已生效」，其实没有；
  · **改了没人知道**：谁在什么时候把某个域加进白名单、把某个工具禁用，
    事后完全查不到。

本模块把这三件事各自收成一个函数，**所有写入面共用**（白名单 / 工具分级 / 运行参数 /
合规模板），避免每个面各写一套、然后其中一套漏掉备份或漏掉重载。

## 为什么写 `_atomic` 而不是直接 `write_text`

`path.write_text()` 先截断再写。如果在截断之后、写完之前进程被杀（或被
WorkBuddy 回收后台子进程 —— 本项目实测过），就留下一个**半截文件**。
`tempfile` 同目录写 + `os.replace()` 是 POSIX/Windows 上的原子替换：
读到的要么是完整旧文件，要么是完整新文件。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from . import config

logger = logging.getLogger(__name__)

# 每次写入前的备份目录（gitignored）
BACKUP_DIR = config.DATA_DIR / "console_backups"
# 配置变更审计（gitignored —— 里面会记真实授权 host，入库即公开泄露）
AUDIT_FILE = config.DATA_DIR / "console_audit.jsonl"
# 运行参数覆盖（gitignored：本机调优值，不该跟着仓库走）
OVERRIDES_FILE = config.DATA_DIR / "runtime_overrides.json"

BACKUP_KEEP = 20
# 单个字段/值的审计摘要长度上限（避免把整个 scope.json 塞进日志）
AUDIT_VALUE_MAX = 400


# ---------------------------------------------------------------- 读
def read_json(path: Path, default: Any = None) -> Any:
    """容错读取 JSON。文件不存在或解析失败返回 default（**不抛异常**）。

    与 `config_io` 的定位一致：调用方（控制台）需要的是「给我一个能渲染的状态」，
    而不是一个栈回溯。解析失败的事实会由 `health()` 单独暴露出来。
    """
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:                                    # noqa: BLE001
        logger.warning("读取 JSON 失败：%s", path, exc_info=True)
        return default


def file_sha256(path: Path) -> str:
    """文件内容的 sha256（十六进制）。文件不存在返回空串。"""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def sha256_short(path: Path, n: int = 12) -> str:
    """前 n 位短哈希，用于乐观锁与「文件是否被改过」的显示。"""
    return file_sha256(path)[:n]


def file_state(path: Path) -> dict:
    """给前端用的文件状态（存在/大小/修改时间/短哈希）。"""
    try:
        st = path.stat()
        return {
            "exists": True,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "sha256_short": sha256_short(path),
        }
    except OSError:
        return {"exists": False, "size": 0, "mtime": 0.0, "sha256_short": ""}


# ---------------------------------------------------------------- 写
def backup(path: Path, keep: int = BACKUP_KEEP) -> str:
    """写前备份。返回备份文件名（失败返回空串，**不阻断写入**）。

    为什么失败不阻断：备份是「事后能回滚」的保险，而写入本身是用户明确要做的动作。
    备份失败就拒绝写入，会把一个次要问题升级成主要问题（用户改不了配置）。
    但失败必须留日志 —— 否则「以为有备份、其实没有」比没有备份更糟。
    """
    try:
        if not path.exists():
            return ""
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        dst = BACKUP_DIR / f"{path.stem}.{stamp}.{path.suffix.lstrip('.') or 'json'}"
        # 同一秒内多次写 → 加序号，避免互相覆盖
        n = 1
        while dst.exists():
            n += 1
            dst = BACKUP_DIR / (f"{path.stem}.{stamp}_{n}."
                               f"{path.suffix.lstrip('.') or 'json'}")
        shutil.copy2(path, dst)
        _prune_backups(path.stem, keep)
        return dst.name
    except Exception:                                    # noqa: BLE001
        logger.warning("备份 %s 失败（写入将继续）", path, exc_info=True)
        return ""


def _prune_backups(stem: str, keep: int) -> None:
    """滚动保留最近 keep 份。"""
    try:
        items = sorted(BACKUP_DIR.glob(f"{stem}.*"), key=lambda p: p.stat().st_mtime)
        for old in items[:-keep] if len(items) > keep else []:
            old.unlink(missing_ok=True)
    except Exception:                                    # noqa: BLE001
        logger.debug("清理旧备份失败", exc_info=True)


def write_json_atomic(path: Path, data: Any, *, backup_first: bool = True) -> dict:
    """原子写 JSON。返回 {ok, backup, sha256_short, before_sha256_short, error}。

    实现要点：
      · 临时文件建在**同目录**（跨盘 rename 不是原子的）；
      · `ensure_ascii=False` + `indent=2` + 行尾 `\\n` —— 与仓库里既有 JSON 的
        风格一致，否则每次控制台写入都会在 git 里产生巨量格式 diff；
      · 写完 `os.replace` 原子替换，再显式 `fsync` 目录项（尽力而为）。
    """
    before = sha256_short(path)
    bk = backup(path) if backup_first else ""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.",
                                   suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)                        # 原子替换
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return {"ok": True, "backup": bk, "before_sha256_short": before,
                "sha256_short": sha256_short(path), "error": ""}
    except Exception as e:                               # noqa: BLE001
        logger.warning("原子写 %s 失败", path, exc_info=True)
        return {"ok": False, "backup": bk, "before_sha256_short": before,
                "sha256_short": before, "error": f"{type(e).__name__}: {e}"}


def write_text_atomic(path: Path, text: str, *, backup_first: bool = True) -> dict:
    """原子写文本（用于 `data/rules/*.md`）。"""
    before = sha256_short(path)
    bk = backup(path) if backup_first else ""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.",
                                   suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return {"ok": True, "backup": bk, "before_sha256_short": before,
                "sha256_short": sha256_short(path), "error": ""}
    except Exception as e:                               # noqa: BLE001
        logger.warning("原子写 %s 失败", path, exc_info=True)
        return {"ok": False, "backup": bk, "before_sha256_short": before,
                "sha256_short": before, "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------- 审计
def _summarize(v: Any) -> Any:
    """审计值摘要：过长的截断，避免审计文件被单次大改动撑爆。"""
    if isinstance(v, str) and len(v) > AUDIT_VALUE_MAX:
        return v[:AUDIT_VALUE_MAX] + f"…（共 {len(v)} 字符）"
    if isinstance(v, (list, dict)):
        s = json.dumps(v, ensure_ascii=False)
        if len(s) > AUDIT_VALUE_MAX:
            return s[:AUDIT_VALUE_MAX] + "…"
        return v
    return v


def audit(face: str, action: str, *, before: Any = None, after: Any = None,
          note: str = "", level: str = "low", actor: str = "console",
          extra: dict | None = None) -> bool:
    """追加一条配置变更审计（JSONL，一行一条）。

    返回是否写成功。**审计失败要留日志但不阻断** —— 理由与 backup 同。

    ⚠️ 审计内容会包含真实授权 host。因此：
      · 文件在 `data/` 且已加入 .gitignore（发布会做红线自检）；
      · 导出接口默认脱敏（见 console_api）。
    """
    rec = {
        "ts": time.time(),
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "face": face,
        "action": action,
        "level": level,
        "actor": actor,
        "note": note,
        "before": _summarize(before),
        "after": _summarize(after),
    }
    if extra:
        rec["extra"] = {k: _summarize(v) for k, v in extra.items()}
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return True
    except Exception:                                    # noqa: BLE001
        logger.warning("写审计失败：%s %s", face, action, exc_info=True)
        return False


def read_audit(limit: int = 200, face: str = "") -> list[dict]:
    """读最近 limit 条审计（倒序）。face 非空则过滤。"""
    try:
        if not AUDIT_FILE.exists():
            return []
        lines = AUDIT_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for ln in reversed(lines):
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except Exception:                                # noqa: BLE001
            continue
        if face and rec.get("face") != face:
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def mask_host(host: str, head: int = 3, tail: int = 3) -> str:
    """导出审计时的默认脱敏：域名只留前后各几字符。

    为什么需要：审计日志是为了**举证**，而举证材料经常要发给别人
    （平台、导师、队友）。默认脱敏能避免「为了举证把授权靶标列表整份发出去」。
    """
    h = (host or "").strip()
    if len(h) <= head + tail:
        return "*" * len(h)
    return f"{h[:head]}{'*' * (len(h) - head - tail)}{h[-tail:]}"


# ---------------------------------------------------------------- 重载
def write_many_atomic(items: list[tuple[Path, Any]]) -> dict:
    """按顺序原子写多个 JSON；**任一失败则把已写的回滚回去**。

    为什么需要它（v051 工具分级页）：改一个工具的「分级」写 `risk_grades.json`，
    改「禁用/超时/caps」写 `tool_overrides.json` —— 一次编辑可能同时动两个文件。
    分两次 `write_json_atomic` 的话，第二次失败会留下**半个改动**：
    分级改了、禁用没改，而操作者只看到一条报错，不知道到底生效了哪一半。

    回滚靠的是 `write_json_atomic` 本来就会做的写前备份 —— 不另存副本。
    返回 `{ok, written:[...], rolled_back:[...], error}`。
    """
    written: list[tuple[Path, str]] = []      # (path, 备份文件名)
    for path, data in items:
        res = write_json_atomic(path, data)
        if not res["ok"]:
            # 回滚已写的部分（用它们各自的写前备份）
            rolled: list[str] = []
            for p, bk in reversed(written):
                if not bk:
                    # 原本不存在 → 无法从备份恢复。删掉新建的文件，回到「不存在」。
                    try:
                        p.unlink(missing_ok=True)
                        rolled.append(p.name)
                    except OSError:
                        logger.warning("回滚删除 %s 失败", p)
                    continue
                try:
                    shutil.copy2(BACKUP_DIR / bk, p)
                    rolled.append(p.name)
                except Exception:                        # noqa: BLE001
                    logger.warning("回滚 %s 失败", p, exc_info=True)
            return {"ok": False, "written": [p.name for p, _ in written],
                    "rolled_back": rolled, "error": res["error"],
                    "failed": path.name}
        written.append((path, res["backup"]))
    return {"ok": True, "written": [p.name for p, _ in written],
            "rolled_back": [], "error": ""}


def read_text(path: Path) -> str:
    """读文本（不存在返回空串，不抛）。"""
    try:
        return path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError:
        return ""


def reload_for(face: str) -> dict:
    """写入后按面触发重载，返回「做了什么」供前端回显。

    为什么必须显式做这件事（本项目反复踩过同类问题）：
      · `scope.json` 每次调用现读，**无需重载** —— 但也没法确认，所以要回显一次
        `check_scope` 的实况，让操作者看到「确实生效了」；
      · `tool_overrides.json` / `risk_grades.json` 被 `registry` **缓存**，
        不重载的话服务继续用旧分级 —— 操作者以为「禁用已生效」，其实没有。
    """
    out = {"face": face, "actions": []}
    try:
        if face in ("tools", "invocation_templates"):
            from .registry import registry
            before = len(registry.tools)
            registry.load()
            out["actions"].append(f"registry 重载：{before} → {len(registry.tools)} 个工具")
            if face == "invocation_templates":
                # v052（复审报告 P2-F）：模板还要让 executor 重新载入。
                # `LocalExecutor.__init__` 里 `self.templates = load_templates()` 只跑一次，
                # 而 `executor` 是模块级单例 —— 不重载的话控制台改完模板，
                # **运行中的实例仍用旧模板**，直到重启。
                from .executor import executor as _exec
                n = _exec.reload_templates()
                out["actions"].append(f"executor 模板重载：{n} 条")
        elif face == "params":
            from . import config as cfg
            changed = apply_overrides(cfg)
            out["actions"].append(
                f"运行参数覆盖已应用：{len(changed)} 项" + (f"（{', '.join(changed)}）"
                                                      if changed else ""))
        elif face == "scope":
            out["actions"].append("scope.json 每次调用现读，无需重载")
        elif face == "rules":
            out["actions"].append("系统提示每轮重建，下一轮生效")
        elif face == "secrets":
            out["actions"].append("config.yaml 每次调用现读，无需重载")
    except Exception as e:                               # noqa: BLE001
        out["actions"].append(f"重载失败（已记录，不影响已写入的文件）：{e}")
        logger.warning("重载 %s 失败", face, exc_info=True)
    return out


# ---------------------------------------------------------------- 运行参数覆盖
# 首次被覆盖前各参数的**原值**快照。
# 为什么必须有它：`setattr` 改掉 config 属性之后，**原值就找不回来了**
# —— 环境变量与字面量默认值的差别在这一层已经看不出来（config 模块只留最终值）。
# 没有它的话「复位」只能把文件里的键删掉，而运行中的属性仍是覆盖后的值：
# 文件看着已复位、服务里其实没复位。这是 v051 端到端测试抓出来的。
_ORIGINALS: dict[str, Any] = {}


def apply_overrides(cfg=None) -> list[str]:
    """把 `runtime_overrides.json` 里的值 setattr 到 config 模块上，返回本次**变化**的键。

    两步，顺序不能反：
      ① **先还原**「曾经被覆盖、但现在不在覆盖文件里」的键（回到快照原值）——
         这是「复位 / 删除某个键」能真正生效的唯一方式；
      ② 再应用当前覆盖文件里的值（首次接触时记下原值快照）。

    可行性依据：全项目 **0 处** `from .config import X`，**220 处** `config.X`
    属性访问（调用时读取），所以运行时 `setattr` 立即对所有调用点生效 —— 不用重启。
    （详见 console 设计文档第 2.4 节。）

    安全性：只接受 config 模块里**已存在且当前是 int/float/bool/str** 的名字，
    绝不凭覆盖文件创建新属性 —— 否则一个手改的覆盖文件能往 config 里塞任意东西。
    """
    cfg = cfg or config
    data = read_json(OVERRIDES_FILE, default={}) or {}
    params = (data.get("params") or {}) if isinstance(data, dict) else {}
    changed: list[str] = []

    # ---- ① 还原已撤销的覆盖 ----
    for k in [k for k in _ORIGINALS if k not in params]:
        original = _ORIGINALS.pop(k)
        if getattr(cfg, k, None) != original:
            setattr(cfg, k, original)
            changed.append(k)

    # ---- ② 应用当前覆盖 ----
    for k, v in params.items():
        if not isinstance(k, str) or not k.isupper():
            continue
        cur = getattr(cfg, k, None)
        if isinstance(cur, bool):
            if not isinstance(v, bool):
                continue
        elif isinstance(cur, int) and not isinstance(cur, bool):
            if not isinstance(v, int) or isinstance(v, bool):
                continue
        elif isinstance(cur, float):
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                continue
        elif isinstance(cur, str):
            if not isinstance(v, str):
                continue
        else:
            # 模块里没有这个名字，或类型不支持 → 跳过（不创建新属性）
            continue
        if k not in _ORIGINALS:
            _ORIGINALS[k] = cur                     # 首次接触：记下原值
        if getattr(cfg, k) != v:
            setattr(cfg, k, v)
            changed.append(k)

    # 自检：覆盖之后不变量必须仍然成立，否则留一条明确的日志
    try:
        warns = cfg.param_warnings()
    except Exception:                                    # noqa: BLE001
        warns = []
    if warns:
        logger.warning("运行参数覆盖后不变量告警：%s", warns)
    return changed


def save_overrides(params: dict) -> dict:
    """写 `runtime_overrides.json`（并立即 apply）。**按传入内容整份覆盖，不再二次合并。**

    ⚠️ v051 修（端到端测试抓出）：原实现在这里又 `merged.update(params)` 合并了一次，
    于是「复位」失效 —— 调用方（`params_commit`）已经算好了「删掉某个键之后」的完整字典，
    交给本函数时又被磁盘上的旧内容**合并回来**，被删的键**原地复活**：
    文件看着改过了、运行值也没变，而界面上「复位成功」的提示照常出现。

    这是个很容易犯的错：**合并语义的函数无法表达「删除」**。
    所以这里改成「写什么就是什么」，把合并的责任明确交给调用方
    （它才知道这次操作是「新增/改值」还是「删除」）。
    """
    data = {"_说明": ("控制台（/console → 运行参数）写入的本机覆盖值。"
                     "优先级高于环境变量默认值，重启后仍生效。"
                     "删掉某个键即回到 env/默认值。本文件不入库。"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "params": dict(params or {})}
    return write_json_atomic(OVERRIDES_FILE, data)
