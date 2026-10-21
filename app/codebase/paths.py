# -*- coding: utf-8 -*-
"""受控根校验 + codebase 授权记录（实施规格 §4.4 / §9）。

## 这个文件存在的唯一理由

白盒工具里，**唯一一处做错就立刻泄露本机文件**的地方就是「按模型给的路径读代码」。
模型控制着 `code_read` 的路径参数，而它读到的内容会进上下文、可能发往云端。
一旦校验被绕过，`config.yaml`（FOFA 密钥）、`data/scope.json`（真实授权靶标）、
`.src_agent_llm.json`（API Key）全都能被读出来。

所以这里的规则只有一条，且**没有例外**：

> **路径解析成绝对路径之后，必须确认它在某个已入库 codebase 的受控根之内；
> 校验不出就拒绝。** —— fail-closed，与 `scope.py` 同一条纪律。

## 三条容易漏的绕过方式（都已在实现里堵住，且有测试）

1. **`..` 逃逸**：`../../config.yaml` —— 靠「先 `resolve()` 再比较」堵住
   （比较**解析后**的路径，而不是字符串拼出来的路径）；
2. **符号链接逃逸**：根目录里放一个指向外部的软链 —— `resolve()` 会跟随软链，
   所以解析后同样落在根外 → 被拒；
3. **大小写 / 短名 / 盘符等价**：Windows 路径大小写不敏感，`C:\\TBOX` 与 `c:\\tbox` 是同一个位置
   —— 靠 `os.path.normcase` 归一后再比较，避免「看起来在根内、实际在根外」（或反之）。

## 与 `data/scope.json` 的关系（刻意不共用）

`data/codebases.json` 是**独立**的授权记录，**不并入** `scope.json`：
白盒的授权对象是代码、不是域名（§4.4）。它同时起两个作用 ——
**既是授权凭据、也是审计记录**（谁、什么时候、把哪份代码放进来审）。
"""
from __future__ import annotations

import json
import os
import pathlib
from dataclasses import dataclass, field

from .. import config

# ---------------------------------------------------------------- 常量与异常

#: codebase 授权记录（**不入库**：里面是本机的代码根路径与审计对象）
CODEBASES_FILE = config.DATA_DIR / "codebases.json"

#: 白盒层级（§1.2）——**决定结论强度上限**，所以必须显式记录，不能靠猜
WHITE_LAYERS = ("full", "partial", "gray")

#: 代码来源（用户决策③：默认只放行开源；其余必须显式登记授权）
SOURCES = ("opensource", "authorized")

WHITE_LAYER_HELP = {
    "full": "全白：完整源码且能编译运行 —— 可静态找 + 动态验证，结论上限最高",
    "partial": "半白：有源码/字节码但跑不起来 —— 只能静态推导，结论须标注「未运行时验证」",
    "gray": "灰盒：只有反编译产物 / heapdump / debug 接口 —— 价值取决于信息量",
}


class PathEscapeError(ValueError):
    """请求的路径不在受控根内（或根本身不可用）。**调用方必须按拒绝处理。**"""


class CodebaseNotFound(LookupError):
    """codebase_id 不存在（未入库 / 记录被删）。"""


# ---------------------------------------------------------------- 记录

@dataclass
class Codebase:
    codebase_id: str
    root: pathlib.Path
    source: str = "opensource"          # opensource | authorized
    white_layer: str = "partial"        # full | partial | gray
    note: str = ""                      # 来源说明 / 授权凭据摘要（人工填）
    added_at: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def layer_help(self) -> str:
        return WHITE_LAYER_HELP.get(self.white_layer, "")


def _norm(p) -> str:
    """归一化用于比较的路径键。

    Windows 下路径大小写不敏感，且 `resolve()` 已经处理了 `..` 与符号链接；
    再加一层 `normcase` 是为了消除大小写差异，避免出现
    「看起来在根内、比较却不等」或反过来「比较相等、实际不同」的误判。
    """
    return os.path.normcase(str(pathlib.Path(p)))


def load_codebases() -> list[Codebase]:
    """读 `data/codebases.json`。文件不存在/解析失败一律返回空表（**不抛异常**）。

    返回空表而不是抛错，是因为「还没入库任何代码」是**正常初始状态**，
    调用方应当看到「没有可用 codebase"，而不是一个栈回溯。
    """
    try:
        if not CODEBASES_FILE.exists():
            return []
        raw = json.loads(CODEBASES_FILE.read_text(encoding="utf-8"))
    except Exception:                                        # noqa: BLE001
        return []
    items = raw.get("codebases") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return []
    out: list[Codebase] = []
    for it in items:
        if not isinstance(it, dict) or not it.get("codebase_id") or not it.get("root"):
            continue                                     # 缺字段的条目直接忽略（宁少不错）
        src = str(it.get("source") or "opensource").lower()
        layer = str(it.get("white_layer") or "partial").lower()
        out.append(Codebase(
            codebase_id=str(it["codebase_id"]),
            root=pathlib.Path(str(it["root"])),
            source=src if src in SOURCES else "opensource",
            white_layer=layer if layer in WHITE_LAYERS else "partial",
            note=str(it.get("note") or ""),
            added_at=str(it.get("added_at") or ""),
            extra={k: v for k, v in it.items()
                   if k not in ("codebase_id", "root", "source", "white_layer",
                                "note", "added_at")},
        ))
    return out


def get_codebase(codebase_id: str) -> Codebase | None:
    cid = (codebase_id or "").strip()
    if not cid:
        return None
    for cb in load_codebases():
        if cb.codebase_id == cid:
            return cb
    return None


# ---------------------------------------------------------------- 核心：受控根校验

def resolve_in_root(root, candidate) -> pathlib.Path:
    """把 `candidate` 解析到 `root` 之内；越界/异常一律抛 `PathEscapeError`。

    **fail-closed**：任何一步拿不准（根不存在、解析失败、比较不出结果）都拒绝。
    绝不返回「尽量猜一个」的路径。
    """
    try:
        root_p = pathlib.Path(root)
    except Exception as e:                                   # noqa: BLE001
        raise PathEscapeError(f"受控根不可解析：{e}") from e

    # 根本身必须是**已存在的目录**：否则「根内」这个判断没有意义
    try:
        if not root_p.exists():
            raise PathEscapeError(f"受控根不存在：{root_p}")
        if not root_p.is_dir():
            raise PathEscapeError(f"受控根不是目录：{root_p}")
    except PathEscapeError:
        raise
    except OSError as e:
        raise PathEscapeError(f"受控根不可访问：{e}") from e

    try:
        # ⚠️ 顺序很重要：**两边都先 resolve**，再做包含性比较。
        # 直接拼 root / candidate 再比较，会漏掉 `..` 与符号链接两种逃逸。
        root_r = root_p.resolve(strict=True)
    except OSError as e:
        raise PathEscapeError(f"受控根解析失败：{e}") from e

    cand = (candidate or "").strip()
    if not cand:
        raise PathEscapeError("路径为空")

    # 相对路径按「根内相对」解释（这是 code_read 的常规用法）；
    # 绝对路径也接受，但**必须**解析后仍落在根内 —— 由下面的包含性检查兜底。
    p = pathlib.Path(cand)
    if not p.is_absolute():
        p = root_r / p

    try:
        resolved = p.resolve(strict=False)
    except OSError as e:
        raise PathEscapeError(f"路径解析失败：{cand}（{e}）") from e

    if not _within(root_r, resolved):
        raise PathEscapeError(
            f"路径越出受控根，已拒绝：{cand}\n"
            f"  受控根：{root_r}\n  解析结果：{resolved}")

    # 再确认一次「解析后仍可访问」（strict=False 允许不存在，但存在时要是文件/目录）
    try:
        if resolved.exists() and not (resolved.is_file() or resolved.is_dir()):
            raise PathEscapeError(f"不是普通文件或目录：{resolved}")
    except OSError as e:
        raise PathEscapeError(f"路径不可访问：{e}") from e

    return resolved


def _within(root: pathlib.Path, target: pathlib.Path) -> bool:
    """`target` 是否等于 `root` 或在其之下（Windows 大小写不敏感）。

    不用 `Path.is_relative_to` 是因为它在 Windows 上大小写敏感，
    而 Windows 文件系统不敏感 —— 那会造成「同一个位置有两种判定」。
    """
    r, t = _norm(root), _norm(target)
    if r == t:
        return True
    sep = os.sep
    return t.startswith(r.rstrip(sep) + sep)


def guard(codebase_id: str, candidate) -> pathlib.Path:
    """对外总入口：按 codebase_id 取受控根，校验 `candidate` 落在其中。

    这是 `code_read` / `code_search` 等工具**必须**经过的门。
    任何异常都说明「无法确认这是已授权代码」，因此**调用方应按拒绝处理**。
    """
    cb = get_codebase(codebase_id)
    if cb is None:
        raise CodebaseNotFound(
            f"codebase「{codebase_id}」未入库。请先用 code_ingest 入库 —— "
            f"白盒只读**已入库**的代码（记录在 data/codebases.json，不入库 git）。")
    return resolve_in_root(cb.root, candidate)


def save_codebases(items: list[Codebase]) -> None:
    """写回记录（供 `ingest` 用）。原子写，复用 `config_io` 的既有实现。"""
    from .. import config_io
    payload = {"_说明": "白盒审计的代码入库记录（授权凭据 + 审计记录）。**本文件不入库 git。**",
               "codebases": [
                   {"codebase_id": c.codebase_id, "root": str(c.root),
                    "source": c.source, "white_layer": c.white_layer,
                    "note": c.note, "added_at": c.added_at, **c.extra}
                   for c in items]}
    res = config_io.write_json_atomic(CODEBASES_FILE, payload, backup_first=False)
    if not res.get("ok"):
        raise OSError(f"写入 codebases.json 失败：{res.get('error')}")
