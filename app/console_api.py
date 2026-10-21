# -*- coding: utf-8 -*-
"""配置控制台后端（v050 P1）：`/api/console/*`。

## 定位

现有 80 个接口里**没有任何配置写入能力** —— 授权白名单、工具分级、运行参数
只能手工改文件。本模块是控制台的配置侧 API，`main.py` 只加三行把它挂上。

## 三条设计红线（都有具体理由，不是风格问题）

### 1. 口令 fail-closed

这个界面能改**授权白名单**。若「未设置口令 = 不校验」，等于把授权红线挂在一个
默认敞开的网页上。所以：未配置口令时 **console 路由一律 403**，
并明确告诉人怎么配。宁可「配了才能用」，不可「没配就能用」。

### 2. 二次确认服务端强制，不是前端装饰

高危写入（白名单增删改）走**两段式**：
`preview` 算 diff 并签发一次性 `confirm_token`，`commit` **必须带这个 token**。
直接把 `commit` 打到 API 上没有 token 会被拒 —— 否则「二次确认」只是前端的
一个 `confirm()` 弹窗，绕过前端即可写。token 5 分钟过期：
「确认」的语义是「我刚看过这份 diff」，隔夜再提交就不算确认。

### 3. 乐观锁：防「控制台与手工编辑互相覆盖」

`commit` 需带 `expect_sha256`。与磁盘现值不符 → `409` 并回显差异。
本项目既有人手工改 `scope.json` 的习惯，不做这层就会出现
「控制台基于旧内容写入 → 手工刚加的那条被静默抹掉」。

## 与现有接口的关系

**不新造任何既有通道**。确认框、SSE 流等仍走 `/api/sessions/*`（P3 实时监控页会直接
复用，不重新实现）—— 那些接口里的确认双闸门（token + step_id + auth_ack）是安全核心，
重写一遍就是绕过它。
"""
from __future__ import annotations

import hmac
import json
import logging
import re as _re
import secrets
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import config, config_io, scope, scope_migrate

logger = logging.getLogger(__name__)

router = APIRouter()

COOKIE_NAME = "console_token"
# 进程级随机密钥：重启即让所有登录票据失效（本地工具，这个代价可接受且更安全）
_SECRET = secrets.token_bytes(32)
# 一次性确认票据：token -> {face, action, payload, exp}
_CONFIRMS: dict[str, dict] = {}


# ============================================================ 口令与票据
def _flat_yaml(path) -> dict:
    """读扁平 `key: value` 配置（本机 config.yaml）。

    ⚠️ 这里**只做转发**，实现在文件末尾的 `console_api_flat_yaml()`。
    曾经的写法是在本函数里直接 `from .fofa import _parse_flat_yaml` 再调，
    结果 P2 新增 secrets 接口时又写了一份同功能的函数 —— **同一个原理两份实现**，
    正是本项目反复踩过的那类问题（v047/v048/v050）。现在只留一份，本函数是别名。
    """
    return console_api_flat_yaml(path)


def console_password() -> str:
    """控制台口令：环境变量优先，其次本机 config.yaml 的 consolePassword。

    ⚠️ v102 修：原来这里写死 `config.APP_DIR / "config.yaml"`，与写入端的
    `_config_yaml_path()` 是**两份路径**。运行时两者恰好同值，但测试重定向
    （Sandbox 只换 `_config_yaml_path`）与将来任何路径调整都会让「写进了 A、
    读的是 B」。现在读写共用同一个函数，只有一份路径口径。
    """
    pw = _env_console_password()
    if pw:
        return pw
    try:
        return str(_flat_yaml(_config_yaml_path())
                   .get("consolePassword") or "").strip()
    except Exception:                                    # noqa: BLE001
        return ""


def _env_console_password() -> str:
    """环境变量来源的口令（**永远优先**于 config.yaml）。"""
    return (config.CONSOLE_PASSWORD or "").strip()


def console_password_source() -> str:
    """当前生效口令的来源。给人看的 —— 「改了 config.yaml 却不生效」的根因
    往往是环境变量还压着一个旧值，不说清楚就只能靠猜。"""
    if _env_console_password():
        return "env:AGENT_CONSOLE_PASSWORD"
    try:
        if str(_flat_yaml(_config_yaml_path())
               .get("consolePassword") or "").strip():
            return "config.yaml"
    except Exception:                                    # noqa: BLE001
        pass
    return ""


def _make_token() -> str:
    exp = int(time.time()) + config.CONSOLE_TOKEN_TTL
    sig = hmac.new(_SECRET, str(exp).encode(), "sha256").hexdigest()
    return f"{exp}.{sig}"


def _token_valid(tok: str) -> bool:
    try:
        exp_s, sig = tok.split(".", 1)
        exp = int(exp_s)
    except Exception:                                    # noqa: BLE001
        return False
    if exp < time.time():
        return False
    want = hmac.new(_SECRET, exp_s.encode(), "sha256").hexdigest()
    return hmac.compare_digest(sig, want)


def _authed(request: Request) -> bool:
    return _token_valid(request.cookies.get(COOKIE_NAME, ""))


def require_auth(request: Request) -> None:
    """依赖：所有 `/api/console/*`（除 login/logout/session）都挂它。

    两种情况分开报，因为要人做的事不同：
      · 没配口令 → 403 + 「怎么配」（fail-closed，不是 401）
      · 配了但没登录/票据过期 → 401 + 「去登录」
    """
    if not console_password():
        raise HTTPException(403, (
            "控制台口令未设置，已拒绝访问（fail-closed）。这个界面能修改授权白名单，"
            "因此不允许在未设口令时开放。"
            "设置方式：登录页直接「首次设置口令」（写入本机 config.yaml，长期保存），"
            "或设置环境变量 AGENT_CONSOLE_PASSWORD，"
            "或在本机 config.yaml 写 consolePassword: <你的口令>。"))
    if not _authed(request):
        raise HTTPException(401, "未登录或登录已过期，请重新登录。")


class LoginRequest(BaseModel):
    password: str = ""


@router.post("/login")
async def login(req: LoginRequest, response: Response):
    want = console_password()
    if not want:
        # 与 require_auth 同口径：没配口令就不给登录入口，而不是「空口令也能进」
        raise HTTPException(403, (
            "控制台口令未设置，无法登录。请在登录页「首次设置口令」，"
            "或设置环境变量 AGENT_CONSOLE_PASSWORD，"
            "或在本机 config.yaml 写 consolePassword。"))
    if not hmac.compare_digest((req.password or "").strip(), want):
        config_io.audit("auth", "login_failed", level="mid", actor="anonymous",
                        note="口令错误")
        raise HTTPException(401, (
            "口令错误。"
            + (f"（当前口令来自 {console_password_source()}；"
               "若你刚在 config.yaml 改过口令却被拒，说明环境变量 AGENT_CONSOLE_PASSWORD "
               "仍在优先生效）" if console_password_source() != "config.yaml" else "")))
    response.set_cookie(
        COOKIE_NAME, _make_token(), max_age=config.CONSOLE_TOKEN_TTL,
        httponly=True, samesite="strict", path="/")
    config_io.audit("auth", "login_ok", level="low")
    return {"ok": True, "expires_in": config.CONSOLE_TOKEN_TTL,
            "password_source": console_password_source()}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/session")
async def session(request: Request):
    """不需要鉴权：登录页要能问「我该不该显示登录框」。

    v102 起新增 `password_source`：口令来自环境变量还是 config.yaml 必须**说清楚** ——
    否则「在 config.yaml 改了口令却不生效」（环境变量压着旧值）只能靠猜，
    表现出来就是「口令设置了不保存，要反复设」。
    """
    return {"authenticated": _authed(request),
            "password_configured": bool(console_password()),
            "password_source": console_password_source()}


# ============================================================ 总览
@router.get("/overview")
async def overview(request: Request):
    """体检卡片数据。**只读**。

    价值在于「一眼看出哪条防线没配上」—— 这些项单看都不报错，组合起来才危险。
    例：`ENFORCE_SCOPE=0` 而白名单非空（以为受约束、其实没有）；
    空白名单（所有工具被拒，但现象是「Agent 突然什么都做不了」）。
    """
    require_auth(request)
    from .registry import registry

    domains = scope.load_scope()
    entries = scope.load_scope_targets()
    raw = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    # ⚠️ 「结构化条目数」必须数 **raw["targets"] 的条数**，不能数 `load_scope_targets()` 的长度：
    # 后者是 domains（旧写法）+ targets（结构化）**合并后**的视图，同一个 host 会各出一条，
    # 于是 7 个 host 显示成「结构化 14 条」—— 实测看到过这个误导，故显式取 raw 计数。
    n_structured = len([t for t in (raw.get("targets") or []) if isinstance(t, dict)])

    # 白名单告警：每一条都对应一种「看起来配了、其实没防住」的情况
    warns: list[dict] = []
    if not domains:
        warns.append({"level": "high", "text":
                      "授权白名单为空 —— 所有命令行工具、HTTP 重放器与 py_exec 都会被拒绝执行。"})
    if not config.ENFORCE_SCOPE:
        warns.append({"level": "high", "text":
                      "ENFORCE_SCOPE=0：授权校验已关闭，工具会对任意目标执行（等同关停红线）。"})
    needs_review = [t.get("host") for t in (raw.get("targets") or [])
                    if isinstance(t, dict) and t.get("needs_review")]
    if needs_review:
        warns.append({"level": "mid", "text":
                      f"{len(needs_review)} 条授权条目缺少 cid 或授权主体，等待人工复核"
                      "（在「授权白名单」页逐条补齐）。"})
    if not console_password():
        warns.append({"level": "high", "text":
                      "控制台口令未设置 —— 本页接口会被拒绝（fail-closed）。"
                      "可在登录页「首次设置口令」（写入 config.yaml，长期保存），"
                      "或设置 AGENT_CONSOLE_PASSWORD / config.yaml 的 consolePassword。"})
    elif console_password_source() == "env:AGENT_CONSOLE_PASSWORD":
        warns.append({"level": "mid", "text":
                      "控制台口令来自环境变量 AGENT_CONSOLE_PASSWORD（优先级最高）—— "
                      "在 config.yaml 或本页「本机密钥」里改 consolePassword 都不会生效，"
                      "要改请改环境变量。"})

    tools = registry.stats()
    interactive = [t.alias for t in registry.interactive_tools()]
    # 工具分级分布 + 进模型清单数（用于「一眼看出哪一类工具最多/有没有异常」）
    levels: dict[str, int] = {}
    for t in registry.tools:
        lv = (registry.risk_of(t.alias) or {}).get("level", "?")
        levels[lv] = levels.get(lv, 0) + 1

    prov = []
    try:
        from . import providers
        for p in providers.list_providers():
            g = providers.get(p["id"]) or {}
            prov.append({"id": p["id"], "name": p.get("name", ""),
                         "local": bool(g.get("local")),
                         "has_key": bool(g.get("api_key")),
                         "enabled": bool(g.get("enabled")),
                         "model": g.get("model", ""),
                         "current": p["id"] == providers.current().get("id")})
    except Exception:                                    # noqa: BLE001
        logger.debug("读供应商失败", exc_info=True)

    mcp = {}
    try:
        # 复用 main 里的实现（延迟导入避免循环）—— 不另写一份，否则两边会漂移
        from .main import _mcp_health
        mcp = await _mcp_health()
    except Exception as e:                               # noqa: BLE001
        mcp = {"available": False, "note": f"状态读取失败：{e}"}

    fp = {}
    try:
        from .fofa import _load_fofa_conf
        c = _load_fofa_conf() or {}
        fp = {"configured": bool(c.get("email") and c.get("key")),
              "email_masked": config_io.mask_host(str(c.get("email") or ""), 2, 6)
              if c.get("email") else ""}
    except Exception:                                    # noqa: BLE001
        fp = {"configured": False, "email_masked": ""}

    return {
        "ok": True,
        "scope": {
            "count": len(domains),          # 主机数（合并视图，已去重）
            "structured": n_structured,     # raw["targets"] 条数（见上方注释）
            "enforce": bool(config.ENFORCE_SCOPE),
            "needs_review": len(needs_review),
            "file": config_io.file_state(config.SCOPE_FILE),
        },
        "tools": tools,
        "tool_levels": levels,
        "interactive_tools": interactive,
        "providers": prov,
        "mcp": mcp,
        "timeouts": config.timeout_profile(),
        "orchestration": {
            "execution_mode": config.EXECUTION_MODE,
            "max_steps": config.MAX_STEPS,
            "run_token_budget": config.RUN_TOKEN_BUDGET,
            "task_constraints_enabled": config.TASK_CONSTRAINTS_ENABLED,
            "py_exec_grade_enabled": config.PY_EXEC_GRADE_ENABLED,
        },
        "fofa": fp,
        "console": {"password_configured": bool(console_password()),
                    "password_source": console_password_source(),
                    "confirm_ttl": config.CONSOLE_CONFIRM_TTL},
        "warnings": warns,
    }


# ============================================================ 授权白名单
def _scope_view() -> dict:
    raw = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    domains = scope.load_scope()
    targets = raw.get("targets")
    if not isinstance(targets, list):
        targets = None
    return {
        "file": config_io.file_state(config.SCOPE_FILE),
        "domains": domains,
        "targets": targets,
        "note": str(raw.get("_说明") or ""),
        # 一致性：domains 与 targets 是否对得上（手工编辑常见的不一致）
        "consistent": (targets is None) or (
            sorted(scope.load_scope()) ==
            sorted({str(t.get("host", "")).lower() for t in targets
                    if isinstance(t, dict) and t.get("host")})),
        "effective": [{"host": e["host"],
                       "ports": sorted(e["ports"]) if e["ports"] else None,
                       "schemes": sorted(e["schemes"]) if e["schemes"] else None}
                      for e in scope.load_scope_targets()],
    }


@router.get("/scope")
async def scope_get(request: Request):
    require_auth(request)
    return {"ok": True, "data": _scope_view()}


@router.post("/scope/plan")
async def scope_plan(request: Request):
    """迁移预演：把当前 `domains` + `_说明` 反解为结构化 `targets`，**不写盘**。"""
    require_auth(request)
    raw = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    new, report = scope_migrate.plan(raw)
    return {"ok": True, "preview": new, "report": report,
            "problems": scope_migrate.validate(new),
            "expect_sha256": config_io.sha256_short(config.SCOPE_FILE)}


class ScopeVerifyRequest(BaseModel):
    host: str = ""


@router.post("/scope/verify")
async def scope_verify(req: ScopeVerifyRequest, request: Request):
    """对单个 host 干跑 `check_scope()`，回显「会放行还是会拒」。

    这是本页最有价值的小功能：让人**在改之前**看到「这条授权到底会不会生效」。
    完全只读 —— 只做本地字符串匹配，**不发任何目标流量**。
    """
    require_auth(request)
    host = (req.host or "").strip()
    if not host:
        raise HTTPException(400, "host 不能为空")
    reason = scope.check_scope(host)
    return {"ok": True, "host": host, "allowed": reason is None,
            "reason": reason or "在授权白名单内，会放行。"}


class ScopeCommitRequest(BaseModel):
    confirm_token: str = ""
    expect_sha256: str = ""
    targets: list[dict] = []
    note_append: str = ""


def _issue_confirm(face: str, action: str, payload: Any, sha: str) -> str:
    tok = secrets.token_urlsafe(18)
    _CONFIRMS[tok] = {"face": face, "action": action, "payload": payload,
                      "sha": sha, "exp": time.time() + config.CONSOLE_CONFIRM_TTL}
    _prune_confirms()
    return tok


def _prune_confirms() -> None:
    now = time.time()
    for k in [k for k, v in _CONFIRMS.items() if v["exp"] < now]:
        _CONFIRMS.pop(k, None)


def _consume_confirm(token: str, face: str) -> dict:
    _prune_confirms()
    rec = _CONFIRMS.get(token or "")
    if not rec:
        raise HTTPException(400, (
            "确认票据无效或已过期（有效期 "
            f"{config.CONSOLE_CONFIRM_TTL // 60} 分钟）。"
            "请重新走一次「预览 → 确认提交」。"
            "提示：二次确认是服务端强制的 —— 没有票据直接提交会被拒绝。"))
    if rec["face"] != face:
        raise HTTPException(400, "确认票据与操作面不匹配。")
    _CONFIRMS.pop(token, None)                           # 一次性
    return rec


@router.post("/scope/preview")
async def scope_preview(req: ScopeCommitRequest, request: Request):
    """算出改动 diff + 影响 + 风险等级，签发一次性确认票据。"""
    require_auth(request)
    cur = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    before_hosts = set(scope.load_scope())
    after_hosts = {str(t.get("host", "")).strip().lower()
                   for t in req.targets if isinstance(t, dict) and t.get("host")}

    new = dict(cur)
    new["targets"] = req.targets
    new["domains"] = [h for h in (cur.get("domains") or [])
                      if isinstance(h, str) and h.strip().lower() in after_hosts]
    for h in sorted(after_hosts):
        if h not in new["domains"]:
            new["domains"].append(h)

    problems = scope_migrate.validate(new)
    if not after_hosts:
        problems.append("提交后白名单为空 —— 所有工具都会被拒绝执行。")
    if problems:
        # 校验不过就不签发票据：不给「先拿到票据再慢慢想办法」的余地
        raise HTTPException(400, "校验未通过：" + "；".join(problems))

    added = sorted(after_hosts - before_hosts)
    removed = sorted(before_hosts - after_hosts)
    level = "high" if (added or removed) else "low"

    sha = config_io.sha256_short(config.SCOPE_FILE)
    tok = _issue_confirm("scope", "write", new, sha)
    return {
        "ok": True,
        "level": level,
        "requires_confirm": True,
        "added": added,
        "removed": removed,
        "unchanged": len(before_hosts & after_hosts),
        "warnings": ([f"将新增 {len(added)} 条授权"] if added else [])
                    + ([f"将移除 {len(removed)} 条授权"] if removed else [])
                    + (["授权校验当前处于关闭状态（ENFORCE_SCOPE=0），写白名单不会产生实际约束"]
                       if not config.ENFORCE_SCOPE else []),
        "confirm_token": tok,
        "expect_sha256": sha,
        "confirm_ttl": config.CONSOLE_CONFIRM_TTL,
    }


@router.post("/scope/commit")
async def scope_commit(req: ScopeCommitRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "scope")

    # 乐观锁：盘上内容变了就停（防「控制台与手工编辑互相覆盖」）
    cur_sha = config_io.sha256_short(config.SCOPE_FILE)
    if req.expect_sha256 and cur_sha and cur_sha != req.expect_sha256:
        raise HTTPException(409, (
            "scope.json 在你预览之后被改动过（可能是手工编辑），已拒绝写入以免覆盖。"
            f"盘上当前哈希 {cur_sha} ≠ 你确认时的 {req.expect_sha256}。"
            "请刷新页面重新预览。"))

    before = config_io.read_json(config.SCOPE_FILE, default={}) or {}
    new = rec["payload"]
    if req.note_append:
        new = dict(new)
        new["_说明"] = str(new.get("_说明") or "") + "\n\n" + req.note_append.strip()

    res = config_io.write_json_atomic(config.SCOPE_FILE, new)
    if not res["ok"]:
        raise HTTPException(500, f"写入失败（已回滚到写前状态）：{res['error']}")
    config_io.audit("scope", "write", before={"domains": before.get("domains")},
                    after={"domains": new.get("domains"),
                           "targets": len(new.get("targets") or [])},
                    level="high", note=req.note_append or "控制台提交授权白名单")
    return {"ok": True, "file": config_io.file_state(config.SCOPE_FILE),
            "reload": config_io.reload_for("scope"), "backup": res["backup"],
            "data": _scope_view()}


@router.get("/audit")
async def audit_get(request: Request, limit: int = 100, face: str = ""):
    require_auth(request)
    limit = max(1, min(int(limit or 100), 1000))
    return {"ok": True, "items": config_io.read_audit(limit=limit, face=face),
            "file": config_io.file_state(config_io.AUDIT_FILE)}


@router.get("/audit/export")
async def audit_export(request: Request, mask: int = 1):
    """导出审计 CSV。**默认脱敏** —— 举证材料常要发给别人（平台/导师/队友），
    默认脱敏能避免「为了举证把授权靶标清单整份发出去」。要全量请显式 `mask=0`。"""
    require_auth(request)
    rows = config_io.read_audit(limit=1000)
    hosts = _collect_hosts(rows)
    lines = ["time,face,action,level,actor,note,before,after"]
    for r in rows:
        b = json.dumps(r.get("before"), ensure_ascii=False)
        a = json.dumps(r.get("after"), ensure_ascii=False)
        if mask:
            b, a = _mask_json(b, hosts), _mask_json(a, hosts)
        cells = [str(r.get("time", "")), str(r.get("face", "")),
                 str(r.get("action", "")), str(r.get("level", "")),
                 str(r.get("actor", "")), str(r.get("note", "")), b, a]
        lines.append(",".join('"' + c.replace('"', '""') + '"' for c in cells))
    return PlainTextResponse("\n".join(lines) + "\n",
                             media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition":
                                      "attachment; filename=console_audit.csv"})


def _mask_json(s: str, hosts: list[str]) -> str:
    """把 JSON 文本里出现的授权主机做掩码。

    ⚠️ v050 实测踩到的坑：最初我用「长得像域名的串」这条正则去匹配并掩码，
    结果 `new.test` 这种**标签很短**的域名匹配不上（正则要求点号前 ≥5 字符），
    → **默认脱敏失效，完整域名照样导出**。而这条检查恰好写在测试里，
    一跑就抓到了 —— 所以这里改成**按已知主机精确替换**：
    主机列表直接从审计记录本身扫出来，不靠正则猜「什么像域名」。

    仍然保留一条宽松兜底正则，用于那些**没被记进 domains 列表**的散落域名
    （例如 note 里手写的），避免出现「主表脱敏了、备注里漏了」。
    """
    known = sorted({h for h in hosts if h}, key=len, reverse=True)
    for h in known:
        s = s.replace(h, config_io.mask_host(h))
    # 兜底：点号前 ≥3 字符的域名形态（覆盖 note 里手写的）
    def rep(m):
        return config_io.mask_host(m.group(1))
    return _re.sub(r"([A-Za-z0-9][A-Za-z0-9.-]{2,}\.[A-Za-z]{2,})", rep, s)


def _collect_hosts(records: list[dict]) -> list[str]:
    """从审计记录的 before/after 里扫出所有字符串值，挑出像主机的那些。

    为什么不做成「读当前 scope.json」：审计是**历史**——某条主机可能已经被移出白名单，
    但它仍留在旧记录里，仍需脱敏。所以只能从记录本身扫。
    """
    pat = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$")
    out: set[str] = set()

    def walk(v):
        if isinstance(v, str):
            if pat.match(v.strip()):
                out.add(v.strip())
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
    for r in records:
        walk(r.get("before"))
        walk(r.get("after"))
        walk(r.get("extra"))
    return sorted(out, key=len, reverse=True)


# ============================================================ 工具与分级（P2）
# 写入面是**两个文件**，键口径还不一样：
#   · `data/risk_grades.json`  —— 键是**工具名**（中文名），存 level + reason
#   · `data/tool_overrides.json` —— 键是 **alias**，存 disabled/timeout/caps/旗标/caveat
# 所以预览要同时报两个文件的哈希，提交要同时带两个（否则可能只把一半改动落盘）。
GRADES_FILE_NAME = "risk_grades.json"
OVERRIDES_FILE_NAME = "tool_overrides.json"

# 控制台允许改的覆写字段（白名单）。**不能让它写任意键** ——
# tool_overrides 里还有 network_control / stdin_input 这类字段，
# 手改它们会绕过速率声明与交互式处理，属于「闸门参数」，不该从工具页随手改。
OVERRIDE_EDITABLE = ("disabled", "reason", "timeout", "caveat", "caps",
                     "target_type", "allowed_flags", "value_flags",
                     "disallowed_flags", "ignore_exit_code", "interactive",
                     "interactive_reason")


def _grades_path():
    return config.DATA_DIR / GRADES_FILE_NAME


def _overrides_path():
    return config.DATA_DIR / OVERRIDES_FILE_NAME


@router.get("/tools")
async def tools_get(request: Request):
    """全部工具（含不可编排的），带分级、覆写、是否进模型清单、文件是否存在。"""
    require_auth(request)
    from .registry import registry

    in_model = {t.alias for t in registry.usable_scriptable()}
    ov_raw = config_io.read_json(_overrides_path(), default={}) or {}
    gr_raw = config_io.read_json(_grades_path(), default={}) or {}
    items = []
    for t in registry.tools:
        ov = ov_raw.get(t.alias) or {}
        g = gr_raw.get(t.name) or {}
        items.append({
            "alias": t.alias, "name": t.name, "category": t.category,
            "type": t.type, "scriptable": t.scriptable,
            "level": t.risk_level, "level_reason": t.risk_reason,
            "level_in_grades": bool(g),
            "has_override": bool(ov),
            "disabled": t.disabled, "disabled_reason": t.disabled_reason,
            "interactive": t.interactive, "interactive_reason": t.interactive_reason,
            "caps": list(t.caps),
            "timeout": t.tool_timeout or 0,
            "target_type": t.target_type,
            "allowed_flags": list(t.allowed_flags),
            "disallowed_flags": list(t.disallowed_flags),
            "value_flags": list(t.value_flags),
            "ignore_exit_code": t.ignore_exit_code,
            "caveat_chars": len(t.caveat or ""),
            "executable": bool(t.executable),
            "in_model_list": t.alias in in_model,
            # 只显示长度不显示内容：caveat 可能很长，整表回传会让页面噎住；
            # 需要看全文时由 /tools/detail 单独取。
        })
    return {"ok": True, "items": items,
            "files": {"grades": config_io.file_state(_grades_path()),
                      "overrides": config_io.file_state(_overrides_path())},
            "editable_fields": list(OVERRIDE_EDITABLE),
            "levels": [{"level": k, "name": v["name"], "policy": v["policy"]}
                       for k, v in config.RISK_LEVELS.items()],
            "note": ("分级写 risk_grades.json（按工具名）；"
                     "禁用/超时/caps/旗标写 tool_overrides.json（按 alias）。"
                     "两者是不同文件，控制台会一起做乐观锁与回滚。")}


class ToolEditRequest(BaseModel):
    alias: str = ""
    overrides: dict | None = None      # None = 不改这个文件
    grade: dict | None = None          # None = 不改这个文件
    confirm_token: str = ""
    expect_sha256: dict = {}


def _tool_edit_diff(alias: str, overrides: dict | None, grade: dict | None) -> dict:
    """算出「改前 → 改后」的差异，并做字段级校验。返回 {diff, problems, payload, to_write}。"""
    from .registry import registry

    problems: list[str] = []
    diff: list[dict] = []
    t = registry.get_by_alias(alias) if alias else None

    ov_raw = config_io.read_json(_overrides_path(), default={}) or {}
    gr_raw = config_io.read_json(_grades_path(), default={}) or {}
    new_ov = dict(ov_raw)
    new_gr = dict(gr_raw)
    to_write: list[tuple] = []

    if overrides is not None:
        if not t:
            problems.append(f"未知工具 alias：{alias}")
        bad = [k for k in overrides if k not in OVERRIDE_EDITABLE]
        if bad:
            problems.append(
                f"不允许从工具页修改这些字段：{bad}（它们属于闸门参数，"
                "改它们会绕过速率声明或交互式处理）")
        if not problems:
            cur = dict(ov_raw.get(alias) or {})
            for k, v in overrides.items():
                old = t and getattr(t, {
                    "timeout": "tool_timeout"}.get(k, k), None)
                if (cur.get(k) if k in cur else old) != v:
                    diff.append({"file": OVERRIDES_FILE_NAME, "key": f"{alias}.{k}",
                                 "before": cur.get(k, old), "after": v})
                cur[k] = v
            if not cur.get("reason") and (cur.get("disabled") or overrides.get("disabled")):
                problems.append("禁用工具必须填 reason（写清「为什么不可用」，否则后来人只能猜）")
            if not problems:
                new_ov[alias] = cur
                to_write.append((_overrides_path(), new_ov))

    if grade is not None:
        if not t:
            problems.append("未知工具，无法改分级")
        lvl = grade.get("level")
        if lvl not in config.RISK_LEVELS:
            problems.append(f"非法风险等级：{lvl!r}（允许 {list(config.RISK_LEVELS)}）")
        if not str(grade.get("reason") or "").strip():
            problems.append("改分级必须填 reason（分级依据要留痕）")
        if t and not t.scriptable:
            problems.append(
                f"「{t.name}」不可编排（图形界面/网页工具），分级只对可编排工具生效 —— "
                "改它不会有任何效果")
        if not problems:
            cur_g = dict(gr_raw.get(t.name) or {})
            for k in ("level", "reason"):
                if cur_g.get(k) != grade.get(k):
                    diff.append({"file": GRADES_FILE_NAME, "key": f"{t.name}.{k}",
                                 "before": cur_g.get(k), "after": grade.get(k)})
            cur_g.update({"level": lvl, "reason": grade.get("reason", "")})
            cur_g.setdefault("type", t.type)
            cur_g.setdefault("category", t.category)
            cur_g.setdefault("path", str(t.rel_path or ""))
            new_gr[t.name] = cur_g
            to_write.append((_grades_path(), new_gr))

    if not to_write and not problems:
        problems.append("没有任何改动")
    return {"diff": diff, "problems": problems, "to_write": to_write,
            "files": [p.name for p, _ in to_write], "tool": t.name if t else ""}


@router.post("/tools/detail")
async def tools_detail(req: ToolEditRequest, request: Request):
    """取单个工具的完整 caveat 等长字段（列表页不回传全文，避免页面噎住）。"""
    require_auth(request)
    from .registry import registry
    t = registry.get_by_alias(req.alias)
    if not t:
        raise HTTPException(404, "未知工具 alias")
    return {"ok": True, "alias": t.alias, "name": t.name,
            "caveat": t.caveat or "", "description": t.description or "",
            "risk_reason": t.risk_reason or "",
            "network_control": t.network_control or {}}


@router.post("/tools/preview")
async def tools_preview(req: ToolEditRequest, request: Request):
    require_auth(request)
    r = _tool_edit_diff(req.alias, req.overrides, req.grade)
    if r["problems"]:
        raise HTTPException(400, "校验未通过：" + "；".join(r["problems"]))
    hashes = {"grades": config_io.sha256_short(_grades_path()),
              "overrides": config_io.sha256_short(_overrides_path())}
    tok = _issue_confirm("tools", "write",
                         {"alias": req.alias, "overrides": req.overrides,
                          "grade": req.grade}, hashes["overrides"] + hashes["grades"])
    level = "high" if any(d["key"].endswith((".level", ".disabled")) for d in r["diff"]) \
        else "mid"
    return {"ok": True, "diff": r["diff"], "files": r["files"], "tool": r["tool"],
            "level": level, "requires_confirm": True, "confirm_token": tok,
            "expect_sha256": hashes, "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/tools/commit")
async def tools_commit(req: ToolEditRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "tools")
    # 乐观锁：两个文件都要核对（任一被手工改过就停）
    for name, path in (("overrides", _overrides_path()), ("grades", _grades_path())):
        want = (req.expect_sha256 or {}).get(name, "")
        cur = config_io.sha256_short(path)
        if want and cur and cur != want:
            raise HTTPException(409, (
                f"{path.name} 在你预览之后被改动过（可能手工编辑），已拒绝写入以免覆盖。"
                f"盘上当前 {cur} ≠ 你确认时的 {want}。请刷新页面重新预览。"))

    r = _tool_edit_diff(rec["payload"]["alias"], rec["payload"]["overrides"],
                        rec["payload"]["grade"])
    if r["problems"]:
        raise HTTPException(400, "校验未通过（预览后可能已有变化）：" + "；".join(r["problems"]))
    res = config_io.write_many_atomic(r["to_write"])
    if not res["ok"]:
        raise HTTPException(500, (
            f"写入失败（{res['failed']}）：{res['error']}。"
            f"已回滚：{res['rolled_back'] or '（无需回滚）'}"))
    config_io.audit("tools", "write",
                    before={"alias": rec["payload"]["alias"]},
                    after={"diff": r["diff"], "files": res["written"]},
                    level="high", note=f"工具 {r['tool']} 改动 {len(r['diff'])} 项")
    reload_info = config_io.reload_for("tools")
    return {"ok": True, "diff": r["diff"], "written": res["written"],
            "reload": reload_info,
            "files": {"grades": config_io.file_state(_grades_path()),
                      "overrides": config_io.file_state(_overrides_path())}}


# ============================================================ 运行参数（P2）
@router.get("/params")
async def params_get(request: Request):
    """分组列出可调参数：当前值 / 默认值 / 来源 / 取值域 / 说明。

    刻意返回 `excluded`：被**有意排除**的参数连理由一起给出。
    否则「参数表里怎么没有 HOST」会被当成漏了，下一个人会想补上它。
    """
    require_auth(request)
    from . import param_spec as ps
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    groups = []
    for g in ps.groups():
        items = []
        for s in g["items"]:
            k = s["key"]
            items.append({**s,
                          "value": getattr(config, k, None),
                          "default": ps.default_value(k),
                          "env": ps.env_name(k),
                          "source": ps.source_of(k, ov)})
        groups.append({"group": g["group"], "items": items})
    return {"ok": True, "groups": groups,
            "excluded": ps.EXCLUDED,
            "overrides": (ov.get("params") or {}),
            "warnings": config.param_warnings(),
            "file": config_io.file_state(config_io.OVERRIDES_FILE),
            "hot": True,
            "note": ("改动**立即生效，不用重启**（全项目 0 处 `from .config import X`、"
                     "220 处 `config.X` 属性访问）。写入 data/runtime_overrides.json，"
                     "删掉某个键即回到环境变量/默认值。")}


class ParamsRequest(BaseModel):
    values: dict = {}
    confirm_token: str = ""
    expect_sha256: str = ""
    reset: list[str] = []


@router.post("/params/preview")
async def params_preview(req: ParamsRequest, request: Request):
    require_auth(request)
    from . import param_spec as ps
    values = {k: v for k, v in (req.values or {}).items()}
    problems = ps.validate(values) if values else []
    if not values and not req.reset:
        problems = ["没有任何改动"]
    if problems:
        raise HTTPException(400, "校验未通过：" + "；".join(problems))
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    cur = ov.get("params") or {}
    diff = []
    for k, v in values.items():
        if getattr(config, k, None) != v:
            diff.append({"key": k, "before": getattr(config, k, None), "after": v,
                         "default": ps.default_value(k)})
    for k in (req.reset or []):
        if k in cur:
            diff.append({"key": k, "before": getattr(config, k, None),
                         "after": ps.default_value(k), "default": ps.default_value(k)})
    if not diff:
        raise HTTPException(400, "没有任何实际变化")
    sha = config_io.sha256_short(config_io.OVERRIDES_FILE)
    tok = _issue_confirm("params", "write",
                         {"values": values, "reset": req.reset or []}, sha)
    # 关闸门类改动按高危（它们直接改变防护强度）
    danger = any(ps.spec_of(d["key"]) and ps.spec_of(d["key"]).get("danger")
                 for d in diff)
    return {"ok": True, "diff": diff, "level": "high" if danger else "mid",
            "requires_confirm": True, "confirm_token": tok,
            "expect_sha256": sha, "confirm_ttl": config.CONSOLE_CONFIRM_TTL,
            "warnings": config.param_warnings()}


@router.post("/params/commit")
async def params_commit(req: ParamsRequest, request: Request):
    require_auth(request)
    from . import param_spec as ps
    rec = _consume_confirm(req.confirm_token, "params")
    cur_sha = config_io.sha256_short(config_io.OVERRIDES_FILE)
    if req.expect_sha256 and cur_sha and cur_sha != req.expect_sha256:
        raise HTTPException(409, (
            "runtime_overrides.json 在你预览之后被改动过，已拒绝写入以免覆盖。"
            "请刷新页面重新预览。"))
    values = dict(rec["payload"]["values"])
    # reset 项从覆盖文件里删掉（回到 env/默认），不是写成默认值
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    merged = dict(ov.get("params") or {})
    for k in rec["payload"]["reset"]:
        merged.pop(k, None)
    merged.update(values)
    res = config_io.save_overrides(merged)
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    applied = config_io.apply_overrides(config)
    config_io.audit("params", "write", before={"params": ov.get("params")},
                    after={"params": merged, "applied": applied},
                    level="high", note=f"改动 {len(values)} 项 / 复位 {len(rec['payload']['reset'])} 项")
    return {"ok": True, "applied": applied,
            "values": {s["key"]: getattr(config, s["key"], None)
                       for s in ps.SPECS},
            "warnings": config.param_warnings(),
            "file": config_io.file_state(config_io.OVERRIDES_FILE)}


@router.post("/params/reset")
async def params_reset(request: Request):
    """清空全部运行时覆盖（回到环境变量/默认值）。高危，需确认票据。

    单独开一个入口是因为它**不是「把值改成默认」而是「删掉覆盖」** ——
    对「被环境变量设过」的参数，这两者结果不同：删掉覆盖会回到环境变量的值，
    写成默认值则会**覆盖掉环境变量**。所以必须分开做，不能靠前端「填默认值」模拟。
    """
    require_auth(request)
    ov = config_io.read_json(config_io.OVERRIDES_FILE, default={}) or {}
    if not (ov.get("params") or {}):
        return {"ok": True, "applied": [], "note": "本来就没有运行时覆盖。"}
    res = config_io.write_json_atomic(config_io.OVERRIDES_FILE,
                                     {"_说明": "（已清空）", "params": {}})
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    # v052（复审报告 P2-A）：**必须**补这一步。原来只写了文件、没应用 ——
    # 于是把 ENFORCE_SCOPE 之类的闸门参数覆盖成关闭之后，再 reset，
    # 本进程的 config.ENFORCE_SCOPE 仍是 False，而总览页读的正是它 →
    # **界面显示「红线已关」而文件已经清空**，是最典型的「改了没生效 + 误导」。
    # `apply_overrides` 现在会先还原 `_ORIGINALS` 里那些已撤销的覆盖，所以复位是**即时**的。
    applied = config_io.apply_overrides(config)
    config_io.audit("params", "reset_all", before={"params": ov.get("params")},
                    after={"params": {}, "restored": applied},
                    level="high", note="清空全部运行时覆盖")
    return {"ok": True, "backup": res["backup"], "restored": applied,
            "values": {k: getattr(config, k, None)
                       for k in (ov.get("params") or {})},
            "warnings": config.param_warnings(),
            "note": ("已清空并**即时还原**：" + ("、".join(applied) if applied else "无覆盖项")
                     + "。回到环境变量/默认值，**不需要重启**。")}


# ============================================================ 合规红线与模板（P2）
def _rules_path():
    return config.DATA_DIR / "rules" / "compliance-redlines.md"


@router.get("/rules")
async def rules_get(request: Request):
    require_auth(request)
    text = config_io.read_text(_rules_path())
    sections = []
    cur = {"title": "（开头，不属于任何章节）", "start": 0}
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("## "):
            sections.append({**cur, "end": i})
            cur = {"title": ln[3:].strip(), "start": i}
    sections.append({**cur, "end": len(lines)})
    for s in sections:
        s["chars"] = len("\n".join(lines[s["start"]:s["end"]]))
    return {"ok": True, "text": text, "sections": sections,
            "file": config_io.file_state(_rules_path()),
            "note": "红线注入系统提示，**下一轮生效**（系统提示每轮重建）。"}


class RulesRequest(BaseModel):
    text: str = ""
    confirm_token: str = ""
    expect_sha256: str = ""


@router.post("/rules/preview")
async def rules_preview(req: RulesRequest, request: Request):
    require_auth(request)
    old = config_io.read_text(_rules_path())
    new = req.text or ""
    if new == old:
        raise HTTPException(400, "内容没有变化")
    if not new.strip():
        raise HTTPException(400, "不允许把合规红线清空 —— 它会注入系统提示，清空等于移除纪律约束")
    sha = config_io.sha256_short(_rules_path())
    tok = _issue_confirm("rules", "write", {"text": new}, sha)
    import difflib
    d = list(difflib.unified_diff(old.splitlines(), new.splitlines(),
                                  lineterm="", n=0))
    return {"ok": True, "level": "mid", "requires_confirm": True,
            "confirm_token": tok, "expect_sha256": sha,
            "stats": {"before_chars": len(old), "after_chars": len(new),
                      "before_lines": len(old.splitlines()),
                      "after_lines": len(new.splitlines())},
            "hunks": len([x for x in d if x.startswith("@@")]),
            "preview": "\n".join(d[:120]),
            "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/rules/commit")
async def rules_commit(req: RulesRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "rules")
    cur = config_io.sha256_short(_rules_path())
    if req.expect_sha256 and cur and cur != req.expect_sha256:
        raise HTTPException(409, "红线文件在你预览之后被改动过，已拒绝写入。请重新预览。")
    old = config_io.read_text(_rules_path())
    res = config_io.write_text_atomic(_rules_path(), rec["payload"]["text"])
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    config_io.audit("rules", "write",
                    before={"chars": len(old)}, after={"chars": len(rec["payload"]["text"])},
                    level="mid", note="编辑合规红线")
    return {"ok": True, "backup": res["backup"],
            "reload": config_io.reload_for("rules"),
            "file": config_io.file_state(_rules_path())}


def _templates_path():
    return config.DATA_DIR / "invocation_templates.json"


@router.get("/templates")
async def templates_get(request: Request):
    require_auth(request)
    raw = config_io.read_json(_templates_path(), default={}) or {}
    items = [{"alias": k, **(v if isinstance(v, dict) else {})}
             for k, v in raw.items() if not k.startswith("_")]
    # 加载期发现的问题（例如手工改写导致缺 {exe}）—— 让界面直接显示，
    # 否则「模板被静默忽略」只留在日志里，等于没发现。
    try:
        from .executor import template_problems
        problems = template_problems()
    except Exception:                                        # noqa: BLE001
        problems = []
    return {"ok": True, "items": items,
            "target_form": raw.get("_target_form", ""),
            "note": raw.get("_说明", ""),
            "problems": problems,
            "file": config_io.file_state(_templates_path()),
            "targets": ["url", "host", "domain", "raw", "asis"]}


class TemplatesRequest(BaseModel):
    items: list[dict] = []
    confirm_token: str = ""
    expect_sha256: str = ""


@router.post("/templates/preview")
async def templates_preview(req: TemplatesRequest, request: Request):
    require_auth(request)
    raw = dict(config_io.read_json(_templates_path(), default={}) or {})
    old_items = {k: v for k, v in raw.items() if not k.startswith("_")}
    problems: list[str] = []
    new_items: dict = {}
    for it in req.items:
        a = str(it.get("alias") or "").strip()
        if not a:
            problems.append("存在没有 alias 的条目")
            continue
        cmd = str(it.get("cmd") or "").strip()
        if "{exe}" not in cmd:
            problems.append(f"{a}：cmd 必须含 {{exe}}（否则根本不知道执行什么）")
        tgt = str(it.get("target") or "raw").strip()
        if tgt not in ("url", "host", "domain", "raw", "asis"):
            problems.append(f"{a}：target={tgt!r} 不是合法取值")
        new_items[a] = {"cmd": cmd, "target": tgt}
    if problems:
        raise HTTPException(400, "校验未通过：" + "；".join(problems))
    added = sorted(set(new_items) - set(old_items))
    removed = sorted(set(old_items) - set(new_items))
    changed = sorted(k for k in set(new_items) & set(old_items)
                     if new_items[k] != old_items[k])
    if not (added or removed or changed):
        raise HTTPException(400, "没有任何改动")
    new_raw = {k: v for k, v in raw.items() if k.startswith("_")}
    new_raw.update(new_items)
    sha = config_io.sha256_short(_templates_path())
    tok = _issue_confirm("invocation_templates", "write", {"raw": new_raw}, sha)
    return {"ok": True, "level": "mid", "requires_confirm": True,
            "confirm_token": tok, "expect_sha256": sha,
            "added": added, "removed": removed, "changed": changed,
            "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/templates/commit")
async def templates_commit(req: TemplatesRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "invocation_templates")
    cur = config_io.sha256_short(_templates_path())
    if req.expect_sha256 and cur and cur != req.expect_sha256:
        raise HTTPException(409, "调用模板文件在你预览之后被改动过，已拒绝写入。")
    res = config_io.write_json_atomic(_templates_path(), rec["payload"]["raw"])
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    config_io.audit("invocation_templates", "write",
                    before={"count": len(req.items)}, after={"count": len(req.items)},
                    level="mid", note="编辑调用模板")
    return {"ok": True, "backup": res["backup"],
            "reload": config_io.reload_for("invocation_templates"),
            "file": config_io.file_state(_templates_path())}


def _config_yaml_path():
    return config.APP_DIR / "config.yaml"

# 控制台允许改的密钥键（白名单）。**其余键一律原样保留** ——
# config.yaml 是被 app/fofa.py 用自写的扁平解析器读的，乱动键名/结构会让它读不到，
# 而表现是「填了却没生效」。所以只允许改这几个已知键的值，格式与其它行都不动。
SECRET_KEYS = ("fofaEmail", "fofaKey", "ceyeApi", "ceyeDomain", "consolePassword")


@router.get("/secrets")
async def secrets_get(request: Request):
    require_auth(request)
    data = console_api_flat_yaml(_config_yaml_path())
    out = []
    for k in SECRET_KEYS:
        v = str(data.get(k) or "")
        out.append({"key": k, "has_value": bool(v),
                    "masked": (config_io.mask_host(v, 2, 4) if v else ""),
                    "is_secret": k in ("fofaKey", "ceyeApi", "consolePassword")})
    return {"ok": True, "items": out,
            "file": config_io.file_state(_config_yaml_path()),
            "note": ("读取时只回显是否已填与打码值，**不下发明文**。"
                     "写入只替换这些键的值，其它行与注释原样保留 —— "
                     "config.yaml 由 app/fofa.py 用自写的扁平解析器读，"
                     "改了键名或结构会导致「填了却没生效」。")}


class SecretsRequest(BaseModel):
    values: dict = {}
    confirm_token: str = ""
    expect_sha256: str = ""


def _write_config_yaml_keys(values: dict) -> dict:
    """把若干键写进本机 config.yaml（只替换值，其它行与注释原样保留）。

    v102 抽出来：`/secrets/commit`、`/password/setup`、`/password/change`
    三个入口都写同一个文件 —— **同一原理只留一份实现**（本项目反复踩的坑）。
    返回 `config_io.write_text_atomic` 的结果（含 backup/error）。
    """
    path = _config_yaml_path()
    old_text = config_io.read_text(path)
    lines = old_text.splitlines()
    done: set[str] = set()
    out_lines = []
    for ln in lines:
        s = ln.strip()
        if ":" in s and not s.startswith("#"):
            k = s.split(":", 1)[0].strip()
            if k in values:
                out_lines.append(f"{k}: {_yaml_scalar(values[k])}")
                done.add(k)
                continue
        out_lines.append(ln)
    for k, v in values.items():
        if k not in done:
            out_lines.append(f"{k}: {_yaml_scalar(v)}")
    res = config_io.write_text_atomic(path, "\n".join(out_lines).rstrip("\n") + "\n")
    res["done"] = sorted(done)
    return res


@router.post("/secrets/commit")
async def secrets_commit(req: SecretsRequest, request: Request):
    """写 config.yaml。低危（不改结构），但**不需要票据**是刻意的：
    它不改变防护强度，且改错了只影响 FOFA 能不能用，一眼能看出来。"""
    require_auth(request)
    bad = [k for k in (req.values or {}) if k not in SECRET_KEYS]
    if bad:
        raise HTTPException(400, f"不允许写这些键：{bad}（只允许 {list(SECRET_KEYS)}）")
    path = _config_yaml_path()
    res = _write_config_yaml_keys(req.values or {})
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    config_io.audit("secrets", "write",
                    before={"keys": sorted(req.values.keys())},
                    after={"kept": res["done"]},
                    level="mid",
                    note="更新 config.yaml 密钥（值不写入审计）")
    # v102：改了 consolePassword 但环境变量还压着 → 值写进去了却不生效，
    # 表现正是「设置了不保存」。必须当场说清楚，不能让人白设一遍又一遍。
    warnings = []
    if "consolePassword" in (req.values or {}) and _env_console_password():
        warnings.append(
            "注意：环境变量 AGENT_CONSOLE_PASSWORD 仍在优先生效 —— 刚写入 config.yaml 的"
            " consolePassword 不会被使用。要让它生效，请清掉/修改该环境变量后重启服务，"
            "或改用登录页的「修改口令」流程。")
    return {"ok": True, "backup": res["backup"], "warnings": warnings,
            "reload": config_io.reload_for("secrets"),
            "file": config_io.file_state(path)}


def _yaml_scalar(v) -> str:
    """写回扁平 yaml 的值。字符串一律加引号并转义，避免含 `:` 或 `#` 时把行拆坏。"""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def console_api_flat_yaml(path) -> dict:
    """读扁平 `key: value`（复用 fofa.py 那份解析器，不另写一份）。"""
    try:
        from .fofa import _parse_flat_yaml
        if not path.exists():
            return {}
        return _parse_flat_yaml(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:                                        # noqa: BLE001
        return {}


# ============================================================ 口令设置 / 修改（v102）
# 为什么要有这两个接口：此前「口令未设置」时**整个 console 都是 403**，
# 登录页只能提示「去设环境变量 / 改 config.yaml 再重启」。环境变量是
# 「当前窗口有效」（`set AGENT_CONSOLE_PASSWORD=...`），于是每开一次服务
# 就要重设一次 —— 这正是「口令设置了不保存、要不断设置」的来源之一。
# 现在：**首次设置**从登录页直接做，写入本机 config.yaml 长期保存；
# **修改**在登录后做，同样落盘。写盘走的还是 secrets 那一份实现。
MIN_PASSWORD_LEN = 8


def _validate_new_password(pw: str) -> None:
    if len(pw) < MIN_PASSWORD_LEN:
        raise HTTPException(400, (
            f"口令至少 {MIN_PASSWORD_LEN} 位 —— 这个界面能改授权白名单，"
            "口令太短等于没设。"))
    if "\n" in pw or "\r" in pw or "\x00" in pw:
        raise HTTPException(400, "口令不能包含换行符或空字符（会破坏 config.yaml 的行结构）。")


def _require_local_console_source(request: Request) -> None:
    """首次设置只接受来自回环地址的请求（纵深防御，不是唯一防线）。

    唯一防线是既有的两道：绑回环 + Host 守卫；远程模式全站 Bearer 闸门。
    这里再收一道：**未设口令的空窗期**最怕「别人抢先设置」，而那只能发生在
    能连到本服务的地址上 —— 非回环来源一律拒绝，远程用户走环境变量。
    """
    client = getattr(request, "client", None)
    host = str(getattr(client, "host", "") or "")
    if not host or host == "testclient":          # TestClient 默认 host（测试场景）
        return
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(403, "「首次设置口令」只允许来自本机（回环地址）的请求。")


class PasswordSetupRequest(BaseModel):
    password: str = ""
    confirm: str = ""


class PasswordChangeRequest(BaseModel):
    current_password: str = ""
    new_password: str = ""


@router.post("/password/setup")
async def password_setup(req: PasswordSetupRequest, request: Request,
                         response: Response):
    """首次使用引导：口令**尚未配置**时从登录页设置，并写入 config.yaml。

    fail-closed 没有被放宽：
      · 口令一旦已配置 → 409（这个接口从此永久关闭，改口令走 `/password/change`）；
      · 非回环来源 → 403（空窗期防「别人抢先设置」，见 `_require_local_console_source`）；
      · 审计留痕（high），但**值不入审计**。
    """
    if console_password():
        raise HTTPException(409, (
            "口令已配置，不能再走「首次设置」。要更换请登录后使用「修改口令」"
            "（/api/console/password/change）。"))
    _require_local_console_source(request)
    pw = (req.password or "").strip()
    _validate_new_password(pw)
    if (req.confirm or "").strip() != pw:
        raise HTTPException(400, "两次输入的口令不一致。")
    res = _write_config_yaml_keys({"consolePassword": pw})
    if not res["ok"]:
        raise HTTPException(500, f"写入 config.yaml 失败：{res['error']}")
    config_io.audit("auth", "password_setup", level="high",
                    note=f"首次设置控制台口令（写入 {res.get('backup') or 'config.yaml'}，值不入审计）")
    # 写完直接登录：设置与进入一步完成（票据与 /login 签发的完全同款）
    response.set_cookie(
        COOKIE_NAME, _make_token(), max_age=config.CONSOLE_TOKEN_TTL,
        httponly=True, samesite="strict", path="/")
    config_io.audit("auth", "login_ok", level="low", note="首次设置口令后自动登录")
    return {"ok": True, "expires_in": config.CONSOLE_TOKEN_TTL,
            "password_source": console_password_source(),
            "note": "口令已写入本机 config.yaml（consolePassword），重启服务后仍然有效。"}


@router.post("/password/change")
async def password_change(req: PasswordChangeRequest, request: Request):
    """登录后修改口令：校验当前口令 → 写入 config.yaml（长期保存）。"""
    require_auth(request)
    if _env_console_password():
        raise HTTPException(409, (
            "当前口令来自环境变量 AGENT_CONSOLE_PASSWORD（它优先于 config.yaml），"
            "控制台不能替你改环境变量 —— 请修改该环境变量后重启服务。"))
    want = console_password()
    if not hmac.compare_digest((req.current_password or "").strip(), want):
        config_io.audit("auth", "password_change_failed", level="mid",
                        actor="anonymous", note="当前口令错误")
        raise HTTPException(401, "当前口令错误。")
    pw = (req.new_password or "").strip()
    _validate_new_password(pw)
    if hmac.compare_digest(pw, want):
        raise HTTPException(400, "新口令与当前口令相同。")
    res = _write_config_yaml_keys({"consolePassword": pw})
    if not res["ok"]:
        raise HTTPException(500, f"写入 config.yaml 失败：{res['error']}")
    config_io.audit("auth", "password_change", level="high",
                    note="修改控制台口令（写入 config.yaml，值不入审计）")
    return {"ok": True, "password_source": console_password_source(),
            "file": config_io.file_state(_config_yaml_path()),
            "note": "新口令已写入本机 config.yaml，重启服务后仍然有效。当前会话保持登录。"}


# ============================================================================
# v102 白盒侧：代码库（data/codebases.json）+ 知识库（data/kb/）
# ============================================================================
# 为什么把白盒的写入口放在控制台、而不是主 UI 的左栏：
#   · **代码库入库 = 一条授权记录**（与授权靶标同级）⇒ 必须走「预览 → 二次确认 → 留痕」，
#     不能点一下就写。这条路径与 scope 页完全同款（见本模块顶部三条设计红线）。
#   · **知识库篇目是"给模型看的文档"**，写坏了模型会照着错的说明去调用工具，
#     比没有文档更坏。所以写入前强制过仓库既有硬约定，并提供一键跑 test_068 回归。
# 主 UI 那边只做只读展示（见 main.py 的 GET /api/codebases）。

#: KB 单篇字符上限。**与 test_068_kb_whitebox_docs.py 的断言同源**：
#: 超了会被默认读取口径（8000）截断，而"截了模型会以为看完了"。
KB_MAX_CHARS = 8000
#: README 索引合计行：「**合计：58 个知识文件**」
_KB_TOTAL_RE = _re.compile(r"(\*\*合计：)\s*(\d+)\s*(个知识文件\*\*)")
#: 白盒系列篇目（互相指得到是仓库硬约定，见 test_068 的 CROSS_REF）
_KB_CROSSREF_MAX = 8000


def _kb_dir():
    return config.DATA_DIR / "kb"


def _kb_readme():
    return _kb_dir() / "README.md"


def _kb_safe_name(name: str) -> str:
    """校验篇目名：只允许**单层**文件名且以 .md 结尾，禁止路径分隔符与上跳。"""
    n = (name or "").strip()
    if not n or not n.endswith(".md"):
        raise HTTPException(400, "篇目名必须以 .md 结尾")
    if any(ch in n for ch in ("/", "\\", ":")) or ".." in n or n.startswith("."):
        raise HTTPException(400, "篇目名不得含路径分隔符、上跳或以点开头")
    if len(n) > 120:
        raise HTTPException(400, "篇目名过长（>120 字符）")
    return n


def _kb_path(name: str):
    return _kb_dir() / _kb_safe_name(name)


def _kb_list_files() -> list[str]:
    d = _kb_dir()
    if not d.exists():
        return []
    return sorted(p.name for p in d.glob("*.md") if p.name != "README.md")


def _kb_compliance(name: str, text: str) -> dict:
    """按仓库既有硬约定检查一篇 KB 文档，返回 {"ok":bool,"issues":[...],"chars":int}。

    只检查**可判定的**那几条（与 test_068 同源），不评判"写得好不好"（那是主观的）：
      ① **白盒系列篇目**字符数 ≤ 8000 —— ⚠️ 这条**只对 whitebox-* 生效**：
         test_068 的长度断言只覆盖 DOCS（白盒各篇），其它篇（如 `xss-test.md`、
         `deserialization-test.md`）本来就是**长参考文档**，加这条限制会误报一片红灯，
         反而诱导人去"修"本应写长的东西。白盒篇目之所以有上限，是因为它在审计循环里
         被反复读取，超了会被默认读取口径截断、而"截了模型会以为看完了"。
      ② 不得含本机绝对路径（与 v056 隐私护栏同一条纪律，**所有篇目都适用**）；
      ③ 白盒系列篇目必须与其姊妹篇**互相指得到**（否则拆篇就散了）。
    """
    issues: list[str] = []
    warns: list[str] = []
    chars = len(text or "")
    if name.startswith("whitebox-"):
        if chars > KB_MAX_CHARS:
            issues.append(f"白盒篇目超出 {KB_MAX_CHARS} 字符上限（当前 {chars}）—— "
                          f"在审计循环里会被默认读取口径截断，而截了模型会以为看完了")
        elif chars > KB_MAX_CHARS * 0.9:
            warns.append(f"已接近上限（{chars}/{KB_MAX_CHARS}，剩 "
                         f"{KB_MAX_CHARS - chars} 字符）—— 仓库规矩是「满了就拆，别压」")
        others = [f[:-3] for f in _kb_list_files()
                  if f.startswith("whitebox-") and f != name]
        miss = [o for o in others if o not in (text or "")]
        if miss:
            issues.append("缺少姊妹篇指针：" + "、".join(f"`{m}`" for m in miss))
    # ⚠️ v102 自查修正：原写法是 `r"[A-Za-z]:\\\\Users\\\\"` —— 那是 4 个反斜杠，
    # 正则里 `\\\\` 匹配的是**两个**字面反斜杠，于是只命中 `C:\\Users\\` 这种
    # JSON/YAML 转义后的形态，而 KB 文档里真正的写法是**单**反斜杠 `C:\Users\…`。
    # 实测（2026-10-11）：真实写法、正斜杠写法**全部不命中** ⇒ 这是一条
    # **永不报警的护栏**，而"不报警的护栏等于没有护栏"。
    # 现在用 `[\\/]{1,2}` 同时吃下单/双反斜杠与正斜杠，并在 test_v102_modes.py 里
    # 加了自检（构造样本必须被命中），防止它再静默失效。
    if _re.search(r"[A-Za-z]:[\\/]{1,2}Users[\\/]", text or "", _re.I):
        issues.append("含本机绝对路径（C:\\Users\\…）—— 与隐私护栏冲突")
    # 三级：error（会被硬拦）> warn（可用但该处理）> ok。
    # 分开的意义：把"接近上限"和"已越界"都画成红灯，会让人以为这 4 篇已经坏了，
    # 而实际上它们只是该考虑拆篇了 —— 一个只会喊狼来了的检查没人看。
    level = "error" if issues else ("warn" if warns else "ok")
    return {"ok": level != "error", "level": level,
            "issues": issues, "warnings": warns, "chars": chars,
            "limited": name.startswith("whitebox-")}


def _kb_sync_readme(name: str, desc: str, remove: bool = False) -> dict:
    """把篇目变动同步进 `data/kb/README.md` 的索引表与合计数字。

    为什么必须自动做：test_068 断言「索引表行数 == 磁盘文件数」且
    「合计数字 == 磁盘文件数」，手工维护必然漂移（这是仓库已经踩过的坑）。
    """
    p = _kb_readme()
    if not p.exists():
        return {"ok": False, "reason": "README 索引不存在"}
    text = config_io.read_text(p)
    lines = text.splitlines()
    row_re = _re.compile(r"^\|\s*`" + _re.escape(name) + r"`\s*\|")
    idx = next((i for i, ln in enumerate(lines) if row_re.match(ln)), -1)

    if remove:
        if idx >= 0:
            del lines[idx]
    else:
        row = f"| `{name}` | {desc or '（待补说明）'} |"
        if idx >= 0:
            lines[idx] = row
        else:
            # 插到最后一行表格行之后（索引表在「文件清单」节里）
            last = max((i for i, ln in enumerate(lines) if ln.startswith("| `")),
                       default=-1)
            if last < 0:
                return {"ok": False, "reason": "README 里找不到索引表"}
            lines.insert(last + 1, row)

    # 合计数字 = 磁盘实际篇目数（以磁盘为准，自动纠正历史漂移）
    n = len(_kb_list_files())
    new_text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    new_text, cnt = _KB_TOTAL_RE.subn(rf"\g<1>{n} \g<3>", new_text)
    if not cnt:
        return {"ok": False, "reason": "README 里找不到「合计：N 个知识文件」那一行"}
    res = config_io.write_text_atomic(p, new_text)
    return {"ok": bool(res.get("ok")), "files": n, "backup": res.get("backup"),
            "error": res.get("error")}


# ---------------------------------------------------------------- 白盒总览

@router.get("/whitebox")
async def whitebox_overview(request: Request):
    """白盒侧总览：代码库列表 + 知识库篇目及其合规状态。只读。"""
    require_auth(request)
    from .codebase import paths as cbpaths

    cbs = []
    try:
        for cb in cbpaths.load_codebases():
            cbs.append({"codebase_id": cb.codebase_id, "root": str(cb.root),
                        "source": cb.source, "white_layer": cb.white_layer,
                        "note": cb.note, "added_at": cb.added_at})
    except Exception as e:                                   # noqa: BLE001
        logger.debug("读 codebases 失败：%s", e)

    docs = []
    for f in _kb_list_files():
        try:
            text = config_io.read_text(_kb_path(f))
        except Exception:                                    # noqa: BLE001
            text = ""
        c = _kb_compliance(f, text)
        # ⚠️ level / warnings 必须一起带上：前端按 level 画三级灯，
        # 只给 ok 的话"接近上限"会静默显示成绿灯（v102 自查抓到的漏项）。
        docs.append({"name": f, "chars": c["chars"], "ok": c["ok"],
                     "level": c["level"], "issues": c["issues"],
                     "warnings": c["warnings"], "limited": c["limited"]})
    docs.sort(key=lambda d: (-(d["level"] == "error"), -(d["level"] == "warn"),
                             -d["chars"]))

    return {"ok": True, "codebases": cbs, "kb": docs,
            "kb_count": len(docs), "kb_max": KB_MAX_CHARS,
            "codebases_file": config_io.file_state(cbpaths.CODEBASES_FILE)}


# ---------------------------------------------------------------- 知识库

@router.get("/kb/read")
async def kb_read(name: str, request: Request):
    require_auth(request)
    p = _kb_path(name)
    if not p.exists():
        raise HTTPException(404, "篇目不存在")
    text = config_io.read_text(p)
    return {"ok": True, "name": _kb_safe_name(name), "text": text,
            "compliance": _kb_compliance(_kb_safe_name(name), text),
            "file": config_io.file_state(p)}


class KbRequest(BaseModel):
    name: str = ""
    text: str = ""
    desc: str = ""          # 新增篇目时写进 README 索引表的一行说明
    delete: bool = False
    confirm_token: str = ""
    expect_sha256: str = ""


@router.post("/kb/preview")
async def kb_preview(req: KbRequest, request: Request):
    """预览 KB 篇目的写入/删除：过合规检查 + 算 diff + 签发确认票据。"""
    require_auth(request)
    name = _kb_safe_name(req.name)
    p = _kb_path(name)
    exists = p.exists()
    old = config_io.read_text(p) if exists else ""

    if req.delete:
        if not exists:
            raise HTTPException(404, "篇目不存在，无法删除")
        if name == "README.md":
            raise HTTPException(400, "README 是索引文件，不允许删除")
        tok = _issue_confirm("kb", "delete", {"name": name}, config_io.sha256_short(p))
        refs = [f for f in _kb_list_files()
                if f != name and name[:-3] in config_io.read_text(_kb_path(f))]
        return {"ok": True, "action": "delete", "level": "high",
                "requires_confirm": True, "confirm_token": tok,
                "expect_sha256": config_io.sha256_short(p),
                "referenced_by": refs[:20], "referenced_count": len(refs),
                "note": ("⚠️ 删除后上述篇目里的指针会指向不存在的文件，"
                         "test_068 的交叉引用断言会报红 —— 请一并修掉引用。"
                         if refs else "未被其它篇目引用。"),
                "confirm_ttl": config.CONSOLE_CONFIRM_TTL}

    new = req.text or ""
    if not new.strip():
        raise HTTPException(400, "内容为空")
    if new == old:
        raise HTTPException(400, "内容没有变化")
    comp = _kb_compliance(name, new)
    # 合规检查只报不拦？——**拦**。这条约定是仓库的硬约束（超了必然被截断），
    # 放行等于允许控制台把知识库写坏，而坏文档比没文档更坏。
    if not comp["ok"]:
        return {"ok": False, "hard_block": True, "compliance": comp,
                "error": "未通过仓库既有硬约定，已拒绝预览：\n- " + "\n- ".join(comp["issues"])}
    tok = _issue_confirm("kb", "write",
                         {"name": name, "text": new, "desc": req.desc}, 
                         config_io.sha256_short(p) if exists else "")
    import difflib
    d = list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0))
    return {"ok": True, "action": "write", "level": "mid", "requires_confirm": True,
            "confirm_token": tok, "expect_sha256": config_io.sha256_short(p) if exists else "",
            "exists": exists, "compliance": comp,
            "stats": {"before_chars": len(old), "after_chars": len(new)},
            "hunks": len([x for x in d if x.startswith("@@")]),
            "preview": "\n".join(d[:120]),
            "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/kb/commit")
async def kb_commit(req: KbRequest, request: Request):
    require_auth(request)
    rec = _consume_confirm(req.confirm_token, "kb")
    p = _kb_path(rec["payload"]["name"])

    if rec["action"] == "delete":
        name = rec["payload"]["name"]
        if not p.exists():
            raise HTTPException(404, "篇目已不存在")
        bak = config_io.backup(p)
        try:
            p.unlink()
        except OSError as e:
            raise HTTPException(500, f"删除失败：{e}")
        rd = _kb_sync_readme(name, "", remove=True)
        config_io.audit("kb", "delete", before={"name": name},
                        level="high", note="控制台删除知识库篇目")
        config_io.reload_for("kb")
        return {"ok": True, "deleted": name, "backup": bak, "readme": rd}

    cur = config_io.sha256_short(p) if p.exists() else ""
    if req.expect_sha256 and cur and cur != req.expect_sha256:
        raise HTTPException(409, "篇目在你预览之后被改动过，已拒绝写入。请重新预览。")
    name = rec["payload"]["name"]
    res = config_io.write_text_atomic(p, rec["payload"]["text"])
    if not res["ok"]:
        raise HTTPException(500, f"写入失败：{res['error']}")
    rd = _kb_sync_readme(name, rec["payload"].get("desc", ""), remove=False)
    config_io.audit("kb", "write",
                    before={"chars": len(config_io.read_text(p))},
                    after={"chars": len(rec["payload"]["text"])},
                    level="mid", note=f"控制台编辑知识库篇目 {name}")
    config_io.reload_for("kb")
    return {"ok": True, "name": name, "backup": res["backup"], "readme": rd,
            "file": config_io.file_state(p),
            "hint": "写完建议点「跑回归」验证 test_068（它会查索引/合计/交叉引用三项一致性）。"}


@router.post("/whitebox/regress")
async def whitebox_regress(request: Request):
    """跑 `test_068_kb_whitebox_docs.py`（KB 文档回归），返回通过/失败与输出尾部。

    为什么给按钮而不是让人敲命令：改 KB 的**唯一**硬验证就是这个脚本，
    把「改完就跑」缩成一次点击，比写在文档里提醒可靠。

    ⚠️ 正式版（发布接口）**刻意不带任何测试脚本** —— 发布库只放运行组件。
    所以这里必须区分两种情况，不能都报「找不到脚本」：
      · 发布版（无 run_all_tests.py）⇒ `shipped: false` + 说明「能力有意不含」，
        否则使用者会以为是安装损坏，去反复重装；
      · 工程测试库但文件被误删 ⇒ 原样报缺文件名（这才是真的异常）。
    """
    require_auth(request)
    import subprocess
    import sys as _sys
    script = config.APP_DIR / "test_068_kb_whitebox_docs.py"
    if not script.exists():
        if not (config.APP_DIR / "run_all_tests.py").exists():
            return {"ok": False, "shipped": False, "error": (
                "当前是正式版：发布库只放运行组件，不含 test_068 等回归脚本。"
                "需要校验 KB 改动时，请在工程测试库执行 "
                "`python test_068_kb_whitebox_docs.py`；"
                "本页的写入校验（字符上限 / 姊妹篇互指 / 索引合计同步）仍然照常生效。")}
        return {"ok": False, "shipped": True, "error": f"找不到回归脚本：{script.name}"}
    try:
        r = subprocess.run([_sys.executable, str(script)],
                           cwd=str(config.APP_DIR), capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=180)
    except Exception as e:                                   # noqa: BLE001
        return {"ok": False, "error": f"执行失败：{e}"}
    out = (r.stdout or "") + (r.stderr or "")
    tail = "\n".join(out.splitlines()[-40:])
    passed = failed = None
    m = _re.search(r"结果：\s*(\d+)\s*通过\s*/\s*(\d+)\s*失败", out)
    if m:
        passed, failed = int(m.group(1)), int(m.group(2))
    return {"ok": r.returncode == 0, "returncode": r.returncode,
            "passed": passed, "failed": failed, "output": tail}


# ---------------------------------------------------------------- 代码库

class CodebaseRequest(BaseModel):
    action: str = "upsert"        # upsert | delete
    codebase_id: str = ""
    root: str = ""
    source: str = "authorized"    # opensource | authorized
    white_layer: str = "partial"  # full | partial | gray
    note: str = ""
    confirm_token: str = ""
    expect_sha256: str = ""


@router.post("/codebases/preview")
async def codebases_preview(req: CodebaseRequest, request: Request):
    """预览代码库登记/删除。

    ⚠️ 代码库登记 = 一条**授权记录**（写进 data/codebases.json，与授权靶标同级）：
    它决定白盒会话"可以审计哪些本机目录"。所以这里用 **high** 级别 + 二次确认，
    并且**不**接受相对路径（避免"当前目录漂移导致审计到别的地方"）。
    """
    require_auth(request)
    from .codebase import paths as cbpaths
    import pathlib

    items = cbpaths.load_codebases()
    if req.action == "delete":
        cid = (req.codebase_id or "").strip()
        if not cid:
            raise HTTPException(400, "缺少 codebase_id")
        if not any(cb.codebase_id == cid for cb in items):
            raise HTTPException(404, f"代码库不存在：{cid}")
        tok = _issue_confirm("codebases", "delete", {"codebase_id": cid},
                             config_io.sha256_short(cbpaths.CODEBASES_FILE))
        return {"ok": True, "action": "delete", "level": "high",
                "requires_confirm": True, "confirm_token": tok,
                "expect_sha256": config_io.sha256_short(cbpaths.CODEBASES_FILE),
                "note": "删除只移除**登记记录**，不会动磁盘上的源码目录。",
                "confirm_ttl": config.CONSOLE_CONFIRM_TTL}

    root = (req.root or "").strip()
    if not root:
        raise HTTPException(400, "缺少 root（本机源码目录绝对路径）")
    p = pathlib.Path(root)
    if not p.is_absolute():
        raise HTTPException(400, "root 必须是**绝对路径**（相对路径会随工作目录漂移）")
    exists = p.exists() and p.is_dir()
    cid = (req.codebase_id or "").strip() or p.name.lower().replace(" ", "-")[:40]
    dup = [cb.codebase_id for cb in items if cb.codebase_id == cid]
    rec = {"codebase_id": cid, "root": str(p),
           "source": req.source if req.source in cbpaths.SOURCES else "authorized",
           "white_layer": (req.white_layer
                           if req.white_layer in cbpaths.WHITE_LAYERS else "partial"),
           "note": (req.note or "").strip()[:300],
           "added_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    tok = _issue_confirm("codebases", "upsert", rec,
                         config_io.sha256_short(cbpaths.CODEBASES_FILE))
    return {"ok": True, "action": "upsert", "level": "high",
            "requires_confirm": True, "confirm_token": tok,
            "expect_sha256": config_io.sha256_short(cbpaths.CODEBASES_FILE),
            "record": rec,
            "warnings": ([] if exists else [f"⚠️ 目录当前不存在：{p}（登记本身仍可写入，"
                                            f"但 code_index 会失败）"])
                        + ([f"⚠️ codebase_id 已存在，将被覆盖：{cid}"] if dup else []),
            "total_before": len(items),
            "confirm_ttl": config.CONSOLE_CONFIRM_TTL}


@router.post("/codebases/commit")
async def codebases_commit(req: CodebaseRequest, request: Request):
    require_auth(request)
    from .codebase import paths as cbpaths
    import pathlib

    rec = _consume_confirm(req.confirm_token, "codebases")
    cur = config_io.sha256_short(cbpaths.CODEBASES_FILE)
    if req.expect_sha256 and cur and cur != req.expect_sha256:
        raise HTTPException(409, "codebases.json 在你预览之后被改动过，已拒绝写入。"
                                 "请重新预览。")
    items = cbpaths.load_codebases()

    if rec["action"] == "delete":
        cid = rec["payload"]["codebase_id"]
        items = [cb for cb in items if cb.codebase_id != cid]
        cbpaths.save_codebases(items)
        config_io.audit("codebases", "delete", before={"codebase_id": cid},
                        after={"total": len(items)}, level="high",
                        note="控制台移除代码库登记")
        return {"ok": True, "deleted": cid, "total": len(items)}

    p = rec["payload"]
    items = [cb for cb in items if cb.codebase_id != p["codebase_id"]]
    items.append(cbpaths.Codebase(
        codebase_id=p["codebase_id"], root=pathlib.Path(p["root"]),
        source=p["source"], white_layer=p["white_layer"],
        note=p["note"], added_at=p["added_at"]))
    cbpaths.save_codebases(items)
    config_io.audit("codebases", "upsert",
                    before={"total": len(items) - 1}, after={"total": len(items)},
                    level="high",
                    note=f"控制台登记代码库 {p['codebase_id']}（{p['white_layer']}）")
    return {"ok": True, "codebase_id": p["codebase_id"], "total": len(items),
            "hint": "登记完可在白盒会话里让 Agent 执行 code_index 建索引。"}


# ============================================================ 本地工具（v110）
# 用户指定一个目录 → 程序自动识别里面的工具 → 并入工具箱。
#
# 为什么要有这一面：工具来源原先只有"某个第三方工具箱的 tools.json"，
# 于是没有那个工具箱的人一个外部工具都没有，也没法用自己的工具。
# 详见 app/local_tools.py 开头的设计说明。
#
# 写入面是**单个文件** data/local_tools.json（本机路径，gitignore），
# 所以乐观锁只需要核对它的哈希。风险分级与闸门**不在这里写** ——
# 那是「工具与分级」页的事，两类工具共用同一份配置（这就是"同一套闸门"的落点）。

#: alias 必须能当 function name 用（模型侧要求 ASCII、不以数字开头）。
#: 校验放在**提交前**：alias 是模型点名工具的唯一依据，写进去一个带中文/空格的
#: alias，表现为"工具在清单里但模型永远调不到"，极难排查。
_ALIAS_RE = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,47}$")

#: 单个目录识别到这么多工具就提醒。不是硬限制 —— 是提醒用户
#: 「这么多工具会给模型清单很大压力，考虑拆成几个目录或排除掉不需要的」。
LOCAL_TOOLS_WARN_COUNT = 60


class LocalRootIn(BaseModel):
    """一个自备工具目录（前端回传的期望状态）。"""
    path: str = ""
    label: str = ""
    category: str = ""
    enabled: bool = True
    java: str = "JAVA8"
    note: str = ""
    excluded: list[str] = []
    aliases: dict[str, str] = {}       # rel_path -> alias（只回传用户改过的）
    overrides: dict = {}               # 高级：name / type / category / description


class LocalToolsRequest(BaseModel):
    roots: list[LocalRootIn] = []
    confirm_token: str = ""
    expect_sha256: str = ""


class LocalBrowseRequest(BaseModel):
    path: str = ""


def _local_tools_path():
    from .local_tools import CONFIG_FILE
    return CONFIG_FILE


def _merge_root(inp: LocalRootIn) -> dict:
    """把前端回传的目录条目并成内部形状（`aliases` 折进 `overrides`）。"""
    ovs: dict[str, dict] = {}
    for rel, v in (inp.overrides or {}).items():
        if isinstance(v, dict):
            ovs[str(rel)] = {k: v[k] for k in ("name", "type", "category", "description")
                             if v.get(k)}
    for rel, alias in (inp.aliases or {}).items():
        a = str(alias or "").strip()
        cur = ovs.setdefault(str(rel), {})
        if a:
            cur["alias"] = a
        else:
            cur.pop("alias", None)
    return {
        "path": str(inp.path or "").strip(),
        "label": str(inp.label or "").strip(),
        "category": str(inp.category or "").strip(),
        "enabled": bool(inp.enabled),
        "java": str(inp.java or "JAVA8").strip().upper(),
        "note": str(inp.note or "").strip(),
        "excluded": [str(x) for x in (inp.excluded or [])],
        "overrides": {k: v for k, v in ovs.items() if v},
    }


def _diff_roots(before: list[dict], after: list[dict]) -> list[dict]:
    """目录级差异（新增 / 移除 / 字段变更 / 排除项增减 / 别名变更）。"""
    bmap = {str(r.get("path", "")).lower(): r for r in before}
    amap = {str(r.get("path", "")).lower(): r for r in after}
    diff: list[dict] = []
    for k, a in amap.items():
        b = bmap.get(k)
        lbl = a.get("label") or a.get("path")
        if not b:
            diff.append({"key": "目录 · 新增", "before": "（无）", "after": f"{lbl}（{a['path']}）"})
            continue
        for f, cn in (("label", "显示名"), ("category", "默认分类"),
                      ("enabled", "启用"), ("java", "jar 的 java 版本"), ("note", "备注")):
            if b.get(f) != a.get(f):
                diff.append({"key": f"{lbl} · {cn}", "before": b.get(f), "after": a.get(f)})
        be, ae = set(b.get("excluded") or []), set(a.get("excluded") or [])
        for x in sorted(ae - be):
            diff.append({"key": f"{lbl} · 不再纳入", "before": "纳入", "after": x})
        for x in sorted(be - ae):
            diff.append({"key": f"{lbl} · 重新纳入", "before": x, "after": "纳入"})
        bo, ao = b.get("overrides") or {}, a.get("overrides") or {}
        for rel in sorted(set(bo) | set(ao)):
            if bo.get(rel) != ao.get(rel):
                diff.append({"key": f"{lbl} · {rel}",
                             "before": json.dumps(bo.get(rel) or {}, ensure_ascii=False),
                             "after": json.dumps(ao.get(rel) or {}, ensure_ascii=False)})
    for k, b in bmap.items():
        if k not in amap:
            diff.append({"key": "目录 · 移除",
                         "before": f"{b.get('label') or b.get('path')}（{b.get('path')}）",
                         "after": "（已移除）"})
    return diff


def _validate_roots(raw: list[dict]) -> tuple[list[str], list[str]]:
    """返回 (阻断性错误, 提醒)。阻断就不签发票据。"""
    from . import local_tools as lt

    errors: list[str] = []
    warns: list[str] = []
    seen: dict[str, str] = {}
    for r in raw:
        lbl = r.get("label") or r.get("path") or "（未命名）"
        p, err = lt.validate_root_path(r.get("path", ""))
        if err:
            errors.append(f"「{lbl}」：{err}")
            continue
        key = str(p).lower()
        if key in seen:
            errors.append(f"「{lbl}」与「{seen[key]}」是同一个目录，重复添加了。")
        seen[key] = lbl
        if r.get("java") not in ("JAVA8", "JAVA11"):
            warns.append(f"「{lbl}」的 java 版本 {r.get('java')!r} 不认识，"
                         "已按 JAVA8 处理（可选 JAVA8 / JAVA11）。")
        # ⚠️ 校验的是**折进 overrides 之后**的别名，不是入参里的 `aliases`。
        # `_merge_root()` 会把 `aliases` 并进 `overrides[rel]["alias"]` 并丢掉顶层键，
        # 所以这里读 `r["aliases"]` 会永远拿到空 —— 那段校验就成了死代码
        # （本套单测第一版就是这么写的，被 test_local_tools 抓出来）。
        for rel, ov in (r.get("overrides") or {}).items():
            a = str((ov or {}).get("alias") or "").strip()
            if a and not _ALIAS_RE.match(a):
                errors.append(
                    f"「{lbl}」的别名 {a!r} 不能用作工具名（{rel}）："
                    "只能是字母/数字/下划线，且以字母或下划线开头（模型侧要求 ASCII）。")
        scan = lt.scan_root(r)
        if scan["exists"]:
            inc = scan["stats"]["included"]
            if inc == 0:
                warns.append(f"「{lbl}」里没有识别到工具，保存后它不会贡献任何工具。")
            elif inc >= LOCAL_TOOLS_WARN_COUNT:
                warns.append(
                    f"「{lbl}」识别到 {inc} 个工具 —— 数量偏多，它们会**全部**进入模型"
                    "工具清单，可能拖慢本地小模型的决策。建议拆成几个目录，"
                    "或把不需要的排除掉。")
    if not raw:
        warns.append("保存后不含任何自备工具目录 —— 等于清空本机自备工具。")
    return errors, warns


@router.get("/localtools")
async def localtools_get(request: Request):
    """列出已添加的目录 + 各自的识别结果。"""
    require_auth(request)
    from . import local_tools as lt
    from .registry import registry

    conf = lt.load_config()
    files = config_io.file_state(_local_tools_path())
    roots = []
    for r in conf["roots"]:
        scan = lt.scan_root(r)
        roots.append({
            "id": scan["id"], "path": scan["path"], "label": scan["label"],
            "category": scan["category"], "enabled": scan["enabled"],
            "java": r.get("java") or "JAVA8", "note": scan.get("note", ""),
            "exists": scan["exists"], "problem": scan["problem"],
            "stats": scan["stats"], "truncated": scan["truncated"],
            "hint": scan.get("hint", ""),
            "tools": [{"rel_path": t["rel_path"], "name": t["name"], "type": t["type"],
                       "category": t["category"], "excluded": t["excluded"],
                       "exists": True} for t in scan["tools"]],
        })
    return {
        "ok": True,
        "roots": roots,
        "counts": {
            "roots": len(roots),
            "local_tools": registry.stats().get("local", 0),
            "registry_total": len(registry.tools),
        },
        "ext_types": {k: v for k, v in sorted(lt.EXT_TYPES.items())},
        "bookmark_exts": sorted(lt.BOOKMARK_EXTS),
        "shortcut_exts": sorted(lt.SHORTCUT_EXTS),
        "max_depth": lt.MAX_DEPTH,
        "warn_count": LOCAL_TOOLS_WARN_COUNT,
        "file": files,
        "note": ("这里只登记**目录**，工具条目每次启动重新扫描 —— "
                 "在目录里增删工具后重启即跟随。风险分级与闸门请到「工具与分级」页改，"
                 "自备工具与外部工具共用那两份配置。"),
    }


@router.post("/localtools/browse")
async def localtools_browse(req: LocalBrowseRequest, request: Request):
    """目录选择器：列出一个目录下的**子目录**（只给名字，不读文件内容）。

    浏览器出于安全**不会**把 `<input type=file>` 选中的绝对路径告诉页面，
    而这里需要的恰是本机绝对路径，所以只能自己给一个浏览入口。
    范围刻意收得很窄：只返回目录名与"该目录里识别到几个工具"，
    **不返回任何文件内容**；控制台本身有口令闸门且只改配置。
    """
    require_auth(request)
    import os
    from pathlib import Path as _P
    from . import local_tools as lt

    raw = str(req.path or "").strip().strip('"').strip("'")
    if not raw:
        drives = []
        for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            d = _P(f"{ch}:\\")
            if d.exists():
                drives.append({"name": f"{ch}:\\", "path": f"{ch}:\\", "count": None})
        return {"ok": True, "path": "", "parent": "", "dirs": drives,
                "is_root_list": True, "hint": "请选择一个盘符，再逐级进入工具目录。"}

    p = _P(raw)
    if not p.exists() or not p.is_dir():
        raise HTTPException(400, f"目录不存在：{raw}")
    dirs = []
    try:
        with os.scandir(p) as it:
            for e in sorted(it, key=lambda x: x.name.lower()):
                if len(dirs) >= 500:
                    break
                try:
                    if e.is_dir(follow_symlinks=False) and not e.name.startswith("."):
                        dirs.append({"name": e.name, "path": str(_P(e.path)), "count": None})
                except OSError:
                    continue
    except OSError as exc:
        raise HTTPException(400, f"读取目录失败：{exc}") from exc

    # 当前目录自己识别到几个工具（浅扫，给用户"就是这里"的判断依据）
    here = None
    try:
        s = lt.scan_root({"path": str(p)})
        if s["exists"]:
            here = s["stats"]
    except Exception:                                     # noqa: BLE001
        here = None
    parent = str(p.parent) if str(p.parent) != str(p) else ""
    return {"ok": True, "path": str(p), "parent": parent, "dirs": dirs,
            "is_root_list": False, "here": here,
            "accepts": sorted(lt.EXT_TYPES) + sorted(lt.BOOKMARK_EXTS)}


@router.post("/localtools/scan")
async def localtools_scan(req: LocalRootIn, request: Request):
    """扫描一个候选目录，返回"纳入后会长什么样"（**不写盘**）。"""
    require_auth(request)
    from . import local_tools as lt
    from .registry import registry

    merged = _merge_root(req)
    _p, err = lt.validate_root_path(merged["path"])
    if err:
        raise HTTPException(400, err)
    scan = registry.preview_local_root(merged)
    scan["ok"] = True
    scan["warn_count"] = LOCAL_TOOLS_WARN_COUNT
    return scan


@router.post("/localtools/preview")
async def localtools_preview(req: LocalToolsRequest, request: Request):
    """校验 + 算差异 + 签发一次性确认票据。"""
    require_auth(request)
    from . import local_tools as lt

    raw = [_merge_root(r) for r in req.roots]
    errors, warns = _validate_roots(raw)
    if errors:
        raise HTTPException(400, "校验未通过：" + "；".join(errors))

    before = [dict(r) for r in lt.load_config()["roots"]]
    after = lt.save_config(raw)["roots"]
    diff = _diff_roots(before, after)
    if not diff:
        raise HTTPException(400, "没有任何改动。")

    sha = config_io.sha256_short(_local_tools_path())
    tok = _issue_confirm("localtools", "write", {"roots": after}, sha)
    adds = sum(1 for d in diff if d["key"].endswith("新增"))
    removes = sum(1 for d in diff if d["key"].endswith("移除"))
    return {
        "ok": True, "diff": diff, "level": "high" if (adds or removes) else "mid",
        "requires_confirm": True, "confirm_token": tok,
        "expect_sha256": sha, "confirm_ttl": config.CONSOLE_CONFIRM_TTL,
        "warnings": warns
                    + ([f"将新增 {adds} 个工具目录"] if adds else [])
                    + ([f"将移除 {removes} 个工具目录"] if removes else []),
    }


@router.post("/localtools/commit")
async def localtools_commit(req: LocalToolsRequest, request: Request):
    require_auth(request)
    from . import local_tools as lt
    from .registry import registry

    rec = _consume_confirm(req.confirm_token, "localtools")
    cur = config_io.sha256_short(_local_tools_path())
    if req.expect_sha256 and cur and cur != req.expect_sha256:
        raise HTTPException(409, (
            "local_tools.json 在你预览之后被改动过（可能手工编辑或另一次提交），"
            f"已拒绝写入以免覆盖。盘上当前 {cur} ≠ 你确认时的 {req.expect_sha256}。"
            "请刷新页面重新预览。"))

    # ⚠️ 先取一份"改前"快照 —— 写盘之后再读就是同一份了，审计会变成"改了=没改"。
    before_paths = [r.get("path") for r in lt.load_config()["roots"]]
    payload = lt.save_config(rec["payload"]["roots"])
    res = config_io.write_json_atomic(_local_tools_path(), payload)
    if not res.get("ok"):
        raise HTTPException(500, f"写入失败：{res.get('error')}")

    n_local = registry.load().stats().get("local", 0)
    config_io.audit("localtools", "write",
                    before={"roots": before_paths},
                    after={"roots": [r["path"] for r in payload["roots"]],
                           "local_tools": n_local},
                    level="high",
                    note=f"自备工具目录 {len(payload['roots'])} 个，识别出 {n_local} 个工具")

    roots = []
    for r in payload["roots"]:
        s = lt.scan_root(r)
        roots.append({"path": s["path"], "label": s["label"], "exists": s["exists"],
                      "stats": s["stats"], "problem": s["problem"]})
    return {
        "ok": True, "roots": roots, "local_tools": n_local,
        "registry_total": len(registry.tools),
        "registry_errors": list(registry.errors),
        "file": config_io.file_state(_local_tools_path()),
        "hint": ("已重载 registry。新工具现在可以在会话里被 Agent 调用；"
                 "想在面板里点击启动的，去「工具与分级」页确认它没被禁用。"),
    }


# ============================================================ 统计看板（v111）
# 「统计看板」页的数据口。与 `/api/usage/*` 是**互补的两侧**，刻意不重叠：
#   · `/api/usage/*`        = **成本侧**（token 用量、费用趋势）—— 已有，本口不重复；
#   · `/api/console/stats`  = **执行侧**（步骤成功率、耗时、工具调用、目标流量）—— 本口。
# 为什么不复用逐会话接口：看板要的是**跨项目聚合**，让前端拉全部会话再算不现实
# （数据量大，且控制台不该拉全量）。
#
# 三条约束（防止它长成一个通用查询口）：
#   ① 只读，不接受任意 SQL / 任意时间范围；`days` 夹取到 [0, 365]。
#   ② 快照式 + 30 秒内存缓存（看板切页会反复拉）。"实时"是「实时监控」页的事，走 SSE。
#   ③ 分母为 0 时 `success_rate` 返回 **None 而不是 0**（0 会被读成"全线失败"）。

STATS_CACHE: dict[str, dict] = {}
STATS_CACHE_TTL = 30.0
STATS_MAX_DAYS = 365
STATS_MAX_TOP = 50
#: 窗口内"配了却一次没用过"的工具最多回传多少条（列表本身可能很长）
STATS_NEVER_USED_MAX = 20

#: 失败归因归一化。原值散落在 `agent.Agent._attribute_failure` 的分层里，
#: 直接画出来是碎的（层级码与语义名混在一列）。这里收敛成有限几个**可行动**的桶。
_ATTR_BUCKETS = {
    "SCOPE": "停手·授权边界",
    "WAF_BLOCKED": "停手·目标防护",
    "WAF_CAUTION": "停手·目标防护",
    "NETWORK": "网络",
    "L1": "工具未跑起来",
    "L3": "被环境拦下",
    "L4": "跑通但无结果",
}
#: 被闸门拒绝（status=denied）时记的是**哪道闸门**（v111 起写入）。
#: 空值 = v111 之前的旧数据 —— 必须与"没归因"区分开，否则会让人以为归因逻辑漏了。
_GATE_BUCKETS = {
    "GATE_SUBTASK": "闸门拒绝·子任务",
    "GATE_CONSTRAINT": "闸门拒绝·任务约束",
    "GATE_RISK": "闸门拒绝·风险确认",
}


def _bucket_of(status: str, attribution: str) -> str:
    a = (attribution or "").strip().upper()
    if status == "denied" or a.startswith("GATE_"):
        return _GATE_BUCKETS.get(a, "闸门拒绝·未标注（旧数据）")
    if a in _ATTR_BUCKETS:
        return _ATTR_BUCKETS[a]
    if not a:
        return "未归因"
    # 未知取值也要**显式出现**，不能悄悄丢 —— 丢了就没人知道归因口径变了。
    return f"其他（{attribution}）"


def _shape_stats(raw: dict, days: int, since, now: float, raw_days: int,
                 cache_hit: bool) -> dict:
    from .registry import registry as reg

    st = raw["steps"]
    bs = st["by_status"]
    done = bs.get("done", 0)
    err = bs.get("error", 0)
    denied = bs.get("denied", 0)
    running = bs.get("running", 0)

    # ⚠️ 分母**只取 `done + error`**。两条都不能混进来：
    #   · `denied` = 闸门按设计拦下的，**不是工具失败**。混进分母会让"成功率"
    #     随"用户有没有配白名单 / 任务约束"漂移 —— 配得越严数字越难看，
    #     看板会骗人（实测本机 11/306 = 3.6%，混进去成功率掉 3.6 个点）；
    #   · `running` = 在途，还没有结论。
    judged = done + err
    success_rate = round(done / judged, 4) if judged else None

    buckets: dict[str, int] = {}
    for row in st["by_attribution"]:
        b = _bucket_of(row["status"], row["attribution"])
        buckets[b] = buckets.get(b, 0) + row["n"]

    used = set(raw["tools"].get("used") or [])
    # ⚠️ 这里比的是**可用可编排工具**（`usable_scriptable()`，本机 60 个），
    # 不是模型实际拿到的 schema 清单（那是 40 条上限截过的）。
    # 所以要回答的是「哪些可用工具从来没被调用过」这个运维问题，
    # 字段名也必须叫 usable —— 叫 in_model 会让人以为它等于 schema 里的条数。
    usable = [t.alias for t in reg.usable_scriptable()]
    never = [a for a in usable if a not in used]

    ev = raw["traffic"]["by_event_type"]
    sent, settled = ev.get("sent", 0), ev.get("settled", 0)

    notes: list[str] = []
    if days != raw_days:
        notes.append(f"请求的 days={raw_days} 超出允许范围，已按 {days} 处理"
                     f"（0 = 全部历史，上限 {STATS_MAX_DAYS} 天）。")
    if not st["total"] and raw["span"]["last_step_at"]:
        notes.append(
            f"这个窗口内没有步骤。库里数据的时间跨度是 "
            f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(raw['span']['first_step_at']))} "
            f"→ {time.strftime('%Y-%m-%d %H:%M', time.localtime(raw['span']['last_step_at']))}"
            f"（共 {raw['span']['sessions']} 个会话）—— "
            "把 days 调大或设为 0 可看全部历史。")
    elif not raw["span"]["last_step_at"]:
        notes.append("库里还没有任何步骤记录（新装或还没跑过任务）。")
    if denied:
        notes.append(f"status=denied 的 {denied} 条是**闸门按设计拦下**的，"
                     "已从「成功率」分母中剔除（见 attribution 分布）。")
    el = st["elapsed"]
    if el.get("excluded"):
        notes.append(f"有 {el['excluded']} 条步骤没记录到耗时（elapsed ≤ 0），"
                     "已排除出分位数计算 —— 否则 p50 会被拉到 0。")
    if sent and settled and sent > settled:
        notes.append(f"流量事件里 sent={sent} 但 settled={settled}，"
                     f"差 {sent - settled} 条（发出去了没落地，可能是事件丢失或未完成）。")
    if running:
        notes.append(f"有 {running} 条步骤仍在 running（在途，不计入成功率）。")

    return {
        "ok": True,
        "window": {"days": days, "since": since, "until": now,
                   "label": "全部历史" if days == 0 else f"最近 {days} 天"},
        "requested_days": raw_days,
        "clamped": days != raw_days,
        "cache": {"hit": cache_hit, "ttl": STATS_CACHE_TTL},
        "generated_at": now,
        "steps": {
            "total": st["total"], "by_status": bs,
            "judged": judged, "success_rate": success_rate,
            "denied_by_gate": denied, "running": running,
            "elapsed": el,
        },
        "attribution": [{"bucket": k, "n": v}
                        for k, v in sorted(buckets.items(), key=lambda x: (-x[1], x[0]))],
        "attribution_raw": st["by_attribution"],
        "tools": {
            "top": raw["tools"]["top"], "distinct": raw["tools"]["distinct"],
            "used": raw["tools"].get("used") or [],
            "usable": len(usable),
            "never_used": never[:STATS_NEVER_USED_MAX],
            "never_used_total": len(never),
        },
        "traffic": raw["traffic"],
        "findings": raw["findings"],
        "flow": raw["flow"],
        "span": raw["span"],
        "notes": notes,
    }


@router.get("/stats")
async def stats_get(request: Request, days: int = 30, top: int = 15, refresh: int = 0):
    """统计看板数据（只读，快照式）。

    `days=0` 表示全部历史；`refresh=1` 跳过缓存（排障时用）。
    """
    require_auth(request)
    from . import store

    raw_days = int(days)
    days = max(0, min(raw_days, STATS_MAX_DAYS))
    top = max(1, min(int(top), STATS_MAX_TOP))
    now = time.time()
    since = None if days == 0 else now - days * 86400

    key = f"{days}:{top}"
    ent = STATS_CACHE.get(key)
    hit = bool(ent) and not refresh and (now - ent["at"]) < STATS_CACHE_TTL
    if hit:
        raw = ent["data"]
    else:
        raw = store.console_stats(since, top)
        # 缓存里存**原始聚合**，派生字段（成功率/桶/notes）每次现算 ——
        # 否则命中缓存时会把上一次的派生结果连同它的 window/hit 一起回给前端。
        STATS_CACHE[key] = {"at": now, "data": raw}
    return _shape_stats(raw, days, since, now, raw_days, hit)


# ============================================================ 运行监控（v112）
# 「实时监控」页的入口列表：跨项目看"现在有哪些运行、各自什么状态、**谁在等我确认**"。
#
# 为什么必须是新接口：此前**没有任何"列会话"的口子** ——
#   · `/api/projects` 只给项目；
#   · `/api/projects/{pid}` 带 sessions，但要看全部就得走遍每个项目（N+1）；
#   · `store.list_sessions(None)` 内部存在却没被任何接口暴露。
# 于是监控页"必须事先知道 sid 才能看"，没法当监控用。
#
# ⚠️ 本接口**只读**，且**绝不新造确认/取消通道**：
# 确认的双闸门（token + step_id + auth_ack）是安全核心，见 `/api/sessions/{sid}/confirm`
# 的注释。控制台只做「换个界面调用同一个接口」——重写一遍就等于绕过它。
# 所以这里只列清单，点进去仍调既有 `/confirm`、`/cancel`、`/stream`。

RUNS_DEFAULT_LIMIT = 50
RUNS_MAX_LIMIT = 200

#: 会话状态 → 给人看的说明。**内存里的 `Session.state` 是权威**（见 _shape_run）。
#: ⚠️ `cancelling` 刻意**不在**这张表里：它不是 `session.state`，只是 `/cancel` 的返回串。
#: 真正的"正在取消"必须读 `cancel_event.is_set()`。
RUN_STATE_LABEL = {
    "idle": "空闲（可派任务）",
    "running": "执行中",
    "awaiting_confirm": "等待人工确认",
    "done": "已完成",
    "error": "出错结束",
    "interrupted": "被中断（服务重启等）",
}
#: 这些状态需要人去管 —— 列表要排在前面并高亮
RUN_URGENT_STATES = ("awaiting_confirm", "interrupted")
#: 「只看活跃」时的保留集
RUN_ACTIVE_STATES = ("idle", "running", "awaiting_confirm")


def _pending_of(s) -> dict | None:
    """把「正在等确认的那一步」整理成列表页要用的最小信息。

    ⚠️ 刻意**不返回** SSE `need_confirm` 事件里那个 `second` 字段：它的含义是
    "这是第几轮"，而 `/api/sessions/{sid}` 里同名的 `second` 是"该步是否需要双轮确认"。
    同名不同义 —— 本项目的看板脚本就曾拿它当风险等级用、把 L3 印成了 L2
    （见 main.py 里那段注释）。这里一律用语义明确的名字。
    """
    pend = getattr(s, "pending_confirm", None) or {}
    if getattr(s, "state", "") != "awaiting_confirm" or not pend:
        return None
    step_id = str(pend.get("step_id") or "")
    step = next((x for x in getattr(s, "steps", []) if x.id == step_id), None)
    lvl = ""
    if step is not None:
        lvl = str((getattr(step, "risk", None) or {}).get("level") or "")
        if not lvl:
            from .registry import registry as _reg
            lvl = (_reg.risk_of(getattr(step, "tool_alias", "")) or {}).get("level", "")
    return {
        "step_id": step_id,
        "tool_alias": getattr(step, "tool_alias", "") if step else "",
        "tool_name": getattr(step, "tool_name", "") if step else "",
        "target": getattr(step, "target", "") if step else "",
        "risk_level": lvl,
        "requires_double_confirm": bool(pend.get("double_confirm")),
        # token 要给前端才能提交（与 `/api/sessions/{sid}` 同口径）：只在本机回环 +
        # 控制台口令闸门之后暴露，且是**一次性**、短时有效。
        "token": str(pend.get("token") or ""),
    }


def _shape_run(sid: str, s, row: dict | None, by_status: dict[str, int],
               pname: str, now: float) -> dict:
    """把「内存会话 + 落库快照」合成列表的一行。

    ⭐ **运行状态以内存为准**：`sessions.sessions` 里的 `Session` 才是"现在"，
    而库里的 `sessions.state` 是**落库时的快照**。服务重启后内存清空，
    `store.init_db()` 会把库里的 running/awaiting_confirm 统一改成 `interrupted`
    （避免"僵尸会话永远显示执行中"）—— 那套机制**已经存在，这里不要重造**，
    但要把它当作一个**行动项**显式展示（可续聊 / 去看半程摘要）。
    """
    live = s is not None
    state = str(getattr(s, "state", "") or "") if live else str((row or {}).get("state") or "unknown")
    mem: dict[str, int] = {}
    if live:
        for st in getattr(s, "steps", []):
            mem[st.status or "?"] = mem.get(st.status or "?", 0) + 1
    db = dict(by_status or {})
    # 两个来源**逐状态取较大值**：步骤是"每步即时落库"的，所以任一侧有的都确实发生过；
    # 取 max 才不会因为某次落库失败而少报，两侧一致时结果不变。
    # （只信内存会在"内存对象没装回历史步骤"时少报；只信库会在"还没轮到落库"时少报。）
    by = {k: max(mem.get(k, 0), db.get(k, 0)) for k in set(mem) | set(db)}
    total = sum(by.values())
    pending = _pending_of(s) if live else None
    # ⚠️ 「正在取消」读的是 cancel_event，**不是** state：`/cancel` 只 set() 事件，
    # `state` 直到循环跑到下一个步骤边界才变。只看 state 会让界面在这段时间里
    # 显示成正常的"执行中"，用户以为取消没生效、反复点。
    cancelling = bool(live and getattr(s, "cancel_event", None) is not None
                      and s.cancel_event.is_set())
    return {
        "session_id": sid,
        "project_id": str((getattr(s, "project", "") if live else (row or {}).get("project_id")) or ""),
        "project_name": pname,
        "title": str((getattr(s, "title", "") if live else (row or {}).get("title")) or ""),
        "target": str((getattr(s, "target", "") if live else (row or {}).get("target")) or ""),
        "mode": str((getattr(s, "mode", "") if live else (row or {}).get("mode")) or "blackbox"),
        "subtask": bool((getattr(s, "subtask", False) if live else (row or {}).get("subtask")) or False),
        "parent_id": str((getattr(s, "parent_id", "") if live else (row or {}).get("parent_id")) or ""),
        "state": state,
        "state_label": RUN_STATE_LABEL.get(state, state),
        "live": live,
        "cancelling": cancelling,
        "awaiting_confirmation": bool(pending),
        "pending": pending,
        "awaiting_summary": (f"{pending['tool_alias'] or pending['tool_name']} → "
                             f"{pending['target'] or '（无目标）'}（风险 {pending['risk_level'] or '?'}）"
                             if pending else ""),
        "steps": {"total": total, "by_status": by,
                  "done": by.get("done", 0), "error": by.get("error", 0),
                  "denied": by.get("denied", 0)},
        # 「需要人管」= 在等我确认 或 被中断。列表据此排序并高亮 —— 这是这一页存在的理由。
        "urgent": state in RUN_URGENT_STATES,
        "created_at": float((getattr(s, "created_at", 0) if live else (row or {}).get("created_at")) or 0),
        "summary": str((getattr(s, "summary", "") if live else (row or {}).get("summary")) or ""),
    }


@router.get("/runs")
async def runs_get(request: Request, limit: int = RUNS_DEFAULT_LIMIT, active: int = 0,
                   project_id: str = "", mode: str = ""):
    """运行时会话列表（只读）。`active=1` 只看活跃，`mode` 按工作模式过滤。"""
    require_auth(request)
    from . import store
    from .agent import sessions as live_mgr

    raw_limit = int(limit)
    n = max(1, min(raw_limit, RUNS_MAX_LIMIT))
    now = time.time()

    rows = store.list_sessions(None, n)
    by_sid = {r["id"]: r for r in rows}
    live = dict(live_mgr.sessions)

    # ⚠️ 内存里刚建、还没跑过的会话**不在库里**（`POST /api/sessions` 只做
    # `sessions.create`，不落库）—— 只查库会漏掉"刚点开还没发任务"的那一条，
    # 而它恰恰是用户最想确认"我点开的那个在哪"的。所以并集要补上内存侧。
    sids = list(by_sid.keys()) + [x for x in live if x not in by_sid]
    counts = store.session_step_counts(sids)
    pnames = {p["id"]: (p.get("name") or "") for p in store.list_projects()}

    # ⚠️ 项目名要按"内存优先"取 project_id 再查表：只在内存里的会话在库里没有行，
    # 用 `(by_sid.get(sid) or {})` 取会得到空串，项目列就会是空的。
    items = []
    for sid in sids:
        sv = live.get(sid)
        row = by_sid.get(sid)
        pid = str((getattr(sv, "project", "") if sv is not None
                   else (row or {}).get("project_id")) or "")
        items.append(_shape_run(sid, sv, row, counts.get(sid) or {}, pnames.get(pid, ""), now))

    m = (mode or "").strip().lower()
    if m in ("blackbox", "whitebox"):
        items = [x for x in items if store.normalize_mode(x["mode"]) == m]
    if project_id:
        items = [x for x in items if x["project_id"] == project_id]
    if int(active or 0):
        items = [x for x in items if x["state"] in RUN_ACTIVE_STATES]

    # 需要人管的排最前，其余按创建时间倒序
    items.sort(key=lambda x: (0 if x["urgent"] else 1, -x["created_at"]))

    notes: list[str] = []
    n_await = sum(1 for x in items if x["awaiting_confirmation"])
    if n_await:
        notes.append(f"有 {n_await} 个运行**正等着你确认**：Agent 不点它就会一直停在那一步"
                     "（超时后该步作废，不会自动放行）。")
    n_int = sum(1 for x in items if x["state"] == "interrupted")
    if n_int:
        notes.append(f"有 {n_int} 个运行是**被中断**的（服务重启或异常结束，落库时统一标成 "
                     "interrupted —— 否则会永远显示『执行中』这个僵尸状态）。"
                     "它们没有在跑，但半程成果已沉淀，可以续聊接着做。")
    n_can = sum(1 for x in items if x["cancelling"])
    if n_can:
        notes.append(f"有 {n_can} 个运行**正在取消**（已请求，等当前步骤跑完即收尾）。"
                     "注意「正在取消」读的是取消事件而不是状态字段 —— state 要跑到下一个"
                     "步骤边界才变。")
    n_mem = sum(1 for x in items if x["live"] and x["session_id"] not in by_sid)
    if n_mem:
        notes.append(f"有 {n_mem} 个会话只存在于内存（建了但还没派任务，因此还没落库）。"
                     "服务重启后它们会消失。")
    if not items:
        notes.append("当前没有任何运行。列表最多回看 "
                     f"{n} 条历史；「只看活跃」可过滤掉已结束的。")
    notes.append("这一页只读：确认与取消都**透传**既有接口"
                 "（/api/sessions/{sid}/confirm 与 /cancel），不另造通道 —— "
                 "确认的双闸门（一次性 token + 绑定步骤 + L3 书面授权确认）是安全核心。")

    return {
        "ok": True,
        "items": items,
        "counts": {
            "total": len(items),
            "live": sum(1 for x in items if x["live"]),
            "awaiting": n_await,
            "cancelling": n_can,
            "interrupted": n_int,
            "urgent": sum(1 for x in items if x["urgent"]),
        },
        "window": {"limit": n, "requested_limit": raw_limit,
                   "clamped": n != raw_limit, "active": bool(int(active or 0)),
                   "project_id": project_id, "mode": m if m in ("blackbox", "whitebox") else ""},
        "generated_at": now,
        "live_total": len(live),
        "run_state_label": RUN_STATE_LABEL,
        "notes": notes,
    }
