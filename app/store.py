# -*- coding: utf-8 -*-
"""项目仓储：SQLite 持久化项目、会话、执行步骤与漏洞发现。"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import config

logger = logging.getLogger("src_agent.store")

DB_PATH = config.DATA_DIR / "projects.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    target      TEXT,
    note        TEXT,
    created_at  REAL,
    mode        TEXT DEFAULT 'blackbox'
);
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    task        TEXT,
    target      TEXT,
    state       TEXT,
    created_at  REAL,
    parent_id   TEXT DEFAULT '',
    title       TEXT DEFAULT '',
    status      TEXT DEFAULT 'active',
    context     TEXT DEFAULT '[]',
    summary     TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS steps (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    tool_alias  TEXT,
    tool_name   TEXT,
    target      TEXT,
    args        TEXT,
    risk_level  TEXT,
    status      TEXT,
    output      TEXT,
    attribution TEXT DEFAULT '',
    elapsed     REAL DEFAULT 0,
    created_at  REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    title       TEXT,
    severity    TEXT,
    target      TEXT,
    detail      TEXT,
    evidence    TEXT,
    session_id  TEXT DEFAULT '',
    created_at  REAL
);
CREATE TABLE IF NOT EXISTS intel (
    project_id  TEXT PRIMARY KEY,
    data        TEXT,
    updated_at  REAL
);
CREATE TABLE IF NOT EXISTS facts (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    content     TEXT,
    source      TEXT,
    session_id  TEXT DEFAULT '',
    step_id     TEXT DEFAULT '',
    created_at  REAL
);
-- v017.1 请求库：Burp XML / HAR 导入的请求（脱敏副本）。
-- 敏感头（Authorization/Cookie 等）入库前已被替换为 <redacted:*:len> 占位——
-- 完整凭据永不入 SQLite（v017.2 身份库走 DPAPI 受保护存储，与本表无关）。
CREATE TABLE IF NOT EXISTS request_library (
    id            TEXT PRIMARY KEY,
    project_id    TEXT,
    source        TEXT,             -- burp_xml | har | manual
    method        TEXT,
    url           TEXT,             -- 原始 URL
    normalized_url TEXT,            -- 去噪 URL（查询值占位、路径数字归一），去重与筛选用
    headers       TEXT,             -- 脱敏后 JSON
    cookies       TEXT,             -- 脱敏后 JSON
    query         TEXT,             -- JSON（参数名 → 原始值）
    body          TEXT,             -- 脱敏后请求体（截断 4KB）
    content_type  TEXT,
    status_code   INTEGER,
    tags          TEXT,             -- JSON 数组
    scope_status  TEXT,             -- allowed | rejected（导入预览时判定）
    dedup_key     TEXT,             -- 方法+规范化URL+参数名集合+body结构键
    object_candidates TEXT,         -- JSON [{field, location, value_masked, source, confidence}]
    created_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_req_lib_proj ON request_library(project_id);
-- v017.2 测试身份库：凭据经 DPAPI 加密（CurrentUser 作用域）后才入列——
-- headers_enc/cookies_enc 是 base64 密文，解密唯一入口是 app/secretbox.py。
-- 任何接口都不得把解密结果写日志/响应/LLM 上下文。
CREATE TABLE IF NOT EXISTS identities (
    id            TEXT PRIMARY KEY,
    project_id    TEXT,
    label         TEXT,             -- 展示标签（anonymous/account_a/...）
    role          TEXT,             -- anonymous | user | admin（自报，不校验）
    tenant        TEXT DEFAULT '',
    headers_enc   TEXT DEFAULT '',  -- DPAPI 密文 base64
    cookies_enc   TEXT DEFAULT '',
    source        TEXT DEFAULT 'manual',
    status        TEXT DEFAULT 'active',  -- active | expired | invalid | disabled
    last_checked_at REAL,
    check_url     TEXT DEFAULT '',  -- 有效性检查用的目标 URL（可空）
    notes         TEXT DEFAULT '',  -- 不含凭据的备注
    created_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_identities_proj ON identities(project_id);
-- v017.4 差分运行记录：只读身份差分的证据链（可回溯到执行序列）。
-- 只存脱敏数据：目标对象值打码、身份只存 label——凭据从不入此表。
CREATE TABLE IF NOT EXISTS diff_runs (
    id            TEXT PRIMARY KEY,
    project_id    TEXT,
    request_id    TEXT,
    baseline_identity TEXT,         -- 基准身份 label（非 id，审计可读）
    target_field  TEXT,
    target_location TEXT,
    target_value_masked TEXT,
    verdict       TEXT,             -- suspect_idor | access_denied | no_diff | unstable | invalid_baseline
    reason        TEXT,
    stable        INTEGER DEFAULT 0,
    steps_json    TEXT,             -- 执行序列 JSON（URL + 状态码 + 错误）
    variant_url   TEXT,
    created_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_diff_runs_proj ON diff_runs(project_id);
-- v017.5 流程绕过检测记录（与 diff_runs 同等脱敏标准）。
CREATE TABLE IF NOT EXISTS flow_runs (
    id            TEXT PRIMARY KEY,
    project_id    TEXT,
    identity_label TEXT,
    step_ids_json TEXT,            -- 流程步骤的 request_library id 序列
    verdict       TEXT,            -- suspect_flow_bypass | suspect_unauthorized | flow_protected | flow_invalid | unstable
    reason        TEXT,
    steps_json    TEXT,
    created_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_flow_runs_proj ON flow_runs(project_id);
-- v023.1 流量安全：目标状态（持久化——服务重启不得清除 PAUSED/BLOCKED）、
-- 流量事件（审计，含网络层错误）、根域名策略（预算/并发覆盖 config 默认）。
CREATE TABLE IF NOT EXISTS traffic_states (
    root_domain   TEXT PRIMARY KEY,
    project_id    TEXT DEFAULT '',
    state         TEXT DEFAULT 'NORMAL',
    reason        TEXT DEFAULT '',
    signal_count  INTEGER DEFAULT 0,
    cooldown_until REAL DEFAULT 0,
    last_success_at REAL,
    last_error_at REAL,
    last_error_type TEXT DEFAULT '',
    last_error_code INTEGER DEFAULT 0,
    updated_at    REAL
);
-- 事件量级大：自增主键 + 索引；按 created_at 定期清理（保留 7 天）
CREATE TABLE IF NOT EXISTS traffic_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    TEXT DEFAULT '',
    session_id    TEXT DEFAULT '',
    root_domain   TEXT DEFAULT '',
    host          TEXT DEFAULT '',
    resolved_ip   TEXT DEFAULT '',
    port          INTEGER DEFAULT 0,
    tool_alias    TEXT DEFAULT '',
    identity_label TEXT DEFAULT '',
    request_fingerprint TEXT DEFAULT '',
    event_type    TEXT DEFAULT '',   -- sent | settled | rejected | paused | resumed | cancelled
    status_code   INTEGER,
    error_type    TEXT DEFAULT '',
    os_error_code INTEGER DEFAULT 0,
    started_at    REAL,
    finished_at   REAL,
    bytes_in      INTEGER DEFAULT 0,
    redaction_summary TEXT DEFAULT '',
    created_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_traffic_events_root ON traffic_events(root_domain, created_at);
CREATE INDEX IF NOT EXISTS idx_traffic_events_proj ON traffic_events(project_id, created_at);
-- 根域名策略覆盖：未配置的 root 用 config 默认（保守档）
CREATE TABLE IF NOT EXISTS traffic_policies (
    root_domain   TEXT PRIMARY KEY,
    window_seconds INTEGER,
    max_requests  INTEGER,
    burst_limit   INTEGER,
    host_concurrency INTEGER,
    root_concurrency INTEGER,
    manual_resume_required INTEGER DEFAULT 1,
    updated_at    REAL
);
-- v017.4 五项复核清单（finding 一对一）。确认闸门：五项不全 → 拒绝 confirmed。
CREATE TABLE IF NOT EXISTS finding_checks (
    finding_id  TEXT PRIMARY KEY,
    c1_repeat INTEGER DEFAULT 0,          -- 至少重复两次且结果一致
    c2_permission_delta INTEGER DEFAULT 0, -- 权限/身份差异明确
    c3_minimal_chain INTEGER DEFAULT 0,   -- 最小 HTTP 复现链完整
    c4_readonly_or_safe INTEGER DEFAULT 0, -- 只读证明或写操作无真实损害
    c5_impact_proven INTEGER DEFAULT 0,   -- 对象/数据/状态影响可证明
    note TEXT DEFAULT '',
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS chat_messages (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    role        TEXT,
    kind        TEXT DEFAULT '',
    content     TEXT,
    created_at  REAL
);
CREATE TABLE IF NOT EXISTS usage_log (
    id              TEXT PRIMARY KEY,
    ts              REAL,
    session_id      TEXT DEFAULT '',
    project_id      TEXT DEFAULT '',
    provider_id     TEXT DEFAULT '',
    model           TEXT DEFAULT '',
    prompt_tokens   INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    duration_ms     INTEGER DEFAULT 0
);
-- SSE 事件持久化（v011 P1-5）：每条事件带自增 seq，供断线重放。
-- 此前事件只走内存队列，页面断线/刷新后中间过程永远丢失——
-- 「跑了几十步、只看到最后一屏」重演。写入在 Session.emit 里同步完成。
CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    type         TEXT,
    payload      TEXT,
    created_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, seq);
-- 因果图（线索树的「因果图」视图）：节点与边按项目隔离。
-- node_type / label 的取值与归一化在 app/graph.py 里。
-- 注意：这两张表曾被一次更新整段漏掉（app/store.py 被替换成不含因果图持久化的版本），
-- 结果是 app/graph.py 里所有 store.upsert_causal_node 之类的调用直接 AttributeError，
-- 前端「因果图」标签页整个 500。故此处保留，且 test_graph.py 守着不许再掉。
CREATE TABLE IF NOT EXISTS causal_nodes (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    node_type   TEXT,
    title       TEXT DEFAULT '',
    description TEXT DEFAULT '',
    status      TEXT DEFAULT 'PENDING',
    confidence  REAL DEFAULT 0.5,
    severity    TEXT DEFAULT '',
    session_id  TEXT DEFAULT '',
    source_step TEXT DEFAULT '',
    data        TEXT DEFAULT '{}',
    created_at  REAL,
    updated_at  REAL
);
CREATE TABLE IF NOT EXISTS causal_edges (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,
    source_id   TEXT,
    target_id   TEXT,
    label       TEXT,
    strength    TEXT DEFAULT 'contingent',
    description TEXT DEFAULT '',
    created_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_steps_session ON steps(session_id);
-- v111：控制台「统计看板」按**时间窗**聚合 steps。原先只有 session_id 索引，
-- `EXPLAIN QUERY PLAN` 对 `WHERE created_at > ?` 是 `SCAN steps`（全表扫）——
-- 步骤表是本库增长最快的表之一，看板每次切页都扫一遍会把控制台拖住。
CREATE INDEX IF NOT EXISTS idx_steps_created ON steps(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_facts_project ON facts(project_id);
CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage_log(ts);
CREATE INDEX IF NOT EXISTS idx_usage_project ON usage_log(project_id);
CREATE INDEX IF NOT EXISTS idx_cnodes_project ON causal_nodes(project_id);
CREATE INDEX IF NOT EXISTS idx_cedges_project ON causal_edges(project_id);
"""


def _connect() -> sqlite3.Connection:
    """建立连接并设置并发相关 PRAGMA。

    - WAL：Agent 后台每步都写 steps，与接口的读请求是并发的；默认 rollback journal
      下写锁会阻塞读，容易出现 "database is locked"。
    - busy_timeout：拿不到锁时等待而不是立刻抛错（连接串的 timeout 与 PRAGMA 双保险）。
    - synchronous=NORMAL：WAL 下兼顾安全与写入吞吐。
    journal_mode 是数据库的持久属性，重复设置无副作用。
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
    except sqlite3.Error:
        pass
    return conn


@contextmanager
def _db():
    """数据库连接上下文：正常提交、异常回滚，**并且一定关闭连接**。

    注意：`with sqlite3.connect(...) as c:` 只提交/回滚事务，并不会关闭连接
    （官方文档明确说明 context manager 不关闭连接）。此前正是用这种写法，
    连接依赖 CPython 引用计数回收，写法上易被误解为「已关闭」。
    """
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _db() as c:
        c.executescript(SCHEMA)
        # ---- v023.3 迁移：traffic_states 补 resolved_ip ----
        # v023.1 建表时漏了这一列，而「同 IP 聚合暂停」靠它反查兄弟主机。
        # CREATE TABLE IF NOT EXISTS 对已存在的表不加列，必须显式 ALTER。
        try:
            tcols = {r["name"] for r in c.execute("PRAGMA table_info(traffic_states)")}
            if tcols and "resolved_ip" not in tcols:
                c.execute("ALTER TABLE traffic_states ADD COLUMN resolved_ip TEXT DEFAULT ''")
        except Exception:
            pass
        # ---- v023.6：清理 v023.2 之前的 IP 解析残留（如 root_domain='0.1'）----
        try:
            clean_n = cleanup_traffic_states()
            if clean_n:
                logger.info("已清理 %d 条无效流量状态（IP 解析残留）", clean_n)
        except Exception:
            pass
        # 旧库升级：会话树新增列（分支对话树功能）。逐列检查，缺哪个补哪个。
        cols = {r["name"] for r in c.execute("PRAGMA table_info(sessions)").fetchall()}
        for col, ddl in (
            ("parent_id", "TEXT DEFAULT ''"),   # 父会话 id，根线索为 ''
            ("title", "TEXT DEFAULT ''"),       # 线索名（分支卡片/小地图显示）
            ("status", "TEXT DEFAULT 'active'"),# 线索状态：active | done | abandoned
            ("context", "TEXT DEFAULT '[]'"),   # 开分支时打包带来的记录（JSON 数组）
            ("summary", "TEXT DEFAULT ''"),     # 每轮结束的结论摘要（写回主对话用）
            # 是否 split_task 派生的并行子任务。必须落库：子任务内禁 L2/L3 是安全闸门，
            # 只存内存的话，服务重启或被 adopt 后标记丢失、闸门就静默失效了。
            ("subtask", "INTEGER DEFAULT 0"),
            # v048 任务级约束（JSON 对象：能力标签 → 命中的任务原文片段）。
            # 与 subtask 同理且更要紧：它是**闸门依据**。只存内存的话，adopt 续聊后
            # 约束消失 → Agent 重新去做任务书明令禁止的事，而库表上看不出任何异常。
            ("constraints", "TEXT DEFAULT '{}'"),
            # v102 工作模式：blackbox | whitebox。决定模型可见的工具集与系统提示片段。
            # 同样必须落库：丢了这个，adopt 续聊后白盒会话会静默变回黑盒口径
            # （反之亦然），而现象只是「工具集不对」，从库表上看不出任何异常。
            ("mode", "TEXT DEFAULT 'blackbox'"),
        ):
            if col not in cols:
                c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {ddl}")

        # 旧库升级：projects 新增 mode（v102 追加 —— 项目也要有模式归属）。
        # 为什么必须有：白盒模式下项目列表照样列出黑盒项目（目标=企业名/域名），
        # 用户看到的就是「选了白盒侧，还冒出来黑盒侧的项目」。与 sessions.mode
        # 同款理由：**闸门依据必须落库**，只在前端按 UI 状态过滤会随刷新/换入口失效。
        # 语义与 sessions 一致：blackbox | whitebox，项目创建后不可改
        # （要换侧就新建项目 —— 一个项目的 target 语义（域名 vs 源码路径）不会变）。
        pcols = {r["name"] for r in c.execute("PRAGMA table_info(projects)").fetchall()}
        if "mode" not in pcols:
            c.execute("ALTER TABLE projects ADD COLUMN mode TEXT")
            # 存量项目一次性回填：按 target 形态判侧。白盒项目的 target 是本机
            # 源码目录（Windows 盘符路径 / UNC / POSIX 绝对路径），黑盒项目是
            # 企业名/域名。判错的代价只是「在另一个模式下看不到」，项目与数据
            # 本身都在，且新项目从现在起都带显式 mode。
            c.execute("UPDATE projects SET mode='whitebox' WHERE mode IS NULL AND "
                      "(target GLOB '[A-Za-z]:*' OR target LIKE '\\\\%' "
                      "OR target LIKE '/%')")
            c.execute("UPDATE projects SET mode='blackbox' WHERE mode IS NULL")

        # 旧库升级：steps 新增列（失败归因 L1/L3/L4 与单步耗时，供会话复盘统计）。
        # 注意：CREATE TABLE IF NOT EXISTS 对已存在的表不会加列，必须显式 ALTER。
        scols = {r["name"] for r in c.execute("PRAGMA table_info(steps)").fetchall()}
        for col, ddl in (
            ("attribution", "TEXT DEFAULT ''"),  # 归因档位：SCOPE | L1 | L3 | L4，成功为空
            ("elapsed", "REAL DEFAULT 0"),       # 单步耗时（秒）
        ):
            if col not in scols:
                c.execute(f"ALTER TABLE steps ADD COLUMN {col} {ddl}")
        # facts / findings 的溯源列（旧库升级）：必须补齐，否则【静默退化】——
        # 因果图的 Evidence→KeyFact（靠 facts.step_id）与 KeyFact→Vulnerability
        # 的同线索关联（靠 facts/findings.session_id）会全部连不出边，
        # 界面不报错，只是图里只剩孤立的点，很难被察觉。
        for tbl, col, ddl in (
            ("facts", "session_id", "TEXT DEFAULT ''"),
            ("facts", "step_id", "TEXT DEFAULT ''"),
            ("findings", "session_id", "TEXT DEFAULT ''"),
        ):
            exist = {r["name"] for r in c.execute(f"PRAGMA table_info({tbl})").fetchall()}
            if col not in exist:
                c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {ddl}")
        # v012 P1-1：事实/漏洞状态模型 + 漏洞结构化字段。
        # 存量数据一律视为已验证（保持旧行为）；新增记录由写入方按来源定状态。
        for tbl, col, ddl in (
            ("facts", "status", "TEXT DEFAULT 'verified'"),
            ("findings", "status", "TEXT DEFAULT 'draft'"),
            ("findings", "vuln_type", "TEXT DEFAULT ''"),
            ("findings", "cwe", "TEXT DEFAULT ''"),
            ("findings", "cvss", "TEXT DEFAULT ''"),
            ("findings", "impact_scope", "TEXT DEFAULT ''"),
            ("findings", "reproduction", "TEXT DEFAULT ''"),
            ("findings", "remediation", "TEXT DEFAULT ''"),
            ("findings", "review_note", "TEXT DEFAULT ''"),
        ):
            exist = {r["name"] for r in c.execute(f"PRAGMA table_info({tbl})").fetchall()}
            if col not in exist:
                c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {ddl}")
        # 服务重启后内存里的运行态会话已丢，落库的 running 状态会永远卡住，
        # 这里统一标记为 interrupted，避免前端显示「执行中」的僵尸会话。
        # awaiting_confirm 同理（确认通道随进程消失，不可能再有人回应）。
        c.execute("UPDATE sessions SET state='interrupted' "
                  "WHERE state IN ('running','awaiting_confirm')")


# ---------- 项目 ----------
def normalize_mode(mode) -> str:
    """模式归一化：只认 blackbox | whitebox，其余一律回落 blackbox（历史行为）。

    与 `/api/sessions` 的建会话口径**同一份判断** —— 项目与会话必须用同一套
    取值域，否则会出现「项目是 whitebox、会话是别的值」这种查不出原因的错配。
    """
    m = (mode or "").strip().lower()
    return m if m in ("blackbox", "whitebox") else "blackbox"


def create_project(name: str, target: str = "", note: str = "",
                   mode: str = "") -> dict:
    """建项目。mode=v102 工作模式（blackbox | whitebox），留空按黑盒（历史行为）。"""
    md = normalize_mode(mode)
    pid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO projects (id,name,target,note,created_at,mode) "
            "VALUES (?,?,?,?,?,?)",
            (pid, name, target, note, time.time(), md),
        )
    return {"id": pid, "name": name, "target": target, "note": note, "mode": md}


def list_projects() -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT p.*, (SELECT COUNT(*) FROM sessions s WHERE s.project_id=p.id) AS session_count,"
            " (SELECT COUNT(*) FROM findings f WHERE f.project_id=p.id) AS finding_count"
            " FROM projects p ORDER BY p.created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_project(pid: str) -> dict | None:
    with _db() as c:
        r = c.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    return dict(r) if r else None


_FIELDS = ("name", "target", "note")   # mode 刻意不在内：项目归属哪一侧创建时定死


def update_project(pid: str, **fields) -> dict | None:
    """更新项目名称/目标/备注。只接受白名单字段，且跳过未传（None）的项。

    返回更新后的项目；项目不存在时返回 None。
    """
    patch = {k: v for k, v in fields.items() if k in _FIELDS and v is not None}
    if not patch:
        return get_project(pid)
    sets = ", ".join(f"{k}=?" for k in patch)
    with _db() as c:
        cur = c.execute(f"UPDATE projects SET {sets} WHERE id=?", (*patch.values(), pid))
        if cur.rowcount == 0:
            return None
    return get_project(pid)


def delete_project(pid: str) -> bool:
    """删除项目及其全部派生数据。

    补清理此前遗漏的两处：
      · chat_messages —— 按 session_id 关联，删会话时不会跟着走，会留下孤儿消息；
      · usage_log —— 保留调用记录本身（计费/统计口径不应因删项目而变），
        只把 project_id 置空，去掉指向已删项目的悬空引用。
    同时去掉原先对 projects 表的重复 DELETE（先用 SELECT 判存在）。
    """
    with _db() as c:
        if not c.execute("SELECT 1 FROM projects WHERE id=?", (pid,)).fetchone():
            return False
        sids = [r["id"] for r in c.execute(
            "SELECT id FROM sessions WHERE project_id=?", (pid,)).fetchall()]
        c.execute("DELETE FROM steps WHERE session_id IN (SELECT id FROM sessions WHERE project_id=?)", (pid,))
        for sid in sids:
            c.execute("DELETE FROM chat_messages WHERE session_id=?", (sid,))
        c.execute("DELETE FROM sessions WHERE project_id=?", (pid,))
        c.execute("DELETE FROM findings WHERE project_id=?", (pid,))
        c.execute("DELETE FROM facts WHERE project_id=?", (pid,))
        c.execute("DELETE FROM intel WHERE project_id=?", (pid,))
        # 因果图必须跟着删：causal_nodes/causal_edges 按 project_id 关联，
        # 不删的话项目删了图还在，下次同一个 pid 重建时会把旧节点捞回来
        # （图里出现"上一个项目"的幽灵节点）。
        c.execute("DELETE FROM causal_edges WHERE project_id=?", (pid,))
        c.execute("DELETE FROM causal_nodes WHERE project_id=?", (pid,))
        c.execute("UPDATE usage_log SET project_id='' WHERE project_id=?", (pid,))
        c.execute("DELETE FROM projects WHERE id=?", (pid,))
    return True


# ---------- 会话与步骤 ----------
def save_session(sid: str, project_id: str, task: str, target: str, state: str,
                 parent_id: str | None = None, title: str | None = None,
                 context: list | None = None, status: str | None = None,
                 summary: str | None = None, subtask: bool | None = None,
                 constraints: dict | None = None, mode: str | None = None) -> None:
    """保存/更新会话。树相关列（parent_id/title/context/status/summary/subtask）
    只在显式传入时更新，避免普通落库把分支元数据冲掉。

    `constraints`（v048 任务级约束）同样只在显式传入时更新，理由更强：
    它是**闸门依据**，不是展示字段。普通落库把它清空 = 任务级约束静默失效，
    而现象只是「Agent 又开始做被禁止的事了」，从库表上看不出任何异常。

    `mode`（v102 工作模式）遵循**同一条**约定：只在显式传入时更新。
    理由与 constraints 一致 —— 它是「模型能看到哪些工具 + 用哪套提示」的依据，
    普通落库若把它冲回默认值，白盒会话会静默变回黑盒口径。
    """
    with _db() as c:
        row = c.execute("SELECT id FROM sessions WHERE id=?", (sid,)).fetchone()
        sets = ["project_id=?", "task=?", "target=?", "state=?"]
        vals: list = [project_id, task, target, state]
        if constraints is not None:
            sets.append("constraints=?")
            vals.append(json.dumps(constraints or {}, ensure_ascii=False))
        if mode is not None:
            sets.append("mode=?")
            vals.append(mode or "blackbox")
        if parent_id is not None:
            sets.append("parent_id=?")
            vals.append(parent_id)
        if title is not None:
            sets.append("title=?")
            vals.append(title)
        if status is not None:
            sets.append("status=?")
            vals.append(status)
        if context is not None:
            sets.append("context=?")
            vals.append(json.dumps(context, ensure_ascii=False))
        if summary is not None:
            sets.append("summary=?")
            vals.append(summary)
        if subtask is not None:
            sets.append("subtask=?")
            vals.append(1 if subtask else 0)
        if row:
            vals.append(sid)
            c.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE id=?", vals)
        else:
            # ⚠️ INSERT 分支也必须带 constraints（v048 由端到端测试抓出）：
            # 首次落库走的**就是**这条分支（sessions.create 只建内存对象，不写库），
            # 若这里漏掉，UPDATE 分支写得再对也没用 —— 约束永远是默认的 `{}`，
            # 也就是「任务级闸门从没真正落过库」，而库表上看不出任何异常。
            # v102：mode 同理，也必须带上（首次落库走的就是这条分支）。
            c.execute(
                "INSERT INTO sessions (id,project_id,task,target,state,created_at,"
                "parent_id,title,status,context,summary,subtask,constraints,mode) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (sid, project_id, task, target, state, time.time(),
                 parent_id or "", title or "", status or "active",
                 json.dumps(context or [], ensure_ascii=False), summary or "",
                 1 if subtask else 0,
                 json.dumps(constraints or {}, ensure_ascii=False),
                 mode or "blackbox"),
            )


def create_branch(parent_sid: str, project_id: str, title: str,
                  records: list[str]) -> dict:
    """从父会话开一条新线索：记录打包带入 context，task/target 首次运行时补齐。

    v102：**继承父会话的 mode** —— 分支是同一项工作的另一条线索，
    模式必须跟着走；否则白盒会话开出的分支会拿到黑盒工具集（反之亦然）。
    """
    sid = uuid.uuid4().hex[:12]
    parent = get_session_row(parent_sid)
    pid = project_id or (parent.get("project_id") or "" if parent else "")
    pmode = (parent.get("mode") or "blackbox") if parent else "blackbox"
    with _db() as c:
        c.execute(
            "INSERT INTO sessions (id,project_id,task,target,state,created_at,"
            "parent_id,title,status,context,summary,mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, pid, "", "", "idle", time.time(), parent_sid,
             (title or "新线索").strip()[:60], "active",
             json.dumps(records or [], ensure_ascii=False), "", pmode),
        )
    return {"id": sid, "parent_id": parent_sid, "title": (title or "新线索").strip()[:60],
            "project_id": pid, "records": records or [], "mode": pmode}


def get_session_row(sid: str) -> dict | None:
    """取会话行（含树字段），不含步骤。"""
    with _db() as c:
        r = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    return dict(r) if r else None


def list_tree(project_id: str) -> list[dict]:
    """项目内全部会话（按创建时间正序，前端按 parent_id 组装成树）。"""
    with _db() as c:
        rows = c.execute(
            "SELECT id,parent_id,title,task,target,state,status,summary,created_at,"
            " (SELECT COUNT(*) FROM steps st WHERE st.session_id=sessions.id) AS step_count"
            " FROM sessions WHERE project_id=? ORDER BY created_at ASC",
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_session_tree(sid: str) -> dict:
    """彻底删除一条线索及其所有后代（子分支），并级联清理步骤、对话历史。

    **刻意不删 usage_log**：那是 token 消耗与调用的审计记录。若随会话一起删掉，
    就等于「删掉线索即可抹掉自己烧过多少钱、调过多少次模型」，成本审计失去可信度。
    这里把 session_id 置空，保留计数与时间戳（总量不丢），只是不再归属到已删会话。

    返回 {deleted_ids: [sid, ...], count: N}。
    """
    with _db() as c:
        # 1) 收集待删节点（含后代）
        to_delete: list[str] = []
        queue = [sid]
        while queue:
            cur = queue.pop(0)
            if cur in to_delete:
                continue
            to_delete.append(cur)
            rows = c.execute(
                "SELECT id FROM sessions WHERE parent_id=?", (cur,)
            ).fetchall()
            queue.extend([r["id"] for r in rows])

        if not to_delete:
            return {"deleted_ids": [], "count": 0}

        # 2) 级联删除（用量记录除外，见上）
        placeholders = ",".join("?" * len(to_delete))
        c.execute(f"DELETE FROM steps WHERE session_id IN ({placeholders})", to_delete)
        c.execute(f"DELETE FROM chat_messages WHERE session_id IN ({placeholders})", to_delete)
        c.execute(f"UPDATE usage_log SET session_id=NULL WHERE session_id IN ({placeholders})",
                  to_delete)
        c.execute(f"DELETE FROM sessions WHERE id IN ({placeholders})", to_delete)

    return {"deleted_ids": to_delete, "count": len(to_delete)}


THREAD_STATUS = ("active", "done", "abandoned")


def update_session_meta(sid: str, title: str | None = None,
                        status: str | None = None) -> dict | None:
    """更新线索标题/状态（白名单校验，status 只接受三种合法值）。"""
    patch: dict[str, str] = {}
    if title is not None and title.strip():
        patch["title"] = title.strip()[:60]
    if status is not None:
        if status not in THREAD_STATUS:
            raise ValueError(f"非法线索状态：{status}")
        patch["status"] = status
    if not patch:
        return get_session_row(sid)
    sets = ", ".join(f"{k}=?" for k in patch)
    with _db() as c:
        cur = c.execute(f"UPDATE sessions SET {sets} WHERE id=?", (*patch.values(), sid))
        if cur.rowcount == 0:
            return None
    return get_session_row(sid)


def save_summary(sid: str, summary: str) -> None:
    """保存会话结论摘要（成果回流：供其他线索的上下文注入与前端小地图展示）。"""
    with _db() as c:
        c.execute("UPDATE sessions SET summary=? WHERE id=?", (summary[:1000], sid))


def search_history(project_id: str, keyword: str, limit: int = 8) -> list[dict]:
    """跨线索检索：在项目内的**工具执行 + 已证事实 + 项目情报**里搜关键词。

    供内置工具 search_history 使用，实现「新对话调取历史对话内容」。

    覆盖面（此前只搜 steps 一张表，比工具描述承诺的范围小得多，模型搜不到就会
    「以为没查过」而重新查一遍）：
      · steps —— 工具输出 / 参数 / 目标 / 工具名（工具执行记忆）
      · facts —— 已证事实正文（note_fact 记下的结论性记忆）
      · intel —— 项目情报库 JSON（跨会话沉淀的子域 / IP / API / 技术栈）
    事实与情报都带 kind 标记，调用方按类型渲染，模型才能分辨
    「这是工具原文，还是已证结论，还是沉淀过的资产清单」。
    """
    kw = (keyword or "").strip()
    if not kw or not project_id:
        return []
    like = f"%{kw}%"
    out: list[dict] = []
    with _db() as c:
        rows = c.execute(
            "SELECT st.session_id, s.title, s.task, st.tool_name, st.tool_alias,"
            " st.target, st.args, st.output, st.status, st.created_at"
            " FROM steps st JOIN sessions s ON s.id=st.session_id"
            " WHERE s.project_id=? AND (st.output LIKE ? OR st.target LIKE ?"
            "  OR st.args LIKE ? OR st.tool_name LIKE ?)"
            " ORDER BY st.created_at DESC LIMIT ?",
            (project_id, like, like, like, like, limit),
        ).fetchall()
        for r in rows:
            d = dict(r)
            d["kind"] = "step"
            text = d.get("output") or ""
            pos = text.find(kw)
            # v031（第三轮实战）：片段从 220 字符提到 config.SEARCH_SNIPPET_CHARS
            # （默认 800）。落库版本本身有 8KB（头 4000 + 尾 4000），只回 220 字符
            # 等于把已经存下来的清单又切掉一刀 —— 实测导致「功能码全集」取不回来，
            # 模型只能重新向目标发请求（6 次，占全局预算 1/3）。
            width = config.SEARCH_SNIPPET_CHARS
            if pos >= 0:
                start = max(0, pos - width // 2)
                d["snippet"] = ("…" if start else "") + text[start:start + width].strip() + "…"
            else:
                d["snippet"] = text[:width].strip() + ("…" if len(text) > width else "")
            out.append(d)

        for r in c.execute(
            "SELECT id, content, session_id, step_id, created_at FROM facts"
            " WHERE project_id=? AND content LIKE ? ORDER BY created_at DESC LIMIT ?",
            (project_id, like, limit),
        ).fetchall():
            d = dict(r)
            d["kind"] = "fact"
            text = d.get("content") or ""
            pos = text.find(kw)
            # v031：事实片段同步提到 SEARCH_SNIPPET_CHARS（原 300），
            # 让「已证事实」类记忆也能被完整回读，而不是只看到一句摘要。
            width = config.SEARCH_SNIPPET_CHARS
            start = max(0, pos - width // 4) if pos >= 0 else 0
            d["snippet"] = text[start:start + width].strip()
            out.append(d)

        for r in c.execute(
            "SELECT data, updated_at FROM intel WHERE project_id=?", (project_id,)
        ).fetchall():
            try:
                data = json.loads(r["data"] or "{}")
            except Exception:
                data = {}
            if not isinstance(data, dict):
                continue
            for k, vals in data.items():
                if not isinstance(vals, list):
                    continue
                hit = [str(v) for v in vals if kw.lower() in str(v).lower()]
                if hit:
                    out.append({
                        "kind": "intel", "key": k, "matches": hit[:10],
                        "total": len(vals), "created_at": r["updated_at"],
                        "snippet": "、".join(hit[:10]),
                    })
    return out[: max(limit, 12)]


def save_step(sid: str, step: dict) -> None:
    """落库单步执行记录。

    ⚠ 主键冲突防护：steps.id 是**全局**主键，而 step["id"] 来自模型的
    tool_call_id —— 它只在**一次对话内**唯一；模型不给 id 时还会退化成
    `call_{步数}_{序号}` 这种固定串。split_task 的并行子任务跑起来后，几条会话
    同时落库极易撞上同一个 id，原来的 INSERT OR REPLACE 会让后写入的一方
    **静默覆盖**另一方的步骤（库里少一条，界面与复盘也跟着少一条）。
    这里发现「该 id 已属于别的会话」时改用 `会话id:原id` 另存，两边都留得住；
    正常情况（同一会话内更新同一步）走原路径，id 语义不变。
    """
    step_id = step.get("id") or uuid.uuid4().hex[:12]
    with _db() as c:
        row = c.execute("SELECT session_id FROM steps WHERE id=?", (step_id,)).fetchone()
        if row is not None and row["session_id"] != sid:
            step_id = f"{sid}:{step_id}"
        c.execute(
            "INSERT OR REPLACE INTO steps"
            " (id,session_id,tool_alias,tool_name,target,args,risk_level,status,output,"
            "  attribution,elapsed,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                step_id,
                sid,
                step.get("tool_alias", ""),
                step.get("tool_name", ""),
                step.get("target", ""),
                step.get("args", ""),
                (step.get("risk") or {}).get("level", ""),
                step.get("status", ""),
                step.get("output", ""),
                step.get("attribution", "") or "",
                float(step.get("elapsed") or 0),
                time.time(),
            ),
        )


def session_review(sid: str) -> dict:
    """会话复盘：这条线索花了多少 token/时间、步骤成败与失败归因的分布。

    全部来自库里已有的记录（steps + usage_log + chat_messages），不做任何模型调用，
    因此复盘本身零 token 成本。归因统计是这套归因机制的价值出口——不看分布就不知道
    模型到底卡在「工具跑不起来(L1)」「被环境拦(L3)」还是「假设不成立(L4)」上。
    """
    with _db() as c:
        srow = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        srows = c.execute(
            "SELECT status, attribution, elapsed FROM steps WHERE session_id=?", (sid,)
        ).fetchall()
        urow = c.execute(
            "SELECT COUNT(*) AS calls,"
            " COALESCE(SUM(prompt_tokens),0) AS prompt,"
            " COALESCE(SUM(completion_tokens),0) AS completion,"
            " COALESCE(SUM(duration_ms),0) AS llm_ms"
            " FROM usage_log WHERE session_id=?", (sid,)
        ).fetchone()
        cnt = c.execute(
            "SELECT COUNT(*) AS n FROM chat_messages WHERE session_id=?", (sid,)
        ).fetchone()
        pid = (srow["project_id"] if srow else "") or ""
        frow = c.execute(
            "SELECT COUNT(*) AS n FROM facts WHERE project_id=?", (pid,)
        ).fetchone() if pid else None
        # intel 是「每项目一行」的汇总表，有行即说明该项目已沉淀过情报
        irow = c.execute(
            "SELECT COUNT(*) AS n FROM intel WHERE project_id=?", (pid,)
        ).fetchone() if pid else None

    by_status: dict[str, int] = {}
    by_attr: dict[str, int] = {}
    tool_seconds = 0.0
    for r in srows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        a = (r["attribution"] or "").strip()
        if a:
            by_attr[a] = by_attr.get(a, 0) + 1
        tool_seconds += float(r["elapsed"] or 0)

    n = len(srows)
    done = by_status.get("done", 0)
    prompt = int(urow["prompt"] or 0)
    completion = int(urow["completion"] or 0)
    return {
        "session_id": sid,
        "project_id": pid,
        "title": ((srow["title"] if srow else "") or ""),
        "state": ((srow["state"] if srow else "") or ""),
        "steps": n,
        "by_status": by_status,
        "by_attribution": by_attr,
        "success_rate": round(done / n, 3) if n else 0.0,
        "tool_seconds": round(tool_seconds, 1),
        "llm": {
            "calls": int(urow["calls"] or 0),
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
            "llm_seconds": round(float(urow["llm_ms"] or 0) / 1000, 1),
        },
        "messages": int(cnt["n"] or 0),
        "facts": int((frow["n"] if frow else 0) or 0),
        "intel": int((irow["n"] if irow else 0) or 0),
    }


def list_sessions(project_id: str | None = None, limit: int = 50) -> list[dict]:
    """会话列表（按创建时间倒序）。

    v112：新增 `limit`。原先不传 project_id 时**写死 LIMIT 50** ——
    对"某个项目的会话列表"够用，但运行监控要的是"最近 N 条"，上限必须是调用方能调的
    （并且由调用方夹取），否则要么看不全、要么被一个死数卡住。
    """
    n = max(1, int(limit or 50))
    with _db() as c:
        if project_id:
            rows = c.execute(
                "SELECT * FROM sessions WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
                (project_id, n),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (n,)
            ).fetchall()
    return [dict(r) for r in rows]


def session_step_counts(session_ids: list[str]) -> dict[str, dict[str, int]]:
    """批量取多个会话的**步骤计数**（按 status 分组）。返回 {sid: {status: n}}。

    为什么要有它：运行列表要给每个会话显示"多少步 / 几步失败"。
    逐会话查一次就是 N+1（列表 50 行 = 51 次查询），这里一次 `IN (...)` 查完。

    ⚠️ **只回计数，不回步骤正文**。`steps.output` 是工具输出的全文，可能很大；
    列表接口带上它会让响应体量翻几十倍，而列表页根本用不到 ——
    要看正文请用既有的 `/api/sessions/{sid}`（那里本来就返回 steps）。
    """
    ids = [str(x) for x in session_ids if x]
    if not ids:
        return {}
    q = ",".join("?" * len(ids))
    out: dict[str, dict[str, int]] = {}
    with _db() as c:
        for r in c.execute(
            f"SELECT session_id, status, COUNT(*) n FROM steps "
            f"WHERE session_id IN ({q}) GROUP BY session_id, status", tuple(ids)
        ):
            out.setdefault(r["session_id"] or "", {})[r["status"] or "?"] = r["n"]
    return out


def get_session(sid: str) -> dict | None:
    """从持久化层取会话及其步骤。

    用于「服务重启后」回看历史会话——内存里的 SessionManager 在重启后清空，
    但 SQLite 里仍存着，详情接口应能回退到这里。
    """
    with _db() as c:
        s = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            return None
        steps = [dict(r) for r in c.execute(
            "SELECT * FROM steps WHERE session_id=? ORDER BY created_at ASC", (sid,)
        ).fetchall()]
    return {"session": dict(s), "steps": steps}


# ---------- SSE 事件持久化（v011 P1-5） ----------
def save_event(session_id: str, event: dict) -> int:
    """落库一条 SSE 事件，返回自增 seq（断线重放的游标）。失败返回 0（不阻断流）。"""
    try:
        with _db() as c:
            cur = c.execute(
                "INSERT INTO events (session_id,type,payload,created_at) VALUES (?,?,?,?)",
                (session_id, str(event.get("type") or ""),
                 json.dumps(event, ensure_ascii=False), time.time()),
            )
            return int(cur.lastrowid or 0)
    except Exception:
        return 0


def list_events(session_id: str, since_seq: int = 0, limit: int = 1000) -> list[dict]:
    """按 seq 升序取某会话的事件（seq > since_seq），供 SSE 断线重放。"""
    with _db() as c:
        rows = c.execute(
            "SELECT seq,type,payload,created_at FROM events"
            " WHERE session_id=? AND seq>? ORDER BY seq ASC LIMIT ?",
            (session_id, int(since_seq), max(1, min(int(limit), 5000))),
        ).fetchall()
    out = []
    for r in rows:
        try:
            ev = json.loads(r["payload"] or "{}")
        except Exception:
            ev = {"type": r["type"]}
        ev["_seq"] = int(r["seq"])
        out.append(ev)
    return out


def last_event_seq(session_id: str) -> int:
    """某会话当前最大事件 seq（无记录返回 0）。"""
    with _db() as c:
        r = c.execute("SELECT MAX(seq) AS m FROM events WHERE session_id=?",
                      (session_id,)).fetchone()
    return int(r["m"] or 0) if r else 0


# ---------- 对话历史（线索回放用） ----------
def save_chat_message(sid: str, role: str, content: str, kind: str = "") -> None:
    """持久化一条对话消息：role=user/assistant；kind=reasoning/answer（assistant 侧细分）。

    供「切换线索时回放历史对话」使用；单条截断 8000 字符防膨胀。
    """
    text = (content or "").strip()
    if not text:
        return
    with _db() as c:
        c.execute(
            "INSERT INTO chat_messages (id,session_id,role,kind,content,created_at)"
            " VALUES (?,?,?,?,?,?)",
            (uuid.uuid4().hex[:12], sid, role, kind, text[:8000], time.time()),
        )


def list_chat_messages(sid: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT role,kind,content,created_at FROM chat_messages"
            " WHERE session_id=? ORDER BY created_at ASC, rowid ASC",
            (sid,),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- Token 用量统计 ----------
def save_usage(provider_id: str, model: str, prompt_tokens: int, completion_tokens: int,
               session_id: str = "", project_id: str = "", duration_ms: int = 0) -> None:
    """记录一次 LLM 调用的 token 用量（仅成功且有 usage 数据的调用）。"""
    with _db() as c:
        c.execute(
            "INSERT INTO usage_log (id,ts,session_id,project_id,provider_id,model,"
            "prompt_tokens,completion_tokens,duration_ms) VALUES (?,?,?,?,?,?,?,?,?)",
            (uuid.uuid4().hex[:12], time.time(), session_id or "", project_id or "",
             provider_id or "", model or "", int(prompt_tokens or 0),
             int(completion_tokens or 0), int(duration_ms or 0)),
        )


def list_usage(project_id: str = "", model: str = "", days: int = 0,
               limit: int = 500) -> list[dict]:
    """明细记录（倒序）。days>0 限定最近 N 天；project_id/model 空串为不过滤。"""
    q = "SELECT * FROM usage_log WHERE 1=1"
    vals: list = []
    if project_id:
        q += " AND project_id=?"
        vals.append(project_id)
    if model:
        q += " AND model=?"
        vals.append(model)
    if days > 0:
        q += " AND ts>=?"
        vals.append(time.time() - days * 86400)
    q += " ORDER BY ts DESC LIMIT ?"
    vals.append(max(1, min(limit, 5000)))
    with _db() as c:
        rows = c.execute(q, vals).fetchall()
    return [dict(r) for r in rows]


def clear_usage(days: int = 0) -> int:
    """清空用量记录；days>0 只删最近 N 天之外的……即保留最近 N 天，删除更早的。"""
    with _db() as c:
        if days > 0:
            cur = c.execute("DELETE FROM usage_log WHERE ts<?", (time.time() - days * 86400,))
        else:
            cur = c.execute("DELETE FROM usage_log")
    return cur.rowcount


# ---------- 漏洞发现 ----------
def add_finding(project_id: str, title: str, severity: str, target: str,
                detail: str = "", evidence: str = "", session_id: str = "",
                status: str = "draft", vuln_type: str = "", cwe: str = "",
                cvss: str = "", impact_scope: str = "", reproduction: str = "",
                remediation: str = "") -> dict:
    """登记漏洞发现（v012 P1-1 状态模型）。

    status：draft（候选，默认——AI 与首次登记都是候选）| needs_review |
            confirmed（人工确认，可进正式报告）| closed。
    「AI 只能产候选」由默认值保证：调用方不显式传 confirmed 就进不了报告的
    已确认章节。结构化字段（vuln_type/cwe/cvss/...）供报告增强使用。
    """
    fid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO findings (id,project_id,title,severity,target,detail,evidence,"
            "session_id,created_at,status,vuln_type,cwe,cvss,impact_scope,reproduction,"
            "remediation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, project_id, title, severity, target, detail, evidence, session_id,
             time.time(), status, vuln_type, cwe, cvss, impact_scope, reproduction,
             remediation),
        )
    return {"id": fid, "project_id": project_id, "title": title, "severity": severity,
            "target": target, "detail": detail, "evidence": evidence,
            "session_id": session_id, "status": status, "vuln_type": vuln_type,
            "cwe": cwe, "cvss": cvss, "impact_scope": impact_scope,
            "reproduction": reproduction, "remediation": remediation}


def review_finding(project_id: str, fid: str, action: str, note: str = "") -> dict | None:
    """人工复核漏洞发现（v012 P1-1）：AI 只能产候选，确认/否决必须由人完成。

    action：confirmed（确认，进正式报告）| needs_review（转待复核）|
            closed（关闭/误报）| draft（退回候选）。
    归属校验同 delete_finding：WHERE 双条件，跨项目返回 None。
    """
    if action not in ("confirmed", "needs_review", "closed", "draft"):
        return None
    with _db() as c:
        cur = c.execute(
            "UPDATE findings SET status=?, review_note=? WHERE id=? AND project_id=?",
            (action, note, fid, project_id),
        )
        if cur.rowcount <= 0:
            return None
        row = c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    return dict(row) if row else None


def list_findings(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC", (project_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_finding(project_id: str, fid: str) -> bool:
    """删除一条漏洞发现（同 delete_fact：v010 P1-3 补归属校验，跨项目拒绝）。"""
    with _db() as c:
        cur = c.execute("DELETE FROM findings WHERE id=? AND project_id=?",
                        (fid, project_id))
    return cur.rowcount > 0


# ---------- 已证客观事实（facts） ----------
def add_fact(project_id: str, content: str, source: str = "manual",
             session_id: str = "", step_id: str = "", status: str = "") -> dict:
    """记录一条「已证实的客观事实」（凭据/漏洞/敏感路径等）。source: manual | agent。

    session_id / step_id 是**因果图的连边依据**，不是可选装饰：
    带 step_id 才能连出 Evidence --REVEALS--> KeyFact，带 session_id 才能把
    同一条线索下的 KeyFact 与 Vulnerability 关联起来。丢了它们图不会报错，
    只会静默退化成一堆孤点，所以调用方必须尽量传。

    v012 P1-1 状态模型：status ∈ verified | candidate | rejected。
    空串时自动判定：人工登记（source=manual）或带溯源步骤（step_id，即有
    工具输出背书）→ verified；AI 记录且无溯源 → candidate（不能只因模型
    声称就当「已证」——这正是路线图 P1-1 要堵的口子）。
    """
    content = content.strip()
    if not content:
        return {}
    if not status:
        status = "verified" if (source == "manual" or step_id) else "candidate"
    if status not in ("verified", "candidate", "rejected"):
        status = "candidate"
    fid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO facts (id,project_id,content,source,session_id,step_id,"
            "created_at,status) VALUES (?,?,?,?,?,?,?,?)",
            (fid, project_id, content, source, session_id, step_id, time.time(),
             status),
        )
    return {"id": fid, "project_id": project_id, "content": content, "source": source,
            "session_id": session_id, "step_id": step_id, "created_at": time.time(),
            "status": status}


def review_fact(project_id: str, fid: str, action: str) -> dict | None:
    """人工复核事实（v012 P1-1）：verified / rejected / candidate。

    归属校验同 delete_fact：WHERE 双条件，跨项目返回 None。
    """
    if action not in ("verified", "rejected", "candidate"):
        return None
    with _db() as c:
        cur = c.execute("UPDATE facts SET status=? WHERE id=? AND project_id=?",
                        (action, fid, project_id))
        if cur.rowcount <= 0:
            return None
        row = c.execute("SELECT * FROM facts WHERE id=?", (fid,)).fetchone()
    return dict(row) if row else None


def list_facts(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM facts WHERE project_id=? ORDER BY created_at DESC", (project_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- 请求库（v017.1：Burp/HAR 导入） ----------
def add_request(project_id: str, rec: dict) -> dict:
    """入库一条导入请求（rec 已由 importer 完成脱敏/scope 判定/去重键计算）。"""
    rid = rec.get("id") or uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT OR IGNORE INTO request_library (id,project_id,source,method,url,"
            "normalized_url,headers,cookies,query,body,content_type,status_code,tags,"
            "scope_status,dedup_key,object_candidates,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, project_id, rec.get("source", ""), rec.get("method", ""),
             rec.get("url", ""), rec.get("normalized_url", ""),
             json.dumps(rec.get("headers", {}), ensure_ascii=False),
             json.dumps(rec.get("cookies", {}), ensure_ascii=False),
             json.dumps(rec.get("query", {}), ensure_ascii=False),
             rec.get("body", ""), rec.get("content_type", ""),
             rec.get("status_code"), json.dumps(rec.get("tags", []), ensure_ascii=False),
             rec.get("scope_status", "allowed"), rec.get("dedup_key", ""),
             json.dumps(rec.get("object_candidates", []), ensure_ascii=False),
             time.time()),
        )
    rec["id"] = rid
    return rec


def list_requests(project_id: str, scope_status: str = "", method: str = "",
                  limit: int = 200) -> list[dict]:
    q = "SELECT * FROM request_library WHERE project_id=?"
    args: list = [project_id]
    if scope_status:
        q += " AND scope_status=?"
        args.append(scope_status)
    if method:
        q += " AND method=?"
        args.append(method.upper())
    q += " ORDER BY created_at DESC LIMIT ?"
    args.append(max(1, min(int(limit), 1000)))
    with _db() as c:
        rows = c.execute(q, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for col in ("headers", "cookies", "query", "tags", "object_candidates"):
            try:
                d[col] = json.loads(d.get(col) or ("{}" if col != "tags" else "[]"))
            except (TypeError, ValueError):
                pass
        out.append(d)
    return out


def delete_request(project_id: str, rid: str) -> bool:
    """删除一条请求库记录（WHERE 双条件防跨项目，同 delete_fact）。"""
    with _db() as c:
        cur = c.execute("DELETE FROM request_library WHERE id=? AND project_id=?",
                        (rid, project_id))
    return cur.rowcount > 0


# ---------- 测试身份库（v017.2） ----------
def add_identity(project_id: str, label: str, role: str = "user",
                 tenant: str = "", headers_enc: str = "", cookies_enc: str = "",
                 source: str = "manual", check_url: str = "",
                 notes: str = "") -> dict:
    """登记测试身份。headers_enc/cookies_enc 必须是 secretbox.seal_dict 的产物。"""
    iid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO identities (id,project_id,label,role,tenant,headers_enc,"
            "cookies_enc,source,status,check_url,notes,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (iid, project_id, label, role, tenant, headers_enc, cookies_enc,
             source, "active", check_url, notes, time.time()),
        )
    return {"id": iid, "project_id": project_id, "label": label, "role": role,
            "tenant": tenant, "status": "active", "check_url": check_url}


def list_identities(project_id: str) -> list[dict]:
    """列出身份元数据——**不含任何凭据字段**（headers_enc/cookies_enc 不出库层）。"""
    with _db() as c:
        rows = c.execute(
            "SELECT id,label,role,tenant,source,status,last_checked_at,check_url,"
            "notes,created_at FROM identities WHERE project_id=? ORDER BY created_at",
            (project_id,)).fetchall()
    return [dict(r) for r in rows]


def get_identity(project_id: str, iid: str) -> dict | None:
    """取单条身份（含密文字段，仅供 secretbox 解密路径使用）。归属不符返回 None。"""
    with _db() as c:
        row = c.execute("SELECT * FROM identities WHERE id=? AND project_id=?",
                        (iid, project_id)).fetchone()
    return dict(row) if row else None


def update_identity_status(project_id: str, iid: str, status: str,
                           last_checked_at: float | None = None) -> bool:
    if status not in ("active", "expired", "invalid", "disabled"):
        return False
    with _db() as c:
        if last_checked_at is not None:
            cur = c.execute(
                "UPDATE identities SET status=?, last_checked_at=? WHERE id=? AND project_id=?",
                (status, last_checked_at, iid, project_id))
        else:
            cur = c.execute(
                "UPDATE identities SET status=? WHERE id=? AND project_id=?",
                (status, iid, project_id))
    return cur.rowcount > 0


def delete_identity(project_id: str, iid: str) -> bool:
    """删除身份（凭据密文随行删除；审计上只保留不含秘密的元数据在此不保留）。"""
    with _db() as c:
        cur = c.execute("DELETE FROM identities WHERE id=? AND project_id=?",
                        (iid, project_id))
    return cur.rowcount > 0


def count_identities(project_id: str) -> int:
    with _db() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM identities WHERE project_id=?",
                        (project_id,)).fetchone()
    return int(row["n"] or 0)


# ---------- 差分记录与复核清单（v017.4） ----------
def add_diff_run(project_id: str, rec: dict) -> str:
    rid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO diff_runs (id,project_id,request_id,baseline_identity,"
            "target_field,target_location,target_value_masked,verdict,reason,"
            "stable,steps_json,variant_url,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, project_id, rec.get("request_id", ""), rec.get("baseline_identity", ""),
             rec.get("target_field", ""), rec.get("target_location", ""),
             rec.get("target_value_masked", ""), rec.get("verdict", ""),
             rec.get("reason", ""), 1 if rec.get("stable") else 0,
             json.dumps(rec.get("steps", []), ensure_ascii=False),
             rec.get("variant_url", ""), time.time()))
    return rid


def list_diff_runs(project_id: str, limit: int = 50) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM diff_runs WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
            (project_id, max(1, min(int(limit), 200)))).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["steps"] = json.loads(d.pop("steps_json") or "[]")
        except (TypeError, ValueError):
            d["steps"] = []
        out.append(d)
    return out


def get_diff_run(project_id: str, run_id: str) -> dict | None:
    with _db() as c:
        row = c.execute("SELECT * FROM diff_runs WHERE id=? AND project_id=?",
                        (run_id, project_id)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["steps"] = json.loads(d.pop("steps_json") or "[]")
    except (TypeError, ValueError):
        d["steps"] = []
    return d


def add_flow_run(project_id: str, rec: dict) -> str:
    rid = uuid.uuid4().hex[:12]
    with _db() as c:
        c.execute(
            "INSERT INTO flow_runs (id,project_id,identity_label,step_ids_json,"
            "verdict,reason,steps_json,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (rid, project_id, rec.get("identity_label", ""),
             json.dumps(rec.get("step_ids", []), ensure_ascii=False),
             rec.get("verdict", ""), rec.get("reason", ""),
             json.dumps(rec.get("steps", []), ensure_ascii=False), time.time()))
    return rid


def list_flow_runs(project_id: str, limit: int = 50) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM flow_runs WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
            (project_id, max(1, min(int(limit), 200)))).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for col in ("step_ids_json", "steps_json"):
            try:
                d[col.replace("_json", "")] = json.loads(d.pop(col) or "[]")
            except (TypeError, ValueError):
                d[col.replace("_json", "")] = []
        out.append(d)
    return out


def get_checks(finding_id: str) -> dict | None:
    with _db() as c:
        row = c.execute("SELECT * FROM finding_checks WHERE finding_id=?",
                        (finding_id,)).fetchone()
    return dict(row) if row else None


def set_checks(finding_id: str, checks: dict, note: str = "") -> dict:
    """写入五项复核清单（upsert）。返回完整清单。"""
    with _db() as c:
        c.execute(
            "INSERT INTO finding_checks (finding_id,c1_repeat,c2_permission_delta,"
            "c3_minimal_chain,c4_readonly_or_safe,c5_impact_proven,note,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(finding_id) DO UPDATE SET c1_repeat=excluded.c1_repeat,"
            " c2_permission_delta=excluded.c2_permission_delta,"
            " c3_minimal_chain=excluded.c3_minimal_chain,"
            " c4_readonly_or_safe=excluded.c4_readonly_or_safe,"
            " c5_impact_proven=excluded.c5_impact_proven,"
            " note=excluded.note, updated_at=excluded.updated_at",
            (finding_id,
             1 if checks.get("c1_repeat") else 0,
             1 if checks.get("c2_permission_delta") else 0,
             1 if checks.get("c3_minimal_chain") else 0,
             1 if checks.get("c4_readonly_or_safe") else 0,
             1 if checks.get("c5_impact_proven") else 0,
             note[:1000], time.time()))
    return get_checks(finding_id)


def checks_complete(finding_id: str) -> bool:
    """五项是否全部勾选——confirmed 的硬闸门依据。"""
    ck = get_checks(finding_id)
    if not ck:
        return False
    return all(ck[k] for k in ("c1_repeat", "c2_permission_delta",
                               "c3_minimal_chain", "c4_readonly_or_safe",
                               "c5_impact_proven"))


# ---------- 流量安全（v023.1） ----------
def upsert_traffic_state(project_id: str, st: dict) -> None:
    """写入/更新目标状态（root_domain 为主键——跨项目共享同一目标的封禁状态）。

    注意必须写入 resolved_ip：同 IP 聚合暂停靠它反查兄弟主机（v023.3 踩坑：
    漏了这一列导致「同 IP 兄弟主机一并暂停」静默失效）。
    """
    with _db() as c:
        c.execute(
            "INSERT INTO traffic_states (root_domain,project_id,state,reason,signal_count,"
            "cooldown_until,last_success_at,last_error_at,last_error_type,last_error_code,"
            "resolved_ip,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(root_domain) DO UPDATE SET state=excluded.state,"
            " reason=excluded.reason, signal_count=excluded.signal_count,"
            " cooldown_until=excluded.cooldown_until,"
            " last_success_at=COALESCE(excluded.last_success_at, traffic_states.last_success_at),"
            " last_error_at=COALESCE(excluded.last_error_at, traffic_states.last_error_at),"
            " last_error_type=excluded.last_error_type,"
            " last_error_code=excluded.last_error_code,"
            " resolved_ip=CASE WHEN excluded.resolved_ip<>'' THEN excluded.resolved_ip"
            "                  ELSE traffic_states.resolved_ip END,"
            " project_id=excluded.project_id, updated_at=excluded.updated_at",
            (st.get("root_domain", ""), project_id, st.get("state", "NORMAL"),
             st.get("reason", ""), int(st.get("signal_count") or 0),
             float(st.get("cooldown_until") or 0), st.get("last_success_at"),
             st.get("last_error_at"), st.get("last_error_type", ""),
             int(st.get("last_error_code") or 0), st.get("resolved_ip", ""),
             time.time()))


def get_traffic_state(root_domain: str) -> dict | None:
    with _db() as c:
        row = c.execute("SELECT * FROM traffic_states WHERE root_domain=?",
                        (root_domain,)).fetchone()
    return dict(row) if row else None


def list_traffic_states(project_id: str = "") -> list[dict]:
    with _db() as c:
        if project_id:
            rows = c.execute("SELECT * FROM traffic_states WHERE project_id=? OR project_id=''"
                             " ORDER BY updated_at DESC", (project_id,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM traffic_states ORDER BY updated_at DESC").fetchall()
    return [dict(r) for r in rows]


def add_traffic_event(ev: dict) -> None:
    with _db() as c:
        c.execute(
            "INSERT INTO traffic_events (project_id,session_id,root_domain,host,resolved_ip,"
            "port,tool_alias,identity_label,request_fingerprint,event_type,status_code,"
            "error_type,os_error_code,started_at,finished_at,bytes_in,redaction_summary,"
            "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev.get("project_id", ""), ev.get("session_id", ""), ev.get("root_domain", ""),
             ev.get("host", ""), ev.get("resolved_ip", ""), int(ev.get("port") or 0),
             ev.get("tool_alias", ""), ev.get("identity_label", ""),
             ev.get("request_fingerprint", ""), ev.get("event_type", ""),
             ev.get("status_code"), ev.get("error_type", ""),
             int(ev.get("os_error_code") or 0), ev.get("started_at"),
             ev.get("finished_at"), int(ev.get("bytes_in") or 0),
             ev.get("redaction_summary", ""), time.time()))


def list_traffic_events(project_id: str = "", root_domain: str = "",
                        limit: int = 100) -> list[dict]:
    q = "SELECT * FROM traffic_events WHERE 1=1"
    args: list = []
    if project_id:
        q += " AND project_id=?"
        args.append(project_id)
    if root_domain:
        q += " AND root_domain=?"
        args.append(root_domain)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 1000)))
    with _db() as c:
        rows = c.execute(q, args).fetchall()
    return [dict(r) for r in rows]


def recent_traffic_sends(root_domain: str, window_seconds: int) -> list[float]:
    """窗口内所有已发送请求的时间戳（重启后重建滑动窗口用）。"""
    since = time.time() - window_seconds
    with _db() as c:
        rows = c.execute(
            "SELECT created_at FROM traffic_events WHERE root_domain=? AND event_type='sent'"
            " AND created_at>=? ORDER BY created_at", (root_domain, since)).fetchall()
    return [float(r["created_at"]) for r in rows if r["created_at"]]


def distinct_traffic_roots() -> list[str]:
    with _db() as c:
        rows = c.execute("SELECT DISTINCT root_domain FROM traffic_events"
                         " WHERE root_domain<>''").fetchall()
    return [r["root_domain"] for r in rows]


def get_traffic_policy(root_domain: str) -> dict | None:
    with _db() as c:
        row = c.execute("SELECT * FROM traffic_policies WHERE root_domain=?",
                        (root_domain,)).fetchone()
    return dict(row) if row else None


def set_traffic_policy(root_domain: str, policy: dict) -> dict:
    with _db() as c:
        c.execute(
            "INSERT INTO traffic_policies (root_domain,window_seconds,max_requests,"
            "burst_limit,host_concurrency,root_concurrency,manual_resume_required,updated_at)"
            " VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(root_domain) DO UPDATE SET window_seconds=excluded.window_seconds,"
            " max_requests=excluded.max_requests, burst_limit=excluded.burst_limit,"
            " host_concurrency=excluded.host_concurrency,"
            " root_concurrency=excluded.root_concurrency,"
            " manual_resume_required=excluded.manual_resume_required,"
            " updated_at=excluded.updated_at",
            (root_domain, int(policy.get("window_seconds") or 600),
             int(policy.get("max_requests") or 30), int(policy.get("burst_limit") or 5),
             int(policy.get("host_concurrency") or 1), int(policy.get("root_concurrency") or 1),
             1 if policy.get("manual_resume_required", True) else 0, time.time()))
    return get_traffic_policy(root_domain)


def cleanup_traffic_states() -> int:
    """清理结构上无效的目标状态行（v023.6，幂等）。

    背景：v023.2 之前 `root_domain_of()` 会把 IP 按末两段切分，产生 `0.1`
    这类不存在的「根域名」（127.0.0.1 → 0.1）。这类行只会污染审计与状态列表，
    且再也不会被匹配到，安全删除。
    """
    removed = 0
    try:
        with _db() as c:
            rows = c.execute(
                "SELECT root_domain FROM traffic_states").fetchall()
            for r in rows:
                rd = (r["root_domain"] or "").strip()
                # 两段纯数字（且不是合法 IPv4/IPv6）→ 解析残留
                if re.fullmatch(r"\d{1,3}\.\d{1,3}", rd):
                    c.execute("DELETE FROM traffic_states WHERE root_domain=?", (rd,))
                    c.execute("DELETE FROM traffic_events WHERE root_domain=?", (rd,))
                    removed += 1
    except Exception:
        logger.debug("清理无效流量状态失败", exc_info=True)
    return removed


def traffic_summary(project_id: str) -> dict:
    """目标流量摘要（v023.1 基础版；v023.5 扩展为完整审计报告）。"""
    with _db() as c:
        rows = c.execute(
            "SELECT root_domain,event_type,status_code,error_type,COUNT(*) AS n"
            " FROM traffic_events WHERE project_id=? GROUP BY root_domain,event_type,"
            "status_code,error_type", (project_id,)).fetchall()
        total = c.execute("SELECT COUNT(*) AS n FROM traffic_events WHERE project_id=?",
                          (project_id,)).fetchone()
    by_root: dict[str, dict] = {}
    for r in rows:
        d = by_root.setdefault(r["root_domain"], {"sent": 0, "settled": 0, "rejected": 0,
                                                  "errors": 0, "paused": 0})
        et = r["event_type"]
        if et == "sent":
            d["sent"] += r["n"]
        elif et == "settled":
            d["settled"] += r["n"]
            if r["error_type"] or (r["status_code"] and r["status_code"] >= 400):
                d["errors"] += r["n"]
        elif et in ("rejected", "cancelled"):
            d["rejected"] += r["n"]
        elif et == "paused":
            d["paused"] += r["n"]
    return {"project_id": project_id, "total_events": int(total["n"] or 0),
            "by_root": by_root}


def traffic_audit(project_id: str) -> dict:
    """完整流量审计（v023.5，对齐 v023 计划第 8 节字段）。

    只读聚合，不联网。所有数字来自 traffic_events（每条请求都有 sent 事件，
    网络层错误在 settled 里带 error_type/os_error_code）。
    """
    with _db() as c:
        span = c.execute(
            "SELECT MIN(created_at) AS t0, MAX(created_at) AS t1,"
            " SUM(CASE WHEN event_type='sent' THEN 1 ELSE 0 END) AS sent,"
            " SUM(CASE WHEN event_type='settled' THEN 1 ELSE 0 END) AS settled,"
            " SUM(CASE WHEN event_type IN ('rejected','cancelled') THEN 1 ELSE 0 END) AS rejected,"
            " SUM(CASE WHEN event_type='paused' THEN 1 ELSE 0 END) AS paused,"
            " SUM(CASE WHEN event_type='state_changed' THEN 1 ELSE 0 END) AS state_changes,"
            " SUM(CASE WHEN event_type='manual_probe' THEN 1 ELSE 0 END) AS probes"
            " FROM traffic_events WHERE project_id=?", (project_id,)).fetchone()
        by_tool = c.execute(
            "SELECT tool_alias, COUNT(*) AS n FROM traffic_events"
            " WHERE project_id=? AND event_type='sent' GROUP BY tool_alias"
            " ORDER BY n DESC", (project_id,)).fetchall()
        by_root = c.execute(
            "SELECT root_domain, COUNT(*) AS n FROM traffic_events"
            " WHERE project_id=? AND event_type='sent' GROUP BY root_domain"
            " ORDER BY n DESC", (project_id,)).fetchall()
        by_error = c.execute(
            "SELECT COALESCE(error_type,'') AS et, os_error_code, COUNT(*) AS n"
            " FROM traffic_events WHERE project_id=? AND event_type='settled'"
            " AND (error_type<>'' OR os_error_code<>0) GROUP BY error_type, os_error_code"
            " ORDER BY n DESC LIMIT 20", (project_id,)).fetchall()
        by_status = c.execute(
            "SELECT status_code, COUNT(*) AS n FROM traffic_events"
            " WHERE project_id=? AND event_type='settled' AND status_code IS NOT NULL"
            " GROUP BY status_code ORDER BY n DESC LIMIT 20", (project_id,)).fetchall()
        sends = c.execute(
            "SELECT created_at FROM traffic_events WHERE project_id=? AND event_type='sent'"
            " ORDER BY created_at", (project_id,)).fetchall()
        waf = c.execute(
            "SELECT redaction_summary, created_at FROM traffic_events"
            " WHERE project_id=? AND (event_type='state_changed' OR event_type='paused')"
            " ORDER BY created_at DESC LIMIT 20", (project_id,)).fetchall()
        states = c.execute(
            "SELECT root_domain,state,reason,resolved_ip,updated_at FROM traffic_states"
            " ORDER BY updated_at DESC LIMIT 50").fetchall()

    ts = [float(r["created_at"]) for r in sends if r["created_at"]]
    gaps = [b - a for a, b in zip(ts, ts[1:])] if len(ts) > 1 else []
    span_s = (float(span["t1"]) - float(span["t0"])) if span and span["t0"] else 0
    return {
        "project_id": project_id,
        "span_seconds": round(span_s, 1),
        "span_text": _fmt_duration(span_s),
        "total_sent": int(span["sent"] or 0),
        "total_settled": int(span["settled"] or 0),
        "total_rejected": int(span["rejected"] or 0),
        "auto_pauses": int(span["paused"] or 0),
        "state_changes": int(span["state_changes"] or 0),
        "manual_probes": int(span["probes"] or 0),
        "avg_interval": round(sum(gaps) / len(gaps), 2) if gaps else None,
        "min_interval": round(min(gaps), 2) if gaps else None,
        "by_tool": [{"tool": r["tool_alias"] or "(未标注)", "sent": r["n"]} for r in by_tool],
        "by_root": [{"root_domain": r["root_domain"], "sent": r["n"]} for r in by_root],
        "by_status": [{"status_code": r["status_code"], "n": r["n"]} for r in by_status],
        "errors": [{"error_type": r["et"], "os_error_code": r["os_error_code"], "n": r["n"]}
                   for r in by_error],
        "waf_events": [{"at": r["created_at"], "reason": r["redaction_summary"]} for r in waf],
        "states": [dict(r) for r in states],
    }


def _fmt_duration(seconds: float) -> str:
    s = int(max(0, seconds))
    if s >= 3600:
        return f"{s // 3600} 小时 {(s % 3600) // 60} 分"
    if s >= 60:
        return f"{s // 60} 分 {s % 60} 秒"
    return f"{s} 秒"


def delete_fact(project_id: str, fid: str) -> bool:
    """删除一条事实。**必须带 project_id 并校验归属**（v010 P1-3）：

    此前只按 id 删——任何项目的接口拿着别人的 fid 都能把别项目的事实删掉
    （跨项目 ID 猜测/串号即误删）。现在 WHERE 同时匹配 id 与 project_id，
    归属不符 = 未删（返回 False，调用方按 404 处理）。
    """
    with _db() as c:
        cur = c.execute("DELETE FROM facts WHERE id=? AND project_id=?",
                        (fid, project_id))
    return cur.rowcount > 0


# ---------- 因果图（线索树的「因果图」视图：证据推理链） ----------
# 这一整段在 2026-09-16 那次更新里被漏掉了（app/store.py 被整体换成不含因果图
# 持久化的版本，而 app/graph.py 没被替换）。缺了它们，graph.py 里每一个
# store.upsert_causal_node / list_causal_nodes 调用都直接 AttributeError，
# 前端点「因果图」就是 500，且【服务启动、攻击图、其它接口都正常】——
# 属于典型的静默缺件。这里按本地谱系原样恢复，连接统一走 _db()（提交并关闭）。
def list_causal_nodes(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM causal_nodes WHERE project_id=? ORDER BY created_at ASC",
            (project_id,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["data"] = json.loads(d.get("data") or "{}")
        except (TypeError, ValueError):
            d["data"] = {}
        out.append(d)
    return out


def list_causal_edges(project_id: str) -> list[dict]:
    with _db() as c:
        rows = c.execute(
            "SELECT * FROM causal_edges WHERE project_id=? ORDER BY created_at ASC",
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_causal_node(project_id: str, node_id: str) -> dict | None:
    with _db() as c:
        r = c.execute(
            "SELECT * FROM causal_nodes WHERE project_id=? AND id=?", (project_id, node_id)
        ).fetchone()
    if not r:
        return None
    d = dict(r)
    try:
        d["data"] = json.loads(d.get("data") or "{}")
    except (TypeError, ValueError):
        d["data"] = {}
    return d


def upsert_causal_node(project_id: str, node: dict) -> dict:
    """按 id 插入或局部更新一个因果节点（未给字段保持不变）。"""
    node_id = (node.get("id") or "").strip()
    if not node_id:
        raise ValueError("因果节点缺少 id")
    now = time.time()
    exist = get_causal_node(project_id, node_id)
    payload = json.dumps(node.get("data") or {}, ensure_ascii=False)
    if exist is None:
        with _db() as c:
            c.execute(
                "INSERT INTO causal_nodes"
                " (id,project_id,node_type,title,description,status,confidence,severity,"
                "  session_id,source_step,data,created_at,updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (node_id, project_id, node.get("node_type", "Evidence"),
                 node.get("title", ""), node.get("description", ""),
                 node.get("status", "PENDING"), float(node.get("confidence", 0.5)),
                 node.get("severity", ""), node.get("session_id", ""),
                 node.get("source_step", ""), payload, now, now),
            )
    else:
        sets, vals = [], []
        for col in ("node_type", "title", "description", "status", "severity",
                    "session_id", "source_step"):
            if node.get(col) is not None:
                sets.append(f"{col}=?")
                vals.append(node[col])
        if node.get("confidence") is not None:
            sets.append("confidence=?")
            vals.append(float(node["confidence"]))
        if node.get("data"):
            sets.append("data=?")
            vals.append(payload)
        if sets:
            sets.append("updated_at=?")
            vals.extend([now, project_id, node_id])
            with _db() as c:
                c.execute(
                    f"UPDATE causal_nodes SET {', '.join(sets)}"
                    " WHERE project_id=? AND id=?", tuple(vals))
    return get_causal_node(project_id, node_id)


def update_causal_confidence(project_id: str, node_id: str,
                             confidence: float, status: str) -> dict | None:
    with _db() as c:
        c.execute(
            "UPDATE causal_nodes SET confidence=?, status=?, updated_at=?"
            " WHERE project_id=? AND id=?",
            (float(confidence), status, time.time(), project_id, node_id),
        )
    return get_causal_node(project_id, node_id)


def add_causal_edge(project_id: str, source_id: str, target_id: str, label: str,
                    strength: str = "contingent", description: str = "") -> dict:
    """加一条因果边。同一 (source,target,label) 已存在则更新，不重复插入。

    v010 P1-4：返回值增加 "created" 标志——True=新建（调用方可据此触发
    置信度传播），False=已有边更新（重复提交不重复加分，幂等）。
    """
    with _db() as c:
        row = c.execute(
            "SELECT id FROM causal_edges WHERE project_id=? AND source_id=?"
            " AND target_id=? AND label=?",
            (project_id, source_id, target_id, label),
        ).fetchone()
        if row:
            c.execute("UPDATE causal_edges SET strength=?, description=? WHERE id=?",
                      (strength, description, row["id"]))
            eid = row["id"]
            created = False
        else:
            eid = uuid.uuid4().hex[:12]
            c.execute(
                "INSERT INTO causal_edges"
                " (id,project_id,source_id,target_id,label,strength,description,created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (eid, project_id, source_id, target_id, label, strength,
                 description, time.time()),
            )
            created = True
    return {"id": eid, "project_id": project_id, "source_id": source_id,
            "target_id": target_id, "label": label, "strength": strength,
            "description": description, "created": created}


def delete_causal_node(project_id: str, node_id: str) -> bool:
    """删节点时一并删掉挂在它上面的边，避免留下悬空边（前端会画不出来）。"""
    with _db() as c:
        c.execute(
            "DELETE FROM causal_edges WHERE project_id=? AND (source_id=? OR target_id=?)",
            (project_id, node_id, node_id),
        )
        cur = c.execute(
            "DELETE FROM causal_nodes WHERE project_id=? AND id=?", (project_id, node_id))
    return cur.rowcount > 0


def delete_causal_nodes_by_prefix(project_id: str, prefix: str) -> int:
    """按 id 前缀清理（例如删除某条 fact 时同步清掉 fact:<id> 节点）。"""
    with _db() as c:
        rows = c.execute(
            "SELECT id FROM causal_nodes WHERE project_id=? AND id LIKE ?",
            (project_id, prefix + "%"),
        ).fetchall()
        ids = [r["id"] for r in rows]
        for nid in ids:
            c.execute(
                "DELETE FROM causal_edges WHERE project_id=? AND (source_id=? OR target_id=?)",
                (project_id, nid, nid),
            )
        if ids:
            c.execute(
                f"DELETE FROM causal_nodes WHERE project_id=? AND id IN"
                f" ({','.join('?' * len(ids))})",
                (project_id, *ids),
            )
    return len(ids)


def clear_causal(project_id: str) -> None:
    with _db() as c:
        c.execute("DELETE FROM causal_edges WHERE project_id=?", (project_id,))
        c.execute("DELETE FROM causal_nodes WHERE project_id=?", (project_id,))


def get_step(step_id: str) -> dict | None:
    """按 id 取一条执行步骤（因果图按 step_id 溯源时要用）。"""
    with _db() as c:
        r = c.execute("SELECT * FROM steps WHERE id=?", (step_id,)).fetchone()
    return dict(r) if r else None


def list_project_steps(project_id: str, limit: int = 400) -> list[dict]:
    """项目内全部执行步骤（带所属会话），供因果图派生 Evidence 节点用。"""
    with _db() as c:
        rows = c.execute(
            "SELECT st.id, st.session_id, st.tool_alias, st.tool_name, st.target,"
            " st.status, st.output, st.created_at"
            " FROM steps st JOIN sessions s ON s.id=st.session_id"
            " WHERE s.project_id=? ORDER BY st.created_at ASC LIMIT ?",
            (project_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------- 项目情报库 ----------
def get_intel(project_id: str) -> dict:
    with _db() as c:
        r = c.execute("SELECT data FROM intel WHERE project_id=?", (project_id,)).fetchone()
    if not r:
        return {}
    try:
        return json.loads(r["data"])
    except Exception:
        return {}


def merge_intel(project_id: str, patch: dict) -> dict:
    """合并情报（按类别去重、排序、限量），返回合并后的完整情报。"""
    data = get_intel(project_id)
    for k, vals in patch.items():
        if not isinstance(vals, (list, tuple, set)):
            continue
        cur = set(str(v) for v in data.get(k, []))
        cur.update(str(v) for v in vals if v)
        data[k] = sorted(cur)[:200]
    with _db() as c:
        c.execute(
            "INSERT OR REPLACE INTO intel (project_id,data,updated_at) VALUES (?,?,?)",
            (project_id, json.dumps(data, ensure_ascii=False), time.time()),
        )
    return data


def delete_intel(project_id: str) -> bool:
    with _db() as c:
        c.execute("DELETE FROM intel WHERE project_id=?", (project_id,))
    return True


# ---------- 控制台「统计看板」聚合（v111）----------
# 只读。**SQL 只在这一层**；「哪些算成功、哪些算失败」这类**口径**留在调用方
# （app/console_api.py），两者不要混在一处 —— 口径要能被单独审阅与测试。
#
# 共同约定：
#   · `since` 是 unix 时间戳下界（含），`None` = 不限时间（全部历史）。
#     窗口边界的计算由调用方负责，这里**不解释 days**（免得两处各算一遍边界）。
#   · 一次调用**只开一个连接**（下面的 `_stat_*` 都接收同一个游标）。

def _stat_steps(c, since) -> dict:
    """步骤：状态分布 + 归因分布 + 耗时统计。"""
    w, p = ("WHERE created_at >= ?", (since,)) if since is not None else ("", ())
    by_status = {(r["status"] or "?"): r["n"] for r in c.execute(
        f"SELECT status, COUNT(*) n FROM steps {w} GROUP BY status", p)}
    by_attr = [{"status": r["status"] or "", "attribution": r["attribution"] or "",
                "n": r["n"]}
               for r in c.execute(
        f"SELECT status, attribution, COUNT(*) n FROM steps {w} "
        # ⚠️ 只取**真正的失败/拒绝**：`running` 是在途、`done` 是成功，
        # 混进「失败归因」图会让人以为它们失败了。
        f"{'AND' if w else 'WHERE'} status IN ('error', 'denied') "
        "GROUP BY status, attribution ORDER BY n DESC", p)]
    # ⚠️ `elapsed <= 0` 是**没记录到耗时**，不是「瞬时完成」。实测占 38%（117/306）——
    # 混进分位数会把 p50 拉到 0，而均值看着还挺正常（6.47s），属于"看着对但错得很远"。
    n_valid = c.execute(
        f"SELECT COUNT(*) FROM steps {w} "
        f"{'AND' if w else 'WHERE'} elapsed > 0", p).fetchone()[0]
    n_zero = c.execute(
        f"SELECT COUNT(*) FROM steps {w} "
        f"{'AND' if w else 'WHERE'} elapsed <= 0", p).fetchone()[0]
    elapsed = {"valid": n_valid, "excluded": n_zero}
    if n_valid:
        elapsed["max"] = round(float(c.execute(
            f"SELECT MAX(elapsed) m FROM steps {w} "
            f"{'AND' if w else 'WHERE'} elapsed > 0", p).fetchone()["m"] or 0.0), 2)
        # 分位数用「排序 + OFFSET 取第 k 个」：SQLite 没有 percentile 函数，
        # 而把整列拉进 Python 在库大了以后是几万行、且每次切页都做一遍。
        for label, frac in (("p50", .5), ("p90", .9), ("p99", .99)):
            off = max(0, min(n_valid - 1, int(n_valid * frac)))
            v = c.execute(
                f"SELECT elapsed FROM steps {w} "
                f"{'AND' if w else 'WHERE'} elapsed > 0 "
                "ORDER BY elapsed LIMIT 1 OFFSET ?", (*p, off)).fetchone()[0]
            elapsed[label] = round(float(v or 0.0), 2)
    else:
        elapsed.update({"max": None, "p50": None, "p90": None, "p99": None})
    total = c.execute(f"SELECT COUNT(*) FROM steps {w}", p).fetchone()[0]
    return {"total": total, "by_status": by_status, "by_attribution": by_attr,
            "elapsed": elapsed}


def _stat_tools(c, since, top: int) -> dict:
    """工具调用频次 TOP N + 用过的工具种数。"""
    w, p = ("WHERE created_at >= ?", (since,)) if since is not None else ("", ())
    andw = f"{'AND' if w else 'WHERE'} tool_alias <> ''"
    rows = [{"alias": r["tool_alias"], "name": r["name"] or "",
             "calls": r["n"], "fail": int(r["f"] or 0)}
            for r in c.execute(
        f"SELECT tool_alias, MAX(tool_name) name, COUNT(*) n, "
        f"SUM(CASE WHEN status <> 'done' THEN 1 ELSE 0 END) f "
        f"FROM steps {w} {andw} GROUP BY tool_alias ORDER BY n DESC, tool_alias "
        "LIMIT ?", (*p, int(top)))]
    distinct = c.execute(
        f"SELECT COUNT(DISTINCT tool_alias) FROM steps {w} {andw}", p).fetchone()[0]
    # 窗口内**用过**的全部别名（不只是 TOP N）。调用方拿它与「模型清单里的工具」做差，
    # 找出「配了却一次没用过」的 —— 那是排障时最有用的一条线索。
    used = [r["tool_alias"] for r in c.execute(
        f"SELECT DISTINCT tool_alias FROM steps {w} {andw}", p)]
    return {"top": rows, "distinct": distinct, "used": used}


def _stat_traffic(c, since) -> dict:
    """目标流量：事件类型 / 错误类型 / 状态码 / 入站字节。"""
    w, p = ("WHERE created_at >= ?", (since,)) if since is not None else ("", ())
    andw = f"{'AND' if w else 'WHERE'}"
    by_ev = {(r["event_type"] or "?"): r["n"] for r in c.execute(
        f"SELECT event_type, COUNT(*) n FROM traffic_events {w} "
        "GROUP BY event_type ORDER BY n DESC", p)}
    by_err = {(r["error_type"] or "?"): r["n"] for r in c.execute(
        f"SELECT error_type, COUNT(*) n FROM traffic_events {w} "
        f"{andw} error_type <> '' GROUP BY error_type ORDER BY n DESC", p)}
    by_code = {str(r["status_code"]): r["n"] for r in c.execute(
        f"SELECT status_code, COUNT(*) n FROM traffic_events {w} "
        f"{andw} status_code IS NOT NULL GROUP BY status_code "
        "ORDER BY n DESC LIMIT 12", p)}
    b = c.execute(f"SELECT COALESCE(SUM(bytes_in),0) b FROM traffic_events {w}",
                  p).fetchone()["b"]
    return {"by_event_type": by_ev, "by_error_type": by_err,
            "by_status_code": by_code, "bytes_in": int(b or 0)}


def _stat_findings(c, since) -> dict:
    w, p = ("WHERE created_at >= ?", (since,)) if since is not None else ("", ())
    return {"by_severity": {(r["severity"] or "未标"): r["n"] for r in c.execute(
        f"SELECT severity, COUNT(*) n FROM findings {w} GROUP BY severity "
        "ORDER BY n DESC", p)}}


def _stat_flow(c, since) -> dict:
    w, p = ("WHERE created_at >= ?", (since,)) if since is not None else ("", ())
    return {"verdicts": {(r["verdict"] or "未判"): r["n"] for r in c.execute(
        f"SELECT verdict, COUNT(*) n FROM flow_runs {w} GROUP BY verdict "
        "ORDER BY n DESC", p)}}


def console_stats(since: float | None = None, top: int = 15) -> dict:
    """控制台统计看板的全部聚合（**一次连接**）。

    `since=None` 表示不限时间窗。参数由调用方算好（见 app/console_api.py）。
    """
    with _db() as c:
        out = {
            "steps": _stat_steps(c, since),
            "tools": _stat_tools(c, since, top),
            "traffic": _stat_traffic(c, since),
            "findings": _stat_findings(c, since),
            "flow": _stat_flow(c, since),
        }
        row = c.execute(
            "SELECT (SELECT MIN(created_at) FROM steps) a, "
            "(SELECT MAX(created_at) FROM steps) b, "
            "(SELECT COUNT(*) FROM projects) p, "
            "(SELECT COUNT(*) FROM sessions) s").fetchone()
    out["span"] = {"first_step_at": row["a"], "last_step_at": row["b"],
                   "projects": row["p"], "sessions": row["s"]}
    return out


# ---------- 产物目录 ----------
def artifact_dir(project_id: str) -> Path:
    p = config.DATA_DIR / "artifacts" / project_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def save_artifact(project_id: str, filename: str, content: str) -> str:
    d = artifact_dir(project_id)
    path = d / filename
    # newline=""：产物按写入内容原样落盘（v033）。Windows 默认会把 \n 改写成
    # \r\n，使产物与工具输出/证据原文不再逐字节一致 —— 证据类文件必须可复核。
    path.write_text(content, encoding="utf-8", newline="")
    return str(path)


init_db()
