# -*- coding: utf-8 -*-
"""报告生成：输出补天/SRC 平台可直接提交的漏洞报告 Markdown。

v012 P1-2 增强：
- 修复建议不再「待补充」：按漏洞类型套内置模板（remediation_for），
  登记时已填的 remediation 优先。
- 已确认漏洞（status=confirmed）与待验证候选（draft/needs_review）分章——
  AI 只能产候选（v012 P1-1），只有人工确认过的才进「已确认」章节，
  避免把模型猜测当结论提交平台。
- Markdown 表格单元格统一转义：项目名/目标/漏洞标题里出现 | 或换行
  会把表格结构打碎（此前项目名含 | 就能毁掉整张清单）。
- 导出前完整性检查：已确认漏洞缺证据/缺复现步骤时在报告头部给出告警清单。
"""
from __future__ import annotations

from datetime import datetime

from . import config
from . import store

SEVERITY_ORDER = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}

CONFIRMED_STATUSES = ("confirmed",)
CANDIDATE_STATUSES = ("draft", "needs_review")

# ---------- 修复建议模板（P1-2） ----------
# key：漏洞类型关键词（小写子串匹配，首个命中的生效）。
# 覆盖 SRC 高频类型；未命中给通用兜底。
_REMEDIATION_TEMPLATES: list[tuple[tuple[str, ...], str]] = [
    (("sql", "注入", "sqli"), (
        "1. 一律使用参数化查询/预编译语句，禁止字符串拼接 SQL；\n"
        "2. 对进入 SQL 语句的输入做白名单校验（排序字段、表名等用枚举映射）；\n"
        "3. 数据库账号最小权限，禁用 root/sa 直连业务；\n"
        "4. 开启 ORM 层过滤并关闭详细 SQL 报错回显。")),
    (("xss", "跨站"), (
        "1. 所有输出到 HTML/JS/属性位置的变量按上下文做实体编码；\n"
        "2. 引入 CSP（Content-Security-Policy）限制内联脚本执行；\n"
        "3. 富文本输入使用服务端白名单过滤（如 DOMPurify 等价方案）；\n"
        "4. Cookie 增加 HttpOnly / Secure 属性。")),
    (("弱口令", "默认口令", "weak password", "爆破"), (
        "1. 强制密码复杂度策略并定期校验弱口令字典；\n"
        "2. 首次登录/初始化后强制修改默认口令；\n"
        "3. 登录接口增加失败锁定与验证码/限速；\n"
        "4. 对管理后台收敛暴露面（VPN/白名单访问）。")),
    (("未授权", "越权", "unauthorized", "idor", "访问控制"), (
        "1. 服务端对每个敏感接口强制会话鉴权，禁止仅前端隐藏入口；\n"
        "2. 数据对象访问统一校验归属（水平越权）与角色权限（垂直越权）；\n"
        "3. 接口返回最小字段集，避免枚举他人资源；\n"
        "4. 对批量导出/查询接口增加频率与数量限制。")),
    (("信息泄露", "泄露", "泄露", "leak", "目录遍历", "路径遍历", "报错"), (
        "1. 关闭调试模式与详细错误回显，统一返回通用错误页；\n"
        "2. 版本控制/备份文件（.git、.svn、.bak 等）移出 Web 目录并拒绝访问；\n"
        "3. 接口响应移除内部 IP、路径、堆栈、密钥等敏感字段；\n"
        "4. 目录列表功能（autoindex）关闭。")),
    (("上传", "upload", "webshell", "文件包含"), (
        "1. 上传文件类型用服务端白名单校验（含魔数/内容检测，不止后缀）；\n"
        "2. 上传目录禁止执行权限，文件名服务端随机重命名；\n"
        "3. 限制上传大小与频率；\n"
        "4. 文件包含路径固定化，禁止用户输入直接拼接 include/require。")),
    (("ssrf", "请求伪造"), (
        "1. 服务端请求目标做白名单校验，禁止访问内网网段/元数据地址（169.254.169.254 等）；\n"
        "2. 禁用不必要的协议（file://、gopher:// 等）；\n"
        "3. 对重定向后的最终地址再次校验；\n"
        "4. 出口网络与内网业务隔离。")),
    (("命令", "rce", "代码执行", "exec"), (
        "1. 禁止将用户输入拼入系统命令，改用参数化 API 或白名单动作映射；\n"
        "2. 必须执行时用 escape 转义并禁用 shell 元字符；\n"
        "3. 执行账号最小权限，禁用危险函数；\n"
        "4. 部署侧监控异常子进程与外连行为。")),
    (("csr f", "csrf", "跨站请求"), (
        "1. 敏感操作接口增加 CSRF Token 校验；\n"
        "2. 校验 Origin/Referer；\n"
        "3. 关键操作引入二次确认（短信/密码）。")),
    (("反序列化", "deserialization"), (
        "1. 反序列化输入来源白名单化，优先改用 JSON 等安全格式；\n"
        "2. 升级受影响组件版本；\n"
        "3. 反序列化操作不做任何业务逻辑触发（防 gadget 链）。")),
]

_GENERIC_REMEDIATION = (
    "1. 修复存在问题的功能点，对相关输入做服务端校验；\n"
    "2. 复核同类功能是否存在相同问题（横向排查）；\n"
    "3. 修复后进行回归测试确认漏洞不再复现；\n"
    "4. 建议引入安全开发流程（代码审计/依赖扫描）防止再次引入。"
)


def remediation_for(vuln_type: str) -> str:
    """按漏洞类型关键词取修复建议模板；未命中返回通用建议（P1-2）。"""
    t = (vuln_type or "").lower()
    if not t:
        return _GENERIC_REMEDIATION
    for keys, tpl in _REMEDIATION_TEMPLATES:
        for k in keys:
            if k in t:
                return tpl
    return _GENERIC_REMEDIATION


def _esc_cell(text) -> str:
    """Markdown 表格单元格转义（P1-2）：竖线会切断列，换行会断表。"""
    s = str(text if text is not None else "")
    return s.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def render_project_report(project_id: str) -> str:
    proj = store.get_project(project_id)
    if not proj:
        return "# 项目不存在\n"

    all_findings = sorted(
        store.list_findings(project_id),
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", ""), 9),
    )
    # v012 P1-1：只有人工确认过的进「已确认」章节，其余一律候选
    confirmed = [f for f in all_findings if f.get("status") in CONFIRMED_STATUSES]
    candidates = [f for f in all_findings if f.get("status") not in CONFIRMED_STATUSES]
    steps = []
    for s in store.list_sessions(project_id):
        steps.extend(_steps_of(s["id"]))

    L = []
    L.append(f"# {_esc_cell(proj['name'])} — 渗透测试报告\n")
    L.append(f"- **目标**：{_esc_cell(proj.get('target') or '（未指定）')}")
    L.append(f"- **生成时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- **已确认漏洞**：{len(confirmed)}（可提交）")
    L.append(f"- **待验证候选**：{len(candidates)}（需人工复核后方可提交）")
    L.append(f"- **执行步骤**：{len(steps)}")
    if proj.get("note"):
        L.append(f"- **备注**：{_esc_cell(proj['note'])}")
    L.append("")

    # ---- 完整性检查（P1-2）：已确认漏洞缺关键材料时显式告警 ----
    warnings = []
    for f in confirmed:
        if not (f.get("evidence") or "").strip():
            warnings.append(f"「{f['title']}」缺少证明材料（evidence）")
        if not (f.get("reproduction") or "").strip():
            warnings.append(f"「{f['title']}」缺少复现步骤")
    if warnings:
        L.append("\n## ⚠ 完整性告警（提交前必须补齐）\n")
        for w in warnings:
            L.append(f"- {w}")
        L.append("")

    L.append("\n## 一、已确认漏洞清单\n")
    if confirmed:
        L.append("| 序号 | 漏洞名称 | 类型 | 危害等级 | 影响目标 |")
        L.append("|---|---|---|---|---|")
        for i, f in enumerate(confirmed, 1):
            L.append(f"| {i} | {_esc_cell(f['title'])} | {_esc_cell(f.get('vuln_type') or '—')} "
                     f"| {f['severity']} | {_esc_cell(f['target'])} |")
    else:
        L.append("（暂无已确认的漏洞。登记的候选漏洞经人工确认后进入本章节。）")
    L.append("")

    if confirmed:
        L.append("\n## 二、已确认漏洞详情\n")
        for i, f in enumerate(confirmed, 1):
            L += _finding_detail(i, f)

    if candidates:
        L.append("\n## 附录、待验证候选（未确认，不作为结论提交）\n")
        for i, f in enumerate(candidates, 1):
            L.append(f"\n### 附{i}. {_esc_cell(f['title'])}（{f.get('status')}）\n")
            L.append(f"- **危害等级**：{f['severity']}")
            L.append(f"- **影响目标**：{_esc_cell(f['target'])}")
            if f.get("detail"):
                L.append(f"\n{f['detail']}\n")
        L.append("\n> 以上候选未经人工确认，请复核后迁移至已确认章节或删除。\n")

    L.append("\n## 三、测试过程记录\n")
    if steps:
        L.append("| 时间 | 工具 | 目标 | 风险等级 | 状态 |")
        L.append("|---|---|---|---|---|")
        for s in steps:
            ts = datetime.fromtimestamp(s["created_at"]).strftime("%m-%d %H:%M")
            L.append(
                f"| {ts} | {_esc_cell(s['tool_name'])} | {_esc_cell(s['target'])} "
                f"| {_esc_cell(s['risk_level'])} | {s['status']} |"
            )
    else:
        L.append("（无执行记录）")
    L.append("")

    # ---- v023.5：测试流量摘要（含防护/暂停事件）----
    # 目的（计划第 8 节）：事后能回答「是请求总量过大、短时突发、还是某工具内部
    # 并发过高导致目标防护」——这对判断测试是否越界、以及向 SRC 平台说明测试
    # 行为都很关键。
    try:
        aud = store.traffic_audit(project_id)
    except Exception:
        aud = None
    if aud and aud.get("total_sent"):
        L.append("\n## 四、测试流量摘要\n")
        L.append(f"- **测试时长**：{aud.get('span_text')}")
        L.append(f"- **实际发出请求**：{aud.get('total_sent')} 次"
                 f"（未发出/被调度拒绝 {aud.get('total_rejected')} 次）")
        if aud.get("avg_interval") is not None:
            L.append(f"- **平均间隔**：{aud.get('avg_interval')} 秒"
                     f"（最短 {aud.get('min_interval')} 秒）")
        L.append(f"- **目标防护事件**：状态变更 {aud.get('state_changes')} 次，"
                 f"自动暂停 {aud.get('auto_pauses')} 次，人工恢复探测 "
                 f"{aud.get('manual_probes')} 次")
        if aud.get("by_tool"):
            L.append("- **按通道分布**：" + "；".join(
                f"{t['tool']} {t['sent']} 次" for t in aud["by_tool"][:8]))
        if aud.get("waf_events"):
            L.append("\n**防护/暂停事件（最近）**\n")
            for ev in aud["waf_events"][:8]:
                ts = datetime.fromtimestamp(ev["at"]).strftime("%m-%d %H:%M:%S")
                L.append(f"- {ts} {_esc_cell(ev.get('reason') or '')}")
        if aud.get("states"):
            L.append("\n**目标最终状态**\n")
            L.append("| 根域名 | 状态 | 原因 | IP |")
            L.append("|---|---|---|---|")
            for st in aud["states"][:10]:
                L.append(f"| {_esc_cell(st.get('root_domain') or '')} "
                         f"| {_esc_cell(st.get('state') or '')} "
                         f"| {_esc_cell((st.get('reason') or '')[:60])} "
                         f"| {_esc_cell(st.get('resolved_ip') or '')} |")
        L.append("")

    L.append("\n---\n")
    L.append("\n> 本报告由本地 SRC 渗透 Agent 生成。所有操作均应在获得书面授权的前提下进行。\n")

    return "\n".join(L)


def _finding_detail(i: int, f: dict) -> list[str]:
    """单个已确认漏洞的详情块（P1-2 结构化字段）。"""
    L = []
    L.append(f"\n### {i}. {_esc_cell(f['title'])}\n")
    L.append(f"- **危害等级**：{f['severity']}")
    if f.get("vuln_type"):
        L.append(f"- **漏洞类型**：{_esc_cell(f['vuln_type'])}")
    if f.get("cwe"):
        L.append(f"- **CWE**：{_esc_cell(f['cwe'])}")
    if f.get("cvss"):
        L.append(f"- **CVSS**：{_esc_cell(f['cvss'])}")
    L.append(f"- **影响目标**：{_esc_cell(f['target'])}")
    if f.get("impact_scope"):
        L.append(f"- **影响范围**：{_esc_cell(f['impact_scope'])}")
    L.append(f"\n**漏洞描述**\n\n{f.get('detail') or '（待补充）'}\n")
    if f.get("reproduction"):
        L.append(f"\n**复现步骤**\n\n{f['reproduction']}\n")
    if f.get("evidence"):
        L.append(f"\n**证明（请求回显 / 截图说明）**\n\n```\n{f['evidence']}\n```\n")
    L.append(f"\n**修复建议**\n\n{f.get('remediation') or remediation_for(f.get('vuln_type'))}\n")
    if f.get("review_note"):
        L.append(f"\n> 人工复核备注：{_esc_cell(f['review_note'])}\n")
    # v017.4：复核清单状态（五项勾选进报告——缺项标 ⚠ 提示报告可信度缺口）。
    # 无清单记录 = 未复核：同样按全缺显示（比静默不渲染更诚实）。
    ck = store.get_checks(f.get("id") or "") or {}
    items = [("可重复验证", "c1_repeat"), ("权限差异明确", "c2_permission_delta"),
             ("最小复现链完整", "c3_minimal_chain"),
             ("只读或无真实损害", "c4_readonly_or_safe"),
             ("影响可证明", "c5_impact_proven")]
    marks = "；".join(f"{'✔' if ck.get(k) else '⚠ 缺'} {name}" for name, k in items)
    L.append(f"\n**复核清单**：{marks}\n")
    return L


def _steps_of(session_id: str) -> list[dict]:
    import sqlite3
    conn = sqlite3.connect(store.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM steps WHERE session_id=? ORDER BY created_at", (session_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def export_report(project_id: str) -> str:
    """生成报告并写入产物目录，返回文件路径。"""
    md = render_project_report(project_id)
    proj = store.get_project(project_id) or {}
    name = (proj.get("name") or "project").replace(" ", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return store.save_artifact(project_id, f"报告_{name}_{stamp}.md", md)


def toolbox_root() -> str:
    # v056：未配置时返回明确文案，而不是让人以为工具箱在 "./"
    if not getattr(config, "TOOLBOX_ROOT_SET", True):
        return "（未配置 TOOLBOX_ROOT）"
    return str(config.TOOLBOX_ROOT)
