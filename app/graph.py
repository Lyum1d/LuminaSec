# -*- coding: utf-8 -*-
"""线索图领域逻辑：节点/边类型、置信度传播、从既有数据派生因果链。

设计上对齐 LuaN1aoAgent 的「因果图」：
  Evidence（证据）--REVEALS--> KeyFact（关键事实）--SUPPORTS--> Vulnerability（漏洞）
并保留它两个关键机制：
  1. 边 label 归一化——把模型爱说的 FALSIFIES / DISPROVES / CONFIRMS 等折叠到标准值；
  2. 置信度传播——necessary（一票确认/否决）与 contingent（logit 累积）两条轨道。
前端只负责画，所有语义判断都在这里。
"""
from __future__ import annotations

import math
import re

from . import store

# ---------- 节点类型 ----------
# 开放集合：未知类型不被丢弃，只是拿不到中文标签（与 LuaN1ao 的做法一致）。
NODE_TYPE_LABEL = {
    "Project": "项目",
    "Thread": "线索",
    "Evidence": "证据",
    "KeyFact": "关键事实",
    "Hypothesis": "假设",
    "Vulnerability": "疑似漏洞",
    "PossibleVulnerability": "疑似漏洞",
    "ConfirmedVulnerability": "确认漏洞",
    "Exploit": "利用",
    "Credential": "凭据",
    "SystemProperty": "系统属性",
    "TargetArtifact": "目标产物",
    "Flag": "目标产物",
}

# 类型别名归一化（模型输出常见写法 → 标准类型）
NODE_TYPE_ALIAS = {
    "key_fact": "KeyFact", "keyfact": "KeyFact", "fact": "KeyFact", "事实": "KeyFact",
    "evidence": "Evidence", "证据": "Evidence",
    "hypothesis": "Hypothesis", "假设": "Hypothesis",
    "possiblevulnerability": "Vulnerability", "vuln": "Vulnerability",
    "vulnerability": "Vulnerability", "漏洞": "Vulnerability",
    "confirmedvulnerability": "ConfirmedVulnerability",
    "exploit": "Exploit", "利用": "Exploit",
    "credential": "Credential", "凭据": "Credential",
    "systemproperty": "SystemProperty", "systemimplementation": "SystemProperty",
    "targetartifact": "TargetArtifact", "flag": "Flag",
    "thread": "Thread", "session": "Thread", "线索": "Thread",
    "project": "Project", "项目": "Project",
}

# ---------- 边类型 ----------
EDGE_LABEL = {
    "SUPPORTS": "支撑",
    "CONTRADICTS": "反驳",
    "REVEALS": "揭示",
    "EXPLOITS": "利用",
    "MITIGATES": "缓解",
    "BRANCH": "分支",
    # v010 P1-4：认不出来的标签不再硬归成 SUPPORTS——「未知关系」单独标注，
    # 不参与置信度传播。旧行为会把任何垃圾标签都当成一票支撑（+0.4），
    # 模型写错标签名就能人为推高节点置信度。
    "UNKNOWN": "未知关系",
}

# 模型输出里五花八门的写法都折叠到上面 5 个（照搬 LuaN1ao graph_manager 的映射表再补几条）
LABEL_ALIAS = {
    "SUPPORT": "SUPPORTS", "SUPPORTS": "SUPPORTS", "CONFIRMS": "SUPPORTS",
    "CONFIRM": "SUPPORTS", "DEFINITIVE_CONFIRMATION": "SUPPORTS",
    "WEAK_SUPPORT": "SUPPORTS", "STRONG_SUPPORT": "SUPPORTS",
    "CONTRADICT": "CONTRADICTS", "CONTRADICTS": "CONTRADICTS",
    "DISPROVES": "CONTRADICTS", "DISPROVE": "CONTRADICTS", "FALSIFIES": "CONTRADICTS",
    "FALSIFY": "CONTRADICTS", "MINOR_CONTRADICTION": "CONTRADICTS",
    "REVEAL": "REVEALS", "REVEALS": "REVEALS", "INFORMS": "REVEALS",
    "DESCRIBES": "REVEALS", "LEADS_TO": "REVEALS", "CAUSED_BY": "REVEALS",
    "EXPLOIT": "EXPLOITS", "EXPLOITS": "EXPLOITS",
    "MITIGATE": "MITIGATES", "MITIGATES": "MITIGATES",
}

# ---------- 状态 ----------
# 因果图状态（大写，对齐 LuaN1ao）
CAUSAL_STATUS = ("PENDING", "SUPPORTED", "FALSIFIED", "CONTRADICTED",
                 "CONFIRMED", "RE_EVALUATION_PENDING")
# 会话线索状态 → 攻击图状态（前端按状态上色）
THREAD_STATE_TO_STATUS = {
    "active": "in_progress",
    "done": "completed",
    "abandoned": "deprecated",
}

EVIDENCE_STRENGTHS = ("necessary", "contingent")

# v010 P1-4：单批写入上限（apply_updates）。防一次异常调用把图撑爆；
# derive 的 max_steps 已限制派生规模，这里补上 Agent/人工批量写入通道。
CAUSAL_MAX_NODES_PER_BATCH = 200
CAUSAL_MAX_EDGES_PER_BATCH = 500


def normalize_node_type(raw: str) -> str:
    """把任意写法归一化到标准节点类型；不认识的保留原样（不丢数据）。"""
    t = (raw or "").strip()
    if not t:
        return "Evidence"
    return NODE_TYPE_ALIAS.get(t.lower(), t)


def normalize_edge_label(raw: str) -> str:
    """边 label 归一化（v010 P1-4 收紧）。

    已知别名折叠到标准标签；**认不出来的一律返回 UNKNOWN**——不再像旧行为
    那样默认当作 SUPPORTS（最宽松语义）。UNKNOWN 会在 score() 里被跳过，
    不动置信度：模型编造的标签名不再能人为推高节点置信度。
    """
    t = (raw or "").strip().upper()
    return LABEL_ALIAS.get(t, "UNKNOWN")


def node_type_label(node_type: str) -> str:
    return NODE_TYPE_LABEL.get(node_type, node_type or "节点")


# ---------- 置信度传播 ----------
def score(current: float, label: str, strength: str) -> tuple[float, str | None]:
    """按证据强度更新置信度，返回 (新置信度, 新状态或 None 表示不改状态)。

    necessary：决定性证据，一票确认（1.0/CONFIRMED）或一票否决（0.0/FALSIFIED）。
    contingent：累积性证据，在 logit 空间上加减 delta，结果夹在 0.05~0.95。
    只有 SUPPORTS / CONTRADICTS 会改数值——REVEALS / EXPLOITS 是结构关系，不动置信度。
    """
    if label not in ("SUPPORTS", "CONTRADICTS"):
        return float(current), None

    cur = max(0.01, min(0.99, float(current)))
    if strength == "necessary":
        if label == "CONTRADICTS":
            return 0.0, "FALSIFIED"
        return 1.0, "CONFIRMED"

    delta = 0.4 if label == "SUPPORTS" else -0.5
    new_logit = math.log(cur / (1 - cur)) + delta
    new_conf = 1 / (1 + math.exp(-new_logit))
    new_conf = max(0.05, min(0.95, new_conf))

    if label == "CONTRADICTS":
        return new_conf, ("FALSIFIED" if new_conf <= 0.10 else "CONTRADICTED")
    if new_conf >= 0.90:
        return new_conf, "CONFIRMED"
    return new_conf, "SUPPORTED"


# ---------- 图读取 ----------
def build_attack_graph(project_id: str) -> dict:
    """攻击图 = 线索（会话）树。项目本身作为根节点，边表示分支父子关系。

    节点粒度按约定控制在「一条线索一个节点」，不展开执行步骤；
    步数与状态挂在节点 data 上，前端在卡片里显示。
    """
    proj = store.get_project(project_id)
    if not proj:
        return {"nodes": [], "edges": []}

    nodes = [{
        "id": f"project:{project_id}",
        "node_type": "Project",
        "type_label": node_type_label("Project"),
        "title": proj.get("name") or "未命名项目",
        "description": proj.get("target") or "",
        "status": "in_progress",
        "confidence": 1.0,
        "data": {"target": proj.get("target") or "", "note": proj.get("note") or "",
                 "is_root": True},
    }]
    edges = []

    for s in store.list_tree(project_id):
        status = THREAD_STATE_TO_STATUS.get(s.get("status"), "in_progress")
        if s.get("state") == "running":
            status = "running"
        elif s.get("state") == "awaiting_confirm":
            status = "blocked"
        nodes.append({
            "id": s["id"],
            "node_type": "Thread",
            "type_label": node_type_label("Thread"),
            "title": s.get("title") or (s.get("task") or "")[:24] or "未命名线索",
            "description": s.get("task") or "",
            "status": status,
            "confidence": 1.0,
            "data": {
                "step_count": s.get("step_count", 0),
                "target": s.get("target") or "",
                "summary": s.get("summary") or "",
                "state": s.get("state") or "",
                "status_raw": s.get("status") or "",
                "parent": s.get("parent_id") or "",   # 前端据此画「上级线索」面包屑
                "created_at": s.get("created_at"),
            },
        })
        parent = s.get("parent_id") or ""
        edges.append({
            "source_id": parent or f"project:{project_id}",
            "target_id": s["id"],
            "label": "BRANCH",
            "label_text": EDGE_LABEL["BRANCH"],
            "strength": "contingent",
            "description": "",
        })

    return {"nodes": nodes, "edges": edges}


def build_causal_graph(project_id: str) -> dict:
    """读因果图，并把数据库里的节点/边整理成前端契约。"""
    raw_nodes = store.list_causal_nodes(project_id)
    raw_edges = store.list_causal_edges(project_id)
    ids = {n["id"] for n in raw_nodes}

    nodes = []
    for n in raw_nodes:
        nodes.append({
            "id": n["id"],
            "node_type": n["node_type"],
            "type_label": node_type_label(n["node_type"]),
            "title": n.get("title") or n.get("description", "")[:28] or n["id"],
            "description": n.get("description") or "",
            "status": n.get("status") or "PENDING",
            "confidence": float(n.get("confidence") or 0.0),
            "severity": n.get("severity") or "",
            "session_id": n.get("session_id") or "",
            "source_step": n.get("source_step") or "",
            "data": n.get("data") or {},
        })

    # 丢弃端点不存在的边，否则前端会画出悬空连线
    edges = [{
        "source_id": e["source_id"],
        "target_id": e["target_id"],
        "label": e["label"],
        "label_text": EDGE_LABEL.get(e["label"], e["label"]),
        "strength": e.get("strength") or "contingent",
        "description": e.get("description") or "",
    } for e in raw_edges if e["source_id"] in ids and e["target_id"] in ids]

    return {"nodes": nodes, "edges": edges}


# ---------- 图写入 ----------
def apply_updates(project_id: str, payload: dict) -> dict:
    """批量写入节点与边（供 Agent 或人工补充线索）。

    先建点后建边；边端点不存在就丢弃；SUPPORTS/CONTRADICTS 触发目标置信度传播。
    v010 P1-4 修正两点：
      ① 置信度传播**只在边真正新增时发生**——同一条边重复提交不再重复加分
        （旧实现 add_causal_edge 内部去重更新，但传播无条件执行，把同一条
        支撑边喂 N 次就 +0.4×N，节点置信度被人为灌满）；
      ② 单批写入上限（节点/边），防止一次异常调用把图撑爆。
    """
    created_nodes, dropped, skipped_limits = [], 0, 0
    for node in (payload.get("nodes") or [])[:CAUSAL_MAX_NODES_PER_BATCH]:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or "").strip()
        if not node_id:
            continue
        node = dict(node)
        node["id"] = node_id
        node["node_type"] = normalize_node_type(node.get("node_type", ""))
        if node.get("status"):
            node["status"] = str(node["status"]).strip().upper()
        store.upsert_causal_node(project_id, node)
        created_nodes.append(node_id)
    skipped_limits += max(0, len(payload.get("nodes") or []) - CAUSAL_MAX_NODES_PER_BATCH)

    added_edges, propagated = [], []
    edges_in = payload.get("edges") or []
    skipped_limits += max(0, len(edges_in) - CAUSAL_MAX_EDGES_PER_BATCH)
    for edge in edges_in[:CAUSAL_MAX_EDGES_PER_BATCH]:
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("source_id") or "").strip()
        dst = str(edge.get("target_id") or "").strip()
        if not src or not dst:
            continue
        if not store.get_causal_node(project_id, src) or not store.get_causal_node(project_id, dst):
            dropped += 1
            continue
        label = normalize_edge_label(edge.get("label", ""))
        strength = edge.get("strength") if edge.get("strength") in EVIDENCE_STRENGTHS else "contingent"
        rec = store.add_causal_edge(project_id, src, dst, label, strength,
                                    str(edge.get("description") or ""))
        added_edges.append({"source_id": src, "target_id": dst, "label": label})

        # 只有「新边」才传播（幂等）：重复提交同一条 SUPPORTS 边，不再重复加分
        if label in ("SUPPORTS", "CONTRADICTS") and rec.get("created"):
            target = store.get_causal_node(project_id, dst)
            new_conf, new_status = score(target.get("confidence", 0.5), label, strength)
            patch = {"confidence": new_conf}
            if new_status:
                patch["status"] = new_status
            store.upsert_causal_node(project_id, {"id": dst, **patch})
            propagated.append({"node_id": dst, "confidence": round(new_conf, 4),
                               "status": new_status or target.get("status")})

    return {"nodes": created_nodes, "edges": added_edges,
            "dropped_edges": dropped, "skipped_over_limit": skipped_limits,
            "propagated": propagated,
            "graph": build_causal_graph(project_id)}


def reset(project_id: str) -> dict:
    store.clear_causal(project_id)
    return derive(project_id)


# ---------- 从既有数据派生 ----------
def _head(text: str, n: int = 160) -> str:
    t = re.sub(r"\s+", " ", (text or "")).strip()
    return t[:n]


def _evidence_payload(step: dict) -> dict:
    """把一次工具执行整理成 Evidence 节点。derive 与实时溯源共用这一份构造。"""
    sid = step["id"]
    out = (step.get("output") or "").strip()
    return {
        "id": f"step:{sid}",
        "node_type": "Evidence",
        "title": step.get("tool_name") or step.get("tool_alias") or "工具执行",
        "description": _head(out),
        "status": "SUPPORTED",
        "confidence": 0.7,
        "session_id": step.get("session_id") or "",
        "source_step": sid,
        "data": {"tool": step.get("tool_name") or step.get("tool_alias") or "",
                 "target": step.get("target") or "",
                 "output_head": _head(out, 400),
                 "created_at": step.get("created_at")},
    }


def _ensure_evidence(project_id: str, step_id: str) -> bool:
    """按需把某次执行物化成 Evidence 节点（已存在则直接算命中）。

    Agent 用 note_fact 记事实时，Evidence 节点很可能还没被 derive 建出来；
    这里即时补建，保证「执行 →事实」的边当场就能连上，线索图是实时生长的。
    """
    sid = (step_id or "").strip()
    if not sid:
        return False
    if store.get_causal_node(project_id, f"step:{sid}"):
        return True
    step = store.get_step(sid)
    if not step or not (step.get("output") or "").strip():
        return False
    store.upsert_causal_node(project_id, _evidence_payload(step))
    return True


def derive(project_id: str, max_steps: int = 120) -> dict:
    """把项目里已经有的数据整理成因果链，免去从零手工录入。

    规则（只用可确证的信号，不做语义猜测）：
      · 每次工具执行 → Evidence 节点（有输出的成功步骤）
      · 每条已证事实 → KeyFact 节点
      · 每个漏洞发现 → Vulnerability / ConfirmedVulnerability（有证据即视为确认）
      · Evidence --REVEALS--> KeyFact：事实带 step_id 溯源时连线
      · KeyFact --SUPPORTS--> Vulnerability：同一线索内，或事实原文出现在漏洞证据里
    写库前会清空旧图，因此可反复执行。
    """
    store.clear_causal(project_id)

    steps = store.list_project_steps(project_id)
    made = 0
    for st in steps:
        if made >= max_steps:
            break
        out = (st.get("output") or "").strip()
        if not out or st.get("status") not in ("ok", "success", "done"):
            continue
        store.upsert_causal_node(project_id, _evidence_payload(st))
        made += 1

    facts = store.list_facts(project_id)
    for f in facts:
        store.upsert_causal_node(project_id, {
            "id": f"fact:{f['id']}",
            "node_type": "KeyFact",
            "title": _head(f.get("content"), 36),
            "description": f.get("content") or "",
            "status": "SUPPORTED",
            "confidence": 0.8,
            "session_id": f.get("session_id") or "",
            "source_step": f.get("step_id") or "",
            "data": {"source": f.get("source") or "", "created_at": f.get("created_at")},
        })

    findings = store.list_findings(project_id)
    for fd in findings:
        confirmed = bool((fd.get("evidence") or "").strip())
        store.upsert_causal_node(project_id, {
            "id": f"finding:{fd['id']}",
            "node_type": "ConfirmedVulnerability" if confirmed else "Vulnerability",
            "title": fd.get("title") or "未命名漏洞",
            "description": fd.get("detail") or "",
            "status": "CONFIRMED" if confirmed else "PENDING",
            "confidence": 0.95 if confirmed else 0.6,
            "severity": fd.get("severity") or "",
            "session_id": fd.get("session_id") or "",
            "data": {"target": fd.get("target") or "",
                     "evidence": _head(fd.get("evidence"), 400),
                     "created_at": fd.get("created_at")},
        })

    # 边 1：事实的溯源步骤 → 该事实（步骤没产出内容就不连，避免空证据）
    for f in facts:
        step = (f.get("step_id") or "").strip()
        if step and _ensure_evidence(project_id, step):
            store.add_causal_edge(project_id, f"step:{step}", f"fact:{f['id']}",
                                  "REVEALS", "contingent", "该次执行得出此事实")

    # 边 2：事实 → 漏洞
    # 区分两种强度，别把"同线索"说成"支撑"——漏洞证据图里夸大证据是有害的：
    #   · 事实原文出现在漏洞的证据/详情里 → SUPPORTS（真·支撑）
    #   · 仅是同一条线索里登记的       → REVEALS（上下文关联，画成虚线）
    fact_nodes = [n for n in store.list_causal_nodes(project_id)
                  if n["node_type"] == "KeyFact"]
    for fd in findings:
        fid = f"finding:{fd['id']}"
        blob = f"{fd.get('detail') or ''}\n{fd.get('evidence') or ''}"
        linked = 0
        for fn in fact_nodes:
            if linked >= 8:
                break
            quoted = len(fn.get("description") or "") >= 6 and fn["description"] in blob
            same_thread = (bool(fd.get("session_id"))
                           and fn.get("session_id") == fd.get("session_id"))
            if quoted:
                store.add_causal_edge(project_id, fn["id"], fid, "SUPPORTS", "contingent",
                                      "漏洞证据引用了该事实")
                linked += 1
            elif same_thread:
                store.add_causal_edge(project_id, fn["id"], fid, "REVEALS", "contingent",
                                      "同一线索内登记的上下文")
                linked += 1

    return build_causal_graph(project_id)


# ---------- 写入钩子（与 facts / findings 联动） ----------
def on_fact_added(project_id: str, fact: dict) -> None:
    """登记事实时同步生成关键事实节点，让因果图实时长出来。"""
    if not project_id or not fact.get("id"):
        return
    store.upsert_causal_node(project_id, {
        "id": f"fact:{fact['id']}",
        "node_type": "KeyFact",
        "title": _head(fact.get("content"), 36),
        "description": fact.get("content") or "",
        "status": "SUPPORTED",
        "confidence": 0.8,
        "session_id": fact.get("session_id") or "",
        "source_step": fact.get("step_id") or "",
        "data": {"source": fact.get("source") or "manual",
                 "created_at": fact.get("created_at")},
    })
    step = (fact.get("step_id") or "").strip()
    if step and _ensure_evidence(project_id, step):
        store.add_causal_edge(project_id, f"step:{step}", f"fact:{fact['id']}",
                              "REVEALS", "contingent", "该次执行得出此事实")


def on_fact_deleted(project_id: str, fid: str) -> None:
    store.delete_causal_nodes_by_prefix(project_id, f"fact:{fid}")


def on_finding_added(project_id: str, finding: dict) -> None:
    if not project_id or not finding.get("id"):
        return
    confirmed = bool((finding.get("evidence") or "").strip())
    fid = f"finding:{finding['id']}"
    store.upsert_causal_node(project_id, {
        "id": fid,
        "node_type": "ConfirmedVulnerability" if confirmed else "Vulnerability",
        "title": finding.get("title") or "未命名漏洞",
        "description": finding.get("detail") or "",
        "status": "CONFIRMED" if confirmed else "PENDING",
        "confidence": 0.95 if confirmed else 0.6,
        "severity": finding.get("severity") or "",
        "session_id": finding.get("session_id") or "",
        "data": {"target": finding.get("target") or "",
                 "evidence": _head(finding.get("evidence"), 400),
                 "created_at": finding.get("created_at")},
    })
    # 同线索下已有关键事实 → 作为上下文关联（REVEALS 虚线），不冒充"支撑证据"
    session_id = finding.get("session_id") or ""
    if session_id:
        linked = 0
        for fn in store.list_causal_nodes(project_id):
            if fn["node_type"] != "KeyFact" or fn.get("session_id") != session_id:
                continue
            if linked >= 8:
                break
            store.add_causal_edge(project_id, fn["id"], fid, "REVEALS", "contingent",
                                  "同一线索内登记的上下文")
            linked += 1


def on_finding_deleted(project_id: str, fid: str) -> None:
    store.delete_causal_nodes_by_prefix(project_id, f"finding:{fid}")
