# -*- coding: utf-8 -*-
"""流程绕过检测（v017.5）：有序流程链的「跳步」与「匿名」受控验证。

场景（v017 计划 5.8）：注册/登录/找回等业务流程中，「跳过前置步骤直接
请求后续端点」是否成功。例：未完成短信验证码步骤，直接调提交接口。

红线（与 difftest 一致，不另造框架）：
- 复用 difftest.execute_readonly——方法硬白名单（GET/HEAD/OPTIONS）、
  scope 校验、限速全部继承。**写类流程步骤不在本模块自动化范围**：
  计划明确首期只支持测试环境或低风险验证，写步骤需人工在 Burp 验证；
- 判定保守：只有「跳步后末步仍返回实际数据且与基准不同/等价可用」才给
  suspect_flow_bypass 候选建议；全部结果需人工复核。
"""
from __future__ import annotations

from . import difftest


async def run_flow_check(requests: list[dict], identity_headers: dict,
                         identity_cookies: dict) -> dict:
    """执行流程检查。

    requests：按流程顺序排列的请求库记录列表（最后一条是「目标步骤」）。
    三种执行模式：
      baseline  —— 按序全部执行（验证前置链路本身可达）；
      skip      —— **只执行最后一步**（跳过全部前置）；
      anonymous —— 无凭据只执行最后一步（未授权双检）。

    verdict：
      flow_invalid     —— 基准链路都不通（身份失效/接口异常），结果不可信
      flow_protected   —— 跳步/匿名均被拒绝（流程保护有效）
      suspect_flow_bypass —— 跳步后末步仍成功返回数据（候选，需人工复核）
      suspect_unauthorized —— 跳步被拒但匿名直访成功（未授权线索，独立验证）
      unstable         —— 无法判定
    """
    if not requests:
        return {"verdict": "unstable", "reason": "流程为空", "steps": []}
    last = requests[-1]
    steps: list[dict] = []

    async def _exec(tag: str, rec: dict, headers: dict, cookies: dict) -> dict:
        ev = await difftest.execute_readonly(rec["url"], rec.get("method", "GET"),
                                             headers, cookies, rec.get("body") or "")
        steps.append({"tag": tag, "url": rec["url"],
                      "status": ev.get("status_code"), "error": ev.get("error")})
        return ev

    # ---- baseline：按序全链路 ----
    baseline_last = None
    for i, rec in enumerate(requests):
        tag = f"baseline#{i+1}"
        ev = await _exec(tag, rec, identity_headers, identity_cookies)
        baseline_last = ev
        if ev.get("error") or (ev.get("status_code") or 500) >= 400:
            # 前置就断了——后续执行没有意义，直接判不可信
            return {"verdict": "flow_invalid",
                    "reason": f"基准链路第 {i+1} 步失败"
                              f"（{ev.get('status_code') or ev.get('error')}），"
                              f"流程检查结果不可信——请先确认身份与流程本身可达",
                    "steps": steps}
    if baseline_last is None or (baseline_last.get("status_code") != 200):
        return {"verdict": "unstable", "reason": "基准末步非 200，无法建立判定基线",
                "steps": steps}

    # ---- skip：只执行末步（带身份）----
    # 跳步语义：重放末步时**剥离查询参数与请求体**——前置产物（验证码、
    # 一次性 token、流程 code）通常经 query/body 传递，跳过前置就该没有它们。
    # 若前置产物在路径中，请改用差分功能手动替换路径段。
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(last["url"])
    skip_rec = dict(last, url=urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")),
                    body="")
    skip_last = await _exec("skip-last", skip_rec, identity_headers, identity_cookies)

    # ---- anonymous：无凭据末步 ----
    anon_last = await _exec("anonymous-last", last, {}, {})

    # ---- 判定 ----
    def _sig(e: dict):
        return difftest._strip_noise(e.get("body_json")) if e.get("body_json") is not None \
            else difftest._norm_text(e.get("body_text") or "")

    skip_denied = skip_last.get("status_code") in (401, 403, 407) or \
        (skip_last.get("status_code") or 0) >= 400
    anon_denied = anon_last.get("status_code") in (401, 403, 407) or \
        (anon_last.get("status_code") or 0) >= 400

    if skip_denied and anon_denied:
        return {"verdict": "flow_protected",
                "reason": "跳步与匿名均被拒绝——流程保护有效",
                "steps": steps}
    if not anon_denied:
        # 匿名（无凭据）直访成功是最强信号——连登录都不要，未授权包含越权语义
        owners: list = []
        if anon_last.get("body_json") is not None:
            difftest._extract_owners(anon_last["body_json"], owners)
        return {"verdict": "suspect_unauthorized",
                "reason": "匿名（无凭据）直接访问末步成功——接口可能本不需要登录"
                          "（未授权访问，独立验证；注意与跳步绕过区分）",
                "owners": owners[:10], "steps": steps}
    if not skip_denied and _sig(skip_last) == _sig(baseline_last):
        # 跳过全部前置，末步响应与按序执行一致 → 前置步骤可被绕过
        owners: list = []
        if skip_last.get("body_json") is not None:
            difftest._extract_owners(skip_last["body_json"], owners)
        return {"verdict": "suspect_flow_bypass",
                "reason": f"跳过前 {len(requests)-1} 个前置步骤后，末步仍返回与按序执行"
                          f"一致的数据——前置步骤可被绕过",
                "owners": owners[:10], "steps": steps}
    if not skip_denied:
        return {"verdict": "suspect_flow_bypass",
                "reason": "跳过前置步骤后末步返回 200（响应与基准有差异，请人工核对内容）",
                "steps": steps}
    return {"verdict": "unstable",
            "reason": f"末步返回异常状态（skip={skip_last.get('status_code')}，"
                      f"anon={anon_last.get('status_code')}），无法判定",
            "steps": steps}
