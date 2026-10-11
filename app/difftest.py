# -*- coding: utf-8 -*-
"""只读身份差分（v017.3）：同请求 × 不同身份/对象 → 语义分层判定。

红线（v017 计划 5.3/5.5/第 2 节）：
- 只允许 GET/HEAD/OPTIONS——写方法在本模块**根本没有入口**（不是校验拦截，
  是不接受）；
- 每次请求都过 scope.check_scope + ratelimit 限速；
- 判定保守：只把「变体返回了可证明的对象数据且可复现」标为疑似，
  状态码差异/公开数据/不稳定响应都不产生候选；
- 差分结论是**候选建议**（draft），确认必须走人工复核（v012 状态模型）。
"""
from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit, parse_qsl, urlencode

import httpx

from . import config, ratelimit, scope, traffic

READONLY_METHODS = ("GET", "HEAD", "OPTIONS")

# 响应噪声键（语义比较时忽略）
_NOISE_KEYS = {"timestamp", "ts", "nonce", "traceid", "trace_id", "requestid",
               "request_id", "elapsed", "took", "cursor", "next_cursor",
               "request_time", "server_time", "generated_at"}

# 对象归属字段（响应语义层提取）
_OWNER_KEYS = ("userid", "user_id", "uid", "ownerid", "owner_id", "createdby",
               "created_by", "accountid", "account_id", "tenantid", "tenant_id",
               "orderid", "order_id", "memberid", "member_id")


def apply_replacement(rec: dict, field: str, location: str, value: str) -> dict:
    """把请求库记录中的对象字段替换为目标值，返回 {url, body, query}。

    location: query | path | body
    - query：替换指定参数值（参数不存在则追加——模型可能漏报候选）；
    - path：URL 路径中**紧邻语义段之后的数字段**替换；
    - body：JSON 键或表单键替换（JSON 值类型跟随原值：数字键替换为数字）。
    """
    url = rec["url"]
    body = rec.get("body") or ""
    method = rec["method"].upper()

    if location == "query":
        parts = urlsplit(url)
        q = [(k, value if k == field else v) for k, v in
             parse_qsl(parts.query, keep_blank_values=True)]
        if field not in [k for k, _ in q]:
            q.append((field, value))
        url = urlunsplit_min(parts, urlencode(q))
    elif location == "path":
        # 找到 URL 路径里「语义段之后」的数字段，替换之
        parts = urlsplit(url)
        segs = parts.path.split("/")
        for i, seg in enumerate(segs[:-1]):
            nxt = segs[i + 1]
            sl = seg.lower()
            if re.fullmatch(r"\d{3,}", nxt) and field.lower() in sl:
                segs[i + 1] = value
                break
        else:
            # 兜底：替换路径中第一个纯数字段
            for i, seg in enumerate(segs):
                if re.fullmatch(r"\d{3,}", seg):
                    segs[i] = value
                    break
        url = f"{parts.scheme}://{parts.netloc}{'/'.join(segs)}"
    elif location == "body":
        b = body.strip()
        if b.startswith("{"):
            try:
                obj = json.loads(b)
                if isinstance(obj, dict):
                    if field in obj and isinstance(obj[field], int):
                        obj[field] = int(value)
                    else:
                        obj[field] = value
                body = json.dumps(obj, ensure_ascii=False)
            except (ValueError, TypeError):
                pass
        else:
            form = parse_qsl(b, keep_blank_values=True)
            if any(k == field for k, _ in form):
                body = urlencode([(k, value if k == field else v)
                                  for k, v in form])
            else:
                form.append((field, value))
                body = urlencode(form)
    return {"url": url, "body": body, "method": method}


def urlunsplit_min(parts, query: str) -> str:
    return f"{parts.scheme}://{parts.netloc}{parts.path}" + (f"?{query}" if query else "")


async def execute_readonly(url: str, method: str, headers: dict,
                           cookies: dict | None, body: str = "",
                           *, identity_id: str = "", variant_id: str = "",
                           project_id: str = "", session_id: str = "",
                           no_cache: bool = False) -> dict:
    """执行单次只读请求。返回 {status_code, content_type, body_json, body_text}。

    - 方法硬白名单（写方法直接拒绝，不走确认流程——差分根本不需要写）；
    - v023.1 起统一走 TrafficGovernor：scope 兜底 + 滑动窗口预算 + 目标/根域名
      并发限制 + 暂停状态检查（排队请求在暂停后不会发出）+ 流量事件落库；
    - v023.4：同指纹短期复用（no_cache=True 绕过——**复验必须绕过**，
      否则「重复验证」会拿到缓存而不是真实响应）；
    - 响应体截断 64KB；JSON 自动解析供语义比较。
    """
    method = method.upper()
    if method not in READONLY_METHODS:
        return {"error": f"差分只允许只读方法 {'/'.join(READONLY_METHODS)}，拒绝 {method}"}
    fp = traffic.governor.fingerprint(method, url, body=body,
                                      identity_id=identity_id, variant_id=variant_id,
                                      headers=headers)
    # v023.4 短期复用：同指纹（方法+URL+身份+变体）在 TTL 内已有成功观察时，
    # 直接复用不再发请求——多分支测试同一接口时只有一次真实流量。
    # 复验必须传不同的 variant_id（如 "verify"）以绕开复用，保证复验真实发出。
    if not no_cache:
        hit = traffic.governor.cached_observation(fp)
        if hit and isinstance(hit.get("response"), dict) and hit["response"]:
            cached = dict(hit["response"])
            cached["cached"] = True
            cached["fingerprint"] = fp
            return cached
    try:
        permit = await traffic.governor.acquire(
            url, project_id=project_id, session_id=session_id,
            identity_id=identity_id, tool_alias="difftest", method=method,
            fingerprint=fp)
    except traffic.TrafficError as e:
        return {"error": str(e), "traffic_rejected": type(e).__name__}
    try:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                     timeout=20.0) as client:
            r = await client.request(method, url, headers=headers,
                                     cookies=cookies or None,
                                     content=body.encode("utf-8") if body else None)
    except Exception as e:
        await traffic.governor.release(permit, error_type=type(e).__name__,
                                       os_error_code=getattr(e, "errno", 0) or 0)
        return {"error": f"请求失败：{type(e).__name__}: {e}"}
    await traffic.governor.release(permit, status_code=r.status_code,
                                  bytes_in=len(r.content))
    text = r.text[:65536]
    j = None
    ct = (r.headers.get("content-type") or "").lower()
    if "json" in ct or text.strip()[:1] in "{[":
        try:
            j = r.json()
        except (ValueError, TypeError):
            j = None
    result = {"status_code": r.status_code, "content_type": ct,
              "body_json": j, "body_text": text if j is None else "",
              "fingerprint": fp, "cached": False}
    # 只缓存成功响应（错误/拦截不缓存——复验必须能重新观察）
    if 200 <= r.status_code < 400:
        traffic.governor.put_observation(
            fp, r.status_code,
            {k: v for k, v in result.items() if k != "fingerprint"})
    return result


def _strip_noise(obj, depth: int = 0):
    """递归删除噪声键（语义比较用）。"""
    if depth > 6:
        return "…"
    if isinstance(obj, dict):
        return {k: _strip_noise(v, depth + 1) for k, v in obj.items()
                if k.lower() not in _NOISE_KEYS}
    if isinstance(obj, list):
        return [_strip_noise(x, depth + 1) for x in obj[:20]]
    return obj


def _extract_owners(obj, found: list, depth: int = 0):
    """提取响应中的对象归属字段值（语义层证据）。"""
    if depth > 6 or not isinstance(obj, (dict, list)):
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = k.lower()
            if any(p in kl for p in _OWNER_KEYS) and isinstance(v, (str, int)):
                found.append((k, str(v)))
            else:
                _extract_owners(v, found, depth + 1)
    elif isinstance(obj, list):
        for x in obj[:20]:
            _extract_owners(x, found, depth + 1)


def classify(baseline: dict, variant: dict, target_value: str = "") -> dict:
    """分层判定（v017 计划 5.5）。返回 verdict + 证据摘要。

    verdict：
      invalid_baseline —— 基准请求失败（身份失效/URL 错），结果不可信
      access_denied    —— 变体被正常拒绝（非漏洞）
      no_diff          —— 响应无差异（可能公开数据，不产生候选）
      suspect_idor     —— 变体 200 且返回了不同的对象数据（候选，需复核）
      unstable         —— 无法判定（错误/超时/响应异常）
    """
    if baseline.get("error") or variant.get("error"):
        return {"verdict": "unstable",
                "reason": f"请求异常：{baseline.get('error') or variant.get('error')}"}
    b_st, v_st = baseline.get("status_code"), variant.get("status_code")
    if b_st in (401, 403, 407) or (b_st and b_st >= 500):
        return {"verdict": "invalid_baseline",
                "reason": f"基准请求返回 {b_st}（身份可能失效或接口异常），结果不可信"}
    if v_st in (401, 403, 407):
        return {"verdict": "access_denied",
                "reason": f"变体请求被正常拒绝（HTTP {v_st}）——鉴权有效，非漏洞"}
    if v_st and v_st >= 400:
        return {"verdict": "access_denied",
                "reason": f"变体请求返回 {v_st}——未获得目标对象"}
    if v_st != 200:
        return {"verdict": "unstable", "reason": f"变体返回非 200（{v_st}）"}

    bj, vj = baseline.get("body_json"), variant.get("body_json")
    b_clean = _strip_noise(bj) if bj is not None else (baseline.get("body_text") or "")
    v_clean = _strip_noise(vj) if vj is not None else (variant.get("body_text") or "")

    if vj is not None and bj is not None:
        # JSON 语义层。判定顺序刻意保守（防误报）：
        #   ① 归属字段对比（最硬证据）→ ② 基准空/变体有 → ③ 响应一致 →
        #   ④ 目标值出现在归属字段值中（收紧：不能是响应任意位置——公开接口
        #      的响应里天然带着 URL 参数回显，宽松匹配会把公开数据误判成越权）
        v_owners: list = []
        b_owners: list = []
        _extract_owners(vj, v_owners)
        _extract_owners(bj, b_owners)
        v_map = dict(v_owners)
        b_map = dict(b_owners)

        if v_owners and b_owners and v_map != b_map:
            return {"verdict": "suspect_idor",
                    "reason": "变体与基准返回了不同的对象归属数据（跨身份访问证据）",
                    "variant_owners": v_owners[:10]}
        if _looks_empty(b_clean) and not _looks_empty(v_clean):
            return {"verdict": "suspect_idor",
                    "reason": "基准为空/拒绝而变体返回了实际数据",
                    "variant_owners": v_owners[:10]}
        if v_clean == b_clean:
            return {"verdict": "no_diff",
                    "reason": "规范化后响应完全一致（可能为公开数据或空数据）"}
        if target_value and any(v == str(target_value) for v in v_map.values()):
            return {"verdict": "suspect_idor",
                    "reason": f"变体响应的归属字段值为目标对象（{target_value}），"
                              f"而基准身份并非其所有者",
                    "variant_owners": v_owners[:10]}
        return {"verdict": "no_diff",
                "reason": "未检测到语义差异（响应结构或归属字段无变化）"}

    # 非 JSON：文本规范化比较
    def _norm(t: str) -> str:
        return re.sub(r"\s+", " ", t or "").strip()
    if _norm(str(b_clean)) == _norm(str(v_clean)):
        return {"verdict": "no_diff", "reason": "文本响应一致"}
    # 文本不同 + 都 200：需要人工看——标 unstable 而不是直接候选（保守）
    return {"verdict": "unstable",
            "reason": "文本响应存在差异但无法自动判定对象归属，请人工查看响应内容"}


def _norm_text(t: str) -> str:
    return re.sub(r"\s+", " ", t or "").strip()


def _looks_empty(obj) -> bool:
    if obj is None:
        return True
    if isinstance(obj, dict):
        return not obj or all(_looks_empty(v) for v in obj.values())
    if isinstance(obj, list):
        return len(obj) == 0
    if isinstance(obj, str):
        return not obj.strip()
    return False
