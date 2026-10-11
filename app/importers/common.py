# -*- coding: utf-8 -*-
"""请求导入公共层（v017.1）：统一请求模型、脱敏、去噪、去重与 scope 过滤。

设计要点（对齐 v017 计划第 2/5.2 节）：
- 敏感头入库前替换为 ``<redacted:NAME:len>`` 占位——完整凭据永不入 SQLite、
  永不进 LLM 上下文与报告；
- 规范化 URL 只保留「方法可见的结构」：查询值占位、路径纯数字段归一，
  作为去重与筛选依据，原始 URL 原样保留；
- scope 判定复用 app/scope.py 的白名单（host 级 + 端口/协议细粒度），
  越界请求只标记 rejected，不进入执行队列。
"""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlsplit, parse_qsl, urlencode

from .. import scope

# 需要脱敏的请求头（大小写不敏感，值为前缀匹配）
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
    "x-session-token", "x-access-token",
}

# 对象标识符候选的语义字段名（键名小写子串匹配）
_OBJECT_KEY_PATTERNS = (
    "userid", "user_id", "uid", "ownerid", "owner_id", "createdby",
    "created_by", "orderid", "order_id", "fileid", "file_id", "tenantid",
    "tenant_id", "orgid", "org_id", "accountid", "account_id", "memberid",
    "member_id", "docid", "doc_id", "recordid", "record_id", "msg_id",
    "messageid", "message_id", "studentid", "student_id", "classid",
    "class_id", "companyid", "company_id",
)
# 噪声字段（对象识别时跳过）
_NOISE_KEYS = ("timestamp", "nonce", "traceid", "trace_id", "_t", "page",
               "pagesize", "page_size", "limit", "offset", "cursor", "callback")

MASK = "<redacted:{name}:{len}>"


def redact_headers(headers: dict) -> dict:
    """按名单脱敏请求头；值为字典/列表时仅处理常见扁平结构。"""
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in SENSITIVE_HEADERS:
            s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
            out[k] = MASK.format(name=k, len=len(s))
        else:
            out[k] = v
    return out


def split_cookies(header_value: str) -> dict:
    """把 Cookie 头拆成 {name: masked_value}（值脱敏，保留键名供身份绑定）。"""
    out = {}
    for part in (header_value or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            if k:
                out[k] = MASK.format(name="cookie:" + k, len=len(v.strip()))
    return out


def normalize_url(url: str) -> str:
    """规范化 URL：查询值 → 占位、路径纯数字/UUID 段 → {n}/{u}。

    用途仅限去重与筛选；原始 URL 原样保留在 url 字段。
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    path = parts.path
    segs = []
    for seg in path.split("/"):
        if re.fullmatch(r"\d+", seg):
            segs.append("{n}")
        elif re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", seg):
            segs.append("{u}")
        else:
            segs.append(seg)
    norm_path = "/".join(segs)
    q = [(k, "{v}") for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit_min(parts.scheme, parts.netloc, norm_path, q)


def urlunsplit_min(scheme: str, netloc: str, path: str, q: list) -> str:
    s = f"{scheme}://{netloc}{path}" if scheme else path
    if q:
        s += "?" + urlencode(q)
    return s


def dedup_key(method: str, url: str, body: str = "") -> str:
    """去重键：方法 + 规范化 URL + 查询参数名集合 + body 结构键。"""
    parts = urlsplit(url)
    qnames = sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True))
    body_key = ""
    if body:
        b = body.strip()
        ct_json = b.startswith("{") or b.startswith("[")
        if ct_json:
            try:
                obj = json.loads(b)
                body_key = "j:" + _shape(obj)
            except (ValueError, TypeError):
                body_key = "raw:" + b[:120]
        else:
            # 表单：保留键名
            try:
                form = parse_qsl(b, keep_blank_values=True)
                body_key = "f:" + ",".join(sorted(k for k, _ in form)) if form else "raw:" + b[:120]
            except Exception:
                body_key = "raw:" + b[:120]
    return "|".join([method.upper(), normalize_url(url), ",".join(qnames), body_key])


def _shape(obj, depth: int = 0) -> str:
    """JSON 结构指纹：只看键集合与类型，不看值。"""
    if depth > 4:
        return "…"
    if isinstance(obj, dict):
        return "{" + ",".join(sorted(f"{k}:{_shape(v, depth+1)}" for k, v in obj.items())) + "}"
    if isinstance(obj, list):
        return "[" + (_shape(obj[0], depth+1) if obj else "") + "]"
    return type(obj).__name__


def object_candidates(url: str, query: dict, body: str) -> list[dict]:
    """提取对象标识符候选（v017 计划 5.4：命名优先，只报候选不做替换）。

    confidence: high=语义键名 / medium=URL 中名为 id 的段与纯数字 query 值。
    """
    out: list[dict] = []
    seen: set = set()

    def add(field: str, location: str, value: str, confidence: str, src: str):
        key = (field, location, value)
        if key in seen:
            return
        seen.add(key)
        # 值脱敏：长度 ≤4 的短值原样（打码无意义），更长的保留首尾各 2 字符
        v = str(value)
        masked = v if len(v) <= 4 else (v[:2] + "***" + v[-2:])
        out.append({"field": field, "location": location, "value_masked": masked,
                    "source": src, "confidence": confidence})

    # 1. query 命名字段
    for k, v in (query or {}).items():
        kl = k.lower()
        if kl in _NOISE_KEYS:
            continue
        if any(p in kl for p in _OBJECT_KEY_PATTERNS):
            add(k, "query", v, "high", "named_query_param")
        elif re.fullmatch(r"\d{3,}", v or ""):
            add(k, "query", v, "medium", "numeric_query_param")

    # 2. 路径段：/order/123、/user/456/ 中的语义前缀 + 纯数字段。
    #    匹配双向子串：段名 "order" 是模式 "orderid" 的前缀形态也算命中
    try:
        segs = urlsplit(url).path.split("/")
    except ValueError:
        segs = []
    for i, seg in enumerate(segs[:-1]):
        nxt = segs[i + 1] if i + 1 < len(segs) else ""
        sl = seg.lower()
        if re.fullmatch(r"\d{3,}", nxt) and len(sl) >= 4 and \
                any(p in sl or sl in p for p in _OBJECT_KEY_PATTERNS):
            add(seg, "path", nxt, "high", "named_path_segment")

    # 3. body：JSON 扁平键 + 表单键
    b = (body or "").strip()
    if b.startswith("{"):
        try:
            obj = json.loads(b)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    kl = k.lower()
                    if kl in _NOISE_KEYS:
                        continue
                    if any(p in kl for p in _OBJECT_KEY_PATTERNS):
                        add(k, "body", str(v)[:64], "high", "named_body_field")
        except (ValueError, TypeError):
            pass
    else:
        try:
            form = parse_qsl(b, keep_blank_values=True)
            for k, v in form:
                kl = k.lower()
                if kl in _NOISE_KEYS:
                    continue
                if any(p in kl for p in _OBJECT_KEY_PATTERNS):
                    add(k, "body", v[:64], "high", "named_body_field")
        except Exception:
            pass
    return out


def parse_raw_http(raw: bytes) -> dict | None:
    """解析原始 HTTP 请求报文（Burp XML 的 base64 request 块）。

    返回 {method, url, headers, cookies, query, body, content_type}；
    无法解析返回 None。目标 URL 由 Host 头 + 请求行路径合成。
    """
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return None
    if "\r\n" not in text and "\n" not in text:
        return None
    lines = re.split(r"\r\n|\n", text)
    first = lines[0].strip()
    m = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP/", first)
    if not m:
        return None
    method, target = m.group(1), m.group(2)
    headers: dict = {}
    body = ""
    in_body = False
    body_lines: list[str] = []
    for ln in lines[1:]:
        if in_body:
            body_lines.append(ln)
            continue
        if not ln.strip():
            in_body = True
            continue
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    if body_lines:
        body = "\n".join(body_lines).strip()
    host = headers.get("Host") or headers.get("host") or ""
    scheme = "https"  # Burp 里通常配了代理；用端口推断
    if host.endswith(":80"):
        scheme = "http"
        host = host[:-3]
    url = f"{scheme}://{host}{target}" if host else target
    cookies = {}
    if headers.get("Cookie"):
        cookies = split_cookies(headers["Cookie"])
    q = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)) if "?" in url else {}
    return {
        "method": method.upper(),
        "url": url,
        "headers": headers,
        "cookies": cookies,
        "query": q,
        "body": body[:4096],
        "content_type": headers.get("Content-Type") or headers.get("content-type") or "",
    }


def build_record(source: str, parsed: dict, status_code=None) -> dict:
    """把解析出的请求加工成入库记录：脱敏 + scope 判定 + 去重键 + 对象候选。"""
    url = parsed.get("url", "")
    headers = redact_headers(parsed.get("headers", {}))
    # Cookie 头单独拆出后，headers 里的 Cookie 已脱敏保留（供身份绑定提示）
    body = parsed.get("body", "")
    host = urlsplit(url).netloc.split(":")[0] if "://" in url else ""
    if host:
        denied = scope.check_scope(url)
        scope_status = "allowed" if denied is None else "rejected"
    else:
        scope_status = "rejected"
    return {
        "source": source,
        "method": parsed.get("method", "GET"),
        "url": url,
        "normalized_url": normalize_url(url),
        "headers": headers,
        "cookies": parsed.get("cookies", {}),
        "query": parsed.get("query", {}),
        "body": body,
        "content_type": parsed.get("content_type", ""),
        "status_code": status_code,
        "tags": [],
        "scope_status": scope_status,
        "dedup_key": dedup_key(parsed.get("method", "GET"), url, body),
        "object_candidates": object_candidates(
            url, parsed.get("query", {}), body),
    }


def parse_import_file(filename: str, content_b64: str) -> tuple[list[dict], dict]:
    """统一入口：按文件名/内容识别 Burp XML 或 HAR，返回 (记录列表, 统计)。

    统计含 total/allowed/rejected/duplicates（同一批内的去重键重复，
    重复记录仍返回但打 tags:["duplicate"]，由 commit 决定是否入库）。
    """
    try:
        raw = base64.b64decode(content_b64, validate=False)
    except Exception as e:
        raise ValueError(f"内容不是合法的 base64：{e}")
    name = (filename or "").lower()
    text = raw.decode("utf-8", errors="replace")
    if name.endswith(".har") or text.lstrip().startswith("{"):
        from . import har as har_mod
        parsed_items = har_mod.parse(text)
    elif name.endswith(".xml") or text.lstrip().startswith("<"):
        from . import burp_xml as burp_mod
        parsed_items = burp_mod.parse(text)
    else:
        raise ValueError("无法识别的文件类型：请上传 Burp XML（.xml）或 HAR（.har）")

    records: list[dict] = []
    seen_keys: set = set()
    stat = {"total": 0, "allowed": 0, "rejected": 0, "duplicates": 0, "parse_errors": 0}
    for item, status_code in parsed_items:
        stat["total"] += 1
        try:
            rec = build_record(source="har" if name.endswith(".har") or
                               text.lstrip().startswith("{") else "burp_xml",
                               parsed=item, status_code=status_code)
        except Exception:
            stat["parse_errors"] += 1
            continue
        k = rec["dedup_key"]
        if k in seen_keys:
            rec["tags"] = rec.get("tags", []) + ["duplicate"]
            stat["duplicates"] += 1
        seen_keys.add(k)
        stat["allowed" if rec["scope_status"] == "allowed" else "rejected"] += 1
        records.append(rec)
    return records, stat
