# -*- coding: utf-8 -*-
"""模型层：统一接入任意 LLM 供应商（OpenAI 兼容 / Anthropic 原生 / 本地 Ollama）。

供应商配置由 app/providers.py 管理（%USERPROFILE%\\.src_agent_llm.json），
本模块只负责「拿到一份供应商配置 → 发请求 → 归一化成 {tool_calls, content}」。

实测结论：
  qwen3.5:9b 在关闭思考模式时会退化成纯文本输出、不再产生 tool_calls。
  因此本地 Ollama 供应商的 thinking 必须保持 True，不要为了省时间关掉它。
"""
from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlparse

import httpx

from . import config, providers, redact


def _egress_prepare(self_label: str, local: bool, messages: list[dict]) -> list[dict]:
    """云端外发闸门（v010 P0-4）：按 config.CLOUD_EGRESS_MODE 处理待发送消息。

    - local_only：选中云端供应商时不允许发请求——直接抛错，调用方（Agent）
      会把错误呈现给用户并提示切换到本地模型；
    - redact：返回脱敏后的**副本**（session.messages 原文不受影响），命中摘要写日志；
    - allow：原样放行。
    本地供应商（local=True）数据不出本机，不经过本函数。
    """
    if local:
        return messages
    mode = redact.egress_mode()
    if mode == redact.MODE_ALLOW:
        return messages
    if mode == redact.MODE_LOCAL_ONLY:
        raise RuntimeError(
            "当前外发策略为 local_only（AGENT_CLOUD_EGRESS=local_only），"
            f"供应商「{self_label}」是云端端点，已拒绝发送。"
            "请在前端切换到本地模型，或调整 AGENT_CLOUD_EGRESS。")
    msgs, hits = redact.egress_messages(messages)
    if hits:
        logging.getLogger("src_agent").info(
            "云端外发脱敏（%s）：本请求命中并打码 %d 处疑似凭据/隐私内容", self_label, hits)
    return msgs


class LLMBackend(ABC):
    name: str = "base"

    @abstractmethod
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """返回归一化结果：{"tool_calls": [...], "content": "..."}"""
        ...

    def available(self) -> bool:
        return True


# ---------- URL 归一化 ----------
# 路径里已出现的版本段（/v1、/v4、/v2、/api/v3、/v1beta ...）
_VERSION_SEG_RE = re.compile(r"(?:^|/)v\d+[a-z0-9.\-]*(?:/|$)", re.I)


def _ensure_v1(url: str) -> str:
    """OpenAI 兼容端点补 /v1 —— 只对「路径里还没有版本段」的端点补。

    用户常粘贴 https://api.deepseek.com 或 http://localhost:11434，需要补 /v1；
    但不少厂商的 Base URL 自带版本段、而且**不是 v1**：

        zhipu       https://open.bigmodel.cn/api/paas/v4
        baidu       https://qianfan.baidubce.com/v2
        volcengine  https://ark.cn-beijing.volces.com/api/v3
        gemini      https://generativelanguage.googleapis.com/v1beta/openai

    旧实现只判断 endswith("/v1")，会把上面这些拼成 .../v4/v1/chat/completions
    这类不存在的路径（404）。改为「路径已含版本段就不再追加」。
    """
    u = (url or "").strip().rstrip("/")
    if not u:
        return u
    if _VERSION_SEG_RE.search(urlparse(u).path or ""):
        return u
    return u + "/v1"


def _strip_v1(url: str) -> str:
    """Anthropic 端点去掉结尾 /v1（AnthropicBackend 自己会拼 /v1/messages）。"""
    u = (url or "").strip().rstrip("/")
    return u[:-3] if u.endswith("/v1") else u


class OpenAICompatBackend(LLMBackend):
    """通用 OpenAI 兼容后端。

    覆盖：OpenAI / DeepSeek / 通义千问 / GLM / Kimi / 火山方舟 / 硅基流动 /
    混元 / 文心 / Groq / OpenRouter / Grok / Gemini(兼容层) / Mistral /
    本地 Ollama / LM Studio / vLLM / Xinference 等一切 /chat/completions 端点。
    """

    def __init__(self, cfg: dict) -> None:
        self.id: str = cfg.get("id", "custom")
        self.name: str = self.id
        self.label: str = cfg.get("name", self.id)
        self.base_url: str = _ensure_v1(cfg.get("base_url", ""))
        self.api_key: str = cfg.get("api_key", "")
        self.model: str = cfg.get("model", "")
        self.thinking: bool = bool(cfg.get("thinking"))
        self.local: bool = bool(cfg.get("local"))
        self.timeout: float = float(cfg.get("timeout") or 300)

    # ---------- 基础能力 ----------
    def available(self) -> bool:
        return bool(self.base_url and self.model) and (self.local or bool(self.api_key))

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _endpoint(self) -> str:
        return self.base_url + "/chat/completions"

    # ---------- 聊天 ----------
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        if not self.base_url or not self.model:
            raise RuntimeError(f"供应商「{self.label}」未配置 Base URL 或模型名")
        if not self.local and not self.api_key:
            raise RuntimeError(f"供应商「{self.label}」未配置 API Key，请在「设置 → 模型供应商」中填写")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": _egress_prepare(self.label, self.local, messages),
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        # 本地小模型：关掉 thinking 会退化成纯文本、不再调工具（实测结论）
        if self.thinking:
            payload["thinking"] = True

        async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
            resp = await client.post(self._endpoint(), json=payload, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()

        msg = _first_message(data)
        content = msg.get("content") or ""
        # 部分推理模型（DeepSeek-R1、QwQ 等）把思考过程放在 reasoning_content
        reasoning = msg.get("reasoning_content") or ""
        if not content and reasoning:
            content = reasoning
        # token 用量（用量统计用）：OpenAI 兼容 usage.prompt_tokens / completion_tokens
        usage = data.get("usage") or {}
        return {
            "tool_calls": _normalize_tool_calls(msg.get("tool_calls")),
            "content": content,
            "backend": self.name,
            "usage": {
                "prompt": int(usage.get("prompt_tokens") or 0),
                "completion": int(usage.get("completion_tokens") or 0),
            },
        }

    # ---------- 健康检查 / 模型列表 ----------
    async def health(self) -> dict:
        base = {"model": self.model, "backend": self.name}
        if not self.available():
            return {**base, "ok": False, "ready": False,
                    "reason": "未配置 API Key" if not self.local else "未配置模型"}
        try:
            models = await self.list_models()
            return {**base, "ok": True, "models": models, "ready": self.model in models}
        except Exception as e:
            # 模型列表接口不通不代表聊天不通（部分网关禁用 /models），退化为仅看配置
            return {**base, "ok": True, "models": [], "ready": True,
                    "reason": f"模型列表不可用（{e}）"}

    async def list_models(self) -> list[str]:
        """GET /models，返回模型 id 列表。"""
        if not self.base_url:
            return []
        url = self.base_url + "/models"
        async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
            r = await client.get(url, headers=self._headers())
            r.raise_for_status()
            data = r.json()
        out = []
        for m in data.get("data") or []:
            mid = m.get("id") if isinstance(m, dict) else str(m)
            if mid:
                out.append(mid)
        return sorted(out)

    async def probe(self) -> dict:
        """连通性 + 工具调用能力探测（供控制台「测试连接」用）。

        两步：先发一条极短对话验证链路，再带一个工具验证 function calling。
        """
        result: dict[str, Any] = {"chat": False, "tools": False, "models": [],
                                  "error": "", "hint": ""}
        try:
            r = await self.chat([{"role": "user", "content": "ping，回复 ok"}])
            result["chat"] = True
            result["reply"] = (r.get("content") or "")[:200]
        except Exception as e:
            result["error"] = _friendly_error(e)
            return result

        probe_tool = [{
            "type": "function",
            "function": {
                "name": "echo_ping",
                "description": "回显传入的文本",
                "parameters": {"type": "object", "properties": {"text": {"type": "string"}},
                               "required": ["text"]},
            },
        }]
        try:
            r2 = await self.chat([{"role": "user", "content": "请调用 echo_ping，参数 text=ok"}],
                                 tools=probe_tool)
            result["tools"] = bool(r2.get("tool_calls"))
        except Exception as e:
            result["hint"] = f"工具调用探测失败：{_friendly_error(e)}"
        if not result["tools"] and not result["hint"]:
            result["hint"] = "该模型未返回工具调用。若任务无法调度工具，请换用支持 function calling 的模型（如 deepseek-chat、gpt-4o、qwen-plus、glm-4.6）。"
        try:
            result["models"] = (await self.list_models())[:200]
        except Exception:
            pass
        return result


class OllamaBackend(OpenAICompatBackend):
    """本地 Ollama：本质是 OpenAI 兼容端点，额外走 /api/tags 探测模型。"""

    def __init__(self, cfg: dict | None = None) -> None:
        cfg = dict(cfg or {})
        cfg.setdefault("id", "ollama")
        cfg.setdefault("name", "本地 Ollama")
        cfg.setdefault("base_url", config.OLLAMA_BASE_URL)
        cfg.setdefault("model", config.OLLAMA_MODEL)
        cfg.setdefault("thinking", config.OLLAMA_THINKING)
        cfg.setdefault("local", True)
        super().__init__(cfg)

    async def list_models(self) -> list[str]:
        # Ollama 的 /v1 兼容层没有 /models 的完整能力，走原生 /api/tags 更准
        root = self.base_url[:-3] if self.base_url.endswith("/v1") else self.base_url
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            r = await client.get(root + "/api/tags")
            r.raise_for_status()
            data = r.json()
        return sorted(m.get("name", "") for m in data.get("models", []) if m.get("name"))


class AnthropicBackend(LLMBackend):
    """Anthropic 原生 /v1/messages 协议（Claude 官方及各类 Anthropic 兼容网关）。

    把本项目 OpenAI 形态的 messages / tool_calls 与 Anthropic 的 blocks 结构互转。
    """

    _ANTHROPIC_VERSION = "2023-06-01"

    def __init__(self, cfg: dict) -> None:
        self.id: str = cfg.get("id", "anthropic")
        self.name: str = self.id
        self.label: str = cfg.get("name", "Anthropic 兼容端点")
        self.base_url: str = _strip_v1(cfg.get("base_url", ""))
        self.api_key: str = cfg.get("api_key", "")
        self.model: str = cfg.get("model", "")
        self.local: bool = bool(cfg.get("local"))
        self.timeout: float = float(cfg.get("timeout") or 300)

    def available(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": self._ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }

    # ---------- 消息结构互转 ----------
    @staticmethod
    def _to_anthropic_messages(messages: list[dict]) -> tuple[str | None, list[dict]]:
        """OpenAI 形态 → Anthropic 形态。返回 (system, msgs)。

        - role=system 汇总为 system 参数
        - assistant 的 tool_calls → content blocks 中的 tool_use
        - role=tool（含 tool_call_id）→ 收拢到紧随的 user 消息 tool_result 块
        """
        system_parts: list[str] = []
        out: list[dict] = []
        tool_results: list[dict] = []

        def flush_results() -> None:
            if tool_results:
                out.append({"role": "user", "content": tool_results.copy()})
                tool_results.clear()

        for m in messages:
            role = m.get("role")
            content = m.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(content)
                continue
            if role == "tool":
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": m.get("tool_call_id", ""),
                    "content": str(content)[:12000],
                })
                continue
            if role == "assistant":
                flush_results()
                blocks: list[dict] = []
                if content:
                    blocks.append({"type": "text", "text": content})
                for tc in m.get("tool_calls") or []:
                    fn = tc.get("function", {})
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except Exception:
                        args = {"raw": fn.get("arguments", "")}
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.get("id", ""),
                        "name": fn.get("name", ""),
                        "input": args if isinstance(args, dict) else {"value": str(args)},
                    })
                if blocks:
                    out.append({"role": "assistant", "content": blocks})
                else:
                    out.append({"role": "assistant", "content": content or ""})
                continue
            flush_results()
            if content:
                out.append({"role": "user", "content": content})
        flush_results()
        system = "\n\n".join(system_parts) if system_parts else None
        return system, out

    @staticmethod
    def _to_anthropic_tools(tools: list[dict]) -> list[dict]:
        """OpenAI function schema → Anthropic tools（去掉 function/type 包裹）。"""
        result = []
        for t in tools:
            fn = t.get("function", t)
            result.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            })
        return result

    # ---------- chat / health ----------
    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        if not self.available():
            raise RuntimeError(
                f"供应商「{self.label}」未配置完整（Base URL / API Key / 模型名），"
                "请在「设置 → 模型供应商」中补齐"
            )

        system, msgs = self._to_anthropic_messages(
            _egress_prepare(self.label, self.local, messages))
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": msgs,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = self._to_anthropic_tools(tools)
            payload["tool_choice"] = {"type": "auto"}

        url = self.base_url.rstrip("/") + "/v1/messages"
        async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
            resp = await client.post(url, json=payload, headers=self._headers())
            resp.raise_for_status()
            data = resp.json()

        text_parts: list[str] = []
        tool_calls: list[dict] = []
        for blk in data.get("content", []):
            if blk.get("type") == "text":
                text_parts.append(blk.get("text", ""))
            elif blk.get("type") == "tool_use":
                tool_calls.append({
                    "id": blk.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": blk.get("name", ""),
                        "arguments": json.dumps(blk.get("input", {}), ensure_ascii=False),
                    },
                })
        # token 用量（用量统计用）：Anthropic usage.input_tokens / output_tokens
        u = data.get("usage") or {}
        return {
            "tool_calls": tool_calls,
            "content": "\n".join(text_parts),
            "backend": self.name,
            "usage": {
                "prompt": int(u.get("input_tokens") or 0),
                "completion": int(u.get("output_tokens") or 0),
            },
        }

    async def health(self) -> dict:
        base = {"model": self.model, "backend": self.name}
        if not self.available():
            return {**base, "ok": False, "ready": False,
                    "reason": "未配置 Base URL / API Key / 模型（Anthropic 兼容端点）"}
        try:
            url = self.base_url.rstrip("/") + "/v1/models"
            async with httpx.AsyncClient(timeout=8.0, trust_env=False) as client:
                r = await client.get(url, headers=self._headers())
                r.raise_for_status()
                data = r.json()
            models = [m.get("id") or m.get("name") for m in (data.get("data") or []) if isinstance(m, dict)]
            return {**base, "ok": True, "models": models, "ready": True,
                    "reason": None if self.model in models else "模型名不在端点列表中（可能是别名，可忽略）"}
        except Exception as e:
            return {**base, "ok": True, "ready": True,
                    "reason": f"端点探测失败（{_friendly_error(e)}）"}

    async def list_models(self) -> list[str]:
        url = self.base_url.rstrip("/") + "/v1/models"
        async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
            r = await client.get(url, headers=self._headers())
            r.raise_for_status()
            data = r.json()
        return sorted((m.get("id") or m.get("name") or "")
                      for m in (data.get("data") or []) if isinstance(m, dict) and (m.get("id") or m.get("name")))

    async def probe(self) -> dict:
        result: dict[str, Any] = {"chat": False, "tools": False, "models": [],
                                  "error": "", "hint": ""}
        try:
            r = await self.chat([{"role": "user", "content": "ping，回复 ok"}])
            result["chat"] = True
            result["reply"] = (r.get("content") or "")[:200]
        except Exception as e:
            result["error"] = _friendly_error(e)
            return result

        probe_tool = [{
            "type": "function",
            "function": {
                "name": "echo_ping",
                "description": "回显传入的文本",
                "parameters": {"type": "object", "properties": {"text": {"type": "string"}},
                               "required": ["text"]},
            },
        }]
        try:
            r2 = await self.chat([{"role": "user", "content": "请调用 echo_ping，参数 text=ok"}],
                                 tools=probe_tool)
            result["tools"] = bool(r2.get("tool_calls"))
        except Exception as e:
            result["hint"] = f"工具调用探测失败：{_friendly_error(e)}"
        try:
            result["models"] = (await self.list_models())[:200]
        except Exception:
            pass
        return result


# ---------- 归一化辅助 ----------
def _first_message(data: dict) -> dict:
    """兼容各家返回结构：标准 choices[0].message，或个别网关的扁平结构。"""
    choices = data.get("choices") or []
    if choices:
        return choices[0].get("message") or {}
    if isinstance(data.get("message"), dict):
        return data["message"]
    return {}


def _normalize_tool_calls(raw: Any) -> list[dict]:
    """统一 tool_calls 结构：补全 id / type / function.arguments 为 JSON 字符串。"""
    out: list[dict] = []
    if not raw:
        return out
    if isinstance(raw, dict):
        raw = [raw]
    for i, tc in enumerate(raw):
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        if not fn and tc.get("name"):
            fn = {"name": tc.get("name"), "arguments": tc.get("arguments") or tc.get("input")}
        args = fn.get("arguments")
        if isinstance(args, (dict, list)):
            args = json.dumps(args, ensure_ascii=False)
        out.append({
            "id": tc.get("id") or f"call_{i}_{abs(hash(str(fn.get('name')))) % 100000}",
            "type": "function",
            "function": {
                "name": fn.get("name", ""),
                "arguments": args if isinstance(args, str) else "",
            },
        })
    return out


def _friendly_error(e: Exception) -> str:
    """把 httpx 异常转成能看懂的中文提示。"""
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        body = ""
        try:
            body = (e.response.text or "")[:300]
        except Exception:
            pass
        tips = {
            401: "API Key 无效或缺失（401）",
            403: "Key 无权限访问该模型（403）",
            404: "端点或模型不存在（404）——检查 Base URL 是否带 /v1、模型名是否正确",
            429: "触发限流或余额不足（429）",
            500: "服务端异常（500）",
        }
        return f"{tips.get(code, f'HTTP {code}')} {body}".strip()
    if isinstance(e, httpx.ConnectError):
        return f"无法连接端点（{e}）——检查网络、代理或 Base URL"
    if isinstance(e, httpx.TimeoutException):
        return "请求超时——本地模型首次加载较慢，可适当调大超时"
    return str(e)


# ---------- 后端工厂 ----------
_backends: dict[str, LLMBackend] = {}
_backend_sig: dict[str, str] = {}


def _signature(p: dict) -> str:
    return "|".join(str(p.get(k, "")) for k in
                    ("id", "type", "base_url", "api_key", "model", "thinking", "timeout"))


def build_backend(p: dict) -> LLMBackend:
    ptype = (p.get("type") or "openai").lower()
    if ptype == "anthropic":
        return AnthropicBackend(p)
    # 只有内置 ollama 走 /api/tags；LM Studio / vLLM 等本地服务仍走标准 /v1/models
    if ptype == "openai" and (p.get("id") == "ollama" or "11434" in (p.get("base_url") or "")):
        return OllamaBackend(p)
    return OpenAICompatBackend(p)


def get_backend(name: str | None = None) -> LLMBackend:
    """取后端实例。name 为供应商 id；不传则用当前选中的供应商。

    实例按「供应商配置签名」缓存，配置一改（设置里保存）下一次调用即生效，
    无需重启服务。
    """
    if not name:
        name = providers.current_id()
    p = providers.get(name)
    if p is None:
        # 供应商被删了/改名了：回退到本地，避免整站不可用
        p = providers.current()

    sig = _signature(p)
    if _backend_sig.get(p["id"]) != sig:
        _backends[p["id"]] = build_backend(p)
        _backend_sig[p["id"]] = sig
    return _backends[p["id"]]


def current_backend_name() -> str:
    return providers.current_id()


def set_backend(name: str) -> LLMBackend:
    """切换当前供应商并持久化，返回后端实例。校验失败抛 ValueError。"""
    providers.set_current(name)
    return get_backend(name)


def auto_route_candidate(current: str) -> LLMBackend | None:
    """漏洞验证类任务的云端自动路由目标（未配置/就是当前后端时返回 None）。"""
    pid = providers.auto_route_id()
    if not pid or pid == current:
        return None
    b = get_backend(pid)
    return b if b.available() else None


# ---------- 可重试判定与故障转移（v011 P1-6） ----------
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def is_retryable_error(e: Exception) -> bool:
    """判断一次模型调用失败是否值得重试。

    可重试：连接失败（DNS 抖动/服务没起）、超时、限流 429、临时网关故障 5xx——
        这些通常是几十秒级别的环境问题，重试/换家就能救回来。
    不可重试：401/403（Key 无效）、400（请求本身错）、404（端点/模型名错）、
        配置缺失（RuntimeError）——重试只会原样再错一遍，直接上抛。
    """
    if isinstance(e, httpx.HTTPStatusError):
        return int(e.response.status_code) in _RETRYABLE_STATUS
    # httpx 的传输层异常族：ConnectError / ConnectTimeout / ReadTimeout /
    # ReadError / RemoteProtocolError 等
    if isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                      httpx.WriteTimeout, httpx.PoolTimeout, httpx.ReadError,
                      httpx.WriteError, httpx.RemoteProtocolError)):
        return True
    if isinstance(e, (httpx.TimeoutException, httpx.TransportError)):
        return True
    return False


def failover_backend(exclude: list[str]) -> LLMBackend | None:
    """挑一个「不是已失败供应商」的可用后端做故障转移（P1-6）。

    顺序沿用 _pick_default 的语义（云端优先、本地兜底），只是排除掉
    刚刚失败的那几个。找不到就返回 None（由调用方决定上抛）。
    """
    try:
        all_providers = providers.cfg().get("providers", [])
    except Exception:
        return None
    for p in all_providers:
        pid = p.get("id") or ""
        if pid in exclude:
            continue
        try:
            usable = providers._usable(p)      # noqa: SLF001 —— 同包内复用判定
        except Exception:
            usable = bool(p.get("enabled") and p.get("base_url") and p.get("model")
                          and (p.get("local") or p.get("api_key")))
        if not usable:
            continue
        try:
            b = get_backend(pid)
            if b.available():
                return b
        except Exception:
            continue
    return None


def parse_tool_arguments(raw: str) -> dict:
    """容错解析模型返回的参数（小模型偶尔吐出不合法 JSON）。"""
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {"target": raw.strip(), "args": ""}


# ---------- 旧接口兼容（DeepSeekBackend / load_anthropic_cfg 等历史引用） ----------
def load_anthropic_cfg() -> dict:
    """旧版 Anthropic 配置读取，保留给兼容路径；新代码请直接用 providers。"""
    p = providers.get("anthropic") or {}
    return {"base_url": p.get("base_url", ""), "api_key": p.get("api_key", ""),
            "model": p.get("model", config.DEFAULT_ANTHROPIC_MODEL)}


DeepSeekBackend = OpenAICompatBackend  # 旧引用别名：DeepSeek 已是普通 OpenAI 兼容供应商
