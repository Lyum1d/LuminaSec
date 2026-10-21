# -*- coding: utf-8 -*-
"""LLM 供应商（Provider）注册中心。

目标：让本控制台能接入市面上几乎所有大模型服务——任何 **OpenAI 兼容端点**、
**Anthropic 原生端点**，以及本地 **Ollama / LM Studio / vLLM**，
都统一用「类型 + Base URL + API Key + 模型名」四件套描述。

配置持久化在 %USERPROFILE%\\.src_agent_llm.json（密钥不进项目仓库），
运行时热读：控制台「设置」里增删改后无需重启服务。

兼容旧版本：首次加载时会把旧的 .deepseek_api_key / .llm_anthropic.json 迁移进来。
"""
from __future__ import annotations

import json
import logging
import os
import re
import uuid
from typing import Any

from . import config, config_io, redact

logger = logging.getLogger(__name__)

STORE_VERSION = 1

# 内置不可删除的三个供应商（可编辑、可重置）
BUILTIN_IDS = ("ollama", "deepseek", "anthropic")

# ---------- 厂商预设目录（控制台「从模板添加」用） ----------
# type: openai = OpenAI 兼容 /chat/completions；anthropic = Anthropic /v1/messages
PRESETS: list[dict[str, Any]] = [
    {"key": "ollama", "name": "本地 Ollama", "type": "openai",
     "base_url": "http://localhost:11434/v1", "model": "qwen3.5:9b",
     "local": True, "thinking": True,
     "note": "本机私有部署，数据不出机器；需先 ollama serve"},
    {"key": "lmstudio", "name": "LM Studio / vLLM / 本地服务", "type": "openai",
     "base_url": "http://localhost:1234/v1", "model": "local-model",
     "local": True, "note": "任意 OpenAI 兼容的本地推理服务"},
    # ---- 国内主流 ----
    {"key": "deepseek", "name": "DeepSeek 深度求索", "type": "openai",
     "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat",
     "note": "deepseek-chat / deepseek-reasoner，function calling 已实测"},
    {"key": "qwen", "name": "通义千问（阿里云百炼）", "type": "openai",
     "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "model": "qwen-plus",
     "note": "qwen-plus / qwen-max / qwen-turbo"},
    {"key": "zhipu", "name": "智谱 GLM", "type": "openai",
     "base_url": "https://open.bigmodel.cn/api/paas/v4", "model": "glm-4.6",
     "note": "GLM-4 系列，端点自带 /v1 语义"},
    {"key": "moonshot", "name": "Moonshot Kimi", "type": "openai",
     "base_url": "https://api.moonshot.cn/v1", "model": "moonshot-v1-128k",
     "note": "超长上下文，适合全量源码/日志分析"},
    {"key": "volcengine", "name": "火山方舟（豆包）", "type": "openai",
     "base_url": "https://ark.cn-beijing.volces.com/api/v3", "model": "doubao-pro-32k",
     "note": "需先在方舟控制台创建推理接入点"},
    {"key": "siliconflow", "name": "硅基流动 SiliconFlow", "type": "openai",
     "base_url": "https://api.siliconflow.cn/v1", "model": "Qwen/Qwen2.5-72B-Instruct",
     "note": "一个 Key 打通多款开源模型，按量计费"},
    {"key": "hunyuan", "name": "腾讯混元", "type": "openai",
     "base_url": "https://api.hunyuan.cloud.tencent.com/v1", "model": "hunyuan-turbo",
     "note": "腾讯云 API Key"},
    {"key": "baidu", "name": "百度千帆（文心）", "type": "openai",
     "base_url": "https://qianfan.baidubce.com/v2", "model": "ernie-4.0-8k",
     "note": "千帆平台 OpenAI 兼容网关"},
    {"key": "stepfun", "name": "阶跃星辰 Step", "type": "openai",
     "base_url": "https://api.stepfun.com/v1", "model": "step-1-8k"},
    {"key": "minimax", "name": "MiniMax", "type": "openai",
     "base_url": "https://api.minimax.chat/v1", "model": "MiniMax-Text-01"},
    {"key": "dashscope-intl", "name": "阿里云国际 Model Studio", "type": "openai",
     "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "model": "qwen-plus"},
    # ---- 海外主流 ----
    {"key": "openai", "name": "OpenAI", "type": "openai",
     "base_url": "https://api.openai.com/v1", "model": "gpt-4o",
     "note": "gpt-4o / gpt-4o-mini / o3-mini"},
    {"key": "anthropic", "name": "Anthropic Claude", "type": "anthropic",
     "base_url": "https://api.anthropic.com", "model": "claude-sonnet-4-5",
     "note": "Anthropic 原生 /v1/messages 协议"},
    {"key": "gemini", "name": "Google Gemini", "type": "openai",
     "base_url": "https://generativelanguage.googleapis.com/v1beta/openai", "model": "gemini-2.0-flash",
     "note": "Google 官方 OpenAI 兼容层"},
    {"key": "grok", "name": "xAI Grok", "type": "openai",
     "base_url": "https://api.x.ai/v1", "model": "grok-3"},
    {"key": "groq", "name": "Groq", "type": "openai",
     "base_url": "https://api.groq.com/openai/v1", "model": "llama-3.3-70b-versatile",
     "note": "推理极快，适合批量低复杂决策"},
    {"key": "openrouter", "name": "OpenRouter", "type": "openai",
     "base_url": "https://openrouter.ai/api/v1", "model": "openai/gpt-4o",
     "note": "一个 Key 访问上百个模型，支持自动回退"},
    {"key": "together", "name": "Together AI", "type": "openai",
     "base_url": "https://api.together.xyz/v1", "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo"},
    {"key": "mistral", "name": "Mistral AI", "type": "openai",
     "base_url": "https://api.mistral.ai/v1", "model": "mistral-large-latest"},
    {"key": "custom", "name": "自定义端点", "type": "openai",
     "base_url": "", "model": "", "note": "任意 OpenAI 兼容 /chat/completions 端点"},
]


# ---------- 存储 ----------
def _file():
    return config.LLM_PROVIDERS_FILE


def _default_providers() -> list[dict[str, Any]]:
    """内置三个默认供应商；ollama 永远可用，云端两个待填 Key。"""
    return [
        {"id": "ollama", "name": "本地 Ollama", "type": "openai",
         "base_url": config.OLLAMA_BASE_URL, "api_key": "", "model": config.OLLAMA_MODEL,
         "thinking": True, "local": True, "builtin": True, "enabled": True},
        {"id": "deepseek", "name": "DeepSeek 深度求索", "type": "openai",
         "base_url": config.DEEPSEEK_BASE_URL, "api_key": config.DEEPSEEK_API_KEY,
         "model": config.DEEPSEEK_MODEL, "local": False, "builtin": True, "enabled": True},
        {"id": "anthropic", "name": "Anthropic 兼容端点", "type": "anthropic",
         "base_url": config.ANTHROPIC_BASE_URL, "api_key": config.ANTHROPIC_AUTH_TOKEN,
         "model": config.ANTHROPIC_MODEL or config.DEFAULT_ANTHROPIC_MODEL,
         "local": False, "builtin": True, "enabled": True},
    ]


def _read() -> dict:
    """读供应商配置。**解析失败时备份坏文件**再返回空，不静默丢密钥。

    v053（审计 §2.5 修）：原实现 `except Exception: pass` → 返回 `{}`。
    这个文件里存着**全部供应商与 API Key**，一旦内容坏掉（半截 JSON），
    表现就是「供应商配置全没了、密钥也没了」，而**没有任何提示**，
    用户只能重新填一遍 —— 而原因可能只是文件末尾缺了个 `}`。
    现在解析失败会：① 留日志；② 把坏文件另存一份带时间戳的副本（供人工抢救），
    这样"内容还能救回来"与"彻底丢了"是能区分的。
    """
    path = _file()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        logger.warning("供应商配置顶层不是对象（%s）：%r", path, type(data).__name__)
        _backup_broken(path, "顶层非对象")
    except Exception as e:                                   # noqa: BLE001
        logger.warning("供应商配置解析失败（%s）：%s", path, e)
        _backup_broken(path, f"解析失败：{e}")
    return {}


def _backup_broken(path, why: str) -> None:
    """把坏掉的配置文件另存一份（尽力而为，失败只记日志）。"""
    try:
        import shutil
        import time as _t
        dst = path.with_suffix(f".broken_{_t.strftime('%Y%m%d_%H%M%S')}.json")
        shutil.copy2(path, dst)
        logger.warning("已备份损坏的供应商配置 → %s（%s）", dst.name, why)
    except Exception:                                        # noqa: BLE001
        logger.warning("备份损坏的供应商配置失败", exc_info=True)


def _write(data: dict) -> None:
    """原子写供应商配置。

    v053（审计 §2.5 修）：原来直接 `write_text` —— 截断后写入，进程在写入中途
    被终止（保存瞬间关窗、断电）就留下**半截 JSON**，下次 `_read` 解析失败
    即返回空 → 全部供应商与密钥静默丢失。

    改为复用 `config_io.write_json_atomic`（临时文件 + `os.replace` 原子替换，
    并把原始字节经 `fsync` 落盘）—— **不在这里另写一份原子写实现**：
    同一原理落两份实现迟早漂移，这个项目已经为这类问题交过多次学费。

    ⚠️ **`backup_first=False` 是刻意的**：`write_json_atomic` 默认会把写前副本放进
    `data/console_backups/`（项目目录内）。而这个文件存着**全部 API Key**，
    它之所以放在 `%USERPROFILE%` 就是为了「密钥不进项目仓库」；
    一开备份就把密钥复制进项目目录了 —— 虽然 `data/console_backups/` 已 gitignored，
    但那是在用「.gitignore 兜底」代替「根本不写进去」，方向反了。
    配置损坏时的抢救副本由 `_backup_broken()` 负责，它写在**原位同目录**（仓库之外）。
    """
    res = config_io.write_json_atomic(_file(), data, backup_first=False)
    if not res.get("ok"):
        # 原子写失败必须让上层知道 —— 静默失败会让界面显示"已保存"而文件没变
        raise OSError(f"写入供应商配置失败：{res.get('error')}")
    logger.debug("供应商配置已原子写入 %s（备份 %s）", _file().name, res.get("backup") or "无")


def _normalize(p: dict) -> dict:
    """补齐字段、清洗空白，保证下游拿到的结构一致。"""
    out = {
        "id": str(p.get("id") or "").strip(),
        "name": str(p.get("name") or "").strip(),
        "type": str(p.get("type") or "openai").strip().lower(),
        "base_url": str(p.get("base_url") or "").strip(),
        "api_key": str(p.get("api_key") or "").strip(),
        "model": str(p.get("model") or "").strip(),
        "thinking": bool(p.get("thinking")),
        "local": bool(p.get("local")),
        "builtin": bool(p.get("builtin")),
        "enabled": p.get("enabled", True) is not False,
        "timeout": int(p.get("timeout") or 0) or 300,
    }
    if out["type"] not in ("openai", "anthropic"):
        out["type"] = "openai"
    return out


def _migrate_legacy(cfg: dict) -> bool:
    """把旧版 .deepseek_api_key / .llm_anthropic.json 迁进新的供应商配置。"""
    changed = False
    by_id = {p["id"]: p for p in cfg.get("providers", [])}

    ds = by_id.get("deepseek")
    if ds and not ds.get("api_key"):
        try:
            key = config.DEEPSEEK_KEY_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            key = ""
        if not key:
            key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        if key:
            ds["api_key"] = key
            changed = True

    an = by_id.get("anthropic")
    if an and not (an.get("api_key") and an.get("base_url")):
        try:
            old = json.loads(config.LLM_ANTHROPIC_FILE.read_text(encoding="utf-8"))
        except Exception:
            old = {}
        if isinstance(old, dict):
            if not an.get("base_url") and old.get("base_url"):
                an["base_url"] = str(old["base_url"]).strip()
                changed = True
            if not an.get("api_key") and old.get("api_key"):
                an["api_key"] = str(old["api_key"]).strip()
                changed = True
            if not an.get("model") and old.get("model"):
                an["model"] = str(old["model"]).strip()
                changed = True
    return changed


# 进程内缓存：避免每次请求都读盘。按文件 mtime 失效，
# 这样外部进程（编辑器、测试脚本、第二实例）改过配置后，服务下一次读取能拿到最新值，
# 不会被自己的陈旧缓存覆盖。
_cache: dict | None = None
_cache_mtime: float = 0.0


def _file_mtime() -> float:
    try:
        return _file().stat().st_mtime
    except OSError:
        return 0.0


def _usable(p: dict) -> bool:
    """该供应商是否「现在就能用」：已启用 + 端点与模型齐全 + 本地或已填 Key。"""
    return bool(
        p.get("enabled")
        and p.get("base_url")
        and p.get("model")
        and (p.get("local") or p.get("api_key"))
    )


def _pick_default(providers: list[dict]) -> str:
    """挑选默认供应商：**云端优先，本地兜底**。

    变更（用户 2026-09-15）：此前无论何种情况都回退到本地 ollama（"本地优先"），
    现在改为保留本地接口可用、但默认优先云端：
      1. `config.PREFERRED_PROVIDER`（默认 deepseek），前提是它已启用且配置完整；
      2. 其它任何「已启用 + 配置完整 + 非本地」的供应商（按 providers 顺序）；
      3. 本地 ollama —— 仅当没有任何可用云端时才兜底；
      4. 最后再退到列表第一个，保证永远不返回空。
    全新安装且未填任何 Key 时，第 2/3 步都落空于云端，最终仍会选到 ollama，不会变砖。
    """
    usable = [p for p in providers if _usable(p)]
    # 云端外发策略 local_only（v010 P0-4）：默认路由跳过一切云端供应商，
    # 只在本地供应商里挑。redact/allow 模式不改变「云端优先」的既有顺序。
    if not redact.cloud_allowed():
        usable = [p for p in usable if p.get("local")]
    pref = (config.PREFERRED_PROVIDER or "").strip()
    if pref:
        for p in usable:
            if p["id"] == pref:
                return p["id"]
    for p in usable:
        if not p.get("local"):
            return p["id"]
    for p in usable:
        if p.get("local"):
            return p["id"]
    return providers[0]["id"] if providers else "ollama"


def cfg() -> dict:
    """读取完整配置（带迁移与默认值兜底）。文件被外部改动时自动重载。"""
    global _cache, _cache_mtime
    mtime = _file_mtime()
    if _cache is not None and mtime == _cache_mtime:
        return _cache

    data = _read()
    providers = [_normalize(p) for p in data.get("providers", []) if isinstance(p, dict)]
    # 内置三个必须存在（老用户删了也会补回来）
    have = {p["id"]: p for p in providers}
    for d in _default_providers():
        if d["id"] not in have:
            providers.append(_normalize(d))
            have[d["id"]] = providers[-1]
        else:
            have[d["id"]]["builtin"] = True

    cfg_data = {
        "version": STORE_VERSION,
        "providers": providers,
        "current": str(data.get("current") or "").strip(),
        "auto_route": data.get("auto_route", True),           # 漏洞类任务自动路由云端
        "auto_route_id": str(data.get("auto_route_id") or "deepseek").strip() or "deepseek",
    }
    if _migrate_legacy(cfg_data):
        _write(cfg_data)

    # 当前选择失效（被删/停用/Key 被清空）时：按「云端优先、本地兜底」重新挑，
    # 而不是无脑回退到本地 ollama。
    if not any(p["id"] == cfg_data["current"] and _usable(p) for p in providers):
        cfg_data["current"] = _pick_default(providers)
    _cache = cfg_data
    _cache_mtime = _file_mtime()
    return _cache


def invalidate() -> None:
    """外部写盘后调用，强制下次重新读盘。"""
    global _cache
    _cache = None


def save(cfg_data: dict) -> None:
    global _cache, _cache_mtime
    cfg_data["version"] = STORE_VERSION
    _write(cfg_data)
    _cache = cfg_data
    _cache_mtime = _file_mtime()


def mask(key: str) -> str:
    key = (key or "").strip()
    if not key:
        return ""
    return key[:4] + "…" + key[-4:] if len(key) > 8 else "****"


# ---------- 查询 ----------
def list_providers() -> list[dict]:
    """返回给前端的供应商列表（密钥打码）。"""
    c = cfg()
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "type": p["type"],
            "base_url": p["base_url"],
            "model": p["model"],
            "local": p["local"],
            "builtin": p["builtin"],
            "enabled": p["enabled"],
            "thinking": p["thinking"],
            "timeout": p["timeout"],
            "configured": bool(p["base_url"] and p["model"]) and (p["local"] or bool(p["api_key"])),
            "has_key": bool(p["api_key"]),
            "key_masked": mask(p["api_key"]),
        }
        for p in c["providers"]
    ]


def get(pid: str) -> dict | None:
    for p in cfg()["providers"]:
        if p["id"] == pid:
            return p
    return None


def raw(pid: str) -> dict | None:
    """取含密钥的原始配置（仅后端内部使用，不下发前端）。"""
    return get(pid)


def current_id() -> str:
    return cfg()["current"]


def current() -> dict:
    p = get(current_id())
    if p and p["enabled"]:
        return p
    # 回退同样走「云端优先」：不再无脑回退到本地 ollama
    picked = get(_pick_default(cfg()["providers"]))
    return picked or cfg()["providers"][0]


# ---------- 增删改 ----------
def _slug(name: str) -> str:
    """生成 URL 安全的 ASCII id（中文名会退化成 p-xxxx 短随机串）。"""
    base = re.sub(r"[^a-zA-Z0-9]+", "-", (name or "").strip()).strip("-").lower()
    if not base:
        # 纯中文/符号名称：给一个稳定的短 id，避免把非 ASCII 塞进 URL 路径
        base = "p-" + uuid.uuid4().hex[:6]
    return base[:24]


def _unique_id(base: str) -> str:
    ids = {p["id"] for p in cfg()["providers"]}
    if base not in ids:
        return base
    for i in range(2, 100):
        cand = f"{base}-{i}"
        if cand not in ids:
            return cand
    return f"{base}-{uuid.uuid4().hex[:6]}"


def upsert(data: dict) -> dict:
    """新增或更新供应商。带 id 且已存在=合并更新；无 id=新建。"""
    c = cfg()
    pid = str(data.get("id") or "").strip()
    target = get(pid) if pid else None

    if target is None:
        name = str(data.get("name") or "").strip() or "未命名供应商"
        pid = _unique_id(_slug(name))
        target = _normalize({"id": pid, "name": name})
        c["providers"].append(target)

    for k in ("name", "type", "base_url", "api_key", "model"):
        if k in data and data[k] is not None:
            val = str(data[k]).strip()
            # api_key 语义：空字符串或打码值（含 …）都视为「不修改已有密钥」，
            # 避免用户在设置里编辑其它字段（如改模型名）保存时把 Key 意外清空。
            # 想清空 Key 用「恢复默认」（内置）或删除重建（自定义）。
            if k == "api_key" and (not val or "…" in val):
                continue
            target[k] = val
    for k in ("thinking", "local", "enabled"):
        if k in data and data[k] is not None:
            target[k] = bool(data[k])
    if data.get("timeout"):
        try:
            target["timeout"] = int(data["timeout"])
        except Exception:
            pass
    if target["id"] in BUILTIN_IDS:
        target["builtin"] = True
    # R4 红线：内置 Ollama（qwen3.5:9b）思考模式必须恒开，关闭会退化成纯文本、不再调工具，
    # 这里强制锁定，即使前端传 thinking=False 也被忽略。
    if target["id"] == "ollama":
        target["thinking"] = True
    target["base_url"] = target["base_url"].rstrip("/")
    save(c)
    return target


def delete(pid: str) -> bool:
    """删除供应商。内置三个不可删除（可改配置停用）。"""
    if pid in BUILTIN_IDS:
        return False
    c = cfg()
    before = len(c["providers"])
    c["providers"] = [p for p in c["providers"] if p["id"] != pid]
    if len(c["providers"]) == before:
        return False
    if c["current"] == pid:
        # 删掉的正是当前选择：按「云端优先、本地兜底」重新挑一个
        c["current"] = _pick_default(c["providers"])
    save(c)
    return True


def reset_builtin(pid: str) -> bool:
    """把内置供应商恢复默认（清空 Key、恢复默认端点）。"""
    d = next((x for x in _default_providers() if x["id"] == pid), None)
    if not d:
        return False
    c = cfg()
    c["providers"] = [_normalize(d) if p["id"] == pid else p for p in c["providers"]]
    save(c)
    return True


def set_current(pid: str) -> dict:
    p = get(pid)
    if not p:
        raise ValueError(f"供应商不存在：{pid}")
    if not p["enabled"]:
        raise ValueError(f"供应商已停用：{p['name']}")
    if not p["local"] and not p["api_key"]:
        raise ValueError(f"未填写 API Key：{p['name']}")
    if not p["base_url"] or not p["model"]:
        raise ValueError(f"未填写 Base URL 或模型名：{p['name']}")
    c = cfg()
    c["current"] = pid
    save(c)
    return p


def set_auto_route(enabled: bool, pid: str = "") -> None:
    c = cfg()
    c["auto_route"] = bool(enabled)
    if pid:
        c["auto_route_id"] = pid
    save(c)


def auto_route_id() -> str:
    c = cfg()
    if not c.get("auto_route", True):
        return ""
    return c.get("auto_route_id", "deepseek")


def presets() -> list[dict]:
    return [dict(p) for p in PRESETS]
