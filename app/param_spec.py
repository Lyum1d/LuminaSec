# -*- coding: utf-8 -*-
"""运行参数的**可调白名单**与校验（v051 配置控制台 P2）。

## 为什么不把 90 个 `os.getenv` 常量全暴露出来

`app/config.py` 里有 **90 个**可用环境变量覆盖的常量。控制台如果「原样列全」，
会引入三类问题 —— 每一类都比「少调几个参数」严重得多：

1. **改了没用** —— `HOST` / `PORT` 是启动时绑定的，运行中改它们不会让服务换端口，
   只会让人以为改了（然后困惑「为什么还是 8770」）。这类参数**不该出现在可调列表里**，
   否则界面就是在说谎。
2. **会把自己锁在外面** —— `CONSOLE_PASSWORD` / `ACCESS_TOKEN` / `ALLOW_REMOTE`
   改错就进不来了；而且控制台改自己的口令是循环依赖。
3. **语义不是「调参」** —— 供应商相关（`OLLAMA_*` / `DEEPSEEK_*` / `ANTHROPIC_*`）
   有专门的供应商接口，混进参数页会出现两个入口写同一份配置。

所以本模块是**白名单**：只列真正适合运行期调整、且改错了能一眼看出来的参数。
**被排除的参数也一并列出并写明理由**（`EXCLUDED`）—— 「因为所以」要让人看得见，
否则下次有人会以为是漏了。

## 热生效的依据

全项目 **0 处** `from .config import X`，**220 处** `config.X` 属性访问（调用时读取），
所以运行时 `setattr(config, ...)` 立即对所有调用点生效 —— 不用重启。
（见 console 设计文档第 2.4 节；本模块的 `hot` 字段标注是否需要重启，P2 全部为 True。）

## 校验分两层

- **单值**：类型 / 取值域 / 枚举；
- **跨值不变量**：调用 `config.param_warnings()`（它复用并扩展了既有的
  `timeout_warnings()`）—— **不在这里另写一套**，避免两份规则漂移。
"""
from __future__ import annotations

from . import config

# 分组顺序即前端展示顺序
GROUP_ORDER = ["编排节奏", "超时与预算", "上下文与输出", "出网限速", "流量治理", "安全闸门", "稳定性"]

# ⚠️ 只列白名单内的参数。**新增项前先问：运行时改它真的有意义吗？改错了看得出来吗？**
SPECS: list[dict] = [
    # ---------------- 编排节奏 ----------------
    {"key": "MAX_STEPS", "group": "编排节奏", "label": "单轮最大步数", "type": "int",
     "min": 1, "max": 200, "hot": True,
     "note": "防死循环的硬上限。调大会显著增加 token 与目标流量消耗。"},
    {"key": "RUN_TOKEN_BUDGET", "group": "编排节奏", "label": "单轮 token 预算", "type": "int",
     "min": 10000, "max": 50_000_000, "step": 10000, "hot": True,
     "note": "累计超过即停止本轮。0 表示不限制（不建议）。"},
    {"key": "TOKEN_BUDGET_WARN_RATIO", "group": "编排节奏", "label": "预算告警比例",
     "type": "float", "min": 0.1, "max": 1.0, "step": 0.05, "hot": True,
     "note": "用量达到该比例时在提醒里提示模型收尾。"},
    {"key": "EXECUTION_MODE", "group": "编排节奏", "label": "执行模式", "type": "enum",
     "options": ["react", "plan"], "hot": True,
     "note": "react=一次一个工具（默认）；plan=允许一轮发起多个工具调用。"},
    {"key": "THINK_STREAK_MAX", "group": "编排节奏", "label": "连续「只想不做」上限",
     "type": "int", "min": 1, "max": 20, "hot": True,
     "note": "连续只调 think 不干活的容忍次数，超过则催促动手。"},
    {"key": "BUDGET_REMIND_AT", "group": "编排节奏", "label": "剩余步数提醒阈值",
     "type": "int", "min": 1, "max": 20, "hot": True,
     "note": "剩余步数少于该值时插入预算提醒。"},
    {"key": "RUN_TIME_BUDGET", "group": "编排节奏", "label": "单轮墙钟上限(秒)",
     "type": "int", "min": 60, "max": 86400, "hot": True,
     "note": "整轮任务的总时长上限，超过即停止。"},

    # ---------------- 超时与预算 ----------------
    {"key": "TOOL_TIMEOUT", "group": "超时与预算", "label": "外部工具总时长上限(秒)",
     "type": "int", "min": 10, "max": 3600, "hot": True,
     "note": "单工具墙钟上限。**必须大于 TOOL_IDLE_TIMEOUT**，否则空闲检测成为死代码。"},
    {"key": "TOOL_IDLE_TIMEOUT", "group": "超时与预算", "label": "外部工具空闲判卡死(秒)",
     "type": "int", "min": 10, "max": 3600, "hot": True,
     "note": "多久无输出判定卡死。**必须小于 TOOL_TIMEOUT**（既有不变量）。"},
    {"key": "PY_EXEC_TIMEOUT", "group": "超时与预算", "label": "py_exec 总时长上限(秒)",
     "type": "int", "min": 10, "max": 3600, "hot": True,
     "note": "只有总时长上限（脚本常长时间不出字，加空闲上限会误杀正常计算）。"},
    {"key": "CONFIRM_TIMEOUT", "group": "超时与预算", "label": "人工确认等待(秒)",
     "type": "int", "min": 30, "max": 3600, "hot": True,
     "note": "L2/L3 步骤等人工确认的上限；超时按拒绝处理。"},
    {"key": "MCP_CALL_TIMEOUT", "group": "超时与预算", "label": "MCP 调用超时(秒)",
     "type": "int", "min": 10, "max": 600, "hot": True,
     "note": "经 Burp MCP 出网的单次调用上限。"},

    # ---------------- 上下文与输出 ----------------
    {"key": "MAX_OUTPUT_LINES", "group": "上下文与输出", "label": "单工具回传行数上限",
     "type": "int", "min": 100, "max": 20000, "step": 100, "hot": True,
     "note": "超出会被截断（截断提示会进模型上下文）。"},
    {"key": "PY_EXEC_TEXT_LIMIT", "group": "上下文与输出", "label": "py_exec 响应字节上限",
     "type": "int", "min": 8192, "max": 4_000_000, "step": 8192, "hot": True,
     "note": "超过会落盘并给出 saved_text_path，用 load_text/load_bytes 读全文。"},
    {"key": "INTEL_CAP", "group": "上下文与输出", "label": "情报条目注入上限",
     "type": "int", "min": 10, "max": 2000, "hot": True},
    {"key": "MAX_TOOL_SCHEMAS", "group": "上下文与输出", "label": "暴露给模型的工具数上限",
     "type": "int", "min": 5, "max": 200, "hot": True,
     "note": "工具太多会拖慢本地小模型的决策速度。"},
    {"key": "HISTORY_COMPRESS_AFTER_MESSAGES", "group": "上下文与输出",
     "label": "对话压缩触发条数", "type": "int", "min": 4, "max": 200, "hot": True},
    {"key": "HISTORY_KEEP_RECENT", "group": "上下文与输出", "label": "压缩时保留最近条数",
     "type": "int", "min": 2, "max": 100, "hot": True},
    {"key": "HISTORY_EXCERPT_CHARS", "group": "上下文与输出", "label": "历史摘要截断字符",
     "type": "int", "min": 20, "max": 2000, "hot": True},

    # ---------------- 出网限速 ----------------
    {"key": "GLOBAL_MIN_INTERVAL", "group": "出网限速", "label": "全局最小请求间隔(秒)",
     "type": "float", "min": 0.0, "max": 60.0, "step": 0.1, "hot": True,
     "note": "所有出网请求之间的最小间隔。**调小会让目标压力变大**。"},
    {"key": "TOOL_MIN_INTERVAL", "group": "出网限速", "label": "单工具最小间隔(秒)",
     "type": "float", "min": 0.0, "max": 60.0, "step": 0.1, "hot": True},
    {"key": "REPLAY_MIN_INTERVAL", "group": "出网限速", "label": "重放器最小间隔(秒)",
     "type": "float", "min": 0.0, "max": 60.0, "step": 0.1, "hot": True},

    # ---------------- 流量治理 ----------------
    {"key": "TRAFFIC_WINDOW_SECONDS", "group": "流量治理", "label": "治理窗口(秒)",
     "type": "int", "min": 60, "max": 86400, "hot": True},
    {"key": "TRAFFIC_MAX_REQUESTS", "group": "流量治理", "label": "窗口内最大请求数",
     "type": "int", "min": 1, "max": 10000, "hot": True,
     "note": "公益 SRC 的「最小必要」主要靠它兜底。**调大会增加被封风险**。"},
    {"key": "TRAFFIC_BURST", "group": "流量治理", "label": "突发额度",
     "type": "int", "min": 1, "max": 1000, "hot": True},
    {"key": "TRAFFIC_HOST_CONCURRENCY", "group": "流量治理", "label": "单主机并发",
     "type": "int", "min": 1, "max": 20, "hot": True},
    {"key": "TRAFFIC_ROOT_CONCURRENCY", "group": "流量治理", "label": "单根域并发",
     "type": "int", "min": 1, "max": 20, "hot": True},

    # ---------------- 安全闸门（高危，改动需二次确认） ----------------
    {"key": "ENFORCE_SCOPE", "group": "安全闸门", "label": "强制授权白名单校验",
     "type": "bool", "hot": True, "danger": True,
     "note": "关掉后工具会对**任意目标**执行，等同停用授权红线。仅在临时排查时关闭。"},
    {"key": "TASK_CONSTRAINTS_ENABLED", "group": "安全闸门", "label": "任务级约束闸门",
     "type": "bool", "hot": True,
     "note": "开启后，任务书里写明的禁令（如「不做字典爆破」）会在工具层被拒绝。"},
    {"key": "PY_EXEC_GRADE_ENABLED", "group": "安全闸门", "label": "py_exec 能力分档",
     "type": "bool", "hot": True,
     "note": "开启后只读出网脚本降为 L2（少一次确认）；关闭则一律按 L3 双轮确认。**只影响确认次数，不放宽能力。**"},
    {"key": "PY_EXEC_GRADE_LEVEL_LOCAL", "group": "安全闸门", "label": "分档：纯本地脚本",
     "type": "enum", "options": ["L0", "L1", "L2", "L3"], "hot": True},
    {"key": "PY_EXEC_GRADE_LEVEL_NET", "group": "安全闸门", "label": "分档：经受控接口出网",
     "type": "enum", "options": ["L0", "L1", "L2", "L3"], "hot": True},
    {"key": "SCANNER_REQUIRE_DECLARATION", "group": "安全闸门", "label": "严格模式：拒绝未声明速率的扫描器",
     "type": "bool", "hot": True, "danger": True,
     "note": "⚠️ 实测 55 个模型可见工具里 **52 个**未声明 network_control —— 打开会拒绝几乎全部工具，"
             "只对少数几个未做声明的扫描器生效。**默认关闭是有意的。**"},
    {"key": "PY_EXEC_NETWORK_POLICY", "group": "安全闸门", "label": "py_exec 直连网络策略",
     "type": "enum", "options": ["safe", "legacy"], "hot": True, "danger": True,
     "note": "safe=拒绝「直接 import 网络库 + 循环体」的脚本（历史上导致目标被封的模式）；"
             "legacy=旧行为（放行）。"},
    {"key": "CLOUD_EGRESS_MODE", "group": "安全闸门", "label": "云端外发策略",
     "type": "enum", "options": ["redact", "allow", "local_only"], "hot": True,
     "note": "redact=外发前脱敏（默认）；allow=原样外发；local_only=禁止使用云端供应商。"},

    # ---------------- 稳定性 ----------------
    {"key": "FAILURE_SWITCH_THRESHOLD", "group": "稳定性", "label": "连续失败切换阈值",
     "type": "int", "min": 1, "max": 50, "hot": True,
     "note": "连续失败达该值即切换到备用供应商。**必须小于停止阈值**。"},
    {"key": "FAILURE_STOP_THRESHOLD", "group": "稳定性", "label": "连续失败停止阈值",
     "type": "int", "min": 2, "max": 100, "hot": True},
    {"key": "LLM_RETRY_MAX", "group": "稳定性", "label": "LLM 重试次数",
     "type": "int", "min": 0, "max": 10, "hot": True},
    {"key": "LLM_RETRY_BASE_DELAY", "group": "稳定性", "label": "重试基础退避(秒)",
     "type": "float", "min": 0.1, "max": 30.0, "step": 0.1, "hot": True},
    {"key": "LLM_FAILOVER_MAX", "group": "稳定性", "label": "供应商故障转移次数",
     "type": "int", "min": 0, "max": 10, "hot": True},
]

# 被**有意排除**的参数。列出来是为了让「为什么没有它」一眼可见，
# 而不是让人以为控制台漏了一批参数。
EXCLUDED: list[dict] = [
    {"key": "HOST / PORT", "why":
     "启动时绑定，运行中改它们不会换端口 —— 列出来就是**界面在说谎**。"
     "要换端口请改启动参数后重启。"},
    {"key": "ALLOW_REMOTE / ACCESS_TOKEN", "why":
     "控制远程访问的令牌。误设会把服务暴露或被锁在外面，属启动期配置。"},
    {"key": "CONSOLE_PASSWORD / CONSOLE_TOKEN_TTL", "why":
     "控制台自己的口令。在这里改有**循环依赖**风险（改错就进不来），"
     "请用环境变量或 config.yaml。"},
    {"key": "OLLAMA_* / DEEPSEEK_* / ANTHROPIC_*", "why":
     "供应商与模型走现有的供应商接口（`/api/llm/providers`），"
     "混进参数页会出现两个入口写同一份配置。"},
    {"key": "MCP_ENABLED / MCP_BURP_URL / MCP_*", "why":
     "MCP 连接配置，计划放进 P3 的「依赖服务」面板（含连通性测试），"
     "单独一页比塞进参数表更合适。"},
    {"key": "TRAFFIC_TEST_MODE / TRAFFIC_TEST_MULTIPLIER", "why":
     "**测试专用**：会放宽流量治理。放在可调列表里等于给了一个「悄悄关掉限速」的开关。"},
]

_BY_KEY = {s["key"]: s for s in SPECS}


# ---------------------------------------------------------------- 环境变量名与默认值
# 为什么**从 config.py 源码解析**而不是在 SPECS 里再抄一份：
# 40 个参数 × {环境变量名, 默认值} 就是 80 个待同步的常量。抄一份的那一刻起，
# 两边就开始漂移 —— 而漂移的表现是「控制台显示的默认值跟实际不一致」，
# 属于**看起来有信息量、其实是假的**那一类展示。源码是唯一事实来源，现读现解。
#
# 代价：读源码有 IO，所以缓存一次（进程内不变）。
_ENV_CACHE: dict[str, tuple[str, object]] | None = None


def _scan_config_source() -> dict[str, tuple[str, object]]:
    """解析 `app/config.py`，返回 `{常量名: (环境变量名, 字面量默认值)}`。

    只认形如 `X = os.getenv("ENV", "默认")` 与带 `int(...)`/`float(...)` 的写法。
    解析不出的常量就是「没有环境变量入口」，调用方按「默认值未知」处理，
    **不猜**。
    """
    import re
    from . import config as _c
    try:
        src = (_c.__file__ and __import__("pathlib").Path(_c.__file__)
               .read_text(encoding="utf-8", errors="ignore")) or ""
    except OSError:
        return {}
    out: dict[str, tuple[str, object]] = {}
    # 形态 ①：`X = os.getenv("ENV", "30")` / `int(...)` / `float(...)`
    pat_num = re.compile(
        r'^([A-Z][A-Z_0-9]+)\s*=\s*(int|float|str)?\(?\s*'
        r'os\.getenv\(\s*"([^"]+)"\s*,\s*"([^"]*)"', re.M)
    for m in pat_num.finditer(src):
        name, cast, env, raw = m.group(1), m.group(2), m.group(3), m.group(4)
        try:
            if cast == "int":
                val: object = int(raw)
            elif cast == "float":
                val = float(raw)
            else:
                val = raw
        except ValueError:
            continue
        out[name] = (env, val)
    # 形态 ②：`X = os.getenv("ENV", "1") == "1"`（含换行写法）
    for m in re.finditer(
            r'^([A-Z][A-Z_0-9]+)\s*=\s*os\.getenv\(\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\)'
            r'\s*==\s*"1"', src, re.M):
        out[m.group(1)] = (m.group(2), m.group(3).strip() == "1")
    # 形态 ③：`X = os.getenv("ENV", "1").strip().lower() not in ("0","false",...)`
    # （多行写法，例如 TASK_CONSTRAINTS_ENABLED / PY_EXEC_GRADE_ENABLED）
    for m in re.finditer(
            r'^([A-Z][A-Z_0-9]+)\s*=\s*os\.getenv\(\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\)'
            r'\s*\.strip\(\)\s*\.lower\(\)\s*not\s+in\s*\(([^)]*)\)', src, re.M):
        neg = {x.strip().strip('"\'').lower() for x in m.group(4).split(",") if x.strip()}
        out[m.group(1)] = (m.group(2), m.group(3).strip().lower() not in neg)
    return out


def _env_map() -> dict[str, tuple[str, object]]:
    global _ENV_CACHE
    if _ENV_CACHE is None:
        _ENV_CACHE = _scan_config_source()
    return _ENV_CACHE


def env_name(key: str) -> str:
    """该参数对应的环境变量名；没有则空串。"""
    return _env_map().get(key, ("", None))[0]


def default_value(key: str) -> object:
    """该参数在 `config.py` 里写的字面量默认值；解析不出返回 None（**不猜**）。"""
    return _env_map().get(key, ("", None))[1]


def source_of(key: str, overrides: dict | None) -> str:
    """当前值的来源：runtime-override / env / default / unknown。

    顺序即优先级，与 `apply_overrides` 之后的实际生效顺序一致：
    运行时覆盖文件 > 环境变量 > config.py 里的字面量。
    """
    import os
    if overrides and key in (overrides.get("params") or {}):
        return "runtime"
    env = env_name(key)
    if env and os.environ.get(env) is not None:
        return "env"
    if default_value(key) is not None:
        return "default"
    return "unknown"


def spec_of(key: str) -> dict | None:
    return _BY_KEY.get(key)


def current_values() -> dict:
    """当前生效值（含运行时覆盖）。只取白名单内的键。"""
    return {s["key"]: getattr(config, s["key"], None) for s in SPECS}


def groups() -> list[dict]:
    """按组返回规格（供前端渲染表单）。"""
    out: list[dict] = []
    for g in GROUP_ORDER:
        items = [s for s in SPECS if s["group"] == g]
        if items:
            out.append({"group": g, "items": items})
    return out


def validate(values: dict) -> list[str]:
    """校验待写入的值。返回问题列表（空 = 通过）。

    单值校验在本函数内做；**跨值不变量调用 `config.param_warnings()`** ——
    那是既有的、被 startup 自检复用的同一个函数，不在这里另写一份规则。
    """
    problems: list[str] = []
    if not isinstance(values, dict):
        return ["values 必须是对象"]
    for k, v in values.items():
        s = _BY_KEY.get(k)
        if not s:
            problems.append(f"{k}：不在可调白名单内（若确需暴露，先加进 param_spec.SPECS 并写理由）")
            continue
        t = s["type"]
        if t == "bool":
            if not isinstance(v, bool):
                problems.append(f"{k}：应为布尔值")
        elif t == "int":
            if not isinstance(v, int) or isinstance(v, bool):
                problems.append(f"{k}：应为整数")
            elif not (s["min"] <= v <= s["max"]):
                problems.append(f"{k}：应在 {s['min']} ~ {s['max']} 之间（当前提交 {v}）")
        elif t == "float":
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                problems.append(f"{k}：应为数字")
            elif not (s["min"] <= float(v) <= s["max"]):
                problems.append(f"{k}：应在 {s['min']} ~ {s['max']} 之间（当前提交 {v}）")
        elif t == "enum":
            if v not in s["options"]:
                problems.append(f"{k}：只允许 {'/'.join(s['options'])}（当前提交 {v!r}）")

    if problems:
        return problems

    # ---- 跨值不变量：走既有函数（不另写一套规则）----
    # 做法：把候选值**临时应用**到 config 上跑一次自检，再恢复。
    # 这样校验的就是「真正生效后会不会违反不变量」，而不是一条平行推断。
    saved = {k: getattr(config, k, None) for k in values}
    try:
        for k, v in values.items():
            setattr(config, k, v)
        problems.extend(config.param_warnings())
    finally:
        for k, v in saved.items():
            setattr(config, k, v)
    return problems
