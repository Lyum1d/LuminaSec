# -*- coding: utf-8 -*-
"""全局配置。所有路径与模型参数集中在此处。"""
from __future__ import annotations

import os
from pathlib import Path

# ---------- 目录 ----------
APP_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = APP_DIR / "data"
WEB_DIR = APP_DIR / "web"
DATA_DIR.mkdir(exist_ok=True, parents=True)

# 天狐渗透工具箱根目录。
#
# v056 改：**不再写死默认路径**。原来这里硬编码了一个本机绝对路径
#   `E:\<网盘下载目录>\天狐渗透工具箱-…`
# 带来三重问题：
#   ① **隐私**：公开仓库里暴露作者的本机目录结构（同一问题在
#      `data/wordlists/common-small.txt` 与 `data/tool_overrides.json` 也各有一处，一并修掉）；
#   ② **可用性**：这条路径在任何人机器上都不存在，而它被当成"默认值"——
#      新 clone 的人得不到「未配置」的明确提示，只会看到一堆"工具文件缺失"；
#   ③ **违反本项目自己的约定**：项目说明写着「工具箱路径由环境变量 TOOLBOX_ROOT
#      指定，**不要写死路径**」。
#
# 现在按三级解析（越靠前越优先）：
#   1. 环境变量 `TOOLBOX_ROOT` —— 跨机协作的正规做法，也是文档里的说法；
#   2. 本机 `config.yaml` 的 `toolboxRoot` —— 该文件**不入库**，天然适合放本机路径；
#      项目已经用它存 FOFA 密钥与控制台口令，**不新增机制**；
#   3. 都没有 → 视为**未配置**（`TOOLBOX_ROOT_SET = False`），由 registry / health /
#      启动信息给出"请先配置"的明确提示，而不是含糊的"找不到工具清单"。
def _toolbox_root_raw() -> str:
    """工具箱根目录的原始字符串（未配置时为空串）。"""
    env = (os.getenv("TOOLBOX_ROOT") or "").strip()
    if env:
        return env
    # 从中性模块读，**不反向依赖 config** —— 否则与 fofa.py 形成循环导入
    from .flat_config import read_flat_yaml
    v = str(read_flat_yaml(APP_DIR / "config.yaml").get("toolboxRoot") or "").strip()
    # 扁平解析器**不做 YAML 转义处理**：若有人按 YAML 习惯写成
    #     toolboxRoot: "D:\\tbox"      （双反斜杠）
    # 解出来就是 `D:\\tbox`（两个反斜杠）→ 路径是错的，且报错信息看着还挺像。
    # 这里把连续双反斜杠折成单个，让「裸写」与「带引号双写」两种写法都能用。
    # ⚠️ 例外：UNC 路径（`\\server\share`）本来就以双反斜杠开头，不能折。
    if v and not v.startswith("\\\\"):
        v = v.replace("\\\\", "\\")
    return v


TOOLBOX_ROOT_RAW = _toolbox_root_raw()
TOOLBOX_ROOT_SET = bool(TOOLBOX_ROOT_RAW)
# 未配置时用空 Path（在 Windows 上等价于当前目录）。**不要**把它当有效路径用：
# 消费方必须先看 TOOLBOX_ROOT_SET —— health / registry / run.py 都已按此处理。
TOOLBOX_ROOT = Path(TOOLBOX_ROOT_RAW) if TOOLBOX_ROOT_SET else Path("")

TOOLBOX_ROOT_HELP = (
    "未配置工具箱根目录。请任选一种方式："
    "① 设置环境变量 TOOLBOX_ROOT=<天狐渗透工具箱根目录>；"
    "② 在本机 config.yaml 写 `toolboxRoot: <路径>`（该文件不入库）。"
)

# ---------- 工具箱内置运行时 ----------
TOOLBOX_PYTHON = TOOLBOX_ROOT / "python3" / "python.exe"
JAVA8_BIN = TOOLBOX_ROOT / "Java_path" / "Java_8_win" / "bin"
JAVA11_BIN = TOOLBOX_ROOT / "Java_path" / "Java_11_win" / "bin"

# ---------- 模型 ----------
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
# 探测结论：qwen3.5:9b 关闭思考模式会退化成纯文本、不再调用工具，因此思考模式必须保持开启
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
OLLAMA_THINKING = True

# 云端备用通道（未配置 API Key 时自动禁用，不影响本地运行）
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

# 通用 Anthropic 兼容通道（claude code 系 / GLM 等任意 Anthropic 兼容端点）。
# 优先从个人配置文件（%USERPROFILE%\.llm_anthropic.json，由控制台「设置」写入）读取，
# 环境变量仅作兜底 seed，命名对齐 tinyctfer：ANTHROPIC_BASE_URL / AUTH_TOKEN / MODEL。
ANTHROPIC_BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "")
ANTHROPIC_AUTH_TOKEN = os.getenv("ANTHROPIC_AUTH_TOKEN", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "")
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"  # 端点若不支持可在设置里改

# ---------- 个人密钥目录（%USERPROFILE%，不进项目仓库） ----------
USER_HOME = Path(os.environ.get("USERPROFILE", str(Path.home())))
DEEPSEEK_KEY_FILE = USER_HOME / ".deepseek_api_key"      # 一行 Key（旧版，已被 providers 迁移接管）
LLM_ANTHROPIC_FILE = USER_HOME / ".llm_anthropic.json"   # {"base_url","api_key","model"}（旧版，同上）
LLM_PROVIDERS_FILE = USER_HOME / ".src_agent_llm.json"   # 通用供应商配置（现行）

# ---------- 默认供应商（云端优先）----------
# 变更（用户 2026-09-15）：此前一律回退到本地 ollama（"本地优先"），
# 现在改为「保留本地模型接口可用，但默认优先云端」。解析顺序见 providers._pick_default：
#   1. 本项指定的供应商（若已启用且配置完整）
#   2. 其它任何「已启用 + 配置完整 + 非本地」的供应商
#   3. 本地 ollama（仅在前两者都不可用时兜底）
# 留空则跳过第 1 步，完全按 2 → 3 自动挑选。
PREFERRED_PROVIDER = os.getenv("AGENT_PREFERRED_PROVIDER", "deepseek")
DEFAULT_BACKEND = PREFERRED_PROVIDER  # 兼容旧名（旧语义即"默认后端"）

# ---------- 风险分级 ----------
# L0 只读/本地分析 -> 自动执行
# L1 主动探测扫描 -> 自动执行（全程留痕）
# L2 漏洞验证利用 -> 需确认
# L3 权限/横向/接管 -> 需确认 + 二次确认
RISK_LEVELS = {
    "L0": {"name": "只读 / 本地分析", "policy": "auto", "auto": True, "double_confirm": False},
    "L1": {"name": "主动探测扫描", "policy": "auto", "auto": True, "double_confirm": False},
    "L2": {"name": "漏洞验证与利用", "policy": "confirm", "auto": False, "double_confirm": False},
    "L3": {"name": "权限 / 横向 / 接管", "policy": "confirm", "auto": False, "double_confirm": True},
}
DEFAULT_RISK_LEVEL = "L2"  # 未定级工具一律按 L2 处理，宁严不松

# 可编排的工具类型（能取回 stdout）；其余为图形界面，只能启动
SCRIPTABLE_TYPES = {"命令行", "Python", "JAVA8", "JAVA11", "批处理"}

# ---------- Agent ----------
MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "30"))  # 单轮最多执行步数，防止死循环
# think 空转上限：到这一轮把「必须动手」推进上下文，再下一轮仍只推理就结束本轮。
# 目的是不让一个「只想不做」的模型把步数预算全烧在思考上（每轮都是一次 LLM 调用）。
THINK_STREAK_MAX = int(os.getenv("AGENT_THINK_STREAK_MAX", "3"))

# 预算感知：剩余步数 <= 该值时，每轮在上下文里明确提示「即将超支」并要求收敛。
BUDGET_REMIND_AT = int(os.getenv("AGENT_BUDGET_REMIND_AT", "3"))

# 执行模式（消融开关）：react=严格单步，plan=整轮批量执行。
EXECUTION_MODE = os.getenv("AGENT_EXECUTION_MODE", "react").strip().lower()
if EXECUTION_MODE not in ("react", "plan"):
    EXECUTION_MODE = "react"

# ---------------- 超时口径（v047 统一说明）----------------
# 系统里存在**两类**上限，含义不同、必须成对理解：
#
#   总时长上限   工具/代码从启动到结束的绝对上限。卡死、无限刷输出都靠它兜底。
#   无输出上限   连续多久没有任何输出就判定卡死。**只对外部工具生效**。
#
# 为什么两类都要：只靠「无输出」挡不住 enscan 这类每 10 秒刷一行
# 「需要安全验证」的工具 —— 输出不断流，idle 永不触发，进程会无限跑；
# 只靠「总时长」则卡死要等满 10 分钟才被发现，反馈太慢。
#
# 各通道的有效上限（v047 起由 /api/health 的 timeouts 段直接给出，不必再推断）：
#
#   通道          总时长上限                        无输出上限
#   外部工具       tool_overrides.timeout 或 TOOL_TIMEOUT      TOOL_IDLE_TIMEOUT
#   py_exec        PY_EXEC_TIMEOUT                           无（脚本常长时间不出字，
#                                                            加 idle 会误杀正常计算）
#   httpreplay     nuclei 分支同「外部工具」
#
# 不变量（startup 会自检并在违反时告警）：
#   **无输出上限 < 总时长上限**。否则 idle 检测永远轮不到触发 ——
#   它是一条死代码，而配置文件上看起来「两个上限都设了」。
TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "600"))  # 单工具总时长上限（秒）
TOOL_IDLE_TIMEOUT = int(os.getenv("TOOL_IDLE_TIMEOUT", "120"))  # 无输出多久判定卡死（秒）
MAX_OUTPUT_LINES = int(os.getenv("MAX_OUTPUT_LINES", "2000"))  # 单工具最多回传多少行
MAX_OUTPUT_CHARS = 8000  # 回喂给模型的最大字符数，超出截断防止撑爆上下文
# L2/L3 等用户确认的等待上限（秒），超时按「拒绝」处理
CONFIRM_TIMEOUT = int(os.getenv("AGENT_CONFIRM_TIMEOUT", "600"))
# 单次决策回传给模型的工具 schema 上限（工具过多会拖慢本地小模型）
MAX_TOOL_SCHEMAS = int(os.getenv("AGENT_MAX_TOOL_SCHEMAS", "40"))
# 项目情报库每类条目上限（注入上下文前会截断）
INTEL_CAP = int(os.getenv("INTEL_CAP", "150"))

# ---- 上下文压缩（机械式，不调用模型）----
# 借鉴 LuaN1ao 的「摘要压缩」思路，但刻意改用确定性裁剪：本地小模型写摘要本身会产生
# 幻觉，等于用一个不可靠环节去修另一个不可靠环节。只压 role=tool 消息的正文，绝不删消息。
HISTORY_COMPRESS_AFTER_MESSAGES = int(os.getenv("HISTORY_COMPRESS_AFTER_MESSAGES", "24"))
HISTORY_KEEP_RECENT = int(os.getenv("HISTORY_KEEP_RECENT", "12"))   # 最近 N 条保持原文
HISTORY_EXCERPT_CHARS = int(os.getenv("HISTORY_EXCERPT_CHARS", "80"))
HISTORY_SUMMARY_CHARS = int(os.getenv("HISTORY_SUMMARY_CHARS", "300"))  # 压缩后每条保留多少字

# ---------- 续聊记忆恢复（SessionManager.adopt） ----------
# 服务重启、或切回某条线索继续聊时，把落库的对话原文还原成「给模型的 messages」。
# 不还原会怎样：会话对象被重建时 messages 一片空白，模型对之前所有轮次零记忆，
# 而前端仍能从 chat_messages 看到完整对话 —— 人和模型看到的历史不一致，
# 用户会以为「它记得」，实际它什么都不记得。
# 只还原对话层（用户原话 + 模型说明/结论）；工具输出不在 chat_messages 里，
# 由 steps 表 / 情报库 / 已证事实库另行注入，这里不重复搬运。
RESTORE_CHAT_MAX = int(os.getenv("AGENT_RESTORE_CHAT_MAX", "24"))        # 最多还原多少条
RESTORE_CHAT_CHARS = int(os.getenv("AGENT_RESTORE_CHAT_CHARS", "1200"))  # 单条截断字符

# ---------- 步骤输出落库裁剪 ----------
# 此前只存尾部（output[-2000:]），导致工具开头的关键结果（命中统计、存活清单首页）
# 永久丢失，而上下文压缩又提示模型「可用 search_history 检索」——提示与事实不符。
# 改为头 + 尾都保留，中间以省略标记连接。
# v031（第三轮 某企业站 实战）：1500/2000 依然不够 —— 功能码全集、存活清单这类**中段**
# 结果仍落进省略区，模型只能重新向目标发请求回捞（实测 6 次，占全局预算 1/3）。
# 提到 4000/4000：单步落库上限 8KB，steps 表膨胀可控，换取「落库版本≈可用版本」。
STEP_OUTPUT_HEAD = int(os.getenv("AGENT_STEP_OUTPUT_HEAD", "4000"))
STEP_OUTPUT_TAIL = int(os.getenv("AGENT_STEP_OUTPUT_TAIL", "4000"))

# ---------- 历史检索回传（v031） ----------
# 原实现只回 220/300 字符片段，即使落库版本有 8KB 也拿不到中段清单。
# 提高片段长度，让 search_history 真正能替代「重新向目标取数」。
SEARCH_SNIPPET_CHARS = int(os.getenv("AGENT_SEARCH_SNIPPET_CHARS", "800"))

# ---------- 受控脚本接口正文上限与落盘（v031） ----------
# 原实现：text 硬截断 65536，且**无法取回完整正文** —— 脚本只能改用 Range 头再发
# 请求（实测门户页 110762 字节被截掉 40%，导致「首页无外链 JS」的错误判定，多耗
# 2 次目标请求）。现改为：上限提高到 128KB（覆盖常见门户页），仍超限时把**完整
# 正文落盘**并回 saved_text_path，脚本可用 tmpdir() 离线读取，不必再打目标。
PY_EXEC_TEXT_LIMIT = int(os.getenv("AGENT_PY_EXEC_TEXT_LIMIT", "131072"))
# v032（第四轮实战）：正文达到该阈值就**无条件落盘**，不再只在截断时落。
# 原因：脚本崩溃时内存里的 Resp 会连同已成功取回的正文一起丢失 → 同一路径被迫
# 重请，实测白烧 2 次真实目标请求（违反「不重复请求」纪律）。落盘后正文可找回。
# v034（第六轮实战）：8192 偏高 —— 实测 7692 字节的 common.js 因低于阈值未落盘，
# 脚本崩溃后只能重取。降到 1024：覆盖「可能有取证价值」的响应，同时跳过 141 字节
# 量级的 404 空页（那类内容在 r.text 里已完整，落盘无价值）。
PY_EXEC_SAVE_THRESHOLD = int(os.getenv("AGENT_PY_EXEC_SAVE_THRESHOLD", "1024"))
# v035（公益 SRC 合规）：技术分析用的落盘文件保留期（天）。
# 「严禁保存测试过程中获取的任何数据」是公益 SRC 的硬要求，因此落盘文件必须**用完即清**。
# 修复点：`cleanup_persist_dirs()` 此前**从未被任何地方调用**，等于数据永久留存 ——
# 现改为服务启动时按本保留期清理（默认只留 1 天）。
PY_EXEC_PERSIST_KEEP_DAYS = int(os.getenv("AGENT_PY_EXEC_PERSIST_KEEP_DAYS", "1"))

# ---------- 记忆注入上限 ----------
# 超过上限的条目会在注入块尾部写明「另有 N 条未展示」，不再是无声截断 ——
# 否则模型既不知道「还有更多记忆它看不见」，也没动机去检索，只会重复收集。
FACT_INJECT_MAX = int(os.getenv("AGENT_FACT_INJECT_MAX", "20"))      # 已证事实库
RECORD_INJECT_MAX = int(os.getenv("AGENT_RECORD_INJECT_MAX", "20"))  # 本线索开局记录
BRANCH_INJECT_MAX = int(os.getenv("AGENT_BRANCH_INJECT_MAX", "8"))   # 同项目其他线索摘要

# ---- 失败止损分两档（借鉴 LuaN1ao EXECUTOR_FAILURE_THRESHOLD 的语义）----
# 连续失败到 SWITCH 档 → 要求模型「换策略」，而不是直接停；到 STOP 档才停止。
FAILURE_SWITCH_THRESHOLD = int(os.getenv("AGENT_FAILURE_SWITCH", "3"))
FAILURE_STOP_THRESHOLD = int(os.getenv("AGENT_FAILURE_STOP", "6"))

# ---- 单次任务 token 预算（成本熔断）----
# 本地 Ollama 不返回 usage，因此不会触发；云端供应商超限即停止，避免无声烧钱。
RUN_TOKEN_BUDGET = int(os.getenv("AGENT_RUN_TOKEN_BUDGET", "2500000"))
# v041：token 预算的**预警比例** —— 达到该比例即注入「强制收敛、先出结论」提示。
# 为什么必须有：原实现只有「步数」预警（BUDGET_REMIND_AT），token 仅在**超限瞬间**
# 硬熔断。实测（某高校 第三轮）出现「步数还有余、token 先超」：811,983/800,000 被直接截断，
# 测绘做完了却没输出任何结论，报告只能靠人工从事实库回捞 —— 交付层面的缺口。
TOKEN_BUDGET_WARN_RATIO = float(os.getenv("AGENT_TOKEN_WARN_RATIO", "0.8"))

# ---- 任务分片并行（split_task：拆小份 → 并发跑 → 合并）----
# 子任务并发上限。**不要调太高**：并行意味着对目标同时发起更多请求，
# 平台规则禁止影响业务可用性的高并发；同时也会推高云端 token 消耗。
SUBTASK_MAX_CONCURRENCY = int(os.getenv("SUBTASK_MAX_CONCURRENCY", "3"))
# 单个子任务的步数预算（比主任务小，避免一个子任务吃光预算）
SUBTASK_MAX_STEPS = int(os.getenv("SUBTASK_MAX_STEPS", "8"))
# 单次最多拆几个子任务
SUBTASK_MAX_COUNT = int(os.getenv("SUBTASK_MAX_COUNT", "4"))
# 合并回主线索时，最多带上多少条子任务期间新增的已证事实
SUBTASK_MERGE_FACTS = int(os.getenv("SUBTASK_MERGE_FACTS", "20"))

# ---------- 服务 ----------
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8770"))

# ---------- 模型路由 ----------
# 漏洞验证类任务自动路由到云端模型（要求 DEEPSEEK_API_KEY 已配置，否则自动回退本地）
AUTO_ROUTE_VULN = os.getenv("AUTO_ROUTE_VULN", "1") == "1"
VULN_KEYWORDS = (
    "漏洞", "验证", "越权", "未授权", "注入", "payload", "exp", "poc",
    "弱口令", "爆破", "绕过", "rce", "sqli", "xss", "ssrf",
)

# ---------- HTTP 重放器 ----------
REPLAY_MIN_INTERVAL = float(os.getenv("REPLAY_MIN_INTERVAL", "0.6"))  # 全局请求最小间隔（秒）
REPLAY_MAX_BODY = 4000     # 回传给模型的最大响应体长度（字符）
SCOPE_FILE = DATA_DIR / "scope.json"  # 授权域名白名单

# ---- v050 配置控制台（/console）----
# 前端独立目录（与 web/ 物理隔离：控制台改动不会碰到作战界面，反之亦然）
CONSOLE_DIR = APP_DIR / "console"
# 控制台口令。**未设置时 console 路由一律拒绝（fail-closed）** ——
# 绝不「未设置 = 不校验」：那个界面能改授权白名单，默认敞开等于把红线挂网上。
# 也可写在本机 config.yaml 的 consolePassword（不入库），环境变量优先。
CONSOLE_PASSWORD = os.getenv("AGENT_CONSOLE_PASSWORD", "")
# 登录票据有效期（秒），默认 12 小时
CONSOLE_TOKEN_TTL = int(os.getenv("AGENT_CONSOLE_TOKEN_TTL", "43200"))
# preview → commit 的一次性确认票据存活时间（秒）。
# 设短是刻意的：「确认」的语义是「我刚看过这份 diff」，隔夜再提交就不算确认了。
CONSOLE_CONFIRM_TTL = int(os.getenv("AGENT_CONSOLE_CONFIRM_TTL", "300"))

# 命令行工具执行前是否强制校验授权白名单（app/executor.py）。
# 背景：白名单此前只在 HTTP 重放器（replayer）生效，命令行工具（executor）
#   仅校验 target 格式、不校验目标是否在授权范围内，存在越权扫描缺口。
# 取值：1=强制（默认，未授权目标直接拒绝执行，与重放器行为对齐）
#       0=关闭（仅日志告警）——仅供临时排查，不建议长期关闭。
# 注意：白名单为空时一律拒绝执行（含未配置 scope.json 的情况），
#   宁可让工具跑不起来，也不能静默放行未授权目标。
ENFORCE_SCOPE = os.getenv("ENFORCE_SCOPE", "1") == "1"

# ---- 出网限速（实现见 app/ratelimit.py）----
TOOL_MIN_INTERVAL = float(os.getenv("TOOL_MIN_INTERVAL", "1.0"))
GLOBAL_MIN_INTERVAL = float(os.getenv("GLOBAL_MIN_INTERVAL", "0.2"))

# ---- 统一流量调度（v023.1，实现见 app/traffic.py）----
# 滑动窗口请求预算：同一 root_domain 在窗口内最多发这么多请求，超出即暂停
# （不是自动提高额度）。默认值取「保守档」——由 tgt-f.edu.cn 实测事故确定：
# 单脚本连发几十个敏感后缀请求即触发 IP 级封禁且封禁 >20 分钟。
TRAFFIC_WINDOW_SECONDS = int(os.getenv("AGENT_TRAFFIC_WINDOW", "600"))
TRAFFIC_MAX_REQUESTS = int(os.getenv("AGENT_TRAFFIC_MAX_REQUESTS", "30"))
TRAFFIC_BURST = int(os.getenv("AGENT_TRAFFIC_BURST", "5"))
# 并发上限：同一主机 1、同一根域名 1（v023.1 保守档，不可自动提高）
TRAFFIC_HOST_CONCURRENCY = int(os.getenv("AGENT_TRAFFIC_HOST_CONCURRENCY", "1"))
TRAFFIC_ROOT_CONCURRENCY = int(os.getenv("AGENT_TRAFFIC_ROOT_CONCURRENCY", "1"))
# 请求指纹短期复用 TTL（秒）。**默认 0 = 关闭**。
# v023.4 实现了完整复用能力（同指纹在 TTL 内复用已有观察，多分支测同一接口
# 时只有一次真实流量），但回归验证发现：开启会改变「差分/流程」的既有语义
# （连续两次相同请求第二次会命中缓存，稳定性判定失真）——即使复验已用独立
# variant_id + no_cache 规避，仍会掩盖真实的目标行为变化。因此默认关闭、
# 由用户按目标敏感度显式开启（AGENT_TRAFFIC_FP_TTL=120）。
TRAFFIC_FP_TTL = float(os.getenv("AGENT_TRAFFIC_FP_TTL", "0"))
# 测试模式：放预算/并发（跑回归套件用），生产不得开启。status 接口会公开该标志
TRAFFIC_TEST_MODE = os.getenv("AGENT_TRAFFIC_TEST_MODE", "") == "1"
TRAFFIC_TEST_MULTIPLIER = int(os.getenv("AGENT_TRAFFIC_TEST_MULTIPLIER", "50"))

# ---- py_exec 流量治理（v023.2）----
# 脚本网络访问策略：
#   safe（默认）——检测到「网络库 + 循环」的脚本直接拒绝，要求改用受控接口；
#   warn         ——只警告不拒绝（过渡期）；
#   legacy       ——完全关闭检测与受控通道（仅为排障保留，不推荐）。
PY_EXEC_NETWORK_POLICY = os.getenv("AGENT_PY_EXEC_NETWORK_POLICY", "safe").strip().lower()
# 单个脚本经受控通道的最大请求数（超出后 safe_http_request 返回预算错误，
# 目标暂停则宿主直接终止脚本进程树）
PY_EXEC_MAX_REQUESTS = int(os.getenv("AGENT_PY_EXEC_MAX_REQUESTS", "20"))
PY_EXEC_REQUEST_TIMEOUT = float(os.getenv("AGENT_PY_EXEC_REQUEST_TIMEOUT", "25"))

# ---- 扫描器速率治理（v023.2）----
# 0（默认）= 未声明内部速率能力的工具在启动前显示「流量不可观测」警告但仍可运行；
# 1 = 严格模式，未声明者直接拒绝自动运行（v023 计划 MUST 项，切到严格需用户确认，
#     因为会一次性禁用大量可用工具——过渡期用警告模式，声明补齐后再切）
SCANNER_REQUIRE_DECLARATION = os.getenv("AGENT_SCANNER_REQUIRE_DECLARATION", "0") == "1"
SCANNER_DEFAULT_RATE = int(os.getenv("AGENT_SCANNER_DEFAULT_RATE", "5"))       # 每秒请求
SCANNER_DEFAULT_THREADS = int(os.getenv("AGENT_SCANNER_DEFAULT_THREADS", "2"))  # 并发线程
# v023.4 拆分背压：目标剩余预算低于该值时拒绝 split_task 并发拆分
SUBTASK_MIN_BUDGET = int(os.getenv("AGENT_SUBTASK_MIN_BUDGET", "6"))

# v023.7：项目「已证实事实」自动注入（每轮提醒里带上，供后续线索复用）。
# 背景（某企业站 第二轮实战）：第一轮的已证实事实（后端入口、免权限控制器…）
# 只能靠人工写进任务书复述给模型，否则模型会重新发现甚至重复验证。
INJECT_FACTS = os.getenv("AGENT_INJECT_FACTS", "1") == "1"
INJECT_FACTS_MAX = int(os.getenv("AGENT_INJECT_FACTS_MAX", "10"))       # 最多注入条数
INJECT_FACTS_CHARS = int(os.getenv("AGENT_INJECT_FACTS_CHARS", "240"))  # 单条截断

# ---- 远程访问（run.py 拒绝启动 + app/main.py 令牌中间件）----
ALLOW_REMOTE = os.getenv("ALLOW_REMOTE", "0") == "1"
ACCESS_TOKEN = os.getenv("SRC_AGENT_TOKEN", "")


# ---------- Python 代码执行通道（py_exec，Agent 直出代码） ----------
# PY_EXEC_TIMEOUT：单段代码总时长上限（秒）。**只有这一个上限，没有 idle 检测** ——
# 脚本常常长时间不出字（纯计算、顺序探测），加「无输出判卡死」会误杀正常代码。
# v047 由 90 → 120，理由（不是随手放宽）：
#   ① py_exec 是**低配额目标的推荐探测通道**（见 tool_overrides 的 dirsearch 说明
#      「低配额目标建议改用 py_exec + safe_http_request 逐点探测」），
#      却是所有通道里预算最紧的 —— 推荐路径带宽比通用路径还小，这是设计倒挂；
#   ② 它与「外部工具」的差别只应体现在**没有 idle 检测**，而不该顺手再压一档：
#      把它对齐到 TOOL_IDLE_TIMEOUT 后，各通道的总时长上限关系变成可解释的；
#   ③ 实测代价：第三轮一个字节往返脚本在 90s 处被砍（`执行超时（>90s）`）。
# 注意这**不放宽流量**：单次请求上限（AGENT_PY_EXEC_REQUEST_TIMEOUT）与
# 单脚本请求总数（AGENT_PY_EXEC_MAX_REQUESTS）都没变，墙钟放宽不增加任何请求。
PY_EXEC_TIMEOUT = int(os.getenv("PY_EXEC_TIMEOUT", "120"))
PY_EXEC_MAX_CHARS = 6000    # 单段代码最大字符数
PY_EXEC_DIR = DATA_DIR / "scripts" / "exec"  # 代码留档目录（按目标分子目录）

# ---- py_exec 静态能力分档（v047：把「一刀切 L3」换成按代码能力分级）----
# 见 app/pyexec_grade.py。开关默认开；关掉则所有 py_exec 一律按工具默认等级（L3），
# 供操作者需要绝对保守时使用。
PY_EXEC_GRADE_ENABLED = os.getenv(
    "AGENT_PY_EXEC_GRADE", "1").strip().lower() not in ("0", "false", "no", "off")
# 档 → 等级映射。可覆盖，但 pyexec_grade.apply_to 强制「只降级不升级」，
# 所以把它调高不会让任何脚本获得更高权限（只会失效为不降级）。
PY_EXEC_GRADE_LEVEL_LOCAL = os.getenv("AGENT_PY_EXEC_GRADE_LEVEL_LOCAL", "L0")
PY_EXEC_GRADE_LEVEL_NET = os.getenv("AGENT_PY_EXEC_GRADE_LEVEL_NET", "L2")

# ---- 任务级约束闸门（v048）----
# 从任务文本解析**显式禁令**（「不做字典爆破」等），凡具备对应能力的工具一律拒绝执行。
# 见 app/taskguard.py。默认开；关掉则只剩风险闸门（回到 v047 的行为）。
# 关闭的正当理由只有一个：约束解析**误判**了（把「禁止扫描未授权主机」当成「禁止扫描」）。
# 误判已有上下文过滤处理，但仍保留这个出口。
TASK_CONSTRAINTS_ENABLED = os.getenv(
    "AGENT_TASK_CONSTRAINTS", "1").strip().lower() not in ("0", "false", "no", "off")

# ---- py_exec 沙箱（v010 P0-1：进程级隔离）----
# 背景：py_exec 在宿主解释器里执行模型直出的任意 Python，此前 env=os.environ
#   完整继承宿主环境——DeepSeek/FOFA/代理凭据等全部对子进程可见，且 proc.kill()
#   只杀直接子进程，脚本再起的子进程会残留。
# 沙箱分级实现（容器/受控代理属架构级方案，另行规划）：
#   ① 环境变量白名单：子进程只继承下方内置白名单 + 用户扩展文件里的变量；
#   ② 临时工作目录：执行 cwd 用一次性临时目录，结束后清理（留档仍在 PY_EXEC_DIR）；
#   ③ Windows Job Object：KILL_ON_JOB_CLOSE —— 超时/异常关闭句柄即终止整棵进程树。
# PY_EXEC_ENV_ALLOW_JSON：用户可扩展的「允许继承」变量名清单（JSON 数组，可选）。
#   为什么不做成 data/*.json 强制项：允许哪些变量是本机个性化配置（如某些脚本
#   需要 HTTP_PROXY 走 Burp），做成「缺省内置 + 用户可选扩展」最省事且不影响他人。
PY_EXEC_ENV_ALLOW_JSON = DATA_DIR / "pyexec_env_allow.json"
PY_EXEC_TMP_ROOT = DATA_DIR / "scripts" / "tmp"   # 一次性工作目录的父目录（自动创建）

# ---------- 云端外发控制（v010 P0-4） ----------
# 背景：默认路由是「云端优先」（见 _pick_default 注释），工具输出里的 Cookie、
#   Authorization、内网路径、凭据会原样进入 LLM 请求。漏洞类任务几乎必然触碰
#   这些内容，等于把目标站点的会话凭据交给云端供应商。
# 模式（环境变量 AGENT_CLOUD_EGRESS，默认 redact）：
#   local_only —— 一切请求只允许本地供应商；选中云端时直接拒绝并提示切换本地。
#   redact     —— 允许上云，但发送前对 messages 做脱敏（Cookie/Bearer/JWT/
#                 password= 形态键值对/邮箱/手机号），并记录命中摘要到日志。
#   allow      —— 不做任何处理（仅在你明确知道并接受外发风险时使用）。
# 注意：脱敏作用于**发往云端的那份副本**，session.messages 原文不受影响，
#   本地供应商（local=True）不经过脱敏（数据不出本机）。
CLOUD_EGRESS_MODE = os.getenv("AGENT_CLOUD_EGRESS", "redact").strip().lower()

# ---------- LLM 重试与故障转移（v011 P1-6） ----------
# 背景：本机 DNS 抖动 / 云端限流（429）/ 网关临时故障（502/503/504）会让
#   一整轮任务直接报废——实际只是几十秒的网络问题。对可重试错误做指数退避，
#   重试耗尽后自动切到下一个可用供应商（切换原因记录到步骤流与日志）。
# LLM_RETRY_MAX：额外重试次数（0=不重试）；退避 = LLM_RETRY_BASE_DELAY * 2^attempt。
# LLM_FAILOVER_MAX：单次任务内最多自动切换几次供应商（防雪崩式连环切换）。
# RUN_TIME_BUDGET：单次任务墙钟时间上限（秒，0=不限）。token 预算管钱、
#   步数管轮次，都不管时间——超时按中断处理，半程成果照常沉淀。
LLM_RETRY_MAX = int(os.getenv("AGENT_LLM_RETRY_MAX", "3"))
LLM_RETRY_BASE_DELAY = float(os.getenv("AGENT_LLM_RETRY_BASE_DELAY", "1.0"))
LLM_FAILOVER_MAX = int(os.getenv("AGENT_LLM_FAILOVER_MAX", "2"))
RUN_TIME_BUDGET = int(os.getenv("AGENT_RUN_TIME_BUDGET", "1800"))

# ---------- MCP 外部工具服务（v044） ----------
# 背景：Burp Suite 官方 MCP Server 扩展（PortSwigger/mcp-server）在 Burp 进程内
#   起一个 SSE 服务，暴露 send_http1_request 等工具。接上它以后，Agent 发的请求
#   会经 Burp 出网并自动落进 Proxy history，Agent 又能回读 history（闭环证据链）。
#
# 设计纪律（与项目既有安全边界一致，逐条都有原因）：
#   ① 只连回环地址（MCP_ALLOW_REMOTE=0）：MCP 是「本机工具服务」，允许远程等于
#      把 Agent 的出网能力交给第三方主机。想连远程必须显式改配置，不改就拒。
#   ② 不跟随环境代理：Burp 自己就是代理（本机 8080）。若 MCP 连接走了环境代理
#      （本机 62063），会出现「代理连代理」，极端情况成环。这条同 httpreplay
#      的 httpx 必须 trust_env=False。
#   ③ 经 MCP 的**主动发包**（send_http*_request）必须过 TrafficGovernor + scope，
#      与 httpreplay / py_exec 同一套治理，不允许出现「绕过限速的第二条出网通道」。
#   ④ 只读类 MCP 工具（读 Proxy history / 编码解码）不出网，不占流量预算。
#
# MCP_ENABLED：总开关。关掉后 Agent 工具清单里不会出现任何 burp_* 工具。
# MCP_BURP_URL：SSE 端点基址（官方扩展默认 host/port 见其 McpConfig.kt）。
# MCP_CALL_TIMEOUT：单次 MCP 调用超时（秒）。Burp 弹窗等人工批准会吃掉时间，
#   所以这个值要显著大于普通 HTTP 工具，否则「等用户点 Allow」会被误判成超时。
# MCP_REQUIRE_APPROVAL：是否要求 Burp 侧弹窗人工批准（仅作为给模型的提示文本，
#   真正的闸门在 Burp 扩展配置里，Agent 无法也**不应该**替用户关掉它）。
MCP_ENABLED = os.getenv("AGENT_MCP_ENABLED", "1") == "1"
MCP_ALLOW_REMOTE = os.getenv("AGENT_MCP_ALLOW_REMOTE", "0") == "1"
MCP_BURP_URL = os.getenv("AGENT_MCP_BURP_URL", "http://127.0.0.1:9876").rstrip("/")
MCP_CALL_TIMEOUT = float(os.getenv("AGENT_MCP_CALL_TIMEOUT", "120"))
MCP_REQUIRE_APPROVAL = os.getenv("AGENT_MCP_REQUIRE_APPROVAL", "1") == "1"
# Proxy history 读取的分页默认值/上限。官方扩展返回的记录含完整请求+响应原文，
# 单条动辄数十 KB，一次拉太多会直接把上下文塞满（第 3 轮实战「上下文压缩丢证据」
# 就是这么来的）。默认 20 条、上限 100 条，配合 offset 翻页。
MCP_HISTORY_PAGE = int(os.getenv("AGENT_MCP_HISTORY_PAGE", "20"))
MCP_HISTORY_MAX = int(os.getenv("AGENT_MCP_HISTORY_MAX", "100"))
# 健康检查里 MCP 状态探测的缓存时长（秒）。
# 加了它之后 /api/health 的延迟不再由「Burp 是否在跑」决定 —— 见 _mcp_health 说明。
MCP_HEALTH_TTL = float(os.getenv("AGENT_MCP_HEALTH_TTL", "15"))


# ---------- 超时口径自检（v047） ----------
def timeout_profile() -> dict:
    """给出各执行通道的**有效**上限，供 /api/health 暴露与 startup 自检。

    为什么要做成函数而不是两张常量表：这些值来自多个环境变量与工具级 overrides，
    散在四处。操作者排查「为什么工具 25 秒就被砍」时要翻源码是极差的体验，
    而「口径不一致」这类问题**只有摆在一起看才看得出来**（v047 之前的实际状况：
    py_exec 90s / 工具 idle 120s / 工具总时长 600s，三者关系从未被写明）。
    """
    return {
        "channels": {
            "external_tool": {
                "total_cap": TOOL_TIMEOUT,
                "total_cap_src": "TOOL_TIMEOUT（可被 tool_overrides.timeout 覆写）",
                "idle_cap": TOOL_IDLE_TIMEOUT,
                "idle_cap_src": "TOOL_IDLE_TIMEOUT",
                "note": "双上限：idle 抓静默卡死，total 抓持续刷屏",
            },
            "py_exec": {
                "total_cap": PY_EXEC_TIMEOUT,
                "total_cap_src": "PY_EXEC_TIMEOUT",
                "idle_cap": None,
                "idle_cap_src": "",
                "note": "只有总时长上限；脚本常长时间不出字，加 idle 会误杀正常计算",
            },
        },
        # 不变量：idle < total。违反时 idle 检测永远轮不到触发（死代码），
        # 而配置上看起来「两个上限都设了」—— 这正是需要机器来提醒的那类错。
        "idle_below_total": TOOL_IDLE_TIMEOUT < TOOL_TIMEOUT,
        "py_exec_grade_enabled": PY_EXEC_GRADE_ENABLED,
        "py_exec_grade_levels": {
            "readonly_local": PY_EXEC_GRADE_LEVEL_LOCAL,
            "readonly_net": PY_EXEC_GRADE_LEVEL_NET,
            "opaque": "L3",
        },
    }


def timeout_warnings() -> list[str]:
    """startup 自检：把「口径配错」从静默变成一条明确的告警。"""
    out: list[str] = []
    if TOOL_IDLE_TIMEOUT >= TOOL_TIMEOUT:
        out.append(
            f"口径异常：TOOL_IDLE_TIMEOUT({TOOL_IDLE_TIMEOUT}s) >= TOOL_TIMEOUT({TOOL_TIMEOUT}s)，"
            "外部工具的「无输出判卡死」永远不会触发（总时长先到）—— 这条检测成了死代码。")
    if PY_EXEC_TIMEOUT <= 0:
        out.append(f"口径异常：PY_EXEC_TIMEOUT={PY_EXEC_TIMEOUT} 非正数。")
    for key in ("PY_EXEC_GRADE_LEVEL_LOCAL", "PY_EXEC_GRADE_LEVEL_NET"):
        if globals()[key] not in RISK_LEVELS:
            out.append(f"口径异常：{key}={globals()[key]!r} 不是合法风险等级，分档将退化为不降级。")
    return out


def param_warnings() -> list[str]:
    """参数自检的**唯一入口**：`timeout_warnings()` 的全部检查 + 它没覆盖的跨参数不变量。

    为什么要合并到一个函数（v051 配置控制台的运行参数页要用）：
    控制台提交前必须校验「改完会不会自相矛盾」。如果控制台自己再写一套规则，
    就会出现两份规则、迟早漂移 —— 与 v047/v048/v050 反复踩的「同一原理落两份实现」
    是同一件事。所以这里只有一个函数：既有检查原样复用，缺的补在这里。

    与 `timeout_warnings()` 的分工：
      · 那个函数是 **startup 自检**用的，保持原样不动（它已被测试与启动流程依赖）；
      · 本函数是它的超集，供**提交前校验**用；startup 也可以改用它，但本次不动，避免牵动既有断言。
    """
    out = list(timeout_warnings())
    # py_exec 与外部工具的空闲上限要能对得上：v047 修过一次倒挂
    # （idle 比 py_exec 总时长还长 → py_exec 永远来不及触发空闲判定）。
    if PY_EXEC_TIMEOUT < TOOL_IDLE_TIMEOUT:
        out.append(
            f"口径异常：PY_EXEC_TIMEOUT({PY_EXEC_TIMEOUT}s) < TOOL_IDLE_TIMEOUT"
            f"({TOOL_IDLE_TIMEOUT}s)，py_exec 的空闲/总时长口径倒挂（v047 修过同类问题）。")
    if FAILURE_SWITCH_THRESHOLD >= FAILURE_STOP_THRESHOLD:
        out.append(
            f"口径异常：FAILURE_SWITCH_THRESHOLD({FAILURE_SWITCH_THRESHOLD}) >= "
            f"FAILURE_STOP_THRESHOLD({FAILURE_STOP_THRESHOLD})，切换阈值必须先于停止阈值生效。")
    if HISTORY_KEEP_RECENT >= HISTORY_COMPRESS_AFTER_MESSAGES:
        out.append(
            f"口径异常：HISTORY_KEEP_RECENT({HISTORY_KEEP_RECENT}) >= "
            f"HISTORY_COMPRESS_AFTER_MESSAGES({HISTORY_COMPRESS_AFTER_MESSAGES})，"
            "压缩后保留条数不能多于触发条数（压缩永远不会生效）。")
    if RUN_TOKEN_BUDGET and TOKEN_BUDGET_WARN_RATIO and not (0 < TOKEN_BUDGET_WARN_RATIO <= 1):
        out.append(f"口径异常：TOKEN_BUDGET_WARN_RATIO={TOKEN_BUDGET_WARN_RATIO} 应在 (0, 1] 内。")
    return out
