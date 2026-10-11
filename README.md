# SRC 渗透 Agent · 本地控制台

**正式版 1.004**

对话驱动的渗透测试编排平台：调度天狐渗透工具箱 V3.0 中的工具，面向 SRC（补天）漏洞挖掘场景。
模型采用单步 ReAct 决策循环，支持任意 OpenAI 兼容 / Anthropic 端点，也可接本地 Ollama。

> **本仓库是「正式发布库」**：只放运行组件，供更新器拉取与直接 clone 使用。
> 日常小版本迭代与全套回归脚本在**工程测试库**中进行（见「本发布版与工程测试库的差异」）。

---

## 快速开始

```bat
python -m pip install -r requirements.txt   :: 首次：安装依赖（fastapi/uvicorn/httpx/pyyaml）
双击「启动控制台.bat」                        :: 浏览器打开（关闭窗口即停服务）
python run.py                               :: 命令行启动（--no-browser 不自动开浏览器）
```

默认地址：<http://127.0.0.1:8770>

### ⚠️ 首次使用：两件必做的事（不做就用不起来）

刚装好、还没配过任何东西时，界面能打开但**干不了活** —— 这不是坏了，是两道授权/依赖闸门还没开：

| # | 要配什么 | 症状（不配会怎样） | 怎么配 |
|---|---|---|---|
| 1 | **工具箱路径** | 工具箱面板只剩内置能力（19 项），外部工具**根本不列出** | 设环境变量 `TOOLBOX_ROOT=<天狐渗透工具箱根目录>`，或在本机 `config.yaml` 写 `toolboxRoot: <路径>` |
| 2 | **授权白名单** | 顶部红字「授权白名单为空」；所有命令行工具 / HTTP 重放器 / 代码执行**一律被拒绝** | 复制 `data/scope.example.json` 为 `data/scope.json`，把 `domains` 换成你的授权目标 |

> 第 2 条是**故意的**（fail-closed）：宁可跑不起来，也不放行未授权目标。
> 另外建议顺手设控制台口令（见「配置控制台」）——它能改授权白名单，不设口令时该界面拒绝访问。

**解释器怎么找（排障必看）**：`启动控制台.bat` 依次探测 `SRC_AGENT_PY` 环境变量 →
项目内 `.venv\Scripts\python.exe` → `py -3` 启动器 → PATH 里的 `python`
（每个候选都实际执行 `--version` 验证，绕开 Windows 商店的 python 占位程序）。
`run.py` 启动前还会自查依赖：若当前解释器没装 `uvicorn/fastapi/httpx/pydantic`，
会自动切换到带依赖的那个解释器并重启自身。因此「双击后窗口一闪」「报
ModuleNotFoundError: No module named 'uvicorn'」这类打不开的情况不会再出现；
万一所有候选都缺依赖，会打印明确的修复指引（而不是直接崩掉）。
多人协作时各人解释器位置不同，可用 `SRC_AGENT_PY` 显式指定。

> **先配授权白名单**：`data/scope.json` 的 `domains` 默认只有 `example.com`，
> 且白名单为空时一律拒绝执行（宁可跑不起来也不放行未授权目标）。换目标前先改这里，
> 否则命令行工具 / HTTP 重放器 / py_exec 都会被拦下。
>
> **先设控制台口令**：打开 `/console` 时若口令尚未配置，登录页会直接给出「首次设置口令」
> 表单，**设置即写入本机 `config.yaml`，重启不丢**（不需要每次启动重设）。

> 首次使用建议：先建「项目」（如"补天-XX厂商"），把任务发到选中的项目下，Agent 的每步输出、
> 已证事实与漏洞登记才会归档到该项目，报告才能聚合生成。
> **项目里的「目标」会自动注入每次决策**：任务描述没写域名/企业名时，模型以项目目标为准；
> 填的是企业名会先引导用 app_info 扩展资产（enscan 因需人工验证码已禁用）。

界面为对话式布局（深色/亮色可切换，右上角 🌙/☀️ 按钮）：
左侧边栏管「项目 / 工具箱」，中间是对话气泡流（AI 回复内含执行计划、命令/输出代码块与结论），
右侧「报告」面板记录漏洞发现与已证事实（可折叠）。
左栏项目列表支持**重命名与删除**（删除需二次确认，会连带删除该项目的漏洞、已证事实与会话记录）。
决策模型在底部下拉框或「设置 → 模型供应商」中切换。

---

## 工作模式：黑盒 / 白盒

进入 `http://127.0.0.1:8770/` 会先看到**起始选择界面**，选定模式后再进入工作区
（`/app?mode=blackbox` 或 `/app?mode=whitebox`）。界面会记住上次选择，顶部徽标可随时切回。

| | 黑盒侧 | 白盒侧 |
|---|---|---|
| 对象 | 已授权域名 / IP | 本机源码目录 |
| 工具集 | 外部工具箱工具（不含 `code_*`） | 只放代码审计 `code_*`、知识库 `kb_*`、留痕 `note_fact`，以及元认知工具 |
| 项目 | 按授权域名组织 | 按代码库组织（入库即一条授权记录） |

**模式是后端闸门，不只是界面过滤**：`registry.mode_allows()` 在**取工具 schema 与执行前**各挡一次 ——
白盒会话拿不到外部工具的 schema，点名调用也会被拦下（白盒本就不该向外部目标发流量）。
模式同时**落在会话与项目两级**（`sessions.mode` / `projects.mode`），分支与子任务继承父会话模式；
项目列表按模式过滤，把会话建到异侧项目上会被后端直接拒绝。项目创建后模式不可改，换侧请新建项目。

起始界面是**模式注册表**驱动的（`web/start.html` 里的 `MODES` 数组），
将来加「CTF 专项」等新入口只需在数组里加一项。

---

## 配置控制台

地址 `/console`（独立页面，与作战界面互不影响）。

- **口令 fail-closed**：未配置口令时控制台接口一律 403；口令优先取环境变量
  `AGENT_CONSOLE_PASSWORD`，其次本机 `config.yaml` 的 `consolePassword`。
  登录页与总览页都会**明示当前口令来源**（环境变量会压住 config.yaml，这一点此前看不出来）。
- **两段式写入**：授权白名单、工具分级、知识库篇目等写操作都是
  「预览 → 二次确认 → 提交」，并带 `expect_sha256` 乐观锁，避免覆盖他人改动；每次变更留审计。
- **白盒侧**页签：登记 / 删除代码库，增删改知识库篇目（写入前强制过仓库硬约定：
  篇目字符上限、姊妹篇互指、不含本机路径），并自动同步知识库索引与合计。

---

## 更新与版本

更新工具：`update.exe`（随发布包分发）或 `python update.py`。功能：检查更新 → 下载 →
**对照 `SHA256SUMS.txt` 逐文件校验** → 迁移本机保留项 → 旧文件备份 → 原子切换，支持一键回滚。

**更新源是可配置的**：`release_repo.txt` 的第一行写 `owner/repo` 即指定从哪个仓库拉更新
（优先级：环境变量 `SRC_AGENT_REPO` > `release_repo.txt` > 内置默认值）。
内置默认值同样指向**正式发布库** `Lyum1d/LuminaSec`，所以即使该文件丢失也仍能更新；
它**不会**去拉工程库（工程库已是私人备份库，对使用者不可见）。
更新器界面会显示**当前更新源及其来源**。改这一行**不需要重新打包 exe**。

⚠️ **关于版本号**：更新器用**字符串相等**判断「是否已是最新」，不做大小比较。
因此版本号必须**始终用同一套格式**递增（如 `1.001` → `1.002` 这种三段式）；
忽而 `1.1`、忽而 `1.001` 会让更新器永远认为「有新版本」而反复触发更新。

⚠️ **更新只新增 / 覆盖文件，不会删除**。上游删掉的文件，本机会保留；
若某次更新移除过文件，需要人工清理。

---

## 本发布版与工程测试库的差异

发布库**只放运行组件**，与工程测试库的差别：

| 项 | 发布库（本仓库） | 工程测试库 |
|---|---|---|
| `test_*.py` / `test_*.js` / `run_all_tests.py` | **不含** | 全套回归（3300+ 项） |
| `codebase_testkit.py`、`migrate_*.py`、`upgrade_templates.py` | **不含** | 含 |
| 内部规划文档（审计报告 / 实施规格 / 路线图 / 架构对比） | **不含** | 含 |
| 运行组件（`app/` `web/` `console/` `data/` `docs/`）+ 启动器 + 更新器 | 含 | 含 |

因此控制台白盒侧的「跑回归 test_068」按钮在发布版会提示**「正式版不含回归脚本」**
（这是有意不含，不是安装损坏）；该页的其他校验（字符上限 / 姊妹篇互指 / 索引合计同步）照常生效。
需要跑回归请到工程测试库执行 `python run_all_tests.py`。

---

## 可调配置

### 通用 LLM 接入

支持任意 **OpenAI 兼容** 端点（含 DeepSeek / 通义 / 智谱 / vLLM 等）与 **Anthropic 原生**协议；
本地 Ollama 也可直接接。凭据存在本机 `data/llm_providers.json`（gitignored，不入库）。
本地模型请**开启 thinking 模式**，否则 ReAct 的推理质量明显下降。

### `app/config.py` 可调项（括号内为对应环境变量）

| 配置 | 含义 | 默认 | 环境变量 |
|---|---|---|---|
| `MAX_STEPS` | 单轮最大步数 | 30 | `AGENT_MAX_STEPS` |
| `TOOL_TIMEOUT` | 单工具总时长(秒) | 600 | `TOOL_TIMEOUT` |
| `TOOL_IDLE_TIMEOUT` | 无输出判卡死(秒)，仅外部工具 | 120 | `TOOL_IDLE_TIMEOUT` |
| `PY_EXEC_TIMEOUT` | 单段代码总时长(秒) | 120 | `PY_EXEC_TIMEOUT` |
| `PY_EXEC_GRADE_ENABLED` | py_exec 静态能力分档开关（关=一律按 L3） | 开 | `AGENT_PY_EXEC_GRADE` |
| `TASK_CONSTRAINTS_ENABLED` | 任务级约束闸门（任务声明「不做字典爆破」时拒绝同类工具） | 开 | `AGENT_TASK_CONSTRAINTS` |
| `CONSOLE_TOKEN_TTL` | 配置控制台登录票据有效期(秒) | 43200 | `AGENT_CONSOLE_TOKEN_TTL` |
| `CONSOLE_CONFIRM_TTL` | 白名单改动的确认票据有效期(秒) | 300 | `AGENT_CONSOLE_CONFIRM_TTL` |
| `CONFIRM_TIMEOUT` | L2/L3 等用户确认上限(秒) | 600 | `AGENT_CONFIRM_TIMEOUT` |
| `MAX_TOOL_SCHEMAS` | 单次决策回传工具数上限 | 40 | `AGENT_MAX_TOOL_SCHEMAS` |
| `FAILURE_SWITCH_THRESHOLD` | 连续失败到几次改为要求「换策略」 | 3 | `AGENT_FAILURE_SWITCH` |
| `FAILURE_STOP_THRESHOLD` | 连续失败到几次才停止 | 6 | `AGENT_FAILURE_STOP` |
| `RUN_TOKEN_BUDGET` | 单次任务 token 预算（成本熔断） | 2500000 | `AGENT_RUN_TOKEN_BUDGET` |
| `PREFERRED_PROVIDER` | 首选供应商（云端优先的解析首位） | deepseek | `AGENT_PREFERRED_PROVIDER` |
| `SUBTASK_MAX_CONCURRENCY` | 子任务并发上限 | 3 | `SUBTASK_MAX_CONCURRENCY` |
| `SUBTASK_MAX_STEPS` | 单个子任务步数上限 | 8 | `SUBTASK_MAX_STEPS` |
| `SUBTASK_MAX_COUNT` | 单次最多拆几个子任务 | 4 | `SUBTASK_MAX_COUNT` |
| `HISTORY_COMPRESS_AFTER_MESSAGES` | 消息数超过多少触发上下文压缩 | 24 | `HISTORY_COMPRESS_AFTER_MESSAGES` |
| `HISTORY_KEEP_RECENT` | 压缩时保留最近多少条原文 | 12 | `HISTORY_KEEP_RECENT` |
| `RESTORE_CHAT_MAX` | 续聊时最多还原多少条历史对话 | 24 | `AGENT_RESTORE_CHAT_MAX` |
| `ENFORCE_SCOPE` | 执行前强制授权白名单 | 开 | `ENFORCE_SCOPE` |
| `CLOUD_EGRESS_MODE` | 云端外发策略：`local_only` 禁发云端 / `redact` 脱敏后上云 / `allow` 原样 | redact | `AGENT_CLOUD_EGRESS` |
| `PORT` / `HOST` | 监听端口 / 地址（非回环默认拒绝启动，`ALLOW_NON_LOOPBACK=1` 显式放行） | 8770 / 127.0.0.1 | `PORT` / `HOST` |

**工具箱路径三级解析**（越靠前越优先，源码里不写死任何路径）：

1. 环境变量 `TOOLBOX_ROOT` —— 跨机协作的正规做法；
2. 本机 `config.yaml` 的 `toolboxRoot` —— 该文件**不入库**，适合放本机路径
   （同一文件也用于存 FOFA 密钥与控制台口令）；
3. 都没有 → 视为**未配置**：启动信息与 `/api/health` 会明确提示（`toolbox_configured: false`），
   工具清单会给出「未配置工具箱根目录」而不是含糊的「找不到工具清单」。

> **未配置工具箱时不会「什么都没得用」**：内置能力（`httpreplay` / `py_exec` /
> `kb_search` / `kb_read` / `note_fact` / `fofa_search` / `code_*` 等，共 19 个）
> **不依赖工具箱**，照常可用；工具面板顶部会同时显示原因与配置方法。
> 缺的只是那批需要工具箱本体的外部工具。白盒侧的代码审计功能（`code_*`）完全可用。

### 其他可手改的配置

- `data/risk_grades.json` —— 工具风险分级（改完在控制台重载）；
- `data/invocation_templates.json` —— 工具调用模板；
- `data/tool_overrides.json` —— 禁用清单 + 参数白名单。

---

## 工具能力边界

工具箱工具 + 10 个内置能力（`httpreplay` / `nuclei_cli` / `note_fact` / `py_exec` /
`search_history` / `propose_branch` / `split_task` / `kb_search` / `kb_read` / `fofa_search`），
其中一部分可编排（有 stdout，能进自动化流水线），其余为图形界面工具（一键启动）与网页工具。
（具体数量随工具箱配置不同。）

可编排工具按风险分为四级：

| 等级 | 含义 | 策略 |
|---|---|---|
| L0 | 只读 / 本地分析 | 自动执行 |
| L1 | 主动探测扫描 | 自动执行（留痕） |
| L2 | 漏洞验证与利用 | 需确认 |
| L3 | 权限 / 横向 / 接管 | 需确认 + 勾选授权（两轮独立确认） |

拒绝执行时 Agent 会自动改用更低风险的工具继续任务。分级可改，见 `data/risk_grades.json`。

---

## 目录结构

```
SRC-Agent/
├── run.py                    启动入口（缺依赖时自动切换解释器并重启自身）
├── requirements.txt          依赖（fastapi / uvicorn / httpx / pyyaml / pytest）
├── 启动控制台.bat             一键启动（GBK + CRLF，含解释器探测）
├── update.py                 更新工具源码（打包为 update.exe 随发布包分发）
├── release_repo.txt          更新源（第一行 owner/repo，改这里即换库）
├── VERSION.txt               版本号（本版 1.004）
├── SHA256SUMS.txt            发布清单（更新器逐文件校验用）
├── config.yaml.example       本机配置模板（复制为 config.yaml 使用，该文件不入库）
├── app/
│   ├── config.py             路径、模型、风险等级、各类超时与上限
│   ├── scope.py              授权白名单唯一实现（executor / replayer / pyexec 共用）
│   ├── registry.py           工具注册表 + 内置能力 + 工作模式闸门
│   ├── executor.py           执行器抽象（工具箱子进程）+ 参数清洗
│   ├── pyexec.py             Python 代码执行通道（py_exec 后端）
│   ├── replayer.py           HTTP 重放器 / nuclei 托管运行器
│   ├── intel.py              项目情报库注入
│   ├── kb.py                 知识库 / 工作流规则检索（data/kb + data/rules）
│   ├── fofa.py               FOFA 资产测绘客户端
│   ├── usage.py              Token 用量聚合与模型单价表
│   ├── providers.py          通用 LLM 供应商注册中心
│   ├── llm.py                模型层：OpenAI 兼容 + Anthropic 原生双协议
│   ├── agent.py              ReAct 单步决策循环（含模式片段、对话树、约束闸门）
│   ├── store.py              SQLite 项目仓储（projects/sessions/steps/findings/intel/facts/usage）
│   ├── report.py             补天格式报告生成
│   ├── console_api.py        配置控制台后端（口令闸门 / 两段式 / 白盒侧）
│   ├── codebase/             白盒审计引擎（入库 / 索引 / 污点 / sink 规则 / 变体分析）
│   └── main.py               FastAPI 后端（本地访问防护 / 项目 / 会话 / 工具接口）
├── console/                  配置控制台前端（原生 ES module，无构建步骤）
├── web/                      作战界面前端（start.html 起始页 + index.html / app.js / style.css）
├── docs/burp-mcp-接入指南.md  把 Burp Suite 接到 Agent 的用法说明
└── data/
    ├── kb/                   知识库（含 KB 索引 README）
    ├── rules/                工作流与合规规则（含不公开规格）
    ├── risk_grades.json      风险分级（可手改）
    ├── invocation_templates.json  工具调用模板（可手改）
    ├── tool_overrides.json   禁用清单 + 参数白名单（可手改）
    ├── scope.example.json    授权白名单模板（复制为 scope.json 再填）
    ├── wordlists/ · tiny_wordlist.txt   内置字典
    ├── scripts/exec/         py_exec 代码留档（运行时生成，不入库）
    └── projects.db           SQLite 数据库（运行时生成，不入库）
```

---

## 已知限制

1. **ENScan 需要过验证码** —— 爱企查数据源会要求浏览器验证，未验证时工具会重试报错。
2. **OneForAll 联网检测** —— 启动时检测 `ip-api.com`，访问不到会告警但仍会执行（子域名收集可能受限）。
3. **GUI 工具无输出** —— 图形界面工具只能启动，Agent 拿不到它们的运行结果。
4. **本地模型决策较慢** —— 单次决策 13~25 秒，复杂任务会更久。默认决策已切云端，只有显式选用
   本地模型时才会遇到；着急时可临时调低 `MAX_STEPS`。
5. **桌面版（窗口壳）随发布包分发** —— `SRC控制台.exe` / `desktop_launcher.py` 不在源码库里；
   用 `启动控制台.bat` 或 `python run.py` 启动时功能完全一致，只是界面呈现在浏览器而非独立窗口。
6. **Anthropic 兼容端点的 tool_use 支持** —— 走 messages API 的标准结构，个别兼容端点对
   function calling 实现不完整时会退化为纯文本，请以实测为准。
7. **线索图前端未接回（后端已就绪）** —— 攻击图 / 因果图的后端路由与 `web/graph.js` 渲染库都在仓库里，
   但 `index.html` 当前未加载 `graph.js`，这些路由属**预留能力**。
8. **授权白名单不区分端口** —— 白名单条目是主机名级（`example.com` 即放行其全部端口）。
   这是设计取舍：SRC 测试通常按主机授权。若需按 `host:port` 收紧，需扩展 `scope.json` 条目格式。
9. **`data/scope.json` 不入库** —— 真实授权数据只在本机；新环境请复制 `data/scope.example.json`
   为 `data/scope.json` 再填授权目标（白名单为空时服务 fail-closed 拒绝一切执行）。
10. **本项目不含回归测试脚本** —— 见「本发布版与工程测试库的差异」。

---

## 合规

仅限已获得**书面授权**的目标测试。L3 级操作（含 `py_exec` 代码执行）需**两次独立确认**才可放行
（后端强制：确认必须绑定当前步骤 id，两轮都 approved 才执行，任何一轮拒绝/超时即取消）。

**绝对不能碰的合规红线（必背）**：禁止测试企业内网 / 内部 OA / 员工办公系统 / 第三方合作平台；
禁止暴力爆破账号、高频端口扫描、DDoS 压测；禁止拖库、批量下载用户隐私数据（确需取证只截图，
不保存、不外传）；禁止植入后门、修改或删除服务器文件、篡改订单 / 密码等真实业务数据；
禁止社工钓鱼与短信轰炸；禁止横向移动（拿到权限后不再向内网其他主机探测）。

完整版见 `data/rules/compliance-redlines.md` —— 它已写入 Agent 的系统提示词（每轮携带），
也可用 `kb_read compliance-redlines` 查阅。

`data/scope.json` 的授权白名单是执行前的**硬闸门**（命令行工具 / HTTP 重放器 / py_exec 共用
`app/scope.py` 一份实现）：白名单为空一律拒绝执行，重放器只允许只读方法（GET/HEAD/OPTIONS）。
服务默认只监听 `127.0.0.1`，并在应用层校验 `Host` 与 `Origin`，拦截跨站请求与 DNS 重绑定。

> 排除某个目标时请写进 `scope.json` 的 `excluded_hosts`，**不要**写进 `targets` ——
> `targets` 里的条目一律按「已授权」放行。
>
> 说明：`Host/Origin` 校验挡的是「浏览器里的其他网页」，`curl` 之类的本地非浏览器客户端仍无鉴权；
> 若需对后者也做鉴权，可在该中间件上加一层 `X-Auth-Token`。
