# Burp Suite MCP 接入指南（v044）

本文档说明如何把 Burp Suite 的 MCP 服务接上 src-agent，以及**为什么这样接**。

---

## 一、总体架构

```
┌──────────────┐   MCP(JSON-RPC over SSE)   ┌─────────────────────┐
│  src-agent   │ ──────────────────────────► │  Burp Suite (Pro)   │
│  (Python)    │   http://127.0.0.1:9876    │  ┌───────────────┐  │
│              │                             │  │ MCP Server 扩展│  │
│ mcp_client.py│ ◄────────────────────────── │  └───────┬───────┘  │
│ burp_tools.py│     工具结果 / 响应正文      │          │          │
└──────┬───────┘                             │  ┌───────▼───────┐  │
       │                                     │  │  Montoya API  │  │
       │ 出网请求必须过 TrafficGovernor      │  └───────┬───────┘  │
       │ (限速/预算/WAF状态机/审计)          │          │          │
       └─── scope.check_scope() 授权校验 ────┼──►  真实目标      │
                                             └─────────────────────┘
```

**证据留痕**（⚠️ 2026-09-22 真机实测**纠正了原先的设想**）：
经 `burp_replay` 发出的请求**不会**落进 Burp Proxy history ——
官方扩展是在扩展内部直接构造并发出请求，不经 Proxy 监听器。
实测对照：经本通道发出真实 GET，目标回了 301，而同一次会话里
`get_proxy_http_history` / `get_organizer_items` / `get_proxy_websocket_history`
三个历史区**全部为空**。

所以两个工具的分工是**互补**而非闭环：

| 工具 | 拿到什么 | 数据来源 |
|------|---------|---------|
| `burp_replay` | 本次请求的**请求 + 响应**（在它自己的返回值里） | 直接发起 |
| `burp_history` | 操作者**手工在 Burp 里抓的包** | Proxy / Organizer / WS history |

**推荐的协作模式**：人在 Burp 里手工浏览目标 → Agent 用 `burp_history`
读取并分析那些流量 → 挑出值得深挖的请求 → 用 `burp_replay` 改包重放。
即「人抓包 + Agent 分析重放」，而不是「Agent 发完再自己读回来」。

---

## 二、前置准备（一次性）

### 1. 加载 MCP Server 扩展

本机已编译好的 jar 在：

```
E:\vulnclaw\burp-mcp\build\libs\burp-mcp-all.jar
```

（若需重新编译：`cd E:\vulnclaw\burp-mcp && .\gradlew.bat embedProxyJar`，
需要 JDK 21 —— 本机在 `E:\bin\java.exe`）

在 Burp 里：**Extensions → Installed → Add**
- Extension type: `Java`
- Select file: 选上面那个 jar
- 点 Next

### 2. 启动 MCP 服务

加载后会多出 **MCP** 标签页 → 点 **Start**。

验证：`netstat -ano | findstr 9876` 应看到 LISTENING。

### 3. 配置目标审批白名单（**关键安全步骤**）

MCP 标签页里找到 **Auto-approve targets**，把 `data/scope.json` 里的授权域
**逐个**加进去：

**本文档刻意不列出授权域清单** —— 以本机 `data/scope.json` 为准，用下面的命令导出：

```bash
python -c "import sys;sys.path.insert(0,'.');from app import scope;print('\n'.join(scope.load_scope()))"
```

把导出结果**逐行**填进 Burp 的 Auto-approve targets，形如：

```
example.com
www.example.com
*.example.com
```

> 上面是占位示例，**不是**真实清单。
>
> 为什么不在文档里写真实域名：本仓库是 **public**，而授权目标是**交战数据**。
> `data/scope.json` 被 gitignore 的理由正是这条；文档里顺手列一份等于绕开它
> —— 而这个口子比那个文件更隐蔽（谁会去看文档中间的一个代码块？）。
>
> 通配（`*.example.com`）比 `scope.json` 的匹配**更宽**，用之前请确认等价或更严。

这一步的意义：**Burp 侧的审批闸门与 Agent 侧的 scope.json 形成两道独立闸门**。
任何一侧配错，另一侧仍能拦住越权请求。

### 4. 检查上游代理（易踩坑）

`Burp → Settings → Network → Connections → Upstream Proxy Servers`

**必须为空**，或指向真正的外部代理。**绝不要填 `127.0.0.1:8080`** ——
那会让 Burp 把自己的流量转发给自己，形成套娃死循环。

Agent 会在 `/api/health` 里自动体检这项配置并给出告警
（见 `mcp_client.check_proxy_sanity()`）。

---

## 三、Agent 侧配置（环境变量）

全部有合理默认值，通常**不需要改**：

| 变量 | 默认 | 说明 |
|---|---|---|
| `AGENT_MCP_ENABLED` | `1` | 总开关。设 `0` 则完全不连 MCP，工具清单里无 `burp_*` |
| `AGENT_MCP_BURP_URL` | `http://127.0.0.1:9876` | SSE 端点基址 |
| `AGENT_MCP_CALL_TIMEOUT` | `120` | 单次调用超时（秒）。**要留足人工点 Allow 的时间** |
| `AGENT_MCP_ALLOW_REMOTE` | `0` | 是否允许连非回环端点。默认拒绝（安全边界） |
| `AGENT_MCP_REQUIRE_APPROVAL` | `1` | 仅作提示文本；真正闸门在 Burp 扩展里 |

---

## 四、可用工具

### `burp_replay`（L2，**会出网**）

把一段 raw HTTP 请求交给 Burp 发出。

- **target**：完整 URL，如 `https://example.com/api/login`
- **args**：**整段 raw HTTP 请求文本**，含起始行 + Host 头 + 末尾空行

```
GET /api/user/1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*

```

允许方法：`GET/HEAD/OPTIONS/POST/PUT/PATCH`
**禁止**：`DELETE`（SRC 场景无验证价值且有破坏性）

### `burp_history`（L0，**不出网**）

读取 Burp 的历史记录区（Proxy HTTP / WebSocket）。

- `regex=<正则>` 按内容过滤（如 `regex=login|token|admin`）
- `count=<N>` `offset=<N>` 翻页（默认 20，上限 100）

> 返回 `Reached end of items` = **没有更多条目**（offset 越界 **或** 该区本来就空），
> **不是错误**。经 `burp_replay` 发出的请求不会出现在这里。

---

## 五、与 `httpreplay` 的分工

| | `httpreplay` | `burp_replay` |
|---|---|---|
| 出网路径 | Agent 直连 | 经 Burp |
| 依赖 | 无 | Burp 在线 + MCP Start |
| 方法限制 | 只读（GET/HEAD/OPTIONS） | 含 POST/PUT/PATCH |
| 人工闸门 | 无 | 有（可配 auto-approve） |
| 留档 | 落盘到会话目录 | **不落 history**，响应只在返回值里 |
| 适用 | 默认选择、快速单点验证 | 需要 Burp 的 TLS/代理链、与手工会话同出口 |

**两者都过 `TrafficGovernor`**，额度合并计算，不存在「换工具绕限速」。

---

## 六、故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 工具清单里没有 `burp_replay` | Burp 没开 / 扩展没加载 / 没点 Start | 看 `/api/health` 的 `mcp.note` |
| 报「连不上 MCP 服务」 | 同上 | 同上（这是**预期降级**，不是崩溃） |
| 请求超时很久 | 等人工点 Allow 弹窗 | 或配 auto-approve targets |
| 报「用户在 Burp 侧拒绝」 | 人工闸门行使否决权 | **不要重试同一请求**，换思路 |
| 请求死循环超时 | Burp 上游代理指向自身 | 清空 Upstream Proxy Servers |
| `burp_history` 一直空 | Burp 里确实没抓过包（**重放不会落 history**） | 先在 Burp 里手工浏览目标 |
| 报 `Encountered an unknown key 'xxx'` | 扩展升级后参数名变了 | 用 `tools/list` 重新核对 schema（见下节契约测试） |

---

## 七、设计取舍记录

**为什么不用第三方 MCP SDK**：
1. 项目所有出网必须过 `TrafficGovernor`，SDK 会把传输层包起来，无法在
   「真正发出请求」那一刻插入治理。
2. 隔离环境每加一个依赖就多一份供应链面；MCP 的 JSON-RPC 部分很小。
3. 需要「优雅降级」语义（Burp 没开是常态），自研可直接写死行为。

**为什么 `trust_env=False`**：
Burp 自己就是代理（本机 8080）。若 MCP 连接走了 WorkBuddy 的会话代理
（端口每次会话都不同，实测见过 58637、62063），会形成「代理连代理」。
这与 `httpreplay` / `fofa` / `llm` 的既有约定一致。

**为什么不发浏览器 UA**：
官方扩展有反 DNS-rebinding 检查，带 `Mozilla`/`Chrome` 等关键字的 UA 会被
直接 403（见其 `KtorServerManager.isBrowserRequest`）。

**为什么每轮刷新可用性**：
Burp 可能中途被关掉或刚被启动。工具留在 schema 里但服务不可用，会让模型
把步数与 token 烧在必然失败的调用上，还会把「工具报错」误判成「目标不可达」。

**为什么 SSE 路径要运行时探测**：
官方扩展 v1.3.0 实测端点在**根路径 `/`**（Kotlin SDK 的 `Server.mcp(path=...)`
默认 `path="/"`），而 MCP 规范文档与部分实现用 `/mcp`。写死任一个都会在
另一种实现上 404。客户端按 `["/", "/mcp", "/sse"]` 依次探测 + 校验
`content-type: text/event-stream`，谁先给出合法 endpoint 就用谁。

**为什么 POST 不看响应体**：
MCP 的 SSE 传输语义是「POST 只负责投递」——服务端回 `202 Accepted` 空体，
真正的 JSON-RPC 响应经长连接以 `event: message` 推回。早先的实现把 POST
响应体当结果解析，拿到 `'Accepted'` 字符串后在 `json.loads` 处报错，
一度被误判成「服务端异常」。正确做法是常驻一条读流（`_SSEReader`）按 id 匹配。
（客户端仍保留「POST 直接回 JSON」的兼容分支，因为部分实现确实这么做。）

**为什么读流器要绑定事件循环**：
asyncio 的对象不能跨循环使用。若在循环 A 建了连接却在新循环 B 里 await，
会得到 `Event loop is closed`。生产环境对应 worker 重启，测试里对应每次
`asyncio.run()`。客户端在 `_ensure_initialized` / `probe` / `call_tool`
三处统一做循环比对，发现变了就整体重连，而不是要求调用方小心。

**为什么参数名要写成契约测试**：
Burp 扩展升级可能改参数名，运行期只会拿到一句
`Encountered an unknown key 'url'`（实测踩过两次）。`test_044_mcp.py` 的
`[A3]` 组用真机读出的 schema 固化了一张表，参数名一变回归就红。
