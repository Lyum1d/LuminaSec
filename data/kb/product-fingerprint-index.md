# 产品指纹 → 敏感路径基线（常见 CMS / 邮件 / 网盘 / 框架）

> **这个篇目解决什么**：指纹识别出产品之后，**直接知道该验证哪些路径**，而不是凭记忆猜。
> 实测背景：`kb_search("KodExplorer 未授权")` 曾零命中 → agent 只能靠记忆撞路径，
> 在某高校实战中**白耗 2 次请求撞 403**。知识库过去只按「漏洞类型」组织，缺「按产品」这一维。
>
> **使用纪律（硬约束）**：本表所有路径**只做只读 GET/HEAD**；**只验证存在性**
> （状态码 + 长度 + 与基线的差分），**不下载内容、不试口令、不遍历**。
> **403 只记存在性、不上报**（除非能证明绕过）。**已公开引用的静态资源返回 200 不算命中。**

## 一、用法

1. 先用 `ehole` / `httpx` 拿到**产品指纹**；
2. 在下表找到对应产品 → 取「优先验证路径」；
3. **串行、逐点、带间隔**地打（每路径 ≤1 次，用内置小字典见 `data/wordlists/common-small.txt`）；
4. 记录「状态码 + 长度」，**用差分判存在性**（见第二节）。

## 二、动手前先建「404 差分基线」（通用，强烈建议）

很多 CMS 会返回**两套 404 页面**：**应用层 404**（框架接管）与 **Web 服务器原生 404**。
先各取一个样本、记录长度，之后任何 404 命中哪一套，就能判断**该路径是否落在应用路由内**。

> 实测（某高校 TRS 站群）：`404 + 2357 字节` = 被 TRS CMS 路由接管（该命名空间**真实存在**）；
> `404 + 1627 字节` = VWebServer 原生未命中（路径**根本不存在**）。
> 这个判据比只看状态码精确得多，且**零额外成本**（反正要测路径存在性）。

## 三、按产品

### 拓尔思 TRS SiteBuilder / VWebServer（高校/政府站群常见）

| 项 | 内容 |
| --- | --- |
| **识别特征** | `Server: VWebServer` 或 `VAppServer`；页面注释 `Announced by Visual SiteBuilder 9`；资源路径含 `_sitegray/`；首页含 `CustomerNO:` 注释 |
| **优先验证** | `/system/`、`/system/resource/`、`/system/login.jsp`（后台）、`/_sitegray/`、`/system/resource/js/`（目录列表） |
| **要点** | 后台 `/system/login.jsp` **通常不公网暴露**（返回 404）；`/system/resource/js/*.js` 是**首页本就引用**的公开资源（200 **不算**命中）；**404 双模板差分**是该 CMS 的天然判据 |

### RainLoop WebMail（开源 PHP 邮件前端）

| 项 | 内容 |
| --- | --- |
| **识别特征** | `Server: RainLoop`（**响应头直接返回产品名**）；页面含 `rainloop`；默认界面为 webmail 登录 |
| **优先验证** | `/?/Admin/`（管理面板）、`/?/admin/`、`/data/`、`/version`、`/index.php` |
| **要点** | `/?/Admin/` 返回 **200 = 管理面板入口公网暴露** —— 但**可达 ≠ 可利用**：是否可登录取决于弱口令/未授权功能，**禁试口令**，只记存在性；**`/data/` 返回 403 = 有防护**（该目录历史上是可访问的高危点，被拦住说明部署有基础防护，**不要按"默认不安全"推定**） |

### KodExplorer / 可道云（网盘类）

| 项 | 内容 |
| --- | --- |
| **识别特征** | 页面标题含 `Powered by KodExplorer`；路由形态 `index.php?user/login`；ehole 常报 `Kodcloud-System` |
| **优先验证** | `/data/`（历史高频高危：用户配置与会话）、`/data/system/`、`/index.php?user/login`、`/plugins/` |
| **要点** | **`/data/` 是这类产品的核心验证点**：可访问则可能泄露用户配置 → 高危；返回 **403/404 即为有防护** |

### Spring Boot Actuator

| 项 | 内容 |
| --- | --- |
| **识别特征** | 错误页为标准 JSON（`{"timestamp":...,"status":404,"error":"Not Found","message":"No message available","path":"..."}`）；`/v3/api-docs` 返回 JSON |
| **优先验证** | `/actuator`、`/actuator/health`、`/actuator/env`、`/actuator/heapdump`、`/env`、`/health` |
| **要点** | **先只看状态码**：`/actuator/env` 若 200，说明配置可读（**高危**）——但按纪律**只记录存在性，不读取内容** |

### Swagger / Knife4j（API 文档）

| 项 | 内容 |
| --- | --- |
| **识别特征** | `/doc.html`、`/swagger-resources` 可达；根路径 302 → `/doc.html` 是典型特征 |
| **优先验证** | `/doc.html`、`/swagger-resources`、`/swagger-resources/configuration/security`、`/swagger-resources/configuration/ui`、`/v2/api-docs`、`/v3/api-docs` |
| **要点** | ⚠️ **必须区分「文档外壳可达」与「接口定义可读」**：前者只是 UI 页面（**低危**），后者才暴露全部接口与参数模型（**严重**）。实测（某 Java 站点）：`/doc.html` 与 `/swagger-resources` 均 200，但 `/v2/api-docs` **403** —— 属于「门开着、数据源关着」，**不得写成接口泄露** |

## 四、高校 / 政企常见业务系统（**二级系统的真正入口**）

> 补充动机（v040，某高校实战第三轮反馈）：原表只有 5 个条目，**对高校二级系统最常见的教务与 OA
> 厂商完全没有覆盖** —— 就算测到了 `jwgl`（教务管理），仍要凭记忆猜路径。以下按「指纹 → 路径」补齐。

| 系统 | 识别特征（指纹） | 优先验证路径 | 要点 |
| --- | --- | --- | --- |
| **强智教务**（QFPU） | 路径含 `jsxsd` / `qf` / `Logintype`；页面「强智科技」 | `/jsxsd/`、`/jsxsd/framework/main.jsp`、`/jsxsd/Logintype` | 老版本有未授权访问与 SQL 注入；**只验证状态码，不做参数遍历** |
| **正方教务** | 路径含 `jwglxt`；页面「正方软件」 | `/jwglxt/`、`/jwglxt/xtgl/login_slogin.html` | 默认口令是历史问题，**禁试口令**，只记入口存在性 |
| **金智教务** | 路径含 `eams` / `urp`；页面「金智教育」 | `/eams/`、`/urp/` | 同上 |
| **泛微 OA**（e-cology） | 路径含 `/wui/` `/weaver/`；`ecology_JSessionid` Cookie | `/wui/index.html`、`/weaver/bsh.servlet.BshServlet`、`/mobile/plugin/1/` | 历史高危（BshServlet 命令执行、未授权读文件）——**只验证端点存在性（状态码），绝不执行命令** |
| **致远 OA**（A8） | 路径含 `/seeyon/`；`JSESSIONID` + `loginPage.do` | `/seeyon/index.jsp`、`/seeyon/htmlofficeservlet` | 同上，只记存在性 |
| **蓝凌 OA**（EKP） | 路径含 `/ekp/` `/sys/` | `/ekp/`、`/sys/ui/` | 同上 |
| **禅道 / Jira** | 页面「ZenTao」/「Atlassian Jira」 | `/zentao/`、`/login.jsp`、`/secure/Dashboard.jspa` | 禅道历史 SQL 注入，**只验证状态码** |
| **图书馆系统** | 页面「汇文」/「Folio」/「Interlib」 | `/opac/`、`/opac/search` | — |
| **VPN / 网关** | 页面含 `Sangfor` / `iNode` / `Juniper` / `EasyConnect` | `/por/login_psw.csp`、`/dana-na/` | 记录型号与版本即可，**禁口令尝试** |
| **联奕科技 认证平台**（lyuap） | 标题「统一身份认证平台」/「微服务认证管理平台」；路径 `/lyuapServer/`；TAG `lyasp`；页脚 `LIANYI TECHNOLOGY` | `/lyuapServer/login`、`/api/uap/unauthorize/pageInfo`、前端包 `assets/js/app.<hash>.js`；常伴生 `:4102`「安全中心」 | ⚠️ **前端包是重点**：实测该校前端 `app_config_names` 模块里**明文发布了 RSA 私钥**（`private_exponent` + `modulus` + `public_exponent`）。拿到前端包先 grep `private_exponent` |

### ⭐ 已知泄露模式速查（**按产品直接定位"通常泄在哪"**）

> 这张表比路径表更值钱：它把「该看什么」直接对应到「**历史上真的泄过什么**」。
> 全部为只读验证点，**不涉及任何提交/口令动作**。

| 产品 | 已知泄露模式（只读可验证） |
| --- | --- |
| **联奕 lyuap / lyasp**（认证平台） | ① 前端 JS 包内**明文 RSA 私钥指数**（`private_exponent`）；② `/api/uap/unauthorize/pageInfo` 未授权即可读；③ 常伴生 `:4102` 安全中心（**注意核对是否与主站共用同一 `modulus`**） |
| **RainLoop** | `/?/Admin/` 管理面板入口可达；`/data/` 历史高危（**403/404 即已防护**）；版本号明文于 `rainloop/v/<版本>/` |
| **KodExplorer / 可道云** | `/data/`（用户配置与会话，**403/404 即已防护**）；`/?user/checkCode` 等未授权接口 |
| **TRS SiteBuilder 9** | 首页注释泄露 `CustomerNO:` 与 `Announced by Visual Site Builder 9`；404 双模板差分（应用层 vs Web 服务器原生） |
| **Spring Boot Actuator** | `/actuator/env`、`/actuator/heapdump` 未授权可读即高危（**只验证状态码，不读内容**） |
| **Swagger / Knife4j** | 区分「文档外壳可达」与「`/v2/api-docs` 接口定义可读」——**前者低危，后者严重** |

### 🔑 跨资产密钥比对该怎么做（v042 固化为标准动作）

拿到任何**密钥材料**（RSA `modulus`、token、AK/SK、Cookie 签名密钥）时，**多花一步做跨资产比对**：
抽出该材料做 hash/前缀比对，看**同一目标的其他资产是否共用同一把**。
**命中即升严重度** —— 实测（某高校实战第四轮）：正因比对发现 `rz` 主站与 `:4102` **共用同一 modulus**，
而 `:4102` 只有公钥、主站却多了私钥，才把结论从「单点字符串可疑」**钉成「打包误发私钥、影响全部接入系统」**。

**配套纪律**：拿到候选密钥后，**先在本地零出网验证其功能可用性**（如 RSA 验 `pow(pow(m,e,n),d,n)==m`），
再决定是否需要申请更高风险等级的验证动作 —— 本轮靠这一条零请求即完成了定级跃升。

### ⭐ 指纹名 → 索引小节 的对照（**机械映射，别靠人工读表**）

| 工具输出的指纹名 | 对应本表小节 |
| --- | --- |
| `Kodcloud-System` | KodExplorer（可道云） |
| `RainLoop` | RainLoop WebMail |
| `VAppServer` / `VWebServer` / `Visual SiteBuilder` | 拓尔思 TRS SiteBuilder |
| `Spring Boot` / JSON 404 页 | Spring Boot Actuator |
| `Swagger` / `Knife4j` / `doc.html` | Swagger / Knife4j |
| `Weaver` / `ecology` | 泛微 OA |
| `Seeyon` | 致远 OA |

> 用法：`ehole` 的输出指纹名 → 查上表 → 定位到对应小节 → 取该产品的优先验证路径。

## 五、通用敏感路径（任何目标都可小步验证）

| 类别 | 路径 |
| --- | --- |
| 备份文件 | `/backup.zip`、`/www.zip`、`/web.zip`、`/database.sql`、`/index.php.bak` |
| 编辑器残留 | `/ewebeditor/`、`/fckeditor/`、`/ueditor/`、`/.swp` |
| 配置文件 | `/.env`、`/config.php`、`/web.config`、`/.git/config`、`/.svn/entries` |
| 上传目录 | `/upload/`、`/uploads/`、`/userfiles/`、`/attachment/` |
| 接口文档 | `/api-docs`、`/swagger-ui.html`、`/doc.html` |
| 目录列表 | `/data/`、`/files/`、`/logs/`、`/temp/` |

> ⚠️ **敏感后缀必须分散**（`.zip`/`.sql`/`.env`/`.git` 不要连续请求）——实测会触发目标 IPS
> **直接封禁源 IP**。要探这类路径时，与普通路径**交错着打**、带间隔、少量。

## 六、这套基线的实际战绩（可参考的期望值）

- **某 Java 站点**：靠 Swagger 基线判出「文档外壳 200 / 接口定义 403」，避免把低危写成高危
- **某高校站群**：靠 404 双模板基准确认「站群后台与上传面未公网暴露」；
  RainLoop `/data/` 403 判为「有防护」而非敞口
- **反例**：某高校首轮**没跑目录扫描**时，这些结论一个都拿不到 —— **阴性结论也需要"扫过"才成立**
