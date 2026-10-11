> 白盒**npm/JS 生态的工具链与判据**（工具链篇）。姊妹篇：`whitebox-targeting-npm`（**npm 选靶**：四问筛子 / 结构性张力）、
> `whitebox-targeting`（**Java/Maven 选靶**）、`whitebox-guard-review`（**守卫写对没有/我的脚本对不对**）、
> `whitebox-audit-method`（**拿到代码之后怎么审**）、`whitebox-sink-triage`（**命中怎么分类**）、
> `whitebox-recall`（**召回数字怎么读**）、`whitebox-miss-attribution`（**漏报怎么归因**）、
> `whitebox-disclosure-gate`（**找到之后能不能报**）。
>
> 本篇只管**"怎么用工具找、怎么避免假阳性、哪些不要再烧"**；
> **"值不值得打"** → `whitebox-targeting-npm`；**"能不能报"** → `whitebox-disclosure-gate`。

# npm 生态审计工具链与判据

## 一、⭐ 工具链（三组脚本，可复用）

### 1.1 选靶与公开记录

| 脚本 | 作用 |
|---|---|
| `_r11_recon.py` | 候选 → **OSV + GitHub issues/PR（含 closed）三路**公开记录 |
| `_r16_channels.py` | 排查披露渠道（GitHub 私密报告是否开启 / 维护者备用邮箱） |

### 1.2 pattern-first 两段式（第 21 轮）

⚠️ **难点：npm search 按"描述"匹配、不按"代码"匹配** ⇒ 必须两段：

```
① _r21_pool.py     按【描述】捞候选 + 下载量过滤
② _r21_scan.py     批量下载 tarball → 解包 → 本地 grep 源码（排除 test/example/bench/fixture）
③ _r21_scan2.py    对【已下载】的池子复用，再扫另一组模式（零额外下载成本）
```

### 1.3 新代码 diff 流水线（第 22/23 轮，**最终形态**）

```
① _r23_pool2.py    建池：N 个超热门种子的**直接依赖 + peer 依赖并集**
                   （比 npm search 客观：被热门包依赖 = 真实被广泛使用；实测 147 种子 → 620 包）
② _r23_find.py     池内找「最近 N 天有新发布」的包（读 registry 的 time 字段）
                   （实测 620 → 178 个；**当天发布的就有 33 个**）
③ _r23_diff.py     ⭐ 批量 diff 新旧两版 + **对新增行做安全关键词判据**
```

`_r23_diff.py` 的两条关键规则：
1. **只比运行时代码**（`.js/.mjs/.cjs`），排除 `test/spec/example/bench/fixture` 与 `*.min.js/*.map/*.d.ts`；
2. 对 **diff 的新增行**匹配关键词，**只人工细读命中文件**：

```
verify|sign|token|auth|hmac|hash|crypt|sanitiz|escape|validat|compare|
secret|password|session|permission|allow|deny|reject|trust|origin|cors|csrf|
timingSafe|constant.?time|rejectUnauthorized|randomBytes|
includes\(|indexOf\(|startsWith\(|slice\(|substring\(|split\(
```

⚠️ **必须再加一条**（第 23 轮踩到）：**排除打包产物**。
`vite` 命中了 3966 次、`jsdom` 169 次 —— 全是 `dist/node/chunks/*.js` 这种
**把 node_modules 打进单个 chunk** 的产物（单文件 +38236 行）。
判据：**文件行数超阈值、或路径含 `chunks/|bundle|.min.` 一律跳过。**

---

## 二、⚠️ 交付环节的两个坑（**不是选靶，但会让你白干**）

### 2.1 **`Sent` 只证明"发出了"，不证明"送达"**

**判送达的唯一办法：查收件箱有没有退信。**（QQ 退信来自 `PostMaster@qq.com`，主题《来自qq.com的退信》）
实测：第 16 轮的披露**第 1 封发出 5 秒就被退信**，若不查收件箱会以为"已联系厂商"。

### 2.2 **给 Gmail 发安全报告：别附可执行附件**

实测：带 `PoC_poc.mjs` 的第 1 封被退，Gmail 的理由是
`552-5.7.0 This message was blocked because its content presents a potential security issue
… https://support.google.com/mail/?p=BlockedMessage`
换成**只附 `.md`** 后即送达并被维护者读到（第 2 封 → 对方回信确认）。

⇒ **安全报告附件优先级**：`.md` / `.txt` ✅ ＞ 内联纯文本 ✅ ≫ **`.js`/`.mjs`/可执行 ❌**。

---

## 三、npm 侧的高频假阳性（三个都实测过）

| 陷阱 | 表现 | 怎么识别 |
|---|---|---|
| **纯原语 ≠ 校验器** | 扫「算了 HMAC 却不用 `timingSafeEqual`」时命中 12/60，**真阳性 0** | 通读：`oauth-sign`/`aws4` 只**签名**不校验；`@noble/hashes`/`fast-sha256` 是 HMAC **实现** |
| **打包产物** | 关键词命中数虚高几十倍 | 见 §一 1.3 |
| **压缩/单行文件** | 整文件一行 ⇒ 关键词"同现"全是假的 | 行数阈值过滤 |

⭐ **反向观察**：**真正的签名校验器反而都用了 `timingSafeEqual`**
（三个头部包 `standardwebhooks` / `cookie-signature` / `buffer-equal-constant-time` 正读全部正确）
⇒ **这个模式在头部生态已被写对**，不值得再烧。

---

## 四、⚠️ 三条"看起来像洞但不是"的形态（别报，报错会掉信誉）

| 形态 | 实例（哪个轮次） | 为什么不是 |
|---|---|---|
| **危险的默认值** | 某 GraphQL 防护插件的白名单默认含 `__typename` ⇒ 把字段别名成 `__typename` 即不计数（第 18 轮） | **官方文档写明**该语义 ⇒ 闸 1 形态② |
| **parser-differential 的不对称** | 某 JWT 库新增的校验函数只在**签名/加密**路径被调用，**校验/解密**路径未调用（第 22 轮） | 校验路径上**签名验证仍必须通过** ⇒ 伪造不了任何东西 |
| **不可达的边界** | 某 ID 生成器的 2⁶⁴ 计数器回绕（第 20 轮）；某调度库的 `updateSettings` 卡死（第 17 轮） | 需天文数字次调用 / 无攻击者可控路径 |

**共同的判定动作**：先问 **"攻击者能做什么？失败让我多放行了吗？"** —— 两问都否 ⇒ **不报**。

---

## 五、不烧清单（23 轮积累，**先看这个再开工**）

```
路径包含判定（startsWith '..'）    shell 转义器        模板沙箱（handlebars/liquidjs）
序列化器（xlsx 等 7/9 有公告）      文件竞态（proper-lockfile/tmp）
resolve-path                       ssrf-req-filter（PR 已合未发）
stale-while-revalidate-cache       纯 OTP 原语（speakeasy / notp：fails-CLOSED + 调用方责任）
弹性库（cockatiel：防护对象是"故障"）  webhook 签名赛道（除 standardwebhooks 外无上量组件）
CORS / 开放重定向 / 客户端 IP 信任   限流子网（IPv4-mapped 整类已修）
ULID / 雪花 ID（参考实现已验证正确）   decimal / bignumber 族（已审透）
校验类比较（timingSafeEqual 用法）   已通读的加固版本（@node-rs/bcrypt / cookies /
compression / jose / oracledb 新 token 插件）
```

---

## 六、⚠️ 本机工具坑（做这套流水线会踩到）

- **bash 里文件名含括号、或命令含反引号** ⇒ 解析失败（`unexpected EOF`）。
  改用**脚本文件**或换文件名。
- **Python/Bash 偶发 SIGTERM** ⇒ **重试即可**（不是代码问题）。
- **npm registry 全量元数据很慢**（`@aws-sdk/*` 这类版本数上千）⇒ 长脚本用**后台运行**，
  别在前台等。
- **`Edit` 报 "String not found"** ⇒ 先回去**逐字核对原文**（少一个字/一个标点都会不匹配）。
