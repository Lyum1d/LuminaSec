> 白盒**怎么读命中**（分类篇）。姊妹篇：`whitebox-targeting`（**打哪个目标**）、`whitebox-guard-review`（**守卫写对没有/我的脚本对不对**）、`whitebox-audit-method`（**拿到代码之后怎么审**）、`whitebox-recall`（**召回数字怎么读**）、`whitebox-miss-attribution`（**漏报怎么归因**）、`whitebox-disclosure-gate`（**找到之后能不能报**）。检索层给你一堆 `文件:行号`，**那全是候选不是漏洞** —— 本篇讲怎么把命中分成「真候选 / 需补链 / 已知误报」三类，以及每条规则能信到几分。查完怎么走流程见 `whitebox-audit-method`。一句话：**`sink` 命中的意思是「这里有个危险调用」，不是「有漏洞」。**
> ⭐ npm/JS 生态另见 `whitebox-targeting-npm`（选靶）、`whitebox-toolchain-npm`（工具链）。

# Sink 命中分类手册

## 一、规则库全貌

| 语言 | 条数 | 抽取方式 |
|---|---|---|
| `php` | 17 | 词法（lexical） |
| `javascript` | 16 | 词法（lexical） |
| `python` | 14 | **AST（精确）** |
| `java` | 13 | 词法（lexical） |
| `*`（通用，跨语言） | 3 | 词法 |
| **合计** | **63** | |

⚠️ **只有 Python 走 AST**（有内置 `ast` 模块）。其余是**词法抽取** —— 每条命中带 `extractor` 字段，**看到 `lexical` 就要多想一步**：它认不出「这行在注释里」，也认不出「这个字符串是给人看的文案」。

### ⚠️ `@taint` / `@runner` 后缀 = **证据强度更低**的另两类命中

`rule_id` 带后缀表示这条命中**不是**行级直接看到的，而是靠**同一函数内的追踪**推出来的：

| 后缀 | 通道 | 形态（看 `why`/`hint` 已写明） | `extractor` | 该怎么对待 |
|---|---|---|---|---|
| （无） | **行级** | 这一行本身就危险：`executeQuery("..." + param)` | `lexical` / `ast` | 正常走 Phase 3 |
| `@taint` | **跨行污染** | **危险值**在别处拼好，这里只把变量传进来 | `taint(lexical)` | **先往上读那个变量的赋值行**，确认它确实由外部输入拼成 |
| `@runner` | **执行器变量** | **执行器**在别处取得（`Runtime r = Runtime.getRuntime()` → `r.exec(...)`） | `runner` | **往上读赋值行**确认执行器来源，再判参数是否可控 |

```java
String sql = "{call " + param + "}";  // ← 危险在这里（上一行）
stmt = conn.prepareCall(sql);        // ← @taint 命中打在这一行
Runtime r = Runtime.getRuntime();    // ← 执行器在这里取得
Process p = r.exec("echo " + param); // ← @runner 命中打在这一行
```

⚠️ 三个通道**可能同时命中同一行** —— 不是重复，是**性质不同的线索**。
⚠️ **两个间接通道只覆盖 4 条 / 1 条规则**：`@taint` 仅 `java.rce.runtime_exec`/`java.sqli.concat`/`java.path.file`/`java.ssrf.url`；
`@runner` 仅 `java.rce.runtime_exec`。**其余规则无这两条通道**，同样写法在别类上仍会漏（**已知边界**）。
⚠️ `java.rce.runtime_exec`/`java.path.file` 的 `call_pattern` 与 `pattern` **逐字节相同** → 那条 `@taint` **纯冗余**（**已知项**，见 `test_072`）。
⚠️ **`@runner` 不做成「放宽 `\.exec\(`」**：那会匹配**任意对象**的同名 `exec`，是裸奔。正确做法是**变量层面的类型判定** —— 只有调用者确实来自 `Runtime.getRuntime()` / `new ProcessBuilder(...)` 才算。

### ⚠️ 调用名白名单：覆盖的**第三个维度**（v091）

一条规则能不能命中，取决于三件事：① 行级 `pattern` 写没写对；② 有没有 `call_pattern` 通道；
③ **`call_pattern` 里枚举了哪些「调用名」**。第三点最容易被忘掉 ——
它的失效**不是"规则写错了"，而是"那批 sink 名压根不在名单里"**，看代码不容易显形。

实测（OWASP BenchmarkJava v1.2，2026-10-07）：`java.sqli.concat` 的 **34 例漏报里 21 例（62%）**
走 **Spring `JdbcTemplate`**，而名单里当时只有 JDBC/JPA 的 8 个名字：

| 曾漏（v091 补上） | 形态 |
|---|---|
| `queryForObject` / `queryForList` / `queryForMap` / `queryForRowSet` / `queryForLong` / `queryForInt` | Spring `JdbcTemplate` 查询 |
| `batchUpdate` / `executeBatch` | 批处理 |

⚠️ **补上后只挂 `@taint` 通道，不加进行级 `pattern`** —— 两个通道**证据强度不同**
（"同行拼接" vs "变量来自别处"），合并就分不清了。**能分开的证据就别合并。**
⚠️ **刻意不收裸 `query` / `update`**：实测把它们一起收进来，召回与误报**一个都没变**
（54/64、误报 30/43 完全相同）—— "更宽"在这里**没买到任何东西**，那就不买
（与 v069 删掉宽口径 `\.load\s*\(` 同一判据）。

⭐ **诊断法（可复用）**：某类召回低时，先问「**这批漏报用例到底调用了什么**」——
把漏报文件的 sink 行捞出来看调用名，通常一眼就能分出是**"名字没覆盖"**还是**"值没传进来"**。
⚠️ 别急着归因成"多行调用"这类含糊说法：**调用侧**（v069 已修）与**赋值侧**（v090 才修）是两回事，
量之前必须说清是哪一侧（详见 `whitebox-miss-attribution` §一第 2 条）。

**13 个 `kind`**（用 `code_search sink <kind>` 收窄）：

| kind | 数 | 说明 |
|---|---|---|
| `rce` | 17 | 命令/代码执行、文件包含 |
| `deserialization` | 7 | 不安全反序列化 |
| `path_traversal` | 7 | 路径穿越 |
| `sqli` | 6 | 含 NoSQL |
| `xss` | 6 | |
| `weak_crypto` | 5 | 弱算法/不安全随机 |
| `ssrf` | 4 | |
| `hardcoded_secret` | 3 | **通用规则**，硬编码凭据 |
| `ssti` | 2 | |
| `auth_bypass` | 2 | JWT/鉴权 |
| `debug` | 2 | |
| `open_redirect` | 1 | |
| `xxe` | 1 | |

⚠️ **某语言没有某 kind 是常态，不是缺口**（Java 无 `hardcoded_secret`＝通用规则覆盖、PHP 无 `xxe`）。**判断"有没有漏"看 kind 覆盖，不按语言数条数。**

---

## 二、命中的三类归宿

拿到一条命中，**先分类再动手**：

| 类 | 特征 | 动作 |
|---|---|---|
| **① 真候选** | `kind` 是 `rce`/`deserialization`/`sqli` 这类**直接危险**的；`why` 无"宽口径"自限；该行**明显在处理外部输入**（`$_GET`/`request.args`/`@RequestParam`） | `code_read <id> <file>:<line> 30` 读上下文 → 走 Phase 3 逆向 |
| **② 需判定层补链** | 命中在**输入采集文件**但 sink 在**另一个文件**；`scope` 空且文件无函数（**include 片段**，如 DVWA `source/*.php`）; `kind=xss` 但拼的是**数据库结果变量** | ⚠️ **不是"规则漏了"，是架构使然** —— **别放宽规则硬凑** |
| **③ 已知误报形态** | `why` 自己写着"宽口径"（如 `php.xss.echo_var`）；命中在**测例/文档/注释**；命中在**安全实现版**（`impossible.php`） | **记下来但别当洞**，**累积成负样本**守回归，不要改规则盖掉 |

---

## 三、⭐ 两条 DVWA 实测得来的硬结论

### 结论 1：期望值**按「sink 在哪」写，不按文件名写**

DVWA 采用**输入/输出分离**架构：`fi` 模块的输入在 `source/low.php`（只有 `$file = $_GET['page'];`），**sink 在 `fi/index.php:36`（`include( $file );`）**；`xss_s`（存储型）的输出点拼的是**数据库结果变量**、不在 `source/` 里。**教训**：拿 `source/low.php` 当期望位置，会得出"工具没打中"的**错误结论** —— 实际是**期望写错了**。⚠️ **跨文件链路是判定层（模型）的活** —— **靠放宽规则硬凑会让全仓库疯狂误报。**
**已知边界（不是 bug）**：存储型 XSS 的输出点常常命不中（拼的是数据库结果变量，没有超级全局变量）。

### 结论 2：**`impossible.php` 是现成的真实负样本**

DVWA 每个模块自带一份 **`source/impossible.php` = 安全实现版**。⚠️ **但用它当负样本必须限定文件范围**：仓库别处当然会命中这些规则（实测 237 处），不限定范围的话负样本**永远"失败"**，等于没测 —— 这是 `forbid_in` 字段的由来。**推广**：验证"规则是否误报"**不要**拿全仓库当负样本，要**挑出明确安全的那个文件/版本**。

---

## 三·五、召回口径与漏报归因 → **已整块移到两篇**

> **`whitebox-recall`**（数字怎么读）讲：**分母口径**（「标注 ∩ 检出」）、**kind 级 vs 文件级**、
> **精确性的误报是谁报的**、**自己写的探针有没有在测东西**。
> **`whitebox-miss-attribution`**（漏报怎么归因）讲：**七条结构性漏报原因**、
> **「数组传播」实测被推翻**、**有意不修的边界**、以及「**改动后必须按 rule_id 拆开比对**」。

一句话带走：**召回数字本身也会骗人 —— 先确认分母、再确认口径、最后才看结果。**
⚠️ **看到「召回低」先别改规则，先查分母。**

---

## 四、逐条读命中的字段

```
code_search <codebase_id> sink rce php   # 收窄到 rce + php
```

| 字段 | 怎么读 |
|---|---|
| `file` / `line` | **证据链唯一合法来源**。禁止凭记忆写行号 |
| `kind` | 上表 13 类之一 |
| `rule_id` | 精确到规则。**同类里不同 rule_id 的宽窄度可能差很多** |
| `why` / `hint` | **先读 `why`** —— 作者会写清取向，出现"宽口径"就降预期；`hint` 是该看什么 |
| `scope` | 所属函数。**空 scope 且文件无函数定义 = include 片段，正常** |
| `extractor` | `lexical` 需人眼复核；`ast`/`taint`/`runner` 见上表 |

### 已知需要额外小心的几条

| rule_id | 问题 | 处理 |
|---|---|---|
| `php.xss.echo_var` | **宽口径**：匹配"变量输出到页面"，真 XSS 只占一部分 | 追变量来源；**留着是因为存储型输出端没它就全漏** |
| `java.xxe.factory` | 报的是"解析 XML"，**默认配置下**才可能允许外部实体 | 查有没有关掉 DTD / 外部实体 |
| `js.xss.react_dangerous` | `dangerouslySetInnerHTML` **名字就说明了它在做什么** | 查传入的 html 是否可能含用户输入 |

---

## 五、正向：什么样的命中**基本可以排除**

| 形态 | 为什么安全 |
|---|---|
| `execute(?, [$name])` / `execute([$name])` / `prepare` / `bindParam` | **参数化绑定/预处理** —— 值不参与 SQL 解析 |
| `htmlspecialchars` / `htmlentities` / `urlencode` / `strip_tags` / `filter_var` | 转义/过滤；**要同行**才被黑名单认到 |
| `subprocess.run([...])` / `yaml.safe_load` / `JSON.parse` / `secrets.token_*` / `os.urandom` | 列表传参无 shell 解析 / 安全反序列化 / 密码学安全随机 |

⚠️ **"用了净化函数"≠"净化对了"**：`intval` 挡不住字符串上下文注入、`addslashes` 挡不住 GBK 宽字节、`htmlspecialchars` 不传 `ENT_QUOTES` 挡不住单引号属性。**要看清净化语义与上下文。**

---

## 六、一页速查

| 你看到的 | 它是什么 | 该怎么办 |
|---|---|---|
| `rule_id` 带 `@taint` / `@runner` | **跨行证据** / **执行器证据** | 先往上读赋值行，再判可达性 |
| 报告写「本机检出是部分的」 | 评测集只检出前一段 | 召回按「可命中」分母读，**别按标注总数读** |
| 报告里标「文件级 xx%」 | 口径混了别类规则的命中 | 以 **kind 级主值**为准 |
| `why` 写"宽口径" | 规则自己在提示会误报 | 追数据来源再定 |
| `scope` 空+文件无函数 / 输入输出分处两文件 | include 片段 / 输入输出分离 | **正常**不是漏抽 / **判定层补链** |
| 真实代码写全限定名（`java.io.File`） | 曾是**全库级盲区**（522 处） | 已修；别的语言先想这一步 |
| 某类**整体**召回低，但代码看着没问题 | 可能是**调用名白名单没覆盖**（第三维度） | 捞漏报用例的 sink 行看**调用名**（本文 §一） |
| `impossible.php` 里命中 | 安全实现版 | 拿去当**负样本**（配 `forbid_in`） |
| 命中在测例/文档/注释里 | 噪音 | 单列，不阻塞 |
| 命中处**有 `getCanonicalPath()` + 前缀校验** | **"校验写对没有"是另一回事** | 看它补没补**分隔符**：`startsWith(base)` = 兄弟目录逃逸（v094 实测 jlhttp，PoC 跑通） |
| **总数变好看/变难看** | 可能只是宽口径规则在抖 | **按 `rule_id`/`extractor` 拆开看** |
