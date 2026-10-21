# -*- coding: utf-8 -*-
"""Java 的危险 sink（首批四种里与 PHP 并列的高产面：反序列化 / 表达式注入 / 框架）。

## v069 两条实测修正（OWASP BenchmarkJava 驱动，不是凭空加的）

### ① 全限定名盲区

早期所有 Java 规则都写成短名，如 `new\\s+(?:File|FileInputStream)\\s*\\(`。
但真实 Java 代码（尤其经 IDE 自动补全的）几乎一律写**全限定名**。
Benchmark 全库统计：

    new java.io.File*      522 处      ← 旧 pattern 全部漏掉
    new File*（短名）        18 处      ← 只有这些能打中
    new java.net.URL        95 处      ← `new\\s+URL` 同样全漏

即 `java.path.file` 的实际召回率只有 **3.3%**，`java.ssrf.url` 约 1%。
修法：`new\\s+(?:[\\w.]+\\.)?(?:File|…)` —— **可选包名前缀**。
⚠️ 但**不要**图省事写成 `new\\s+[\\w.]*\\s*\\(`（任意类名）：那会把
`new BufferedReader(`、`new ArrayList(` 全都收进来，误报爆炸。
**必须逐类显式枚举**。

### ② 跨行污染（`call_pattern`）

「先拼到局部变量、再传给 sink」的写法**结构上打不中**：

    String sql = "{call " + param + "}";       // ← 危险在这里
    CallableStatement st = conn.prepareCall(sql);  // ← 本行括号里只有变量名

实测 sqli 272 个真漏洞命中 0。补法是在**同一条规则**上加 `call_pattern`
（只描述调用名、不要求参数里有危险成分），由 `search.py` 配合 `taint.py` 判
「这次调用的括号内有没有污点变量」。

⚠️ **不要**另开一条「平行规则」去做这件事 —— v069 第一版就是这么写的，
结果是死代码 + 平行规则裸奔（详见 `base.py` 的 `call_pattern` 注释）。
"""
from __future__ import annotations

from .base import SinkRule, rule

#: 常见文件/流类的**可选全限定名前缀**（`java.io.` / `java.nio.file.` / 无前缀都能匹配）
#: 刻意**不**用「任意类名」，否则会把所有 `new XxxFileReader(` 类构造收进来。
_FS_CLASSES = r"(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter" \
              r"|RandomAccessFile|BufferedReader|BufferedWriter)"

#: 文件/流类的「调用名」pattern（跨行污染用：只认调用，不要求参数里有 `+`）
_FS_CALL = rf"\bnew\s+(?:[\w.]+\.)?{_FS_CLASSES}\s*\("
#: JDBC / JPA 语句执行的**调用名清单**（行级 pattern 与跨行通道共用这一份）
_SQL_CALL_NAMES = (r"executeQuery|executeUpdate|execute|prepareStatement|prepareCall"
                   r"|nativeSQL|createQuery|createNativeQuery")
#: ⚠️ v091 补：**Spring `JdbcTemplate` 家族 + JDBC 批处理**。**只进跨行通道**，见 `_SQL_CALL`。
_SQL_CALL_NAMES_EXTRA = (r"queryForObject|queryForList|queryForMap|queryForRowSet"
                         r"|queryForLong|queryForInt|batchUpdate|executeBatch")
#: 行级用：调用名（不含开头括号 —— 其后要接「参数里有 `+`」的要求）
_SQL_CALL_BARE = r"\.(?:" + _SQL_CALL_NAMES + r")"
#: 跨行污染用：调用名 + 开头括号（只认调用，不要求参数里有 `+`）
#:
#: ## ⚠️ v091：为什么 Spring 家族**只**加在这里，不加进行级 `pattern`
#:
#: 实测（OWASP BenchmarkJava v1.2，2026-10-07）：sqli 的 34 例漏报里 **21 例（62%）**
#: 走 Spring `DatabaseHelper.JDBCtemplate.*`：
#:
#:     JDBCtemplate.queryForObject(sql, Long.class);   // BenchmarkTest00025
#:     JDBCtemplate.batchUpdate(sql);                  // BenchmarkTest00194
#:     JDBCtemplate.query(sql, rowMapper);             // BenchmarkTest00431
#:
#: 它们**一个都不在**旧白名单里 —— 这不是「多行调用」问题，是**sink 调用名没覆盖**。
#:
#: **只挂跨行通道**（要求括号内有**污点变量**）的理由：
#: ① 行级形态（同行有 `+`）**没有实测过**，别顺手放宽；
#: ② 两个通道**证据强度不同**（"同行拼接" vs "变量来自别处"），合在一起就分不清了 ——
#:    与 v072「两个方向都会骗人」同族：**能分开的证据就别合并。**
#:
#: ⚠️ 刻意**不收**裸 `query` / `update`：实测把它们一起收进来，
#: Benchmark 上的召回与误报**一个都没变**（54/64、误报 30/43 完全相同）——
#: 即"更宽"在这里**没有买到任何东西**，那就不买（v069 删宽口径 `.load(` 的同一判据）。
_SQL_CALL = r"\.(?:" + _SQL_CALL_NAMES + r"|" + _SQL_CALL_NAMES_EXTRA + r")\s*\("
#: 命令执行的「调用名」pattern
#:
#: ## v071：调用者变量盲区（实测驱动，**不是**猜的）
#:
#: 原来只认字面量 `Runtime.getRuntime().exec`（带半角括号的形态）。但真实 Java 代码几乎一律先存变量：
#:
#:     Runtime r = Runtime.getRuntime();
#:     Process p = r.exec（cmd + param）;      // ← 旧 pattern 完全匹配不到
#:
#: **OWASP Benchmark 实测**：cmdi 真漏洞 35 个里 **27 个是这种写法**
#: （`_cmdi_miss.py` 普查：27/27 未命中的文件都是
#: 「`Runtime.getRuntime()` 赋值给变量」+「裸方法名由变量调用」）。
#:
#: ⚠️ 本节里的调用示例一律用**全角括号** —— 规则文件本身是 `.py`，
#:    写半角会被 `py.rce.eval` 自己命中（v079 实测踩到，已加自命中守卫）。
#:
#: ## 为什么不写成「任意变量 `.exec` + 半角括号」
#:
#: 那会匹配任意对象的任意 `exec` 方法（各类框架/测试库都有）→ **裸奔**。
#: v069 删掉宽口径 `.load` 就是因为同一个错误：**看起来能打，实际在制造误报**。
#:
#: ## 正确做法：**调用者必须是「执行器变量」**
#:
#: `search.py` 里对 `_CMD_EXEC_ON_VAR` 命中的行，会去 `taint.py` 新加的
#: `runners` 集合里查「这个调用者是不是从 `Runtime.getRuntime()` /
#: `new ProcessBuilder(...)` 来的」。是才产出命中 —— 精度由**类型判定**保证，
#: 而不是靠正则有多宽。
_CMD_EXEC_LITERAL = r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("
#: 裸方法名 + 变量调用者形如 `r.exec（` / `pb.exec（` —— 调用者是**变量**
#: （不是 `Runtime.getRuntime()` 字面量）。单独一条是为了让 `search.py`
#: 能把它路由到「执行器变量」判定。（全角括号同上：避免自命中。）
_CMD_EXEC_ON_VAR = r"\b(\w+)\s*\.\s*exec\s*\("

_CMD_CALL = _CMD_EXEC_LITERAL + r"|\bProcessBuilder\s*\("

RULES: list[SinkRule] = [
    # ---------- 命令执行 ----------
    rule("java.rce.runtime_exec", "java", "rce",
         _CMD_CALL,
         "执行系统命令；参数可控即可 RCE",
         "追参数拼接方式（数组传参比字符串拼接安全）；有无白名单",
         # 跨行形态：`argList.add("cat " + param);` → `new ProcessBuilder(argList)`
         call_pattern=_CMD_CALL,
         # v071：`Runtime r = Runtime.getRuntime();` → 裸方法名由变量调用。
         # 由 search.py 用 taint 的 runners 集合判「调用者是不是真的执行器」。
         runner_pattern=_CMD_EXEC_ON_VAR),

    # ---------- 反序列化（Java 最典型的高危类） ----------
    rule("java.deser.objectinput", "java", "deserialization",
         r"\bObjectInputStream\b|\breadObject\s*\(\s*\)|\breadUnshared\s*\(\s*\)",
         "原生反序列化 —— 存在 gadget 链时可直接 RCE（ysoserial 类）",
         "输入是否来自网络/用户；类路径里有没有 commons-collections 等已知链"),
    rule("java.deser.xmldecoder", "java", "deserialization",
         r"\bXMLDecoder\b",
         "XMLDecoder 反序列化可直接触发方法调用 → RCE",
         "是否解析外部 XML；能否控制其内容"),
    rule("java.deser.snakeyaml", "java", "deserialization",
         # ⚠️ v069：这里原来还有一条裸分支 `|\.load\s*\(` —— 它匹配**任何** `.load(`，
         # 包括 `Session.load()` / `config.load()`。Benchmark 上它贡献的 45 处命中
         # **绝大多数是误报**（只是混在总数里、被 kind 分布掩盖了）。已删除：
         # 宁可用 `new Yaml()` 精确匹配，也不要一个「看起来很能打」的宽口径。
         r"\bnew\s+(?:[\w.]+\.)?Yaml\s*\(\s*\)|SnakeYaml|SafeConstructor",
         "YAML 反序列化可实例化任意类；未用 SafeConstructor 时风险高",
         "有没有用 SafeConstructor；输入是否可控"),

    # ---------- JNDI / 表达式注入 ----------
    rule("java.jndi.lookup", "java", "rce",
         r"\b(?:InitialContext|Context)\b[^;]{0,60}?\.lookup\s*\(|\blookup\s*\(\s*[a-zA-Z_]",
         "JNDI 注入（Log4Shell 同源）：lookup 的名字可控即可加载远程类 → RCE",
         "名字是否含用户输入；JDK 版本与 `com.sun.jndi.ldap.object.trustURLCodebase` 设置"),
    rule("java.expression.inject", "java", "rce",
         r"\bScriptEngine\b|\bSpelExpressionParser\b|\bOgnl\b|\bMVEL\b|\bGroovyShell\b"
         r"|\bExpressionParser\b|\bTemplateEngine\b",
         "表达式/脚本引擎执行 —— 表达式可控时等价于代码执行（Spring/OGNL/Groovy 都出过）",
         "表达式的**模板**是否可控（不是变量可控）；沙箱是否可绕"),

    # ---------- SQL ----------
    rule("java.sqli.concat", "java", "sqli",
         # `prepareCall` / `createNativeQuery` 是 v069 补的：Benchmark 的 sqli 大量走
         # `CallableStatement`（`{call ...}`）与 JPA native query，原来完全不在覆盖面内。
         _SQL_CALL_BARE + r"\s*\([^;]{0,120}?\+",
         "SQL 语句用字符串拼接 —— 经典注入",
         "是否用 `?` 占位符参数化；拼接的是值还是标识符（表名/排序字段参数化不了，另看白名单）",
         # 跨行形态：`sql = "{call " + param + "}";` → `conn.prepareCall(sql)`
         call_pattern=_SQL_CALL),

    # ---------- XXE ----------
    rule("java.xxe.factory", "java", "xxe",
         r"\b(?:DocumentBuilderFactory|SAXParserFactory|SAXReader|XMLInputFactory|"
         r"TransformerFactory|SchemaFactory)\b",
         "解析 XML —— 默认配置下可能允许外部实体（XXE/SSRF/文件读取）",
         "有没有关掉 DTD / 外部实体（`disallow-doctype-decl`、`XMLConstants.FEATURE_SECURE_PROCESSING`）"),

    # ---------- 文件与路径 ----------
    rule("java.path.file", "java", "path_traversal",
         _FS_CALL
         + r"|\bFiles\s*\.\s*(?:readAllBytes|write|newInputStream|copy|delete|readString)\s*\(",
         "文件路径若来自外部可穿越目录（读配置/写 Web 目录）",
         "有没有 `getCanonicalPath()` 后做前缀校验；能否 `..` 穿越",
         # 跨行形态：`fileName = DIR + param;` → `new FileInputStream(fileName)`
         call_pattern=_FS_CALL
         + r"|\bFiles\s*\.\s*(?:readAllBytes|write|newInputStream|copy|delete|readString)\s*\("),

    # ---------- SSRF ----------
    rule("java.ssrf.url", "java", "ssrf",
         # 同全限定名问题：`new java.net.URL(` 有 95 处、短名仅 1 处。
         r"\bnew\s+(?:[\w.]+\.)?URL\s*\(|\bHttpURLConnection\b|\bopenConnection\s*\(|\bHttpClient\b",
         "发起外部请求 —— URL 可控即可探测内网/云元数据",
         "URL 是否可控；有无网段/协议白名单",
         call_pattern=r"\bnew\s+(?:[\w.]+\.)?URL\s*\(|\bopenConnection\s*\("),

    # ---------- 弱加密 ----------
    rule("java.crypto.weak", "java", "weak_crypto",
         r"Cipher\s*\.\s*getInstance\s*\(\s*[\"'](?:DES|RC2|RC4|Blowfish|AES/ECB)",
         "弱加密算法或 ECB 模式",
         "用途是什么：口令存储（更该用 bcrypt/argon2）还是传输"),
    rule("java.hash.weak", "java", "weak_crypto",
         r"MessageDigest\s*\.\s*getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']",
         "MD5/SHA-1 已不适合做完整性/口令摘要",
         "是否用于口令（是则可爆破）；是否用于签名（可伪造）"),

    # ---------- 反射/可见性 ----------
    rule("java.reflect.accessible", "java", "rce",
         r"\.setAccessible\s*\(\s*true\s*\)|\bClass\s*\.\s*forName\s*\(",
         "反射可绕过访问控制 —— 常是 gadget 链的一环",
         "类名/方法名是否可控；是否在反序列化或表达式引擎的路径上"),
]
