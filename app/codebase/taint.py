# -*- coding: utf-8 -*-
r"""函数内轻量污染分析（v069）。

## 为什么需要它

`sink_rules` 的正则只在**单行**上匹配。这在一种很常见（而且很自然）的写法上**结构必漏**：

    String sql = "{call " + param + "}";              // ← 拼接在这一行
    CallableStatement st = connection.prepareCall(sql);  // ← sink 在下一行，括号里只有变量名

规则要求「`prepareCall(...)` 括号内有 `+`」，而这里括号内只有 `sql` —— **不是规则写松了就能修的**：
把 `+` 去掉改成「括号里有变量名就算」，会让整个仓库疯狂误报。

实测证据（OWASP BenchmarkJava v1.2，官方 ground truth）：
`sqi` 类别 **272 个真漏洞命中 0**；`cmdi` 126 → 命中 8；`pathtraver` 133 → 命中 2。
三个类别**同一个根因**（先拼变量、再传变量）。

## 这一层做什么、不做什么

**做**：在**同一个函数体内**、**严格按源码顺序**，推出「哪些局部变量是污点」。

- 污点起点（**必须显式含外部输入**）：
  - 语言级超级全局：`$_GET`/`$_POST`/`$_REQUEST`/`req.getParameter`/`request.getHeader` …
  - 已知的「取值 API」形态：`getHeader(`/`getParameter(`/`getQueryString(`/`getCookies(` …
- 污点传播：`x = <表达式>` 且该表达式含 `+` 拼接、且含**污点变量或污点起点** → `x` 变污点。
  - **传递闭包按行向下**（第 N 行的赋值只影响 N 行之后），保证确定性、可回归。
- 污点清除：`x = <不含任何污点成分的表达式>` → `x` 从污点集合移除（**覆盖即净化**）。

**不做**（有意为之，写在这里防止后人误以为漏了）：

- **不做跨函数**：不追参数进入被调函数、不追返回值。那需要真正的 AST/调用图，
  且**跨文件链路本就是判定层（模型）的活**（与 §4.1 分工一致）。
- **不做净化识别**：`htmlspecialchars` / `prepareStatement("...?")` 这类**不在这里判**——
  正则判不准「净化是否用对」。这里只回答「**这个变量是否由外部输入拼成**」，
  **是否真的可利用仍然要靠模型读上下文**（与「sink 命中≠漏洞」同一条纪律）。
- **不做别名/数组/字段传播**：`a.b` / `arr[i]` 只按字面变量名跟踪。
  ⚠️ **`@@CF-NOTE`：v086 实测确认这条边界「留着是对的」** —— 见下方专节。

## v072 追加：**容器追加式污染**（`container.add(...)`）

第三类结构形态（前两类：跨行赋值 v069、执行器变量 v071）：

    java.util.List<String> argList = new java.util.ArrayList<String>();
    argList.add("cmd.exe");
    argList.add("echo " + param);        // ← 污点**经 .add() 进入容器**
    pb.command(argList);                 // ← sink 参数是容器，不是污点变量

**为什么必须单独处理**：`analyze()` 原来只看**赋值**（`lhs = rhs`）。
`argList.add(污点)` 既不是赋值、也不清除任何东西 —— `argList` **从头到尾不在污点集合里**，
于是 `pb.command(argList)` 参数被判为「不脏」。实测 cmdi 里 **10 处**这种写法。

### ⚠️⚠️ 实测结论：这两处修正对 Benchmark 的命中数**增量为 0**（必须写下来）

`_v072_diff.py` 用 `git stash` 把本文件还原到 v071，同一批 669 个文件跑两遍，
**逐行逐规则**比对命中集合：**1487 → 1487，新增 0，消失 0**。

为什么修了却没变——**因为原来的「漏报」本来就不在这两处**：

1. `java.rce.runtime_exec` 的 `pattern` 里已经有 `\bProcessBuilder\s*\(`，
   它**不关心括号里是什么**。所以 `new ProcessBuilder(argList)` 那行
   **v071 就已经命中了**；容器污点只是让 `@taint` 通道**多报一条重复的**。
2. 该规则的 `call_pattern` 与原 `pattern` **逐字节相同** —— 按下面的「平行规则」教训，
   这条 `@taint` 通道是**纯冗余**，永远与 `[line]` 同生共死。
3. `.command(argList)` 那行确实**没被任何通道匹配**（`_CMD_CALL` 没有 `.command(` 分支），
   但全库只有 5 处 `.command(`，且那 5 个文件**都已经**因为同一文件里的
   `new ProcessBuilder(` 行而命中 → 补上也**不增加召回**。

**所以本修正的价值是「正确性」而不是「召回」**：它让 taint 层对
「全限定泛型声明」和「容器追加」两种形态不再视而不见。
真正的召回缺口在**控制流分支合并**（见下），那是另一件事。

**判据（有意保守）**：
- 只认**已知的容器方法名**（`add`/`addAll`/`put`/`append`/`push`/`offer`），
  **不写成「任意 `.方法(`」** —— 否则 `logger.add(...)`/`pool.add(...)` 之类全进来。
- 实参含**已有污点变量**或**外部输入起点** → 容器进污点集（与赋值通道同判据）。
- ⚠️ **追加式，不是覆盖式**：`.add()` **不清除**容器原有污点（与「覆盖即净化」正交）。
  容器被**赋值**（`argList = ...`）时才按赋值规则处理 —— 两个通道各管各的。
- ⚠️ **不处理 `.add()` 的逆操作**：`.remove(0)` / `.clear()` / `.get(i)` **不做传播**。
  那是真正的**数组/字段传播**（见下方「不做」），属独立议题：
  它需要下标语义、且会显著放大误报面（v072 有意留到后续版本）。

## ⚠️⚠️ v086 实测：**「数组传播」不是独立缺口**（推翻待办里的一条）

长期待办里写着「数组/字段传播是 Benchmark sqli 的主力漏报形态（39.1%，最大缺口）」。
v086 用真实引擎**直接量了**，结论是**这条判断不成立**：

| 测法 | 结果 |
|---|---|
| 「右值 = 已有变量`[下标]`」的行，基变量已污点时左值**没接上**的 | **0 处** |
| 「右值 = 变量`[下标]`」总计 | 225 行，**225 行全部正常传播** |
| 先按 `new byte[N]` 粗筛出的「判不脏」261 行 | 绝大多数是**数组分配**（本就不该脏），不是传播失败 |

原因很朴素：`_names()` 抠的是**标识符**，`values[i]` 里的 `values` 与 `[i]` 无关，
所以「容器脏 → 下标取值也脏」**现成就能工作**（这也顺带解释了 `values.length` 为何无害）。

那为什么漏报统计里「数组取值」标签有 19 个？因为**真正的断点在上游**：
`if (values != null) param = values[0];` 这一行被 `_ASSIGN` 的 `^\s*` 锚点吞掉了 ——
**是控制流前缀问题，不是下标语义问题**。**两者被同一个标签混在一起了。**

⭐ 教训：**待办里那条「最大缺口是数组传播」是推断，不是测量。** 一旦真的去量，
它就让位给了另一个更朴素、更靠前的根因。**动手前先量，别照着推断排优先级。**

## ⚠️⚠️ 已知最大缺口：**控制流分支不合并**（v072 查明，**未修**）

本层是**直线分析**：按源码顺序走一遍，**后一条赋值覆盖前一条**。
于是**分支结构天然出错** —— 最后一次赋值（文本顺序最后的那个分支）说了算。

实测 OWASP Benchmark 的 `switch` 形态（169 个用例里有 **129 个**用这个结构）：

    String guess = "ABC";
    char switchTarget = guess.charAt(2);      // ← 'C'
    switch (switchTarget) {
        case 'A': bar = param; break;          // ← 有污点
        case 'B': bar = "bobs_your_uncle"; break;
        case 'C':
        case 'D': bar = param; break;          // ← 有污点（且**这条真的会执行**）
        default:  bar = "bobs_your_uncle"; break;  // ← 文本上最后；本层按它清掉 bar
    }
    ProcessBuilder pb = new ProcessBuilder(argList);   // ← argList 收了 bar → 实际有污点

本层在 `default` 那行把 `bar` 清掉 → 下游判「不脏」→ **真漏洞漏报**。

### 为什么**不能**简单地改成「分支取并集」

看起来正确修法是：遇 `if`/`switch` 时**快照**污点集，块结束时取**并集**。
但实测发现这条路**会把精确性打穿**：

| 用例 | `guess.charAt(N)` | 实际走的 case | 标注 | 并集后的结果 |
|---|---|---|---|---|
| `BenchmarkTest00077` | `charAt(2)` → `'C'` | `case 'C'` → `bar = param` | **true** | 命中 ✓ 对 |
| `BenchmarkTest00310` | `charAt(1)` → `'B'` | `case 'B'` → `bar = "bob"` | **false** | 命中 ✗ **误报** |
| `BenchmarkTest00659` | `charAt(1)` → `'B'` | 同上 | **false** | 命中 ✗ **误报** |

三者的 `switch` 段**逐字节相同**，唯一区别是 `charAt` 的**下标**（`2` vs `1`），
而 Benchmark 自己在注释里写了 "condition 'B', which is **safe**"。
**要判对必须做常量折叠**（推出 `guess = "ABC"` → `charAt(1) = 'B'` → 走 `case 'B'`）
—— 那是**值级分析**，不是词法/污点层能做的事（那是判定层/模型的活）。

全库统计：`charAt(2)` **26 个文件**（真漏洞）vs `charAt(1)` **26 个文件**（安全），
**几乎 1:1** —— 换句话说，改「并集」会**同时**捞回 ~26 个真漏洞、
**同时**制造 ~26 个误报（在那 129 个 `switch` 用例上更多）。
**净收益接近零，而精确性会明显下降**，所以 v072 **有意不做**。

**正确的下一步不是改本层**，而是：
① 维持本层保守（宁可漏、不可误报），
② 让**判定层（模型）**去读 `switch` 上下文判可达性（与 §4.1 分工一致），
③ 若真要自动做，得先有**常量折叠**能力（独立议题，见 MEMORY 待办）。

## v071 追加：**命令执行器变量**（`runners`）

除了「污点」，本层还顺带跟踪**另一类正交的信息**：哪些变量持有**命令执行器**。

    Runtime r = Runtime.getRuntime();     // ← r 不是「污点」（不含用户输入）
    Process p = r.exec(cmd + bar);        // ← 但 r 是执行器，这行就是命令执行 sink

**为什么必须单独跟踪**：`sink_rules` 的 `_CMD_CALL` 只认字面量
`Runtime.getRuntime().exec(`。实测 OWASP Benchmark 的 cmdi 真漏洞里
**35 个中 27 个**写成「先存变量、再 `r.exec(...)`」—— 那 27 个**一个都打不中**。

**为什么不直接把正则放宽成 `.exec(`**：那会裸奔（`.exec(` 会吃到一切同名方法）。
v069 已用「删掉宽口径 `.load(`」证明过这条教训。正确做法是**在变量层面判类型**，
而不是在方法名层面放宽。

**与污点的关系**：两者**正交且互相独立**——
`r` 是执行器但不是污点；`param` 是污点但不是执行器。
所以它们是 `TaintResult` 上**两个独立的字段**，不是一个合并的集合。
合并会让「这个变量脏不脏」和「这个变量能不能执行命令」互相污染。

## 输出是**候选**，不是漏洞

本层只把「原来打不中的形态」提升为**可被规则命中的候选**。命中之后该验证什么，
仍然由规则的 `hint` 引导（与既有 sink 命中完全同一条链路）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: 语言级「外部输入起点」形态（**只要出现就视为外部输入**）
#
# ⚠️ 扩充依据来自 OWASP Benchmark 实测：真实项目里「取值」的写法很分散，
# 只认 `request.getParameter` 会漏掉 `cookie.getValue()` / 枚举器 `.nextElement()`
# 这类**间接取值**——实测 BenchmarkTest00002 就卡在
# `param = URLDecoder.decode(theCookie.getValue(), "UTF-8")` 上（param 没被判污点，
# 导致下游 `new FileOutputStream(fileName)` 一个都命中不了）。
#
# ⚠️ **刻意不收**（它们是元数据/框架对象，不是用户可控值，收了会大面积误报）：
# `getSession` / `getRequestURI` / `getRequestURL` / `getRequestDispatcher` / `getHeaderNames`。
SOURCE_PATTERNS: dict[str, str] = {
    "php": r"\$_+(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b",
    "java": (r"\b(?:request|req)\s*\.\s*get(?:Parameter|ParameterValues|ParameterMap"
             r"|Header|Headers|QueryString|Cookies|InputStream|Reader)\b"
             r"|\bget(?:Parameter|ParameterValues|Header|Headers|QueryString|Cookies)\s*\("
             r"|\b\w*[Cc]ookie\w*\s*\.\s*getValue\s*\("
             r"|\b\w*(?:headers|params|names|cookies)\w*\s*\.\s*next(?:Element|Token)\s*\("),
    "javascript": (r"\b(?:req|request)\s*\.\s*(?:query|body|params|cookies|headers)\b"
                   r"|\bprocess\s*\.\s*argv\b"),
    "python": (r"\brequest\s*\.\s*(?:args|form|values|json|data|cookies|headers|GET|POST)\b"
               r"|\b(?:input|raw_input)\s*\("),
}

#: 通用的「取值 API」形态（跨语言，独立于框架）
SOURCE_GENERIC = r"\b(?:getHeader|getHeaders|getParameter|getParameterValues|getQueryString|getCookies|nextElement)\s*\("

#: 变量名的**词法**：PHP 一律带 `$` 前缀（`$param`），Java/JS/Python 不带（`param`）。
#: ⚠️ v069 实测踩到：早期这里只写 `[A-Za-z_]\w*`，**不允许 `$`**，
#: 于是 `$x = $_GET["a"]` 的左值抠不出来 → **PHP 的污点链一条都没工作过**。
#: 两种形态都收，靠 `_STOPWORDS` 与「必须带 `$` 或必须是纯标识符」两条约束控制噪音。
_IDENT_BODY = r"\$?[A-Za-z_]\w*"

#: 赋值语句：`<左值> = <右值>;`。左值只取简单标识符/带类型声明（不做复杂解析）。
#: **两个捕获组**：① 左值 ② 右值。
#:
#: ⚠️ **v072 修正「带类型声明」分支允许 `.`**（即允许**全限定类型名**）：
#: 原写法 `[A-Za-z_][\w<>\[\],\s]*?` **不允许 `.`**，于是
#: `java.util.List<String> argList = new java.util.ArrayList<String>();`
#: **整行匹配失败** —— 该变量从此不进污点分析，连"覆盖即净化"都没发生过。
#: 这是 v069「全限定名盲区」在 **taint 层的复现**（v069 修的是规则 `pattern` 层，
#: 漏掉了 taint 层；同一类错误在同一版的两个地方只修了一处）。
#: **实测影响面：全库 591 行**（`java.util.List` 93 / `Map` 88 / `HashMap` 123 / `Enumeration` 287）。
#: 放开 `.` 后正样本 6/9 → 9/9，负样本误匹配 3/12 **不变**（见 `test_072`）。
_ASSIGN = re.compile(
    r"^\s*("
    r"\$?[A-Za-z_][\w.]*"                                     # 变量名（PHP 可带 `$`）
    r"|(?:var|let|const)\s+\$?[A-Za-z_]\w*"                    # var/let/const 声明
    r"|(?:final\s+)?[A-Za-z_][\w.<>\[\],\s]*?\s+\$?[A-Za-z_]\w*"  # 带类型声明（v072 起允许全限定名）
    r")"
    r"\s*=\s*(?!=)(.+?);?\s*$"
)

#: ⚠️ v090 实测发现：`_ASSIGN` 的「带类型声明」分支会把**控制流前缀**一起当成左值。
#:
#:     else bar = "This should never happen";     ← 抠出的左值是 `else bar`
#:
#: 为什么 `if` 没事、`else` 出事：该分支的字符类 `[A-Za-z_][\w.<>\[\],\s]*?` **不含括号**，
#: 于是 `if ((500 / 42) + num > 200) bar = param;` 匹配失败（条件里有括号）→ 落到
#: `_PREFIXED_ASSIGN`、走 v086 的不对称判据；而 `else bar = ...` 不含括号 → **被 `_ASSIGN` 吞下**
#: → 走「覆盖即净化」。
#:
#: 后果正是 v086 明令禁止的那一种：**右值安全 → 清除**。实测 `BenchmarkTest00606` 因此漏报 ——
#: `else bar = "This should never happen";` 把上一行 `if (...) bar = param;` 刚标好的脏**清掉**了，
#: 于是 `sql` 不脏、`statement.executeUpdate(sql)` 连 `@taint` 都产不出来。
#:
#: **修法**：这类行交给 v086 的不对称判据（脏 → 标脏；安全 → **不清除**），不让 `_ASSIGN` 判。
#: ⚠️⚠️ **不要"整个忽略"这类行** —— 那会把 `else bar = param;` 该标的脏一起丢掉。
#: v090 测量时第一版就是"忽略"，结果是**误报与召回同时下降**；而"只加污点"不可能让误报下降，
#: 这个矛盾当场暴露了它是**用一个回归换来的假收益**（改成不对称语义后才采信数字）。
_CTRL_IN_LHS = re.compile(
    r"\b(?:else|if|while|for|switch|case|default|do|try|catch|finally|return)\b")

#: ⚠️ v090：**跨行赋值** —— 左值与 `=` 在本行、右值在**续行**（真实代码格式化后极常见）：
#:
#:     bar =
#:         new String(Base64.decodeBase64(Base64.encodeBase64(param.getBytes())));
#:
#: `_ASSIGN` 的右值要求 `.+?`（至少一个字符），于是 `bar =` 这一行**整行匹配失败** ——
#: 续行里的污点变量看不见，变量**从未被判脏**（实测 `BenchmarkTest00604` 漏报）。
#:
#: ⚠️ 这与「跨行**调用**」是两件事，后者 v069 已修（`search.py:_tainted_in_args`）。
#: **同一个"跨行"盲区在赋值侧又犯了一次** —— 与 v072「修一处后要问：同类判据还有几处」同族。
_ASSIGN_OPEN = re.compile(
    r"^\s*("
    r"\$?[A-Za-z_][\w.]*"                                          # 变量名（PHP 可带 `$`）
    r"|(?:var|let|const)\s+\$?[A-Za-z_]\w*"                         # var/let/const 声明
    r"|(?:final\s+)?[A-Za-z_][\w.<>\[\],\s]*?\s+\$?[A-Za-z_]\w*"    # 带类型声明
    r")\s*=\s*$"
)

#: 跨行赋值往下看多少行（够覆盖格式化后的续行，又不会吃到别处的代码）
_ASSIGN_LOOKAHEAD = 6

#: 从赋值左值里抠出**变量名**
_LHS_NAME = re.compile(
    r"(?:^|\s)(\$?[A-Za-z_]\w*)\s*$|(\$?[A-Za-z_]\w*)\s*(?:\.\w+|\s*\[[^\]]*\])*\s*$"
)

#: 从右值里抠出**出现的标识符**（用于判断它是否含污点变量）。
#: 左侧用 `(?<![A-Za-z0-9_])` 而非 `\b` —— 因为 `$` 前缀会让 `\b` 在 `$param` 上失效
#: （`$` 非 word 字符，`\bparam` 能匹配到 `param`，但我们要连 `$` 一起抠出来统一处理）。
_IDENT = re.compile(rf"(?<![A-Za-z0-9_])(\$?[A-Za-z_]\w*)")

#: 「命令执行器」的右值形态（v071）—— 赋值给变量后，该变量可以 `.exec(...)`。
#:
#: ## 为什么需要单独跟踪这一类
#:
#: v069 的 `_CMD_CALL` 只认字面量 `Runtime.getRuntime().exec(`。但真实 Java 代码
#: 几乎一律先存变量。**实测 OWASP Benchmark：cmdi 真漏洞 35 个里 27 个是这种写法**
#: （`Runtime r = Runtime.getRuntime(); Process p = r.exec(...)`），
#: 那 27 个**一个都打不中** —— 这是比「跨行污染」更彻底的结构性漏报。
#:
#: ## 为什么不直接把规则放宽成 `.exec(`
#:
#: 因为那会**裸奔**：`.exec(` 会匹配到 `ProcessBuilder.exec` 之外的一切同名方法
#: （各类框架、测试库都有 `exec`）—— v069 已用「删除宽口径 `.load(`」证明过这条教训：
#: **宁可用精确的白名单形态，也不要一个看起来很能打的宽正则**。
#: 所以做法是：**在变量层面判类型**（这个变量是不是从 `Runtime.getRuntime()` 来的），
#: 而不是在方法名层面放宽。
#:
#: 收集范围（刻意保守，只收真的能执行命令的）：
#:   - `Runtime.getRuntime()`
#:   - `new ProcessBuilder(...)` / `ProcessBuilder` 的静态工厂
#: 不收 `ProcessBuilder` 实例**经 `.command()` 后**的形态 —— 那属于容器间接污染，
#: 是有意留到后续版本、且需要突破「不做数组/字段传播」边界的独立议题。
_RUNNER_RHS = re.compile(
    r"(?:\bRuntime\s*\.\s*getRuntime\s*\(\s*\))"
    r"|(?:\bnew\s+(?:[\w.]+\.)?ProcessBuilder\s*\()"
)

#: **带控制流前缀的赋值**（v086）。**四个捕获组**：①② 是 `if/while/for` 分支，③④ 是 `} else` 分支。
#:
#: ## 为什么需要它（**实测驱动，占漏报真漏洞的 56%**）
#:
#: `_ASSIGN` 锚在 `^\s*` 上 —— 于是**任何带控制流前缀的赋值都整行匹配失败**：
#:
#:     if (values != null) param = values[0];     // ← 整行看不见！
#:     if (param == null) param = "";             // ← 同样看不见
#:     if ((500 / 42) + num > 200) bar = param;   // ← 同样看不见
#:
#: 后果是 `param` / `bar` **从头到尾不进污点集**，下游 `sql = "..." + param` 判「不脏」。
#:
#: 实测（OWASP BenchmarkJava v1.2，官方标注，本机有源码那 107 个 sqli 用例）：
#: 43 个漏报真漏洞里 **24 个（56%）** 命中这个形态 —— 是当时**最大的单一漏报根因**，
#: 比「数组传播」（同批 19 个）更靠前，而原以为的「数组传播」其实**根本不是独立问题**
#: （见下方 `@@CF-NOTE`：那 19 个里绝大多数真正的断点也在这里）。
#:
#: ## 判据：**标脏方向放宽、清脏方向不放宽**（这是刻意的，不是漏写）
#:
#: 条件分支里「这条赋值到底执行没有」在词法层**判不出来**（需要常量折叠，
#: 与 `switch` 那节同一个理由）。所以两个方向**不对称处理**：
#:
#: - 右值含**污点起点**或**已有污点变量** → **标脏**。
#:   即使这个分支实际不执行，最坏结果是**多一个候选**（判定层会筛掉）。
#: - 右值**安全** → **不清除**（与 `_ASSIGN` 的「覆盖即净化」**相反**）。
#:   因为「`param = "safe"` 只在这条分支里发生」并不意味着别处没赋过脏值。
#:
#: ⚠️ **这个不对称是「宁可多报候选、不可漏报」的体现**，与 §「输出是候选不是漏洞」一致。
#: 但**不适用于** `_ASSIGN`（无前缀赋值）—— 那是直线代码，覆盖即净化仍然正确。
#:
#: ⚠️ **实测净收益**（同上口径，`_probe` 模拟）：召回 **21/64 → 26/64（32.8% → 40.6%）**，
#: 误报 **13 → 17**。**召回增量大于误报增量**，且漏报的真漏洞是**不可恢复**的、
#: 而多出的候选可由判定层筛掉 —— 所以这个交换是划算的。
#:
#: ## ⚠️ 条件里的**嵌套括号**（`test_086` 当场抓到的实现缺陷）
#:
#: 第一版条件写成 `\([^)]*\)` —— 只吃到**第一个** `)`。于是本库/本项目里极常见的
#:
#:     while (it.hasNext()) bar = p;      // ← 条件里有 it.hasNext() 的括号
#:
#: **整行匹配失败**（`[^)]*` 停在 `it.hasNext(` 后的那个 `)`，剩下 `) bar = p;` 对不上）。
#: 这跟本版要修的 `_ASSIGN` 锚点问题是**同一类错误**（正则比实际代码形态窄），
#: 只是发生在**我刚写下的新正则**里 —— 说明这类错误是**会复发的**，必须靠测试钉住。
#: 修法：条件部分允许**一层嵌套括号**（`(?:[^()]|\([^()]*\))*`）。
#: 不做到任意深度 —— 那需要真正的括号配平，词法层不做（见「不做跨函数」同族的边界说明）。
_PREFIXED_ASSIGN = re.compile(
    r"^\s*(?:if|while|for)\s*\((?:[^()]|\([^()]*\))*\)\s*"
    r"(?:[A-Za-z_][\w.<>\[\],\s]*?\s+)?(\$?[A-Za-z_]\w*)\s*=\s*(?!=)(.+?);?\s*$"
    r"|^\s*\}\s*else\s*\{?\s*"
    r"(?:[A-Za-z_][\w.<>\[\],\s]*?\s+)?(\$?[A-Za-z_]\w*)\s*=\s*(?!=)(.+?);?\s*$"
)

#: 容器**追加**方法（v072）：`<容器>.<方法>(<实参>)`。**两个捕获组**：① 容器 ② 实参。
#:
#: ## 为什么必须是白名单
#:
#: 若写成 `(\w+)\s*\.\s*\w+\s*\(([^)]*)\)`（任意方法），`logger.info(param)`、
#: `resp.setHeader(param)`、`sb.append(...)` 全都进来 —— 那会把**任何一个收污点的对象**
#: 都标成「容器污点」，等于让污点集快速饱和，sink 层将大面积误报。
#: 只认真的「往集合里塞值」的语义（见下），与《教训库》「宁要精确白名单，
#: 不要看起来很能打的宽正则」一致（v069 删 `.load(` 同族）。
#:
#: 白名单覆盖实测用到的：`List/ArrayList`（`add`/`addAll`）、`Map/HashMap`（`put`/`putAll`）、
#: `StringBuilder/StringBuffer`（`append`）、`Deque/Stack`（`push`/`offer`/`addLast`）。
_CONTAINER_ADD = re.compile(
    r"\b(\$?[A-Za-z_]\w*)\s*\.\s*"
    r"(add|addAll|put|putAll|append|push|offer|addLast|addFirst)\s*\(([^)]*)\)"
)


def _norm(name: str) -> str:
    """变量名归一：**去掉 PHP 的 `$` 前缀**。

    `$param` / `param` 在集合比较时必须是同一个键，否则
    「左值抠出 `param`、右值抠出 `$param`」会永远对不上，污点传不下去。
    """
    return name.lstrip("$")

#: 常见的类型/关键字，避免被当成变量名（减少噪音）
_STOPWORDS = frozenset({
    "new", "return", "true", "false", "null", "None", "this", "super", "String",
    "int", "long", "byte", "char", "boolean", "double", "float", "void", "var",
    "let", "const", "final", "public", "private", "protected", "static",
})


@dataclass
class TaintResult:
    """一次函数级分析的结果。"""
    tainted: dict[int, set[str]] = field(default_factory=dict)
    """行号 → 该行**之后**处于污点状态的变量集合（含该行赋值产生的）。"""

    runners: dict[int, set[str]] = field(default_factory=dict)
    """行号 → 该行之后持有**命令执行器**的变量集合（v071）。

    `Runtime r = Runtime.getRuntime();` → 从这一行起 `r` 是执行器。
    用途见 `_RUNNER_RHS` 的说明：让 `.exec(` 的**调用者变量**能判出来。
    """

    def at(self, line: int) -> set[str]:
        """取「第 line 行被处理完时」的污点集合（供 sink 匹配时查）。"""
        return self.tainted.get(line, set())

    def runners_at(self, line: int) -> set[str]:
        """取「第 line 行被处理完时」的命令执行器变量集合。"""
        return self.runners.get(line, set())


def _lhs_name(lhs: str) -> str:
    """从赋值左值里取变量名：`String sql` → `sql`，`argList` → `argList`，`$x` → `x`。

    ## ⚠️ v072 修正：类型前缀必须允许 `.`（全限定名）

    原正则的类型前缀是 `[A-Za-z_<>\\[\\],\\s]*?` —— **没有 `.`**。于是
    `java.util.List<String> argList` 里 `java.util.List<String>` **吃不下**，
    整个匹配失败 → 返回 `""` → **该变量名抠不出来**。

    后果比 `_ASSIGN` 不匹配更隐蔽：`analyze()` 是

        name = _lhs_name(lhs_raw)
        if name:            # ← 空字符串 → **整个传播分支静默跳过**
            ...

    —— `_ASSIGN` 不匹配是「这一行没看见」，这里却是「**看见这行了，但变量名是空的**」，
    两者都让 `java.util.List<String> x = ...` 的 `x` 永远不进污点集合。
    **实测这是 v069「全限定名盲区」在 taint 层的第二处**（第一处是 `_ASSIGN` 本身）。
    影响面 591 行（`List` 93 / `Map` 88 / `HashMap` 123 / `Enumeration` 287）。
    """
    s = lhs.strip()
    # 去掉修饰符与类型
    s = re.sub(r"^(?:final|var|let|const)\s+", "", s)
    m = re.match(r"^[A-Za-z_.<>\[\],\s]*?(\$?[A-Za-z_]\w*(?:\s*\.\s*\w+|\s*\[[^\]]*\])*)\s*$", s)
    return _norm(m.group(1).replace(" ", "")) if m else ""


def _is_source(lang: str, expr: str) -> bool:
    """表达式里是否含**外部输入起点**。"""
    pat = SOURCE_PATTERNS.get(lang)
    if pat and re.search(pat, expr):
        return True
    return bool(re.search(SOURCE_GENERIC, expr))


def _names(expr: str) -> set[str]:
    """表达式里出现的标识符集合（去掉常见关键字，`$` 前缀归一掉）。"""
    return {_norm(n) for n in _IDENT.findall(expr)
            if n not in _STOPWORDS and _norm(n) not in _STOPWORDS}


def analyze(lines: list[str], lang: str) -> TaintResult:
    """按**源码顺序**做函数外层的污点传播（调用方自己切分函数边界）。

    ⚠️ 这里刻意**不解析函数边界** —— 由调用方按 `scope` 切好再喂进来。
    传入的应当是**单个函数体的行**（或整个文件，此时污染可能跨函数泄漏，
    但因为要求显式含外部输入、且赋值覆盖即清除，实际影响很小）。
    """
    res = TaintResult()
    cur: set[str] = set()
    runners: set[str] = set()
    for i, line in enumerate(lines, 1):
        m = _ASSIGN.match(line)
        # ⚠️ v090：控制流前缀（`else bar` / `case 'A': bar`）**不许**当左值走 `_ASSIGN` ——
        # 那里是「覆盖即净化」，会清除掉 v086 刚标好的脏。改走 v086 的不对称判据
        # （脏 → 标脏；安全 → **不清除**）。详见 `_CTRL_IN_LHS` 的长注释。
        if m is not None and _CTRL_IN_LHS.search(m.group(1)):
            cf_lhs, cf_rhs = m.group(1), m.group(2)
            m = None
            cf_name = _lhs_name(cf_lhs)
            if cf_name and cf_name not in _STOPWORDS:
                if _is_source(lang, cf_rhs) or (_names(cf_rhs) & cur):
                    cur = cur | {cf_name}
                # ⚠️ else 分支**故意为空** —— 同 v086：分支执行与否词法层判不出，
                # 清除 = 制造**不可恢复的漏报**。
                if _RUNNER_RHS.search(cf_rhs):
                    runners = runners | {cf_name}
        # ⚠️ v090：跨行赋值（`bar =` 后换行）—— `_ASSIGN` 看不见续行里的右值，
        # 于是「本行没有右值」被当成了「右值无污点成分」。往后并几行再判。
        if m is None and _ASSIGN_OPEN.match(line):
            chunk = [line]
            for j in range(i, min(i + _ASSIGN_LOOKAHEAD, len(lines))):
                chunk.append(lines[j])
                if lines[j].rstrip().endswith(";"):
                    break
            m = _ASSIGN.match(" ".join(chunk))
        if m:
            lhs_raw, rhs = m.group(1), m.group(2)
            name = _lhs_name(lhs_raw)
            if name:
                rhs_has_source = _is_source(lang, rhs)
                rhs_names = _names(rhs)
                rhs_has_taint = bool(rhs_names & cur)
                # ⚠️ 判据顺序是踩出来的：
                # ① 右值含外部输入起点 → 污点（`param = request.getHeader(...)`）；
                # ② 右值含**已有污点变量** → 污点，**不论有没有 `+`** ——
                #    因为 `param = URLDecoder.decode(param, "UTF-8")` 这类是**传递**不是净化
                #    （早先写成「必须有拼接才算」，结果这一行把 param 从污点集里清掉了，
                #    下游 sink 一个都命不中 —— 修 Benchmark 时当场抓到的）；
                # ③ 其余 → **覆盖即净化**。
                if rhs_has_source or rhs_has_taint:
                    cur = cur | {name}
                else:
                    # 不含任何污点成分 → **覆盖即净化**（`param = "safe"`；
                    # 纯常量拼接 `"a" + "b"` 也走这里，同样安全）
                    cur = cur - {name}

                # ---- 命令执行器变量（v071）：与污点是**正交**的两件事 ----
                # 同一条赋值同时更新两个集合：`Runtime r = Runtime.getRuntime();`
                # 里 `r` **不是污点**（它不含用户输入），但它是**执行器**。
                # ⚠️ 合并成一个集合会让「r 本身脏不脏」和「r 能不能执行命令」
                # 互相污染 —— 后者是类型信息，前者是数据流信息。
                if _RUNNER_RHS.search(rhs):
                    runners = runners | {name}
                else:
                    runners = runners - {name}                # 覆盖即失效（重赋值就不是执行器了）
        else:
            # ---- 带控制流前缀的赋值（v086）----
            # `if (values != null) param = values[0];` —— `_ASSIGN` 锚在 `^\s*`，
            # 这类整行匹配失败 → 变量永远不进污点集。实测占漏报真漏洞的 56%。
            #
            # ⚠️⚠️ 两个方向**不对称**（刻意，见 `_PREFIXED_ASSIGN` 的长注释）：
            #   脏 → 标脏；**安全 → 不清除**。
            # 理由是条件分支「执行与否」词法层判不出来，清除会制造**不可恢复的漏报**。
            # ⚠️ 与 `_ASSIGN` 的「覆盖即净化」不矛盾：那是直线代码，无分支歧义。
            pm = _PREFIXED_ASSIGN.match(line)
            if pm:
                p_lhs = pm.group(1) or pm.group(3) or ""
                p_rhs = pm.group(2) or pm.group(4) or ""
                p_name = _lhs_name(p_lhs) or _norm(p_lhs)
                if p_name and p_name not in _STOPWORDS:
                    if _is_source(lang, p_rhs) or (_names(p_rhs) & cur):
                        cur = cur | {p_name}
                    # ⚠️ else 分支**故意为空** —— 见上面的不对称说明。
                    if _RUNNER_RHS.search(p_rhs):
                        runners = runners | {p_name}

            # ---- 容器追加式污染（v072）----
            # `argList.add("echo " + param)` —— 这是**赋值之外**的第二条污染通道。
            # ⚠️ 必须放在非赋值行里：`x = y.add(..)` 这种既赋值又追加的行，
            #    赋值通道已经把 `x` 处理了，此处不重复。
            # ⚠️ 追加**不清除**（`.add` 是往容器里加，不是覆盖容器）。
            for cm in _CONTAINER_ADD.finditer(line):
                cname = _norm(cm.group(1))
                cargs = cm.group(3)
                if cname in _STOPWORDS:
                    continue
                if _is_source(lang, cargs) or (_names(cargs) & cur):
                    cur = cur | {cname}
        res.tainted[i] = set(cur)
        res.runners[i] = set(runners)
    return res


def tainted_names_at(res: TaintResult, line: int) -> set[str]:
    """便捷取数：第 line 行当时处于污点的变量集合。"""
    return res.at(line)


def runner_names_at(res: TaintResult, line: int) -> set[str]:
    """便捷取数：第 line 行当时持有**命令执行器**的变量集合。"""
    return res.runners_at(line)
