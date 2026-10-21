# -*- coding: utf-8 -*-
"""JavaScript / TypeScript 的危险 sink（含前端 XSS 与服务端 Node）。"""
from __future__ import annotations

from .base import SinkRule, rule

RULES: list[SinkRule] = [
    # ---------- 代码执行 ----------
    rule("js.rce.eval", "javascript", "rce",
         r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*[\"']",
         "把字符串当代码执行",
         "输入是否可控；是否只是配置/表达式求值（那也是注入）"),
    rule("js.rce.timeout_string", "javascript", "rce",
         r"\bset(?:Timeout|Interval)\s*\(\s*[\"']",
         "`setTimeout('字符串')` 会把它当代码执行（易被忽略的 RCE 面）",
         "第一个参数是不是用户可影响的字符串"),
    rule("js.rce.vm", "javascript", "rce",
         r"\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|createScript|Script)\b",
         "Node 的 vm 模块常被当沙箱，但**沙箱逃逸是已知的**（能拿到宿主对象即可 RCE）",
         "有没有把宿主对象传进上下文（`this`/`process`/`require`）"),
    rule("js.rce.child_process", "javascript", "rce",
         r"\bchild_process\b|\b(?:execSync|exec|execFile|spawn|spawnSync|fork)\s*\(",
         "执行系统命令；参数可控即 RCE。`exec` 会走 shell，比 `execFile` 更危险",
         "用的是 exec（shell）还是 execFile（无 shell）；参数来源与转义"),
    rule("js.rce.require_dynamic", "javascript", "path_traversal",
         r"\brequire\s*\(\s*[a-zA-Z_$]",
         "动态 require 路径 —— 配合路径穿越可加载任意模块",
         "路径是否可控；能否 `../` 穿越"),

    # ---------- SQL / NoSQL ----------
    rule("js.sqli.concat", "javascript", "sqli",
         r"\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)",
         "SQL 用模板串/拼接 —— 经典注入",
         "是否用参数化（`?`/`$1`）；拼接的是值还是表名"),
    rule("js.nosqli.object", "javascript", "sqli",
         r"\$(?:where|ne|gt|regex)\b|\.find\s*\(\s*req\.",
         "把整个请求对象直接传给 Mongo 查询 —— `$where`/`$ne` 可绕过认证",
         "有没有对查询对象做字段白名单或类型校验（应排除以 `$` 开头的键）"),

    # ---------- 前端 XSS ----------
    rule("js.xss.innerhtml", "javascript", "xss",
         r"\.innerHTML\s*=|\.outerHTML\s*=|document\s*\.\s*write\s*\(",
         "直接写入 HTML —— 内容来自用户输入时是 DOM XSS",
         "赋值来源；有无用 textContent 或框架的转义。"
         "⚠️ 这是**宽口径**规则（`.innerHTML =` 在任何前端项目里都太普遍 —— "
         "实测在某真实仓库命中 92 处、占该次扫描总量的 45%，而**全部是假阳性**："
         "插值都过了项目自己的 `esc()` / `md()` 转义）。"
         "它是为「DOM XSS 的注入点**没有它就全漏**」而留的，"
         "命中请当**低置信候选**看待 —— 必须逐个插值确认有没有过转义，再下结论。"),
    rule("js.xss.react_dangerous", "javascript", "xss",
         r"dangerouslySetInnerHTML",
         "React 里显式绕过转义 —— 名字就说明了它在做什么",
         "传入的 html 是否可能含用户输入；有无做 sanitize（DOMPurify）"),
    rule("js.xss.template_raw", "javascript", "xss",
         r"v-html\s*=|\[innerHTML\]\s*=",
         "Vue/Angular 里显式渲染原始 HTML",
         "同上：内容来源 + 有无 sanitize"),

    # ---------- 文件与路径 ----------
    rule("js.path.fs", "javascript", "path_traversal",
         r"\bfs\s*\.\s*(?:readFile|readFileSync|writeFile|writeFileSync|unlink|"
         r"createReadStream|createWriteStream|rm|rmdir)\s*\("
         r"|\bpath\s*\.\s*join\s*\(",
         "文件操作/路径拼接 —— 路径可控即可穿越（`path.join` 不防 `..`）",
         "有没有 `path.resolve` + 前缀校验；能否 `..` 穿越"),

    # ---------- SSRF ----------
    rule("js.ssrf.fetch", "javascript", "ssrf",
         r"\b(?:fetch|axios|got|superagent|request|https?)\s*(?:\.\s*(?:get|post|put|delete|request|patch))?\s*\(",
         "发起外部请求 —— URL 可控即可探测内网",
         "URL 是否可控；有无网段/协议白名单与重定向限制"),

    # ---------- 反序列化 ----------
    rule("js.deser.node_serialize", "javascript", "deserialization",
         r"\bnode-serialize\b|\bunserialize\s*\(|\byaml\s*\.\s*load\s*\(",
         "不安全的反序列化（`node-serialize` 的 IIFE 载荷可直接 RCE；js-yaml 旧版可实例化函数）",
         "数据来源；库版本；能否换成 JSON"),

    # ---------- 其他 ----------
    rule("js.jwt.none", "javascript", "auth_bypass",
         r"algorithms?\s*:\s*\[?\s*[\"']none[\"']|verify\s*\([^)]{0,80}?\balgorithms\s*:\s*\[\s*\]",
         "JWT 允许 `none` 算法或未限定算法 —— 可伪造任意身份",
         "服务端是否强制校验算法；密钥是否弱/硬编码"),
    rule("js.postmessage.origin", "javascript", "auth_bypass",
         r"addEventListener\s*\(\s*[\"']message[\"']|onmessage\s*=",
         "postMessage 处理里若不校验 `event.origin`，任意站点可投递消息",
         "有没有检查 `event.origin`；消息内容是否直接进危险 sink"),
    rule("js.crypto.weak", "javascript", "weak_crypto",
         r"createHash\s*\(\s*[\"'](?:md5|sha1)[\"']|Math\s*\.\s*random\s*\(\s*\)",
         "MD5/SHA-1 或 `Math.random()` 用于安全场景",
         "是否用于口令/令牌/签名；应改用 crypto 的强算法与 `crypto.randomBytes`"),
]
