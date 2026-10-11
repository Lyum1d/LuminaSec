# -*- coding: utf-8 -*-
"""PHP 的危险 sink（PHP 是首批四种里 0day 最高产的一类 —— 用户决策②把它排第一）。

配套的判定依据见 `data/rules/researcher-blackbox-whitebox.md` 的 Phase 3（Sink 逆向追踪）。
"""
from __future__ import annotations

from .base import SinkRule, rule

RULES: list[SinkRule] = [
    # ---------- 代码执行 ----------
    rule("php.rce.eval", "php", "rce",
         r"\b(?:eval|assert)\s*\(",
         "把字符串当 PHP 代码执行，输入可控即远程代码执行",
         "看括号里的值从哪来：是否来自 $_GET/$_POST/请求头；有没有只允许白名单"),
    rule("php.rce.dynamic_call", "php", "rce",
         r"\b(?:call_user_func|call_user_func_array|forward_static_call)\s*\(",
         "以变量当函数名/回调调用 —— 常见于「参数决定调用什么」的写法",
         "追第一个参数（被调用的函数名）是否用户可控"),
    rule("php.rce.create_function", "php", "rce",
         r"\bcreate_function\s*\(", r"老 API：内部 eval，等价于代码执行",
         "PHP 7.2 起已废弃，但老代码里仍常见"),
    rule("php.rce.preg_e", "php", "rce",
         r"\bpreg_replace\s*\([^)]{0,80}?/e",
         r"`preg_replace` 的 `/e` 修饰符会把替换结果当代码执行",
         "PHP 7 起已移除，属遗留代码里的高危点"),
    rule("php.rce.include", "php", "rce",
         r"\b(?:include|include_once|require|require_once)\s*[\( ]\s*\$",
         r"被包含的文件路径是变量 —— 可文件包含（LFI），配合上传可 RCE",
         "看变量来源；有没有固定前缀/白名单；能否配合上传落一个可执行文件"),

    # ---------- 命令执行 ----------
    rule("php.rce.shell", "php", "rce",
         r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
         "直接调用系统命令执行函数",
         "追参数来源与转义（escapeshellarg/escapeshellcmd 是否用上、用了是否够）"),

    # ---------- 反序列化 ----------
    rule("php.deser.unserialize", "php", "deserialization",
         r"\bunserialize\s*\(",
         "反序列化用户数据可触发 POP 链上的魔术方法 → RCE/任意文件操作",
         "输入是否可控；项目里有没有可用的 gadget 链（常来自依赖）"),

    # ---------- SQL ----------
    rule("php.sqli.concat", "php", "sqli",
         r"(?:mysql|mysqli|pg|sqlite)[_a-z]*query\s*\([^;]{0,120}?\$"
         # `(?<!\[)` 用来排除**参数化绑定**：`->execute([$name])` 里的 `$` 紧跟在 `[` 后，
         # 那是绑定数组而不是"SQL 串里拼变量"。召回基准的负样本 `neg_php_prepared` 抓到的。
         r"|->(?:query|exec|prepare|execute)\s*\([^;]{0,120}?(?<!\[)\$",
         "SQL 语句里直接拼接变量 —— 经典注入",
         "看是否用了预处理（参数化）；拼接的是标识符还是值；有无 addslashes 这类不充分的转义"),

    # ---------- 文件与路径 ----------
    rule("php.path.file_ops", "php", "path_traversal",
         r"\b(?:file_get_contents|file_put_contents|fopen|readfile|file|unlink|"
         r"copy|rename|move_uploaded_file|scandir|glob)\s*\(",
         "文件操作函数的路径若来自外部，可读写任意路径（含配置文件、上传点）",
         "路径是否可被 `..` 穿越；有没有 basename()/realpath() 校验"),
    rule("php.path.upload", "php", "path_traversal",
         r"\$_FILES\s*\[",
         "处理上传文件 —— 常见风险是扩展名/类型校验不足导致的可执行文件落盘",
         "看落盘目录是否可被 Web 访问、扩展名白名单是否严格、是否重命名"),

    # ---------- SSRF / 请求伪造 ----------
    rule("php.ssrf.http", "php", "ssrf",
         r"\b(?:curl_exec|curl_setopt\s*\([^;]{0,60}CURLOPT_URL|fsockopen|"
         r"stream_socket_client)\b",
         "请求外部 URL —— 若 URL 可控则可探测内网/云元数据",
         "URL 是否用户可控；有没有协议与网段白名单"),

    # ---------- 模板注入 ----------
    rule("php.ssti.template", "php", "ssti",
         r"\b(?:Twig|Smarty|Blade|Latte)\b|\{\{.*\}\}",
         "模板引擎的表达式注入（SSTI）—— 常能直达 RCE",
         "模板内容是否由用户输入拼接（而不是把用户输入当变量传入）"),

    # ---------- 重定向 ----------
    rule("php.redirect", "php", "open_redirect",
         r"\bheader\s*\(\s*['\"]Location:\s*['\"]?\s*\.?\s*\$",
         "Location 头由变量拼接 —— 开放重定向（常用于钓鱼/绕过校验）",
         "看是否能重定向到站外；是否被用作 OAuth/回调链的一环"),

    # ---------- XSS（v066 补：DVWA 实测暴露的缺口 —— 16 条 PHP 规则里唯独没有 xss）----------
    # ⚠️ 这几条都带**同一行内的转义黑名单**（`htmlspecialchars` / `htmlentities` / `urlencode`
    # / `strip_tags` / `filter_var`）：XSS 规则最容易犯的错就是把已经转义的安全写法也报出来。
    # 行内黑名单是个粗判据（跨行拼接判不了），所以 `hint` 里明确要求去追输出路径上的转义。
    rule("php.xss.superglobal_to_html", "php", "xss",
         r"^(?!.*(?:htmlspecialchars|htmlentities|htmlspecialchars_decode|urlencode"
         r"|strip_tags|filter_var))"
         r"(?=.*<[A-Za-z/!])"
         r".*\$_(?:GET|POST|REQUEST|COOKIE)\b",
         "把请求变量拼进 HTML 片段 —— 输出时未转义即反射型 XSS",
         "**DVWA 这类「先拼进 $html、之后才 echo」的写法就是它**："
         "要顺着这个变量找到真正的输出点，看那里有没有转义"),
    rule("php.xss.echo_var", "php", "xss",
         r"^(?!.*(?:htmlspecialchars|htmlentities|urlencode|strip_tags|filter_var))"
         r".*\b(?:echo|print)\b[^;]{0,120}?\$",
         "把变量直接输出到页面 —— 内容可由用户影响时即 XSS。",
         "追这个变量能否到请求参数 / 数据库里的用户内容（存储型）；"
         "以及它在到达输出前有没有被转义。"
         "⚠️ 这是**宽口径**规则（`echo` 一个变量在 PHP 里太普遍，DVWA 上命中 58 处、"
         "其中真 XSS 只占一部分）—— 它是为「存储型 XSS 的输出端**没有它就全漏**」而留的，"
         "命中请当**低置信候选**看待，必须先追来源再下结论。"),
    # ⚠️ 已知边界（v066 实测，DVWA）：**存储型 XSS 的输出点常常命中不了**。
    # DVWA 的 `xss_s` 是「输入在 source/*.php 入库 → 输出在 index.php 拼 `$page['body']`」，
    # 输出那一行拼的是**数据库结果变量**、没有超级全局变量 → 单文件规则覆盖不到。
    # 这是**单文件静态规则的固有边界**（与 `fi` 模块「输入与 sink 分居两个文件」同构），
    # **不该靠放宽规则去硬凑**（那会疯狂误报）；跨文件那条链路由判定层追。
    rule("php.xss.short_echo", "php", "xss",
         r"<\?=(?!.*(?:htmlspecialchars|htmlentities))[^?]{0,120}?\$",
         "PHP 短输出标签直接打印变量（等价于 echo）",
         "同 echo：追变量来源能不能到用户输入"),
    rule("php.debug.dump", "php", "debug",
         r"\b(?:var_dump|print_r|phpinfo|debug_zval_dump)\s*\(",
         "调试输出 —— 把内部结构/配置回显给访问者（信息泄露）",
         "确认这行是否在生产可达的路径上"),
]
