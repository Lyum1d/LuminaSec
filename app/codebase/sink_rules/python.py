# -*- coding: utf-8 -*-
"""Python 的危险 sink。

⚠️ 注意：Python 里 `eval`/`exec`/`subprocess` 的使用**大量是正当的**（测试、构建脚本、CLI）。
本库只标"调用点"，**是不是漏洞要看输入从哪来** —— 这正是 `hint` 字段的用途。
"""
from __future__ import annotations

from .base import SinkRule, rule

RULES: list[SinkRule] = [
    # ---------- 代码执行 ----------
    rule("py.rce.eval", "python", "rce",
         # ⚠️ `compile` 必须排除**方法调用**形态（`re.compile(pat)`）：
         #    那是正则编译，与「把字符串当代码执行」毫无关系，而 Python 代码里到处都是它。
         #    v076 自审实测：这条规则在 src-agent 上命中 151 处，**其中 85 处（56%）
         #    是 `re.compile(` / `("class", re.compile(...))` / `re.compile(_user, re.I)`** —— 零 RCE。
         #    裸的三参内建 `compile`（可控输入即可编译执行）仍照常命中。
         #    ⚠️ 本注释同样不写带括号的调用字面量 —— 规则文件是 .py，写了会被自己命中。
         r"\b(?:eval|exec|__import__)\s*\(|(?<![.\w])compile\s*\(",
         "把字符串当代码执行 / 动态导入",
         "输入是否可控；`eval` 的 globals 有没有限制（`{'__builtins__': {}}` 也不是绝对安全）"),
    rule("py.rce.pickle", "python", "deserialization",
         r"\b(?:pickle|cPickle|_pickle|dill|marshal|shelve)\s*\.\s*"
         r"(?:load|loads|Unpickler)",
         "反序列化可执行任意代码（`__reduce__`）—— 只要数据可控就等于 RCE",
         "数据是否来自网络/不可信来源；有没有换成 JSON 之类的纯数据格式"),
    rule("py.deser.yaml_load", "python", "deserialization",
         r"\byaml\s*\.\s*load\s*\(",
         "`yaml.load` 不带 SafeLoader 时可实例化任意对象",
         "有没有 `Loader=SafeLoader` / `yaml.safe_load`"),

    # ---------- 命令执行 ----------
    rule("py.rce.subprocess_shell", "python", "rce",
         r"\bsubprocess\s*\.\s*(?:run|call|check_call|check_output|Popen)\s*\([^)]{0,200}?"
         r"shell\s*=\s*True",
         "`shell=True` 会把参数交给 shell 解释 —— 拼接用户输入即可注入命令",
         "命令串是否由用户输入拼接；能否改成列表传参"),
    rule("py.rce.os_system", "python", "rce",
         r"\bos\s*\.\s*(?:system|popen|spawn\w*|exec\w*)\s*\(",
         "直接调用系统命令",
         "参数来源；有无 shlex.quote 之类的转义"),

    # ---------- SQL ----------
    rule("py.sqli.fstring", "python", "sqli",
         r"(?:execute|executemany|executescript|raw|text)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*%|"
         r"[\"'][^\"']*[\"']\s*\.\s*format|[\"'][^\"']*\{\%)",
         "SQL 用 f-string / % / format 拼接 —— 经典注入",
         "是否用参数化占位符（`?`/`%s` + 元组）；拼接的是值还是表名/排序字段"),
    rule("py.sqli.concat", "python", "sqli",
         r"(?:execute|executemany|raw|text)\s*\([^)]{0,120}?\+\s*\w",
         "SQL 用 `+` 拼接变量",
         "同上：能否参数化"),

    # ---------- 文件与路径 ----------
    rule("py.path.open", "python", "path_traversal",
         r"\bopen\s*\(|os\s*\.\s*(?:remove|unlink|rename|mkdir|makedirs|listdir|walk)\s*\("
         r"|shutil\s*\.\s*(?:copy\w*|move|rmtree)\s*\(",
         "文件操作 —— 路径可控即可穿越（读配置/写任意位置）",
         "有无 `os.path.basename` / `realpath` + 前缀校验；能否 `..` 穿越。"
         "⚠️ 这是**宽口径**规则（Python 里文件读写太日常 —— `open` 系列、`os.remove`、"
         "`shutil` 的复制/删除每天都在用；实测某真实仓库命中 59 处，占该次扫描的 29%，"
         "绝大多数是**固定路径或内部计算的路径**）。"
         "它是为「路径穿越**没有它就全漏**」而留的，"
         "命中请当**低置信候选**看待 —— 必须先确认路径里有没有不可信输入，再下结论。"
         # ⚠️ 本段刻意不写出带**半角括号**的调用字面量：规则文件本身是 `.py`，
         #    写出来会被**自己**命中（v079 实测踩到）。`test_079` 里有自命中守卫。
         ),
    rule("py.path.send_file", "python", "path_traversal",
         r"\b(?:send_file|send_from_directory|FileResponse)\s*\(",
         "Web 框架的文件下发接口 —— 路径可控即任意文件读取",
         "路径是否可控；框架版本是否已修过相关绕过"),

    # ---------- SSRF ----------
    rule("py.ssrf.requests", "python", "ssrf",
         r"\b(?:requests|httpx|urllib|urllib2|urllib3|aiohttp)\b[^\n]{0,40}?"
         r"\.\s*(?:get|post|put|delete|patch|head|request|urlopen|Request)\s*\(",
         "发起外部请求 —— URL 可控即可探测内网/云元数据（169.254.169.254）",
         "URL 是否可控；有无网段/协议白名单；是否跟随重定向"),

    # ---------- 模板注入 ----------
    rule("py.ssti.template", "python", "ssti",
         r"\bTemplate\s*\(|\brender_template_string\s*\(|\bfrom_string\s*\(",
         "模板字符串可控即服务端模板注入 → 常直达 RCE",
         "是「模板内容可控」还是「变量可控」—— 只有前者是 SSTI"),

    # ---------- 弱加密 / 不安全反序列化配套 ----------
    rule("py.crypto.weak", "python", "weak_crypto",
         r"\b(?:md5|sha1)\s*\(|hashlib\s*\.\s*(?:md5|sha1)\s*\(",
         "MD5/SHA-1 不适合口令与签名",
         "是否用于口令（应 bcrypt/argon2）；是否用于签名（可伪造）"),
    rule("py.random.insecure", "python", "weak_crypto",
         r"\brandom\s*\.\s*(?:random|randint|choice|choice|sample|shuffle)\s*\(",
         "`random` 不是密码学安全随机 —— 用于令牌/口令/验证码时可预测",
         "是否用于生成 token/口令/重置码；应改用 `secrets`"),
    rule("py.debug.on", "python", "debug",
         r"\.\s*run\s*\([^)]{0,120}?debug\s*=\s*True|DEBUG\s*=\s*True",
         "调试模式开启 —— Werkzeug 调试器可执行任意代码、泄漏源码",
         "是否只在本机；生产配置是否覆盖"),
]
