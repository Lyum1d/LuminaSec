# -*- coding: utf-8 -*-
"""py_exec 静态能力分档（v047 正式立项，原型来自 v045 实战）。

## 要解决的问题（2026-09-22 tgt-e.test 实战暴露）

风险分级的判定依据原本是**工具**，不是**这段代码实际会做什么**。
`py_exec` 是万能工具，于是一刀切评为 L3（double_confirm，要连续两轮人工确认）。

后果在侦察阶段立刻显现：抓首页、抽 JS 链接、正则提路径、比对响应——
侦察期**几乎所有**动作都要靠 Python，于是每一步都弹 L3。操作者只有两条路：

  · 被几十次弹窗拖死 → 放弃用 py_exec → Agent 能力大幅缩水
  · 闭眼连点确认 → 闸门变成橡皮图章，**比不设闸门更危险**（制造了「已审过」的假象）

实测证据：本轮第一轮侦察里，Agent 一次普通的「抓首页 + 正则抽链接」被判定为
`{"level":"L3","name":"权限 / 横向 / 接管","double_confirm":true}`。

## 分档依据：能力等价，而不是通道

风险等级的本义是「这一步能造成多大后果」。同一种后果走哪个通道进来，
不该改变等级。于是本模块按**代码的静态能力**归入三档，并对齐到已有等级：

| 档位 | 静态能力 | 对齐等级 | 依据 |
|---|---|---|---|
| `readonly_local` | 无网络、无文件写、无子进程、无动态执行 | **L0** | 语义就是 L0「只读 / 本地分析」，与 `note_fact` 同级 |
| `readonly_net` | 仅经受控接口出网（`safe_http_request` 等） | **L2** | 能力与 `httpreplay` 等价，而 `httpreplay` 就是 L2 |
| `opaque` | 含危险能力，**或无法判定** | **L3** | 保持原状，fail-closed |

第二条是这套映射的锚点：**同一个能力必须给同一个等级**。只读单发请求的
`httpreplay` 是 L2，那么「只用受控接口出网 + 纯计算」的 py_exec 能力**不超过**它，
没有理由反过来比它更严。反过来，只要能判定出不只这些能力，就整档回到 L3。

## 定位声明（与 app/pyexec_bridge.py::detect_direct_network 一致）

这是**人机效率优化，不是对抗性安全边界**。

静态分析可被刻意绕过（动态构造属性名、`getattr` 链、`__class__` 爬升……本模块
已把已知路径逐一拒掉，但静态判定不可能完备）。所以本模块的纪律是：

  · **只降级、不升级**：分档结果永远不高于工具原本的等级（`apply_to` 强制）
  · **fail-closed**：判定不出确定结论 → 一律回到 L3 交人工
  · **只减少确认次数，不放宽任何执行能力**：真正的边界始终是
    py_exec 沙箱（env 白名单 + 临时目录 + Job Object）+ TrafficGovernor
    + data/scope.json + Burp 侧人工闸门
  · 被降级的步骤**必须留痕**（`apply_to` 返回可读理由，由调用方写进事件与步骤记录）

## 两处「字面量例外」（v048 补齐第二条）

`__import__` 与 `getattr` 都是动态能力的入口，默认拒绝。但当**参数是字面量字符串**时，
它们不构成任何动态能力 —— 这种形态拦下来只是白卡一步（两处都是实测踩出来的）：

| 例外 | 放行条件 | 判定函数 |
|---|---|---|
| `__import__("re")` | 唯一实参、字面量、模块在白名单内 | `_literal_allowed_import` |
| `getattr(x, "text", "")` | 2–3 个位置参数、第 2 个是字面量、不以 `_` 开头、不在 `DENIED_ATTR_NAMES` | `_literal_allowed_getattr` |

**为什么第二条必须补**：第一条早已存在，第二条却一直缺 —— 同一个原理只落在一半的
入口上，就是自相矛盾。`getattr(obj, "text", "")` 是模型最常用的防御性取字段写法，
实测因它一步 py_exec 被判 L3、白等 90 秒。

## 与 `_classify_step.py` 的关系

那个文件是本模块的原型（v045 实战期间以临时脚本形式验证收益，27/27 自测通过）。
现在判定逻辑**只有这一份实现**，原型脚本已改为薄壳转调本模块——
两套实现并存必然分叉，而分叉的防线上限是「两套里更松的那套」。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from . import config

# 纯计算模块：不含文件 / 网络 / 进程能力。
# 白名单而不是黑名单——新增模块默认拒绝，逼着人来复核。
ALLOWED_MODULES = {
    "re", "json", "base64", "binascii", "hashlib", "hmac", "math", "cmath",
    "collections", "itertools", "functools", "operator", "string", "textwrap",
    "difflib", "datetime", "time", "calendar", "html", "unicodedata",
    "csv", "random", "statistics", "decimal", "fractions", "uuid", "typing",
    "dataclasses", "enum", "abc", "copy", "pprint", "zlib", "gzip",
    "urllib.parse",      # 只放 parse 子模块（request/error 不在白名单）
    "json.decoder",
}

# srcagent 受控通道里允许使用的名字（沙箱注入的 API）。
#
# ⚠️ 这张表**必须与沙箱实际导出的名字逐一对应**（v048 加守卫测试绑定）。
# 原先表里还有 `range_download` 与 `save_artifact` 两个名字 —— 实测**沙箱根本没导出它们**
# （`save_artifact` 是 store 的宿主侧函数，`range_download` 在所有代码里都查不到）。
# 后果很隐蔽：脚本写 `from srcagent import save_artifact` 会被判「只读出网」放行，
# 然后在子进程里 ImportError —— **闸门说自己放行了一个它其实不该放行的东西**。
# 白名单列出不存在的 API，比漏列更糟：漏列只是多问一次人，多列是给了假许可。
# 已移除；将来要提供这两个能力，先实现沙箱导出，再回填到这里。
ALLOWED_SRCAGENT_NAMES = {
    "safe_http_request", "get", "post", "tmpdir", "TMPDIR", "Resp",
    "save_text", "load_text", "list_tmpdir",
    # v045.2：原始字节读取。**必须有这三个** —— 平台落盘是二进制 `.bin`，
    # 而 docstring 原本教人用 `open(p, "rb")`（被本判定器禁止），
    # 于是「被文档推荐的标准动作」反而过不了自己的闸门（实测白烧三步）。
    "load_bytes", "file_md5", "file_info",
}

# 允许「裸导入」的模块。srcagent 必须在内 —— Agent 撞到字段名错误后用
# `print(safe_http_request.__doc__)` / `dir(srcagent)` 内省 API 是**正确行为**。
# 前提是下面「禁止下划线属性」规则生效：沙箱模块内部是 `import os as _os`，
# `srcagent._os` 是一条真实逃逸路径。
ALLOWED_BARE_MODULES = ALLOWED_MODULES | {"srcagent"}

# 会出网的名字（决定 readonly_net 档）
EGRESS_NAMES = {"safe_http_request", "get", "post"}
# 会产生本地副作用的受控名字（拿不准算不算「只读」→ 统一按 net 档，宁严不松）
EFFECT_NAMES = {"save_text"}

# 禁止访问下划线开头的属性（`_os` / `__class__` / `__globals__` / `__subclasses__` …）。
# 这条比「禁止导入」更贴近真实威胁：`import re; re._compiler` 本身无害，
# 真正的逃逸是「拿到某个对象再顺着私有属性爬到 os / builtins」。
ALLOWED_DUNDER_ATTRS = {"__doc__", "__name__"}

# 危险内建：出现即判非只读。
# 注意必须含 getattr —— 它是「动态取属性」的入口，实测可绕过静态判定：
#   getattr(__builtins__, 'ev'+'al')('1')   ← 拼出来的名字躲过字面量检查
# 宁可让用了 getattr 的正常代码回落到人工确认，也不放行这条绕过路径。
# **例外**：参数是字面量字符串的 getattr 不构成动态能力，见 _literal_allowed_getattr。
DENIED_BUILTINS = {
    "open", "exec", "eval", "compile", "__import__", "input", "breakpoint",
    "globals", "locals", "vars", "setattr", "delattr", "getattr", "exit",
    "quit", "help", "memoryview",
}

# 「属性名本身就是危险动词」的名单。
# 为什么 `getattr` 放开字面量调用之后还需要它：`getattr(x, "system")` 的参数确实是
# 字面量、也确实不以 `_` 开头，但取到的属性本身就是起进程 / 删文件 / 出网的入口。
# 光看「是不是字面量」不够，还得看「取出来的这个名字危不危险」。
DENIED_ATTR_NAMES = {
    # 起进程
    "system", "popen", "spawn", "spawnl", "spawnle", "spawnv", "spawnve",
    "execv", "execve", "execvp", "execvpe", "fork", "forkpty", "posix_spawn",
    "run", "call", "check_output", "check_call", "Popen", "startfile",
    # 环境与路径
    "environ", "getenv", "putenv", "chdir", "chroot", "getcwd", "startfile",
    # 文件系统
    "listdir", "scandir", "walk", "remove", "unlink", "rmdir", "removedirs",
    "rmtree", "chmod", "chown", "rename", "replace", "symlink", "link",
    "mkdir", "makedirs", "open", "fdopen",
    # 网络
    "urlopen", "urlretrieve", "socket", "connect", "bind", "listen", "send",
    "sendall", "recv", "recvfrom",
    # 动态加载与内省逃逸
    "modules", "import_module", "invalidate_caches", "reload",
    "builtins", "__builtins__", "__loader__", "__import__",
    # 终止
    "kill", "killpg", "abort", "_exit",
}

# 危险根模块：任何位置的引用都判非只读。
DENIED_ROOTS = {
    "os", "sys", "subprocess", "socket", "shutil", "pathlib", "ctypes",
    "pickle", "marshal", "importlib", "builtins", "__builtin__", "tempfile",
    "glob", "io", "threading", "multiprocessing", "asyncio", "signal",
    "pty", "platform", "webbrowser", "runpy", "code", "codeop", "site",
    "requests", "httpx", "aiohttp", "urllib.request", "urllib.error",
    "http", "ssl", "ftplib", "smtplib", "telnetlib", "xmlrpc", "sqlite3",
    "shelve", "dbm", "fcntl", "msvcrt", "winreg", "posix", "nt",
    # 内建命名空间本身就是逃逸入口（可从中取到 eval / open）
    "__builtins__", "__builtin__",
}

TIER_LOCAL = "readonly_local"
TIER_NET = "readonly_net"
TIER_OPAQUE = "opaque"


@dataclass
class Grade:
    """一次分档结果。"""
    tier: str
    level: str          # 建议等级（L0/L1/L2/L3）
    reason: str         # 面向操作者的一句话依据
    detail: str = ""    # 命中的具体能力（problems 列表摘要）

    @property
    def downgradable(self) -> bool:
        return self.tier in (TIER_LOCAL, TIER_NET)


def _root_name(node: ast.AST) -> str:
    """取属性链最左端的名字（a.b.c → a）。"""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _dotted(node: ast.AST) -> str:
    """把 Name/Attribute 链拼成点分字符串（urllib.parse → 'urllib.parse'）。"""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _literal_allowed_import(node: ast.Call) -> bool:
    """判断 `__import__("re")` 这类**静态**导入是否无害。

    为什么单开一条：`__import__` 本身是动态导入逃逸路径（`__import__("o"+"s")`
    能拿到 os），所以它在 DENIED_BUILTINS 里。但模型偶尔写
    `__import__('re').findall(...)` 代替顶部 import —— 这种形态**参数是字面量、
    模块在白名单内**，不构成任何逃逸能力，拦下来只是白卡一步（实测踩过一次：
    Agent 一个干净的只读取图/取表单脚本因此被拒）。

    判定极窄：唯一实参、字面量字符串、且模块在 ALLOWED_MODULES 内。
    任何拼接、变量、关键字参数都仍然拒绝（fail-closed）。
    """
    if len(node.args) != 1 or node.keywords:
        return False
    a = node.args[0]
    if not (isinstance(a, ast.Constant) and isinstance(a.value, str)):
        return False
    return a.value in ALLOWED_MODULES


def _literal_allowed_getattr(node: ast.Call) -> bool:
    """判断 `getattr(obj, "字面量名"[, 默认值])` 是否无害。

    为什么单开一条（v048 实测踩到）：`getattr` 本身是动态取属性的入口，
    `getattr(__builtins__, "ev"+"al")` 是经典绕过，所以它在 DENIED_BUILTINS 里。
    但模型大量使用**字面量的防御性取字段**（`getattr(r, "text", "")`）——
    这与 `__import__("re")` 是**同一类**「参数是字面量、不构成任何动态能力」的形态。
    分档器已经给后者开了窄例外，却对前者一律拒绝，**自相矛盾**。

    实测代价：一步 py_exec 因此被判 L3、白等 90 秒才被拒（2026-09-25 某企业站）。

    判定极窄，四条同时满足才放行：
      · 2 或 3 个位置参数、**无**关键字参数
      · 第 2 个参数是**字面量字符串**
      · 该字符串**不以 `_` 开头**（挡 `__class__` / `__globals__` / `__subclasses__`）
      · 不在 DENIED_ATTR_NAMES（挡「属性名本身就是危险动词」，如 `getattr(x, "system")`）

    任何拼接、变量、双下划线属性名都仍然拒绝（fail-closed）。
    """
    if node.keywords or not (2 <= len(node.args) <= 3):
        return False
    arg = node.args[1]
    if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
        return False
    name = arg.value
    if not name or name.startswith("_"):
        return False
    return name not in DENIED_ATTR_NAMES


def analyze(code: str) -> tuple[list[str], bool]:
    """静态扫描代码，返回 (非只读能力清单, 是否出网)。

    出网 = 用到 EGRESS_NAMES 或 EFFECT_NAMES 里的受控名字。
    """
    src = (code or "").strip()
    if not src:
        return ["空代码"], False
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        # 语法错误交给调用方（v045 的 syntax_error 预检先跑，会给出更友好的信息）
        return [f"语法错误，无法静态判定：{e.msg}"], False

    problems: list[str] = []
    net = False

    for node in ast.walk(tree):
        # ---- import ----
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name not in ALLOWED_BARE_MODULES:
                    problems.append(f"import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "srcagent":
                for a in node.names:
                    if a.name not in ALLOWED_SRCAGENT_NAMES:
                        problems.append(f"srcagent.{a.name}")
                    elif a.name in EGRESS_NAMES or a.name in EFFECT_NAMES:
                        net = True
            elif mod not in ALLOWED_MODULES:
                problems.append(f"from {mod} import")

        # ---- 私有属性访问（逃逸主路径）----
        # 单列一条：它不依赖「调用」也不依赖「根模块名」。只要出现
        # `x._os` / `y.__class__` 这类链，就可能是爬向 os / builtins。
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_") and node.attr not in ALLOWED_DUNDER_ATTRS:
                problems.append(f"访问私有属性 .{node.attr}")
            # 裸导入 srcagent 后的属性用法：srcagent.safe_http_request(...)
            if _root_name(node) == "srcagent":
                if node.attr not in ALLOWED_SRCAGENT_NAMES:
                    problems.append(f"srcagent.{node.attr}")
                elif node.attr in EGRESS_NAMES or node.attr in EFFECT_NAMES:
                    net = True

        # ---- 危险内建调用 ----
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in DENIED_BUILTINS:
                # 两处窄例外：字面量白名单模块的 __import__、字面量属性名的 getattr
                # （两者的共同点：**参数是字面量 → 不构成动态能力**）
                if f.id == "__import__" and _literal_allowed_import(node):
                    continue
                if f.id == "getattr" and _literal_allowed_getattr(node):
                    continue
                problems.append(f"调用 {f.id}()")
            elif isinstance(f, ast.Attribute):
                base = _root_name(f)
                if base in DENIED_ROOTS:
                    problems.append(f"调用 {_dotted(f)}()")
                # 动态取属性 / 直接起进程：可能绕过静态判定
                if base == "getattr" or f.attr in ("system", "popen", "spawn",
                                                   "execv", "execve", "fork"):
                    problems.append(f"调用 {_dotted(f)}()")

        # ---- 危险根模块的任意引用（不只是调用）----
        elif isinstance(node, ast.Name):
            if node.id in DENIED_ROOTS:
                problems.append(f"引用 {node.id}")

    return problems, net


def grade(code: str) -> Grade:
    """对 py_exec 代码分档。判定不出结论时一律返回 opaque（fail-closed）。"""
    problems, net = analyze(code)
    if problems:
        uniq = sorted(set(problems))
        return Grade(
            tier=TIER_OPAQUE,
            level="L3",
            reason="含非只读能力或无法静态判定，保持 L3 人工确认",
            detail="、".join(uniq[:6]),
        )
    if net:
        return Grade(
            tier=TIER_NET,
            level=config.PY_EXEC_GRADE_LEVEL_NET,
            reason="仅经受控接口出网，能力与 httpreplay 等价",
            detail="",
        )
    return Grade(
        tier=TIER_LOCAL,
        level=config.PY_EXEC_GRADE_LEVEL_LOCAL,
        reason="结构上只读：无网络、无文件写、无子进程、无动态执行",
        detail="",
    )


def classify_py_exec(code: str) -> tuple[bool, str]:
    """原型兼容接口：是否「结构上只读」。返回 (是否只读, 理由)。

    保留它是为了让 v045 期间写的自测与调用点不用改语义；
    新增代码请直接用 `grade()`（它还能区分「本地只读」与「受控出网」）。
    """
    problems, _ = analyze(code)
    if problems:
        return False, "含非只读能力：" + "、".join(sorted(set(problems))[:6])
    return True, "结构上只读（仅受控通道出网 + 纯计算）"


_LEVEL_ORDER = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "": 9}


def apply_to(code: str, base_risk: dict) -> tuple[dict, str]:
    """把分档结果套到基线 risk 上，返回 (新的 risk dict, 人类可读说明)。

    说明为空串表示**未降级**（调用方据此决定要不要发事件）。
    三条不可让步的纪律：
      1. 分档**只降级不升级** —— 结果高于基线时原样返回基线；
      2. 关闭开关（`AGENT_PY_EXEC_GRADE=0`）时完全不动（操作者要绝对保守时的出口）；
      3. `double_confirm` 必须跟着等级一起改 —— 只改 level 会让前端与后端
         （`_await_confirm` 读的是 `risk.double_confirm`）对同一等级给出不同行为。
    """
    if not config.PY_EXEC_GRADE_ENABLED:
        return base_risk, ""

    g = grade(code)
    base_level = str(base_risk.get("level") or "")
    if _LEVEL_ORDER.get(g.level, 9) >= _LEVEL_ORDER.get(base_level, 0):
        # 不降级：可能是判定为 opaque（L3 == L3），也可能是基线本来就更低
        return base_risk, ""

    meta = config.RISK_LEVELS.get(g.level)
    if not meta:
        return base_risk, ""

    new_risk = dict(base_risk)
    new_risk.update({
        "level": g.level,
        "name": meta["name"],
        "auto": meta["auto"],
        "double_confirm": meta["double_confirm"],
        "reason": f"静态能力分档（{g.tier}）：{g.reason}"
                  + (f"；{g.detail}" if g.detail else "")
                  + f"｜原定级 {base_level}",
    })
    note = (f"py_exec 本步经静态能力分档判为 {g.level}（{meta['name']}），"
            f"低于工具默认的 {base_level}：{g.reason}"
            + (f"（{g.detail}）" if g.detail else "")
            + "。这是减少人工确认次数的效率优化，执行能力未放宽 —— "
              "沙箱、授权范围与流量治理照常生效。")
    return new_risk, note
