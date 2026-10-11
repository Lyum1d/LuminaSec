# -*- coding: utf-8 -*-
"""召回基准（实施规格 §7.3 / §8 的 A2·A8）。

## 它回答什么问题

**「这次改动让召回涨了还是跌了？」** —— 没有基准，改动就是盲改（本项目既有教训）。
所以这里做的是：一组**有已知答案**的代码样本 + 一个能算出数字的跑分器。

## 两类样本（缺一不可）

- **正样本**：含一个已知形态的漏洞，预期「在某个 `文件:行号` 命中某条规则」→ 计入**召回**；
- **负样本**：「看起来能命中、其实安全」的写法（参数化 SQL、列表传参的 subprocess、
  `yaml.safe_load`、`JSON.parse`、`secrets` 而非 `random`）→ 预期**不该**命中那些规则
  → 计入**精确性**。
  ⚠️ **只测召回不测误报，等于只测了一半** —— §1.4 说白盒头号陷阱就是误报被当发现。

## ⚠️ 这里内置的是「形态样本」，不是真实 CVE 的代码

规格 §7.3 建议"用已知有 CVE 的历史版本"做召回测试。本版内置的是**手工写的最小样本**，
它们**复现已知 CVE 的形态**（Log4Shell 的 JNDI lookup、反序列化、LFI、pickle 等），
但**不是那些项目的真实源码**。所以：

> **本基准测的是「规则能不能打中这个形态」，不是「在真实项目里的召回率」。**

这是**刻意的取舍**：内置样本**离线、秒级、确定**，能进日常回归；真实仓库要下载、慢、还会漂。
两者不冲突 —— `Case.dir` 就是给**真实仓库**留的口子：把某项目的已修复版本 checkout 到本地，
在 `REAL_CASES` 里加一条（`dir=` 指向它 + `expect` 写已知的修复点位置），
同一个跑分器就能算真实召回。**机制是本版交付物，语料可以持续长。**

## ③ 批量基准（v070）：真实仓库 + 官方标注

单点模型回答不了「**这个仓库里 272 个 SQL 注入用例，你打中了几个**」——
那是**批量**的，见 `batch.py`：吃「一个仓库 + 一份逐用例标注 CSV」，
按类别算真实召回/精确性。首个接入 **OWASP BenchmarkJava v1.2**（2740 条官方标注）。

> ⚠️ **DVWA 的 100% 是假的**：那是我们手工挑的点，规则还是照着那个形态调的。
> 真实项目的形态（跨行污染、全限定名、跨行参数区）**完全不同**。
> 要回答「规则在真实项目上到底行不行」，只有拿带官方标注的评测集跑这一条路。

三个来源在报告里**分开统计**：内置语料卡硬阈值；`recall_real`（单点真实用例）
与 `recall_batch`（批量评测集）**只报数，不卡阈值**（取决于本机有没有检出那份代码）。

## 已知误报（不藏起来）

有些用例是**已知会红**的（规则本身的精度问题）。它们不写进"必须通过"的断言里，
而是标 `known_fp` 单列出来 —— **既不掩盖问题，也不让它挡住别的回归**。
"""
from __future__ import annotations

import os
import pathlib
import tempfile
from dataclasses import dataclass, field

from .. import config
from . import index as I
from . import ingest as G
from . import paths as P
from . import search as Q


@dataclass
class Case:
    """一个基准样本。

    要么给 `lines`（内置的形态样本，会被物化成临时目录），
    要么给 `dir`（真实仓库/本地目录的路径）。
    """
    id: str
    kind: str                       # positive | negative
    lang: str
    file: str = ""                  # 相对路径（物化时用）
    lines: list[str] = field(default_factory=list)
    dir: str = ""                   # 真实目录（与 lines 二选一）
    # 正样本：期望命中的位置与规则（任一命中即算召回）
    expect_loc: list[str] = field(default_factory=list)
    expect_rules: list[str] = field(default_factory=list)
    # 负样本：**不该**命中的规则
    forbid_rules: list[str] = field(default_factory=list)
    #: 负样本的作用范围（只检查命中里 `file` 含这个子串的）。
    #: ⚠️ 真实项目必须有它：整个仓库里别处当然会有这些规则命中，
    #: 不限定范围的话，真实项目的负样本**永远会"失败"**，等于没测。
    forbid_in: str = ""
    # 已知误报：说明原因后单列，不参与"必须通过"
    known_fp: str = ""
    note: str = ""


#: 依赖的规则必须真的存在（防止规则改名后基准静默失效）
def _rule_exists(rid: str) -> bool:
    from . import sink_rules as S
    return S.by_id(rid) is not None


#: ------------------------------ 内置形态样本（10 正 + 6 负）------------------------------
CORPUS: list[Case] = [
    # ---------------- PHP ----------------
    Case("php_lfi", "positive", "php", "app.php", [
        "<?php",
        "// 形态：文件包含 + 未过滤输入（LFI，配合上传可 RCE）",
        "$page = $_GET['page'];",
        "include($page . '.php');",
        "?>",
    ], expect_loc=["app.php:4"], expect_rules=["php.rce.include"],
        note="最小 LFI 形态（真实案例：大量 PHP CMS 的 page/module 参数）"),
    Case("php_unserialize", "positive", "php", "app.php", [
        "<?php",
        "// 形态：反序列化用户可控数据（POP 链 → RCE）",
        "$data = base64_decode($_COOKIE['u']);",
        "$obj = unserialize($data);",
    ], expect_loc=["app.php:4"], expect_rules=["php.deser.unserialize"],
        note="cookie 反序列化（真实案例：多款 PHP 框架的 remember-me）"),
    Case("php_xss_reflected", "positive", "php", "xss_r.php", [
        "<?php",
        "// 形态取自 DVWA 反射型 XSS：**先拼进变量、之后才输出**",
        "if( array_key_exists( \"name\", $_GET ) && $_GET[ 'name' ] != NULL ) {",
        "    $html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';",
        "}",
    ], expect_loc=["xss_r.php:4"], expect_rules=["php.xss.superglobal_to_html"],
        note="DVWA 真实形态：sink 是「拼 HTML」，输出点可能在**另一个文件**（跨文件是判定层的活）"),
    Case("php_xss_echo", "positive", "php", "out.php", [
        "<?php",
        "// 形态：把数据库里存的用户内容直接输出（存储型 XSS 的输出端）",
        "$name = $row['name'];",
        "echo $name;",
    ], expect_loc=["out.php:4"], expect_rules=["php.xss.echo_var"],
        note="存储型 XSS 的输出端（DVWA xss_s 的 index.php 就是这个形态）"),

    # ---------------- Java ----------------
    Case("java_jndi", "positive", "java", "Lookup.java", [
        "import javax.naming.InitialContext;",
        "public class Lookup {",
        "    public Object resolve(InitialContext ctx, String url) throws Exception {",
        "        return ctx.lookup(url);",
        "    }",
        "}",
    ], expect_loc=["Lookup.java:4"], expect_rules=["java.jndi.lookup"],
        note="JNDI 注入形态（Log4Shell 同源）"),
    Case("java_deser", "positive", "java", "Session.java", [
        "import java.io.ObjectInputStream;",
        "public class Session {",
        "    public Object restore(ObjectInputStream in) throws Exception {",
        "        return in.readObject();",
        "    }",
        "}",
    ], expect_loc=["Session.java:4"], expect_rules=["java.deser.objectinput"],
        note="原生反序列化形态（真实案例：Java 生态最常见的高危类）"),

    # ---------------- Python ----------------
    Case("py_pickle", "positive", "python", "app.py", [
        "import base64",
        "import pickle",
        "",
        "def load_session(cookie):",
        "    raw = base64.b64decode(cookie)",
        "    return pickle.loads(raw)",
    ], expect_loc=["app.py:6"], expect_rules=["py.rce.pickle"],
        note="pickle 反序列化形态（真实案例：Flask session 伪造）"),
    Case("py_shell", "positive", "python", "tool.py", [
        "import subprocess",
        "",
        "def run(user_cmd):",
        "    subprocess.run(user_cmd, shell=True)",
    ], expect_loc=["tool.py:4"], expect_rules=["py.rce.subprocess_shell"],
        note="shell=True 形态（真实案例：无数后台工具的命令注入）"),
    Case("py_sqli_fstring", "positive", "python", "search.py", [
        "def find(cur, name):",
        "    cur.execute(f\"select * from users where name = '{name}'\")",
    ], expect_loc=["search.py:2"], expect_rules=["py.sqli.fstring"],
        note="f-string 拼 SQL 形态"),
    Case("py_hardcoded_secret", "positive", "python", "config.py", [
        "DB_PASSWORD = \"S3cr3t-P@ssw0rd-2026\"",
        "TIMEOUT = 30",
    ], expect_loc=["config.py:1"], expect_rules=["secret.assignment"],
        note="硬编码口令形态（顺带验证：普通配置项不应误报）"),

    # ---------------- JavaScript ----------------
    Case("js_eval", "positive", "javascript", "render.js", [
        "function render(tpl) {",
        "    return eval(tpl);",
        "}",
    ], expect_loc=["render.js:2"], expect_rules=["js.rce.eval"],
        note="eval 动态执行形态"),
    Case("js_exec", "positive", "javascript", "run.js", [
        "const cp = require(\"child_process\");",
        "",
        "function run(cmd) {",
        "    return cp.exec(cmd);",
        "}",
    ], expect_loc=["run.js:4"], expect_rules=["js.rce.child_process"],
        note="Node 命令执行形态"),

    # ---------------- 负样本（测精确性）----------------
    Case("neg_py_param_sql", "negative", "python", "db.py", [
        "def find(cur, name):",
        "    cur.execute(\"select * from users where name = ?\", (name,))",
    ], forbid_rules=["py.sqli.fstring", "py.sqli.concat"],
        note="参数化 SQL **不该**被判成注入 —— 只看「有没有拼」，不看「参数化没」就是误报"),
    Case("neg_py_subprocess_list", "negative", "python", "tool.py", [
        "import subprocess",
        "",
        "def ls(path):",
        "    subprocess.run([\"ls\", \"-l\", path], capture_output=True)",
    ], forbid_rules=["py.rce.subprocess_shell"],
        note="列表传参（无 shell）**不该**直接判命令注入"),
    Case("neg_py_yaml_safe", "negative", "python", "cfg.py", [
        "import yaml",
        "",
        "def load(text):",
        "    return yaml.safe_load(text)",
    ], forbid_rules=["py.deser.yaml_load"],
        note="`safe_load` 与 `load` 差一个字，**必须区分**"),
    Case("neg_js_json", "negative", "javascript", "parse.js", [
        "function parse(body) {",
        "    return JSON.parse(body);",
        "}",
    ], forbid_rules=["js.rce.eval"],
        note="`JSON.parse` 是纯数据解析，**不该**被当代码执行"),
    Case("neg_py_secrets", "negative", "python", "token.py", [
        "import secrets",
        "",
        "def make():",
        "    return secrets.token_urlsafe(32)",
    ], forbid_rules=["py.random.insecure"],
        note="`secrets` 是密码学安全随机，与 `random` **必须区分**"),
    Case("neg_php_prepared", "negative", "php", "db.php", [
        "<?php",
        "$stmt = $pdo->prepare('select * from users where name = ?');",
        "$stmt->execute([$name]);",
    ], forbid_rules=["php.sqli.concat"],
        note="参数化预处理 **不该**被判成注入。"
             "⚠️ 本条**曾经是已知误报**：规则匹配「括号内有 $」，把 `execute([$name])`"
             "（参数化绑定）也算进去了 —— 是本基准第一次跑就抓出来的，"
             "已用 `(?<!\\[)` 排除「$ 紧跟 `[`」这种绑定数组形态。留在这里当回归钉。"),
    Case("neg_php_escaped_echo", "negative", "php", "safe_out.php", [
        "<?php",
        "// 已转义的输出 —— XSS 规则**不该**报它（这是这类规则最容易犯的误报）",
        "echo htmlspecialchars( $name, ENT_QUOTES, 'UTF-8' );",
        "echo '<h1>Hello</h1>';",
    ], forbid_rules=["php.xss.echo_var", "php.xss.superglobal_to_html"],
        note="转义过 / 纯静态的 echo **不该**被判 XSS"),
    Case("neg_php_concat_escaped", "negative", "php", "safe_concat.php", [
        "<?php",
        "// 拼了 HTML 也拼了请求变量，但**经过转义** —— 不该报",
        "$html .= '<pre>' . htmlspecialchars( $_GET['name'] ) . '</pre>';",
    ], forbid_rules=["php.xss.superglobal_to_html"],
        note="同行有转义函数时不该报 —— 行内黑名单就是为它准备的"),
]


#: 本机真实项目用例的配置文件（**不入库**）。
#:
#: 为什么不在代码里直接写 `dir=` 的绝对路径：那是**本机路径、带用户名**，
#: 进公开仓库既泄露本机信息、又会直接触发 v056 的隐私护栏（v059 就被抓过一次）。
#: 所以沿用 `data/scope.json` / `data/codebases.json` 的同一套约定：
#: **机制入库（本文件 + `*.example` 模板），本机路径写在被 gitignore 的 json 里。**
REAL_CASES_FILE = config.DATA_DIR / "recall_real.json"


def load_real_cases(path: pathlib.Path | None = None) -> list[Case]:
    """读本机真实项目用例。文件不存在/解析失败一律返回空表（**不抛异常**）。

    返回空表是正常状态：没配真实项目时，基准只跑内置语料 —— 不该因此报错。
    """
    import json
    p = pathlib.Path(path) if path else REAL_CASES_FILE
    try:
        if not p.exists():
            return []
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:                                        # noqa: BLE001
        return []
    items = raw.get("cases") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return []
    out: list[Case] = []
    for it in items:
        if not isinstance(it, dict) or not it.get("id") or not it.get("dir"):
            continue                                        # 缺字段直接忽略（宁少不错）
        if not pathlib.Path(it["dir"]).is_dir():
            continue                                        # 目录不在（换机器了）→ 跳过
        out.append(Case(
            id=str(it["id"]),
            kind=str(it.get("kind") or "positive"),
            lang=str(it.get("lang") or ""),
            dir=str(it["dir"]),
            expect_loc=list(it.get("expect_loc") or []),
            expect_rules=list(it.get("expect_rules") or []),
            forbid_rules=list(it.get("forbid_rules") or []),
            forbid_in=str(it.get("forbid_in") or ""),
            known_fp=str(it.get("known_fp") or ""),
            note=str(it.get("note") or ""),
        ))
    return out


# ---------------------------------------------------------------- 跑分

@dataclass
class CaseResult:
    case: Case
    ok: bool
    detail: str
    hits: list[str] = field(default_factory=list)


@dataclass
class Report:
    results: list[CaseResult] = field(default_factory=list)
    known_fp_triggered: list[str] = field(default_factory=list)
    #: 批量基准（真实仓库 + 官方标注）—— 与上面的单点用例**互不影响**。
    #: 单点 = 内置语料 + 自己挑的真实点；批量 = 评测集整体召回。
    batches: list = field(default_factory=list)

    @property
    def positives(self) -> list[CaseResult]:
        return [r for r in self.results if r.case.kind == "positive"]

    @property
    def negatives(self) -> list[CaseResult]:
        return [r for r in self.results if r.case.kind == "negative"]

    # ---- 按来源分开：内置语料（稳定、可卡阈值） vs 本机真实项目（取决于本机有没有检出）----
    @property
    def builtin_results(self) -> list[CaseResult]:
        return [r for r in self.results if not r.case.dir]

    @property
    def real_results(self) -> list[CaseResult]:
        return [r for r in self.results if r.case.dir]

    def recall_of(self, subset: list[CaseResult]) -> float:
        p = [r for r in subset if r.case.kind == "positive"]
        return (sum(1 for r in p if r.ok) / len(p)) if p else 0.0

    def precision_of(self, subset: list[CaseResult]) -> float | None:
        """负样本通过率。**没有负样本时返回 None**（=「未测」，不是 0%）。

        ⚠️ 这里踩过一次：原先无负样本时返回 0.0，于是真实项目那一栏显示「精确性 0%」——
        而事实是**根本没测精确性**（那批用例全是正样本）。
        **把「没测」显示成「0 分」比不显示更有害** —— 看的人会以为规则在误报。
        """
        n = [r for r in subset if r.case.kind == "negative" and not r.case.known_fp]
        if not n:
            return None
        return sum(1 for r in n if r.ok) / len(n)

    def recall(self) -> float:
        p = self.positives
        return (sum(1 for r in p if r.ok) / len(p)) if p else 0.0

    def precision(self) -> float | None:
        """负样本通过率 —— 只认「没被已知误报豁免」的那些。无负样本时返回 None（未测）。"""
        return self.precision_of(self.results)

    def failed(self) -> list[CaseResult]:
        return [r for r in self.results if not r.ok and not r.case.known_fp]

    def render(self) -> str:
        # ⚠️ 精确性是 `float | None` —— **无负样本时是 None（未测），不是 0.0**。
        # 这里必须分两条路渲染：直接 `:.0%` 格式化 None 会 TypeError
        # （v070 加批量基准时被 test_070 撞出来：真实跑总会带内置语料，
        #  所以这条路径一直没被走到 —— 但「只跑批量、不跑单点」是完全合法的用法）。
        b_prec = self.precision_of(self.builtin_results)
        lines = ["=" * 68,
                 "白盒召回基准",
                 "=" * 68,
                 "【内置语料】（稳定，可卡硬阈值）",
                 f"  正样本 {len(self.positives) - len([r for r in self.real_results if r.case.kind == 'positive'])} 个；"
                 f"负样本 {len(self.negatives) - len([r for r in self.real_results if r.case.kind == 'negative'])} 个"
                 f"（其中 {len([r for r in self.negatives if r.case.known_fp and not r.case.dir])} 个为已知误报）",
                 f"  召回率   = {self.recall_of(self.builtin_results):.0%}",
                 "  精确性   = " + (f"{b_prec:.0%}（负样本通过率）" if b_prec is not None
                                   else "（本批未含负样本 → **未测**，不是 0 分）")]
        for r in self.builtin_results:
            mark = "PASS" if r.ok else ("KNOWN-FP" if r.case.known_fp else "FAIL")
            lines.append(f"  [{mark:>8}] {r.case.id:<24} {r.detail}")
        if self.real_results:
            rp = self.precision_of(self.real_results)
            lines += ["", "【本机真实项目】（取决于本机有没有检出那份代码）",
                      f"  召回率   = {self.recall_of(self.real_results):.0%}"
                      f"（{sum(1 for r in self.real_results if r.case.kind == 'positive' and r.ok)}"
                      f"/{len([r for r in self.real_results if r.case.kind == 'positive'])}）",
                      "  精确性   = " + (f"{rp:.0%}" if rp is not None
                                        else "（本批未含负样本 → **未测**，不是 0 分）")]
            for r in self.real_results:
                mark = "PASS" if r.ok else ("KNOWN-FP" if r.case.known_fp else "FAIL")
                lines.append(f"  [{mark:>8}] {r.case.id:<24} {r.detail}")
        else:
            lines += ["", "【本机真实项目】未配置（见 data/recall_real.json.example）"]
        if self.known_fp_triggered:
            lines.append("")
            lines.append("  ⚠️ 已知误报被触发（**不掩盖、不阻塞**，但要知道它还在）：")
            for cid in self.known_fp_triggered:
                c = next(x for x in self.results if x.case.id == cid).case
                lines.append(f"    · {cid}：{c.known_fp}")
        # 批量基准（真实仓库 + 官方标注）单列 —— 它是**真实召回**，不是形态样本
        if self.batches:
            from . import batch as B
            lines += ["", B.render_all(self.batches)]
        lines.append("=" * 68)
        return "\n".join(lines)


def _materialize(case: Case, workspace: pathlib.Path) -> pathlib.Path:
    """把内置样本物化成真实文件（工具要的是**目录**）。"""
    d = workspace / case.id
    f = d / case.file
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(case.lines) + "\n", encoding="utf-8")
    return d


def run_case(case: Case, workspace: pathlib.Path) -> CaseResult:
    """跑单个样本。**依赖仓库/受控根/索引目录都落在 workspace 下**（不碰真实数据）。"""
    src = pathlib.Path(case.dir) if case.dir else _materialize(case, workspace)
    store = workspace / "_store"
    with _patched(store, workspace):
        r = G.ingest(src, codebase_id=f"bench-{case.id}")
        I.build(r.codebase_id)
        hits = Q.search_sinks(r.codebase_id, limit=1000)
        got_rules = {h.rule_id for h in hits}
        got_locs = {h.loc for h in hits}
        shown = sorted(got_locs)[:4]

        if case.kind == "positive":
            hit_loc = [l for l in case.expect_loc if l in got_locs]
            hit_rule = [x for x in case.expect_rules if x in got_rules]
            ok = bool(hit_loc or hit_rule)
            detail = (f"命中 {hit_loc or '—'} / {hit_rule or '—'}"
                      if ok else f"**没打到**（期望 {case.expect_loc or case.expect_rules}；"
                                 f"实际命中 {shown}）")
            return CaseResult(case, ok, detail, shown)

        # 负样本：不该命中 forbidden 规则（可限定在 `forbid_in` 指定的文件范围内）
        sub_hits = [h for h in hits if not case.forbid_in or case.forbid_in in h.file]
        bad = sorted(set(case.forbid_rules) & {h.rule_id for h in sub_hits})
        ok = not bad
        scope = f"（限于 {case.forbid_in}）" if case.forbid_in else ""
        detail = ("未误报 ✓" if ok else f"**误报**：{bad} @ {sorted({h.loc for h in sub_hits})[:3]}")
        return CaseResult(case, ok, detail + scope, [h.loc for h in sub_hits][:4])


class _patched:
    """把 ingest/index 的落盘位置临时改到 workspace 下（**不碰真实 store**）。"""

    def __init__(self, store: pathlib.Path, idx: pathlib.Path):
        self.store, self.idx = store, idx / "_index"
        self._stack = []

    def __enter__(self):
        from unittest import mock
        from . import ingest, index, paths
        self._stack = [
            mock.patch.object(ingest, "CODEBASE_STORE", self.store),
            mock.patch.object(paths, "CODEBASES_FILE", self.store / "codebases.json"),
            mock.patch.object(index, "INDEX_DIR", self.idx),
        ]
        for p in self._stack:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._stack):
            p.stop()
        return False


def evaluate(cases: list[Case] | None = None, workspace: pathlib.Path | None = None,
             include_real: bool = True, include_batch: bool = True) -> Report:
    """跑一遍全部样本。

    默认 = **内置语料** + **本机真实项目用例**（读 `data/recall_real.json`，没有就跳过）
    + **批量基准**（读 `data/recall_batch.json`，没有就跳过）。
    三者在报告里**分开统计**：内置语料稳定、可以卡硬阈值；真实项目与批量基准
    取决于本机有没有检出那份代码，**只报数、不卡阈值**。

    `include_batch=False` 可跳过批量基准 —— 它要**整仓入库 + 建索引**
    （OWASP Benchmark 858 文件约 2 秒），日常快速回归时可以不要
    （内置语料那批是秒级的）。
    """
    if cases is None:
        cases = list(CORPUS) + (load_real_cases() if include_real else [])
    tmp = pathlib.Path(workspace) if workspace else pathlib.Path(
        tempfile.mkdtemp(prefix="recall_"))
    tmp.mkdir(parents=True, exist_ok=True)
    rep = Report()
    for c in cases:
        try:
            rep.results.append(run_case(c, tmp))
        except Exception as e:                                # noqa: BLE001
            rep.results.append(CaseResult(c, False, f"用例执行出错：{type(e).__name__}: {e}"))
    rep.known_fp_triggered = [r.case.id for r in rep.results
                              if r.case.known_fp and not r.ok]
    if include_batch:
        from . import batch as B
        # 批量基准**不抛异常**（`evaluate_batches` 自己兜底），所以这里不用 try
        rep.batches = B.evaluate_batches(workspace=tmp / "_batch")
    return rep


def corpus_health() -> list[str]:
    """语料自身的体检：引用的规则是否存在、样本是否自相矛盾。"""
    problems: list[str] = []
    seen: set[str] = set()
    for c in CORPUS:
        if c.id in seen:
            problems.append(f"{c.id}：id 重复")
        seen.add(c.id)
        if c.kind not in ("positive", "negative"):
            problems.append(f"{c.id}：kind 非法（{c.kind}）")
        if not c.lines and not c.dir:
            problems.append(f"{c.id}：既没有内置样本也没有目录")
        if c.lines and not c.file:
            problems.append(f"{c.id}：有内置样本但没写 file（无法物化）")
        for rid in list(c.expect_rules) + list(c.forbid_rules):
            if not _rule_exists(rid):
                problems.append(f"{c.id}：引用了不存在的规则 {rid}（规则改名后会静默失效）")
        if c.kind == "positive" and not (c.expect_loc or c.expect_rules):
            problems.append(f"{c.id}：正样本没有期望答案")
        if c.kind == "negative" and not c.forbid_rules:
            problems.append(f"{c.id}：负样本没有要禁的规则")
    return problems
