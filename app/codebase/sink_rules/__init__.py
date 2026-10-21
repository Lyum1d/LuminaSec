# -*- coding: utf-8 -*-
"""危险 sink 规则库（实施规格 §7.1 的 `sink_rules/`）。

## 这个库**不是**漏洞判定器

它只回答一个问题：**「哪些位置是危险函数的调用点」**。
命中**不等于**漏洞 —— §1.4 说白盒的头号陷阱就是「误报被当成发现」，
而静态匹配**天然无法判断可达性与净化**。

所以每条规则都带两个字段，供判定层（模型）使用：

- `why`：这类 sink 危险**因为什么**（帮模型判断影响面）；
- `hint`：**要证明可利用，还得看什么**（通常是"输入从哪来、中间有没有净化"）。

## 规则为什么放在代码里而不是 JSON

`why`/`hint` 是**给人看也给模型看的长文本**，放进 JSON 需要各种转义与"注释键"的变通；
Python 模块本身就有注释与 docstring，改起来更不容易写错。
每条规则都是 `frozen dataclass`（定义在 `base.py`），**写错了会立刻在测试里暴露**。

## 文件布局

```
sink_rules/
├── base.py          # SinkRule 数据结构 + rule() 构造器（放在这里避免循环导入）
├── php.py           # 一个语言一个模块，便于单独扩
├── java.py
├── python.py
├── javascript.py
└── __init__.py      # 汇总 + 查询接口（本文件）
```

## 覆盖范围是**起点，不是终点**

首批四种语言各挑**最常见、最高产**的 sink。不追求穷举 ——
穷举出来的长清单会稀释注意力，而"看哪里最该先看"本来就有优先级
（见 `data/rules/researcher-blackbox-whitebox.md` §3.0 那张表）。
"""
from __future__ import annotations

from .base import SinkRule, rule            # noqa: F401（对外也暴露这两个名字）
from . import java, javascript, php, python

#: 与语言无关的规则（密钥/凭据类）—— `lang="*"` 表示对所有语言生效
COMMON: list[SinkRule] = [
    rule("secret.aws_ak", "*", "hardcoded_secret", r"AKIA[0-9A-Z]{16}",
         "硬编码的 AWS Access Key，可用于访问云资源",
         "确认它是否仍有效、以及代码是否公开可得"),
    rule("secret.private_key", "*", "hardcoded_secret",
         r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
         "源码内嵌私钥",
         "判断这把私钥用于什么（代码签名 / SSH / 服务间认证）"),
    rule("secret.assignment", "*", "hardcoded_secret",
         # ⚠️ 这里**不能用 `\b`**：`DB_PASSWORD` / `MY_API_KEY` 的变量名前缀是下划线，
         # 而 `_` 属于 word 字符 → `\bpassword` 根本不成立，于是最典型的硬编码口令全漏掉。
         # 召回基准第一次跑就抓到了这一条（`py_hardcoded_secret` 没打到）。
         r"(?i)(?<![A-Za-z0-9])(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret"
         r"|auth[_-]?token|private[_-]?key|passwd|password)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]",
         "疑似把密钥/口令直接写在代码里",
         "先排除示例值；真实的要确认它是否有权限、以及是否已进过公开仓库"),
]

#: 全部规则（顺序即检索顺序，保持稳定以便回归）
ALL: list[SinkRule] = list(COMMON) + list(php.RULES) + list(java.RULES) + \
    list(python.RULES) + list(javascript.RULES)


def rules_for(lang: str) -> list[SinkRule]:
    """取某语言的规则（**含**与语言无关的那组）。"""
    l = (lang or "").lower()
    return [r for r in ALL if r.lang in (l, "*")]


def by_id(rid: str) -> SinkRule | None:
    return next((r for r in ALL if r.id == rid), None)


def kinds() -> list[str]:
    return sorted({r.kind for r in ALL})


def stats() -> dict:
    by_lang: dict[str, int] = {}
    for r in ALL:
        by_lang[r.lang] = by_lang.get(r.lang, 0) + 1
    return {"total": len(ALL), "by_lang": by_lang, "kinds": kinds()}
