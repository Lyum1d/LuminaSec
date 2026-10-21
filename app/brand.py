# -*- coding: utf-8 -*-
"""LuminaSec 品牌标识 —— 启动横幅的**唯一数据源**。

v114 起产品由「SRC 渗透 Agent」更名为 **LuminaSec**。启动时终端里那行
「SRC 渗透 Agent · 本地控制台」换成由符号拼成的大标题。

两个入口共用本模块，不各写一份：
    - `run.py`               import 后打印（Python 侧）
    - `启动控制台.bat`        echo 同一批行（GBK + CRLF，见 `bat_lines()`）
    - `test_brand.py`        断言 bat 里的行与本模块一致（防漂移护栏）

⚠️ 为什么全用纯 ASCII（`_ | / \\ ( ) ,`）而不用 Unicode 方块（`█ ╗ ═ ║`）：
   Windows 终端默认代码页是 936（GBK），本项目 `启动控制台.bat` 本身就是 GBK
   编码。Unicode 制表符在两种代码页下必有一个显示为乱码，而 ASCII 在任何
   代码页下都安全。品牌名的第一要件是「被一眼认出」，不能赌用户的 chcp。

字体：FIGlet `slant`（斜体，55 列 × 5 行）—— 由 pyfiglet 生成后**固化为
静态字符串**，运行时不再依赖 pyfiglet（它不在 requirements.txt 里）。
"""
from __future__ import annotations

import unicodedata

#: 产品名。用于 FastAPI title、网页 <title>、报告落款等处。
NAME = "LuminaSec"

#: 一句话副标题（大字下面那行）。中文在终端里占 2 列，见 `_dw()`。
TAGLINE = "本地控制台 · 仅限已获得书面授权的目标测试"

#: LuminaSec 大标题（FIGlet slant，5 行 × 55 列，纯 ASCII）。
ART: tuple[str, ...] = (
    "    __                    _             _____",
    "   / /   __  ______ ___  (_)___  ____ _/ ___/___  _____",
    "  / /   / / / / __ `__ \\/ / __ \\/ __ `/\\__ \\/ _ \\/ ___/",
    " / /___/ /_/ / / / / / / / / / / /_/ /___/ /  __/ /__",
    "/_____/\\__,_/_/ /_/ /_/_/_/ /_/\\__,_//____/\\___/\\___/",
)


def _dw(s: str) -> int:
    """终端显示宽度：CJK/全角算 2 列，其余算 1 列。

    不能用 `len()` 对齐 —— `len("本地控制台")` 是 5，但在终端里占 10 列，
    直接拿 len 补空格会让中文副标题相对艺术字右移半行。
    """
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
               for c in s)


def _pad(s: str, width: int) -> str:
    """按显示宽度右补空格（CJK 已按 2 列计）。"""
    return s + " " * max(0, width - _dw(s))


def art_lines() -> list[str]:
    """大标题各行（不含副标题与边框）。"""
    return list(ART)


def banner(subtitle: str = TAGLINE, *, border: str = "=", pad: int = 2) -> str:
    """拼出完整启动横幅：大字 + 一行副标题，上下加边框。

    `border`/`pad` 可调，默认与旧版视觉一致（`=` 边框、2 列内缩）。
    """
    lines = art_lines()
    inner = max([_dw(l) for l in lines] + [_dw(subtitle)])
    out = [border * (inner + pad * 2)]
    for l in lines:
        out.append(" " * pad + _pad(l, inner))
    if subtitle:
        out.append(" " * pad + _pad(subtitle, inner))
    out.append(border * (inner + pad * 2))
    return "\n".join(out)


def bat_lines(subtitle: str = TAGLINE, *, pad: int = 2) -> list[str]:
    """给 `启动控制台.bat` 用的 `echo` 行（ASCII 部分，GBK 安全）。

    bat 在探测 Python **之前**就要打印横幅，那时还没有可用的解释器，
    所以不能靠 import 本模块 —— 只能把行固化成 echo。drift 由
    `test_brand.py` 断言兜底。

    `pad` 与 `banner()` 保持一致：艺术字在边框内右缩 2 列。
    """
    art = art_lines()
    inner = max([_dw(l) for l in art] + [_dw(subtitle)])
    bar = "=" * (inner + pad * 2)
    out = ["echo " + bar]
    for l in art:
        out.append("echo " + " " * pad + l)
    out.append("echo " + " " * pad + subtitle)
    out.append("echo " + bar)
    return out
