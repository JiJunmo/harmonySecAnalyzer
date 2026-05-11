#!/usr/bin/env python3
"""
JSON5 解析器 —— 将鸿蒙项目中的 JSON5 配置文件转为标准 JSON 并解析。

处理以下 JSON5 特性：
  - 单行注释 //
  - 多行注释 /* */
  - 尾逗号
  - 无引号键名（常见于非鸿蒙的 JSON5 文件）
"""

import json
import re
from pathlib import Path
from typing import Any


_STRIP_MULTILINE_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRIP_SINGLELINE_COMMENT = re.compile(r"//.*$", re.MULTILINE)
_STRIP_TRAILING_COMMA = re.compile(r",\s*([}\]])")

# 无引号键名修复 —— 仅在初始解析失败后作为回退使用
# 锚定行首以避免误伤字符串值内的冒号组合（如 $string:xxx）
_FIX_UNQUOTED_KEY = re.compile(r'^(\s*)([a-zA-Z_$][\w$]*)(\s*:)', re.MULTILINE)


def _strip_comments(text: str) -> str:
    """移除 JSON5 注释。"""
    text = _STRIP_MULTILINE_COMMENT.sub("", text)
    text = _STRIP_SINGLELINE_COMMENT.sub("", text)
    return text


def _strip_trailing_commas(text: str) -> str:
    """移除尾逗号。"""
    return _STRIP_TRAILING_COMMA.sub(r"\1", text)


def _fix_unquoted_keys(text: str) -> str:
    """为无引号键名添加双引号（仅处理行首位置，作为解析失败后的回退方案）。"""
    return _FIX_UNQUOTED_KEY.sub(r'\1"\2"\3', text)


def _format_error(cleaned: str, e: json.JSONDecodeError) -> str:
    """格式化解析错误信息。"""
    lines = cleaned.split("\n")
    start = max(0, e.lineno - 3)
    end = min(len(lines), e.lineno + 2)
    context = "\n".join(
        f"  {start + i + 1}: {lines[start + i]}" for i in range(end - start)
    )
    return (
        f"JSON5 解析失败 (行 {e.lineno}, 列 {e.colno}): {e.msg}\n"
        f"上下文:\n{context}"
    )


def clean_json5(text: str) -> str:
    """将 JSON5 文本转换为标准 JSON 字符串（移除注释和尾逗号，不修改键名）。"""
    text = _strip_comments(text)
    text = _strip_trailing_commas(text)
    return text


def parse_json5(text: str) -> Any:
    """
    解析 JSON5 文本为 Python 对象。

    先以标准 JSON 解析；失败时尝试修复无引号键名后重试。

    返回解析结果，解析失败时抛出 ValueError。
    """
    cleaned = clean_json5(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e1:
        # 回退：尝试修复无引号键名
        try:
            fixed = _fix_unquoted_keys(cleaned)
            return json.loads(fixed)
        except json.JSONDecodeError as e2:
            raise ValueError(_format_error(fixed, e2)) from e2


def parse_json5_file(filepath: str | Path) -> Any:
    """
    从文件读取并解析 JSON5。

    返回解析结果，或解析失败时抛出异常。
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"文件不存在: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()

    if not text.strip():
        return {}

    return parse_json5(text)


def safe_parse_json5_file(filepath: str | Path) -> tuple[Any, str | None]:
    """
    安全解析 JSON5 文件，不抛出异常。

    返回 (解析结果, 错误消息)。
    成功时错误消息为 None，失败时解析结果为 None。
    """
    try:
        return parse_json5_file(filepath), None
    except (FileNotFoundError, ValueError, OSError) as e:
        return None, str(e)
