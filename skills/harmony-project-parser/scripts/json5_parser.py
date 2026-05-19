#!/usr/bin/env python3
"""
JSON5 解析器 —— 使用 json5 库将鸿蒙项目中的 JSON5 配置文件解析为 Python 对象。

处理以下 JSON5 特性（由 json5 库原生支持）：
  - 单行注释 //
  - 多行注释 /* */
  - 尾逗号
  - 无引号键名
  - 单引号字符串
  - 十六进制数字、Infinity、NaN
"""

import re
from pathlib import Path
from typing import Any

import json5


# 从 json5 的错误信息中提取行列号 (格式: "<string>:<line> <msg> at column <col>")
_ERROR_PATTERN = re.compile(r"<string>:(\d+).*column\s+(\d+)")


def _format_error(text: str, e: ValueError) -> str:
    """格式化解析错误信息，包含上下文。"""
    msg = str(e)
    lines = text.split("\n")

    # 尝试从错误消息中提取行列号
    match = _ERROR_PATTERN.search(msg)
    if match:
        lineno = int(match.group(1))
        colno = int(match.group(2))
        start = max(0, lineno - 3)
        end = min(len(lines), lineno + 2)
        context = "\n".join(
            f"  {start + i + 1}: {lines[start + i]}" for i in range(end - start)
        )
        return (
            f"JSON5 解析失败 (行 {lineno}, 列 {colno}): {msg}\n"
            f"上下文:\n{context}"
        )

    # 回退：无法提取行列号时显示原始错误
    last_lines = lines[-5:] if len(lines) > 5 else lines
    context = "\n".join(f"  ...{l}" for l in last_lines)
    return f"JSON5 解析失败: {msg}\n末尾上下文:\n{context}"


def parse_json5(text: str) -> Any:
    """
    解析 JSON5 文本为 Python 对象。

    返回解析结果；解析失败时抛出 ValueError（包含上下文信息）。
    """
    if not text.strip():
        return {}

    try:
        return json5.loads(text)
    except ValueError as e:
        raise ValueError(_format_error(text, e)) from e


def parse_json5_file(filepath: str | Path) -> Any:
    """
    从文件读取并解析 JSON5。

    返回解析结果；解析失败时抛出异常。
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"文件不存在: {filepath}")

    text = filepath.read_text(encoding="utf-8")

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
