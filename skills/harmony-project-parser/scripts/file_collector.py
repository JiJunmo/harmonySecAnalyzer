#!/usr/bin/env python3
"""
文件收集器 —— 递归扫描鸿蒙项目目录，按类型收集源文件和配置文件。

排除目录: node_modules, oh_modules, build, .git, .idea, .hvigor, .preview
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


EXCLUDE_DIRS = {
    "node_modules", "oh_modules", "build", ".git",
    ".idea", ".hvigor", ".preview", ".cxx",
    "__pycache__", ".svn", ".hg",
    "libs", "har", "hsp",  # 预编译库目录
}

IMPORT_PATTERNS = {
    "uses_webview": "@kit.ArkWeb",
    "uses_database": "relationalStore",
    "uses_preferences": "data.preferences",
    "uses_kvstore": "distributedKVStore",
    "uses_distributed_data": "distributedData",
    "uses_distributed_object": "distributedObject",
    "uses_crypto": "cryptoFramework",
    "uses_http": "@kit.NetworkKit",
    "uses_socket": "net.socket",
    "uses_bluetooth": "bluetooth",
    "uses_location": "geoLocationManager",
    "uses_nfc": "nfc",
}


@dataclass
class SourceFile:
    path: str
    lines: int


@dataclass
class FileCollection:
    ets_sources: list[SourceFile] = field(default_factory=list)
    ts_sources: list[SourceFile] = field(default_factory=list)
    json5_configs: list[str] = field(default_factory=list)
    json_configs: list[str] = field(default_factory=list)
    hml_files: list[str] = field(default_factory=list)
    css_files: list[str] = field(default_factory=list)
    cpp_sources: list[str] = field(default_factory=list)
    c_headers: list[str] = field(default_factory=list)
    cmake_files: list[str] = field(default_factory=list)
    certificates: list[str] = field(default_factory=list)
    key_files: list[str] = field(default_factory=list)
    pfx_files: list[str] = field(default_factory=list)
    resource_dirs: list[str] = field(default_factory=list)
    total_ets_files: int = 0
    total_ts_files: int = 0
    total_json5_files: int = 0
    total_lines: int = 0
    capabilities: dict = field(default_factory=dict)


def _should_exclude(parts: list[str]) -> bool:
    """检查路径中是否包含排除目录。"""
    return bool(EXCLUDE_DIRS & set(parts))


def _count_lines(filepath: Path) -> int:
    """快速统计文件行数。"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except (OSError, PermissionError):
        return 0


def _detect_capabilities(filepath: Path) -> dict:
    """轻量检测文件使用了哪些鸿蒙能力（基于 import 字符串搜索）。"""
    caps: dict[str, bool] = {}
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for cap_name, pattern in IMPORT_PATTERNS.items():
            if pattern in content:
                caps[cap_name] = True
    except (OSError, PermissionError):
        pass
    return caps


def _resolve_path(root: Path, filepath: Path) -> str:
    """将绝对路径转为相对于项目根目录的路径。"""
    try:
        return str(filepath.relative_to(root))
    except ValueError:
        return str(filepath)


_CERT_EXTENSIONS = {".p12", ".cer", ".crt", ".p7b", ".pem", ".der"}
_KEY_EXTENSIONS = {".jks", ".bks", ".keystore"}
_PFX_EXTENSIONS = {".pfx"}


def collect_files(root_path: str | Path) -> FileCollection:
    """
    扫描鸿蒙项目目录，收集所有相关文件。

    返回 FileCollection 结构。
    """
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"项目目录不存在: {root}")

    result = FileCollection()
    merged_caps: dict[str, bool] = {}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_parts = Path(dirpath).relative_to(root).parts
        if _should_exclude(rel_parts):
            dirnames.clear()
            continue

        # 过滤掉排除目录
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            ext = filepath.suffix.lower()
            rel_path = _resolve_path(root, filepath)

            if ext == ".ets":
                lines = _count_lines(filepath)
                result.ets_sources.append(SourceFile(path=rel_path, lines=lines))
                result.total_ets_files += 1
                result.total_lines += lines
                caps = _detect_capabilities(filepath)
                merged_caps.update(caps)

            elif ext == ".ts":
                lines = _count_lines(filepath)
                result.ts_sources.append(SourceFile(path=rel_path, lines=lines))
                result.total_ts_files += 1
                result.total_lines += lines
                caps = _detect_capabilities(filepath)
                merged_caps.update(caps)

            elif ext == ".json5":
                result.json5_configs.append(rel_path)
                result.total_json5_files += 1

            elif ext == ".json":
                result.json_configs.append(rel_path)

            elif ext == ".hml":
                result.hml_files.append(rel_path)

            elif ext == ".css":
                result.css_files.append(rel_path)

            elif ext in (".cpp", ".cxx", ".cc", ".c"):
                result.cpp_sources.append(rel_path)

            elif ext in (".h", ".hpp", ".hxx"):
                result.c_headers.append(rel_path)

            elif filename == "CMakeLists.txt":
                result.cmake_files.append(rel_path)

            elif ext in _CERT_EXTENSIONS:
                result.certificates.append(rel_path)

            elif ext in _KEY_EXTENSIONS:
                result.key_files.append(rel_path)

            elif ext in _PFX_EXTENSIONS:
                result.pfx_files.append(rel_path)

            elif "resources" in rel_parts and ext == "":
                result.resource_dirs.append(rel_path)

        # 记录 resources 目录
        if "resources" in rel_parts:
            result.resource_dirs.append(str(Path(dirpath).relative_to(root)))

    # 去重
    result.resource_dirs = sorted(set(result.resource_dirs))
    result.json5_configs = sorted(set(result.json5_configs))

    # 合并能力检测结果
    result.capabilities = dict(sorted(merged_caps.items()))

    return result


def collect_files_summary(fc: FileCollection) -> dict:
    """将 FileCollection 转为 JSON 可序列化的摘要字典。"""
    return {
        "total_ets_files": fc.total_ets_files,
        "total_ts_files": fc.total_ts_files,
        "total_json5_files": fc.total_json5_files,
        "total_hml_files": len(fc.hml_files),
        "total_css_files": len(fc.css_files),
        "total_cpp_sources": len(fc.cpp_sources),
        "total_c_headers": len(fc.c_headers),
        "total_lines": fc.total_lines,
        "ets_sources": [
            {"path": sf.path, "lines": sf.lines} for sf in fc.ets_sources
        ],
        "ts_sources": [
            {"path": sf.path, "lines": sf.lines} for sf in fc.ts_sources
        ],
        "json5_configs": fc.json5_configs,
        "json_configs": fc.json_configs,
        "hml_files": fc.hml_files,
        "css_files": fc.css_files,
        "cpp_sources": fc.cpp_sources,
        "c_headers": fc.c_headers,
        "cmake_files": fc.cmake_files,
        "certificates": fc.certificates,
        "key_files": fc.key_files,
        "pfx_files": fc.pfx_files,
        "resource_dirs": fc.resource_dirs,
        "capabilities": fc.capabilities,
    }
