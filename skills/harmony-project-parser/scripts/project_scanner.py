#!/usr/bin/env python3
"""
鸿蒙项目扫描器 —— 主编排入口

用法:
    python project_scanner.py <project_path> [-o output.json] [--verbose]

功能:
    1. 递归扫描项目目录，收集源文件和配置文件
    2. 解析所有 module.json5，提取 abilities/permissions/network 等安全审计关键信息
    3. 解析 oh-package.json5 和 build-profile.json5，提取依赖和 SDK 版本
    4. 输出统一的 project-metadata.json 供下游审计 skill 使用
"""

import argparse
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# 确保能找到同目录下的子模块
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from file_collector import collect_files, collect_files_summary
from module_analyzer import analyze_all_modules
from dependency_analyzer import analyze_dependencies


VERSION = "1.0.0"

# 危险权限列表（需要更高安全关注度）
DANGEROUS_PERMISSIONS = {
    "ohos.permission.LOCATION",
    "ohos.permission.APPROXIMATELY_LOCATION",
    "ohos.permission.LOCATION_IN_BACKGROUND",
    "ohos.permission.CAMERA",
    "ohos.permission.MICROPHONE",
    "ohos.permission.READ_CONTACTS",
    "ohos.permission.WRITE_CONTACTS",
    "ohos.permission.READ_CALENDAR",
    "ohos.permission.WRITE_CALENDAR",
    "ohos.permission.ACTIVITY_MOTION",
    "ohos.permission.READ_HEALTH_DATA",
    "ohos.permission.DISTRIBUTED_DATASYNC",
    "ohos.permission.READ_PASTEBOARD",
    "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
    "ohos.permission.READ_IMAGEVIDEO",
    "ohos.permission.WRITE_IMAGEVIDEO",
    "ohos.permission.READ_AUDIO",
    "ohos.permission.WRITE_AUDIO",
    "ohos.permission.READ_DOCUMENT",
    "ohos.permission.WRITE_DOCUMENT",
    "ohos.permission.ACCESS_BLUETOOTH",
    "ohos.permission.GET_WIFI_INFO",
    "ohos.permission.INTERNET",
}

HIGH_RISK_PERMISSIONS = {
    "ohos.permission.LOCATION",
    "ohos.permission.LOCATION_IN_BACKGROUND",
    "ohos.permission.CAMERA",
    "ohos.permission.MICROPHONE",
    "ohos.permission.READ_CONTACTS",
    "ohos.permission.READ_CALENDAR",
    "ohos.permission.READ_HEALTH_DATA",
    "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
    "ohos.permission.DISTRIBUTED_DATASYNC",
}

# 省电/后台权限
BACKGROUND_PERMISSIONS = {
    "ohos.permission.LOCATION_IN_BACKGROUND",
    "ohos.permission.RUNNING_LOCK",
    "ohos.permission.KEEP_BACKGROUND_RUNNING",
}


def _compute_security_surface(modules: list[dict], dependencies: dict, files: dict) -> dict:
    """
    计算项目的安全攻击面摘要。
    聚合各模块的关键安全指标，供 Agent 编排器和后续 skill 使用。
    """
    all_permissions: list[str] = []
    all_dangerous_permissions: list[str] = []
    all_high_risk_permissions: list[str] = []
    all_background_permissions: list[str] = []
    exported_abilities: list[str] = []
    exported_extensions: list[str] = []
    has_cleartext = False
    all_network_domains: list[str] = []

    has_webview = False
    has_database = False
    has_distributed = False
    has_napi = bool(files.get("cpp_sources") or files.get("cmake_files"))
    has_ipc_service = False
    has_service_extension = False
    icp_service_count = 0
    filtered_abilities_count = 0
    filtered_extensions_count = 0

    for mod in modules:
        if mod.get("_parse_error"):
            continue

        for perm in mod.get("permissions", []):
            pname = perm.get("name", "")
            if pname:
                all_permissions.append(pname)
                if pname in DANGEROUS_PERMISSIONS:
                    all_dangerous_permissions.append(pname)
                if pname in HIGH_RISK_PERMISSIONS:
                    all_high_risk_permissions.append(pname)
                if pname in BACKGROUND_PERMISSIONS:
                    all_background_permissions.append(pname)

        for ab in mod.get("abilities", []):
            if ab.get("exported"):
                exported_abilities.append(ab.get("name", ""))
            if ab.get("filtered_by_system_permission"):
                filtered_abilities_count += 1

        for ext in mod.get("extension_abilities", []):
            if ext.get("exported"):
                exported_extensions.append(ext.get("name", ""))
            ext_type = ext.get("type", "").lower()
            ext_filtered = ext.get("filtered_by_system_permission", False)
            if ext_type == "service":
                if not ext_filtered:
                    has_ipc_service = True
                    icp_service_count += 1
                else:
                    filtered_extensions_count += 1
                has_service_extension = True
            elif ext_type:
                has_service_extension = True
                if ext_filtered:
                    filtered_extensions_count += 1

        nc = mod.get("network_config", {})
        if nc.get("cleartext_traffic"):
            has_cleartext = True
        for domain in nc.get("domains", []):
            if isinstance(domain, dict) and domain.get("name"):
                all_network_domains.append(domain["name"])

        features = mod.get("_features", {})
        if features.get("has_webview"):
            has_webview = True
        if features.get("has_database"):
            has_database = True
        if features.get("has_distributed"):
            has_distributed = True

    capabilities = files.get("capabilities", {})
    if not has_webview and capabilities.get("uses_webview"):
        has_webview = True
    if not has_database and (capabilities.get("uses_database") or capabilities.get("uses_preferences") or capabilities.get("uses_kvstore")):
        has_database = True
    if not has_distributed and (capabilities.get("uses_distributed_data") or capabilities.get("uses_distributed_object")):
        has_distributed = True
    if not has_ipc_service and (capabilities.get("uses_ipc") or capabilities.get("uses_ipc_kit") or capabilities.get("uses_ipc_stub") or capabilities.get("uses_service_extension")):
        has_ipc_service = True
        has_service_extension = True

    return {
        "total_permissions": len(set(all_permissions)),
        "total_dangerous_permissions": len(set(all_dangerous_permissions)),
        "total_high_risk_permissions": len(set(all_high_risk_permissions)),
        "total_background_permissions": len(set(all_background_permissions)),
        "exported_abilities": sorted(set(exported_abilities)),
        "exported_extensions": sorted(set(exported_extensions)),
        "exported_abilities_count": len(set(exported_abilities)),
        "exported_extensions_count": len(set(exported_extensions)),
        "has_cleartext_traffic": has_cleartext,
        "network_domains": sorted(set(all_network_domains)),
        "network_domains_count": len(set(all_network_domains)),
        "has_webview": has_webview,
        "has_database": has_database,
        "has_distributed": has_distributed,
        "has_napi": has_napi,
        "has_ipc_service": has_ipc_service,
        "has_service_extension": has_service_extension,
        "ipc_service_count": icp_service_count,
        "filtered_abilities_count": filtered_abilities_count,
        "filtered_extensions_count": filtered_extensions_count,
        "uses_crypto": capabilities.get("uses_crypto", False),
        "uses_http": capabilities.get("uses_http", False),
        "uses_bluetooth": capabilities.get("uses_bluetooth", False),
        "uses_location": capabilities.get("uses_location", False),
        "uses_nfc": capabilities.get("uses_nfc", False),
        "capabilities": capabilities,
    }


def scan_project(project_path: str) -> dict:
    """
    扫描鸿蒙项目并返回完整的项目元数据。

    这是项目的顶层入口函数，也是其他脚本和 skill 调用的主要接口。

    参数:
        project_path: 鸿蒙项目根目录路径

    返回:
        完整的 project-metadata 字典
    """
    project_root = Path(project_path).resolve()

    parse_errors: list[str] = []
    parse_warnings: list[str] = []

    # 1. 文件收集
    try:
        file_collection = collect_files(project_root)
        files_summary = collect_files_summary(file_collection)
    except (FileNotFoundError, PermissionError) as e:
        parse_errors.append(f"文件收集失败: {e}")
        files_summary = {
            "total_ets_files": 0,
            "total_ts_files": 0,
            "total_json5_files": 0,
            "total_lines": 0,
            "ets_sources": [],
            "ts_sources": [],
            "json5_configs": [],
            "capabilities": {},
        }

    # 2. Module 分析
    modules = analyze_all_modules(project_root)
    for mod in modules:
        if mod.get("_parse_error"):
            parse_errors.append(f"模块 {mod.get('name', mod.get('_path', 'unknown'))} 解析失败: {mod['_parse_error']}")

    # 3. 依赖分析
    dependencies = analyze_dependencies(project_root)
    if dependencies.get("_parse_error"):
        parse_errors.append(f"依赖分析失败: {dependencies['_parse_error']}")

    # 4. 安全攻击面计算
    security_surface = _compute_security_surface(modules, dependencies, files_summary)

    # 5. 组装最终输出
    return {
        "_meta": {
            "scanner_version": VERSION,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "project_path": str(project_root),
            "parse_errors": parse_errors,
            "parse_warnings": parse_warnings,
        },
        "project": {
            "name": dependencies.get("project_name", project_root.name),
            "version": dependencies.get("version", ""),
            "package_name": dependencies.get("bundle_name", ""),
            "description": dependencies.get("description", ""),
        },
        "build": {
            "compile_sdk_version": dependencies.get("compile_sdk_version", ""),
            "compile_sdk_api": dependencies.get("compile_sdk_api"),
            "compatible_sdk_version": dependencies.get("compatible_sdk_version", ""),
            "compatible_sdk_api": dependencies.get("compatible_sdk_api"),
            "target_sdk_version": dependencies.get("target_sdk_version", ""),
            "target_sdk_api": dependencies.get("target_sdk_api"),
            "version_name": dependencies.get("version_name", ""),
            "version_code": dependencies.get("version_code", ""),
            "build_mode": dependencies.get("build_mode", ""),
            "products": dependencies.get("products", []),
        },
        "modules": [
            {k: v for k, v in mod.items() if not k.startswith("_")}
            for mod in modules
        ],
        "dependencies": {
            "production": dependencies.get("dependencies", {}).get("production", []),
            "dev": dependencies.get("dependencies", {}).get("dev", []),
            "overrides": dependencies.get("overrides", {}),
            "third_party_count": dependencies.get("third_party_count", 0),
            "third_party_deps": dependencies.get("third_party_deps", []),
        },
        "files": files_summary,
        "security_surface": security_surface,
    }


def main():
    parser = argparse.ArgumentParser(
        description="鸿蒙应用项目扫描器 —— 解析项目结构并输出安全审计元数据",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python project_scanner.py ./MyHarmonyApp
    python project_scanner.py ./MyHarmonyApp -o metadata.json
    python project_scanner.py ./MyHarmonyApp --verbose
        """,
    )
    parser.add_argument("project_path", help="鸿蒙项目根目录路径")
    parser.add_argument("-o", "--output", default=None, help="输出 JSON 文件路径（默认输出到 stdout）")
    parser.add_argument("--verbose", action="store_true", help="输出详细日志")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON 输出")

    args = parser.parse_args()

    if args.verbose:
        print(f"[INFO] 扫描项目: {args.project_path}", file=sys.stderr)

    try:
        metadata = scan_project(args.project_path)
    except Exception as e:
        print(f"[ERROR] 扫描失败: {e}", file=sys.stderr)
        sys.exit(1)

    indent = 2 if args.pretty else None
    json_output = json.dumps(metadata, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_output)
        if args.verbose:
            print(f"[INFO] 输出已保存到: {output_path}", file=sys.stderr)
        print(f"[DONE] 扫描完成，输出: {output_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
