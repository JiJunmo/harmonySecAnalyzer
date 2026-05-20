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


def generate_audit_plan(metadata: dict, project_path: str) -> dict:
    """
    基于完整 metadata 预计算审计调度计划。

    返回精简的 audit-plan.json 内容（< 2KB），供 AI 编排器直接使用，
    无需 AI 读取完整 metadata 做决策。
    """
    ss = metadata.get("security_surface", {})
    files = metadata.get("files", {})
    build = metadata.get("build", {})
    project = metadata.get("project", {})
    modules = metadata.get("modules", [])

    plan: dict = {
        "project": {
            "name": project.get("name", project.get("package_name", "")),
            "package_name": project.get("package_name", ""),
            "sdk_version": build.get("compile_sdk_version", ""),
            "api_level": build.get("compile_sdk_api"),
            "module_count": len(modules),
            "total_ets_files": files.get("total_ets_files", 0),
            "total_lines": files.get("total_lines", 0),
        },
        "parse_errors": metadata.get("_meta", {}).get("parse_errors", []),
        "dispatch": {},
        "summary": {
            "total_permissions": ss.get("total_permissions", 0),
            "high_risk_permissions": ss.get("total_high_risk_permissions", 0),
            "dangerous_permissions": ss.get("total_dangerous_permissions", 0),
            "exported_abilities": ss.get("exported_abilities_count", 0),
            "exported_extensions": ss.get("exported_extensions_count", 0),
            "filtered_extensions": ss.get("filtered_extensions_count", 0),
            "has_cleartext_traffic": ss.get("has_cleartext_traffic", False),
            "network_domains_count": ss.get("network_domains_count", 0),
            "has_webview": ss.get("has_webview", False),
            "has_database": ss.get("has_database", False),
            "has_distributed": ss.get("has_distributed", False),
            "has_napi": ss.get("has_napi", False),
            "uses_crypto": ss.get("uses_crypto", False),
        },
    }

    # --- IPC 审计 ---
    ipc_instances: list[dict] = []
    ipc_filtered = 0
    for mod in modules:
        for ext in mod.get("extension_abilities", []):
            if ext.get("type") != "service":
                continue
            if not ext.get("src_entry"):
                continue
            if ext.get("filtered_by_system_permission"):
                ipc_filtered += 1
                continue
            ipc_instances.append({
                "instance_id": f"ipc-{len(ipc_instances) + 1:03d}",
                "name": ext.get("name", ""),
                "module": mod.get("name", ""),
                "exported": ext.get("exported", False),
                "src_entry": ext.get("src_entry", ""),
            })

    if ipc_instances:
        plan["dispatch"]["harmony-ipc-security-audit"] = {
            "run": True,
            "reason": f"发现 {len(ipc_instances)} 个导出的 service 类型 ExtensionAbility（非系统权限守卫）",
            "instance_count": len(ipc_instances),
            "instances": ipc_instances,
        }
        if ipc_filtered > 0:
            plan["dispatch"]["harmony-ipc-security-audit"]["filtered_out"] = ipc_filtered
            plan["dispatch"]["harmony-ipc-security-audit"]["filtered_reason"] = (
                f"{ipc_filtered} 个 service 由系统未开放权限守卫，普通应用无法调用，已跳过"
            )
    else:
        reason = "未发现导出的 service 类型 ExtensionAbility"
        if ipc_filtered > 0:
            reason += f"（{ipc_filtered} 个由系统权限守卫，已跳过）"
        plan["dispatch"]["harmony-ipc-security-audit"] = {
            "run": False,
            "reason": reason,
        }

    # --- WebView 审计 ---
    has_webview = ss.get("has_webview", False)
    if has_webview:
        # 轻量扫描 WebView 使用点
        wv_instances = _scan_webview_instances(project_path, files)
        plan["dispatch"]["harmony-webview-audit"] = {
            "run": True,
            "reason": f"检测到 @kit.ArkWeb 使用，发现 {len(wv_instances)} 个 WebView 实例",
            "instance_count": len(wv_instances),
            "instances": wv_instances,
        }
    else:
        plan["dispatch"]["harmony-webview-audit"] = {
            "run": False,
            "reason": "未检测到 @kit.ArkWeb 使用",
        }

    # --- 简单 skill（根据 security_surface 判断） ---
    _add_simple_skill(plan, "harmony-permission-audit",
        ss.get("total_permissions", 0) > 0,
        f"项目申请了 {ss.get('total_permissions', 0)} 个权限（含 {ss.get('total_high_risk_permissions', 0)} 个高危）" if ss.get("total_permissions", 0) > 0 else "未申请权限")

    _add_simple_skill(plan, "harmony-component-audit",
        ss.get("exported_abilities_count", 0) > 0,
        f"发现 {ss.get('exported_abilities_count', 0)} 个导出 Ability" if ss.get("exported_abilities_count", 0) > 0 else "无导出 Ability")

    _add_simple_skill(plan, "harmony-secrets-audit",
        files.get("total_ets_files", 0) > 0,
        f"项目包含 {files.get('total_ets_files', 0)} 个 .ets 源文件" if files.get("total_ets_files", 0) > 0 else "无 .ets 源文件")

    _add_simple_skill(plan, "harmony-network-audit",
        ss.get("network_domains_count", 0) > 0 or ss.get("has_cleartext_traffic", False),
        f"发现 {ss.get('network_domains_count', 0)} 个网络域名" + ("，含 cleartext_traffic" if ss.get("has_cleartext_traffic") else "") if (ss.get("network_domains_count", 0) > 0 or ss.get("has_cleartext_traffic")) else "未发现网络配置")

    _add_simple_skill(plan, "harmony-crypto-audit",
        ss.get("uses_crypto", False),
        "源文件中检测到 cryptoFramework 使用" if ss.get("uses_crypto") else "未使用 cryptoFramework")

    _add_simple_skill(plan, "harmony-data-storage-audit",
        ss.get("has_database", False),
        "检测到数据库使用" if ss.get("has_database") else "未检测到数据库使用")

    _add_simple_skill(plan, "harmony-code-quality-audit",
        files.get("total_ets_files", 0) > 0,
        f"项目包含 {files.get('total_ets_files', 0)} 个 .ets 源文件" if files.get("total_ets_files", 0) > 0 else "无源文件")

    return plan


def _add_simple_skill(plan: dict, skill_name: str, should_run: bool, reason: str):
    """为不需要深度分析的 skill 添加 dispatch 条目。"""
    if not should_run:
        plan["dispatch"][skill_name] = {"run": False, "reason": reason}
    else:
        plan["dispatch"][skill_name] = {"run": True, "reason": reason}


def _scan_webview_instances(project_path: str, files: dict) -> list[dict]:
    """轻量扫描 WebView 使用点，返回实例列表。"""
    instances: list[dict] = []
    counter = 0
    project_root = Path(project_path).resolve()

    ets_sources = files.get("ets_sources", [])
    for sf in ets_sources:
        filepath = project_root / sf["path"]
        if not filepath.exists():
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if "@kit.ArkWeb" not in content and "web_webview" not in content:
            continue

        idx = 0
        while True:
            idx = content.find("Web({", idx)
            if idx == -1:
                break
            counter += 1
            line_no = content[:idx].count("\n") + 1

            import re
            src_match = re.search(r"src:\s*['\"]([^'\"]+)['\"]", content[idx:idx + 200])
            src_url = src_match.group(1) if src_match else "未知"

            instances.append({
                "instance_id": f"webview-{counter:03d}",
                "name": f"WebView_{sf['path'].split('/')[-1].replace('.ets', '')}_{src_url[:30]}",
                "file": sf["path"],
                "line": line_no,
                "src_url": src_url,
            })
            idx += 5

    return instances


def list_entries(project_path: str) -> list[dict]:
    """
    扫描项目中所有外部可控入口（DeepLink、Want 参数、IPC 消息、URL Scheme 等）。

    返回入口列表，每个入口包含 entry_id、type、file、line、handler、controlled_params。
    """
    import re
    project_root = Path(project_path).resolve()
    entries: list[dict] = []
    counter = 0

    # 收集所有源文件
    try:
        fc = collect_files(project_root)
    except (FileNotFoundError, PermissionError):
        return entries

    for sf in fc.ets_sources:
        filepath = project_root / sf.path
        if not filepath.exists():
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # --- DeepLink 入口: want.parameters 取值 ---
        for m in re.finditer(r"(?:want|Want)\s*\.\s*parameters\s*\??\s*\.\s*(\w+)", content):
            counter += 1
            line_no = content[:m.start()].count("\n") + 1
            param_name = m.group(1)
            ctx_start = max(0, m.start() - 100)
            ctx_end = min(len(content), m.end() + 200)
            snippet = content[ctx_start:ctx_end].strip()[:300]

            entries.append({
                "entry_id": f"entry-{counter:03d}",
                "type": "deeplink",
                "file": sf.path,
                "line": line_no,
                "handler": "want.parameters",
                "controlled_params": [param_name],
                "snippet": snippet,
            })

        # --- Want 接收器: startAbility 中传入的外部 want ---
        for m in re.finditer(r"(?:startAbility|startAbilityForResult)\s*\([^)]*want[^)]*\)", content):
            counter += 1
            line_no = content[:m.start()].count("\n") + 1
            ctx_start = max(0, m.start() - 50)
            ctx_end = min(len(content), m.end() + 100)
            snippet = content[ctx_start:ctx_end].strip()[:300]

            entries.append({
                "entry_id": f"entry-{counter:03d}",
                "type": "want_receiver",
                "file": sf.path,
                "line": line_no,
                "handler": "startAbility(want)",
                "controlled_params": ["want.parameters", "want.uri"],
                "snippet": snippet,
            })

        # --- IPC 消息入口: onRemoteMessageRequest ---
        for m in re.finditer(r"onRemoteMessageRequest\s*\([^)]*\)", content):
            counter += 1
            line_no = content[:m.start()].count("\n") + 1
            ctx_start = max(0, m.start() - 50)
            ctx_end = min(len(content), m.end() + 200)
            snippet = content[ctx_start:ctx_end].strip()[:300]

            entries.append({
                "entry_id": f"entry-{counter:03d}",
                "type": "ipc",
                "file": sf.path,
                "line": line_no,
                "handler": "onRemoteMessageRequest",
                "controlled_params": ["code", "data"],
                "snippet": snippet,
            })

        # --- URL Scheme 回调: onLoadIntercept / onUrlLoadIntercept ---
        for pattern in ["onLoadIntercept", "onUrlLoadIntercept"]:
            for m in re.finditer(rf"{pattern}\s*\(\s*(?:event|\w+)\s*(?:\)|:)", content):
                counter += 1
                line_no = content[:m.start()].count("\n") + 1
                ctx_start = max(0, m.start() - 50)
                ctx_end = min(len(content), m.end() + 200)
                snippet = content[ctx_start:ctx_end].strip()[:300]

                entries.append({
                    "entry_id": f"entry-{counter:03d}",
                    "type": "url_callback",
                    "file": sf.path,
                    "line": line_no,
                    "handler": pattern,
                    "controlled_params": ["url"],
                    "snippet": snippet,
                })

    return entries


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
    parser.add_argument("--audit-plan", action="store_true", help="输出审计调度计划（精简版，供 AI 编排器）")
    parser.add_argument("--list-entries", action="store_true", help="发现所有外部可控入口")
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

    if args.list_entries:
        output_data = {
            "_meta": {
                "scanner_version": VERSION,
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "project_path": str(Path(args.project_path).resolve()),
                "total_entries": 0,
            },
            "entries": list_entries(args.project_path),
        }
        output_data["_meta"]["total_entries"] = len(output_data["entries"])
    elif args.audit_plan:
        output_data = generate_audit_plan(metadata, args.project_path)
    else:
        output_data = metadata

    indent = 2 if args.pretty else None
    json_output = json.dumps(output_data, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_output)
        if args.verbose:
            print(f"[INFO] 输出已保存到: {output_path}", file=sys.stderr)
        label = "入口发现" if args.list_entries else ("审计计划" if args.audit_plan else "扫描")
        print(f"[DONE] {label}完成，输出: {output_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
