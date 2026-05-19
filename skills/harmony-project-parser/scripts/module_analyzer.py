#!/usr/bin/env python3
"""
Module 分析器 —— 解析鸿蒙项目中的 module.json5 文件，提取 abilities、permissions、network 等安全审计关键信息。
"""

import json
from pathlib import Path
from typing import Any

from json5_parser import parse_json5_file, safe_parse_json5_file


def _resolve_string_ref(ref: str, resource_dir: str | None) -> str:
    """
    解析 $string:xxx 引用，从 element/string.json 获取实际值。

    示例:
        "$string:app_name" → "我的应用"
        "not_a_ref" → "not_a_ref"
    """
    if not ref or not ref.startswith("$string:"):
        return ref

    key = ref[len("$string:"):]
    if not resource_dir:
        return ref

    string_json_path = Path(resource_dir) / "element" / "string.json"
    if not string_json_path.exists():
        return ref

    try:
        with open(string_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        strings = data.get("string", [])
        for item in strings:
            if isinstance(item, dict) and item.get("name") == key:
                return item.get("value", ref)
    except (json.JSONDecodeError, OSError):
        pass

    return ref


def _resolve_profile_ref(ref: str, module_dir: str | None) -> list | dict | None:
    """
    解析 $profile:xxx 引用，读取对应的 profile JSON 文件。

    示例:
        "$profile:main_pages" → 读取 resources/base/profile/main_pages.json
    """
    if not ref or not ref.startswith("$profile:"):
        return None

    filename = ref[len("$profile:"):]
    if not module_dir:
        return None

    # 尝试多个可能的路径
    possible_paths = [
        Path(module_dir) / "src" / "main" / "resources" / "base" / "profile" / f"{filename}.json",
        Path(module_dir) / "src" / "main" / "resources" / "base" / "profile" / f"{filename}.json5",
    ]

    for path in possible_paths:
        if not path.exists():
            continue
        if path.suffix == ".json5":
            result, err = safe_parse_json5_file(path)
            return result if err is None else None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    return None


def _parse_ability(ability: dict, module_dir: str | None) -> dict:
    """标准化单个 ability 信息。"""
    return {
        "name": ability.get("name", ""),
        "type": ability.get("type", "UIAbility"),
        "src_entry": ability.get("srcEntry", ""),
        "exported": ability.get("exported", False),
        "visible": ability.get("visible", []),
        "permissions": ability.get("permissions", []),
        "launch_type": ability.get("launchType", "singleton"),
        "description": ability.get("description", ""),
        "icon": ability.get("icon", ""),
        "label": ability.get("label", ""),
        "skills": ability.get("skills", []),
        "background_modes": ability.get("backgroundModes", []),
        "start_window_icon": ability.get("startWindowIcon", ""),
        "start_window_background": ability.get("startWindowBackground", ""),
        "remove_mission_after_terminate": ability.get("removeMissionAfterTerminate"),
        "orientation": ability.get("orientation"),
        "support_window_mode": ability.get("supportWindowMode", []),
        "max_window_ratio": ability.get("maxWindowRatio"),
        "min_window_ratio": ability.get("minWindowRatio"),
        "max_window_width": ability.get("maxWindowWidth"),
        "min_window_width": ability.get("minWindowWidth"),
        "max_window_height": ability.get("maxWindowHeight"),
        "min_window_height": ability.get("minWindowHeight"),
    }


def _parse_extension_ability(ext: dict) -> dict:
    """标准化单个 extensionAbility 信息。"""
    return {
        "name": ext.get("name", ""),
        "type": ext.get("type", ""),
        "src_entry": ext.get("srcEntry", ""),
        "exported": ext.get("exported", False),
        "permissions": ext.get("permissions", []),
        "description": ext.get("description", ""),
        "metadata": ext.get("metadata", []),
    }


def _parse_permission(perm: dict, module_dir: str | None, resource_dir: str | None) -> dict:
    """标准化单个权限信息。"""
    return {
        "name": perm.get("name", ""),
        "reason": _resolve_string_ref(perm.get("reason", ""), resource_dir),
        "used_scene": perm.get("usedScene", {}),
    }


def _parse_network_config(network: dict) -> dict:
    """标准化网络配置信息。"""
    return {
        "cleartext_traffic": network.get("cleartextTraffic", False),
        "domains": network.get("domains", []),
        "security_config": network.get("securityConfig", {}),
    }


def parse_module_config(module_json5_path: str | Path) -> dict:
    """
    解析单个 module.json5 文件，提取完整的安全审计相关配置。

    返回标准化字典，解析失败时返回含 _parse_error 字段的字典。
    """
    module_path = Path(module_json5_path)
    # module.json5 位于 <module_root>/src/main/module.json5
    # 所以 module 根目录是 module_path.parent.parent.parent
    module_dir = str(module_path.parent.parent.parent) if "module.json5" in module_path.name else str(module_path.parent)
    resource_dir = str(Path(module_dir) / "src" / "main" / "resources" / "base") if module_dir else None

    data, err = safe_parse_json5_file(module_path)
    if err is not None:
        return {
            "_parse_error": err,
            "_path": str(module_path),
            "name": "",
            "type": "",
        }

    module = data.get("module", data)

    abilities = [_parse_ability(a, module_dir) for a in module.get("abilities", [])]
    extension_abilities = [
        _parse_extension_ability(e) for e in module.get("extensionAbilities", [])
    ]
    permissions = [
        _parse_permission(p, module_dir, resource_dir)
        for p in module.get("requestPermissions", [])
    ]
    network_config = _parse_network_config(module.get("network", {}))

    pages_raw = module.get("pages")
    pages = []
    if isinstance(pages_raw, list):
        pages = pages_raw
    elif isinstance(pages_raw, str) and pages_raw.startswith("$profile:"):
        profile_data = _resolve_profile_ref(pages_raw, module_dir)
        if isinstance(profile_data, list):
            pages = profile_data
        elif isinstance(profile_data, dict):
            pages = profile_data.get("src", list(profile_data.values()))

    router_map = []
    router_map_raw = module.get("routerMap")
    if isinstance(router_map_raw, str) and router_map_raw.startswith("$profile:"):
        profile_data = _resolve_profile_ref(router_map_raw, module_dir)
        if isinstance(profile_data, list):
            router_map = profile_data
    elif isinstance(router_map_raw, list):
        router_map = router_map_raw

    has_webview = "@kit.ArkWeb" in str(data)
    has_database = "relationalStore" in str(data) or "keyValueStore" in str(data) or "@kit.ArkData" in str(data)
    has_distributed = "distributed" in str(data).lower()

    return {
        "_path": str(module_path),
        "module_path": str(module_path),
        "name": module.get("name", ""),
        "type": module.get("type", "entry"),
        "description": module.get("description", ""),
        "main_element": module.get("mainElement", ""),
        "src_entry": module.get("srcEntry", ""),
        "device_types": module.get("deviceTypes", []),
        "delivery_with_install": module.get("deliveryWithInstall"),
        "installation_free": module.get("installationFree", False),
        "isolation_mode": module.get("isolationMode"),
        "abilities": abilities,
        "extension_abilities": extension_abilities,
        "permissions": permissions,
        "pages": pages,
        "router_map": router_map,
        "network_config": network_config,
        "metadata": module.get("metadata", []),
        "app_startup": module.get("appStartup"),
        "query_schemes": module.get("querySchemes", []),
        "_features": {
            "has_webview": has_webview,
            "has_database": has_database,
            "has_distributed": has_distributed,
        },
    }


def analyze_all_modules(project_path: str | Path) -> list[dict]:
    """
    查找并解析项目中的所有 module.json5 文件。

    返回 module 信息列表。
    """
    project_path = Path(project_path)
    modules = []

    for module_path in project_path.glob("**/module.json5"):
        rel = str(module_path.relative_to(project_path))
        if any(excl in rel for excl in {"node_modules", "oh_modules", "build", ".hvigor", ".preview"}):
            continue
        module_info = parse_module_config(module_path)
        modules.append(module_info)

    return modules
