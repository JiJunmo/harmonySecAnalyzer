#!/usr/bin/env python3
"""
Module 分析器 —— 解析鸿蒙项目中的 module.json5 文件，提取 abilities、permissions、network 等安全审计关键信息。
"""

import json
from pathlib import Path
from typing import Any

from json5_parser import parse_json5_file, safe_parse_json5_file


# 鸿蒙系统未开放的权限（普通应用无法获取）
# 如果 Ability/ExtensionAbility 仅由这些权限守卫，普通应用无法越权调用，风险极低
SYSTEM_ONLY_PERMISSIONS: set[str] = {
    "ohos.permission.ABILITY_BACKGROUND_COMMUNICATION",
    "ohos.permission.ACCESS_AUTH_RESPOOL",
    "ohos.permission.ACCESS_BUNDLE_DIR",
    "ohos.permission.ACCESS_CAST_ENGINE_MIRROR",
    "ohos.permission.ACCESS_CAST_ENGINE_STREAM",
    "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL",
    "ohos.permission.ACCESS_DLP_FILE",
    "ohos.permission.ACCESS_IDS",
    "ohos.permission.ACCESS_MISSIONS",
    "ohos.permission.ACCESS_PIN_AUTH",
    "ohos.permission.ACCESS_PUSH_SERVICE",
    "ohos.permission.ACCESS_SCREEN_LOCK_INNER",
    "ohos.permission.ACCESS_SENSING_WITH_ULTRASOUND",
    "ohos.permission.ACCESS_SERVICE_DM",
    "ohos.permission.ACCESS_SYSTEM_SETTINGS",
    "ohos.permission.ACCESS_USER_AUTH_INTERNAL",
    "ohos.permission.ACTIVATE_THEME_PACKAGE",
    "ohos.permission.ANSWER_CALL",
    "ohos.permission.ATTEST_KEY",
    "ohos.permission.BACKUP",
    "ohos.permission.BUNDLE_ACTIVE_INFO",
    "ohos.permission.CAPTURE_SCREEN",
    "ohos.permission.CAPTURE_VOICE_DOWNLINK_AUDIO",
    "ohos.permission.CHANGE_ABILITY_ENABLED_STATE",
    "ohos.permission.CHANGE_OVERLAY_ENABLED_STATE",
    "ohos.permission.CLEAN_APPLICATION_DATA",
    "ohos.permission.CLOUDDATA_CONFIG",
    "ohos.permission.CLOUDFILE_SYNC",
    "ohos.permission.CLOUDFILE_SYNC_MANAGER",
    "ohos.permission.CONNECTIVITY_INTERNAL",
    "ohos.permission.CONNECT_CELLULAR_CALL_SERVICE",
    "ohos.permission.CONNECT_IME_ABILITY",
    "ohos.permission.CONNECT_IMS_SERVICE",
    "ohos.permission.CONNECT_SCREEN_SAVER_ABILITY",
    "ohos.permission.CONTROL_TASK_SYNC_ANIMATOR",
    "ohos.permission.DEVICE_STANDBY_EXEMPTION",
    "ohos.permission.DISTRIBUTED_SOFTBUS_CENTER",
    "ohos.permission.DOWNLOAD_SESSION_MANAGER",
    "ohos.permission.DUMP",
    "ohos.permission.ENFORCE_USER_IDM",
    "ohos.permission.ENTERPRISE_GET_DEVICE_INFO",
    "ohos.permission.ENTERPRISE_GET_NETWORK_INFO",
    "ohos.permission.ENTERPRISE_GET_SETTINGS",
    "ohos.permission.ENTERPRISE_INSTALL_BUNDLE",
    "ohos.permission.ENTERPRISE_MANAGE_CERTIFICATE",
    "ohos.permission.ENTERPRISE_MANAGE_NETWORK",
    "ohos.permission.ENTERPRISE_MANAGE_SET_APP_RUNNING_POLICY",
    "ohos.permission.ENTERPRISE_MANAGE_USB",
    "ohos.permission.ENTERPRISE_RESET_DEVICE",
    "ohos.permission.ENTERPRISE_RESTRICT_POLICY",
    "ohos.permission.ENTERPRISE_SET_ACCOUNT_POLICY",
    "ohos.permission.ENTERPRISE_SET_BROWSER_POLICY",
    "ohos.permission.ENTERPRISE_SET_BUNDLE_INSTALL_POLICY",
    "ohos.permission.ENTERPRISE_SET_DATETIME",
    "ohos.permission.ENTERPRISE_SET_NETWORK",
    "ohos.permission.ENTERPRISE_SET_SCREENOFF_TIME",
    "ohos.permission.ENTERPRISE_SET_WIFI",
    "ohos.permission.ENTERPRISE_SUBSCRIBE_MANAGED_EVENT",
    "ohos.permission.FACTORY_RESET",
    "ohos.permission.FILE_ACCESS_MANAGER",
    "ohos.permission.FILE_GUARD_MANAGER",
    "ohos.permission.GET_ALL_APP_ACCOUNTS",
    "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED",
    "ohos.permission.GET_DEFAULT_APPLICATION",
    "ohos.permission.GET_DISTRIBUTED_ACCOUNTS",
    "ohos.permission.GET_DOMAIN_ACCOUNTS",
    "ohos.permission.GET_INSTALLED_BUNDLE_LIST",
    "ohos.permission.GET_LOCAL_ACCOUNTS",
    "ohos.permission.GET_NETWORK_STATS",
    "ohos.permission.GET_PHONE_NUMBERS",
    "ohos.permission.GET_RUNNING_INFO",
    "ohos.permission.GET_SCENE_CODE",
    "ohos.permission.GET_SENSITIVE_PERMISSIONS",
    "ohos.permission.GET_TELEPHONY_STATE",
    "ohos.permission.GET_WALLPAPER",
    "ohos.permission.GET_WIFI_CONFIG",
    "ohos.permission.GET_WIFI_INFO_INTERNAL",
    "ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
    "ohos.permission.INSTALL_BUNDLE",
    "ohos.permission.INSTALL_ENTERPRISE_BUNDLE",
    "ohos.permission.INSTALL_ENTERPRISE_MDM_BUNDLE",
    "ohos.permission.INSTALL_ENTERPRISE_NORMAL_BUNDLE",
    "ohos.permission.INSTALL_SELF_BUNDLE",
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION",
    "ohos.permission.LAUNCH_DATA_PRIVACY_CENTER",
    "ohos.permission.LISTEN_BUNDLE_CHANGE",
    "ohos.permission.MANAGE_AUDIO_CONFIG",
    "ohos.permission.MANAGE_BLUETOOTH",
    "ohos.permission.MANAGE_CAMERA_CONFIG",
    "ohos.permission.MANAGE_DEVICE_AUTH_CRED",
    "ohos.permission.MANAGE_DISPOSED_APP_STATUS",
    "ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS",
    "ohos.permission.MANAGE_ECOLOGICAL_RULE",
    "ohos.permission.MANAGE_ENTERPRISE_DEVICE_ADMIN",
    "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
    "ohos.permission.MANAGE_MEDIA_RESOURCES",
    "ohos.permission.MANAGE_MISSIONS",
    "ohos.permission.MANAGE_NET_STRATEGY",
    "ohos.permission.MANAGE_PRINT_JOB",
    "ohos.permission.MANAGE_SECURE_SETTINGS",
    "ohos.permission.MANAGE_SENSOR",
    "ohos.permission.MANAGE_SHORTCUTS",
    "ohos.permission.MANAGE_USER_IDM",
    "ohos.permission.MANAGE_VOICEMAIL",
    "ohos.permission.MANAGE_VPN",
    "ohos.permission.MANAGE_WIFI_CONNECTION",
    "ohos.permission.MANAGE_WIFI_HOTSPOT",
    "ohos.permission.MOUNT_FORMAT_MANAGER",
    "ohos.permission.MOUNT_UNMOUNT_MANAGER",
    "ohos.permission.NETSYS_INTERNAL",
    "ohos.permission.NOTIFICATION_AGENT_CONTROLLER",
    "ohos.permission.NOTIFICATION_CONTROLLER",
    "ohos.permission.OBSERVE_FORM_RUNNING",
    "ohos.permission.PERMISSION_USED_STATS",
    "ohos.permission.PLACE_CALL",
    "ohos.permission.POWER_MANAGER",
    "ohos.permission.POWER_OPTIMIZATION",
    "ohos.permission.PRIVACY_WINDOW",
    "ohos.permission.PROVISIONING_MESSAGE",
    "ohos.permission.PROXY_AUTHORIZATION_URI",
    "ohos.permission.PUBLISH_SYSTEM_COMMON_EVENT",
    "ohos.permission.QUERY_ACCESSIBILITY_ELEMENT",
    "ohos.permission.READ_ACCESSIBILITY_CONFIG",
    "ohos.permission.READ_APP_PUSH_DATA",
    "ohos.permission.READ_CALL_LOG",
    "ohos.permission.READ_CELL_MESSAGES",
    "ohos.permission.READ_DFX_SYSEVENT",
    "ohos.permission.READ_DOCUMENT",
    "ohos.permission.READ_HIVIEW_SYSTEM",
    "ohos.permission.READ_MESSAGES",
    "ohos.permission.READ_SCREEN_SAVER",
    "ohos.permission.REBOOT",
    "ohos.permission.REBOOT_RECOVERY",
    "ohos.permission.RECEIVER_STARTUP_COMPLETED",
    "ohos.permission.RECEIVE_MMS",
    "ohos.permission.RECEIVE_SMS",
    "ohos.permission.RECEIVE_WAP_MESSAGES",
    "ohos.permission.RECOVER_BUNDLE",
    "ohos.permission.REFRESH_USER_ACTION",
    "ohos.permission.REMOVE_CACHE_FILES",
    "ohos.permission.REQUIRE_FORM",
    "ohos.permission.RESTRICT_APPLICATION_ACTIVE",
    "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS",
    "ohos.permission.RUNNING_STATE_OBSERVER",
    "ohos.permission.RUN_ANY_CODE",
    "ohos.permission.SEND_MESSAGES",
    "ohos.permission.SET_ABILITY_CONTROLLER",
    "ohos.permission.SET_DEFAULT_APPLICATION",
    "ohos.permission.SET_ENTERPRISE_INFO",
    "ohos.permission.SET_FILE_GUARD_POLICY",
    "ohos.permission.SET_TELEPHONY_STATE",
    "ohos.permission.SET_TIME",
    "ohos.permission.SET_TIME_ZONE",
    "ohos.permission.SET_UNREMOVABLE_NOTIFICATION",
    "ohos.permission.SET_WIFI_CONFIG",
    "ohos.permission.START_ABILITIES_FROM_BACKGROUND",
    "ohos.permission.START_INVISIBLE_ABILITY",
    "ohos.permission.STORAGE_MANAGER",
    "ohos.permission.UNINSTALL_BUNDLE",
    "ohos.permission.UPDATE_CONFIGURATION",
    "ohos.permission.UPDATE_MIGRATE",
    "ohos.permission.UPDATE_SYSTEM",
    "ohos.permission.UPLOAD_SESSION_MANAGER",
    "ohos.permission.USE_USER_IDM",
    "ohos.permission.WAKEUP_VISION",
    "ohos.permission.WAKEUP_VOICE",
    "ohos.permission.WRITE_ACCESSIBILITY_CONFIG",
    "ohos.permission.WRITE_APP_PUSH_DATA",
    "ohos.permission.WRITE_CALL_LOG",
    "ohos.permission.WRITE_DOCUMENT",
    "ohos.permission.WRITE_HIVIEW_SYSTEM",
    "ohos.permission.WRITE_SCREEN_SAVER",
    "ohos.permission.radio.ACCESS_FM_AM",
    "ohos.permission.sec.ACCESS_UDID",
    "ohos.permission.securityguard.REPORT_SECURITY_INFO",
    "ohos.permission.securityguard.REQUEST_SECURITY_EVENT_INFO",
    "ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT",
    "ohos.permission.securityguard.SET_MODEL_STATE",
}


def _is_filtered_by_system_permission(permissions: list[str]) -> bool:
    """检查权限列表是否完全由系统未开放权限组成。"""
    if not permissions:
        return False
    return all(p in SYSTEM_ONLY_PERMISSIONS for p in permissions)


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
    perms = ability.get("permissions", [])
    return {
        "name": ability.get("name", ""),
        "type": ability.get("type", "UIAbility"),
        "src_entry": ability.get("srcEntry", ""),
        "exported": ability.get("exported", False),
        "visible": ability.get("visible", []),
        "permissions": perms,
        "filtered_by_system_permission": _is_filtered_by_system_permission(perms),
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
    perms = ext.get("permissions", [])
    return {
        "name": ext.get("name", ""),
        "type": ext.get("type", ""),
        "src_entry": ext.get("srcEntry", ""),
        "exported": ext.get("exported", False),
        "permissions": perms,
        "filtered_by_system_permission": _is_filtered_by_system_permission(perms),
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
