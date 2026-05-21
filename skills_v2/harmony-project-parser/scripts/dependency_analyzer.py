#!/usr/bin/env python3
"""
依赖分析器 —— 解析鸿蒙项目的 oh-package.json5 和 build-profile.json5，提取依赖信息和 SDK 版本。
"""

import re
from pathlib import Path
from typing import Any

from json5_parser import safe_parse_json5_file


def _extract_sdk_api_level(version_str: str) -> int | None:
    """
    从版本字符串中提取 API Level。

    示例:
        "5.0.0(12)" → 12
        "12" → 12
        "5.0.0" → None
    """
    if not version_str:
        return None

    # "5.0.0(12)" 格式
    match = re.search(r"\((\d+)\)", str(version_str))
    if match:
        return int(match.group(1))

    # 纯数字格式
    if isinstance(version_str, (int, float)):
        return int(version_str)

    match = re.match(r"^(\d+)$", str(version_str).strip())
    if match:
        return int(match.group(1))

    return None


def parse_oh_package(project_root: str | Path) -> dict:
    """
    解析 oh-package.json5，提取项目信息和依赖。

    返回包含 project_name, version, dependencies 的字典。
    """
    project_root = Path(project_root)
    oh_package_path = project_root / "oh-package.json5"

    data, err = safe_parse_json5_file(oh_package_path)
    if err is not None:
        return {
            "_parse_error": err,
            "project_name": "",
            "version": "",
            "dependencies": {"production": [], "dev": []},
        }

    production_deps = []
    for name, version in data.get("dependencies", {}).items():
        production_deps.append({
            "name": name,
            "version": str(version) if version is not None else "",
        })

    dev_deps = []
    for name, version in data.get("devDependencies", {}).items():
        dev_deps.append({
            "name": name,
            "version": str(version) if version is not None else "",
        })

    overrides = {}
    for name, version in data.get("overrides", {}).items():
        overrides[name] = str(version) if version is not None else ""

    return {
        "project_name": data.get("name", ""),
        "version": str(data.get("version", "")),
        "description": data.get("description", ""),
        "main": data.get("main", ""),
        "author": data.get("author", ""),
        "license": data.get("license", ""),
        "dependencies": {
            "production": production_deps,
            "dev": dev_deps,
        },
        "overrides": overrides,
    }


def parse_build_profile(project_root: str | Path) -> dict:
    """
    解析 build-profile.json5，提取 SDK 版本和模块构建配置。

    返回包含 compile_sdk_version, compatible_sdk_version 等的字典。
    """
    project_root = Path(project_root)
    build_profile_path = project_root / "build-profile.json5"

    data, err = safe_parse_json5_file(build_profile_path)
    if err is not None:
        return {
            "_parse_error": err,
            "compile_sdk_version": "",
            "compatible_sdk_version": "",
            "target_sdk_version": "",
            "build_mode": "",
            "modules": [],
            "products": [],
        }

    app = data.get("app", {})

    products = []
    compile_sdk = ""
    compatible_sdk = ""
    target_sdk = ""

    for product in app.get("products", []):
        products.append({
            "name": product.get("name", "default"),
            "signing_config": product.get("signingConfig", ""),
            "compatible_sdk_version": str(product.get("compatibleSdkVersion", "")),
            "compile_sdk_version": str(product.get("compileSdkVersion", "")),
            "target_sdk_version": str(product.get("targetSdkVersion", "")),
            "runtime_os": product.get("runtimeOS", "HarmonyOS"),
        })

    if products:
        first = products[0]
        compile_sdk = first.get("compile_sdk_version", "")
        compatible_sdk = first.get("compatible_sdk_version", "")
        target_sdk = first.get("target_sdk_version", "")

    # 从 app 全局配置回退
    if not compile_sdk:
        compile_sdk = str(app.get("compileSdkVersion", ""))
    if not compatible_sdk:
        compatible_sdk = str(app.get("compatibleSdkVersion", ""))
    if not target_sdk:
        target_sdk = str(app.get("targetSdkVersion", ""))

    version_name = app.get("versionName", "")
    version_code = app.get("versionCode", "")
    bundle_name = app.get("bundleName", "")

    modules_build = []
    for mod in app.get("modules", data.get("modules", [])):
        modules_build.append({
            "name": mod.get("name", ""),
            "src_path": mod.get("srcPath", ""),
            "targets": mod.get("targets", []),
        })

    compile_api = _extract_sdk_api_level(compile_sdk)
    compatible_api = _extract_sdk_api_level(compatible_sdk)
    target_api = _extract_sdk_api_level(target_sdk)

    return {
        "compile_sdk_version": compile_sdk,
        "compile_sdk_api": compile_api,
        "compatible_sdk_version": compatible_sdk,
        "compatible_sdk_api": compatible_api,
        "target_sdk_version": target_sdk,
        "target_sdk_api": target_api,
        "version_name": version_name,
        "version_code": version_code,
        "bundle_name": bundle_name,
        "build_mode": app.get("buildMode", ""),
        "products": products,
        "modules_build": modules_build,
        "signing_configs": app.get("signingConfigs", []),
    }


def analyze_dependencies(project_root: str | Path) -> dict:
    """
    综合分析项目依赖和构建信息。

    返回合并后的依赖分析字典。
    """
    project_root = Path(project_root)
    oh_package = parse_oh_package(project_root)
    build_profile = parse_build_profile(project_root)

    # 收集所有第三方依赖（生产 + 开发）
    all_thirtd_party = []
    for dep in oh_package.get("dependencies", {}).get("production", []):
        if dep["name"].startswith("@ohos/") or dep["name"].startswith("@"):
            all_thirtd_party.append(dep)

    return {
        **oh_package,
        **build_profile,
        "third_party_count": len(all_thirtd_party),
        "third_party_deps": all_thirtd_party,
    }
