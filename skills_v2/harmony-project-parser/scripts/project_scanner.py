#!/usr/bin/env python3
"""
HarmonyOS 项目攻击面发现器 v2 —— Phase 1: Discover

用法:
    python project_scanner.py <project_path> <output_dir>

功能:
    1. 发现所有外部入口（entries.json）
    2. 发现所有攻击终点（sinks.json）
    3. 预判入口到终点的可连性（attack_map.json）

说明:
    v2 不再输出完整的 metadata.json。entry、sink、attack_map 是正交的三份数据，
    分别用于理解"攻击者从哪进来"、"能打到哪"、"哪条路可能走得通"。
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from file_collector import collect_files, collect_files_summary
from module_analyzer import analyze_all_modules, SYSTEM_ONLY_PERMISSIONS
from dependency_analyzer import analyze_dependencies

VERSION = "2.0.0"


# ============================================================
#  Entry Discovery
# ============================================================

def discover_entries(project_root: str, modules: list[dict], files: dict) -> list[dict]:
    """发现所有外部可控入口。"""
    root = Path(project_root).resolve()
    entries = []
    counter = 0

    for sf in files.get("ets_sources", []):
        filepath = root / sf["path"]
        if not filepath.exists():
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # DeepLink / Want 参数入口
        file_deeplinks = {}  # dict[str, list[dict]]
        for m in re.finditer(r"(?:want|Want)\s*(?:\??\.|\[\s*['\"])\s*parameters\s*(?:\??\.|\[\s*['\"])(\w+)", content):
            param_name = m.group(1)
            line = content[:m.start()].count("\n") + 1
            start = max(0, m.start() - 150)
            end = min(len(content), m.end() + 250)
            snippet = content[start:end].strip()[:400]

            if param_name not in file_deeplinks:
                file_deeplinks[param_name] = []
            file_deeplinks[param_name].append({
                "line": line,
                "snippet": snippet
            })

        for param_name, matches in file_deeplinks.items():
            # Check if this file is a verified deep link entry point in module.json5
            verified_deeplink = False
            deeplink_configs = []

            # Normalize current ets file path to absolute path relative to project root
            current_file_path = (root / sf["path"]).resolve().as_posix()

            for mod in modules:
                mod_json_path = mod.get("module_path", "")
                if not mod_json_path:
                    continue
                # module_path is e.g. "entry/src/main/module.json5" -> parent is "entry/src/main" -> parent is "entry"
                mod_base = Path(mod_json_path).parent.parent.parent

                for ab in mod.get("abilities", []):
                    src_entry = ab.get("src_entry", "")
                    if not src_entry:
                        continue

                    # Ability's source entry is relative to "<module_base>/src/main/"
                    ab_file_path = (mod_base / "src" / "main" / src_entry.lstrip("./")).as_posix()

                    if Path(ab_file_path).resolve() == Path(current_file_path).resolve():
                        if ab.get("exported") is True:
                            skills = ab.get("skills", [])
                            uris = []
                            for skill in skills:
                                if "uris" in skill:
                                    uris.extend(skill["uris"])
                            if uris:
                                verified_deeplink = True
                                for u in uris:
                                    deeplink_configs.append({
                                        "scheme": u.get("scheme", ""),
                                        "host": u.get("host", ""),
                                        "port": u.get("port", ""),
                                        "path": u.get("path", "") or u.get("pathStartWith", "") or u.get("pathRegex", "")
                                    })
                        break
                if verified_deeplink:
                    break

            counter += 1
            lines = sorted(list(set(m["line"] for m in matches)))
            snippets_summary = "\n---\n".join(f"[Line {m['line']}]: {m['snippet']}" for m in matches[:3])

            entry_data = {
                "id": f"entry-{counter:03d}",
                "type": "deeplink",
                "file": sf["path"],
                "line": lines[0],
                "lines": lines,
                "handler": "want.parameters",
                "controlled_params": [param_name],
                "snippet": snippets_summary,
            }
            if verified_deeplink:
                entry_data["verified_deeplink"] = True
                entry_data["deeplink_configs"] = deeplink_configs

            entries.append(entry_data)

        # IPC 消息入口
        for m in re.finditer(r"onRemoteMessageRequest\s*\(", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            start = max(0, m.start() - 100)
            end = min(len(content), m.end() + 300)
            entries.append({
                "id": f"entry-{counter:03d}",
                "type": "ipc",
                "file": sf["path"],
                "line": line,
                "handler": "onRemoteMessageRequest",
                "controlled_params": ["code", "data", "reply"],
                "snippet": content[start:end].strip()[:400],
            })

        # URL 加载拦截回调（外部 URL 可能注入）
        for pattern in ["onLoadIntercept", "onUrlLoadIntercept", "onInterceptRequest"]:
            for m in re.finditer(rf"{pattern}\s*\(", content):
                counter += 1
                line = content[:m.start()].count("\n") + 1
                start = max(0, m.start() - 100)
                end = min(len(content), m.end() + 300)
                entries.append({
                    "id": f"entry-{counter:03d}",
                    "type": "url_callback",
                    "file": sf["path"],
                    "line": line,
                    "handler": pattern,
                    "controlled_params": ["url"],
                    "snippet": content[start:end].strip()[:400],
                })

    # IPC ExtensionAbility 作为入口（从 modules 中提取）
    for mod in modules:
        for ext in mod.get("extension_abilities", []):
            if ext.get("type") != "service":
                continue
            if not ext.get("src_entry"):
                continue
            if ext.get("filtered_by_system_permission"):
                continue
            counter += 1
            entries.append({
                "id": f"entry-{counter:03d}",
                "type": "ipc_service",
                "file": mod.get("module_path", f"{mod.get('name', '')}/module.json5"),
                "line": 0,
                "handler": f"ExtensionAbility({ext.get('name', '')})",
                "controlled_params": ["code", "data"],
                "exported": ext.get("exported", False),
                "src_entry": ext.get("src_entry", ""),
                "snippet": json.dumps(ext, ensure_ascii=False)[:400],
            })

    # exported UIAbility 作为入口（从 modules 中提取）
    for mod in modules:
        mod_json_path = mod.get("module_path", "")
        if not mod_json_path:
            continue
        mod_base = Path(mod_json_path).parent.parent.parent

        for ab in mod.get("abilities", []):
            if ab.get("exported") is not True:
                continue
            if ab.get("filtered_by_system_permission") is True:
                continue
            src_entry = ab.get("src_entry", "")
            if not src_entry:
                continue

            ab_file_path = (mod_base / "src" / "main" / src_entry.lstrip("./")).as_posix()
            try:
                rel_ab_path = Path(ab_file_path).resolve().relative_to(root).as_posix()
            except ValueError:
                rel_ab_path = ab_file_path

            counter += 1
            entries.append({
                "id": f"entry-{counter:03d}",
                "type": "exported_ability",
                "file": rel_ab_path,
                "line": 0,
                "handler": f"UIAbility({ab.get('name', '')})",
                "controlled_params": ["want"],
                "exported": True,
                "src_entry": src_entry,
                "snippet": json.dumps({
                    "name": ab.get("name"),
                    "exported": ab.get("exported"),
                    "permissions": ab.get("permissions"),
                    "skills": ab.get("skills")
                }, ensure_ascii=False)[:400],
            })

    return entries


# ============================================================
#  Sink Discovery
# ============================================================

def discover_sinks(project_root: str, modules: list[dict], files: dict) -> list[dict]:
    """发现所有攻击终点。"""
    root = Path(project_root).resolve()
    sinks = []
    counter = 0

    for sf in files.get("ets_sources", []):
        filepath = root / sf["path"]
        if not filepath.exists():
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Sink: IPC 回包泄露（reply.writeString / reply.writeParcelable）
        for m in re.finditer(r"(?:reply|result\.reply)\s*\.\s*(?:writeString|writeParcelable|writeArrayBuffer)", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "data_exfil",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
                "note": "IPC 回包写入，可能泄露服务端数据",
            })

        # Sink: 全局状态写入（外部数据流入全局变量/单例）
        for m in re.finditer(r"(?:dataStatus|globalState|globalData|dataStore)\s*\.\s*(?:updata|update|set|write|put)", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "state_mutation",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
                "note": "攻击者数据写入全局状态",
            })

        # Sink: WebView 加载点（正则匹配，兼容换行和空格）
        for wm in re.finditer(r'Web\s*\(\s*\{', content):
            counter += 1
            idx = wm.start()
            line = content[:idx].count("\n") + 1
            # 提取 Web 组件后续 2000 字符用于属性分析
            web_block = content[idx:idx + 2000]

            # 提取 src（支持字符串字面量、$rawfile、变量引用）
            src_m = re.search(r"src:\s*(?:(\$rawfile\s*\([^)]*\))|['\"]([^'\"]+)['\"]|([\w.]+(?:\?\.\w+)*))", web_block)
            if src_m:
                src_url = src_m.group(1) or src_m.group(2) or f"var:{src_m.group(3)}"
            else:
                src_url = "未识别"

            # 提取关键 Web 属性配置
            web_settings = {}
            for attr in ["javaScriptAccess", "fileAccess", "domStorageAccess",
                         "mixedMode", "onlineImageAccess", "imageAccess",
                         "geolocationAccess", "databaseAccess"]:
                attr_m = re.search(rf"\.{attr}\s*\(\s*(true|false|WebMixedMode\.\w+)", web_block)
                if attr_m:
                    val = attr_m.group(1)
                    web_settings[attr] = val == "true" if val in ("true", "false") else val

            # 在整个文件中搜索 JS Bridge 和 WebMessagePort（不限定距离）
            has_jsbridge = "registerJavaScriptProxy" in content
            has_message_port = "createWebMessagePorts" in content

            is_local_resource = src_url.startswith("$rawfile")
            is_dynamic = src_url.startswith("var:") or src_url == "未识别"

            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "webview",
                "file": sf["path"],
                "line": line,
                "target": f"WebView(src={src_url})",
                "features": {
                    "js_bridge": has_jsbridge,
                    "message_port": has_message_port,
                    "external_url": not is_local_resource,
                    "local_resource": is_local_resource,
                    "dynamic_src": is_dynamic,
                    "web_settings": web_settings,
                },
                "snippet": content[idx:idx + 500].strip()[:400],
            })

        # Sink: 文件写入
        for m in re.finditer(r"(?:fileIo|fs)\s*\.\s*(?:openSync|writeSync|write|writeText)", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "file_write",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
            })

        # Sink: 数据库操作
        for m in re.finditer(r"(?:executeSql|querySql|rdbStore|relationalStore)", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "database",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
            })

        # Sink: 网络请求
        for m in re.finditer(r"(?:http\.request|createHttp|fetch)\s*\(", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "network",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
            })

        # Sink: Ability 启动 (重定向风险)
        for m in re.finditer(r"(?:context\s*\.)?\s*startAbility(?:ForResult)?\s*\(", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "start_ability",
                "file": sf["path"],
                "line": line,
                "target": m.group(0).strip(),
            })

        # Sink: Result 回传 (敏感信息泄露)
        for m in re.finditer(r"(?:context\s*\.)?\s*terminateSelfWithResult\s*\(", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "terminate_result",
                "file": sf["path"],
                "line": line,
                "target": m.group(0).strip(),
            })

    return sinks


# ============================================================
#  Attack Map (预判入口→sink 可连性)
# ============================================================

def build_attack_map(entries: list[dict], sinks: list[dict]) -> list[dict]:
    """将入口和 sink 配对，根据同文件/同模块/跨模块做可连性预判，并按 (entry_id, sink_file) 进行归并去重。"""
    grouped_paths = {}  # dict[tuple[str, str], list[dict]]

    # 需要跨模块配对的 entry_type → sink_type 组合
    # 这些组合即使不在同一文件/目录下，也应生成攻击路径让 AI 验证
    CROSS_MODULE_PAIRS = {
        ("deeplink", "webview"),
        ("deeplink", "file_write"),
        ("deeplink", "database"),
        ("deeplink", "network"),
        ("deeplink", "state_mutation"),
        ("deeplink", "data_exfil"),
        ("url_callback", "webview"),
        ("ipc", "data_exfil"),
        ("ipc", "file_write"),
        ("ipc_service", "data_exfil"),
        ("ipc_service", "file_write"),
        ("exported_ability", "start_ability"),
        ("exported_ability", "terminate_result"),
        ("exported_ability", "webview"),
        ("exported_ability", "file_write"),
        ("exported_ability", "database"),
        ("exported_ability", "network"),
    }

    for entry in entries:
        for sink in sinks:
            is_valid_pair = False
            conf = "same_module"
            note = ""

            if entry["file"] == sink["file"]:
                is_valid_pair = True
                is_high_verified = entry.get("verified_deeplink") is True and sink.get("type") == "webview"
                is_high_ability = entry.get("type") == "exported_ability" and sink.get("type") in ("start_ability", "terminate_result", "webview")
                conf = "high_verified_deeplink" if is_high_verified else ("high_verified_ability" if is_high_ability else "same_file")
                note = f"入口通过同文件直接流向终点，极高置信度"

            elif os.path.dirname(entry["file"]) == os.path.dirname(sink["file"]):
                is_valid_pair = True
                is_high_verified = entry.get("verified_deeplink") is True and sink.get("type") == "webview"
                is_high_ability = entry.get("type") == "exported_ability" and sink.get("type") in ("start_ability", "terminate_result", "webview")
                conf = "high_verified_deeplink" if is_high_verified else ("high_verified_ability" if is_high_ability else "same_dir")
                note = f"入口与终点在同目录，可能通过函数直接到达，高置信度"

            elif (entry["type"], sink["type"]) in CROSS_MODULE_PAIRS:
                is_valid_pair = True
                entry_parts = entry["file"].split("/")
                sink_parts = sink["file"].split("/")
                entry_module = entry_parts[0] if len(entry_parts) > 1 else ""
                sink_module = sink_parts[0] if len(sink_parts) > 1 else ""

                is_high_verified = entry.get("verified_deeplink") is True and sink.get("type") == "webview"
                is_high_ability = entry.get("type") == "exported_ability" and sink.get("type") in ("start_ability", "terminate_result", "webview")

                if is_high_verified:
                    conf = "high_verified_deeplink"
                elif is_high_ability:
                    conf = "high_verified_ability"
                else:
                    conf = "same_module" if entry_module == sink_module else "cross_module"
                note = f"外部入口可能通过路由/状态管理到达跨文件终点，需 AI 验证可达性"

            if is_valid_pair:
                key = (entry["id"], sink["file"])
                if key not in grouped_paths:
                    grouped_paths[key] = []
                grouped_paths[key].append({
                    "sink_id": sink["id"],
                    "sink_type": sink["type"],
                    "confidence": conf,
                    "target": sink.get("target", sink["type"]),
                    "entry": entry
                })

    # 合并并生成最终的 attack_map
    paths = []
    counter = 0

    # 评级优先级权重表 (用于选举合并路径后的最终置信度)
    CONFIDENCE_WEIGHTS = {
        "high_verified_deeplink": 6,
        "high_verified_ability": 5,
        "same_file": 4,
        "same_dir": 3,
        "same_module": 2,
        "cross_module": 1
    }

    # 排序使输出更加确定有序
    for key in sorted(grouped_paths.keys()):
        entry_id, sink_file = key
        sub_pairs = grouped_paths[key]

        counter += 1
        entry = sub_pairs[0]["entry"]

        # 归并 Sinks
        sink_ids = sorted(list(set(sp["sink_id"] for sp in sub_pairs)))
        sink_types = sorted(list(set(sp["sink_type"] for sp in sub_pairs)))

        # 选举最高的置信度
        highest_conf = "cross_module"
        highest_weight = 0
        for sp in sub_pairs:
            w = CONFIDENCE_WEIGHTS.get(sp["confidence"], 0)
            if w > highest_weight:
                highest_weight = w
                highest_conf = sp["confidence"]

        # 组合生成说明 Note
        targets_str = ", ".join(sorted(list(set(sp["target"] for sp in sub_pairs))))
        if entry["file"] == sink_file:
            note = f"真实入口 {entry['handler']} ➜ 同文件所有高危终点 [{targets_str}]，置信度: {highest_conf}"
        else:
            note = f"真实入口 {entry['handler']} ➜ 跨文件终点 [{targets_str}]，置信度: {highest_conf}"

        paths.append({
            "id": f"path-{counter:03d}",
            "entry_id": entry_id,
            "sink_ids": sink_ids,
            "sink_types": sink_types,
            "entry_type": entry["type"],
            "file": entry["file"] if entry["file"] == sink_file else f"{entry['file']} ↔ {sink_file}",
            "confidence": highest_conf,
            "note": note
        })

    return paths


# ============================================================
#  Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="HarmonyOS 攻击面发现器 v2")
    parser.add_argument("project_path", help="鸿蒙项目根目录路径")
    parser.add_argument("-o", "--output-dir", required=True, help="输出目录路径")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON")
    args = parser.parse_args()

    project_root = Path(args.project_path).resolve()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    indent = 2 if args.pretty else None

    # 扫描项目
    file_collection = collect_files(project_root)
    files = collect_files_summary(file_collection)
    modules = analyze_all_modules(project_root)

    # 入口
    entries = discover_entries(str(project_root), modules, files)
    entries_json = {
        "_meta": {"version": VERSION, "time": datetime.now(timezone.utc).isoformat(), "count": len(entries)},
        "entries": entries,
    }
    (out_dir / "entries.json").write_text(json.dumps(entries_json, ensure_ascii=False, indent=indent), encoding="utf-8")

    # Sink
    sinks = discover_sinks(str(project_root), modules, files)
    sinks_json = {
        "_meta": {"version": VERSION, "time": datetime.now(timezone.utc).isoformat(), "count": len(sinks)},
        "sinks": sinks,
    }
    (out_dir / "sinks.json").write_text(json.dumps(sinks_json, ensure_ascii=False, indent=indent), encoding="utf-8")

    # Attack Map
    attack_map = build_attack_map(entries, sinks)
    map_json = {
        "_meta": {"version": VERSION, "time": datetime.now(timezone.utc).isoformat(), "count": len(attack_map)},
        "attack_map": attack_map,
    }
    (out_dir / "attack_map.json").write_text(json.dumps(map_json, ensure_ascii=False, indent=indent), encoding="utf-8")

    print(f"[DONE] v2 攻击面发现完成: {len(entries)} 入口, {len(sinks)} 终点, {len(attack_map)} 潜在路径 → {out_dir}")


if __name__ == "__main__":
    main()
