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
        for m in re.finditer(r"(?:want|Want)\s*(?:\.|\[\s*['\"])\s*parameters\s*(?:\.|\[\s*['\"])(\w+)", content):
            counter += 1
            line = content[:m.start()].count("\n") + 1
            start = max(0, m.start() - 150)
            end = min(len(content), m.end() + 250)
            entries.append({
                "id": f"entry-{counter:03d}",
                "type": "deeplink",
                "file": sf["path"],
                "line": line,
                "handler": "want.parameters",
                "controlled_params": [m.group(1)],
                "snippet": content[start:end].strip()[:400],
            })

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

        # Sink: WebView 加载点
        idx = 0
        while True:
            idx = content.find("Web({", idx)
            if idx == -1:
                break
            counter += 1
            line = content[:idx].count("\n") + 1
            src_m = re.search(r"src:\s*['\"]([^'\"]+)['\"]", content[idx:idx + 300])
            src_url = src_m.group(1) if src_m else "动态/变量"
            has_jsbridge = "registerJavaScriptProxy" in content[idx:idx + 1000]
            sinks.append({
                "id": f"sink-{counter:03d}",
                "type": "webview",
                "file": sf["path"],
                "line": line,
                "target": f"WebView(src={src_url})",
                "features": {
                    "js_bridge": has_jsbridge,
                    "external_url": not src_url.startswith("$") and "rawfile" not in src_url,
                },
                "snippet": content[idx:idx + 500].strip()[:400],
            })
            idx += 5

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

    return sinks


# ============================================================
#  Attack Map (预判入口→sink 可连性)
# ============================================================

def build_attack_map(entries: list[dict], sinks: list[dict]) -> list[dict]:
    """将入口和 sink 配对，根据同文件/同模块做轻量可连性预判。"""
    paths = []
    counter = 0

    for entry in entries:
        for sink in sinks:
            # 基本过滤：同文件才有意义做配对（跨文件需要 AI 验证）
            if entry["file"] == sink["file"]:
                counter += 1
                paths.append({
                    "id": f"path-{counter:03d}",
                    "entry_id": entry["id"],
                    "sink_id": sink["id"],
                    "entry_type": entry["type"],
                    "sink_type": sink["type"],
                    "file": entry["file"],
                    "confidence": "same_file",
                    "note": f"入口 {entry['handler']} 和终点 {sink['target']} 在同一文件，极可能可达",
                })
            elif os.path.dirname(entry["file"]) == os.path.dirname(sink["file"]):
                counter += 1
                paths.append({
                    "id": f"path-{counter:03d}",
                    "entry_id": entry["id"],
                    "sink_id": sink["id"],
                    "entry_type": entry["type"],
                    "sink_type": sink["type"],
                    "file": f"{entry['file']} ↔ {sink['file']}",
                    "confidence": "same_dir",
                    "note": f"入口和终点在同一目录，可能通过函数调用可达",
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
