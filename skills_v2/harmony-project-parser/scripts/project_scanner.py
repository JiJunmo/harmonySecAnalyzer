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
from module_analyzer import analyze_all_modules
from dependency_analyzer import analyze_dependencies

VERSION = "2.0.0"


class EntryDiscoverer:
    """发现所有外部可控入口。"""
    def __init__(self, project_root: str, modules: list[dict], files: dict):
        self.root = Path(project_root).resolve()
        self.modules = modules
        self.files = files
        self.entries = []
        self.counter = 0

    def discover(self) -> list[dict]:
        self._scan_ets_sources()
        self._discover_ipc_services()
        self._discover_exported_abilities()
        return self.entries

    def _scan_ets_sources(self):
        import concurrent.futures

        ets_sources = self.files.get("ets_sources", [])
        if not ets_sources:
            return

        # 动态线程池大小
        max_workers = min(32, (os.cpu_count() or 1) * 2)
        deeplink_pattern = re.compile(r"(?:want|Want)\s*(?:\??\.|\[\s*['\"])\s*parameters\s*(?:\??\.|\[\s*['\"])(\w+)")

        def scan_file(sf: dict) -> list[dict]:
            filepath = self.root / sf["path"]
            if not filepath.exists():
                return []
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return []

            local_entries = []

            # 1. 寻找 DeepLinks
            file_deeplinks = {}
            for m in re.finditer(deeplink_pattern, content):
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
                verified_deeplink, deeplink_configs = self._verify_deeplink(sf["path"])
                lines = sorted(list(set(m["line"] for m in matches)))
                snippets_summary = "\n---\n".join(f"[Line {m['line']}]: {m['snippet']}" for m in matches[:3])

                entry_data = {
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
                local_entries.append(entry_data)

            # 2. 寻找 IPC 消息入口
            for m in re.finditer(r"onRemoteMessageRequest\s*\(", content):
                line = content[:m.start()].count("\n") + 1
                start = max(0, m.start() - 100)
                end = min(len(content), m.end() + 300)
                local_entries.append({
                    "type": "ipc",
                    "file": sf["path"],
                    "line": line,
                    "handler": "onRemoteMessageRequest",
                    "controlled_params": ["code", "data", "reply"],
                    "snippet": content[start:end].strip()[:400],
                })

            # 3. 寻找 URL 回调
            for pattern in ["onLoadIntercept", "onUrlLoadIntercept", "onInterceptRequest"]:
                for m in re.finditer(rf"{pattern}\s*\(", content):
                    line = content[:m.start()].count("\n") + 1
                    start = max(0, m.start() - 100)
                    end = min(len(content), m.end() + 300)
                    local_entries.append({
                        "type": "url_callback",
                        "file": sf["path"],
                        "line": line,
                        "handler": pattern,
                        "controlled_params": ["url"],
                        "snippet": content[start:end].strip()[:400],
                    })

            return local_entries

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(scan_file, ets_sources)

        # 汇总并进行稳定排序，保证 ID 递增和字段输出 100% 确定且可复现
        all_staged = []
        for local_list in results:
            all_staged.extend(local_list)

        all_staged.sort(key=lambda x: (x["file"], x["line"], x.get("controlled_params", [""])[0]))

        for entry in all_staged:
            self.counter += 1
            entry["id"] = f"entry-{self.counter:03d}"
            self.entries.append(entry)

    def _verify_deeplink(self, sf_path: str) -> tuple[bool, list[dict]]:
        current_file_path = (self.root / sf_path).resolve().as_posix()
        for mod in self.modules:
            mod_json_path = mod.get("module_path", "")
            if not mod_json_path:
                continue
            mod_base = Path(mod_json_path).parent.parent.parent

            for ab in mod.get("abilities", []):
                src_entry = ab.get("src_entry", "")
                if not src_entry:
                    continue

                ab_file_path = (mod_base / "src" / "main" / src_entry.lstrip("./")).as_posix()
                if Path(ab_file_path).resolve() == Path(current_file_path).resolve():
                    if ab.get("exported") is True:
                        uris = []
                        for skill in ab.get("skills", []):
                            if "uris" in skill:
                                uris.extend(skill["uris"])
                        if uris:
                            return True, [
                                {
                                    "scheme": u.get("scheme", ""),
                                    "host": u.get("host", ""),
                                    "port": u.get("port", ""),
                                    "path": u.get("path", "") or u.get("pathStartWith", "") or u.get("pathRegex", "")
                                } for u in uris
                            ]
                    break
        return False, []

    def _discover_ipc_services(self):
        for mod in self.modules:
            for ext in mod.get("extension_abilities", []):
                if ext.get("type") != "service" or not ext.get("src_entry"):
                    continue
                if ext.get("filtered_by_system_permission"):
                    continue
                self.counter += 1
                self.entries.append({
                    "id": f"entry-{self.counter:03d}",
                    "type": "ipc_service",
                    "file": mod.get("module_path", f"{mod.get('name', '')}/module.json5"),
                    "line": 0,
                    "handler": f"ExtensionAbility({ext.get('name', '')})",
                    "controlled_params": ["code", "data"],
                    "exported": ext.get("exported", False),
                    "src_entry": ext.get("src_entry", ""),
                    "snippet": json.dumps(ext, ensure_ascii=False)[:400],
                })

    def _discover_exported_abilities(self):
        for mod in self.modules:
            mod_json_path = mod.get("module_path", "")
            if not mod_json_path:
                continue
            mod_base = Path(mod_json_path).parent.parent.parent

            for ab in mod.get("abilities", []):
                if ab.get("exported") is not True or ab.get("filtered_by_system_permission") is True:
                    continue
                src_entry = ab.get("src_entry", "")
                if not src_entry:
                    continue

                ab_file_path = (mod_base / "src" / "main" / src_entry.lstrip("./")).as_posix()
                try:
                    rel_ab_path = Path(ab_file_path).resolve().relative_to(self.root).as_posix()
                except ValueError:
                    rel_ab_path = ab_file_path

                self.counter += 1
                self.entries.append({
                    "id": f"entry-{self.counter:03d}",
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


# 预编译所有 Sink 策略的正则表达式，省去每次调用的编译开销
SINK_STRATEGIES = [
    {
        "type": "data_exfil",
        "pattern": re.compile(r"(?:reply|result\.reply)\s*\.\s*(?:writeString|writeParcelable|writeArrayBuffer)"),
        "note": "IPC 回包写入，可能泄露服务端数据",
    },
    {
        "type": "state_mutation",
        "pattern": re.compile(r"(?:dataStatus|globalState|globalData|dataStore)\s*\.\s*(?:updata|update|set|write|put)"),
        "note": "攻击者数据写入全局状态",
    },
    {
        "type": "file_write",
        "pattern": re.compile(r"(?:fileIo|fs)\s*\.\s*(?:openSync|writeSync|write|writeText)"),
    },
    {
        "type": "database",
        "pattern": re.compile(r"(?:executeSql|querySql|rdbStore|relationalStore)"),
    },
    {
        "type": "network",
        "pattern": re.compile(r"(?:http\.request|createHttp|fetch)\s*\("),
    },
    {
        "type": "start_ability",
        "pattern": re.compile(r"(?:context\s*\.)?\s*startAbility(?:ForResult)?\s*\("),
    },
    {
        "type": "terminate_result",
        "pattern": re.compile(r"(?:context\s*\.)?\s*terminateSelfWithResult\s*\("),
    },
    {
        "type": "telephony",
        "pattern": re.compile(r"['\"]@kit\.TelephonyKit['\"]|['\"]@ohos\.telephony\.\w+['\"]"),
        "note": "使用了蜂窝通信模块，涉及通话、短信或SIM卡等敏感硬件操作",
    },
    {
        "type": "location",
        "pattern": re.compile(r"['\"]@kit\.LocationKit['\"]|['\"]@ohos\.geoLocationManager['\"]|['\"]@ohos\.location['\"]"),
        "note": "使用了地理位置服务，涉及GPS、基站等敏感定位操作",
    },
    {
        "type": "calendar",
        "pattern": re.compile(r"['\"]@kit\.CalendarKit['\"]|['\"]@ohos\.calendarManager['\"]|['\"]@ohos\.calendar['\"]"),
        "note": "使用了日历管理模块，涉及对本地日程事件的增删改查等敏感操作",
    },
]


class SinkDiscoverer:
    """发现所有攻击终点。"""
    def __init__(self, project_root: str, modules: list[dict], files: dict):
        self.root = Path(project_root).resolve()
        self.modules = modules
        self.files = files
        self.sinks = []
        self.counter = 0

    def discover(self) -> list[dict]:
        import concurrent.futures

        ets_sources = self.files.get("ets_sources", [])
        if not ets_sources:
            return []

        # 动态线程池大小
        max_workers = min(32, (os.cpu_count() or 1) * 2)

        def scan_file(sf: dict) -> list[dict]:
            filepath = self.root / sf["path"]
            if not filepath.exists():
                return []
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return []

            local_sinks = []

            # 1. 扫描通用 Sinks
            for strategy in SINK_STRATEGIES:
                for m in re.finditer(strategy["pattern"], content):
                    line = content[:m.start()].count("\n") + 1
                    sink_item = {
                        "type": strategy["type"],
                        "file": sf["path"],
                        "line": line,
                        "target": m.group(0).strip(),
                    }
                    if "note" in strategy:
                        sink_item["note"] = strategy["note"]
                    local_sinks.append(sink_item)

            # 2. 扫描 Webviews
            for wm in re.finditer(r'Web\s*\(\s*\{', content):
                idx = wm.start()
                line = content[:idx].count("\n") + 1
                web_block = content[idx:idx + 2000]

                src_url = self._extract_web_src(web_block)
                web_settings = self._extract_web_settings(web_block)

                has_jsbridge = "registerJavaScriptProxy" in content
                has_message_port = "createWebMessagePorts" in content

                is_local_resource = src_url.startswith("$rawfile")
                is_dynamic = src_url.startswith("var:") or src_url == "未识别"

                local_sinks.append({
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

            return local_sinks

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(scan_file, ets_sources)

        # 汇总并进行稳定排序，以确保 ID 唯一与 100% 的确定性
        all_staged = []
        for local_list in results:
            all_staged.extend(local_list)

        all_staged.sort(key=lambda x: (x["file"], x["line"], x["type"]))

        for sink in all_staged:
            self.counter += 1
            sink["id"] = f"sink-{self.counter:03d}"
            self.sinks.append(sink)

        return self.sinks

    def _extract_web_src(self, web_block: str) -> str:
        src_m = re.search(r"src:\s*(?:(\$rawfile\s*\([^)]*\))|['\"]([^'\"]+)['\"]|([\w.]+(?:\?\.\w+)*))", web_block)
        if src_m:
            return src_m.group(1) or src_m.group(2) or f"var:{src_m.group(3)}"
        return "未识别"

    def _extract_web_settings(self, web_block: str) -> dict:
        web_settings = {}
        attrs = [
            "javaScriptAccess", "fileAccess", "domStorageAccess",
            "mixedMode", "onlineImageAccess", "imageAccess",
            "geolocationAccess", "databaseAccess"
        ]
        for attr in attrs:
            attr_m = re.search(rf"\.{attr}\s*\(\s*(true|false|WebMixedMode\.\w+)", web_block)
            if attr_m:
                val = attr_m.group(1)
                web_settings[attr] = val == "true" if val in ("true", "false") else val
        return web_settings


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
    discoverer = EntryDiscoverer(str(project_root), modules, files)
    entries = discoverer.discover()
    entries_json = {
        "_meta": {"version": VERSION, "time": datetime.now(timezone.utc).isoformat(), "count": len(entries)},
        "entries": entries,
    }
    (out_dir / "entries.json").write_text(json.dumps(entries_json, ensure_ascii=False, indent=indent), encoding="utf-8")

    # Sink
    sink_discoverer = SinkDiscoverer(str(project_root), modules, files)
    sinks = sink_discoverer.discover()
    sinks_json = {
        "_meta": {"version": VERSION, "time": datetime.now(timezone.utc).isoformat(), "count": len(sinks)},
        "sinks": sinks,
    }
    (out_dir / "sinks.json").write_text(json.dumps(sinks_json, ensure_ascii=False, indent=indent), encoding="utf-8")

    print(f"[DONE] v2 攻击面发现完成: {len(entries)} 入口, {len(sinks)} 终点 -> {out_dir}")


if __name__ == "__main__":
    main()
