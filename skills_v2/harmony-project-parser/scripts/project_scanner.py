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
        for sf in self.files.get("ets_sources", []):
            filepath = self.root / sf["path"]
            if not filepath.exists():
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            self._find_deeplinks(sf, content)
            self._find_ipc_message(sf, content)
            self._find_url_callbacks(sf, content)

    def _find_deeplinks(self, sf: dict, content: str):
        file_deeplinks = {}
        pattern = r"(?:want|Want)\s*(?:\??\.|\[\s*['\"])\s*parameters\s*(?:\??\.|\[\s*['\"])(\w+)"
        for m in re.finditer(pattern, content):
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
            self._add_deeplink_entry(sf, param_name, matches)

    def _add_deeplink_entry(self, sf: dict, param_name: str, matches: list[dict]):
        verified_deeplink, deeplink_configs = self._verify_deeplink(sf["path"])
        self.counter += 1
        lines = sorted(list(set(m["line"] for m in matches)))
        snippets_summary = "\n---\n".join(f"[Line {m['line']}]: {m['snippet']}" for m in matches[:3])

        entry_data = {
            "id": f"entry-{self.counter:03d}",
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

        self.entries.append(entry_data)

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

    def _find_ipc_message(self, sf: dict, content: str):
        for m in re.finditer(r"onRemoteMessageRequest\s*\(", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            start = max(0, m.start() - 100)
            end = min(len(content), m.end() + 300)
            self.entries.append({
                "id": f"entry-{self.counter:03d}",
                "type": "ipc",
                "file": sf["path"],
                "line": line,
                "handler": "onRemoteMessageRequest",
                "controlled_params": ["code", "data", "reply"],
                "snippet": content[start:end].strip()[:400],
            })

    def _find_url_callbacks(self, sf: dict, content: str):
        for pattern in ["onLoadIntercept", "onUrlLoadIntercept", "onInterceptRequest"]:
            for m in re.finditer(rf"{pattern}\s*\(", content):
                self.counter += 1
                line = content[:m.start()].count("\n") + 1
                start = max(0, m.start() - 100)
                end = min(len(content), m.end() + 300)
                self.entries.append({
                    "id": f"entry-{self.counter:03d}",
                    "type": "url_callback",
                    "file": sf["path"],
                    "line": line,
                    "handler": pattern,
                    "controlled_params": ["url"],
                    "snippet": content[start:end].strip()[:400],
                })

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


class SinkDiscoverer:
    """发现所有攻击终点。"""
    def __init__(self, project_root: str, modules: list[dict], files: dict):
        self.root = Path(project_root).resolve()
        self.modules = modules
        self.files = files
        self.sinks = []
        self.counter = 0

    def discover(self) -> list[dict]:
        for sf in self.files.get("ets_sources", []):
            filepath = self.root / sf["path"]
            if not filepath.exists():
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            self._scan_file_sinks(sf, content)
        return self.sinks

    def _scan_file_sinks(self, sf: dict, content: str):
        self._find_ipc_exfil(sf, content)
        self._find_state_mutations(sf, content)
        self._find_webviews(sf, content)
        self._find_file_writes(sf, content)
        self._find_databases(sf, content)
        self._find_networks(sf, content)
        self._find_ability_starts(sf, content)
        self._find_result_terminations(sf, content)

    def _find_ipc_exfil(self, sf: dict, content: str):
        for m in re.finditer(r"(?:reply|result\.reply)\s*\.\s*(?:writeString|writeParcelable|writeArrayBuffer)", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
                "type": "data_exfil",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
                "note": "IPC 回包写入，可能泄露服务端数据",
            })

    def _find_state_mutations(self, sf: dict, content: str):
        for m in re.finditer(r"(?:dataStatus|globalState|globalData|dataStore)\s*\.\s*(?:updata|update|set|write|put)", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
                "type": "state_mutation",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
                "note": "攻击者数据写入全局状态",
            })

    def _find_webviews(self, sf: dict, content: str):
        for wm in re.finditer(r'Web\s*\(\s*\{', content):
            self.counter += 1
            idx = wm.start()
            line = content[:idx].count("\n") + 1
            web_block = content[idx:idx + 2000]

            src_url = self._extract_web_src(web_block)
            web_settings = self._extract_web_settings(web_block)

            has_jsbridge = "registerJavaScriptProxy" in content
            has_message_port = "createWebMessagePorts" in content

            is_local_resource = src_url.startswith("$rawfile")
            is_dynamic = src_url.startswith("var:") or src_url == "未识别"

            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
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

    def _find_file_writes(self, sf: dict, content: str):
        for m in re.finditer(r"(?:fileIo|fs)\s*\.\s*(?:openSync|writeSync|write|writeText)", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
                "type": "file_write",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
            })

    def _find_databases(self, sf: dict, content: str):
        for m in re.finditer(r"(?:executeSql|querySql|rdbStore|relationalStore)", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
                "type": "database",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
            })

    def _find_networks(self, sf: dict, content: str):
        for m in re.finditer(r"(?:http\.request|createHttp|fetch)\s*\(", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
                "type": "network",
                "file": sf["path"],
                "line": line,
                "target": m.group(0),
            })

    def _find_ability_starts(self, sf: dict, content: str):
        for m in re.finditer(r"(?:context\s*\.)?\s*startAbility(?:ForResult)?\s*\(", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
                "type": "start_ability",
                "file": sf["path"],
                "line": line,
                "target": m.group(0).strip(),
            })

    def _find_result_terminations(self, sf: dict, content: str):
        for m in re.finditer(r"(?:context\s*\.)?\s*terminateSelfWithResult\s*\(", content):
            self.counter += 1
            line = content[:m.start()].count("\n") + 1
            self.sinks.append({
                "id": f"sink-{self.counter:03d}",
                "type": "terminate_result",
                "file": sf["path"],
                "line": line,
                "target": m.group(0).strip(),
            })


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
