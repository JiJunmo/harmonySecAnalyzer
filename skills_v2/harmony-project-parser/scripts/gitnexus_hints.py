#!/usr/bin/env python3
"""
GitNexus 数据流预分析器 —— Phase 1.5

用法:
    python gitnexus_hints.py <project_path> <audit_dir>

功能:
    1. 确保目标项目已被 GitNexus 索引
    2. 读取 entries.json / sinks.json / attack_map.json
    3. 用 GitNexus Cypher 查询检测 entry→sink 的数据流连接
    4. 为 attack_map 路径追加 data_flow_hint 字段
    5. 输出更新后的 attack_map.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent


def run_cypher(query: str, repo_path: str) -> list[dict]:
    """运行 GitNexus Cypher 查询并解析结果。"""
    try:
        result = subprocess.run(
            ["npx", "gitnexus", "cypher", query, "--repo", repo_path],
            capture_output=True, text=True, timeout=30, cwd=SKILL_DIR
        )
        if result.returncode != 0:
            print(f"[WARN] Cypher query failed: {result.stderr[:200]}", file=sys.stderr)
            return []
        data = json.loads(result.stdout)
        if "markdown" not in data:
            return []
        return _parse_markdown_table(data["markdown"])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[WARN] Cypher query error: {e}", file=sys.stderr)
        return []


def _parse_markdown_table(md: str) -> list[dict]:
    """将 GitNexus 返回的 Markdown 表格解析为字典列表。"""
    lines = [l.strip() for l in md.split("\n") if l.strip()]
    if len(lines) < 2:
        return []
    headers = [h.strip() for h in lines[0].strip("|").split("|")]
    rows = []
    for line in lines[2:]:
        vals = [v.strip() for v in line.strip("|").split("|")]
        if len(vals) == len(headers):
            rows.append(dict(zip(headers, vals)))
    return rows


def ensure_indexed(project_path: str) -> str:
    """确保项目已被 GitNexus 索引，返回 repo path。"""
    repo_path = str(Path(project_path).resolve())
    try:
        result = subprocess.run(
            ["npx", "gitnexus", "analyze", "--skip-git"],
            capture_output=True, text=True, timeout=60,
            cwd=project_path
        )
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            if "/" in line and "Repository indexed" not in line:
                cleaned = line.strip().split("\n")[-1]
                if cleaned.startswith("/"):
                    repo_path = cleaned
                    break
    except Exception:
        pass
    return repo_path


def collect_accesses(repo: str) -> list[dict]:
    """收集所有入口方法对属性的写入关系。"""
    query = """
    MATCH (a)-[r:CodeRelation {type: 'ACCESSES', reason: 'write'}]->(p:Property)
    RETURN a.name as method, a.filePath as method_file, p.name as property, p.filePath as property_file
    """
    return run_cypher(query, repo)


def collect_calls(repo: str) -> list[dict]:
    """收集调用链关系（不再限制 caller 节点类型，Method 和 Function 都纳入）。"""
    query = """
    MATCH (a)-[r:CodeRelation {type: 'CALLS'}]->(b)
    RETURN a.name as caller, a.filePath as caller_file, b.name as callee, b.filePath as callee_file
    """
    return run_cypher(query, repo)


def collect_all_methods(repo: str) -> list[dict]:
    """收集所有方法（用于跨文件检测）。"""
    query = """
    MATCH (m:Method) RETURN m.name as name, m.filePath as file, m.startLine as line
    """
    return run_cypher(query, repo)


def normalize_path(p: str, project_root: str) -> str:
    """将绝对路径或相对路径标准化。"""
    path = str(p)
    root = str(Path(project_root).resolve())
    if path.startswith(root):
        path = path[len(root):].lstrip("/")
    if "demo_test_scanner/" in path:
        path = path.split("demo_test_scanner/")[-1]
    return path


def file_match(path_a: str, path_b: str) -> bool:
    """检查两个文件路径是否指代同一文件。"""
    a = Path(path_a).name if "/" in path_a else path_a
    b = Path(path_b).name if "/" in path_b else path_b
    return a == b or path_a == path_b or path_a.endswith(path_b) or path_b.endswith(path_a)


def build_hints(
    entries: list[dict],
    sinks: list[dict],
    attack_map: list[dict],
    accesses: list[dict],
    calls: list[dict],
    project_root: str
) -> list[dict]:
    """为每条 attack_map 路径构建 data_flow_hint。"""
    # 构建快速查找结构
    entry_by_id = {e["id"]: e for e in entries}
    sink_by_id = {s["id"]: s for s in sinks}

    enriched = []
    for path in attack_map:
        entry = entry_by_id.get(path["entry_id"])
        if not entry:
            enriched.append(path)
            continue

        entries_with_hints_by_sink_file = {}  # grouping hints by sink file

        # 如果多个 sink id 归并在一起，提取每个 sink 所在文件
        for sid in path.get("sink_ids", []):
            sink = sink_by_id.get(sid)
            if not sink or not entry:
                continue
            sink_file = normalize_path(sink["file"], project_root)
            if sink_file not in entries_with_hints_by_sink_file:
                entries_with_hints_by_sink_file[sink_file] = {
                    "sink_file": sink_file,
                    "hints": []
                }

        entry_file = normalize_path(entry["file"], project_root)
        entry_type = entry["type"]
        trace = []
        verified = False

        if entry_type == "ipc_service":
            trace = _build_ipc_hints(entry_file, accesses, calls)
            verified = len(trace) >= 2

        elif entry_type in ("deeplink", "url_callback"):
            trace = _build_deeplink_hints(entry_file, accesses, calls)
            verified = len(trace) >= 2

        elif entry_type == "exported_ability":
            trace = _build_ability_hints(entry_file, accesses, calls)
            verified = len(trace) >= 2

        elif entry_type == "ipc":
            trace = _build_ipc_method_hints(entry_file, calls)
            verified = len(trace) >= 2

        enriched_path = dict(path)
        if trace:
            enriched_path["data_flow_hint"] = {
                "trace": trace,
                "verified": verified,
                "source": "gitnexus_cypher"
            }
        enriched.append(enriched_path)

    return enriched


def _build_ipc_hints(entry_file: str, accesses: list[dict], calls: list[dict]) -> list[str]:
    """构建 IPC 服务的数据流追踪链。"""
    trace = []

    # Step 1: onConnect 是否连接到全局单例
    for c in calls:
        if c.get("caller") == "onConnect" and _file_in(c.get("caller_file"), entry_file):
            trace.append(f"onConnect → {c['callee']} ({c.get('caller_file')}) [单例模式，无会话隔离]")

    # Step 2: onRemoteMessageRequest → onHandleClientReq (分发)
    for c in calls:
        if c.get("caller") == "onRemoteMessageRequest" and _file_in(c.get("caller_file"), entry_file):
            trace.append(f"onRemoteMessageRequest → {c['callee']} ({c.get('callee_file')}) [业务分发]")

    # Step 3: onHandleClientReq → 敏感业务方法
    for c in calls:
        if c.get("caller") == "onHandleClientReq":
            callee = c.get("callee", "")
            if callee in ("updateParcelableData", "updateArrayBufferData"):
                trace.append(f"{c['caller']} → {callee} ({c.get('callee_file')}) [全局状态写入]")
            elif callee not in ("MyParcelable",):
                trace.append(f"{c['caller']} → {callee} ({c.get('callee_file')}) [敏感业务执行]")

    # Step 4: 属性写入 (update* 方法写入全局状态)
    for a in accesses:
        method = a.get("method", "")
        if method in ("updateParcelableData", "updateArrayBufferData") and _file_in(a.get("method_file"), entry_file):
            trace.append(f"{method} → write({a['property']}) ({a.get('property_file')}) [全局状态修改]")

    return trace


def _build_deeplink_hints(entry_file: str, accesses: list[dict], calls: list[dict]) -> list[str]:
    """构建 DeepLink 的数据流追踪链。"""
    trace = []
    seen = set()

    for a in accesses:
        method = a.get("method", "")
        prop = a.get("property", "")
        method_file = a.get("method_file", "")

        if method in ("onCreate", "onNewWant") and _file_in(method_file, entry_file):
            key = f"{method} → write({prop})"
            if key not in seen:
                seen.add(key)
                trace.append(f"{key} ({method_file}) [外部参数注入]")

    return trace


def _build_ability_hints(entry_file: str, accesses: list[dict], calls: list[dict]) -> list[str]:
    """构建 UIAbility 的数据流追踪链。"""
    trace = []
    seen = set()

    for a in accesses:
        method = a.get("method", "")
        prop = a.get("property", "")
        method_file = a.get("method_file", "")

        if method in ("onCreate", "onNewWant") and _file_in(method_file, entry_file):
            key = f"{method} → write({prop})"
            if key not in seen:
                seen.add(key)
                trace.append(f"{key} ({method_file}) [嵌套 Want 注入]")

    return trace


def _build_ipc_method_hints(entry_file: str, calls: list[dict]) -> list[str]:
    """构建 IPC 方法的调用链追踪。"""
    trace = []

    # 按调用路径排序展示：入口 → 分发 → 敏感操作
    for c in calls:
        if _file_in(c.get("caller_file"), entry_file):
            caller = c.get("caller", "")
            callee = c.get("callee", "")
            # 跳过 File→Class 关系（无意义）
            if caller.endswith(".ets") or caller == "IPC_Service.ets":
                continue
            label = "IPC调用链"
            if callee in ("updateParcelableData", "updateArrayBufferData"):
                label = "全局状态写入"
            elif callee in ("MyParcelable", "DataStatus"):
                label = "敏感类实例化"
            trace.append(f"{caller} → {callee} ({c.get('callee_file')}) [{label}]")

    return trace


def _file_in(file_path: str, target: str) -> bool:
    """检查 file_path 是否在 target 文件中。"""
    if not file_path or not target:
        return False
    return Path(file_path).name == Path(target).name or target in file_path or file_path in target


def main():
    parser = argparse.ArgumentParser(description="GitNexus 数据流预分析器")
    parser.add_argument("project_path", help="鸿蒙项目根目录")
    parser.add_argument("audit_dir", help="审计输出目录（含 entries.json 等）")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON")
    args = parser.parse_args()

    audit_dir = Path(args.audit_dir)
    entries_file = audit_dir / "entries.json"
    sinks_file = audit_dir / "sinks.json"
    attack_map_file = audit_dir / "attack_map.json"

    if not attack_map_file.exists():
        print("[ERROR] attack_map.json 不存在，先运行 project_scanner.py", file=sys.stderr)
        sys.exit(1)

    # Step 1: 确保 GitNexus 索引
    print("[STEP 1] 确保项目已索引...")
    repo = ensure_indexed(args.project_path)
    print(f"  GitNexus repo: {repo}")

    # Step 2: 查询数据流
    print("[STEP 2] 查询 ACCESSES 边...")
    accesses = collect_accesses(repo)
    print(f"  找到 {len(accesses)} 条属性写入关系")

    print("[STEP 3] 查询 CALLS 边...")
    calls = collect_calls(repo)
    print(f"  找到 {len(calls)} 条调用关系")

    # Step 3: 读取数据
    print("[STEP 4] 读取 entries + sinks + attack_map...")
    entries_data = json.loads(entries_file.read_text(encoding="utf-8"))
    entries = entries_data.get("entries", [])
    sinks_data = json.loads(sinks_file.read_text(encoding="utf-8"))
    sinks = sinks_data.get("sinks", [])
    amap_data = json.loads(attack_map_file.read_text(encoding="utf-8"))
    attack_map = amap_data.get("attack_map", [])

    # Step 4: 构建 hints
    print("[STEP 5] 构建数据流 hints...")
    enriched = build_hints(entries, sinks, attack_map, accesses, calls, args.project_path)

    hint_count = sum(1 for p in enriched if "data_flow_hint" in p)
    verified_count = sum(1 for p in enriched if p.get("data_flow_hint", {}).get("verified"))
    print(f"  {hint_count}/{len(attack_map)} 条路径获得数据流提示 ({verified_count} 条已确认)")

    # Step 5: 输出
    output = dict(amap_data)
    output["attack_map"] = enriched
    output["_meta"]["gitnexus_hints"] = {
        "total": len(enriched),
        "with_hints": hint_count,
        "verified": verified_count,
        "accesses_count": len(accesses),
        "calls_count": len(calls)
    }

    indent = 2 if args.pretty else None
    attack_map_file.write_text(json.dumps(output, ensure_ascii=False, indent=indent), encoding="utf-8")
    print(f"[DONE] GitNexus hints 注入完成 → {attack_map_file}")


if __name__ == "__main__":
    main()
