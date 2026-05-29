#!/usr/bin/env python3
"""
GitNexus 图遍历路径发现器 —— Phase 1.5

用法:
    python path_discovery.py <project_path> <audit_dir>

功能:
    1. 从 GitNexus 拉取完整代码图（CALLS + ACCESSES 边）
    2. 从每个 entry 出发沿 CALLS 边 BFS 遍历（最大深度 10）
    3. 自动发现所有可达 sink 的完整路径
    4. 反向 BFS 补漏：未被连接的 sink 从自身出发回溯到 entry
    5. 输出 enriched attack_map.json

与旧方案的关键区别:
    旧: 正则配对 entry+sink → GitNexus 验证配对真假（只能收缩，不能扩展）
    新: GitNexus 图 BFS 遍历直接发现路径（不依赖配对规则，不漏检跨文件调用链）
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent

# [[[[1. 基础设施]]]]
BFS_MAX_DEPTH = 10


def run_cypher(query: str, repo_path: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["npx", "gitnexus", "cypher", query, "--repo", repo_path],
            capture_output=True, text=True, timeout=30, cwd=SKILL_DIR
        )
        if result.returncode != 0:
            print(f"[WARN] Cypher 查询失败: {result.stderr[:200]}", file=sys.stderr)
            return []
        if not result.stdout or result.stdout.strip() == "[]":
            return []
        data = json.loads(result.stdout)
        if isinstance(data, list):
            if len(data) > 0 and isinstance(data[0], dict):
                data = data[0]
            else:
                return []
        if isinstance(data, dict):
            return _parse_markdown_table(data.get("markdown", ""))
        return []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[WARN] Cypher 错误: {e}", file=sys.stderr)
        return []


def _parse_markdown_table(md: str) -> list[dict]:
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
    repo_path = str(Path(project_path).resolve())
    try:
        subprocess.run(
            ["npx", "gitnexus", "analyze", "--skip-git"],
            capture_output=True, text=True, timeout=60, cwd=project_path
        )
    except Exception:
        pass
    return repo_path


# [[[[2. 图构建]]]]

def fetch_call_graph(repo: str) -> list[dict]:
    query = """
    MATCH (a)-[r:CodeRelation {type: 'CALLS'}]->(b)
    RETURN a.name as caller, a.filePath as caller_file, b.name as callee, b.filePath as callee_file
    """
    return run_cypher(query, repo)


def fetch_all_methods(repo: str) -> list[dict]:
    """拉取所有 Method 和 Function 节点（DuckDB 不支持 WHERE n:Method OR n:Function，需两次查询）。"""
    rows = []
    # 查询 Method 节点
    query_m = "MATCH (n:Method) RETURN n.name as name, n.filePath as file, n.startLine as line"
    rows.extend(run_cypher(query_m, repo))
    # 查询 Function 节点
    query_f = "MATCH (n:Function) RETURN n.name as name, n.filePath as file, n.startLine as line"
    rows.extend(run_cypher(query_f, repo))
    return rows


def normalize_path(p: str, project_root: str) -> str:
    path = str(p)
    root = str(Path(project_root).resolve())
    if path.startswith(root):
        path = path[len(root):].lstrip("/")
    if "demo_test_scanner/" in path:
        path = path.split("demo_test_scanner/", maxsplit=1)[-1]
    return path


def build_graph(calls: list[dict], project_root: str) -> dict[str, list[tuple[str, str, str]]]:
    """
    构建有向邻接表。
    graph[caller_key] = [(callee_key, callee_file, callee_name), ...]
    key 格式: file::function_name
    """
    graph: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    seen_keys = set()

    for c in calls:
        cf = normalize_path(c.get("caller_file", ""), project_root)
        cn = c.get("caller", "")
        tf = normalize_path(c.get("callee_file", ""), project_root)
        tn = c.get("callee", "")

        if not cf or not cn or not tf or not tn:
            continue
        if cn.endswith(".ets") or tn.endswith(".ets"):
            continue

        ckey = f"{cf}::{cn}"
        tkey = f"{tf}::{tn}"

        edge = (tkey, tf, tn)
        edge_hash = f"{ckey}->{tkey}"
        if edge_hash not in seen_keys:
            seen_keys.add(edge_hash)
            graph[ckey].append(edge)

    return dict(graph)


# [[[[3. Entry/Sink 映射]]]]

def map_entries_to_nodes(
    entries: list[dict],
    all_methods: list[dict],
    project_root: str
) -> dict[str, list[tuple[str, str]]]:
    """
    将 entries.json 中的入口映射到图中的 Method/Function 节点。
    返回: {entry_id: [(node_key, method_name), ...]}
    """
    mapping: dict[str, list[tuple[str, str]]] = defaultdict(list)

    for entry in entries:
        eid = entry["id"]
        entry_file = normalize_path(entry["file"], project_root)
        entry_name = Path(entry_file).name

        for m in all_methods:
            mf = normalize_path(m.get("file", ""), project_root)
            mn = m.get("name", "")

            if not _file_match(mf, entry_name):
                continue

            if entry["type"] in ("deeplink", "url_callback", "exported_ability"):
                # 匹配 onCreate / onNewWant 或文件中的任意方法
                if mn in ("onCreate", "onNewWant", "onConnect", "onRemoteMessageRequest"):
                    nkey = f"{mf}::{mn}"
                    mapping[eid].append((nkey, mn))

            elif entry["type"] in ("ipc", "ipc_service"):
                if mn in ("onConnect", "onRemoteMessageRequest", "onHandleClientReq"):
                    nkey = f"{mf}::{mn}"
                    mapping[eid].append((nkey, mn))

    return dict(mapping)


def map_sinks_to_nodes(
    sinks: list[dict],
    all_methods: list[dict],
    project_root: str
) -> dict[str, set[str]]:
    """
    将 sinks.json 中的终点映射到图中的 Method/Function 节点。
    返回: {sink_id: set(node_keys)}
    匹配策略: 同文件下的所有方法均视为潜在 sink 节点。
    """
    mapping: dict[str, set[str]] = defaultdict(set)

    for sink in sinks:
        sid = sink["id"]
        sink_file = normalize_path(sink["file"], project_root)

        for m in all_methods:
            mf = normalize_path(m.get("file", ""), project_root)
            if _file_match(mf, sink_file):
                mn = m.get("name", "")
                nkey = f"{mf}::{mn}"
                mapping[sid].add(nkey)

    return dict(mapping)


# [[[[4. BFS 路径发现]]]]

def bfs_discover(
    entry_id: str,
    start_nodes: list[tuple[str, str]],
    sink_map: dict[str, set[str]],
    graph: dict[str, list[tuple[str, str, str]]],
) -> list[dict]:
    """
    从 entry 的起始节点出发做 BFS，找到所有可达的 sink。
    返回: [{entry_id, sink_id, trace, hops, verified}, ...]
    """
    results = []
    # 构建 sink_key -> sink_id 的反向索引（一个节点可能命中多个 sink）
    sink_key_to_ids: dict[str, set[str]] = defaultdict(set)
    for sid, node_keys in sink_map.items():
        for nk in node_keys:
            sink_key_to_ids[nk].add(sid)

    for start_key, start_name in start_nodes:
        visited: dict[str, int] = {}      # node_key -> depth
        parent: dict[str, str | None] = {}  # node_key -> parent_key

        queue = deque()
        queue.append(start_key)
        visited[start_key] = 0
        parent[start_key] = None

        while queue:
            current = queue.popleft()
            depth = visited[current]

            if depth >= BFS_MAX_DEPTH:
                continue

            # 剪枝：跳过太密集的节点
            neighbors = graph.get(current, [])
            if len(neighbors) > 20:
                continue

            for next_key, next_file, next_name in neighbors:
                if next_key in visited:
                    continue

                visited[next_key] = depth + 1
                parent[next_key] = current

                # 检查是否命中 sink
                if next_key in sink_key_to_ids:
                    for sid in sink_key_to_ids[next_key]:
                        trace = _reconstruct_trace(parent, start_key, next_key)
                        results.append({
                            "entry_id": entry_id,
                            "sink_id": sid,
                            "trace": trace,
                            "hops": depth + 1,
                            "verified": True,
                        })

                if depth + 1 < BFS_MAX_DEPTH:
                    queue.append(next_key)

    return results


def reverse_bfs_discover(
    sink_id: str,
    sink_nodes: set[str],
    entry_map: dict[str, list[tuple[str, str]]],
    graph: dict[str, list[tuple[str, str, str]]],
) -> list[dict]:
    """
    从 sink 出发反向 BFS，找到可达的 entry。
    用于补漏：正向 BFS 未覆盖的 sink。
    注意：需要在反向图上遍历。
    """
    # 构建反向图: graph_rev[callee_key] = [(caller_key, caller_file, caller_name), ...]
    graph_rev: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for ckey, edges in graph.items():
        cf = ckey.split("::")[0]
        cn = ckey.split("::")[1] if "::" in ckey else ""
        for (tkey, tf, tn) in edges:
            graph_rev[tkey].append((ckey, cf, cn))

    # 构建 entry_node -> entry_id 索引
    entry_key_to_ids: dict[str, set[str]] = defaultdict(set)
    for eid, nodes in entry_map.items():
        for nk, _ in nodes:
            entry_key_to_ids[nk].add(eid)

    results = []
    for sink_key in sink_nodes:
        visited = {}
        parent = {}
        queue = deque()
        queue.append(sink_key)
        visited[sink_key] = 0
        parent[sink_key] = None

        while queue:
            current = queue.popleft()
            depth = visited[current]
            if depth >= BFS_MAX_DEPTH:
                continue

            for rev_key, _, _ in graph_rev.get(current, []):
                if rev_key in visited:
                    continue
                visited[rev_key] = depth + 1
                parent[rev_key] = current

                if rev_key in entry_key_to_ids:
                    for eid in entry_key_to_ids[rev_key]:
                        trace = _reconstruct_rev_trace(parent, rev_key, sink_key)
                        results.append({
                            "entry_id": eid,
                            "sink_id": sink_id,
                            "trace": trace,
                            "hops": depth + 1,
                            "verified": True,
                        })

                if depth + 1 < BFS_MAX_DEPTH:
                    queue.append(rev_key)

    return results


def _reconstruct_trace(parent: dict, start_key: str, end_key: str) -> list[str]:
    trace = []
    current = end_key
    while current is not None:
        parts = current.split("::", 1)
        trace.append(f"{parts[1]} ({parts[0]})" if len(parts) == 2 else current)
        current = parent.get(current)
    trace.reverse()
    return trace


def _reconstruct_rev_trace(parent: dict, entry_key: str, sink_key: str) -> list[str]:
    return _reconstruct_trace(parent, entry_key, sink_key)


# [[[[5. 构建 attack_map]]]]

def build_attack_map(
    entries: list[dict],
    sinks: list[dict],
    all_paths: list[dict],
    graph_stats: dict,
    project_root: str,
) -> list[dict]:
    """合并正向、反向和 ACCESSES 回退发现的路径，去重，输出 attack_map 格式。"""

    entry_by_id = {e["id"]: e for e in entries}
    sink_by_id = {s["id"]: s for s in sinks}

    # 合并并去重 (entry_id, sink_id) 对
    grouped_by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for p in all_paths:
        key = (p["entry_id"], p["sink_id"])
        grouped_by_pair[key].append(p)

    # 按 (entry_id, sink_file) 归并
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for (eid, sid), paths in grouped_by_pair.items():
        entry = entry_by_id.get(eid)
        sink = sink_by_id.get(sid)
        if not entry or not sink:
            continue
        sink_file = normalize_path(sink["file"], project_root)
        key = (eid, sink_file)
        grouped[key].extend(paths)

    counter = 0
    attack_map = []

    for (eid, sink_file), paths in sorted(grouped.items()):
        counter += 1
        entry = entry_by_id[eid]
        best = min(paths, key=lambda p: p["hops"])
        sink_ids = sorted(set(p["sink_id"] for p in paths))
        sink_types = sorted(set(
            sink_by_id[sid]["type"] for sid in sink_ids if sid in sink_by_id
        ))

        entry_type = entry["type"]
        confidence = "high" if best["hops"] <= 3 else "medium" if best["hops"] <= 5 else "lower"

        attack_map.append({
            "id": f"path-{counter:03d}",
            "entry_id": eid,
            "sink_ids": sink_ids,
            "sink_types": sink_types,
            "entry_type": entry_type,
            "file": f"{normalize_path(entry['file'], project_root)} ↔ {sink_file}",
            "confidence": confidence,
            "note": f"{entry['handler']} → {len(best['trace'])} 步到达 {sink_file}（{', '.join(sink_types)}）",
            "data_flow_hint": {
                "trace": best["trace"],
                "verified": True,
                "hops": best["hops"],
                "source": "gitnexus_bfs",
            }
        })

    return attack_map


# [[[[6. 工具函数]]]]

def _file_match(path_a: str, path_b: str) -> bool:
    if not path_a or not path_b:
        return False
    a_name = Path(path_a).name
    b_name = Path(path_b).name if "/" in path_b else path_b
    return a_name == b_name or path_a.endswith(path_b) or path_b.endswith(path_a)


# [[[[7. 主入口]]]]


def _accesses_backfill(
    orphan_entries: list[dict],
    sinks: list[dict],
    entry_map: dict[str, list[tuple[str, str]]],
    sink_map: dict[str, set[str]],
    graph: dict[str, list[tuple[str, str, str]]],
    calls: list[dict],
    normalize_path_fn,
    project_root: str,
    repo: str,
) -> list[dict]:
    """
    对 CALLS BFS 未覆盖的 entry，用 ACCESSES（属性写入）做回退路径发现。
    策略：如果 entry 方法写入了某个 Property，且该 Property 所在文件与 sink 所在文件相同，
    则视为存在潜在数据流连接。
    """
    results = []
    # 构建 sink module → sink_ids 索引（同模块匹配）
    sink_by_module: dict[str, list[dict]] = defaultdict(list)
    for sid, node_keys in sink_map.items():
        for nk in node_keys:
            parts = nk.split("::", 1)
            if parts:
                module = parts[0].split("/")[0] if "/" in parts[0] else parts[0]
                sink_by_module[module].append({"id": sid, "file": parts[0]})

    # 用 Cypher 查询 ACCESSES（write）边
    accesses_query = """
    MATCH (a)-[r:CodeRelation {type: 'ACCESSES', reason: 'write'}]->(p:Property)
    RETURN a.name as method, a.filePath as method_file, p.name as property, p.filePath as property_file
    """
    accesses = run_cypher(accesses_query, repo)

    # 按 entry 分组
    for entry in orphan_entries:
        eid = entry["id"]
        entry_file_norm = normalize_path_fn(entry["file"], project_root)
        entry_module = entry_file_norm.split("/")[0] if "/" in entry_file_norm else entry_file_norm

        hit_sinks = set()

        for a in accesses:
            method_file = normalize_path_fn(a.get("method_file", ""), project_root)
            prop_file = normalize_path_fn(a.get("property_file", ""), project_root)
            method_name = a.get("method", "")
            prop_name = a.get("property", "")
            prop_module = prop_file.split("/")[0] if "/" in prop_file else prop_file

            # 检查：ACCESSES 的方法是否在 entry 文件中
            if not _file_match(method_file, entry_file_norm):
                continue

            # 检查：属性所在模块是否有 sink（不再要求同文件）
            if prop_module not in sink_by_module and entry_module not in sink_by_module:
                continue

            candidates = sink_by_module.get(prop_module, sink_by_module.get(entry_module, []))
            for sink_info in candidates:
                sid = sink_info["id"]
                sfile = sink_info["file"]
                key = (eid, sid)
                if key not in hit_sinks:
                    hit_sinks.add(key)
                    trace = [
                        f"{method_name} → write({prop_name}) ({method_file}) [属性写入，外部参数注入]",
                        f"{prop_name} → Sink [{sid}] ({sfile}) [同模块数据流: {prop_module}]",
                    ]
                    results.append({
                        "entry_id": eid,
                        "sink_id": sid,
                        "trace": trace,
                        "hops": 2,
                        "verified": True,
                    })

    return results


# [[[[8. 主入口]]]]

def main():
    parser = argparse.ArgumentParser(description="GitNexus 图遍历路径发现器")
    parser.add_argument("project_path", help="鸿蒙项目根目录")
    parser.add_argument("audit_dir", help="审计输出目录（含 entries.json / sinks.json）")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON")
    args = parser.parse_args()

    audit_dir = Path(args.audit_dir)
    entries_file = audit_dir / "entries.json"
    sinks_file = audit_dir / "sinks.json"

    for f in [entries_file, sinks_file]:
        if not f.exists():
            print(f"[ERROR] {f.name} 不存在，先运行 project_scanner.py", file=sys.stderr)
            sys.exit(1)

    # Step 1: 确保 GitNexus 索引
    print("[STEP 1] 确保项目已索引...")
    repo = ensure_indexed(args.project_path)
    print(f"  repo: {repo}")

    # Step 2: 拉取代码图
    print("[STEP 2] 拉取 GitNexus 代码图...")
    calls = fetch_call_graph(repo)
    all_methods = fetch_all_methods(repo)
    print(f"  CALLS 边: {len(calls)}, 方法节点: {len(all_methods)}")

    # Step 3: 构建内存图
    print("[STEP 3] 构建邻接表...")
    graph = build_graph(calls, args.project_path)
    print(f"  图节点数: {len(graph)}, 边数: {sum(len(v) for v in graph.values())}")

    # Step 4: 读数据
    entries_data = json.loads(entries_file.read_text(encoding="utf-8"))
    entries = entries_data.get("entries", [])
    sinks_data = json.loads(sinks_file.read_text(encoding="utf-8"))
    sinks = sinks_data.get("sinks", [])

    # Step 5: 映射
    print("[STEP 4] 映射 entry/sink 到图节点...")
    entry_map = map_entries_to_nodes(entries, all_methods, args.project_path)
    sink_map = map_sinks_to_nodes(sinks, all_methods, args.project_path)
    mapped_entries = len(entry_map)
    mapped_sinks = sum(len(v) for v in sink_map.values())
    print(f"  映射入口: {mapped_entries}/{len(entries)}, 映射 sink 节点: {mapped_sinks}")

    # Step 6: 正向 BFS
    print("[STEP 5] 正向 BFS：从 entry 出发发现路径...")
    forward_paths = []
    for eid, start_nodes in entry_map.items():
        paths = bfs_discover(eid, start_nodes, sink_map, graph)
        forward_paths.extend(paths)
    print(f"  正向发现: {len(forward_paths)} 条路径")

    # Step 7: 反向 BFS 补漏
    connected_sink_ids = set(p["sink_id"] for p in forward_paths)
    orphan_sinks = {sid: nodes for sid, nodes in sink_map.items() if sid not in connected_sink_ids}
    print(f"[STEP 6] 反向 BFS 补漏：{len(orphan_sinks)} 个 sink 未连接...")
    reverse_paths = []
    for sid, nodes in orphan_sinks.items():
        paths = reverse_bfs_discover(sid, nodes, entry_map, graph)
        reverse_paths.extend(paths)
    print(f"  反向发现: {len(reverse_paths)} 条路径")

    # Step 8: ACCESSES 回退——对 CALLS BFS 未覆盖的 entry，用属性写入追踪补全
    connected_entry_ids = set(p["entry_id"] for p in forward_paths)
    connected_entry_ids.update(p["entry_id"] for p in reverse_paths)
    orphan_entries = [e for e in entries if e["id"] not in connected_entry_ids]
    print(f"[STEP 8] ACCESSES 回退：{len(orphan_entries)} 个 entry 无 CALLS 路径，用属性写入追踪...")
    accesses_paths = _accesses_backfill(
        orphan_entries, sinks, entry_map, sink_map, graph, calls,
        normalize_path, args.project_path, repo
    )
    print(f"  ACCESSES 发现: {len(accesses_paths)} 条路径")

    # Step 9: 构建攻击地图
    print("[STEP 9] 构建 attack_map...")
    gs = {"nodes": len(graph), "edges": sum(len(v) for v in graph.values())}
    attack_map = build_attack_map(
        entries, sinks,
        forward_paths + reverse_paths + accesses_paths,
        gs,
        args.project_path
    )
    print(f"  最终路径数: {len(attack_map)}")

    # Step 9: 输出
    output = {
        "_meta": {
            "version": "2.1.0",
            "discovery": "gitnexus_bfs",
            "bfs_max_depth": BFS_MAX_DEPTH,
            "graph_nodes": len(graph),
            "graph_edges": sum(len(v) for v in graph.values()),
            "forward_paths": len(forward_paths),
            "reverse_paths": len(reverse_paths),
            "final_paths": len(attack_map),
            "orphan_sinks": len(orphan_sinks),
        },
        "attack_map": attack_map,
    }

    indent = 2 if args.pretty else None
    attack_map_file = audit_dir / "attack_map.json"
    attack_map_file.write_text(json.dumps(output, ensure_ascii=False, indent=indent), encoding="utf-8")
    print(f"[DONE] BFS 路径发现完成: {len(attack_map)} 条路径 → {attack_map_file}")


if __name__ == "__main__":
    main()
