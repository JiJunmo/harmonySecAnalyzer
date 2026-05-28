#!/usr/bin/env python3
"""
v2 攻击路径聚合器。扫描审计目录中所有 skill 的 attack-paths.json，合并统计。

用法:
    python report_aggregator.py <audit_dir> [-o aggregated_data.json]

输入: 审计工作目录（含 entries.json, sinks.json, attack_map.json, *-attack-paths.json）
输出: aggregated_data.json
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

_SCRIPT_DIR = Path(__file__).resolve().parent


import hashlib

def compute_fingerprint(p: dict) -> str:
    """计算漏洞的唯一性指纹。"""
    # 提取 rule_id
    matched_rules = p.get("matched_rules", [])
    rule_id = matched_rules[0] if matched_rules else ""
    if not rule_id:
        rule_id = p.get("id", "").split("-")[0]
    
    # 提取 sink_file & sink_signature
    flow = p.get("flow", [])
    sink_file = ""
    sink_signature = ""
    if flow:
        sink_step = flow[-1]
        sink_file = sink_step.get("file", "")
        snippet = sink_step.get("snippet", "")
        # 去除注释和空白字符
        snippet_no_comments = re.sub(r'//.*|/\*[\s\S]*?\*/', '', snippet)
        sink_signature = re.sub(r'\s+', '', snippet_no_comments)
    else:
        evidence = p.get("evidence", [])
        if evidence:
            ev = evidence[0]
            sink_file = ev.get("file", "")
            snippet = ev.get("snippet", "")
            snippet_no_comments = re.sub(r'//.*|/\*[\s\S]*?\*/', '', snippet)
            sink_signature = re.sub(r'\s+', '', snippet_no_comments)

    fp_string = f"{rule_id}@{sink_file}@{sink_signature}"
    return hashlib.md5(fp_string.encode("utf-8")).hexdigest()


def aggregate(audit_dir: str) -> dict:
    audit_path = Path(audit_dir)
    if not audit_path.exists():
        raise FileNotFoundError(f"审计目录不存在: {audit_dir}")

    # 读取所有 attack-paths 分片（匹配 *-attack-paths*.json）
    all_paths = []
    processed_files_count = 0
    for fpath in sorted(audit_path.glob("*-attack-paths*.json")):
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            all_paths.extend(data.get("attack_paths", []))
            processed_files_count += 1
        except (json.JSONDecodeError, OSError):
            pass

    # 对所有路径按指纹归并
    groups = defaultdict(list)
    for p in all_paths:
        fp = compute_fingerprint(p)
        groups[fp].append(p)

    merged_paths = []
    for fp, paths in groups.items():
        if not paths:
            continue
        # 以第一个作为主路径模板
        primary = dict(paths[0])
        
        # 提取并合并所有入口路径与 Flow
        entry_paths = []
        seen_entry_keys = set()
        for idx, path in enumerate(paths):
            entry = path.get("entry")
            # 针对没有顶层 entry 的 IPC 服务等适配生成结构化 entry
            if not entry:
                if "input" in path:
                    entry = {
                        "type": "ipc_message",
                        "file": path.get("flow", [{}])[0].get("file", "") if path.get("flow") else "",
                        "how": "发送特定的 IPC 消息请求",
                        "payload": {
                            "code": path["input"].get("code"),
                            "snippet": path["input"].get("snippet")
                        }
                    }
                else:
                    entry = {
                        "type": "unknown",
                        "file": path.get("flow", [{}])[0].get("file", "") if path.get("flow") else "",
                        "how": "外部输入传导"
                    }
            
            entry_key = f"{entry.get('type')}@{entry.get('file')}@{entry.get('how')}"
            if entry_key in seen_entry_keys:
                continue
            seen_entry_keys.add(entry_key)

            entry_paths.append({
                "path_id": path.get("id"),
                "entry": entry,
                "flow": path.get("flow", [])
            })

        primary["entry_paths"] = entry_paths

        # 清理原顶层的单例 entry 和 flow
        if "entry" in primary:
            del primary["entry"]
        if "flow" in primary:
            del primary["flow"]

        # 严重度提升：保留同一漏洞中最高的严重级别
        max_severity = "info"
        for path in paths:
            sev = path.get("severity", "info").lower()
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity.lower(), 0):
                max_severity = sev
        primary["severity"] = max_severity

        # 漏洞 ID 重构：如果归并了多条路径，给予 VULN 前缀以区分
        if len(paths) > 1:
            primary["id"] = f"VULN-{primary['id']}"

        merged_paths.append(primary)

    # 排序
    merged_paths.sort(key=lambda p: SEVERITY_RANK.get(p.get("severity", "info"), 1), reverse=True)

    # 统计唯一漏洞数
    by_severity = {}
    by_skill = {}
    for p in merged_paths:
        sv = p.get("severity", "info")
        by_severity[sv] = by_severity.get(sv, 0) + 1
        skill = p.get("id", "").split("-")[0] if "-" in p.get("id", "") else "unknown"
        # 移除可能带有 VULN- 前缀的情况
        if skill.startswith("VULN"):
            skill = p.get("id", "").split("-")[1] if len(p.get("id", "").split("-")) > 1 else "unknown"
        by_skill[skill] = by_skill.get(skill, 0) + 1

    # 风险评分（基于去重后的唯一漏洞）
    risk = 0
    if merged_paths:
        total = sum(SEVERITY_WEIGHT.get(p.get("severity", "info"), 0) for p in merged_paths)
        max_p = len(merged_paths) * 10
        risk = min(100, round(total / max_p * 100)) if max_p else 0


    # 计数校验：动态计算预期任务文件数（防断流/剪枝误报）
    warnings = []
    expected_files = 0
    entries_path = audit_path / "entries.json"
    if entries_path.exists():
        try:
            entries_data = json.loads(entries_path.read_text(encoding="utf-8"))
            entries = entries_data.get("entries", [])
            ipc_count = sum(1 for e in entries if e.get("type") == "ipc_service")
            ability_count = sum(1 for e in entries if e.get("type") == "exported_ability")
            
            # 计算批次数量 (向上取整，每 5 个一批)
            expected_ipc_batches = (ipc_count + 4) // 5
            expected_ability_batches = (ability_count + 4) // 5
            
            # 统计实际生成的 warm-start 文件数以获取触发的 WebView 任务预期批次数
            warm_start_count = len(list(audit_path.glob("harmony-webview-warm-start-*.json")))
            expected_webview_batches = (warm_start_count + 4) // 5
            
            expected_files = expected_ipc_batches + expected_ability_batches + expected_webview_batches
        except Exception:
            pass

    if expected_files > 0 and processed_files_count < expected_files:
        warnings.append(
            f"预期完成 {expected_files} 个批次任务文件，实际完成 {processed_files_count} 个，可能存在漏分析"
        )

    # 读取项目概览
    entries_count = 0
    sinks_count = 0
    for fname in ["entries.json", "sinks.json"]:
        fp = audit_path / fname
        if fp.exists():
            try:
                d = json.loads(fp.read_text(encoding="utf-8"))
                if fname == "entries.json":
                    entries_count = d.get("_meta", {}).get("count", 0)
                else:
                    sinks_count = d.get("_meta", {}).get("count", 0)
            except (json.JSONDecodeError, OSError):
                pass

    return {
        "project": {
            "entries_count": entries_count,
            "sinks_count": sinks_count,
            "verified_paths": len(merged_paths),
        },
        "attack_paths": merged_paths,
        "statistics": {
            "by_severity": dict(sorted(by_severity.items(), key=lambda x: SEVERITY_RANK.get(x[0], 0), reverse=True)),
            "by_skill": dict(sorted(by_skill.items(), key=lambda x: x[1], reverse=True)),
        },
        "risk_score": risk,
        "warnings": warnings,
        "audit_time": datetime.now(timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="v2 攻击路径聚合器")
    parser.add_argument("audit_dir", help="审计工作目录路径")
    parser.add_argument("-o", "--output", default=None, help="输出路径")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON")
    args = parser.parse_args()

    try:
        data = aggregate(args.audit_dir)
    except Exception as e:
        print(f"[ERROR] 聚合失败: {e}", file=sys.stderr)
        sys.exit(1)

    indent = 2 if args.pretty else None
    out = json.dumps(data, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        p = Path(args.output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(out, encoding="utf-8")
        print(f"[DONE] v2 聚合完成，共 {len(data['attack_paths'])} 条攻击路径，输出: {p}")
    else:
        print(out)


if __name__ == "__main__":
    main()
