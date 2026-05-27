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
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

_SCRIPT_DIR = Path(__file__).resolve().parent


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

    all_paths.sort(key=lambda p: SEVERITY_RANK.get(p.get("severity", "info"), 1), reverse=True)

    # 统计
    by_severity = {}
    by_skill = {}
    for p in all_paths:
        sv = p.get("severity", "info")
        by_severity[sv] = by_severity.get(sv, 0) + 1
        skill = p.get("id", "").split("-")[0] if "-" in p.get("id", "") else "unknown"
        by_skill[skill] = by_skill.get(skill, 0) + 1

    # 风险评分
    risk = 0
    if all_paths:
        total = sum(SEVERITY_WEIGHT.get(p.get("severity", "info"), 0) for p in all_paths)
        max_p = len(all_paths) * 10
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
            "verified_paths": len(all_paths),
        },
        "attack_paths": all_paths,
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
