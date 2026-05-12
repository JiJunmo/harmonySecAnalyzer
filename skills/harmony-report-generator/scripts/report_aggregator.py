#!/usr/bin/env python3
"""
审计发现聚合器。扫描审计目录中所有 skill 的 findings.json，合并去重，计算统计量。

用法:
    python3 report_aggregator.py <audit_dir> [-o aggregated_data.json]

输入: 审计工作目录（含 metadata.json 和各个 *-findings.json）
输出: aggregated_data.json（供 AI 润色生成报告）
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

_SCRIPT_DIR = Path(__file__).resolve().parent


def find_skill_dirs(root: Path) -> list[str]:
    """扫描 skills/ 目录，发现所有已实现的 skill 名称。"""
    skills_root = root / "skills"
    if not skills_root.exists():
        return []
    result = []
    for d in sorted(skills_root.iterdir()):
        if d.is_dir() and d.name.startswith("harmony-") and (d / "SKILL.md").exists():
            result.append(d.name)
    return result


def merge_findings(audit_dir: Path) -> list[dict]:
    """从审计目录读取所有 *-findings.json，合并、去重、排序。"""
    all_findings: list[dict] = []
    json_files = sorted(audit_dir.glob("*-findings.json"))

    seen: dict[tuple, dict] = {}
    for fpath in json_files:
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        items = data.get("findings", [])
        if isinstance(data, list):
            items = data
        for item in items:
            if not isinstance(item, dict):
                continue
            key = (
                item.get("title", ""),
                item.get("location", {}).get("file", ""),
                item.get("location", {}).get("line"),
            )
            cur_rank = SEVERITY_RANK.get(item.get("severity", "info"), 1)
            if key in seen:
                exist_rank = SEVERITY_RANK.get(seen[key].get("severity", "info"), 1)
                if cur_rank > exist_rank:
                    seen[key] = item
            else:
                seen[key] = item

    all_findings = list(seen.values())
    all_findings.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 1), reverse=True)
    return all_findings


def compute_statistics(findings: list[dict]) -> dict:
    """计算 findings 的统计分布。"""
    by_severity: dict[str, int] = {}
    by_skill: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    by_owasp: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        skill = f.get("skill", "unknown")
        by_skill[skill] = by_skill.get(skill, 0) + 1

        cwe = f.get("cwe")
        if cwe:
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

        owasp = f.get("owasp")
        if owasp:
            by_owasp[owasp] = by_owasp.get(owasp, 0) + 1

    return {
        "by_severity": dict(sorted(by_severity.items(), key=lambda x: SEVERITY_RANK.get(x[0], 0), reverse=True)),
        "by_skill": dict(sorted(by_skill.items(), key=lambda x: x[1], reverse=True)),
        "by_cwe": dict(sorted(by_cwe.items(), key=lambda x: x[1], reverse=True)),
        "by_owasp": dict(sorted(by_owasp.items())),
    }


def compute_risk_score(findings: list[dict]) -> int:
    """计算风险评分 0-100。"""
    if not findings:
        return 0
    total = sum(SEVERITY_WEIGHT.get(f.get("severity", "info"), 0) for f in findings)
    max_possible = len(findings) * 10
    if max_possible == 0:
        return 0
    return min(100, round(total / max_possible * 100))


def aggregate(audit_dir: str, project_root_path: str | None = None) -> dict:
    """执行聚合，返回 aggregated_data 字典。"""
    audit_path = Path(audit_dir)

    if not audit_path.exists():
        raise FileNotFoundError(f"审计目录不存在: {audit_dir}")

    # 读取 metadata
    metadata_path = audit_path / "harmony-project-parser-findings.json"
    meta_fallback = audit_path / "metadata.json"
    metadata: dict = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    elif meta_fallback.exists():
        metadata = json.loads(meta_fallback.read_text(encoding="utf-8"))

    # 合并 findings
    findings = merge_findings(audit_path)
    stats = compute_statistics(findings)
    risk_score = compute_risk_score(findings)

    # 提取项目概览
    project_meta = metadata.get("project", {})
    build_meta = metadata.get("build", {})
    security_surface = metadata.get("security_surface", {})

    # 发现已执行和待实现的 skill
    project_root = project_root_path or str(_SCRIPT_DIR.parent.parent.parent)
    all_skills = find_skill_dirs(Path(project_root))
    executed_skills: list[str] = []
    for fpath in audit_path.glob("*-findings.json"):
        name = fpath.stem.replace("-findings", "")
        if name.startswith("harmony-"):
            executed_skills.append(name)

    # parser skill 已执行但 audit_skills 中排除
    audit_skills = [s for s in all_skills if s not in ("harmony-project-parser", "harmony-report-generator")]
    executed_audit = [s for s in audit_skills if s in executed_skills]
    pending_audit = [s for s in audit_skills if s not in executed_skills]

    return {
        "project": {
            "name": project_meta.get("name", ""),
            "version": project_meta.get("version", ""),
            "package_name": project_meta.get("package_name", ""),
            "sdk_version": build_meta.get("compile_sdk_version", ""),
            "api_level": build_meta.get("compile_sdk_api"),
            "build_mode": build_meta.get("build_mode", ""),
            "module_count": len(metadata.get("modules", [])),
            "total_ets_files": metadata.get("files", {}).get("total_ets_files", 0),
            "total_lines": metadata.get("files", {}).get("total_lines", 0),
        },
        "security_surface": {
            "total_permissions": security_surface.get("total_permissions", 0),
            "high_risk_permissions": security_surface.get("total_high_risk_permissions", 0),
            "exported_abilities": security_surface.get("exported_abilities_count", 0),
            "exported_extensions": security_surface.get("exported_extensions_count", 0),
            "has_ipc_service": security_surface.get("has_ipc_service", False),
            "has_webview": security_surface.get("has_webview", False),
            "has_database": security_surface.get("has_database", False),
            "has_distributed": security_surface.get("has_distributed", False),
            "has_napi": security_surface.get("has_napi", False),
        },
        "audit": {
            "time": datetime.now(timezone.utc).isoformat(),
            "skills_executed": executed_skills,
            "skills_pending": pending_audit,
        },
        "findings": {
            "total": len(findings),
            **stats,
        },
        "risk_score": risk_score,
        "items": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="审计发现聚合器")
    parser.add_argument("audit_dir", help="审计工作目录路径")
    parser.add_argument("-o", "--output", default=None, help="输出 aggregated_data.json 路径")
    parser.add_argument("--project-root", default=None, help="项目根目录（用于发现 skill 列表）")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON 输出")

    args = parser.parse_args()

    try:
        data = aggregate(args.audit_dir, args.project_root)
    except Exception as e:
        print(f"[ERROR] 聚合失败: {e}", file=sys.stderr)
        sys.exit(1)

    indent = 2 if args.pretty else None
    json_output = json.dumps(data, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_output, encoding="utf-8")
        print(f"[DONE] 聚合完成，共 {data['findings']['total']} 个发现，输出: {out_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
