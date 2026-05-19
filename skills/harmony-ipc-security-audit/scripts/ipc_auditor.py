#!/usr/bin/env python3
"""
HarmonyOS IPC 安全审计器 —— 配置级规则检查。

用法:
    python3 ipc_auditor.py <metadata_json> <project_path> [-o findings.json]

功能:
    1. 读取 Phase 1 输出的项目元数据 JSON
    2. 加载 IPC 安全审计规则 JSON
    3. 执行配置级规则检查（module.json5 的 extensionAbilities 配置）
    4. 输出标准化的 findings.json

说明:
    代码级安全检测由 AI 执行（见 SKILL.md Step 2-3），本脚本仅做 metadata 配置查询。
    每个 config_pattern 规则的 detection.config_check 字段定义了查询方式和条件，
    脚本按字段解释执行，无需逐规则硬编码。
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_COUNTER = [0]


def _next_finding_id() -> str:
    _COUNTER[0] += 1
    return f"HM-IPC-2026-{_COUNTER[0]:04d}"


def _make_finding(
    rule: dict,
    file_path: str = "",
    line_no: int | None = None,
    snippet: str = "",
    extra_desc: str = "",
) -> dict:
    description = rule.get("description", "")
    if extra_desc:
        description = (description + (" " + extra_desc if extra_desc else "")).strip()
    return {
        "id": _next_finding_id(),
        "skill": "harmony-ipc-security-audit",
        "rule_id": rule.get("id", ""),
        "severity": rule.get("severity", "info"),
        "title": rule.get("title", ""),
        "description": description,
        "location": {
            "file": file_path,
            "line": line_no,
            "snippet": snippet,
        },
        "cwe": rule.get("cwe"),
        "owasp": rule.get("owasp"),
        "remediation": rule.get("remediation", ""),
        "reference": rule.get("reference", ""),
    }


def load_rules(rules_dir: Path) -> list[dict]:
    """加载所有规则 JSON 文件，返回扁平的规则列表。"""
    all_rules: list[dict] = []
    for json_file in sorted(rules_dir.glob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "rules" in data:
                all_rules.extend(data["rules"])
        except Exception as e:
            print(f"[WARN] 规则文件 {json_file} 解析失败: {e}", file=sys.stderr)
    return all_rules


def check_config_rules(metadata: dict, rules: list[dict]) -> list[dict]:
    """规则驱动的配置级检查。

    遍历 rules 中所有 type=config_pattern 的规则，读取其 detection.config_check
    字段，在 metadata.modules 中查询 extension_abilities 配置并生成发现。
    """
    findings: list[dict] = []
    modules = metadata.get("modules", [])

    for rule in rules:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            continue
        if detection.get("type") != "config_pattern":
            continue

        config_check = detection.get("config_check", {})
        if not config_check:
            continue

        condition = config_check.get("condition", "")
        scope = config_check.get("scope", "")

        for mod in modules:
            if mod.get("_parse_error"):
                continue

            mod_path = mod.get("module_path", mod.get("_path", mod.get("name", "unknown")))

            items: list[dict] = []
            item_label = "Item"
            if scope == "extension_abilities":
                items = mod.get("extension_abilities", [])
                item_label = "extensionAbility"
            elif scope == "abilities":
                items = mod.get("abilities", [])
                item_label = "ability"

            for item in items:
                item_name = item.get("name", "")

                if condition == "field_missing":
                    field = config_check.get("field", "")
                    if not item.get(field):
                        findings.append(_make_finding(
                            rule, file_path=mod_path,
                            extra_desc=f"{item_label} '{item_name}' 未配置 {field} 字段。",
                        ))

                elif condition == "true_without_guard":
                    field = config_check.get("field", "")
                    guard_fields = config_check.get("guard_fields", [])
                    if item.get(field) is True and not any(item.get(gf) for gf in guard_fields):
                        findings.append(_make_finding(
                            rule, file_path=mod_path,
                            extra_desc=f"{item_label} '{item_name}' {field} 为 true 但未设置任何访问控制。",
                        ))

    return findings


def run_audit(metadata_path: str, project_path: str, rules_dir: str | None = None) -> list[dict]:
    """运行 IPC 安全审计（仅配置级），返回 findings 列表。"""
    if rules_dir is None:
        rules_dir = str(_SCRIPT_DIR / ".." / "rules")

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    rules = load_rules(Path(rules_dir))

    config_findings = check_config_rules(metadata, rules)

    config_findings.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 0), reverse=True)

    return config_findings


def main():
    parser = argparse.ArgumentParser(
        description="HarmonyOS IPC 安全审计器（配置级规则检查）",
    )
    parser.add_argument("metadata_path", help="Phase 1 输出的 metadata JSON 文件路径")
    parser.add_argument("project_path", help="鸿蒙项目根目录路径")
    parser.add_argument("-o", "--output", default=None, help="输出 findings JSON 文件路径")
    parser.add_argument("--rules-dir", default=None, help="规则文件目录")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON 输出")

    args = parser.parse_args()

    if not os.path.exists(args.metadata_path):
        print(f"[ERROR] metadata 文件不存在: {args.metadata_path}", file=sys.stderr)
        sys.exit(1)

    try:
        findings = run_audit(args.metadata_path, args.project_path, args.rules_dir)
    except Exception as e:
        print(f"[ERROR] 审计失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    output = {
        "_meta": {
            "auditor": "harmony-ipc-security-audit",
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "project_path": args.project_path,
            "total_findings": len(findings),
            "severity_counts": {
                sev: sum(1 for f in findings if f.get("severity") == sev)
                for sev in ["critical", "high", "medium", "low", "info"]
            },
            "note": "仅配置级检查。代码级安全分析由 AI 执行。",
        },
        "findings": findings,
    }

    indent = 2 if args.pretty else None
    json_output = json.dumps(output, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_output, encoding="utf-8")
        print(f"[DONE] IPC 配置审计完成，共 {len(findings)} 个发现，输出: {output_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
