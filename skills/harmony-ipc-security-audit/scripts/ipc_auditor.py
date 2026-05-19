#!/usr/bin/env python3
"""
HarmonyOS IPC 安全审计器 —— 配置级规则检查 + 实例发现。

用法:
    # 配置级审计
    python ipc_auditor.py <metadata_json> <project_path> [-o findings.json]

    # 列出所有 IPC 实例（供 agent.md Phase 2 按实例派发 Task）
    python ipc_auditor.py --list-instances <metadata_json> <project_path> [-o instances.json]

功能:
    1. 读取 Phase 1 输出的项目元数据 JSON
    2. 加载 IPC 安全审计规则 JSON
    3. 执行配置级规则检查（module.json5 的 extensionAbilities 配置）
    4. --list-instances: 列出所有 IPC 服务实例 + 预填 Layer 1 骨架
    5. 输出标准化的 findings.json / instances.json

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


def list_instances(metadata_path: str, project_path: str) -> list[dict]:
    """
    列出所有 IPC 服务实例并预填 Layer 1（服务注册层）骨架。

    返回的每个实例包含 instance_id、name、module、exported、src_entry、
    以及 skeleton（含 call_chain 的 id、service_name、module 和 Layer 1 预填分析）。
    """
    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    instances: list[dict] = []
    chain_counter = 0

    modules = metadata.get("modules", [])
    for mod in modules:
        if mod.get("_parse_error"):
            continue
        mod_name = mod.get("name", "")
        mod_path = mod.get("module_path", mod.get("_path", ""))

        for ext in mod.get("extension_abilities", []):
            ext_type = ext.get("type", "")
            if ext_type != "service":
                continue
            if not ext.get("src_entry"):
                continue

            chain_counter += 1
            ext_name = ext.get("name", "")
            exported = ext.get("exported", False)
            permissions = ext.get("permissions", [])
            src_entry = ext.get("src_entry", "")
            description = ext.get("description", "")

            # 预填 Layer 1 分析
            issues = []
            if exported:
                issues.append("exported: true — 组件对外导出，增加攻击面")
                if not permissions:
                    issues.append("缺少 permissions 权限守卫")

            analysis_text = (
                f"extensionAbility '{ext_name}' 注册在模块 {mod_name} 的 module.json5 中。"
                f"type: {ext_type}, exported: {exported}, permissions: {permissions or '无'}, "
                f"description: '{description}', srcEntry: {src_entry}。"
            )
            if exported and not permissions:
                analysis_text += " 该服务被导出 (exported: true) 但未配置 permissions，任意应用均可连接。"

            skeleton = {
                "id": f"chain-{chain_counter:03d}",
                "service_name": ext_name,
                "module": mod_name,
                "extension_type": ext_type,
                "overview": f"{ext_name} 是 {mod_name} 模块的 IPC 服务入口",
                "layers": [
                    {
                        "layer": "1-服务注册层",
                        "order": 1,
                        "file": mod_path if mod_path else f"{mod_name}/src/main/module.json5",
                        "analysis": analysis_text,
                        "code_references": [
                            {
                                "file": mod_path if mod_path else f"{mod_name}/src/main/module.json5",
                                "line_range": "",
                                "snippet": json.dumps(ext, ensure_ascii=False, indent=2),
                                "description": f"{ext_name} 的 extensionAbility 配置"
                            }
                        ],
                        "issues_identified": issues,
                        "_source": "script"
                    }
                ]
            }

            instances.append({
                "instance_id": f"ipc-{chain_counter:03d}",
                "name": ext_name,
                "module": mod_name,
                "exported": exported,
                "src_entry": src_entry,
                "permissions": permissions,
                "skeleton": skeleton,
            })

    return instances


def main():
    parser = argparse.ArgumentParser(
        description="HarmonyOS IPC 安全审计器（配置级规则检查 + 实例发现）",
    )
    parser.add_argument("metadata_path", help="Phase 1 输出的 metadata JSON 文件路径")
    parser.add_argument("project_path", help="鸿蒙项目根目录路径")
    parser.add_argument("-o", "--output", default=None, help="输出文件路径")
    parser.add_argument("--rules-dir", default=None, help="规则文件目录")
    parser.add_argument("--list-instances", action="store_true", help="列出所有 IPC 服务实例并预填 Layer 1 骨架")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON 输出")

    args = parser.parse_args()

    if not os.path.exists(args.metadata_path):
        print(f"[ERROR] metadata 文件不存在: {args.metadata_path}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.list_instances:
            # 实例发现模式
            instances = list_instances(args.metadata_path, args.project_path)
            output = {
                "_meta": {
                    "auditor": "harmony-ipc-security-audit",
                    "scan_time": datetime.now(timezone.utc).isoformat(),
                    "project_path": args.project_path,
                    "total_instances": len(instances),
                    "note": "IPC 服务实例列表，每个实例含 Layer 1 预填骨架。代码级深度分析由 AI 执行。",
                },
                "instances": instances,
            }
        else:
            # 审计模式
            findings = run_audit(args.metadata_path, args.project_path, args.rules_dir)
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
    except Exception as e:
        print(f"[ERROR] 审计失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    indent = 2 if args.pretty else None
    json_output = json.dumps(output, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_output, encoding="utf-8")
        mode = "实例发现" if args.list_instances else "配置审计"
        print(f"[DONE] IPC {mode}完成，共 {len(output.get('instances', output.get('findings', [])))} 个{'实例' if args.list_instances else '发现'}，输出: {output_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
