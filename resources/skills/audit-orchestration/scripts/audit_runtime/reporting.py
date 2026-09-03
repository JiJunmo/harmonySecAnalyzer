"""Deterministic exports and reports derived exclusively from SQLite state."""
from __future__ import annotations

import hashlib
import html
import json
from collections import Counter

from .common import *
from .store import database
from .task_context import entry_context, group_context, semantic_group_context, validation_context


def _rows(conn, query, params=()):
    return [dict(row) for row in conn.execute(query, params)]


def _decode(row, *fields):
    value = dict(row)
    for field in fields:
        key = field + "_json"
        if key in value:
            value[field] = json.loads(value.pop(key))
    return value


CLASSIFICATION_RANK = {
    "confirmed_vulnerability": 0, "residual_risk": 1, "insufficient_evidence": 2,
    "protected_exposure": 3, "no_exploitable_path": 4, "benign_business_flow": 5,
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RESULT_LABELS = {
    "confirmed_vulnerability": "已确认漏洞", "residual_risk": "残余风险",
    "insufficient_evidence": "证据不足", "protected_exposure": "已有有效防护",
    "benign_business_flow": "正常业务行为", "verification_incomplete": "验证未完成",
    "no_exploitable_path": "未形成可利用路径", "no_security_relevant_operation": "未发现安全相关操作",
    "generated_unverified": "已生成，未编译验证", "build_verified": "已通过编译验证",
    "device_verified": "已通过设备验证", "generation_failed": "生成失败",
    "pending_generation": "生成中",
    "entry_excluded": "组件输入已排除", "entry_uncertain": "组件输入状态不确定",
    "external_entry_excluded": "未确认外部入口", "not_analyzed": "未完成分析",
    "pending": "等待探索", "running": "探索中", "complete": "探索完成", "partial": "部分完成",
    "queued": "待分析", "leased": "分析中", "completed": "已分析",
    "stopped": "已停止", "gap": "覆盖缺口",
    "confirmed": "已确认", "excluded": "已排除", "uncertain": "不确定",
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示",
    "injection": "注入", "filesystem": "文件系统", "web": "Web 安全",
    "icc": "组件通信", "provider": "数据提供", "ipc_rpc": "IPC/RPC",
    "archive": "压缩包", "privacy": "隐私", "network": "网络",
    "crypto": "密码学", "distributed": "分布式",
    "native_dependency": "Native 与依赖",
    "not_externally_reachable": "外部不可达",
}


def _label(value):
    return RESULT_LABELS.get(value, value or "-")


def finding_sort_key(row):
    return (
        CLASSIFICATION_RANK.get(row.get("classification"), 99),
        SEVERITY_RANK.get(row.get("severity"), 99),
        row.get("title") or "",
    )


def _finding_row(raw):
    row = _decode(raw, "controlled_properties", "evidence", "payload")
    row["path_id"] = row["group_id"]
    row["controlled_property"] = ",".join(row["controlled_properties"])
    row["payload"]["related_path_ids"] = row["payload"].get("related_group_ids", [row["group_id"]])
    row["payload"]["conclusion"] = row.get("impact") or row["payload"].get("demotion_reason", "")
    return row


def _entry_row(raw):
    row = _decode(raw, "facets", "profiles", "payload")
    payload = row.get("payload", {})
    for key in ("module", "module_id", "module_root", "component_id"):
        row[key] = payload.get(key)
    return row


def _evidence_path(group, entry, finding_ids):
    """Paths are report-only evidence chains for actionable groups."""
    branches = group.get("branches", [])
    return {
        "path_id": group["group_id"], "group_id": group["group_id"], "root_entry_id": group["entry_id"],
        "status": group["classification"], "branch_key": " | ".join(row["condition"] for row in branches),
        "controlled_properties": group["controlled_properties"],
        "controlled_property": ",".join(group["controlled_properties"]),
        "current_symbol": group["operation_location"], "facts": group.get("facts", []),
        "edges": group.get("edges", []), "segments": [], "assessments": [group],
        "finding_ids": finding_ids, "entry": entry,
    }


def _dedupe_records(rows):
    unique = {}
    for row in rows:
        if not row:
            continue
        key = canonical_json({
            name: row.get(name) for name in (
                "type", "location", "protects", "subject_kind", "validated_property", "behavior",
            )
        })
        unique.setdefault(key, row)
    return list(unique.values())


def _component_result_status(analysis, coverage, groups):
    if not analysis:
        return "not_analyzed"
    entry_status = coverage.get("entry_status", "uncertain")
    classifications = {row.get("classification") for row in groups if row.get("classification")}
    for status in (
        "confirmed_vulnerability", "residual_risk", "insufficient_evidence",
        "protected_exposure", "no_exploitable_path", "benign_business_flow",
    ):
        if status in classifications:
            return status
    if entry_status == "excluded":
        return "entry_excluded"
    if coverage.get("external_entry_status") == "excluded":
        return "external_entry_excluded"
    if groups and any(
        not row.get("classification")
        and (coverage.get("external_entry_status") == "confirmed" or row.get("validation_required"))
        for row in groups
    ):
        return "verification_incomplete"
    if entry_status == "uncertain":
        return "entry_uncertain"
    return "no_security_relevant_operation"


def _exploration_graph(conn):
    components = []
    all_nodes = []
    all_edges = []
    for exploration in conn.execute(
        "SELECT * FROM component_explorations ORDER BY entry_id"
    ):
        nodes = []
        for raw in conn.execute(
            """SELECT * FROM exploration_nodes WHERE exploration_id=?
               ORDER BY depth,discovered_order,node_id""", (exploration["exploration_id"],),
        ):
            observation = json.loads(raw["observation_json"] or "{}")
            analyzed_symbols = observation.get("analyzed_symbols", [])
            resolved_relations = observation.get("resolved_relations", [])
            node = {
                "node_id": raw["node_id"], "parent_node_id": raw["parent_node_id"],
                "work_type": raw["work_type"], "symbol": json.loads(raw["symbol_json"]),
                "security_state": json.loads(raw["state_json"]), "depth": raw["depth"],
                "order": raw["discovered_order"], "status": raw["status"],
                "stop_reason": raw["stop_reason"], "summary": observation.get("summary"),
                "operation_groups": len(observation.get("operation_groups", [])),
                "component_calls": len(observation.get("component_calls", [])),
                "analyzed_symbols": analyzed_symbols,
                "analyzed_symbol_count": len(analyzed_symbols),
                "resolved_relations": resolved_relations,
                "source_resolved_relation_count": sum(
                    row.get("resolved_by") == "source_evidence"
                    for row in resolved_relations
                ),
                "gaps": observation.get("gaps", []),
            }
            nodes.append(node)
            all_nodes.append({"exploration_id": exploration["exploration_id"], **node})
        edges = []
        for raw in conn.execute(
            """SELECT * FROM exploration_edges WHERE exploration_id=?
               ORDER BY created_at,edge_id""", (exploration["exploration_id"],),
        ):
            edge = {
                "edge_id": raw["edge_id"], "source_node_id": raw["source_node_id"],
                "target_node_id": raw["target_node_id"], "relation": raw["relation"],
                "decision": raw["decision"], "condition": raw["condition"],
            }
            edges.append(edge)
            all_edges.append({"exploration_id": exploration["exploration_id"], **edge})
        counts = dict(Counter(node["status"] for node in nodes))
        components.append({
            "exploration_id": exploration["exploration_id"], "entry_id": exploration["entry_id"],
            "status": exploration["status"], "entry_status": exploration["entry_status"],
            "external_entry_status": exploration["external_entry_status"],
            "component_summary": exploration["component_summary"],
            "rounds": exploration["round_no"], "node_counts": counts,
            "nodes": nodes, "edges": edges,
        })
    return {"components": components, "nodes": all_nodes, "edges": all_edges}


def _component_results(entries, analyses, semantic_groups, groups, component_calls, explorations):
    analyses_by_entry = {row["entry_id"]: row for row in analyses}
    combined_by_group = {row["group_id"]: row for row in groups}
    results = []
    for entry in entries:
        analysis = analyses_by_entry.get(entry["entry_id"])
        exploration = explorations.get(entry["entry_id"], {})
        coverage = analysis.get("coverage", {}) if analysis else {}
        component_id = entry.get("component_id")
        related_groups = []
        for semantic in semantic_groups:
            chain = semantic.get("component_chain", [])
            if semantic.get("entry_id") != entry["entry_id"] and component_id not in chain:
                continue
            related_groups.append(combined_by_group.get(semantic["group_id"], semantic))
        related_groups = list({row["group_id"]: row for row in related_groups}.values())
        outgoing = [row for row in component_calls if row["source_entry_id"] == entry["entry_id"]]
        incoming = [row for row in component_calls if component_id and row["target_component_id"] == component_id]
        security_checks = _dedupe_records([
            check for group in related_groups for check in group.get("security_checks", [])
        ] + [
            check for call in outgoing + incoming for check in call.get("security_checks", [])
        ])
        status = _component_result_status(analysis, coverage, related_groups)
        review_notes = []
        if not analysis:
            if exploration:
                review_notes.append(
                    f"组件语义探索状态：{_label(exploration.get('status'))}；"
                    f"已执行 {exploration.get('rounds', 0)} 轮。"
                )
            review_notes.append("组件语义分析未完成，不能据此判断组件是否安全。")
        if coverage.get("entry_status") == "uncertain":
            review_notes.append("真实入口状态仍不确定，需要人工核对触发方式和回调实现。")
        if coverage.get("external_entry_status") == "uncertain":
            review_notes.append("外部入口状态仍不确定，本次不会把该组件作为攻击路径起点。")
        if coverage.get("unresolved_targets"):
            review_notes.append("存在未解析的调用目标，可能影响跨组件覆盖完整性。")
        if analysis and not related_groups:
            review_notes.append("未识别到安全相关操作，建议结合组件功能和已检查符号复核是否遗漏敏感行为。")
        if security_checks:
            review_notes.append("已观察到防护代码，需核对其约束主体、受控属性和生效路径是否与安全边界一致。")
        if status in {"protected_exposure", "no_exploitable_path", "benign_business_flow"}:
            review_notes.append("当前证据未形成漏洞结论；该结果表示已检查范围内未发现可利用问题，不等同于形式化安全证明。")
        if status == "verification_incomplete":
            review_notes.append("已识别到安全相关操作，正在等待六维有效性验证，当前不能判定是否存在漏洞。")
        results.append({
            "entry_id": entry["entry_id"], "component_id": component_id,
            "component": entry.get("component"), "module": entry.get("module"),
            "module_id": entry.get("module_id"), "module_root": entry.get("module_root"),
            "symbol": entry.get("symbol"), "external_reachability": entry.get("reachability"),
            "facets": entry.get("facets", []), "profiles": entry.get("profiles", []),
            "status": status, "status_label": _label(status),
            "function_summary": (analysis.get("summary") if analysis else
                                 exploration.get("component_summary") or "组件语义分析未完成"),
            "coverage": coverage, "operation_groups": related_groups,
            "security_checks": security_checks, "outgoing_calls": outgoing, "incoming_calls": incoming,
            "review_notes": review_notes, "exploration": exploration,
        })
    return results


def export_state(run_dir):
    run_paths = ensure_run_dirs(run_dir)
    with database(run_paths["db"]) as conn:
        entries = [_entry_row(row) for row in _rows(conn, "SELECT * FROM entries ORDER BY entry_key")]
        analyses = [_decode(row, "coverage") for row in _rows(conn, "SELECT * FROM semantic_analyses ORDER BY entry_id")]
        component_calls = [_decode(row, "parameter_mappings", "security_checks", "evidence", "payload") for row in _rows(
            conn, "SELECT * FROM component_calls ORDER BY source_entry_id,call_id"
        )]
        group_ids = [row["group_id"] for row in _rows(conn, "SELECT group_id FROM operation_groups ORDER BY entry_id,group_id")]
        semantic_groups = [semantic_group_context(conn, group_id) for group_id in group_ids]
        validations = [value for group_id in group_ids if (value := validation_context(conn, group_id))]
        groups = [group_context(conn, group_id) for group_id in group_ids if validation_context(conn, group_id)]
        findings = [_finding_row(row) for row in _rows(conn, "SELECT * FROM findings ORDER BY classification,severity,finding_id")]
        tasks = [_decode(row, "input") for row in _rows(conn, "SELECT task_id,semantic_key,kind,subject_id,status,agent,input_json,attempts,error,created_at,updated_at FROM tasks ORDER BY created_at,task_id")]
        exploration_graph = _exploration_graph(conn)
    finding_by_group = {}
    for finding in findings:
        for group_id in finding["payload"].get("related_group_ids", [finding["group_id"]]):
            finding_by_group.setdefault(group_id, []).append(finding["finding_id"])
    evidence_paths = [
        _evidence_path(group, next((entry for entry in entries if entry["entry_id"] == group["entry_id"]), None),
                       finding_by_group.get(group["group_id"], []))
        for group in groups if group["classification"] in {"confirmed_vulnerability", "residual_risk"}
    ]
    attack_matrix = [{
        "entry_id": group["entry_id"], "group_id": group["group_id"], "operation": group["operation_location"],
        "controlled_properties": group["controlled_properties"], "security_check_outcome": group["security_check_outcome"],
        "boundary": group["boundary"], "classification": group["classification"],
        "finding_ids": finding_by_group.get(group["group_id"], []),
    } for group in groups]
    component_graph = {
        "nodes": [{
            key: entry.get(key) for key in (
                "entry_id", "component_id", "component", "module", "module_id", "module_root",
            )
        } for entry in entries],
        "edges": [{
            "call_id": row["call_id"], "source_entry_id": row["source_entry_id"],
            "source_component_id": row["source_component_id"],
            "target_component_id": row["target_component_id"], "transport": row["transport"],
            "call_location": row["call_location"], "parameter_mappings": row["parameter_mappings"],
            "principal_transition": row["payload"].get("principal_transition", {}),
        } for row in component_calls],
    }
    artifacts = {"entries.json": entries, "semantic_analyses.json": analyses,
                 "component_calls.json": component_calls, "component_graph.json": component_graph,
                 "operation_groups.json": semantic_groups, "validation_results.json": validations,
                 "exploration_graph.json": exploration_graph,
                 "evidence_paths.json": evidence_paths,
                 "attack_matrix.json": attack_matrix, "tasks.json": tasks}
    for name, value in artifacts.items():
        write_json(run_paths["exports"] / name, {"schema_version": 1, "items": value})
    write_json(run_paths["findings"], {"schema_version": 1, "findings": findings})
    return {"ok": True, "exports": {name: str(run_paths["exports"] / name) for name in artifacts}, "findings": str(run_paths["findings"])}


def build_report(run_dir, live=False, report_status=None):
    run_paths = ensure_run_dirs(run_dir)
    change_set = read_json(run_paths["change_set"], {})
    impact_plan = read_json(run_paths["impact_plan"], {})
    baseline_findings = read_json(run_paths["baseline_findings"], {"items": []}).get("items", [])
    if not live:
        export_state(run_dir)
    with database(run_paths["db"]) as conn:
        run = dict(conn.execute("SELECT * FROM runs LIMIT 1").fetchone())
        correlation = json.loads(run.get("correlation_json") or "{}")
        project = read_json(run_paths["project_model"], {})
        entries = [_entry_row(row) for row in _rows(
            conn, "SELECT entry_id,entry_key,component,symbol,facets_json,profiles_json,payload_json,reachability FROM entries ORDER BY entry_key"
        )]
        fact_count = conn.execute("SELECT COUNT(*) n FROM group_facts").fetchone()["n"]
        group_ids = [row["group_id"] for row in _rows(conn, "SELECT group_id FROM operation_groups ORDER BY entry_id,group_id")]
        semantic_groups = [semantic_group_context(conn, group_id) for group_id in group_ids]
        groups = [group_context(conn, group_id) for group_id in group_ids if validation_context(conn, group_id)]
        analyses = [_decode(row, "coverage") for row in _rows(conn, "SELECT * FROM semantic_analyses ORDER BY entry_id")]
        component_calls = [_decode(row, "parameter_mappings", "security_checks", "evidence", "payload") for row in _rows(
            conn, "SELECT * FROM component_calls ORDER BY source_entry_id,call_id"
        )]
        findings = [_finding_row(row) for row in _rows(conn, "SELECT * FROM findings")]
        poc_rows = [dict(row) for row in conn.execute(
            "SELECT poc_id,finding_id,entry_type,payload_json FROM poc_artifacts ORDER BY poc_id"
        )]
        poc_by_finding = {}
        for row in poc_rows:
            row["payload"] = json.loads(row.pop("payload_json"))
            poc_by_finding.setdefault(row["finding_id"], row)
        tasks = _rows(conn, "SELECT task_id,kind,subject_id,status,attempts,error FROM tasks ORDER BY created_at,task_id")
        task_counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
        exploration_graph = _exploration_graph(conn)
        exploration_symbols = {
            symbol
            for node in exploration_graph["nodes"]
            for symbol in (
                [node.get("symbol", {}).get("qualified_name")]
                + [row.get("qualified_name") for row in node.get("analyzed_symbols", [])]
            )
            if symbol and symbol != "$entry_discovery"
        }
        source_resolved_relations = sum(
            node.get("source_resolved_relation_count", 0)
            for node in exploration_graph["nodes"]
        )
        poc_tasks = {row["subject_id"]: row for row in tasks if row["kind"] == "poc_generation"}
        for finding in findings:
            artifact = poc_by_finding.get(finding["finding_id"])
            task = poc_tasks.get(finding["finding_id"])
            finding["poc_artifact"] = artifact
            if artifact:
                finding["poc_status"] = artifact["payload"].get("assurance_status", "generated_unverified")
            elif task and task["status"] == "exhausted":
                finding["poc_status"] = "generation_failed"
            else:
                finding["poc_status"] = "pending_generation"
    classification_counts = Counter(row["classification"] for row in groups)
    entry_status_counts = Counter(row["coverage"].get("entry_status", "uncertain") for row in analyses)
    external_entry_status_counts = Counter(
        row["coverage"].get("external_entry_status", "uncertain") for row in analyses
    )
    finding_classification_counts = Counter(row["classification"] for row in findings)
    findings.sort(key=finding_sort_key)
    finding_changes = {"status": "not_applicable", "added": [], "removed": [], "changed": [], "unchanged": []}
    comparison_ready = (
        run["audit_mode"] == "incremental" and run.get("correlation_status") == "complete"
        and not task_counts.get("queued", 0) and not task_counts.get("running", 0)
    )
    if run["audit_mode"] == "incremental" and not comparison_ready:
        finding_changes["status"] = "pending"
    elif comparison_ready:
        finding_changes["status"] = "complete"
        previous_by_id = {row.get("finding_id"): row for row in baseline_findings if row.get("finding_id")}
        current_by_id = {row.get("finding_id"): row for row in findings if row.get("finding_id")}
        comparison_keys = ("classification", "title", "severity", "cwe", "impact", "boundary", "operation_location")
        for finding_id in sorted(set(current_by_id) - set(previous_by_id)):
            finding_changes["added"].append(current_by_id[finding_id])
        for finding_id in sorted(set(previous_by_id) - set(current_by_id)):
            finding_changes["removed"].append(previous_by_id[finding_id])
        for finding_id in sorted(set(previous_by_id) & set(current_by_id)):
            previous = {key: previous_by_id[finding_id].get(key) for key in comparison_keys}
            current = {key: current_by_id[finding_id].get(key) for key in comparison_keys}
            target = "unchanged" if previous == current else "changed"
            finding_changes[target].append(current_by_id[finding_id])
    actionable_findings = len(findings)
    entry_by_id = {row["entry_id"]: row for row in entries}
    finding_by_group = {}
    for finding in findings:
        for group_id in finding["payload"].get("related_group_ids", [finding["group_id"]]):
            finding_by_group.setdefault(group_id, []).append(finding["finding_id"])
    evidence_paths = [_evidence_path(group, entry_by_id.get(group["entry_id"]), finding_by_group.get(group["group_id"], []))
                      for group in groups if group["classification"] in {"confirmed_vulnerability", "residual_risk"}]
    explorations_by_entry = {
        row["entry_id"]: row for row in exploration_graph["components"]
    }
    component_results = _component_results(
        entries, analyses, semantic_groups, groups, component_calls, explorations_by_entry,
    )
    component_result_counts = Counter(row["status"] for row in component_results)
    gaps = []
    for row in project.get("diagnostics", []):
        gaps.append({"type": "项目解析", "subject": row.get("file") or "project", "description": row.get("message") or str(row)})
    for group in groups:
        for fact in group["facts"]:
            if fact.get("type") == "gap":
                gaps.append({"type": "证据链", "subject": group["group_id"], "description": fact["body"]})
        if group["classification"] == "insufficient_evidence":
            gaps.append({"type": "安全判定", "subject": group["group_id"], "description": group.get("evidence_gap") or group.get("demotion_reason")})
    for analysis in analyses:
        if analysis["coverage"].get("entry_status") == "uncertain":
            gaps.append({"type": "组件输入确认", "subject": analysis["entry_id"],
                         "description": "; ".join(analysis["coverage"].get("entry_notes", [])) or "组件输入状态不确定"})
        if analysis["coverage"].get("external_entry_status") == "uncertain":
            gaps.append({"type": "外部入口确认", "subject": analysis["entry_id"],
                         "description": "; ".join(analysis["coverage"].get("entry_notes", [])) or "外部入口状态不确定"})
        for target in analysis["coverage"].get("unresolved_targets", []):
            gaps.append({"type": "未解析调用", "subject": analysis["entry_id"], "description": target})
    validated_group_ids = {row["group_id"] for row in groups}
    for group in semantic_groups:
        if group.get("validation_required") and group["group_id"] not in validated_group_ids:
            gaps.append({"type": "未完成验证", "subject": group["group_id"],
                         "description": "该敏感操作未完成六维有效性验证"})
    for gap in correlation.get("gaps", []):
        gap_type = gap.get("type")
        descriptions = {
            "target_component_not_in_analysis_scope": "目标组件不在本次分析范围内，跨组件链未继续连接",
            "target_component_semantics_missing": "目标组件语义分析未完成，跨组件链未继续连接",
            "state_limit": "组件连接状态达到上限，已停止继续展开",
        }
        gaps.append({
            "type": "组件连接",
            "subject": gap.get("call_id") or gap.get("target_entry_id") or gap.get("root_entry_id") or "component_graph",
            "description": descriptions.get(gap_type, gap_type or str(gap)),
        })
    for row in tasks:
        if row["status"] == "exhausted" and row["kind"] != "poc_generation":
            gaps.append({"type": "任务未完成", "subject": row["task_id"],
                         "description": row.get("error") or "任务达到最大尝试次数"})
    coverage_status = "完整" if not gaps else "部分完成"
    model = {
        "schema_version": 1,
        "generated_at": now(),
        "run": {
            "run_id": run["run_id"], "target_repo": run["target_repo"], "mode": run["audit_mode"],
            "status": report_status or run["status"], "live": live,
            "capabilities": json.loads(run["capability_filter_json"]),
            "components": json.loads(run["component_filter_json"]),
            "correlation": correlation,
            "incremental": {
                "change_set": change_set, "impact_plan": impact_plan,
                "risk_path_changes": finding_changes,
            } if run["audit_mode"] == "incremental" else None,
        },
        "project": {
            "application": project.get("application") or {}, "summary": project.get("summary", {}),
            "build": project.get("build", {}),
            "modules": project.get("modules", []), "components": project.get("components", []),
            "requested_permissions": project.get("requested_permissions", []),
            "defined_permissions": project.get("defined_permissions", []),
            "dependencies": project.get("dependencies", []),
            "module_dependencies": project.get("module_dependencies", []),
            "diagnostics": project.get("diagnostics", []),
        },
        "summary": {
            "entries": len(entries), "paths": len(evidence_paths), "evidence_facts": fact_count,
            "analyzed_components": len(analyses),
            "findings": actionable_findings,
            "poc_artifacts": len(poc_by_finding),
            "validation_results": len(groups), "operation_groups": len(semantic_groups),
            "component_calls": len(component_calls),
            "exploration_components": len(exploration_graph["components"]),
            "exploration_nodes": len(exploration_graph["nodes"]),
            "exploration_symbols": len(exploration_symbols),
            "source_resolved_relations": source_resolved_relations,
            "exploration_status": dict(sorted(Counter(
                row["status"] for row in exploration_graph["components"]
            ).items())),
            "cross_component_groups": sum(group.get("scope") == "cross_component" for group in semantic_groups),
            "confirmed_vulnerabilities": finding_classification_counts.get("confirmed_vulnerability", 0),
            "residual_risks": finding_classification_counts.get("residual_risk", 0),
            "protected_exposures": classification_counts.get("protected_exposure", 0),
            "no_exploitable_paths": classification_counts.get("no_exploitable_path", 0),
            "benign_business_flows": classification_counts.get("benign_business_flow", 0),
            "insufficient_evidence": classification_counts.get("insufficient_evidence", 0),
            "components_with_findings": sum(
                row["status"] in {"confirmed_vulnerability", "residual_risk"} for row in component_results
            ),
            "components_without_findings": sum(
                row["status"] in {
                    "protected_exposure", "no_exploitable_path", "benign_business_flow",
                    "no_security_relevant_operation", "entry_excluded", "external_entry_excluded",
                }
                for row in component_results
            ),
            "component_results": dict(sorted(component_result_counts.items())),
            "path_status": dict(sorted(Counter(row["status"] for row in evidence_paths).items())),
            "classifications": dict(sorted(classification_counts.items())), "tasks": task_counts,
        },
        "coverage": {
            "status": coverage_status,
            "project_candidates": len(project.get("entry_candidates", [])),
            "component_catalog": len(entries),
            "analysis_units": sum(row["kind"] == "component_semantic_analysis" for row in tasks),
            "exploration_components": len(exploration_graph["components"]),
            "exploration_nodes": len(exploration_graph["nodes"]),
            "exploration_symbols": len(exploration_symbols),
            "source_resolved_relations": source_resolved_relations,
            "semantic_analyses": len(analyses),
            "operation_groups": len(semantic_groups),
            "component_calls": len(component_calls), "component_correlation": correlation,
            "entry_status": dict(sorted(entry_status_counts.items())),
            "external_entry_status": dict(sorted(external_entry_status_counts.items())),
            "task_status": task_counts,
            "assessment_status": dict(sorted(classification_counts.items())),
            "gaps": gaps,
        },
        "entries": entries, "semantic_analyses": analyses,
        "exploration_graph": exploration_graph,
        "component_results": component_results,
        "component_calls": component_calls,
        "operation_groups": groups, "semantic_operation_groups": semantic_groups,
        "paths": evidence_paths, "assessments": groups, "findings": findings, "pocs": list(poc_by_finding.values()),
    }
    write_json(run_paths["report_model"], model)
    write_text(run_paths["report_html"], _render_html(model))
    if live:
        return {
            "report_html": str(run_paths["report_html"]),
            "report_model": str(run_paths["report_model"]),
            "summary": model["summary"],
        }
    write_text(run_paths["report_md"], _render_markdown(model))
    hashes = {}
    for key in ("report_model", "report_md", "report_html", "findings"):
        target = run_paths[key]
        hashes[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    snapshot = {"schema_version": 1, "generated_at": now(), "run_id": run["run_id"], "sha256": hashes}
    write_json(run_paths["snapshot"], snapshot)
    return {"report_markdown": str(run_paths["report_md"]), "report_html": str(run_paths["report_html"]),
            "report_model": str(run_paths["report_model"]), "snapshot": str(run_paths["snapshot"]), "summary": model["summary"]}


def refresh_live_report(run_dir):
    try:
        return {"ok": True, **build_report(run_dir, live=True)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}:{exc}"}


def _render_markdown(model):
    summary = model["summary"]
    lines = [
        "# HarmonyOS 应用安全审计报告", "",
        f"- 审计目标：`{model['run']['target_repo']}`",
        f"- 运行编号：`{model['run']['run_id']}`",
        f"- 组件范围：`{', '.join(model['run']['components']) or '全部组件'}`",
        f"- 能力范围：`{', '.join(model['run']['capabilities']) or '全部能力'}`",
        f"- 组件目录：{summary['entries']}",
        f"- 安全语义断点：{summary['exploration_nodes']}",
        f"- 已覆盖函数：{summary['exploration_symbols']}",
        f"- 源码补全的动态关系：{summary.get('source_resolved_relations', 0)}",
        f"- 已分析组件：{summary['analyzed_components']}",
        f"- 未发现漏洞的已分析组件：{summary['components_without_findings']}",
        f"- 攻击路径：{summary['paths']}",
        f"- 跨组件调用：{summary['component_calls']}",
        f"- 跨组件操作组：{summary['cross_component_groups']}",
        f"- 证据事实：{summary['evidence_facts']}",
        f"- 需要处置的发现：{summary['findings']}",
        f"- 已确认漏洞：{summary['confirmed_vulnerabilities']}",
        f"- 残余风险：{summary['residual_risks']}",
        f"- 已有有效防护：{summary['protected_exposures']}",
        f"- 未形成可利用路径：{summary['no_exploitable_paths']}",
        f"- 正常业务行为：{summary['benign_business_flows']}",
        f"- 证据不足：{summary['insufficient_evidence']}", "",
    ]
    incremental = model["run"].get("incremental") or {}
    if incremental:
        change_set = incremental.get("change_set", {})
        impact_plan = incremental.get("impact_plan", {})
        risk_changes = incremental.get("risk_path_changes", {})
        files = change_set.get("files", {})
        lines.extend([
            "## 增量分析概览", "",
            f"- 基线运行：`{change_set.get('baseline_run_id') or '-'}`",
            f"- 变化来源：`{change_set.get('source_type') or '-'}`",
            f"- 文件变化：新增 {len(files.get('added', []))} / 修改 {len(files.get('modified', []))} / 删除 {len(files.get('deleted', []))}",
            f"- 入口变化：新增 {len(impact_plan.get('added_entries', []))} / 修改 {len(impact_plan.get('changed_entries', []))} / 删除 {len(impact_plan.get('deleted_entries', []))}",
            f"- 重新分析组件：{len(impact_plan.get('affected_entries', []))}",
            f"- 复用组件语义：{len(impact_plan.get('reusable_entries', []))}", "",
            (f"- 风险路径变化：新增 {len(risk_changes.get('added', []))} / 结论变化 {len(risk_changes.get('changed', []))} / 已消失 {len(risk_changes.get('removed', []))} / 未变 {len(risk_changes.get('unchanged', []))}"
             if risk_changes.get("status") == "complete" else "- 风险路径变化：等待本轮审计完成后比较"), "",
        ])
    lines.extend(["## 组件审计结果", ""])
    for component in model["component_results"]:
        coverage = component.get("coverage", {})
        exploration = component.get("exploration", {})
        node_counts = exploration.get("node_counts", {})
        component_name = component.get("component") or component["entry_id"]
        lines.extend([
            f"### {component_name}", "",
            f"- 所属模块：`{component.get('module') or component.get('module_id') or '-'}`",
            f"- 审计结论：**{component['status_label']}**",
            f"- 组件功能：{component['function_summary']}",
            (f"- 探索进度：{_label(exploration.get('status'))}，{exploration.get('rounds', 0)} 轮，"
             f"已分析 {node_counts.get('completed', 0)} / 待分析 {node_counts.get('queued', 0)} / "
             f"缺口 {node_counts.get('gap', 0)}" if exploration else "- 探索进度：增量基线复用，无本轮节点记录"),
            f"- 组件输入状态：{_label(coverage.get('entry_status', 'uncertain'))}",
            f"- 外部入口状态：{_label(coverage.get('external_entry_status', 'uncertain'))}",
            f"- 已检查入口：{', '.join(coverage.get('entry_symbols_checked', [])) or '无'}",
            f"- 已检查操作位置：{', '.join(coverage.get('operation_sites_checked', [])) or '无'}", "",
            "#### 安全相关操作", "",
        ])
        if not component["operation_groups"]:
            lines.append("- 本次分析未识别到可达的安全相关操作。")
        for group in component["operation_groups"]:
            operation = group.get("operation", {})
            conclusion = group.get("impact") or group.get("demotion_reason") or "尚未形成六维验证结论"
            lines.append(
                f"- **{group.get('title') or group['group_id']}**：{_label(group.get('classification') or 'verification_incomplete')}；"
                f"操作 `{operation.get('body') or group.get('operation_location')}`，位置 `{operation.get('location') or group.get('operation_location')}`；{conclusion}"
            )
            availability = group.get("availability") or {}
            availability_analysis = group.get("availability_analysis") or {}
            if availability:
                lines.append(
                    f"  - 可用性事实：{availability.get('resource_or_failure')}；"
                    f"上限/放大关系：{availability.get('limit_or_amplification')}；"
                    f"异常处理/隔离：{availability.get('exception_or_isolation')}；"
                    f"影响范围：{availability.get('affected_scope')}"
                )
            if availability_analysis:
                lines.append(
                    f"  - DoS验证：{availability_analysis.get('reason')}；"
                    f"恢复方式：{availability_analysis.get('recovery')}"
                )
        lines.extend(["", "#### 防护事实", ""])
        if not component["security_checks"]:
            lines.append("- 未观察到显式防护事实；若组件未执行安全相关操作，这不表示组件存在漏洞。")
        for check in component["security_checks"]:
            lines.append(
                f"- **{check.get('type') or '安全检查'}**：{check.get('behavior') or check.get('protects') or '-'}；"
                f"校验对象 `{check.get('validated_property') or '-'}`，位置 `{check.get('location') or '-'}`"
            )
        lines.extend(["", "#### 人工复核提示", ""])
        lines.extend(f"- {note}" for note in component["review_notes"])
        if not component["review_notes"]:
            lines.append("- 当前未记录额外覆盖缺口。")
        lines.append("")

    lines.extend(["## 需要处置的安全发现", ""])
    if not model["findings"]:
        lines.append("本次审计未生成需要处置的漏洞或残余风险；各组件的安全结果与覆盖信息见上一节。")
    for finding in model["findings"]:
        lines.extend([
            f"### {finding['finding_id']}: {finding['title']}", "",
            f"- 结论：`{_label(finding['classification'])}`", f"- 风险等级：`{_label(finding.get('severity'))}`",
            f"- 安全边界：`{finding['boundary']}`", f"- 受控属性：`{finding['controlled_property']}`",
            f"- 敏感操作：`{finding['operation_location']}`", f"- 关联路径：{', '.join(finding['payload'].get('related_path_ids', [finding['path_id']]))}", "",
            finding["payload"].get("conclusion", ""), "",
            *poc_markdown(finding), "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def poc_markdown(finding):
    """Structured PoC block; a confirmed finding without an artifact renders a placeholder."""
    artifact = finding.get("poc_artifact") or {}
    poc = artifact.get("payload") or {}
    if not poc:
        if finding["classification"] in ("confirmed_vulnerability", "residual_risk"):
            return [
                "#### 验证方式 / PoC", "",
                f"- 状态：`{_label(finding.get('poc_status') or 'pending_generation')}`",
            ]
        return []
    trigger = poc.get("trigger") or {}
    hint = poc.get("execution_hint") or {}
    steps = hint.get("step_by_step", [])
    preamble = []
    if poc.get("entry_type"):
        preamble.append(f"- 入口类型：`{poc['entry_type']}`")
    if trigger.get("kind"):
        preamble.append(f"- 触发方式：`{trigger['kind']}`")
    payload = trigger.get("payload")
    if payload is not None:
        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        if text and text != "{}":
            preamble.append(f"- 触发载荷：`{text}`")
    if poc.get("language"):
        preamble.append(f"- 语言：`{poc['language']}`")
    prereqs = poc.get("prerequisites", [])
    if prereqs:
        preamble.append(f"- 前置条件：{'、'.join(f'`{item}`' for item in prereqs)}")
    device = hint.get("device_required")
    lines = ["#### 验证方式 / PoC", ""]
    lines.append(f"- 可信度：`{_label(finding.get('poc_status') or poc.get('assurance_status'))}`")
    lines.extend(preamble)
    if preamble:
        lines.append("")
    if poc.get("expected_observation"):
        lines.append(f"**预期现象**：{poc['expected_observation']}")
    if poc.get("limitations"):
        lines.append(f"> 复现限制：{poc['limitations']}")
    if device and device != "none":
        lines.append(f"> 复现环境：{device}")
    if steps:
        lines.extend(["", "**逐步复现**：", *[f"{index}. {step}" for index, step in enumerate(steps, 1)]])
    lines.extend(["", f"```{poc.get('language') or 'typescript'}", poc.get("code") or "未提供 PoC", "```"])
    return lines


_POC_JS = """const pocF=arr(D.findings).find(f=>arr(p.finding_ids).includes(f.finding_id));const pocA=obj(pocF?.poc_artifact);const poc=obj(pocA.payload||pocA);const pocStatus=pocF?.poc_status||poc.assurance_status||'pending_generation';const pocSteps=arr(obj(poc.execution_hint).step_by_step);const pocHtml=poc.code?`<h3>验证方式 / PoC</h3><div class="structure-item"><dl class="kv"><dt>可信度</dt><dd>${badge(pocStatus)}</dd><dt>入口 / 触发 / 语言</dt><dd>${[poc.entry_type,poc.trigger?.kind,poc.language].filter(Boolean).map(esc).join(' · ')}</dd>${poc.expected_observation?`<dt>预期现象</dt><dd>${esc(poc.expected_observation)}</dd>`:''}${poc.limitations?`<dt>复现限制</dt><dd>${esc(poc.limitations)}</dd>`:''}${arr(poc.prerequisites).length?`<dt>前置条件</dt><dd>${arr(poc.prerequisites).map(esc).join('、')}</dd>`:''}${pocSteps.length?`<dt>逐步复现</dt><dd><ol>${pocSteps.map(s=>`<li>${esc(s)}</li>`).join('')}</ol></dd>`:''}</dl><pre><code>${esc(poc.code)}</code></pre></div>`:((x.classification==='confirmed_vulnerability'||x.classification==='residual_risk')?`<h3>验证方式 / PoC</h3><div class="empty">${badge(pocStatus)}</div>`:'');"""


def _render_html(model):
    application = model.get("project", {}).get("application") or {}
    title = html.escape(application.get("bundle_name") or "HarmonyOS 安全审计")
    view_model = {
        "generated_at": model["generated_at"],
        "run": model["run"], "project": model["project"], "summary": model["summary"],
        "coverage": model["coverage"], "entries": model["entries"],
        "component_results": [{
            key: component.get(key) for key in (
                "entry_id", "component_id", "component", "module", "module_id", "module_root", "symbol",
                "external_reachability", "facets", "profiles", "status", "status_label", "function_summary",
                "coverage", "security_checks", "review_notes", "exploration",
            )
        } | {
            "operation_groups": [{key: group.get(key) for key in (
                "group_id", "scope", "title", "category", "classification", "operation", "operation_location",
                "controlled_properties", "context", "security_checks", "impact", "demotion_reason", "evidence_gap",
                "business_intent", "security_boundary", "exploitability", "counter_evidence", "component_chain",
                "availability", "availability_analysis", "effect_chain",
            )} | {"facts": [{key: fact.get(key) for key in (
                "type", "body", "location", "evidence_refs",
            )} for fact in group.get("facts", [])]} for group in component["operation_groups"]],
            "outgoing_calls": [{key: call.get(key) for key in (
                "call_id", "target_component_id", "transport", "call_location", "condition",
                "parameter_mappings", "security_checks", "payload",
            )} for call in component["outgoing_calls"]],
            "incoming_calls": [{key: call.get(key) for key in (
                "call_id", "source_entry_id", "source_component_id", "transport", "call_location", "condition",
                "parameter_mappings", "security_checks", "payload",
            )} for call in component["incoming_calls"]],
        } for component in model["component_results"]],
        "paths": [{
            key: path.get(key) for key in (
                "path_id", "flow_ids", "root_entry_id", "branch_key", "controlled_property",
                "current_symbol", "status", "entry", "finding_ids",
            )
        } | {
            "facts": [{
                "type": fact.get("type") or fact.get("fact_type"),
                **{key: fact.get(key) for key in ("body", "location", "evidence_refs")},
            } for fact in path["facts"]],
            "assessments": [{key: row.get(key) for key in (
                "assessment_id", "capability_id", "category", "classification",
                "title", "severity", "boundary", "operation_location", "impact", "demotion_reason",
                "evidence_gap", "exploitability", "business_intent", "security_boundary",
                "principal_analysis", "security_checks", "counter_evidence", "effect_chain", "evidence_refs",
            )} for row in path["assessments"]],
        } for path in model["paths"]],
        "findings": [{
            key: finding.get(key) for key in (
                "finding_id", "path_id", "classification", "title", "severity", "cwe",
                "impact", "boundary", "controlled_property", "operation_location", "evidence",
                "poc_artifact", "poc_status",
            )
        } | {"payload": {
            key: finding["payload"].get(key) for key in (
                "conclusion", "exploitability", "business_intent", "security_boundary",
                "principal_analysis", "security_checks", "effect_chain",
                "counter_evidence", "demotion_reason", "evidence_gap", "evidence_refs", "related_path_ids",
            )
        }} for finding in model["findings"]],
    }
    report_data = json.dumps(view_model, ensure_ascii=False).replace("</", "<\\/")
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>
:root{{--ink:#17201d;--muted:#66736e;--line:#d9e0dc;--paper:#f5f7f5;--surface:#fff;--accent:#087f5b;--danger:#b42318;--warn:#b54708;--safe:#287a50}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}}button,input,select{{font:inherit}}header.top{{background:var(--surface);border-bottom:1px solid var(--line)}}.top-inner,nav,.view{{max-width:1180px;margin:auto}}.top-inner{{padding:26px 24px 20px}}h1{{font-size:27px;margin:3px 0 7px}}h2{{font-size:18px;margin:0 0 14px}}h3{{font-size:15px;margin:0 0 8px}}.muted{{color:var(--muted)}}.runmeta{{display:flex;flex-wrap:wrap;gap:8px 20px;color:var(--muted)}}nav{{padding:0 24px}}.tabs{{display:flex;gap:2px;overflow:auto}}.tab{{border:0;border-bottom:3px solid transparent;background:transparent;padding:12px 18px;white-space:nowrap;cursor:pointer;color:var(--muted)}}.tab.active{{border-color:var(--accent);color:var(--ink);font-weight:650}}.view{{display:none;padding:26px 24px 72px}}.view.active{{display:block}}.metrics{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border:1px solid var(--line);background:var(--line);gap:1px;margin-bottom:24px}}.metric{{background:var(--surface);padding:16px;min-width:0}}.metric strong{{display:block;font-size:25px;overflow-wrap:anywhere}}.metric span{{color:var(--muted)}}.grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}.panel{{background:var(--surface);border:1px solid var(--line);padding:18px;margin-bottom:20px}}.summary-list{{display:grid;gap:10px}}.summary-item{{border-left:3px solid var(--accent);padding:7px 10px;background:#f8faf8}}.summary-item.danger{{border-color:var(--danger)}}.summary-item h3{{margin:0}}.summary-item p{{margin:4px 0 0;color:var(--muted)}}.toolbar{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}}.control{{height:38px;border:1px solid var(--line);background:var(--surface);padding:0 11px;min-width:160px}}input.control{{flex:1;min-width:240px}}.count{{color:var(--muted);margin:0 0 8px}}.table-wrap{{overflow:auto;border:1px solid var(--line);background:var(--surface)}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{font-size:12px;color:var(--muted);background:#fafbfa;white-space:nowrap}}tr.path-row,tr.component-row{{cursor:pointer}}tr.path-row:hover,tr.component-row:hover{{background:#f2f7f4}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;overflow-wrap:anywhere}}.badge{{display:inline-block;border:1px solid var(--line);padding:2px 7px;font-size:12px;white-space:nowrap}}.badge.confirmed_vulnerability{{color:var(--danger);border-color:#efb4ae;background:#fff5f4}}.badge.residual_risk,.badge.gap,.badge.insufficient_evidence,.badge.verification_incomplete,.badge.entry_uncertain{{color:var(--warn);border-color:#e8c39c;background:#fff9f0}}.badge.protected_exposure,.badge.no_exploitable_path,.badge.no_security_relevant_operation,.badge.stopped{{color:var(--safe);border-color:#aed8c0;background:#f1faf5}}.badge.benign_business_flow,.badge.entry_excluded,.badge.reached{{color:#42665a;background:#f4f8f6}}.badge.not_analyzed{{color:var(--muted);background:#f5f6f5}}.structure-list{{display:grid;gap:10px}}.structure-item{{border-bottom:1px solid var(--line);padding:0 0 10px}}.structure-item:last-child{{border:0;padding-bottom:0}}.kv{{display:grid;grid-template-columns:150px 1fr;gap:7px 14px}}.kv dt{{color:var(--muted)}}.kv dd{{margin:0;overflow-wrap:anywhere}}.gap-list{{display:grid;gap:9px}}.gap-item{{border-left:3px solid var(--warn);background:#fffaf3;padding:10px 12px}}.empty{{padding:22px;color:var(--muted);text-align:center;background:var(--surface);border:1px solid var(--line)}}.drawer-backdrop{{display:none;position:fixed;inset:0;background:rgba(17,28,23,.34);z-index:10}}.drawer-backdrop.open{{display:block}}.drawer{{position:absolute;right:0;top:0;width:min(760px,94vw);height:100%;overflow:auto;background:var(--surface);padding:24px;box-shadow:-12px 0 40px rgba(0,0,0,.16)}}.drawer-head{{display:flex;justify-content:space-between;gap:16px;align-items:start;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:18px}}.close{{border:1px solid var(--line);background:var(--surface);width:34px;height:34px;font-size:21px;cursor:pointer}}.timeline{{list-style:none;margin:0;padding:0}}.timeline li{{position:relative;margin-left:7px;padding:0 0 16px 24px;border-left:1px solid var(--line)}}.timeline li:before{{content:"";position:absolute;left:-5px;top:5px;width:9px;height:9px;background:var(--accent)}}.timeline li:last-child{{border-left-color:transparent}}.timeline b{{display:block}}@media(max-width:900px){{.metrics{{grid-template-columns:repeat(3,minmax(0,1fr))}}.grid-2{{grid-template-columns:1fr}}}}@media(max-width:600px){{.top-inner,.view,nav{{padding-left:14px;padding-right:14px}}.metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}.kv{{grid-template-columns:1fr}}}}
.badge.generation_failed{{color:var(--danger);border-color:#efb4ae;background:#fff5f4}}.badge.generated_unverified,.badge.pending_generation,.badge.running,.badge.leased,.badge.partial{{color:var(--warn);border-color:#e8c39c;background:#fff9f0}}.badge.build_verified,.badge.device_verified,.badge.complete,.badge.completed{{color:var(--safe);border-color:#aed8c0;background:#f1faf5}}.explore-node{{padding:8px 10px;border-left:2px solid var(--line);margin:5px 0;background:#fafbfa}}.explore-node code{{display:block}}
</style></head><body><header class="top"><div class="top-inner"><div class="muted">HarmonyOS 应用安全审计报告</div><h1>{title}</h1><div class="runmeta" id="runmeta"></div></div><nav><div class="tabs"><button class="tab active" data-view="overview">概览</button><button class="tab" data-view="components">组件审计</button><button class="tab" data-view="paths">攻击路径</button><button class="tab" data-view="project">项目结构</button><button class="tab" data-view="coverage">覆盖与缺口</button></div></nav></header>
<main><section id="overview" class="view active"><div class="metrics" id="overview-metrics"></div><div id="incremental-summary" class="panel"><h2>增量分析</h2><div class="structure-list" id="incremental-summary-content"></div></div><div class="grid-2"><div class="panel"><h2>分析结果</h2><div id="result-summary" class="summary-list"></div></div><div class="panel"><h2>重点结论</h2><div id="key-findings" class="summary-list"></div></div></div><div class="panel"><h2>入口与路径概况</h2><div id="entry-summary"></div></div></section>
<section id="components" class="view"><h2>组件审计结果</h2><p class="muted">所有已识别组件均在此展示，包括未发现漏洞、已有有效防护、正常业务和证据不足的组件。点击组件可查看功能、防护与覆盖事实。</p><div class="toolbar"><input id="component-search" class="control" placeholder="搜索组件、模块、功能或入口"><select id="component-result" class="control"><option value="">全部结果</option></select></div><p class="count" id="component-count"></p><div class="table-wrap"><table><thead><tr><th>审计结论</th><th>组件</th><th>组件功能</th><th>真实入口</th><th>安全相关操作</th><th>防护事实</th></tr></thead><tbody id="component-result-body"></tbody></table></div></section>
<section id="paths" class="view"><h2>攻击路径</h2><div class="toolbar"><input id="search" class="control" placeholder="搜索入口、分支、受控参数或敏感操作"><select id="path-result" class="control"><option value="">全部结果</option></select><select id="path-severity" class="control"><option value="">全部等级</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="info">提示</option></select></div><p class="count" id="path-count"></p><div class="table-wrap"><table><thead><tr><th>结果</th><th>等级</th><th>入口</th><th>分支</th><th>受控参数</th><th>敏感操作 / 当前位置</th></tr></thead><tbody id="path-body"></tbody></table></div></section>
<section id="project" class="view"><div class="grid-2"><div class="panel"><h2>项目信息</h2><dl class="kv" id="project-info"></dl></div><div class="panel"><h2>权限与依赖</h2><div id="permission-list" class="structure-list"></div></div></div><div class="panel"><h2>模块</h2><div id="module-list" class="structure-list"></div></div><div class="panel"><h2>组件</h2><div class="table-wrap"><table><thead><tr><th>组件</th><th>类型</th><th>模块</th><th>导出</th><th>权限</th><th>源码</th></tr></thead><tbody id="component-body"></tbody></table></div></div></section>
<section id="coverage" class="view"><div class="metrics" id="coverage-metrics"></div><div class="grid-2"><div class="panel"><h2>覆盖统计</h2><div id="coverage-summary" class="structure-list"></div></div><div class="panel"><h2>任务状态</h2><div id="task-summary" class="structure-list"></div></div></div><div class="panel"><h2>缺口与分析注记</h2><div id="gap-list" class="gap-list"></div></div></section></main>
<div class="drawer-backdrop" id="drawer-backdrop"><aside class="drawer" role="dialog" aria-modal="true"><div class="drawer-head"><div><div class="muted" id="drawer-kind">详情</div><h2 id="drawer-title"></h2></div><button class="close" id="drawer-close" aria-label="关闭">×</button></div><div id="drawer-body"></div></aside></div>
<script type="application/json" id="report-data">{report_data}</script><script>
const D=JSON.parse(document.getElementById('report-data').textContent);const arr=v=>Array.isArray(v)?v:[];const obj=v=>v&&typeof v==='object'?v:{{}};const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const labels={{confirmed_vulnerability:'已确认漏洞',residual_risk:'残余风险',protected_exposure:'已有有效防护',benign_business_flow:'正常业务行为',insufficient_evidence:'证据不足',verification_incomplete:'验证未完成',no_exploitable_path:'未形成可利用路径',no_security_relevant_operation:'未发现安全相关操作',entry_excluded:'组件输入已排除',entry_uncertain:'组件输入状态不确定',external_entry_excluded:'未确认外部入口',not_analyzed:'未完成分析',generated_unverified:'已生成，未编译验证',build_verified:'已通过编译验证',device_verified:'已通过设备验证',generation_failed:'生成失败',pending_generation:'生成中',confirmed:'已确认',excluded:'已排除',uncertain:'不确定',component_semantic_analysis:'组件语义分析',exploitability_validation:'六维验证',poc_generation:'PoC 生成',reached:'已到达敏感操作',stopped:'已停止',open:'继续追踪',gap:'覆盖缺口',pending:'等待探索',complete:'探索完成',partial:'部分完成',completed:'已分析',leased:'分析中',exhausted:'未完成',queued:'待分析',running:'探索中',critical:'严重',high:'高危',medium:'中危',low:'低危',info:'提示',entrypoint:'入口',reachability:'可达性',control:'控制关系',transform:'参数传递',security_check:'安全检查',operation:'安全相关操作',effect:'实际影响',dead_end:'路径终止',deeplink:'深度链接',want:'Want 调用',exported_ability:'导出组件',provider:'数据提供组件',common_event:'公共事件',ipc_transaction:'IPC/RPC 调用',effective_security_check:'有效安全检查',business_intent:'业务意图',not_attacker_controlled:'操作不受控',sink_not_reached:'未到达敏感操作',no_boundary_violation:'未突破安全边界',no_concrete_impact:'未形成具体影响',origin_principal:'原始调用者',immediate_caller:'直接调用者',transferred_property:'传递参数',resource_owner:'资源所有者',security_boundary:'安全边界','$invocation':'操作触发'}};const label=v=>labels[v]||v||'-';
labels.not_externally_reachable='外部不可达';
const findingById=Object.fromEntries(arr(D.findings).map(x=>[x.finding_id,x]));const resultRank={{confirmed_vulnerability:6,residual_risk:5,insufficient_evidence:4,protected_exposure:3,no_exploitable_path:2,benign_business_flow:1}};const pathResult=p=>arr(p.finding_ids).map(id=>findingById[id]).filter(Boolean)[0]||arr(p.assessments).slice().sort((a,b)=>(resultRank[b.classification]||0)-(resultRank[a.classification]||0))[0]||{{}};const metric=(v,t)=>`<div class="metric"><strong>${{esc(v)}}</strong><span>${{esc(t)}}</span></div>`;const badge=v=>`<span class="badge ${{esc(v)}}">${{esc(label(v))}}</span>`;
document.getElementById('runmeta').innerHTML=`<span>运行编号 <b>${{esc(D.run.run_id)}}</b></span><span>审计模式 <b>${{esc(D.run.mode)}}</b></span><span>运行状态 <b>${{esc(label(D.run.status))}}</b></span><span>审计范围 <b>${{esc(arr(D.run.components).join(', ')||'全部组件')}}</b></span><span>覆盖状态 <b>${{esc(D.coverage.status)}}</b></span><span>更新时间 <b>${{esc(D.generated_at)}}</b></span>`;
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.view').forEach(x=>x.classList.toggle('active',x.id===b.dataset.view));}});
const S=D.summary;document.getElementById('overview-metrics').innerHTML=metric(S.confirmed_vulnerabilities,'已确认漏洞')+metric(S.residual_risks,'残余风险')+metric(S.components_without_findings,'未发现漏洞组件')+metric(S.protected_exposures,'有效防护')+metric(S.analyzed_components,'已分析组件')+metric(S.paths,'攻击路径');
const resultRows=[['confirmed_vulnerability',S.confirmed_vulnerabilities],['residual_risk',S.residual_risks],['protected_exposure',S.protected_exposures],['no_exploitable_path',S.no_exploitable_paths],['benign_business_flow',S.benign_business_flows],['insufficient_evidence',S.insufficient_evidence]];document.getElementById('result-summary').innerHTML=resultRows.map(([k,v])=>`<div class="summary-item"><h3>${{badge(k)}} ${{esc(v)}} 条</h3></div>`).join('');
const key=arr(D.findings).filter(x=>['confirmed_vulnerability','residual_risk'].includes(x.classification)).slice(0,6);document.getElementById('key-findings').innerHTML=key.map(x=>`<div class="summary-item danger"><h3>${{esc(x.title)}}</h3><p>${{badge(x.classification)}} · ${{esc(label(x.severity||'未定级'))}} · ${{esc(x.operation_location)}}</p></div>`).join('')||'<div class="empty">未发现需要处置的安全问题</div>';
const entryTypes={{}};arr(D.entries).forEach(x=>arr(x.facets).forEach(f=>entryTypes[f.entry_type]=(entryTypes[f.entry_type]||0)+1));document.getElementById('entry-summary').innerHTML=`<div class="structure-list">${{Object.entries(entryTypes).map(([k,v])=>`<div class="structure-item"><strong>${{esc(label(k))}}</strong><div class="muted">${{v}} 个入口渠道</div></div>`).join('')}}</div>`;
const I=obj(D.run.incremental),CS=obj(I.change_set),IP=obj(I.impact_plan),RC=obj(I.risk_path_changes),CF=obj(CS.files),riskDelta=RC.status==='complete'?`新增 ${{arr(RC.added).length}} / 结论变化 ${{arr(RC.changed).length}} / 已消失 ${{arr(RC.removed).length}} / 未变 ${{arr(RC.unchanged).length}}`:'等待本轮审计完成后比较';if(!Object.keys(I).length){{document.getElementById('incremental-summary').style.display='none'}}else{{document.getElementById('incremental-summary-content').innerHTML=`<div class="structure-item"><strong>基线与变化</strong><div class="muted">${{esc(CS.source_type)}} 基线 ${{esc(CS.baseline_run_id||'-')}} · 新增 ${{arr(CF.added).length}} / 修改 ${{arr(CF.modified).length}} / 删除 ${{arr(CF.deleted).length}} 个文件</div></div><div class="structure-item"><strong>入口变化</strong><div class="muted">新增 ${{arr(IP.added_entries).length}} / 修改 ${{arr(IP.changed_entries).length}} / 删除 ${{arr(IP.deleted_entries).length}}</div></div><div class="structure-item"><strong>执行范围</strong><div class="muted">重新分析 ${{arr(IP.affected_entries).length}} 个组件 · 复用 ${{arr(IP.reusable_entries).length}} 个组件语义结果</div></div><div class="structure-item"><strong>风险路径变化</strong><div class="muted">${{esc(riskDelta)}}</div></div>`}};
const componentSelect=document.getElementById('component-result');[...new Set(arr(D.component_results).map(x=>x.status))].forEach(k=>componentSelect.insertAdjacentHTML('beforeend',`<option value="${{esc(k)}}">${{esc(label(k))}}</option>`));
function renderComponents(){{const q=document.getElementById('component-search').value.toLowerCase(),r=componentSelect.value;const rows=arr(D.component_results).filter(x=>{{const coverage=obj(x.coverage),facets=arr(x.facets).map(f=>label(f.entry_type)).join(' '),text=[x.component,x.module,x.module_id,x.symbol,x.function_summary,facets,...arr(coverage.entry_symbols_checked)].join(' ').toLowerCase();return(!q||text.includes(q))&&(!r||x.status===r)}});document.getElementById('component-count').textContent=`显示 ${{rows.length}} / ${{arr(D.component_results).length}} 个组件`;document.getElementById('component-result-body').innerHTML=rows.map(x=>{{const coverage=obj(x.coverage),exploration=obj(x.exploration),counts=obj(exploration.node_counts),entries=arr(x.facets).map(f=>label(f.entry_type)).join('、')||label(coverage.entry_status),operations=arr(x.operation_groups),checks=arr(x.security_checks),progress=Object.keys(exploration).length?`${{label(exploration.status)}} · ${{exploration.rounds||0}} 轮 · 已分析 ${{counts.completed||0}} / 待分析 ${{counts.queued||0}} / 分析中 ${{counts.leased||0}} / 缺口 ${{counts.gap||0}}`:'';return`<tr class="component-row" data-entry-id="${{esc(x.entry_id)}}"><td>${{badge(x.status)}}</td><td><strong>${{esc(x.component||x.entry_id)}}</strong><br><span class="muted">${{esc(x.module||x.module_id||'-')}}</span><br><code>${{esc(x.symbol||'')}}</code></td><td>${{esc(x.function_summary)}}${{progress?`<br><span class="muted">${{esc(progress)}}</span>`:''}}</td><td>${{esc(entries)}}<br><span class="muted">组件输入：${{esc(label(coverage.entry_status))}} · 外部入口：${{esc(label(coverage.external_entry_status))}}</span></td><td>${{operations.length}} 项</td><td>${{checks.length}} 项</td></tr>`}}).join('')||'<tr><td colspan="6"><div class="empty">没有符合条件的组件</div></td></tr>';document.querySelectorAll('.component-row').forEach(row=>row.onclick=()=>openComponent(row.dataset.entryId));}}
['component-search','component-result'].forEach(id=>document.getElementById(id).addEventListener(id==='component-search'?'input':'change',renderComponents));
function openComponent(id){{const x=arr(D.component_results).find(row=>row.entry_id===id);if(!x)return;const coverage=obj(x.coverage);const refs=v=>arr(v).map(r=>`<code>${{esc(r)}}</code>`).join(' · ');const groups=arr(x.operation_groups).map(g=>{{const operation=obj(g.operation),context=obj(g.context),result=g.classification||'verification_incomplete',checks=arr(g.security_checks).map(c=>`<div class="structure-item"><strong>${{esc(label(c.type))}}</strong><div>${{esc(c.behavior||c.protects||'-')}}</div><div class="muted">校验对象：${{esc(c.validated_property||'-')}} · 约束主体：${{esc(label(c.subject_kind))}} · ${{esc(c.location||'-')}}</div></div>`).join('');const facts=arr(g.facts).map(f=>`<li><b>${{esc(label(f.type))}} · ${{esc(f.body)}}</b><code>${{esc(f.location||'')}}</code></li>`).join('');const conclusion=g.impact||g.demotion_reason||g.evidence_gap||'尚未形成六维验证结论';return`<div class="panel"><h3>${{esc(g.title||g.group_id)}} · ${{badge(result)}}</h3><dl class="kv"><dt>安全相关操作</dt><dd>${{esc(operation.body||g.operation_location||'-')}}</dd><dt>源码位置</dt><dd><code>${{esc(operation.location||g.operation_location||'-')}}</code></dd><dt>受控参数</dt><dd>${{esc(arr(g.controlled_properties).join('、')||'无外部受控参数')}}</dd><dt>业务用途</dt><dd>${{esc(context.intended_behavior||obj(g.business_intent).declared_or_inferred_purpose||'-')}}</dd><dt>验证结论</dt><dd>${{esc(conclusion)}}</dd></dl>${{checks?`<h3>该操作前的防护</h3><div class="structure-list">${{checks}}</div>`:''}}${{facts?`<h3>语义证据</h3><ol class="timeline">${{facts}}</ol>`:''}}</div>`}}).join('')||'<div class="empty">本次分析未识别到可达的安全相关操作。请结合组件功能和下方覆盖范围复核是否遗漏敏感行为。</div>';const defenses=arr(x.security_checks).map(c=>`<div class="structure-item"><strong>${{esc(label(c.type))}}</strong><div>${{esc(c.behavior||c.protects||'-')}}</div><div class="muted">保护目标：${{esc(c.protects||'-')}} · 校验对象：${{esc(c.validated_property||'-')}} · 约束主体：${{esc(label(c.subject_kind))}} · 位置：${{esc(c.location||'-')}}</div>${{arr(c.evidence_refs).length?`<div class="muted">证据：${{refs(c.evidence_refs)}}</div>`:''}}</div>`).join('')||'<div class="empty">未观察到显式防护事实；若组件未执行安全相关操作，这不表示组件存在漏洞。</div>';const calls=[...arr(x.outgoing_calls).map(c=>['调用下游组件',c.target_component_id,c]),...arr(x.incoming_calls).map(c=>['被上游组件调用',c.source_component_id,c])].map(([direction,target,c])=>`<div class="structure-item"><strong>${{esc(direction)}} · ${{esc(target||'-')}}</strong><div>${{esc(c.condition||'-')}}</div><div class="muted">方式：${{esc(c.transport||'-')}} · 位置：${{esc(c.call_location||'-')}}</div></div>`).join('')||'<div class="empty">未记录跨组件调用。</div>';const exploration=obj(x.exploration),nodeCounts=obj(exploration.node_counts),explorationNodes=arr(exploration.nodes).map(n=>`<div class="explore-node" style="margin-left:${{Math.min(n.depth||0,8)*12}}px"><strong>${{badge(n.status)}} ${{esc(obj(n.symbol).qualified_name||'-')}}</strong><code>${{esc(obj(n.symbol).file_path||'')}}${{obj(n.symbol).line?`:${{obj(n.symbol).line}}`:''}}</code><span class="muted">${{esc(n.summary||n.stop_reason||'等待分析')}} · 本段函数 ${{n.analyzed_symbol_count||0}} · 源码补全关系 ${{n.source_resolved_relation_count||0}} · 操作 ${{n.operation_groups||0}} · 组件调用 ${{n.component_calls||0}}</span></div>`).join('')||'<div class="empty">该组件没有渐进探索记录，可能来自增量基线复用。</div>';const explorationHtml=Object.keys(exploration).length?`<dl class="kv"><dt>探索状态</dt><dd>${{badge(exploration.status)}}</dd><dt>探索轮次</dt><dd>${{exploration.rounds||0}}</dd><dt>断点统计</dt><dd>已分析 ${{nodeCounts.completed||0}} · 待分析 ${{nodeCounts.queued||0}} · 分析中 ${{nodeCounts.leased||0}} · 停止 ${{nodeCounts.stopped||0}} · 缺口 ${{nodeCounts.gap||0}}</dd></dl>${{explorationNodes}}`:explorationNodes;const notes=arr(x.review_notes).map(n=>`<div class="gap-item">${{esc(n)}}</div>`).join('')||'<div class="empty">当前未记录额外覆盖缺口。</div>';document.getElementById('drawer-kind').textContent='组件审计详情';document.getElementById('drawer-title').textContent=x.component||x.entry_id;document.getElementById('drawer-body').innerHTML=`<dl class="kv"><dt>审计结论</dt><dd>${{badge(x.status)}}</dd><dt>所属模块</dt><dd>${{esc(x.module||x.module_id||'-')}}</dd><dt>组件功能</dt><dd>${{esc(x.function_summary)}}</dd><dt>入口状态</dt><dd>${{esc(label(coverage.entry_status))}}</dd><dt>入口渠道</dt><dd>${{esc(arr(x.facets).map(f=>label(f.entry_type)).join('、')||'-')}}</dd><dt>已检查入口</dt><dd>${{arr(coverage.entry_symbols_checked).map(v=>`<code>${{esc(v)}}</code>`).join('<br>')||'无'}}</dd><dt>已检查操作位置</dt><dd>${{arr(coverage.operation_sites_checked).map(v=>`<code>${{esc(v)}}</code>`).join('<br>')||'无'}}</dd></dl><h3>渐进探索过程</h3>${{explorationHtml}}<h3>安全相关操作与验证</h3>${{groups}}<h3>防护事实</h3><div class="structure-list">${{defenses}}</div><h3>跨组件调用</h3><div class="structure-list">${{calls}}</div><h3>人工复核提示</h3><div class="gap-list">${{notes}}</div>`;document.getElementById('drawer-backdrop').classList.add('open');}}
const resultSelect=document.getElementById('path-result');[...new Set(arr(D.paths).map(p=>pathResult(p).classification||p.status))].forEach(k=>resultSelect.insertAdjacentHTML('beforeend',`<option value="${{esc(k)}}">${{esc(label(k))}}</option>`));
function renderPaths(){{const q=document.getElementById('search').value.toLowerCase(),r=resultSelect.value,s=document.getElementById('path-severity').value;const rows=arr(D.paths).filter(p=>{{const x=pathResult(p),state=x.classification||p.status,text=[p.path_id,p.branch_key,p.controlled_property,p.current_symbol,p.entry?.component,p.entry?.module,p.entry?.module_id,p.entry?.symbol,x.title].join(' ').toLowerCase();return(!q||text.includes(q))&&(!r||state===r)&&(!s||x.severity===s)}});document.getElementById('path-count').textContent=`显示 ${{rows.length}} / ${{arr(D.paths).length}} 条路径`;document.getElementById('path-body').innerHTML=rows.map(p=>{{const x=pathResult(p),state=x.classification||p.status;return`<tr class="path-row" data-path-id="${{esc(p.path_id)}}"><td>${{badge(state)}}</td><td>${{esc(label(x.severity||'-'))}}</td><td><strong>${{esc(p.entry?.component||p.root_entry_id)}}</strong><br><span class="muted">${{esc(p.entry?.module||p.entry?.module_id||'')}}</span><br><code>${{esc(p.entry?.symbol||'')}}</code></td><td>${{esc(p.branch_key)}}</td><td><code>${{esc(p.controlled_property)}}</code></td><td>${{esc(x.operation_location||p.current_symbol)}}</td></tr>`}}).join('');document.querySelectorAll('.path-row').forEach(row=>row.onclick=()=>openPath(row.dataset.pathId));}}
['search','path-result','path-severity'].forEach(id=>document.getElementById(id).addEventListener(id==='search'?'input':'change',renderPaths));
function openPath(id){{const p=arr(D.paths).find(x=>x.path_id===id),x=pathResult(p);document.getElementById('drawer-kind').textContent='攻击路径详情';document.getElementById('drawer-title').textContent=x.title||`${{p.entry?.component||p.root_entry_id}} · ${{p.branch_key}}`;const refs=v=>arr(v).map(r=>`<code>${{esc(r)}}</code>`).join(' · ');const facts=arr(p.facts).map(v=>`<li><b>${{esc(label(v.type||v.fact_type))}} · ${{esc(v.body)}}</b><code>${{esc(v.location||'')}}</code>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</li>`).join('');const decisions=arr(p.assessments).map(v=>`<div class="structure-item"><strong>${{esc(label(v.category))}} · ${{badge(v.classification)}}</strong><div>${{esc(v.impact||v.demotion_reason||'')}}</div>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</div>`).join('');const checkNames={{externally_reachable:'外部可达',attacker_controlled:'关键参数可控',sink_reached:'到达敏感操作',security_check_bypassed_or_absent:'防护缺失或可绕过',boundary_violated:'突破安全边界',concrete_impact:'存在具体影响'}};const checks=Object.entries(obj(x.exploitability||x.payload?.exploitability)).map(([k,v])=>`<div class="structure-item"><strong>${{esc(checkNames[k]||label(k))}}</strong><div class="muted">${{(v===true||obj(v).status==='true')?'满足':(v===false||obj(v).status==='false')?'不满足':'未知'}}</div></div>`).join('');{_POC_JS}const conclusion=x.impact||x.demotion_reason||x.payload?.conclusion;const gap=x.evidence_gap||x.payload?.evidence_gap;const boundary=x.security_boundary||x.payload?.security_boundary;const intent=x.business_intent||x.payload?.business_intent;const security_checks=arr(x.security_checks||x.payload?.security_checks).map(v=>`<div class="structure-item"><strong>${{esc(label(v.type))}}</strong><div class="muted">${{esc(v.location||'')}} · 校验 ${{esc(v.validated_property)}}</div><div>${{esc(v.behavior||'')}}</div>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</div>`).join('');const counters=arr(x.counter_evidence||x.payload?.counter_evidence).map(v=>`<div class="structure-item"><strong>${{esc(label(v.kind))}}</strong><div>${{esc(v.reason)}}</div>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</div>`).join('');const evidence=refs(x.evidence_refs||x.evidence||x.payload?.evidence_refs);document.getElementById('drawer-body').innerHTML=`<dl class="kv"><dt>结果</dt><dd>${{badge(x.classification||p.status)}}</dd><dt>路径</dt><dd><code>${{esc(p.path_id)}}</code></dd><dt>入口</dt><dd>${{esc(p.entry?.symbol||p.root_entry_id)}}</dd><dt>分支</dt><dd>${{esc(p.branch_key)}}</dd><dt>受控参数</dt><dd><code>${{esc(p.controlled_property)}}</code></dd><dt>敏感操作</dt><dd><code>${{esc(x.operation_location||p.current_symbol)}}</code></dd><dt>安全边界</dt><dd>${{esc(boundary?.expected_boundary||x.boundary||'-')}}${{boundary?.reason?`<div class="muted">${{esc(boundary.reason)}}</div>`:''}}</dd></dl>${{conclusion?`<div class="panel"><h3>最终结论</h3><p>${{esc(conclusion)}}</p>${{gap?`<p><strong>证据缺口：</strong>${{esc(gap)}}</p>`:''}}${{evidence?`<p class="muted">判定证据：${{evidence}}</p>`:''}}</div>`:''}}${{intent?`<div class="panel"><h3>业务意图</h3><p>${{esc(intent.declared_or_inferred_purpose)}}</p></div>`:''}}${{checks?`<h3>六维有效性验证</h3><div class="structure-list">${{checks}}</div>`:''}}${{security_checks?`<h3>防护事实</h3><div class="structure-list">${{security_checks}}</div>`:''}}${{counters?`<h3>反证</h3><div class="structure-list">${{counters}}</div>`:''}}<h3>路径事实</h3><ol class="timeline">${{facts}}</ol><h3>安全判定</h3><div class="structure-list">${{decisions||'<div class="empty">未发现需要记录的安全场景</div>'}}</div>${{pocHtml}}`;document.getElementById('drawer-backdrop').classList.add('open');}}
const closeDrawer=()=>document.getElementById('drawer-backdrop').classList.remove('open');document.getElementById('drawer-close').onclick=closeDrawer;document.getElementById('drawer-backdrop').onclick=e=>{{if(e.target.id==='drawer-backdrop')closeDrawer()}};
const A=obj(D.project.application);document.getElementById('project-info').innerHTML=[['应用包名',A.bundle_name],['版本',`${{A.version_name||'-'}} (${{A.version_code??'-'}})`],['厂商',A.vendor],['目标仓库',D.run.target_repo],['模块',D.project.summary?.modules],['组件',D.project.summary?.components]].map(([k,v])=>`<dt>${{esc(k)}}</dt><dd>${{esc(v??'-')}}</dd>`).join('');
const perms=[...arr(D.project.requested_permissions).map(x=>['申请权限',x]),...arr(D.project.defined_permissions).map(x=>['自定义权限',x])];const deps=arr(D.project.dependencies);document.getElementById('permission-list').innerHTML=perms.map(([k,x])=>`<div class="structure-item"><strong>${{esc(x.name)}}</strong><div class="muted">${{esc(k)}} · ${{esc(x.grant_mode||x.available_level||'')}}</div></div>`).join('')+deps.map(x=>`<div class="structure-item"><strong>${{esc(x.name)}} ${{esc(x.version||'')}}</strong><div class="muted">依赖 · ${{esc(x.group||'')}}</div></div>`).join('')||'<div class="empty">无权限与依赖信息</div>';
document.getElementById('module-list').innerHTML=arr(D.project.modules).map(x=>`<div class="structure-item"><strong>${{esc(x.name)}} · ${{esc((x.output_kind||x.type||'未知类型').toUpperCase())}}</strong><div class="muted">${{esc(x.root||x.source_scope||x.file)}} · ${{esc(arr(x.products).join(', ')||'全部产品')}} · <code>${{esc(x.module_id||'')}}</code></div></div>`).join('')||'<div class="empty">无模块信息</div>';document.getElementById('component-body').innerHTML=arr(D.project.components).map(x=>`<tr><td><strong>${{esc(x.name)}}</strong></td><td>${{esc(x.extension_type||x.kind)}}</td><td>${{esc(x.module_name)}}<br><code>${{esc(x.module_id||'')}}</code></td><td>${{x.exported===true?'是':x.exported===false?'否':'-'}}</td><td>${{esc(arr(x.permissions).join(', ')||'-')}}</td><td><code>${{esc(x.source_file_hint||x.src_entry||'-')}}</code></td></tr>`).join('');
const C=D.coverage,es=obj(C.entry_status),ac=obj(C.assessment_status),tc=obj(C.task_status),cc=obj(C.component_correlation);
document.getElementById('coverage-metrics').innerHTML=metric(C.status,'覆盖状态')+metric(C.component_catalog||0,'组件目录')+metric(C.analysis_units||0,'实际分析组件')+metric(es.confirmed||0,'已确认输入')+metric(es.excluded||0,'已排除输入')+metric(es.uncertain||0,'不确定输入')+metric(arr(C.gaps).length,'缺口与注记');
document.getElementById('coverage-summary').innerHTML=`<div class="structure-item"><strong>渐进语义探索</strong><div class="muted">已创建 ${{C.exploration_components||0}} 个组件探索 · 记录 ${{C.exploration_nodes||0}} 个安全语义断点 · 覆盖 ${{C.exploration_symbols||0}} 个函数 · 源码补全 ${{C.source_resolved_relations||0}} 条动态关系 · 已生成 ${{C.semantic_analyses||0}} 个最终组件结果</div></div><div class="structure-item"><strong>安全相关操作</strong><div class="muted">归并 ${{C.operation_groups||0}} 个操作组 · 记录 ${{C.component_calls||0}} 条组件传递</div></div><div class="structure-item"><strong>组件连接</strong><div class="muted">生成 ${{S.cross_component_groups||0}} 个跨组件操作组 · 检查 ${{cc.states_visited||0}} 个连接状态</div></div><div class="structure-item"><strong>六维验证</strong><div class="muted">漏洞 ${{ac.confirmed_vulnerability||0}} · 风险 ${{ac.residual_risk||0}} · 防护 ${{ac.protected_exposure||0}} · 不可利用 ${{ac.no_exploitable_path||0}} · 正常 ${{ac.benign_business_flow||0}} · 缺证据 ${{ac.insufficient_evidence||0}}</div></div>`;
document.getElementById('task-summary').innerHTML=Object.entries(tc).map(([k,v])=>`<div class="structure-item"><strong>${{esc(label(k))}}</strong><div class="muted">${{v}} 个任务</div></div>`).join('')||'<div class="empty">无任务信息</div>';
document.getElementById('gap-list').innerHTML=arr(C.gaps).map(x=>`<div class="gap-item"><strong>${{esc(x.type)}} · ${{esc(x.subject)}}</strong><div>${{esc(x.description)}}</div></div>`).join('')||'<div class="empty">未发现覆盖缺口</div>';
renderComponents();renderPaths();
</script></body></html>'''
