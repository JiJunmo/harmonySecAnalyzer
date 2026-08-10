"""Build immutable semantic, validation and poc task documents from canonical state."""
from __future__ import annotations

import hashlib

from .common import canonical_json, load_capabilities
from .evidence import semantic_admissible_refs, semantic_hypothesis_refs
from .store import row_json

# Candidate type -> allowed PoC trigger entry types (same mapping as v3.2).
ENTRY_TYPE_MAP = {
    "exported_component": ["exported_ability", "want"],
    "deeplink": ["deeplink"],
    "implicit_want": ["want"],
    "extension_uri": ["provider"],
    "ipc_service_candidate": ["ipc_transaction"],
    "common_event_candidate": ["common_event"],
    "project_scope": ["project"],
}


def _source_file(location):
    head, separator, tail = str(location).rpartition(":")
    return head if separator and tail.isdigit() else str(location)


def entry_context(conn, entry_id):
    row = conn.execute("SELECT * FROM entries WHERE entry_id=?", (entry_id,)).fetchone()
    if not row:
        return None
    payload = row_json(row, "payload_json", {})
    return {
        **payload,
        "entry_id": row["entry_id"], "entry_key": row["entry_key"],
        "component": row["component"], "symbol": row["symbol"],
        "facets": row_json(row, "facets_json", []),
        "external_reachability": row["reachability"],
        "profiles": row_json(row, "profiles_json", []),
    }


def semantic_group_context(conn, group_id):
    row = conn.execute("SELECT * FROM operation_groups WHERE group_id=?", (group_id,)).fetchone()
    if not row:
        return None
    group = row_json(row, "payload_json", {})
    group.update({
        "group_id": group_id, "entry_id": row["entry_id"],
        "scope": row["scope"], "validation_required": bool(row["validation_required"]),
        "source_group_id": row["source_group_id"],
        "operation_location": row["operation_location"],
        "controlled_properties": row_json(row, "controlled_properties_json", []),
        "evidence_refs": row_json(row, "evidence_json", []),
    })
    group["facts"] = [{
        "fact_id": fact["fact_id"], "fact_key": fact["fact_key"], "type": fact["fact_type"],
        "body": fact["body"], "location": fact["location"],
        "evidence_refs": row_json(fact, "evidence_json", []),
    } for fact in conn.execute(
        "SELECT * FROM group_facts WHERE group_id=? ORDER BY created_at,fact_id", (group_id,)
    )]
    group["edges"] = [{
        "edge_id": edge["edge_id"], "from": edge["from_key"], "to": edge["to_key"],
        "kind": edge["kind"], "evidence_refs": row_json(edge, "evidence_json", []),
    } for edge in conn.execute(
        """SELECT e.*,src.fact_key from_key,dst.fact_key to_key
           FROM group_edges e
           JOIN group_facts src ON src.fact_id=e.from_fact_id
           JOIN group_facts dst ON dst.fact_id=e.to_fact_id
           WHERE e.group_id=? ORDER BY e.created_at,e.edge_id""", (group_id,)
    )]
    return group


def validation_group_fingerprint(conn, group_id):
    """Hash every security-relevant input consumed by six-dimensional validation."""
    group = semantic_group_context(conn, group_id)
    if not group:
        return None
    group.pop("validation_required", None)
    return hashlib.sha256(canonical_json(group).encode("utf-8")).hexdigest()


def validation_context(conn, group_id):
    row = conn.execute("SELECT * FROM validation_results WHERE group_id=?", (group_id,)).fetchone()
    if not row:
        return None
    payload = row_json(row, "payload_json", {})
    payload["boundary"] = row["boundary"]
    return payload


def _evidence_records(conn, evidence_ids):
    records = []
    for evidence_id in sorted(evidence_ids):
        row = conn.execute(
            "SELECT evidence_id,kind,source,location,summary,content_ref,sha256 FROM evidence WHERE evidence_id=?",
            (evidence_id,),
        ).fetchone()
        if row:
            records.append(dict(row))
    return records


def _attach_evidence_scope(conn, group):
    group["evidence_scope"] = {
        "admissible": _evidence_records(conn, semantic_admissible_refs(group)),
        "hypothesis_only": _evidence_records(conn, semantic_hypothesis_refs(group)),
    }
    return group


def group_context(conn, group_id):
    """Combined read model used only by exports and reports."""
    semantic = semantic_group_context(conn, group_id)
    if not semantic:
        return None
    validation = validation_context(conn, group_id)
    if validation:
        semantic_evidence = set(semantic.get("evidence_refs", []))
        validation_evidence = set(validation.get("evidence_refs", []))
        semantic["validation"] = validation
        semantic.update(validation)
        semantic["evidence_refs"] = sorted(semantic_evidence | validation_evidence)
    return semantic


def task_context(conn, task):
    payload = row_json(task, "input_json", {})
    entry = entry_context(conn, task["subject_id"])
    if task["kind"] == "component_semantic_analysis":
        profile_ids = set(entry.get("profiles", [])) if entry else set()
        profiles = [{key: row.get(key) for key in ("capability_id", "title", "domain")}
                    for row in load_capabilities() if row["capability_id"] in profile_ids]
        analysis_contract = {
            "task_unit": "one deterministic component analysis unit",
            "phases": ["confirm_component_inputs", "trace_within_component", "collect_operations", "record_component_calls", "merge_equivalent_operations", "record_gaps"],
            "group_by": ["operation_location", "controlled_properties"],
            "stop_at": "component_call",
            "forbidden_outputs": ["classification", "exploitability", "severity", "cwe", "poc"],
            "evidence_model": {
                "facts": "only directly observed source facts",
                "effect_hypotheses": "untrusted search leads with explicit missing proofs",
                "forbidden_as_fact": ["name_based_effect_inference", "comment_based_effect_inference", "unverified_runtime_effect"],
            },
        }
        if "CAP-DOS-001" in profile_ids:
            analysis_contract["availability_requirements"] = [
                "externally_triggered_failure_or_resource_consumption",
                "attacker_scale_or_repeatability",
                "bounds_and_amplification",
                "exception_handling_or_isolation",
                "affected_scope_and_recovery",
            ]
        return {
            **payload,
            "entry": entry,
            "audit_scope": profiles,
            "analysis_contract": analysis_contract,
        }
    if task["kind"] == "exploitability_validation":
        analysis = conn.execute(
            "SELECT * FROM semantic_analyses WHERE entry_id=?", (task["subject_id"],)
        ).fetchone()
        groups = [semantic_group_context(conn, row["group_id"]) for row in conn.execute(
            "SELECT group_id FROM operation_groups WHERE entry_id=? AND validation_required=1 ORDER BY group_id",
            (task["subject_id"],)
        )]
        for group in groups:
            group.pop("edges", None)
            _attach_evidence_scope(conn, group)
        full_coverage = row_json(analysis, "coverage_json", {})
        coverage = {
            key: full_coverage.get(key)
            for key in ("entry_status", "entry_notes", "unresolved_targets")
            if key in full_coverage
        }
        locations = set(full_coverage.get("operation_sites_checked", []))
        for group in groups:
            locations.add(group["operation"]["location"])
            for key in ("facts", "security_checks"):
                locations.update(row.get("location") for row in group.get(key, []) if row.get("location"))
            for branch in group.get("branches", []):
                locations.update(branch.get("locations", []))
        run = conn.execute("SELECT target_repo FROM runs LIMIT 1").fetchone()
        return {
            "semantic_analysis": {
                "summary": analysis["summary"],
                "coverage": coverage,
                "operation_groups": groups,
            },
            "validation_contract": {
                "semantic_effect_hypotheses_are_untrusted": True,
                "semantic_refs_must_come_from_current_group_admissible_scope": True,
                "hypothesis_only_evidence_cannot_support_validation": True,
                "new_source_evidence_is_inline_and_runtime_numbered": True,
                "dimensions_require_status_reason_evidence_level_and_support": True,
                "confirmed_effect_chain": ["controlled_value_use", "security_behavior_change", "protected_operation", "concrete_impact"],
                "confirmed_effect_chain_requires_fresh_validation_evidence": True,
                "poc_produced_by_later_phase": True,
            },
            "verification_scope": {
                "target_repo": run["target_repo"],
                "seed_locations": sorted(locations),
                "seed_files": sorted({_source_file(location) for location in locations}),
                "seed_symbols": full_coverage.get("entry_symbols_checked", []),
            },
        }
    if task["kind"] == "poc_generation":
        finding = conn.execute("SELECT * FROM findings WHERE finding_id=?", (task["subject_id"],)).fetchone()
        if not finding:
            return payload
        group = semantic_group_context(conn, finding["group_id"])
        if not group:
            return payload
        validation = validation_context(conn, finding["group_id"]) or {}
        entry = entry_context(conn, group["entry_id"]) or {}
        allowed_entry_types = sorted({
            candidate_type
            for facet in entry.get("facets", [])
            for candidate_type in ENTRY_TYPE_MAP.get(facet.get("entry_type"), [facet.get("entry_type")] if facet.get("entry_type") else [])
        })
        evidence_rows = conn.execute(
            """SELECT evidence_id,kind,source,location,summary FROM evidence
               WHERE task_id IN (
                 SELECT task_id FROM semantic_analyses WHERE entry_id=?
                 UNION
                 SELECT task_id FROM validation_results WHERE group_id=?
               ) ORDER BY evidence_id""",
            (group["entry_id"], finding["group_id"]),
        ).fetchall()
        inherited_evidence = [dict(row) for row in evidence_rows]
        return {
            **payload,
            "finding": {
                "finding_id": finding["finding_id"], "root_cause_key": finding["root_cause_key"],
                "title": finding["title"], "classification": finding["classification"],
                "severity": finding["severity"], "cwe": finding["cwe"], "impact": finding["impact"],
            },
            "validation": validation,
            "operation_group": group,
            "entry": entry,
            "allowed_entry_types": allowed_entry_types,
            "inherited_evidence": inherited_evidence,
            "inherited_evidence_ids": [row["evidence_id"] for row in inherited_evidence],
            "output_contract": {
                "task_unit": "one deterministic PoC generation unit for one confirmed finding",
                "entry_type_constraint": "entry_type 必须来自 allowed_entry_types",
                "trigger_kind": ["adb_shell", "ability_want", "common_event", "ipc_client", "provider_query", "web_navigation", "jsbridge_call", "network", "crypto", "archive", "distributed", "generic"],
                "forbidden_outputs": ["classification", "exploitability", "severity", "cwe", "impact"],
                "form_selection": "受控值到敏感操作的完整触发链能用 hdc shell aa start 命令行表达时选 shell；需要应用上下文/复杂参数/回调/内部链路时选 arkts 并附最小工程复现步骤",
                "evidence_refs_scope": "evidence_refs 只能引用 inherited_evidence_ids 中已有的证据 id；新证据内联在 symbol_refs 的 evidence 数组，不创建证据 ID，编号和去重由运行时完成",
                "self_verification_required": "code/trigger.payload 引用的应用内符号必须逐一用 atlas 核验并写回 symbol_refs 与内联 evidence",
            },
        }
    return payload
