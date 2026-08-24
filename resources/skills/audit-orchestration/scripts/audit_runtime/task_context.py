"""Build immutable semantic, validation and poc task documents from canonical state."""
from __future__ import annotations

import hashlib

from .common import SCHEMAS_DIR, SCRIPTS_DIR, canonical_json, load_capabilities
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


def _result_protocol(paths, task):
    runtime = str((SCRIPTS_DIR / "audit_orchestrator.py").resolve())
    run_dir = str(paths["root"])
    draft_file = str(
        paths["tasks"] / f"{task['task_id']}.attempt-{task['attempts']}.draft.json"
    )
    return {
        "writer": "audit_orchestrator.py task-submit",
        "draft_file": draft_file,
        "runtime_commits_result": True,
        "instructions": [
            "只把当前任务的结论草稿写入 draft_file",
            "必须调用 commands.submit 由 Python 规范化、校验并正式落库",
            "accepted=false 时按 errors 修正 draft_file 后再次调用",
            "只有 accepted=true 且 status=completed 才允许结束子任务",
        ],
        "commands": {
            "submit": [
                "python3", runtime, "task-submit", run_dir,
                "--task-id", task["task_id"],
                "--attempt", str(task["attempts"]),
                "--input", draft_file,
            ],
        },
    }


def task_context(conn, task, paths=None):
    payload = row_json(task, "input_json", {})
    entry = entry_context(conn, task["subject_id"])
    if task["kind"] == "component_semantic_analysis":
        profile_ids = set(entry.get("profiles", [])) if entry else set()
        profiles = [{
            **{key: row.get(key) for key in ("capability_id", "title", "domain", "entry_types")},
            "analysis_scope": row.get("analysis_scope", "component"),
        } for row in load_capabilities() if row["capability_id"] in profile_ids]
        analysis_contract = {
            "task_unit": "one bounded round of a persistent component exploration",
            "phases": ["claim_node", "query_atlas", "record_step", "repeat_until_round_complete", "finish_round"],
            "exploration_unit": "a security-semantic checkpoint, not every ordinary function",
            "inline_analysis": "continue through ordinary project functions inside one step until security semantics change or the step budget is exhausted",
            "checkpoint_when": ["security_state_changes", "security_relevant_branch", "component_boundary", "unresolved_target", "step_budget_exhausted"],
            "round_policy": "finish the active path first; continue with another short path while the cumulative function budget remains",
            "long_path_policy": "persist the current segment and resume the queued continuation in the next round without creating a coverage gap",
            "group_by": ["capability", "operation_location", "controlled_properties", "security_semantics"],
            "component_completion": "all discovered nodes are completed, stopped with a reason, or recorded as coverage gaps",
            "sensitive_operation_is_not_a_stop_condition": True,
            "stop_at": ["component_boundary", "platform_boundary", "ordinary_third_party_boundary", "security_influence_ended", "return_or_throw"],
            "component_call_control": {
                "invocation_control": "whether the current component input controls reaching the component call",
                "parameter_mappings": "data mappings only; may be empty",
            },
            "capability_entry_types": "priority hints for investigation, never component exclusion rules",
            "minimum_evidence_chain": "omit only irrelevant nodes; retain every branch, transform and security check that can change later validation",
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
        context = {
            **payload,
            "entry": entry,
            "audit_scope": profiles,
            "analysis_contract": analysis_contract,
        }
        if paths:
            from .semantic_exploration import (
                MAX_COMPONENT_ROUNDS, MAX_COMPONENT_WORK_NODES,
                ROUND_FUNCTION_BUDGET, STEP_SYMBOL_BUDGET,
            )

            exploration = conn.execute(
                "SELECT * FROM component_explorations WHERE entry_id=?", (task["subject_id"],)
            ).fetchone()
            node_counts = {
                row["status"]: row["n"] for row in conn.execute(
                    """SELECT n.status,COUNT(*) n FROM exploration_nodes n
                       JOIN component_explorations x ON x.exploration_id=n.exploration_id
                       WHERE x.entry_id=? GROUP BY n.status""", (task["subject_id"],)
                )
            }
            runtime = str((SCRIPTS_DIR / "audit_orchestrator.py").resolve())
            run_dir = str(paths["root"])
            step_file = str(
                paths["tasks"] / f"{task['task_id']}.attempt-{task['attempts']}.step.json"
            )
            common = [runtime]
            context["exploration_protocol"] = {
                "run_dir": run_dir,
                "task_id": task["task_id"],
                "attempt": task["attempts"],
                "round_no": (exploration["round_no"] + 1) if exploration else 1,
                "current_status": exploration["status"] if exploration else "pending",
                "node_counts": node_counts,
                "round_function_budget": ROUND_FUNCTION_BUDGET,
                "step_symbol_budget": STEP_SYMBOL_BUDGET,
                "component_checkpoint_limit": MAX_COMPONENT_WORK_NODES,
                "component_round_limit": MAX_COMPONENT_ROUNDS,
                "step_file": step_file,
                "step_schema_file": str(SCHEMAS_DIR / "component-exploration-step.schema.json"),
                "semantic_schema_file": str(SCHEMAS_DIR / "component-semantic-result.schema.json"),
                "commands": {
                    "next": ["python3", *common, "explore-next", run_dir, "--task-id",
                             task["task_id"], "--attempt", str(task["attempts"])],
                    "record": ["python3", *common, "explore-record", run_dir, "--task-id",
                               task["task_id"], "--attempt", str(task["attempts"]),
                               "--input", step_file],
                    "finish": ["python3", *common, "explore-finish", run_dir, "--task-id",
                               task["task_id"], "--attempt", str(task["attempts"])],
                },
            }
        return context
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
            for key in ("entry_status", "external_entry_status", "confirmed_external_candidate_ids", "entry_notes", "unresolved_targets")
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
        context = {
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
                "attacker_controlled_accepts": ["security_critical_parameter", "operation_invocation"],
                "source_read_scope": "all implementations needed to prove or disprove this operation group, including callers, callees, inheritance, dependencies and component-chain endpoints",
                "forbidden_scope_expansion": ["discover_independent_operation", "create_operation_group", "construct_new_path", "rewrite_semantic_facts"],
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
        if paths:
            context["result_protocol"] = _result_protocol(paths, task)
        return context
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
        context = {
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
        if paths:
            context["result_protocol"] = _result_protocol(paths, task)
        return context
    return payload
