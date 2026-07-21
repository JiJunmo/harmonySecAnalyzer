"""Strict semantic contracts for flow-runtime worker submissions."""
from __future__ import annotations

from jsonschema import Draft202012Validator

from .common import *
from .store import row_json


SCHEMA_BY_TASK = {
    "entry_planning": "entry-plan-result.schema.json",
    "entry_exploration": "flow-task-result.schema.json",
    "shared_handler": "flow-task-result.schema.json",
    "chain_correlation": "flow-task-result.schema.json",
    "pattern_evaluation": "pattern-evaluation-result.schema.json",
    "flow_validation": "flow-validation-result.schema.json",
}


def normalize_submission(result, kind):
    """Apply deterministic invariants that should not consume another model turn."""
    if kind in {"entry_exploration", "shared_handler", "chain_correlation"}:
        for flow in result.get("flows", []):
            if flow.get("continuations"):
                flow["status"] = "open"
    return result


def schema_errors(kind, result):
    schema_name = SCHEMA_BY_TASK.get(kind)
    if not schema_name:
        return [f"unknown_task_kind:{kind}"]
    schema = read_json(SCHEMAS_DIR / schema_name)
    if not isinstance(schema, dict):
        return [f"missing_schema:{schema_name}"]
    errors = []
    for error in Draft202012Validator(schema).iter_errors(result):
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in error.absolute_path
        )
        errors.append(f"schema:{path}:{error.message}")
    return sorted(errors)


def validate_entry_plan(result, project_candidate_ids):
    errors = []
    assignments = {}

    def assign(candidate_ids, disposition):
        for candidate_id in candidate_ids:
            assignments.setdefault(candidate_id, set()).add(disposition)

    for entry in result.get("entries", []):
        assign(entry.get("project_candidate_ids", []), "resolved_entry")
    for row in result.get("excluded_candidates", []):
        assign(row.get("project_candidate_ids", []), "excluded")
    for row in result.get("gaps", []):
        assign(row.get("project_candidate_ids", []), "gap")
    expected = set(project_candidate_ids)
    actual = set(assignments)
    if expected - actual:
        errors.append("unaccounted_project_candidates:" + ",".join(sorted(expected - actual)))
    if actual - expected:
        errors.append("unknown_project_candidates:" + ",".join(sorted(actual - expected)))
    conflicts = sorted(key for key, values in assignments.items() if len(values) != 1)
    if conflicts:
        errors.append("conflicting_project_candidates:" + ",".join(conflicts))
    keys = [entry.get("entry_key") for entry in result.get("entries", [])]
    if len(keys) != len(set(keys)):
        errors.append("duplicate_entry_key")
    evidence = {row.get("evidence_id") for row in result.get("evidence", [])}
    for row in list(result.get("entries", [])) + list(result.get("excluded_candidates", [])) + list(result.get("gaps", [])):
        missing = set(row.get("evidence_refs", [])) - evidence
        if missing:
            errors.append("unknown_evidence:" + ",".join(sorted(missing)))
    return errors


def validate_flow_result(result, task, conn):
    errors = []
    seen = set()
    submitted_evidence = {row.get("evidence_id") for row in result.get("evidence", [])}
    stored_evidence = {row["evidence_id"] for row in conn.execute("SELECT evidence_id FROM evidence")}
    known_evidence = submitted_evidence | stored_evidence
    allowed_roots = set()
    allowed_parent_flows = set()
    if task["kind"] == "entry_exploration":
        allowed_roots.add(task["subject_id"])
    else:
        for row in conn.execute("SELECT flow_id FROM continuations WHERE task_id=?", (task["task_id"],)):
            allowed_parent_flows.add(row["flow_id"])
            parent = conn.execute("SELECT root_entry_id FROM flows WHERE flow_id=?", (row["flow_id"],)).fetchone()
            if parent:
                allowed_roots.add(parent["root_entry_id"])
    for flow in result.get("flows", []):
        flow_key = flow_identity_key(flow)
        if flow_key in seen:
            errors.append(f"duplicate_flow_key:{flow_key}")
        seen.add(flow_key)
        if flow.get("root_entry_id") not in allowed_roots:
            errors.append(f"flow_entry_mismatch:{flow_key}")
        if task["kind"] == "entry_exploration" and flow.get("parent_flow_id"):
            errors.append(f"entry_flow_cannot_have_parent:{flow_key}")
        if task["kind"] != "entry_exploration" and flow.get("parent_flow_id") not in allowed_parent_flows:
            errors.append(f"continuation_parent_mismatch:{flow_key}")
        fact_keys = {fact.get("fact_key") for fact in flow.get("facts", [])}
        existing_flow = conn.execute("SELECT flow_id FROM flows WHERE flow_key=?", (flow_key,)).fetchone()
        existing_facts = set()
        if existing_flow:
            existing_facts = {
                row["fact_key"] for row in conn.execute(
                    "SELECT fact_key FROM facts WHERE flow_id=?", (existing_flow["flow_id"],)
                )
            }
        inherited_facts = set()
        parent_id = flow.get("parent_flow_id")
        seen_parents = set()
        while parent_id and parent_id not in seen_parents:
            seen_parents.add(parent_id)
            inherited_facts.update(
                row["fact_key"] for row in conn.execute(
                    "SELECT fact_key FROM facts WHERE flow_id=?", (parent_id,)
                )
            )
            parent = conn.execute("SELECT parent_flow_id FROM flows WHERE flow_id=?", (parent_id,)).fetchone()
            parent_id = parent["parent_flow_id"] if parent else None
        known = fact_keys | existing_facts | inherited_facts
        for edge in flow.get("edges", []):
            if edge.get("from") not in known or edge.get("to") not in known:
                errors.append(f"edge_unknown_fact:{flow_key}:{edge.get('from')}->{edge.get('to')}")
        refs = []
        refs.extend(ref for fact in flow.get("facts", []) for ref in fact.get("evidence_refs", []))
        refs.extend(ref for edge in flow.get("edges", []) for ref in edge.get("evidence_refs", []))
        refs.extend(ref for cont in flow.get("continuations", []) for ref in cont.get("evidence_refs", []))
        missing_evidence = set(refs) - known_evidence
        if missing_evidence:
            errors.append(f"unknown_evidence:{flow_key}:" + ",".join(sorted(missing_evidence)))
        continuations = flow.get("continuations", [])
        if flow.get("status") == "open" and not continuations:
            errors.append(f"open_flow_requires_continuation:{flow_key}")
        if flow.get("status") in TERMINAL_FLOW_STATES and continuations:
            errors.append(f"terminal_flow_cannot_have_continuation:{flow_key}")
    return errors


def validate_pattern_result(result, task, conn):
    errors = []
    if result.get("flow_id") != task["subject_id"]:
        errors.append("pattern_flow_mismatch")
        return errors
    flow = conn.execute(
        "SELECT root_entry_id FROM flows WHERE flow_id=?", (task["subject_id"],)
    ).fetchone()
    if not flow:
        return ["flow_not_found"]
    entry = conn.execute(
        "SELECT profiles_json FROM entries WHERE entry_id=?", (flow["root_entry_id"],)
    ).fetchone()
    profiles = set(row_json(entry, "profiles_json", []))
    expected = {
        (capability["capability_id"], pattern_id)
        for capability in load_capabilities()
        if capability["capability_id"] in profiles
        for pattern_id in capability.get("pattern_ids", [])
    }
    actual = {(row.get("capability_id"), row.get("pattern_id")) for row in result.get("assessments", [])}
    if actual != expected:
        render = lambda rows: ",".join(f"{cap}/{pattern}" for cap, pattern in sorted(rows))
        errors.append("pattern_disposition_mismatch:expected=" + render(expected) + ":actual=" + render(actual))
    known_evidence = {row["evidence_id"] for row in conn.execute("SELECT evidence_id FROM evidence")}
    missing = {ref for row in result.get("assessments", []) for ref in row.get("evidence_refs", [])} - known_evidence
    if missing:
        errors.append("unknown_evidence:" + ",".join(sorted(missing)))
    return errors


def validate_validation_result(result, task, conn):
    errors = []
    flow_id = task["subject_id"]
    if result.get("flow_id") != flow_id:
        errors.append("validation_flow_mismatch")
        return errors
    flow = conn.execute("SELECT * FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
    if not flow:
        return ["flow_not_found"]
    root = result.get("root_cause", {})
    if root.get("branch") != flow["branch_key"]:
        errors.append("root_branch_mismatch")
    if root.get("controlled_property") != flow["controlled_property"]:
        errors.append("root_controlled_property_mismatch")
    classification = result.get("classification")
    gates = result.get("gates", {})
    if classification == "confirmed_vulnerability":
        if flow["status"] != "connected":
            errors.append("confirmed_requires_connected_flow")
        if not all(gates.get(name) is True for name in (
            "externally_reachable", "attacker_controlled", "operation_reached",
            "guard_absent_or_bypassed", "boundary_violated", "observable_effect",
        )):
            errors.append("confirmed_requires_all_six_gates")
        has_effect = conn.execute(
            "SELECT 1 FROM facts WHERE flow_id=? AND fact_type='effect' LIMIT 1", (flow_id,)
        ).fetchone()
        if not has_effect:
            errors.append("confirmed_requires_effect_fact")
    if classification == "protected_exposure" and flow["status"] != "blocked":
        errors.append("protected_requires_blocked_flow")
    if classification == "benign_business_flow" and flow["status"] != "benign":
        errors.append("benign_requires_benign_flow")
    if classification in {"insufficient_evidence", "residual_risk"} and flow["status"] != "gap":
        errors.append("uncertain_requires_gap_flow")
    known_evidence = {row["evidence_id"] for row in conn.execute("SELECT evidence_id FROM evidence")}
    missing = set(result.get("evidence_refs", [])) - known_evidence
    if missing:
        errors.append("unknown_evidence:" + ",".join(sorted(missing)))
    return errors


def validate_submission(result, task, conn, project_candidate_ids=None):
    errors = schema_errors(task["kind"], result)
    if result.get("task_id") != task["task_id"]:
        errors.append("task_id_mismatch")
    if errors:
        return sorted(set(errors))
    if task["kind"] == "entry_planning":
        errors.extend(validate_entry_plan(result, project_candidate_ids or []))
    elif task["kind"] in {"entry_exploration", "shared_handler", "chain_correlation"}:
        errors.extend(validate_flow_result(result, task, conn))
    elif task["kind"] == "pattern_evaluation":
        errors.extend(validate_pattern_result(result, task, conn))
    elif task["kind"] == "flow_validation":
        errors.extend(validate_validation_result(result, task, conn))
    return sorted(set(errors))
