"""Strict semantic contracts for flow-runtime worker submissions."""
from __future__ import annotations

import json

from jsonschema import Draft202012Validator

from .common import *
from .store import row_json


SCHEMA_BY_TASK = {
    "entry_resolution": "entry-resolution-result.schema.json",
    "entry_path_discovery": "flow-task-result.schema.json",
    "continuation_resolution": "flow-task-result.schema.json",
    "security_assessment": "security-assessment-result.schema.json",
}


def _flow_lineage(conn, flow_id):
    lineage = []
    seen = set()
    current = flow_id
    while current and current not in seen:
        seen.add(current)
        lineage.append(current)
        row = conn.execute("SELECT parent_flow_id FROM flows WHERE flow_id=?", (current,)).fetchone()
        current = row["parent_flow_id"] if row else None
    return lineage


def _flow_evidence(conn, flow_ids):
    evidence = set()
    for flow_id in flow_ids:
        for table in ("facts", "edges", "continuations"):
            for row in conn.execute(f"SELECT evidence_json FROM {table} WHERE flow_id=?", (flow_id,)):
                evidence.update(json.loads(row["evidence_json"]))
    return evidence


def _path_flow_ids(conn, path_id):
    row = conn.execute("SELECT flow_ids_json FROM paths WHERE path_id=?", (path_id,)).fetchone()
    return row_json(row, "flow_ids_json", []) if row else []


def normalize_submission(result, task, conn=None):
    """Apply deterministic invariants that should not consume another model turn."""
    kind = task["kind"]
    if kind in {"entry_path_discovery", "continuation_resolution"}:
        for flow in result.get("flows", []):
            if kind == "entry_path_discovery":
                flow["root_entry_id"] = task["subject_id"]
                flow["parent_flow_id"] = None
            elif conn is not None and flow.get("parent_flow_id"):
                parent = conn.execute(
                    "SELECT root_entry_id FROM flows WHERE flow_id=?", (flow["parent_flow_id"],)
                ).fetchone()
                if parent:
                    flow["root_entry_id"] = parent["root_entry_id"]
            if flow.get("continuations"):
                flow["status"] = "open"
    elif kind == "security_assessment":
        result["path_id"] = task["subject_id"]
        if conn is not None:
            flow = conn.execute(
                """SELECT f.branch_key,f.controlled_property FROM paths p
                   JOIN flows f ON f.flow_id=p.terminal_flow_id WHERE p.path_id=?""",
                (task["subject_id"],),
            ).fetchone()
            if flow:
                for assessment in result.get("assessments", []):
                    root = assessment.get("root_cause")
                    if isinstance(root, dict):
                        root["branch"] = flow["branch_key"]
                        root["controlled_property"] = flow["controlled_property"]
                        operation_fact_id = assessment.get("operation_fact_id")
                        if operation_fact_id:
                            operation = conn.execute(
                                "SELECT location FROM facts WHERE fact_id=?", (operation_fact_id,)
                            ).fetchone()
                            if operation and operation["location"]:
                                root["operation_location"] = operation["location"]
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


def validate_entry_resolution(result, project_candidate_ids):
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
    known_evidence = set(submitted_evidence)
    allowed_roots = set()
    allowed_parent_flows = set()
    if task["kind"] == "entry_path_discovery":
        allowed_roots.add(task["subject_id"])
    else:
        for row in conn.execute("SELECT flow_id FROM continuations WHERE task_id=?", (task["task_id"],)):
            allowed_parent_flows.add(row["flow_id"])
            parent = conn.execute("SELECT root_entry_id FROM flows WHERE flow_id=?", (row["flow_id"],)).fetchone()
            if parent:
                allowed_roots.add(parent["root_entry_id"])
    submitted_parents = {
        flow.get("parent_flow_id") for flow in result.get("flows", [])
        if flow.get("parent_flow_id")
    }
    if task["kind"] != "entry_path_discovery":
        missing_parents = allowed_parent_flows - submitted_parents
        if missing_parents:
            errors.append("unaccounted_continuation_parents:" + ",".join(sorted(missing_parents)))
        inherited_ids = set()
        for parent_flow_id in allowed_parent_flows:
            inherited_ids.update(_flow_lineage(conn, parent_flow_id))
        known_evidence.update(_flow_evidence(conn, inherited_ids))
    for flow in result.get("flows", []):
        identity_key = flow_identity_key(flow)
        if identity_key in seen:
            errors.append(f"duplicate_flow_identity:{identity_key}")
        seen.add(identity_key)
        if flow.get("root_entry_id") not in allowed_roots:
            errors.append(f"flow_entry_mismatch:{identity_key}")
        if task["kind"] == "entry_path_discovery" and flow.get("parent_flow_id"):
            errors.append(f"entry_flow_cannot_have_parent:{identity_key}")
        if task["kind"] != "entry_path_discovery" and flow.get("parent_flow_id") not in allowed_parent_flows:
            errors.append(f"continuation_parent_mismatch:{identity_key}")
        fact_keys = {fact.get("fact_key") for fact in flow.get("facts", [])}
        if len(fact_keys) != len(flow.get("facts", [])):
            errors.append(f"duplicate_fact_key:{identity_key}")
        existing_flow = conn.execute("SELECT flow_id FROM flows WHERE identity_key=?", (identity_key,)).fetchone()
        existing_facts = set()
        if existing_flow:
            known_evidence.update(_flow_evidence(conn, [existing_flow["flow_id"]]))
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
                errors.append(f"edge_unknown_fact:{identity_key}:{edge.get('from')}->{edge.get('to')}")
        refs = []
        refs.extend(ref for fact in flow.get("facts", []) for ref in fact.get("evidence_refs", []))
        refs.extend(ref for edge in flow.get("edges", []) for ref in edge.get("evidence_refs", []))
        refs.extend(ref for cont in flow.get("continuations", []) for ref in cont.get("evidence_refs", []))
        missing_evidence = set(refs) - known_evidence
        if missing_evidence:
            errors.append(f"unknown_evidence:{identity_key}:" + ",".join(sorted(missing_evidence)))
        continuations = flow.get("continuations", [])
        if flow.get("status") == "open" and not continuations:
            errors.append(f"open_flow_requires_continuation:{identity_key}")
        if flow.get("status") in TERMINAL_FLOW_STATES and continuations:
            errors.append(f"terminal_flow_cannot_have_continuation:{identity_key}")
    return errors


def validate_security_assessment(result, task, conn):
    errors = []
    path_id = task["subject_id"]
    if result.get("path_id") != path_id:
        errors.append("assessment_path_mismatch")
        return errors
    path = conn.execute("SELECT * FROM paths WHERE path_id=?", (path_id,)).fetchone()
    if not path:
        return ["path_not_found"]
    flow = conn.execute("SELECT * FROM flows WHERE flow_id=?", (path["terminal_flow_id"],)).fetchone()
    known_evidence = _flow_evidence(conn, _path_flow_ids(conn, path_id))
    entry = conn.execute("SELECT payload_json FROM entries WHERE entry_id=?", (path["root_entry_id"],)).fetchone()
    if entry:
        known_evidence.update(row_json(entry, "payload_json", {}).get("evidence_refs", []))
    submitted_evidence = {row.get("evidence_id") for row in result.get("evidence", [])}
    known_evidence.update(submitted_evidence)
    run = conn.execute("SELECT capability_filter_json FROM runs LIMIT 1").fetchone()
    capabilities = {
        row["capability_id"]: row
        for row in load_capabilities(row_json(run, "capability_filter_json", []))
    }
    patterns = {
        pattern_id: capability["capability_id"]
        for capability in capabilities.values()
        for pattern_id in capability.get("pattern_ids", [])
    }
    flow_ids = _path_flow_ids(conn, path_id)
    placeholders = ",".join("?" for _ in flow_ids)
    path_facts = {
        row["fact_id"]: row for row in conn.execute(
            f"SELECT * FROM facts WHERE flow_id IN ({placeholders})", flow_ids,
        )
    } if flow_ids else {}
    has_effect = any(row["fact_type"] == "effect" for row in path_facts.values())
    seen = set()
    for index, assessment in enumerate(result.get("assessments", [])):
        label = f"assessment[{index}]"
        capability_id = assessment.get("capability_id")
        pattern_id = assessment.get("pattern_id")
        if (capability_id is None) != (pattern_id is None):
            errors.append(f"{label}:capability_and_pattern_must_both_be_set_or_null")
        if capability_id is not None and capability_id not in capabilities:
            errors.append(f"{label}:unknown_capability:{capability_id}")
        if pattern_id is not None:
            if pattern_id not in patterns:
                errors.append(f"{label}:unknown_pattern:{pattern_id}")
            elif capability_id != patterns[pattern_id]:
                errors.append(f"{label}:pattern_capability_mismatch:{pattern_id}")
        root = assessment.get("root_cause", {})
        identity = (pattern_id, assessment.get("category"), assessment.get("operation_fact_id"), root.get("boundary"))
        if identity in seen:
            errors.append(f"{label}:duplicate_assessment")
        seen.add(identity)
        operation_fact_id = assessment.get("operation_fact_id")
        operation_fact = path_facts.get(operation_fact_id) if operation_fact_id else None
        if operation_fact_id and operation_fact is None:
            errors.append(f"{label}:operation_fact_not_in_path:{operation_fact_id}")
        elif operation_fact is not None and operation_fact["fact_type"] != "operation":
            errors.append(f"{label}:operation_fact_wrong_type:{operation_fact_id}")
        if root.get("branch") != flow["branch_key"]:
            errors.append(f"{label}:root_branch_mismatch")
        if root.get("controlled_property") != flow["controlled_property"]:
            errors.append(f"{label}:root_controlled_property_mismatch")
        if operation_fact is not None and operation_fact["location"] and normalize_location(root.get("operation_location")) != normalize_location(operation_fact["location"]):
            errors.append(f"{label}:root_operation_location_mismatch")
        checks = assessment.get("exploitability", {})
        refs = list(assessment.get("evidence_refs", []))
        business_intent = assessment.get("business_intent") or {}
        security_boundary = assessment.get("security_boundary") or {}
        refs.extend(business_intent.get("evidence_refs", []))
        refs.extend(security_boundary.get("evidence_refs", []))
        for guard in assessment.get("guards", []):
            refs.extend(guard.get("evidence_refs", []))
        for counter in assessment.get("counter_evidence", []):
            refs.extend(counter.get("evidence_refs", []))
        classification = assessment.get("classification")
        if classification == "confirmed_vulnerability":
            if not all(checks.get(name) is True for name in SIX_EXPLOITABILITY_CHECKS):
                errors.append(f"{label}:confirmed_requires_all_six_checks")
            if assessment.get("counter_evidence"):
                errors.append(f"{label}:confirmed_cannot_have_counter_evidence")
            if any(guard.get("effectiveness") == "effective" for guard in assessment.get("guards", [])):
                errors.append(f"{label}:confirmed_cannot_have_effective_guard")
            if operation_fact is None:
                errors.append(f"{label}:confirmed_requires_operation_fact")
            if not has_effect:
                errors.append(f"{label}:confirmed_requires_effect_fact")
        elif all(checks.get(name) is True for name in SIX_EXPLOITABILITY_CHECKS):
            errors.append(f"{label}:demoted_result_has_all_six_checks_true")
        if security_boundary and security_boundary.get("violation") is not checks.get("boundary_violated"):
            errors.append(f"{label}:security_boundary_mismatch")
        if classification == "protected_exposure":
            if checks.get("guard_bypassed_or_absent") is not False:
                errors.append(f"{label}:protected_guard_check_must_be_false")
            if not any(guard.get("effectiveness") == "effective" for guard in assessment.get("guards", [])):
                errors.append(f"{label}:protected_requires_effective_guard")
        if classification == "benign_business_flow" and checks.get("boundary_violated") is not False:
            errors.append(f"{label}:benign_boundary_check_must_be_false")
        missing = set(refs) - known_evidence
        if missing:
            errors.append(f"{label}:unknown_evidence:" + ",".join(sorted(missing)))
    return errors


def validate_submission(result, task, conn, project_candidate_ids=None):
    errors = schema_errors(task["kind"], result)
    if result.get("task_id") != task["task_id"]:
        errors.append("task_id_mismatch")

    kind = task["kind"]
    rows_by_kind = {
        "entry_resolution": ("entries", "excluded_candidates", "gaps"),
        "entry_path_discovery": ("flows",),
        "continuation_resolution": ("flows",),
        "security_assessment": ("assessments",),
    }
    semantic_shape_ok = all(
        isinstance(result.get(field), list)
        and all(isinstance(row, dict) for row in result.get(field, []))
        for field in rows_by_kind.get(kind, ())
    )
    if kind in {"entry_path_discovery", "continuation_resolution"} and semantic_shape_ok:
        semantic_shape_ok = all(
            all(
                isinstance(flow.get(field), list)
                and all(isinstance(row, dict) for row in flow.get(field, []))
                for field in ("facts", "edges", "continuations")
            )
            for flow in result["flows"]
        )

    # Return field and semantic errors together when the collections are usable,
    # so one retry can correct the whole submission contract.
    if not semantic_shape_ok:
        return sorted(set(errors))
    if kind == "entry_resolution":
        errors.extend(validate_entry_resolution(result, project_candidate_ids or []))
    elif kind in {"entry_path_discovery", "continuation_resolution"}:
        errors.extend(validate_flow_result(result, task, conn))
    elif kind == "security_assessment":
        errors.extend(validate_security_assessment(result, task, conn))
    return sorted(set(errors))
