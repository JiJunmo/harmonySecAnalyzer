"""Strict contracts separating source semantics from security judgments."""
from __future__ import annotations

from jsonschema import Draft202012Validator

from .common import *
from .store import row_json
from .task_context import semantic_group_context


SCHEMA_BY_TASK = {
    "component_semantic_analysis": "component-semantic-result.schema.json",
    "exploitability_validation": "exploitability-validation-result.schema.json",
}


def normalize_submission(result, task, conn=None):
    if not isinstance(result, dict):
        return result
    result["entry_id"] = task["subject_id"]
    if task["kind"] == "component_semantic_analysis":
        # Edges belong to individual groups and are rebuilt below from ordered facts.
        result.pop("edges", None)
        coverage = result.get("coverage", {})
        if not isinstance(coverage, dict) or not isinstance(result.get("operation_groups", []), list):
            return result
        checked = coverage.get("operation_sites_checked", [])
        checked_sites = set(checked) if isinstance(checked, list) and all(isinstance(v, str) for v in checked) else set()
        for group in result.get("operation_groups", []):
            if not isinstance(group, dict):
                continue
            controlled = group.get("controlled_properties", [])
            if isinstance(controlled, list) and all(isinstance(v, str) for v in controlled):
                group["controlled_properties"] = sorted(set(controlled))
            branches = group.get("branches", [])
            if isinstance(branches, list) and all(isinstance(row, dict) for row in branches):
                group["branches"] = sorted(branches, key=lambda row: canonical_json([
                    normalize_text(row.get("condition")),
                    sorted(row.get("locations", [])) if isinstance(row.get("locations", []), list) else [],
                ]))
            facts = group.get("facts", [])
            if not isinstance(facts, list) or not all(isinstance(fact, dict) for fact in facts):
                continue
            used_keys = set()
            for index, fact in enumerate(facts, 1):
                base = str(fact.get("fact_key") or f"fact-{index}")
                key = base
                suffix = 2
                while key in used_keys:
                    key = f"{base}-{suffix}"
                    suffix += 1
                fact["fact_key"] = key
                used_keys.add(key)

            operation = group.get("operation", {})
            if not isinstance(operation, dict):
                continue
            operation_facts = [fact for fact in facts if fact.get("type") == "operation"]
            if operation_facts:
                canonical_operation = operation_facts[0]
                canonical_operation["body"] = operation.get("body", canonical_operation.get("body"))
                canonical_operation["location"] = operation.get("location")
                for extra in operation_facts[1:]:
                    extra["type"] = "reachability"
            elif operation.get("body") and operation.get("location"):
                key = "operation"
                suffix = 2
                while key in used_keys:
                    key = f"operation-{suffix}"
                    suffix += 1
                facts.append({
                    "fact_key": key,
                    "type": "operation",
                    "body": operation["body"],
                    "location": operation["location"],
                    "evidence_refs": list(group.get("evidence_refs", [])),
                })

            # Facts are an ordered trace. Persisting their adjacency is deterministic
            # and should not be delegated to the model as another fragile identifier contract.
            group["edges"] = [{
                "from": source["fact_key"],
                "to": target["fact_key"],
                "kind": "next",
                "evidence_refs": sorted({
                    value for fact in (source, target)
                    for value in (fact.get("evidence_refs", []) if isinstance(fact.get("evidence_refs", []), list) else [])
                    if isinstance(value, str)
                }),
            } for source, target in zip(facts, facts[1:])]
            if operation.get("location"):
                checked_sites.add(operation["location"])
        merged_groups = {}
        unmergeable_groups = []
        for group in result.get("operation_groups", []):
            if not isinstance(group, dict):
                unmergeable_groups.append(group)
                continue
            operation = group.get("operation")
            controlled = group.get("controlled_properties")
            if (not isinstance(operation, dict) or not operation.get("location")
                    or not isinstance(controlled, list)):
                unmergeable_groups.append(group)
                continue
            identity = operation_group_identity(task["subject_id"], group)
            existing = merged_groups.get(identity)
            if existing is None:
                merged_groups[identity] = group
                continue
            if len(group.get("facts", [])) > len(existing.get("facts", [])):
                group, existing = existing, group
                merged_groups[identity] = existing
            for key in ("branches", "security_checks"):
                rows = existing.get(key, []) + group.get(key, [])
                existing[key] = list({canonical_json(row): row for row in rows}.values())
            existing["evidence_refs"] = sorted(set(existing.get("evidence_refs", [])) | set(group.get("evidence_refs", [])))
            existing_context = existing.get("context", {})
            duplicate_context = group.get("context", {})
            existing_context["evidence_refs"] = sorted(
                set(existing_context.get("evidence_refs", [])) | set(duplicate_context.get("evidence_refs", []))
            )
        result["operation_groups"] = list(merged_groups.values()) + unmergeable_groups
        normalized_calls = {}
        for component_call in result.get("component_calls", []):
            if not isinstance(component_call, dict):
                continue
            mappings = component_call.get("parameter_mappings", [])
            if isinstance(mappings, list) and all(isinstance(row, dict) for row in mappings):
                component_call["parameter_mappings"] = sorted(
                    {canonical_json(row): row for row in mappings}.values(),
                    key=canonical_json,
                )
            identity = canonical_json([
                component_call.get("target_component_id"), normalize_location(component_call.get("call_location")),
                component_call.get("parameter_mappings", []), component_call.get("principal_transition", {}),
            ])
            normalized_calls.setdefault(identity, component_call)
        result["component_calls"] = list(normalized_calls.values())
        coverage["operation_sites_checked"] = sorted(checked_sites)
    elif task["kind"] == "exploitability_validation":
        for validation in result.get("validations", []):
            if not isinstance(validation, dict):
                continue
            for key in ("impact", "severity", "cwe", "poc", "demotion_reason", "evidence_gap"):
                value = validation.get(key)
                if isinstance(value, str) and not value.strip():
                    validation.pop(key)
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


def _semantic_refs(group):
    refs = list(group.get("evidence_refs", []))
    for key in ("facts", "edges", "branches", "security_checks"):
        for row in group.get(key, []):
            refs.extend(row.get("evidence_refs", []))
    refs.extend(group.get("context", {}).get("evidence_refs", []))
    refs.extend(group.get("availability", {}).get("evidence_refs", []))
    return refs


def _component_call_refs(component_call):
    refs = list(component_call.get("evidence_refs", []))
    refs.extend(component_call.get("principal_transition", {}).get("evidence_refs", []))
    for security_check in component_call.get("security_checks", []):
        refs.extend(security_check.get("evidence_refs", []))
    return refs


def validate_semantic_analysis(result, task, conn):
    errors = []
    if result.get("task_id") != task["task_id"]:
        errors.append("task_id_mismatch")
    if result.get("entry_id") != task["subject_id"]:
        errors.append("entry_id_mismatch")
    evidence_ids = [row.get("evidence_id") for row in result.get("evidence", [])]
    if len(evidence_ids) != len(set(evidence_ids)):
        errors.append("duplicate_evidence_id")
    known_evidence = set(evidence_ids)
    coverage = result.get("coverage", {})
    entry_status = coverage.get("entry_status")
    if entry_status == "confirmed" and not coverage.get("entry_symbols_checked"):
        errors.append("confirmed_entry_requires_checked_symbol")
    if entry_status == "excluded" and (result.get("operation_groups") or result.get("component_calls")):
        errors.append("excluded_entry_cannot_have_semantic_outputs")

    model_keys = []
    identities = []
    for index, group in enumerate(result.get("operation_groups", [])):
        label = f"operation_groups[{index}]"
        model_keys.append(group.get("group_key"))
        identities.append(operation_group_identity(task["subject_id"], group))
        missing = set(_semantic_refs(group)) - known_evidence
        if missing:
            errors.append(f"{label}:unknown_evidence:" + ",".join(sorted(missing)))
    if len(model_keys) != len(set(model_keys)):
        errors.append("duplicate_group_key")
    if len(identities) != len(set(identities)):
        errors.append("equivalent_operation_groups_must_merge")
    payload = row_json(task, "input_json", {})
    entry = conn.execute("SELECT profiles_json FROM entries WHERE entry_id=?", (task["subject_id"],)).fetchone()
    allowed_capabilities = set(row_json(entry, "profiles_json", [])) if entry else set()
    run = conn.execute("SELECT audit_mode FROM runs LIMIT 1").fetchone()
    for index, group in enumerate(result.get("operation_groups", [])):
        capability_id = group.get("capability_id")
        if run and run["audit_mode"] == "capability" and not capability_id:
            errors.append(f"operation_groups[{index}]:capability_id_required_in_scoped_audit")
        if capability_id and capability_id not in allowed_capabilities:
            errors.append(f"operation_groups[{index}]:capability_outside_audit_scope:{capability_id}")
    project = read_json(payload.get("project_model"), {})
    known_components = {
        row.get("component_id") for row in project.get("components", []) if row.get("component_id")
    }
    call_keys = []
    call_identities = []
    for index, component_call in enumerate(result.get("component_calls", [])):
        label = f"component_calls[{index}]"
        call_keys.append(component_call.get("call_key"))
        call_identities.append(canonical_json([
            component_call.get("target_component_id"), normalize_location(component_call.get("call_location")),
            component_call.get("parameter_mappings", []), component_call.get("principal_transition", {}),
        ]))
        if component_call.get("target_component_id") not in known_components:
            errors.append(f"{label}:unknown_target_component")
        missing = set(_component_call_refs(component_call)) - known_evidence
        if missing:
            errors.append(f"{label}:unknown_evidence:" + ",".join(sorted(missing)))
    if len(call_keys) != len(set(call_keys)):
        errors.append("duplicate_call_key")
    if len(call_identities) != len(set(call_identities)):
        errors.append("equivalent_component_calls_must_merge")
    return errors


def validate_exploitability(result, task, conn):
    errors = []
    if result.get("task_id") != task["task_id"]:
        errors.append("task_id_mismatch")
    if result.get("entry_id") != task["subject_id"]:
        errors.append("entry_id_mismatch")
    expected = {row["group_id"] for row in conn.execute(
        "SELECT group_id FROM operation_groups WHERE entry_id=? AND validation_required=1",
        (task["subject_id"],)
    )}
    group_ids = [row.get("group_id") for row in result.get("validations", [])]
    actual = set(group_ids)
    if expected - actual:
        errors.append("unvalidated_operation_groups:" + ",".join(sorted(expected - actual)))
    if actual - expected:
        errors.append("unknown_operation_groups:" + ",".join(sorted(actual - expected)))
    if len(group_ids) != len(actual):
        errors.append("duplicate_operation_group_validation")

    verification_ids = [row.get("evidence_id") for row in result.get("evidence", [])]
    if len(verification_ids) != len(set(verification_ids)):
        errors.append("duplicate_evidence_id")

    analysis = conn.execute("SELECT coverage_json FROM semantic_analyses WHERE entry_id=?", (task["subject_id"],)).fetchone()
    entry_status = row_json(analysis, "coverage_json", {}).get("entry_status") if analysis else None
    for index, validation in enumerate(result.get("validations", [])):
        label = f"validations[{index}]"
        group = semantic_group_context(conn, validation.get("group_id"))
        if not group:
            continue
        known_evidence = set(_semantic_refs(group)) | set(verification_ids)
        refs = list(validation.get("evidence_refs", []))
        refs.extend(validation.get("business_intent", {}).get("evidence_refs", []))
        refs.extend(validation.get("security_boundary", {}).get("evidence_refs", []))
        refs.extend(validation.get("principal_analysis", {}).get("evidence_refs", []))
        refs.extend(validation.get("availability_analysis", {}).get("evidence_refs", []))
        for counter in validation.get("counter_evidence", []):
            refs.extend(counter.get("evidence_refs", []))
        missing = set(refs) - known_evidence
        if missing:
            errors.append(f"{label}:unknown_semantic_evidence:" + ",".join(sorted(missing)))
        checks = validation.get("exploitability", {})
        if group.get("scope") == "cross_component" and not validation.get("principal_analysis"):
            errors.append(f"{label}:cross_component_requires_principal_analysis")
        if validation.get("capability_id") != group.get("capability_id"):
            errors.append(f"{label}:capability_id_mismatch")
        if validation.get("classification") == "confirmed_vulnerability":
            if entry_status != "confirmed":
                errors.append(f"{label}:confirmed_vulnerability_requires_confirmed_entry")
            if not all(checks.get(name) is True for name in SIX_EXPLOITABILITY_CHECKS):
                errors.append(f"{label}:confirmed_requires_six_dimensions")
        if validation.get("security_check_outcome") == "effective" and checks.get("security_check_bypassed_or_absent") is True:
            errors.append(f"{label}:effective_security_check_conflicts_with_exploitability")
        if validation.get("security_boundary", {}).get("violation") != checks.get("boundary_violated"):
            errors.append(f"{label}:boundary_dimension_mismatch")
    return errors


def validate_submission(result, task, conn):
    errors = schema_errors(task["kind"], result)
    if errors:
        return errors
    if task["kind"] == "component_semantic_analysis":
        errors.extend(validate_semantic_analysis(result, task, conn))
    elif task["kind"] == "exploitability_validation":
        errors.extend(validate_exploitability(result, task, conn))
    return errors
