"""Strict contracts separating source semantics from security judgments."""
from __future__ import annotations

import re

from jsonschema import Draft202012Validator

from .common import *
from .evidence import (semantic_admissible_refs, semantic_hypothesis_refs,
                       validation_semantic_refs)
from .store import row_json
from .task_context import semantic_group_context, task_context


SCHEMA_BY_TASK = {
    "component_semantic_analysis": "component-semantic-result.schema.json",
    "exploitability_validation": "exploitability-validation-result.schema.json",
    "poc_generation": "poc-result.schema.json",
}


def normalize_submission(result, task, conn=None):
    if not isinstance(result, dict):
        return result
    # PoC tasks are scoped to a finding (subject_id=finding_id) and carry no entry_id.
    if task["kind"] != "poc_generation":
        result["entry_id"] = task["subject_id"]
    if task["kind"] == "component_semantic_analysis":
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
                    "evidence": list(operation.get("evidence", [])),
                })
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
            existing_context = existing.get("context", {})
            duplicate_context = group.get("context", {})
            context_evidence = existing_context.get("evidence", []) + duplicate_context.get("evidence", [])
            existing_context["evidence"] = list({canonical_json(row): row for row in context_evidence}.values())
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
                component_call.get("invocation_control", {}), component_call.get("parameter_mappings", []),
                component_call.get("principal_transition", {}),
            ])
            normalized_calls.setdefault(identity, component_call)
        result["component_calls"] = list(normalized_calls.values())
        coverage["operation_sites_checked"] = sorted(checked_sites)
    elif task["kind"] == "exploitability_validation":
        for validation in result.get("validations", []):
            if not isinstance(validation, dict):
                continue
            for key in ("impact", "severity", "cwe", "demotion_reason", "evidence_gap"):
                value = validation.get(key)
                if isinstance(value, str) and not value.strip():
                    validation.pop(key)
    elif task["kind"] == "poc_generation":
        for key in ("code", "expected_observation", "limitations", "prerequisites"):
            value = result.get(key)
            if key == "prerequisites":
                if isinstance(value, list):
                    result["prerequisites"] = sorted({str(item) for item in value if isinstance(item, str)})
            elif isinstance(value, str) and not value.strip():
                result.pop(key)
        refs = result.get("evidence_refs", [])
        if isinstance(refs, list):
            result["evidence_refs"] = sorted({str(item) for item in refs if isinstance(item, str)})
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


def validate_semantic_analysis(result, task, conn):
    errors = []
    if result.get("task_id") != task["task_id"]:
        errors.append("task_id_mismatch")
    if result.get("entry_id") != task["subject_id"]:
        errors.append("entry_id_mismatch")
    coverage = result.get("coverage", {})
    entry_status = coverage.get("entry_status")
    external_status = coverage.get("external_entry_status")
    confirmed_external = coverage.get("confirmed_external_candidate_ids", [])
    if entry_status == "confirmed" and not coverage.get("entry_symbols_checked"):
        errors.append("confirmed_entry_requires_checked_symbol")
    if entry_status == "excluded" and (result.get("operation_groups") or result.get("component_calls")):
        errors.append("excluded_entry_cannot_have_semantic_outputs")
    if entry_status == "excluded" and external_status != "excluded":
        errors.append("excluded_entry_requires_excluded_external_entry")
    if external_status == "confirmed" and entry_status != "confirmed":
        errors.append("confirmed_external_entry_requires_confirmed_component_input")
    if external_status == "confirmed" and not confirmed_external:
        errors.append("confirmed_external_entry_requires_candidate")
    if external_status != "confirmed" and confirmed_external:
        errors.append("unconfirmed_external_entry_cannot_list_confirmed_candidates")

    model_keys = []
    identities = []
    for index, group in enumerate(result.get("operation_groups", [])):
        label = f"operation_groups[{index}]"
        model_keys.append(group.get("group_key"))
        identities.append(operation_group_identity(task["subject_id"], group))
        semantic_context = group.get("context", {})
        if semantic_context.get("direct_observed_effect") is not None and not semantic_context.get("evidence"):
            errors.append(f"{label}:direct_effect_evidence_missing")
    if len(model_keys) != len(set(model_keys)):
        errors.append("duplicate_group_key")
    if len(identities) != len(set(identities)):
        errors.append("equivalent_operation_groups_must_merge")
    payload = row_json(task, "input_json", {})
    task_entry = task_context(conn, task).get("entry", {})
    known_external_candidates = {
        row.get("candidate_id") for row in task_entry.get("project_candidates", [])
        if row.get("type") != "component_scope" and row.get("candidate_id")
    }
    if not known_external_candidates and external_status != "excluded":
        errors.append("component_without_external_candidates_requires_excluded_external_entry")
    unknown_confirmed = set(confirmed_external) - known_external_candidates
    if unknown_confirmed:
        errors.append("unknown_confirmed_external_candidates:" + ",".join(sorted(unknown_confirmed)))
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
            component_call.get("invocation_control", {}), component_call.get("parameter_mappings", []),
            component_call.get("principal_transition", {}),
        ]))
        if component_call.get("target_component_id") not in known_components:
            errors.append(f"{label}:unknown_target_component")
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

    analysis = conn.execute("SELECT coverage_json FROM semantic_analyses WHERE entry_id=?", (task["subject_id"],)).fetchone()
    entry_status = row_json(analysis, "coverage_json", {}).get("entry_status") if analysis else None
    for index, validation in enumerate(result.get("validations", [])):
        label = f"validations[{index}]"
        group = semantic_group_context(conn, validation.get("group_id"))
        if not group:
            continue
        refs = validation_semantic_refs(validation)
        admissible_refs = semantic_admissible_refs(group)
        hypothesis_refs = semantic_hypothesis_refs(group)
        outside_refs = refs - admissible_refs - hypothesis_refs
        if outside_refs:
            errors.append(f"{label}:evidence_outside_operation_group:" + ",".join(sorted(outside_refs)))
        inadmissible_refs = refs & hypothesis_refs
        if inadmissible_refs:
            errors.append(f"{label}:hypothesis_evidence_not_admissible:" + ",".join(sorted(inadmissible_refs)))
        checks = validation.get("exploitability", {})
        for name in SIX_EXPLOITABILITY_CHECKS:
            dimension = checks.get(name, {})
            support = dimension.get("evidence", {})
            has_support = bool(support.get("semantic_refs") or support.get("verification"))
            status = dimension.get("status")
            if status in {"true", "false"} and (
                    dimension.get("evidence_level") == "hypothesis" or not has_support):
                errors.append(f"{label}:{status}_dimension_evidence_insufficient:{name}")
        if group.get("scope") == "cross_component" and not validation.get("principal_analysis"):
            errors.append(f"{label}:cross_component_requires_principal_analysis")
        if validation.get("capability_id") != group.get("capability_id"):
            errors.append(f"{label}:capability_id_mismatch")
        if validation.get("classification") == "confirmed_vulnerability":
            if entry_status != "confirmed":
                errors.append(f"{label}:confirmed_vulnerability_requires_confirmed_entry")
            if not all(checks.get(name, {}).get("status") == "true" for name in SIX_EXPLOITABILITY_CHECKS):
                errors.append(f"{label}:confirmed_requires_six_dimensions")
            effect_chain = validation.get("effect_chain", {})
            for proof_name in ("controlled_value_use", "security_behavior_change", "protected_operation", "concrete_impact"):
                proof = effect_chain.get(proof_name, {})
                support = proof.get("evidence", {})
                if not proof.get("location") or not (support.get("semantic_refs") or support.get("verification")):
                    errors.append(f"{label}:confirmed_effect_chain_incomplete:{proof_name}")
                elif not support.get("verification"):
                    errors.append(f"{label}:confirmed_effect_not_independently_verified:{proof_name}")
        if (validation.get("security_check_outcome") == "effective"
                and checks.get("security_check_bypassed_or_absent", {}).get("status") == "true"):
            errors.append(f"{label}:effective_security_check_conflicts_with_exploitability")
        guard_status = checks.get("security_check_bypassed_or_absent", {}).get("status")
        outcome = validation.get("security_check_outcome")
        expected_guard_status = {
            "absent": "true", "bypassable": "true", "effective": "false", "unknown": "unknown",
        }.get(outcome)
        if expected_guard_status and guard_status != expected_guard_status:
            errors.append(f"{label}:security_check_outcome_dimension_mismatch")

        classification = validation.get("classification")
        core_statuses = [checks.get(name, {}).get("status") for name in (
            "externally_reachable", "attacker_controlled", "sink_reached",
        )]
        final_statuses = [checks.get(name, {}).get("status") for name in (
            "security_check_bypassed_or_absent", "boundary_violated", "concrete_impact",
        )]
        if classification == "protected_exposure" and not (
                core_statuses[:2] == ["true", "true"] and outcome == "effective"
                and guard_status == "false"):
            errors.append(f"{label}:protected_exposure_decision_mismatch")
        elif classification == "no_exploitable_path" and "false" not in core_statuses:
            errors.append(f"{label}:no_exploitable_path_requires_decisive_core_false")
        elif classification == "benign_business_flow" and not (
                core_statuses == ["true", "true", "true"]
                and validation.get("business_intent", {}).get("is_public_api") is True
                and checks.get("boundary_violated", {}).get("status") == "false"
                and checks.get("concrete_impact", {}).get("status") == "false"):
            errors.append(f"{label}:benign_business_flow_decision_mismatch")
        elif classification == "residual_risk" and not (
                core_statuses == ["true", "true", "true"] and "false" not in final_statuses):
            errors.append(f"{label}:residual_risk_requires_established_core_path")
        elif classification == "insufficient_evidence" and not (
                "unknown" in core_statuses and "false" not in core_statuses):
            errors.append(f"{label}:insufficient_evidence_requires_unknown_core_path")
    return errors


PLACEHOLDER_PATTERN = re.compile(r"略|省略|\.\.\.|…|TODO|TBD|your[\s_-]?(?:code|command|payload)|[《<](?:填入|替换|your)[^》>]*[》>]")
FORBIDDEN_POC_OUTPUTS = (
    "classification", "exploitability", "severity", "cwe", "impact", "assurance_status",
)
SHELL_PREFIX = re.compile(r"^\s*(?:hdc|adb|curl|aa)\b")
ARKTS_TRIGGER_API = re.compile(r"startAbility|rpc\.|commonEventManager|dataAbilityHelper|runJavaScript|webview|createChannel|requestSubmitJob|wifiManager")


def validate_poc(result, task, conn):
    """PoC contract: refs within inherited scope, inline symbol evidence, executable code, phase boundary."""
    errors = []
    if result.get("task_id") != task["task_id"]:
        errors.append("task_id_mismatch")
    if result.get("finding_id") != task["subject_id"]:
        errors.append("finding_id_mismatch")
    for field in FORBIDDEN_POC_OUTPUTS:
        if field in result:
            errors.append(f"forbidden_output:{field}")
    # The task seed input carries only a finding hash; the full context is
    # rebuilt from canonical state, exactly like validation group checks.
    input_doc = task_context(conn, task)
    allowed_entry_types = input_doc.get("allowed_entry_types", [])
    entry_type = result.get("entry_type")
    if entry_type not in allowed_entry_types:
        errors.append(f"entry_type_mismatch:{entry_type}:allowed={','.join(sorted(allowed_entry_types))}")
    allowed_evidence = set(input_doc.get("inherited_evidence_ids", []))
    code = result.get("code")
    if not isinstance(code, str) or not code:
        errors.append("poc_code_required")
    elif PLACEHOLDER_PATTERN.search(code):
        errors.append("poc_placeholder_found")
    if not isinstance(result.get("expected_observation"), str) or not result.get("expected_observation"):
        errors.append("poc_expected_observation_required")
    trigger = result.get("trigger") or {}
    trigger_kind = trigger.get("kind")
    if not isinstance(trigger_kind, str) or not trigger_kind:
        errors.append("poc_trigger_kind_required")
    if "payload" not in trigger:
        errors.append("poc_trigger_payload_required")
    elif isinstance(trigger.get("payload"), dict) and not trigger["payload"]:
        errors.append("poc_trigger_payload_empty")
    language = result.get("language")
    if language == "shell":
        if not SHELL_PREFIX.match(code or ""):
            errors.append("poc_shell_command_required")
        if trigger_kind not in ("adb_shell", "ability_want"):
            errors.append(f"poc_shell_trigger_mismatch:{trigger_kind}")
    if language == "arkts":
        if trigger_kind == "adb_shell":
            errors.append(f"poc_arkts_trigger_mismatch:{trigger_kind}")
        if not ARKTS_TRIGGER_API.search(code or ""):
            errors.append("poc_arkts_api_required")
    refs = list(result.get("evidence_refs", []))
    for symbol_ref in result.get("symbol_refs", []):
        if not symbol_ref.get("evidence"):
            errors.append("symbol_ref_evidence_missing")
    missing = set(refs) - allowed_evidence
    if missing:
        errors.append("unknown_evidence:" + ",".join(sorted(missing)))
    return errors


def validate_submission(result, task, conn):
    errors = schema_errors(task["kind"], result)
    if errors:
        return errors
    if task["kind"] == "component_semantic_analysis":
        errors.extend(validate_semantic_analysis(result, task, conn))
    elif task["kind"] == "exploitability_validation":
        errors.extend(validate_exploitability(result, task, conn))
    elif task["kind"] == "poc_generation":
        errors.extend(validate_poc(result, task, conn))
    return errors
