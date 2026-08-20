"""Normalize, validate, and commit Agent drafts while their task context is alive."""
from __future__ import annotations

from pathlib import Path

from .common import canonical_json, read_json, run_paths
from .contracts import normalize_submission, validate_submission
from .evidence import semantic_admissible_refs
from .store import database, transaction
from .task_context import semantic_group_context, task_context


VALIDATION_FIELDS = {
    "group_id", "capability_id", "classification", "title",
    "security_check_outcome", "business_intent", "security_boundary",
    "principal_analysis", "availability_analysis", "exploitability",
    "effect_chain", "counter_evidence", "impact", "severity", "cwe",
    "demotion_reason", "evidence_gap", "evidence",
}
POC_FIELDS = {
    "entry_type", "trigger", "language", "code", "prerequisites",
    "expected_observation", "limitations", "execution_hint", "symbol_refs",
    "evidence_refs",
}


def draft_path(paths, task):
    return paths["tasks"] / f"{task['task_id']}.attempt-{task['attempts']}.draft.json"


def _dedupe_strings(values):
    if not isinstance(values, list):
        return []
    return sorted({value.strip() for value in values if isinstance(value, str) and value.strip()})


def _dedupe_objects(values):
    if not isinstance(values, list):
        return []
    return list({canonical_json(value): value for value in values if isinstance(value, dict)}.values())


def _support(value, allowed_refs, warnings, path):
    source = value if isinstance(value, dict) else {}
    requested = set(_dedupe_strings(source.get("semantic_refs", [])))
    removed = sorted(requested - allowed_refs)
    if removed:
        warnings.append(f"{path}:removed_out_of_scope_evidence:" + ",".join(removed))
    return {
        "semantic_refs": sorted(requested & allowed_refs),
        "verification": _dedupe_objects(source.get("verification", [])),
    }


def _normalize_support_tree(value, allowed_refs, warnings, path="$"):
    if isinstance(value, list):
        return [
            _normalize_support_tree(item, allowed_refs, warnings, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if not isinstance(value, dict):
        return value
    value = dict(value)
    support_bearing_shapes = (
        {"status", "reason", "evidence_level"},
        {"description", "location"},
        {"is_public_api", "declared_or_inferred_purpose"},
        {"type", "expected_boundary", "reason"},
        {"origin_principal", "target_observed_principal"},
        {"single_trigger_fatal_or_repeatable", "material_availability_loss"},
        {"kind", "reason"},
    )
    if any(shape <= set(value) for shape in support_bearing_shapes):
        value.setdefault("evidence", {})
    normalized = {}
    for key, item in value.items():
        child_path = f"{path}.{key}"
        if key == "evidence":
            normalized[key] = _support(item, allowed_refs, warnings, child_path)
        elif key in {"allowed_controls", "security_check_subjects"}:
            normalized[key] = _dedupe_strings(item)
        else:
            normalized[key] = _normalize_support_tree(item, allowed_refs, warnings, child_path)
    return normalized


def _normalize_validation_draft(conn, task, draft):
    warnings = []
    source = draft if isinstance(draft, dict) else {}
    rows = source.get("validations", draft if isinstance(draft, list) else [])
    rows = rows if isinstance(rows, list) else []
    expected = [
        row["group_id"] for row in conn.execute(
            """SELECT group_id FROM operation_groups
               WHERE entry_id=? AND validation_required=1 ORDER BY group_id""",
            (task["subject_id"],),
        )
    ]
    normalized_rows = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            normalized_rows.append(raw)
            continue
        row = {key: raw[key] for key in VALIDATION_FIELDS if key in raw}
        group_id = row.get("group_id")
        if not group_id and len(expected) == 1:
            group_id = expected[0]
            warnings.append(f"validations[{index}]:group_id_filled_from_task")
        row["group_id"] = group_id
        group = semantic_group_context(conn, group_id) if group_id else None
        if group:
            row["capability_id"] = group.get("capability_id")
            allowed_refs = semantic_admissible_refs(group)
        else:
            allowed_refs = set()
        row.setdefault("counter_evidence", [])
        row.setdefault("evidence", {})
        row = _normalize_support_tree(
            row, allowed_refs, warnings, f"validations[{index}]",
        )
        normalized_rows.append(row)
    summary = source.get("summary") if isinstance(source.get("summary"), str) else ""
    return {
        "task_id": task["task_id"],
        "entry_id": task["subject_id"],
        "summary": summary.strip() or f"完成 {len(normalized_rows)} 个操作组的六维有效性验证",
        "validations": normalized_rows,
    }, warnings


def _normalize_poc_draft(conn, task, draft):
    warnings = []
    source = draft if isinstance(draft, dict) else {}
    result = {key: source[key] for key in POC_FIELDS if key in source}
    context = task_context(conn, task)
    allowed_refs = set(context.get("inherited_evidence_ids", []))
    requested = set(_dedupe_strings(result.get("evidence_refs", [])))
    removed = sorted(requested - allowed_refs)
    if removed:
        warnings.append("evidence_refs:removed_out_of_scope_evidence:" + ",".join(removed))
    result.update({
        "task_id": task["task_id"],
        "finding_id": task["subject_id"],
        "prerequisites": _dedupe_strings(result.get("prerequisites", [])),
        "symbol_refs": _dedupe_objects(result.get("symbol_refs", [])),
        "evidence_refs": sorted(requested & allowed_refs),
    })
    execution_hint = result.get("execution_hint")
    if isinstance(execution_hint, dict):
        execution_hint = dict(execution_hint)
        execution_hint.setdefault("network_required", False)
        result["execution_hint"] = execution_hint
    if not isinstance(result.get("limitations"), str) or not result["limitations"].strip():
        result["limitations"] = "该 PoC 尚未经过编译或真机/模拟器执行，需要人工验证。"
        warnings.append("limitations:filled_runtime_verification_boundary")
    return result, warnings


def submit_task_result(run_dir, task_id, attempt, input_path):
    """Normalize, validate, and atomically complete one running task."""
    paths = run_paths(run_dir)
    actual_draft = Path(input_path).expanduser().resolve()
    result_ref = None
    try:
        with database(paths["db"]) as conn, transaction(conn):
            task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not task:
                raise ValueError("task_not_found")
            if task["status"] == "completed" and task["attempts"] == int(attempt):
                return {
                    "ok": True, "accepted": True, "task_id": task_id,
                    "status": "completed", "result_ref": task["result_ref"],
                    "warnings": [], "idempotent": True,
                }
            if task["status"] != "running":
                raise ValueError(f"task_not_running:{task['status']}")
            if int(attempt) != task["attempts"]:
                raise ValueError(f"stale_attempt:expected={task['attempts']}:actual={attempt}")
            if task["kind"] == "component_semantic_analysis":
                raise ValueError("component_semantic_analysis_uses_exploration_protocol")
            if actual_draft != draft_path(paths, task).resolve():
                raise ValueError("unexpected_draft_path")
            draft = read_json(actual_draft)
            if draft is None:
                return {
                    "ok": True, "accepted": False, "task_id": task_id,
                    "error": "invalid_draft_json", "errors": ["invalid_draft_json"],
                }
            if task["kind"] == "exploitability_validation":
                result, warnings = _normalize_validation_draft(conn, task, draft)
            elif task["kind"] == "poc_generation":
                result, warnings = _normalize_poc_draft(conn, task, draft)
            else:
                raise ValueError(f"unsupported_task_kind:{task['kind']}")
            result = normalize_submission(result, task, conn)
            errors = validate_submission(result, task, conn)
            if errors:
                return {
                    "ok": True, "accepted": False, "task_id": task_id,
                    "error": "; ".join(errors), "errors": errors, "warnings": warnings,
                }
            from .commands import complete_task_result
            summary, result_ref = complete_task_result(conn, paths, task, result)
    except Exception:
        if result_ref:
            Path(result_ref).unlink(missing_ok=True)
        raise
    actual_draft.unlink(missing_ok=True)
    from .reporting import refresh_live_report
    return {
        "ok": True, "accepted": True, "task_id": task_id,
        "status": "completed", "result_ref": str(result_ref),
        "warnings": warnings, "live_report": refresh_live_report(run_dir),
        **summary,
    }
