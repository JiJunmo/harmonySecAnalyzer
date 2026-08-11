"""Transactional commands for the component-driven audit runtime."""
from __future__ import annotations

import json
from pathlib import Path

from .common import *
from .contracts import normalize_submission, validate_submission
from .evidence import (materialize_component_call, materialize_poc, materialize_semantic_group,
                       materialize_validation)
from .lifecycle import run_row, update_session
from .scheduler import readiness, reject_attempt
from .store import *
from .task_context import group_context


def submit_result(run_dir, task_id, input_path, attempt=None):
    paths = run_paths(run_dir)
    result = read_json(input_path)
    rejected = None
    result_ref = None
    with database(paths["db"]) as conn, transaction(conn):
        task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if task is None:
            raise ValueError("task_not_found")
        if task["status"] != "running":
            return {"ok": True, "accepted": False, "task_id": task_id, "status": task["status"],
                    "error": f"task_not_running:{task['status']}", "ignored": True}
        if attempt is not None and int(attempt) != task["attempts"]:
            return {"ok": True, "accepted": False, "task_id": task_id, "status": task["status"],
                    "error": f"stale_attempt:expected={task['attempts']}:actual={attempt}", "ignored": True}
        expected = paths["tasks"] / f"{task_id}.attempt-{task['attempts']}.submission.json"
        if attempt is not None and Path(input_path).expanduser().resolve() != expected.resolve():
            return {"ok": True, "accepted": False, "task_id": task_id, "status": task["status"],
                    "error": "unexpected_submission_path", "ignored": True}
        if not isinstance(result, dict):
            errors = ["invalid_result_json"]
        else:
            result = normalize_submission(result, task, conn)
            errors = validate_submission(result, task, conn)
        if errors:
            error = "invalid_submission:" + "|".join(errors)
            rejected = {"error": error, "status": reject_attempt(conn, task, error)}
        else:
            if task["kind"] == "component_semantic_analysis":
                summary = _merge_semantic_analysis(conn, task, result)
            elif task["kind"] == "exploitability_validation":
                summary = _merge_exploitability_validation(conn, task, result, paths)
            elif task["kind"] == "poc_generation":
                summary = _merge_poc_artifact(conn, task, result)
            else:
                raise ValueError(f"unsupported_task_kind:{task['kind']}")
            result_ref = paths["tasks"] / f"{task_id}.result.json"
            write_json(result_ref, result)
            conn.execute("UPDATE tasks SET status='completed',result_ref=?,error=NULL,updated_at=? WHERE task_id=?",
                         (str(result_ref), now(), task_id))
            append_event(conn, "task_completed", task_id, summary)
    if rejected:
        return {"ok": True, "accepted": False, "task_id": task_id, **rejected}
    submitted = Path(input_path).expanduser().resolve()
    if result_ref and submitted != result_ref.resolve():
        submitted.unlink(missing_ok=True)
    return {"ok": True, "accepted": True, "task_id": task_id, "status": "completed", **summary}


def _merge_finding(conn, group_id, group, validation):
    if validation["classification"] not in {"confirmed_vulnerability", "residual_risk"}:
        return None
    root_key = canonical_json({
        "operation": normalize_location(group["operation"]["location"]),
        "controlled_properties": sorted(normalize_text(v) for v in group["controlled_properties"]),
        "boundary": normalize_text(validation["security_boundary"]["expected_boundary"]),
    })
    finding_id = stable_id("FIND", root_key)
    existing = conn.execute("SELECT * FROM findings WHERE root_cause_key=?", (root_key,)).fetchone()
    payload = {**group, **validation, "related_group_ids": [group_id]}
    nested_validation_refs = {
        ref
        for section in (validation.get("exploitability", {}), validation.get("effect_chain", {}))
        for item in section.values()
        for ref in item.get("evidence_refs", [])
    }
    evidence_refs = sorted(
        set(group["evidence_refs"]) | set(validation.get("evidence_refs", [])) | nested_validation_refs
    )
    if existing:
        old = row_json(existing, "payload_json", {})
        related_group_ids = sorted(set(old.get("related_group_ids", [existing["group_id"]])) | {group_id})
        evidence = sorted(set(row_json(existing, "evidence_json", [])) | set(evidence_refs))
        rank = {"residual_risk": 1, "confirmed_vulnerability": 2}
        chosen = dict(payload if rank[validation["classification"]] > rank[existing["classification"]] else old)
        chosen["related_group_ids"] = related_group_ids
        chosen_group_id = chosen.get("group_id", existing["group_id"])
        chosen_boundary = chosen.get("security_boundary", {}).get(
            "expected_boundary", existing["boundary"]
        )
        chosen_properties = chosen.get(
            "controlled_properties", row_json(existing, "controlled_properties_json", [])
        )
        chosen_operation = chosen.get("operation", {}).get(
            "location", existing["operation_location"]
        )
        conn.execute(
            """UPDATE findings SET group_id=?,classification=?,title=?,severity=?,cwe=?,impact=?,
               boundary=?,controlled_properties_json=?,operation_location=?,evidence_json=?,payload_json=?
               WHERE finding_id=?""",
            (chosen_group_id, chosen.get("classification", existing["classification"]),
             chosen.get("title", existing["title"]),
             chosen.get("severity", existing["severity"]), chosen.get("cwe", existing["cwe"]),
             chosen.get("impact", existing["impact"]),
             chosen_boundary, canonical_json(chosen_properties), chosen_operation,
             canonical_json(evidence), canonical_json(chosen), existing["finding_id"]),
        )
        return existing["finding_id"]
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (finding_id, root_key, group_id, validation["classification"], validation["title"], validation.get("severity"),
         validation.get("cwe"), validation.get("impact"), validation["security_boundary"]["expected_boundary"],
         canonical_json(group["controlled_properties"]), group["operation"]["location"],
         canonical_json(evidence_refs), canonical_json(payload), now()),
    )
    return finding_id


def _merge_semantic_analysis(conn, task, result):
    conn.execute("INSERT INTO semantic_analyses VALUES (?,?,?,?,?)",
                 (task["subject_id"], task["task_id"], result["summary"], canonical_json(result["coverage"]), now()))
    entry = conn.execute("SELECT payload_json FROM entries WHERE entry_id=?", (task["subject_id"],)).fetchone()
    entry_payload = row_json(entry, "payload_json", {})
    call_ids = []
    for source in result["component_calls"]:
        component_call = materialize_component_call(conn, task["task_id"], source)
        identity = canonical_json([
            task["subject_id"], component_call["target_component_id"],
            normalize_location(component_call["call_location"]), component_call["invocation_control"],
            component_call["parameter_mappings"],
            component_call["principal_transition"],
        ])
        call_id = stable_id("CALL", identity)
        conn.execute(
            """INSERT INTO component_calls
               (call_id,identity_key,source_entry_id,source_component_id,target_component_id,
                task_id,transport,call_location,condition,parameter_mappings_json,security_checks_json,
                evidence_json,payload_json,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (call_id, identity, task["subject_id"],
             entry_payload.get("component_id") or f"entry:{task['subject_id']}",
             component_call["target_component_id"], task["task_id"], component_call["transport"],
             component_call["call_location"], component_call["condition"],
             canonical_json(component_call["parameter_mappings"]), canonical_json(component_call["security_checks"]),
             canonical_json(component_call["evidence_refs"]), canonical_json(component_call), now()),
        )
        call_ids.append(call_id)
    group_ids = []
    for source in result["operation_groups"]:
        group = materialize_semantic_group(conn, task["task_id"], source)
        identity = operation_group_identity(task["subject_id"], group)
        group_id = stable_id("GROUP", identity)
        conn.execute(
            """INSERT INTO operation_groups
               (group_id,identity_key,entry_id,task_id,scope,validation_required,source_group_id,
                capability_id,category,title,operation_body,operation_location,
                controlled_properties_json,context_json,security_checks_json,branches_json,evidence_json,
                payload_json,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (group_id, identity, task["subject_id"], task["task_id"], "local", 0, None,
             group.get("capability_id"),
             group["category"], group["title"], group["operation"]["body"], group["operation"]["location"],
             canonical_json(group["controlled_properties"]), canonical_json(group["context"]),
             canonical_json(group["security_checks"]), canonical_json(group["branches"]),
             canonical_json(group["evidence_refs"]), canonical_json(group), now()),
        )
        fact_ids = {}
        for fact in group["facts"]:
            fact_id = stable_id("FACT", [group_id, fact["fact_key"]])
            fact_ids[fact["fact_key"]] = fact_id
            conn.execute("INSERT INTO group_facts VALUES (?,?,?,?,?,?,?,?,?)", (
                fact_id, fact["fact_key"], group_id, fact["type"], fact["body"], fact.get("location"),
                canonical_json(fact["evidence_refs"]), canonical_json(fact), now()))
        for edge in group["edges"]:
            edge_id = stable_id("EDGE", [group_id, edge["from"], edge["to"], edge["kind"]])
            conn.execute("INSERT INTO group_edges VALUES (?,?,?,?,?,?,?)", (
                edge_id, group_id, fact_ids[edge["from"]], fact_ids[edge["to"]], edge["kind"],
                canonical_json(edge["evidence_refs"]), now()))
        group_ids.append(group_id)
    return {"entry_id": task["subject_id"], "operation_groups_created": len(group_ids),
            "group_ids": group_ids, "component_calls_created": len(call_ids),
            "call_ids": call_ids}


def _merge_exploitability_validation(conn, task, result, paths=None):
    finding_ids = []
    for source in result["validations"]:
        validation = materialize_validation(conn, task["task_id"], source)
        group_id = validation["group_id"]
        group = group_context(conn, group_id)
        conn.execute(
            """INSERT INTO validation_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (group_id, task["task_id"], validation.get("capability_id"),
             validation["classification"], validation["title"], validation["security_check_outcome"],
             validation["security_boundary"]["expected_boundary"], canonical_json(validation["exploitability"]),
             canonical_json(validation["business_intent"]), canonical_json(validation["security_boundary"]),
             canonical_json(validation["counter_evidence"]), validation.get("severity"), validation.get("cwe"),
             validation.get("impact"), validation.get("demotion_reason"),
             validation.get("evidence_gap"), canonical_json(validation), now()),
        )
        finding_id = _merge_finding(conn, group_id, group, validation)
        if finding_id:
            finding_ids.append(finding_id)
            _ensure_poc_task(conn, finding_id, paths)
    return {"entry_id": task["subject_id"], "validations_created": len(result["validations"]),
            "findings_created_or_merged": len(set(finding_ids))}


def _ensure_poc_task(conn, finding_id, paths=None):
    """Schedule a PoC task per confirmed finding; repair when the finding changes.

    Mirrors v3.2 scheduling: validation landing derives the task immediately,
    a changed finding requeues a completed task, and incremental runs reuse a
    fingerprint-matched baseline artifact.
    """
    finding = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
    if not finding or finding["classification"] not in ("confirmed_vulnerability", "residual_risk"):
        return None
    key = f"poc:{finding_id}"
    input_doc = {"_finding_hash": stable_id("POCIN", finding["payload_json"]), "finding_id": finding_id}
    existing = conn.execute("SELECT * FROM tasks WHERE semantic_key=?", (key,)).fetchone()
    if existing and existing["status"] == "completed":
        old = row_json(existing, "input_json", {})
        if old.get("_finding_hash") == input_doc["_finding_hash"]:
            return existing["task_id"]
        conn.execute("DELETE FROM poc_artifacts WHERE finding_id=?", (finding_id,))
        conn.execute(
            "UPDATE tasks SET status='queued',attempts=0,error='poc_finding_changed',result_ref=NULL,input_json=?,updated_at=? WHERE task_id=?",
            (canonical_json(input_doc), now(), existing["task_id"]),
        )
        append_event(conn, "poc_artifact_repair", existing["task_id"], {"finding_id": finding_id})
        return existing["task_id"]
    if existing and existing["status"] == "queued":
        conn.execute(
            "UPDATE tasks SET input_json=?,updated_at=? WHERE task_id=?",
            (canonical_json(input_doc), now(), existing["task_id"]),
        )
        return existing["task_id"]
    task_id = enqueue_task(conn, key, "poc_generation", subject_id=finding_id, payload=input_doc)
    if paths:
        _try_reuse_poc(conn, paths, task_id)
    return task_id


def _try_reuse_poc(conn, paths, task_id):
    from .task_context import validation_group_fingerprint

    task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    finding = conn.execute("SELECT * FROM findings WHERE finding_id=?", (task["subject_id"],)).fetchone()
    if not finding:
        return False
    fingerprint = validation_group_fingerprint(conn, finding["group_id"])
    if not fingerprint:
        return False
    document = read_json(paths["baseline_pocs"], {})
    snapshot = next(
        (item for item in document.get("items", []) if item.get("group_fingerprint") == fingerprint),
        None,
    )
    if not snapshot or not isinstance(snapshot.get("result"), dict):
        return False
    try:
        result = json.loads(json.dumps(snapshot["result"]))
        result["task_id"] = task["task_id"]
        result["finding_id"] = task["subject_id"]
        result = normalize_submission(result, task, conn)
        errors = validate_submission(result, task, conn)
    except Exception as exc:
        return False
    if errors:
        append_event(conn, "poc_reuse_rejected", task["subject_id"], {"errors": errors})
        return False
    summary = _merge_poc_artifact(conn, task, result)
    result_ref = paths["tasks"] / f"{task['task_id']}.result.json"
    write_json(result_ref, result)
    conn.execute(
        "UPDATE tasks SET status='completed',result_ref=?,error=NULL,updated_at=? WHERE task_id=?",
        (str(result_ref), now(), task["task_id"]),
    )
    append_event(conn, "poc_result_reused", task["subject_id"], summary)
    return True


def _merge_poc_artifact(conn, task, result):
    poc = materialize_poc(conn, task["task_id"], result)
    poc_id = stable_id("POC", task["task_id"])
    conn.execute(
        "INSERT OR REPLACE INTO poc_artifacts VALUES (?,?,?,?,?,?)",
        (poc_id, task["subject_id"], task["task_id"], poc["entry_type"], canonical_json(poc), now()),
    )
    return {"finding_id": task["subject_id"], "entry_type": poc["entry_type"]}


def export_state(run_dir):
    from .reporting import export_state as _export
    return _export(run_dir)


def build_report_ready(run_dir):
    from .reporting import build_report
    ready = readiness(run_dir)
    if not ready["ready"]:
        raise ValueError("run_not_ready:" + ",".join(ready["reasons"]))
    return {"ok": True, **build_report(run_dir)}


def finalize_run(run_dir):
    from .reporting import build_report
    ready = readiness(run_dir)
    if not ready["ready"]:
        raise ValueError("run_not_ready:" + ",".join(ready["reasons"]))
    result = build_report(run_dir, report_status="complete")
    from .incremental import save_baseline
    baseline = save_baseline(run_dir)
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        stamp = now()
        conn.execute("UPDATE runs SET status='complete',updated_at=?,finalized_at=? WHERE run_id=?", (stamp, stamp, run["run_id"]))
        append_event(conn, "run_finalized", run["run_id"], result)
    update_session(paths, "complete")
    return {"ok": True, **result, "baseline": baseline}


def resume_run(run_dir):
    """Reopen a finalized partial run and retry only its exhausted tasks."""
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        if run["status"] != "complete":
            raise ValueError(f"run_not_complete:{run['status']}")
        exhausted = [row["task_id"] for row in conn.execute(
            "SELECT task_id FROM tasks WHERE status='exhausted' ORDER BY created_at,task_id"
        )]
        if not exhausted:
            raise ValueError("run_has_no_exhausted_tasks")
        stamp = now()
        conn.execute(
            "UPDATE tasks SET status='queued',attempts=0,error=NULL,result_ref=NULL,updated_at=? "
            "WHERE status='exhausted'",
            (stamp,),
        )
        conn.execute(
            "UPDATE runs SET status='running',error=NULL,updated_at=?,finalized_at=NULL WHERE run_id=?",
            (stamp, run["run_id"]),
        )
        append_event(conn, "run_resumed", run["run_id"], {"task_ids": exhausted})
        target_repo = run["target_repo"]
    update_session(paths, "running")
    from .reporting import refresh_live_report
    live_report = refresh_live_report(run_dir)
    return {
        "ok": True, "run_dir": str(paths["root"]), "target_repo": target_repo,
        "requeued_task_ids": exhausted, "count": len(exhausted),
        "live_report": live_report,
    }


def status(run_dir):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = dict(run_row(conn))
        run["capability_filter"] = json.loads(run.pop("capability_filter_json"))
        run["component_filter"] = json.loads(run.pop("component_filter_json"))
        run["correlation"] = json.loads(run.pop("correlation_json"))
        task_counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
        counts = {table: conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"]
                  for table in ("entries", "semantic_analyses", "component_calls", "operation_groups", "validation_results", "group_facts", "findings")}
        retry_categories = {}
        for row in conn.execute("SELECT payload_json FROM events WHERE event_type='task_retry'"):
            payload = json.loads(row["payload_json"])
            category = payload.get("category") or str(payload.get("error") or "unknown").split(":", 1)[0]
            retry_categories[category] = retry_categories.get(category, 0) + 1
    return {"ok": True, "run": run, "tasks": task_counts, "objects": counts,
            "retries": {"total": sum(retry_categories.values()), "by_category": retry_categories},
            "readiness": readiness(run_dir)}
