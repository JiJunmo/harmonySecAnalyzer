"""Transactional commands for the component-driven audit runtime."""
from __future__ import annotations

import json
from pathlib import Path

from .common import *
from .contracts import normalize_submission, validate_submission
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
                summary = _merge_exploitability_validation(conn, task, result)
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


def _insert_evidence(conn, task_id, rows):
    identities = {}
    for row in rows or []:
        evidence_id = stable_id("EVID", [task_id, row["evidence_id"]])
        identities[row["evidence_id"]] = evidence_id
        conn.execute(
            "INSERT INTO evidence(evidence_id,task_id,kind,source,location,summary,content_ref,sha256,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (evidence_id, task_id, row["kind"], row["source"], row.get("location"), row["summary"],
             row.get("content_ref"), row.get("sha256"), now()),
        )
    return identities


def _refs(values, identities):
    return sorted({identities.get(value, value) for value in values})


def _remap_group_evidence(group, evidence_ids):
    payload = json.loads(json.dumps(group))
    payload["evidence_refs"] = _refs(payload.get("evidence_refs", []), evidence_ids)
    for key in ("facts", "edges", "branches", "security_checks"):
        for row in payload.get(key, []):
            row["evidence_refs"] = _refs(row.get("evidence_refs", []), evidence_ids)
    payload["context"]["evidence_refs"] = _refs(payload["context"].get("evidence_refs", []), evidence_ids)
    for hypothesis in payload["context"].get("effect_hypotheses", []):
        hypothesis["basis_evidence_refs"] = _refs(hypothesis.get("basis_evidence_refs", []), evidence_ids)
    if payload.get("availability"):
        payload["availability"]["evidence_refs"] = _refs(
            payload["availability"].get("evidence_refs", []), evidence_ids
        )
    return payload


def _remap_component_call_evidence(component_call, evidence_ids):
    payload = json.loads(json.dumps(component_call))
    payload["evidence_refs"] = _refs(payload.get("evidence_refs", []), evidence_ids)
    for security_check in payload.get("security_checks", []):
        security_check["evidence_refs"] = _refs(security_check.get("evidence_refs", []), evidence_ids)
    transition = payload.get("principal_transition", {})
    transition["evidence_refs"] = _refs(transition.get("evidence_refs", []), evidence_ids)
    return payload


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
            """UPDATE findings SET group_id=?,classification=?,title=?,severity=?,cwe=?,impact=?,poc=?,
               boundary=?,controlled_properties_json=?,operation_location=?,evidence_json=?,payload_json=?
               WHERE finding_id=?""",
            (chosen_group_id, chosen.get("classification", existing["classification"]),
             chosen.get("title", existing["title"]),
             chosen.get("severity", existing["severity"]), chosen.get("cwe", existing["cwe"]),
             chosen.get("impact", existing["impact"]), chosen.get("poc", existing["poc"]),
             chosen_boundary, canonical_json(chosen_properties), chosen_operation,
             canonical_json(evidence), canonical_json(chosen), existing["finding_id"]),
        )
        return existing["finding_id"]
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (finding_id, root_key, group_id, validation["classification"], validation["title"], validation.get("severity"),
         validation.get("cwe"), validation.get("impact"), validation.get("poc"), validation["security_boundary"]["expected_boundary"],
         canonical_json(group["controlled_properties"]), group["operation"]["location"],
         canonical_json(evidence_refs), canonical_json(payload), now()),
    )
    return finding_id


def _merge_semantic_analysis(conn, task, result):
    evidence_ids = _insert_evidence(conn, task["task_id"], result.get("evidence", []))
    conn.execute("INSERT INTO semantic_analyses VALUES (?,?,?,?,?)",
                 (task["subject_id"], task["task_id"], result["summary"], canonical_json(result["coverage"]), now()))
    entry = conn.execute("SELECT payload_json FROM entries WHERE entry_id=?", (task["subject_id"],)).fetchone()
    entry_payload = row_json(entry, "payload_json", {})
    call_ids = []
    for source in result["component_calls"]:
        component_call = _remap_component_call_evidence(source, evidence_ids)
        identity = canonical_json([
            task["subject_id"], component_call["target_component_id"],
            normalize_location(component_call["call_location"]), component_call["parameter_mappings"],
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
        group = _remap_group_evidence(source, evidence_ids)
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


def _merge_exploitability_validation(conn, task, result):
    evidence_ids = _insert_evidence(conn, task["task_id"], result.get("evidence", []))
    finding_ids = []
    for source in result["validations"]:
        validation = json.loads(json.dumps(source))
        validation["evidence_refs"] = _refs(validation.get("evidence_refs", []), evidence_ids)
        for key in ("business_intent", "security_boundary"):
            validation[key]["evidence_refs"] = _refs(validation[key].get("evidence_refs", []), evidence_ids)
        for dimension in validation.get("exploitability", {}).values():
            dimension["evidence_refs"] = _refs(dimension.get("evidence_refs", []), evidence_ids)
        for proof in validation.get("effect_chain", {}).values():
            proof["evidence_refs"] = _refs(proof.get("evidence_refs", []), evidence_ids)
        if validation.get("principal_analysis"):
            validation["principal_analysis"]["evidence_refs"] = _refs(
                validation["principal_analysis"].get("evidence_refs", []), evidence_ids
            )
        if validation.get("availability_analysis"):
            validation["availability_analysis"]["evidence_refs"] = _refs(
                validation["availability_analysis"].get("evidence_refs", []), evidence_ids
            )
        for counter in validation.get("counter_evidence", []):
            counter["evidence_refs"] = _refs(counter.get("evidence_refs", []), evidence_ids)
        group_id = validation["group_id"]
        group = group_context(conn, group_id)
        conn.execute(
            """INSERT INTO validation_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (group_id, task["task_id"], validation.get("capability_id"),
             validation["classification"], validation["title"], validation["security_check_outcome"],
             validation["security_boundary"]["expected_boundary"], canonical_json(validation["exploitability"]),
             canonical_json(validation["business_intent"]), canonical_json(validation["security_boundary"]),
             canonical_json(validation["counter_evidence"]), validation.get("severity"), validation.get("cwe"),
             validation.get("impact"), validation.get("poc"), validation.get("demotion_reason"),
             validation.get("evidence_gap"), canonical_json(validation), now()),
        )
        finding_id = _merge_finding(conn, group_id, group, validation)
        if finding_id:
            finding_ids.append(finding_id)
    return {"entry_id": task["subject_id"], "validations_created": len(result["validations"]),
            "findings_created_or_merged": len(set(finding_ids))}


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
