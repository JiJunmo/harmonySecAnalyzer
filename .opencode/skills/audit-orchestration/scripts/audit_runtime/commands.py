"""Transactional commands for the flow-driven audit runtime."""
from __future__ import annotations

import json
from pathlib import Path

from .common import *
from .contracts import normalize_submission, validate_submission
from .lifecycle import candidate_rows, initialize_run, new_run, run_row, update_session
from .scheduler import claim_tasks, fail_task, readiness, transition_failure
from .store import *


def _project_candidate_ids(paths, conn=None):
    model = read_json(paths["project_model"], {})
    component_filter = row_json(run_row(conn), "component_filter_json", []) if conn else []
    return [row["candidate_id"] for row in candidate_rows(model, component_filter)]


def _assessment_gap_result(conn, task, error):
    """Close one repeatedly invalid assessment without aborting unrelated paths."""
    path = conn.execute("SELECT * FROM paths WHERE path_id=?", (task["subject_id"],)).fetchone()
    flow = conn.execute("SELECT * FROM flows WHERE flow_id=?", (path["terminal_flow_id"],)).fetchone()
    flow_ids = row_json(path, "flow_ids_json", [])
    operation = None
    fallback_fact = None
    if flow_ids:
        placeholders = ",".join("?" for _ in flow_ids)
        operation = conn.execute(
            f"SELECT * FROM facts WHERE flow_id IN ({placeholders}) AND fact_type='operation' "
            "ORDER BY created_at,fact_id LIMIT 1", flow_ids,
        ).fetchone()
        fallback_fact = operation or conn.execute(
            f"SELECT * FROM facts WHERE flow_id IN ({placeholders}) ORDER BY created_at,fact_id LIMIT 1",
            flow_ids,
        ).fetchone()
    evidence_refs = row_json(fallback_fact, "evidence_json", []) if fallback_fact else []
    location = operation["location"] if operation and operation["location"] else flow["current_symbol"]
    return {
        "task_id": task["task_id"], "path_id": task["subject_id"],
        "summary": "Security assessment could not be completed after repeated invalid submissions.",
        "assessments": [{
            "capability_id": None, "pattern_id": None, "category": "unassessed",
            "operation_fact_id": operation["fact_id"] if operation else None,
            "classification": "insufficient_evidence", "title": "安全判定未完成",
            "exploitability": {name: False for name in SIX_EXPLOITABILITY_CHECKS},
            "root_cause": {
                "operation_location": location, "branch": flow["branch_key"],
                "boundary": "unassessed", "controlled_property": flow["controlled_property"],
            },
            "guards": [], "counter_evidence": [],
            "demotion_reason": "安全判定结果连续未通过提交契约，未将该路径计为漏洞。",
            "evidence_gap": error, "evidence_refs": evidence_refs,
        }],
        "evidence": [],
    }


def submit_result(run_dir, task_id, input_path, attempt=None):
    paths = run_paths(run_dir)
    result = read_json(input_path)
    rejected = None
    degraded_error = None
    with database(paths["db"]) as conn, transaction(conn):
        task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if task is None:
            raise ValueError("task_not_found")
        if task["status"] != "running":
            return {
                "ok": True, "accepted": False, "task_id": task_id,
                "status": task["status"], "error": f"task_not_running:{task['status']}",
                "ignored": True,
            }
        if attempt is not None and int(attempt) != task["attempts"]:
            return {
                "ok": True, "accepted": False, "task_id": task_id, "status": task["status"],
                "error": f"stale_attempt:expected={task['attempts']}:actual={attempt}", "ignored": True,
            }
        expected_input = paths["tasks"] / f"{task_id}.attempt-{task['attempts']}.submission.json"
        if attempt is not None and Path(input_path).expanduser().resolve() != expected_input.resolve():
            return {
                "ok": True, "accepted": False, "task_id": task_id, "status": task["status"],
                "error": "unexpected_submission_path", "ignored": True,
            }
        if not isinstance(result, dict):
            error = "invalid_result_json"
            rejected = {"error": error, "status": transition_failure(conn, task, error)}
        else:
            result = normalize_submission(result, task, conn)
            errors = validate_submission(result, task, conn, _project_candidate_ids(paths, conn))
            if errors:
                error = "invalid_submission:" + "|".join(errors)
                if task["kind"] == "security_assessment" and task["attempts"] >= MAX_TASK_ATTEMPTS:
                    degraded_error = error
                    result = _assessment_gap_result(conn, task, error)
                    summary = _merge_security_assessment(conn, task, result)
                    result_ref = paths["tasks"] / f"{task_id}.result.json"
                    write_json(result_ref, result)
                    conn.execute(
                        "UPDATE tasks SET status='completed',result_ref=?,error=?,updated_at=? WHERE task_id=?",
                        (str(result_ref), "degraded:" + error, now(), task_id),
                    )
                    append_event(conn, "task_degraded", task_id, {
                        "error": error, "classification": "insufficient_evidence", **summary,
                    })
                else:
                    rejected = {"error": error, "status": transition_failure(conn, task, error)}
            else:
                if task["kind"] == "entry_resolution":
                    summary = _merge_entry_resolution(conn, task, result)
                elif task["kind"] in {"entry_path_discovery", "continuation_resolution"}:
                    summary = _merge_flows(conn, task, result)
                elif task["kind"] == "security_assessment":
                    summary = _merge_security_assessment(conn, task, result)
                else:
                    raise ValueError(f"unsupported_task_kind:{task['kind']}")
                result_ref = paths["tasks"] / f"{task_id}.result.json"
                write_json(result_ref, result)
                conn.execute(
                    "UPDATE tasks SET status='completed',result_ref=?,error=NULL,updated_at=? WHERE task_id=?",
                    (str(result_ref), now(), task_id),
                )
                append_event(conn, "task_completed", task_id, summary)
    if rejected:
        if rejected["status"] == "failed":
            update_session(paths, "failed", rejected["error"])
        return {"ok": True, "accepted": False, "task_id": task_id, **rejected}
    submitted = Path(input_path).expanduser().resolve()
    if submitted != result_ref.resolve():
        submitted.unlink(missing_ok=True)
    return {
        "ok": True, "accepted": True, "task_id": task_id,
        "status": "completed", "degraded": degraded_error is not None,
        **({"error": degraded_error} if degraded_error else {}), **summary,
    }


def _insert_evidence(conn, task_id, rows):
    identities = {}
    for row in rows or []:
        evidence_id = stable_id("EVID", [task_id, row["evidence_id"]])
        identities[row["evidence_id"]] = evidence_id
        conn.execute(
            """INSERT INTO evidence(evidence_id,task_id,kind,source,location,summary,content_ref,sha256,created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (evidence_id, task_id, row["kind"], row["source"], row.get("location"),
             row["summary"], row.get("content_ref"), row.get("sha256"), now()),
        )
    return identities


def _evidence_refs(rows, identities):
    return [identities.get(ref, ref) for ref in rows]


def _merge_entry_resolution(conn, task, result):
    evidence_ids = _insert_evidence(conn, task["task_id"], result.get("evidence", []))
    run = run_row(conn)
    capabilities = load_capabilities(row_json(run, "capability_filter_json", []))
    capability_scoped = run["audit_mode"] == "capability"
    created = []
    path_tasks_created = 0
    outside_capability_scope = 0
    candidate_entries = {}
    candidate_evidence = {}
    for entry in result["entries"]:
        entry_id = stable_id("ENTRY", entry["entry_key"])
        profiles = profiles_for_entry(entry["entry_type"], capabilities)
        profile_rows = [row for row in capabilities if row["capability_id"] in profiles]
        entry_payload = {**entry, "evidence_refs": _evidence_refs(entry.get("evidence_refs", []), evidence_ids)}
        conn.execute(
            """INSERT INTO entries(entry_id,entry_key,entry_type,component,symbol,discriminator_json,transport,reachability,profiles_json,payload_json,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (entry_id, entry["entry_key"], entry["entry_type"], entry.get("component"), entry["symbol"],
             canonical_json(entry["discriminator"]), entry["transport"], entry["external_reachability"],
             canonical_json(profiles), canonical_json(entry_payload), now()),
        )
        for candidate_id in entry["project_candidate_ids"]:
            candidate_entries.setdefault(candidate_id, []).append(entry_id)
            candidate_evidence.setdefault(candidate_id, set()).update(entry_payload["evidence_refs"])
        if not capability_scoped or profiles:
            enqueue_task(conn, f"entry:{entry_id}", "entry_path_discovery", entry_id, {
                "entry": {**entry_payload, "entry_id": entry_id}, "capability_profiles": profile_rows,
            }, [task["task_id"]])
            path_tasks_created += 1
        else:
            outside_capability_scope += 1
        created.append(entry_id)
    for candidate_id, entry_ids in candidate_entries.items():
        singular_entry_id = entry_ids[0] if len(entry_ids) == 1 else None
        conn.execute("INSERT INTO entry_dispositions VALUES (?,?,?,?,?)", (
            candidate_id, "resolved_entry", singular_entry_id, None,
            canonical_json(sorted(candidate_evidence[candidate_id]))))
    for field, disposition in (("excluded_candidates", "excluded"), ("gaps", "gap")):
        for row in result[field]:
            for candidate_id in row["project_candidate_ids"]:
                conn.execute("INSERT INTO entry_dispositions VALUES (?,?,?,?,?)", (
                    candidate_id, disposition, None, row["reason"], canonical_json(_evidence_refs(row["evidence_refs"], evidence_ids))))
    return {
        "entries_created": len(created),
        "path_tasks_created": path_tasks_created,
        "entries_outside_capability_scope": outside_capability_scope,
    }


def _flow_lineage_ids(conn, flow_id):
    lineage = []
    seen = set()
    current = flow_id
    while current and current not in seen:
        seen.add(current)
        lineage.append(current)
        row = conn.execute("SELECT parent_flow_id FROM flows WHERE flow_id=?", (current,)).fetchone()
        current = row["parent_flow_id"] if row else None
    return list(reversed(lineage))


def _create_path(conn, terminal_flow_id, status, source_task_id, gap_continuation_id=None):
    flow = conn.execute("SELECT root_entry_id FROM flows WHERE flow_id=?", (terminal_flow_id,)).fetchone()
    path_id = stable_id("PATH", [terminal_flow_id, gap_continuation_id])
    stamp = now()
    conn.execute(
        """INSERT INTO paths(path_id,root_entry_id,terminal_flow_id,gap_continuation_id,status,flow_ids_json,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT(path_id) DO UPDATE SET status=excluded.status,flow_ids_json=excluded.flow_ids_json,
             updated_at=excluded.updated_at""",
        (path_id, flow["root_entry_id"], terminal_flow_id, gap_continuation_id, status,
         canonical_json(_flow_lineage_ids(conn, terminal_flow_id)), stamp, stamp),
    )
    enqueue_task(conn, f"security:{path_id}", "security_assessment", path_id, {
        "path_id": path_id,
    }, [source_task_id])
    return path_id, "security_assessment"


def _merge_flows(conn, task, result):
    evidence_ids = _insert_evidence(conn, task["task_id"], result.get("evidence", []))
    produced = []
    paths_created = []
    followup_count = 0
    for item in result["flows"]:
        item_payload = {
            **item,
            "facts": [{**row, "evidence_refs": _evidence_refs(row["evidence_refs"], evidence_ids)} for row in item["facts"]],
            "edges": [{**row, "evidence_refs": _evidence_refs(row["evidence_refs"], evidence_ids)} for row in item["edges"]],
            "continuations": [{**row, "evidence_refs": _evidence_refs(row["evidence_refs"], evidence_ids)} for row in item["continuations"]],
        }
        identity_key = flow_identity_key(item)
        flow_id = stable_id("FLOW", identity_key)
        stamp = now()
        conn.execute(
            """INSERT INTO flows(flow_id,identity_key,root_entry_id,parent_flow_id,producer_task_id,branch_key,controlled_property,current_symbol,status,controlled_values_json,payload_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(identity_key) DO UPDATE SET current_symbol=excluded.current_symbol,status=excluded.status,
                 controlled_values_json=excluded.controlled_values_json,payload_json=excluded.payload_json,updated_at=excluded.updated_at""",
            (flow_id, identity_key, item["root_entry_id"], item.get("parent_flow_id"), task["task_id"],
             item["branch_key"], item["controlled_property"], item["current_symbol"], item["status"],
             canonical_json(item["controlled_values"]), canonical_json(item_payload), stamp, stamp),
        )
        fact_ids = {}
        for fact in item["facts"]:
            canonical_fact_key = fact_identity_key(fact)
            fact_id = stable_id("FACT", [flow_id, canonical_fact_key])
            fact_ids[fact["fact_key"]] = fact_id
            fact_ids[canonical_fact_key] = fact_id
            fact_payload = {**fact, "source_fact_key": fact["fact_key"],
                            "evidence_refs": _evidence_refs(fact["evidence_refs"], evidence_ids)}
            conn.execute(
                """INSERT INTO facts(fact_id,fact_key,flow_id,fact_type,body,location,evidence_json,payload_json,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(flow_id,fact_key) DO UPDATE SET fact_type=excluded.fact_type,
                     body=excluded.body,location=excluded.location,evidence_json=excluded.evidence_json,
                     payload_json=excluded.payload_json""",
                (fact_id, canonical_fact_key, flow_id, fact["type"], fact["body"], fact.get("location"),
                 canonical_json(fact_payload["evidence_refs"]), canonical_json(fact_payload), now()),
            )
        parent_id = item.get("parent_flow_id")
        seen_parents = set()
        while parent_id and parent_id not in seen_parents:
            seen_parents.add(parent_id)
            for row in conn.execute("SELECT fact_key,fact_id FROM facts WHERE flow_id=?", (parent_id,)):
                fact_ids.setdefault(row["fact_key"], row["fact_id"])
            parent = conn.execute("SELECT parent_flow_id FROM flows WHERE flow_id=?", (parent_id,)).fetchone()
            parent_id = parent["parent_flow_id"] if parent else None
        for edge in item["edges"]:
            edge_id = stable_id("EDGE", [flow_id, fact_ids[edge["from"]], fact_ids[edge["to"]], edge["kind"]])
            conn.execute(
                """INSERT INTO edges VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(flow_id,from_fact_id,to_fact_id,kind) DO UPDATE SET evidence_json=excluded.evidence_json""",
                (edge_id, flow_id, fact_ids[edge["from"]], fact_ids[edge["to"]], edge["kind"],
                 canonical_json(_evidence_refs(edge["evidence_refs"], evidence_ids)), now()),
            )
        for continuation in item["continuations"]:
            continuation_id = stable_id("CONT", [flow_id, continuation["semantic_key"]])
            target_known = continuation["kind"] != "unknown_target"
            handler_key = handler_identity(continuation["target"]) if target_known else None
            base_semantic = "continuation:" + (handler_key if target_known else continuation_id)
            existing_task = conn.execute("SELECT * FROM tasks WHERE semantic_key=?", (base_semantic,)).fetchone()
            dependencies = [task["task_id"]]
            reuse_task_ids = []
            continuation_status = "open"
            if existing_task and existing_task["status"] != "queued":
                if existing_task["task_id"] == task["task_id"]:
                    continuation_status = "gap"
                    next_task = None
                else:
                    base_semantic = "continuation-join:" + continuation_id
                    reuse_task_ids.append(existing_task["task_id"])
                    if existing_task["status"] == "running":
                        dependencies.append(existing_task["task_id"])
            if continuation_status == "open":
                next_task = enqueue_task(conn, base_semantic, "continuation_resolution", flow_id, {
                    "handler_key": handler_key, "target_known": target_known,
                    "reuse_task_ids": reuse_task_ids,
                }, dependencies)
            conn.execute(
                """INSERT INTO continuations(continuation_id,semantic_key,flow_id,kind,target,status,task_id,child_flow_ids_json,evidence_json,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(flow_id,semantic_key) DO UPDATE SET kind=excluded.kind,target=excluded.target,
                     status=excluded.status,task_id=excluded.task_id,child_flow_ids_json=excluded.child_flow_ids_json,
                     evidence_json=excluded.evidence_json,updated_at=excluded.updated_at""",
                (continuation_id, continuation["semantic_key"], flow_id, continuation["kind"], continuation["target"],
                 continuation_status, next_task, "[]",
                 canonical_json(_evidence_refs(continuation["evidence_refs"], evidence_ids)), now(), now()),
            )
            if continuation_status == "gap":
                path_id, followup = _create_path(conn, flow_id, "gap", task["task_id"], continuation_id)
                paths_created.append(path_id)
                if followup: followup_count += 1
        if item["status"] in TERMINAL_FLOW_STATES:
            path_id, followup = _create_path(conn, flow_id, item["status"], task["task_id"])
            paths_created.append(path_id)
            if followup: followup_count += 1
        produced.append(flow_id)

    if task["kind"] == "continuation_resolution":
        by_parent = {}
        for item, flow_id in zip(result["flows"], produced):
            by_parent.setdefault(item.get("parent_flow_id"), []).append(flow_id)
        for row in conn.execute("SELECT continuation_id,flow_id FROM continuations WHERE task_id=?", (task["task_id"],)):
            children = sorted(by_parent.get(row["flow_id"], []))
            conn.execute(
                "UPDATE continuations SET status='resolved',child_flow_ids_json=?,updated_at=? WHERE continuation_id=?",
                (canonical_json(children), now(), row["continuation_id"]),
            )
    return {
        "flows_merged": len(produced), "flow_ids": produced,
        "paths_created": len(paths_created), "path_ids": paths_created,
        "security_assessment_tasks_created": followup_count,
    }


def _merge_finding(conn, assessment, assessment_id):
    root = assessment["root_cause"]
    root_key = canonical_json({
        "operation": normalize_location(root["operation_location"]), "branch": normalize_text(root["branch"]),
        "boundary": normalize_text(root["boundary"]), "controlled_property": normalize_text(root["controlled_property"]),
    })
    finding_id = stable_id("FIND", root_key)
    payload = {**assessment, "assessment_ids": [assessment_id]}
    existing = conn.execute("SELECT * FROM findings WHERE root_cause_key=?", (root_key,)).fetchone()
    if existing:
        merged = sorted(set(row_json(existing, "evidence_json", [])) | set(assessment["evidence_refs"]))
        old_payload = row_json(existing, "payload_json", {})
        related = sorted(set(old_payload.get("related_path_ids", [existing["path_id"]])) | {assessment["path_id"]})
        assessment_ids = sorted(set(old_payload.get("assessment_ids", [])) | {assessment_id})
        validations = old_payload.get("validations", [{
            "path_id": existing["path_id"], "classification": existing["classification"],
            "conclusion": old_payload.get("conclusion", ""),
        }])
        validations.append({"path_id": assessment["path_id"], "classification": assessment["classification"], "conclusion": assessment["conclusion"]})
        payload["related_path_ids"] = related
        payload["assessment_ids"] = assessment_ids
        payload["validations"] = sorted(validations, key=lambda row: (row["path_id"], row["classification"], row["conclusion"]))
        rank = {"residual_risk": 1, "confirmed_vulnerability": 2}
        if rank[assessment["classification"]] > rank[existing["classification"]]:
            conn.execute(
                """UPDATE findings SET path_id=?,classification=?,title=?,severity=?,cwe=?,impact=?,poc=?,
                   boundary=?,controlled_property=?,operation_location=?,evidence_json=?,payload_json=? WHERE finding_id=?""",
                (assessment["path_id"], assessment["classification"], assessment["title"], assessment["severity"], assessment["cwe"],
                 assessment["impact"], assessment["poc"], root["boundary"], root["controlled_property"],
                 root["operation_location"], canonical_json(merged), canonical_json(payload), existing["finding_id"]),
            )
        else:
            old_payload["related_path_ids"] = related
            old_payload["assessment_ids"] = assessment_ids
            old_payload["validations"] = payload["validations"]
            conn.execute("UPDATE findings SET evidence_json=?,payload_json=? WHERE finding_id=?",
                         (canonical_json(merged), canonical_json(old_payload), existing["finding_id"]))
        finding_id = existing["finding_id"]
        merged_root = True
    else:
        payload["related_path_ids"] = [assessment["path_id"]]
        conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding_id, root_key, assessment["path_id"], assessment["classification"], assessment["title"], assessment["severity"],
             assessment["cwe"], assessment["impact"], assessment["poc"], root["boundary"], root["controlled_property"],
             root["operation_location"], canonical_json(assessment["evidence_refs"]), canonical_json(payload), now()),
        )
        merged_root = False
    return finding_id, merged_root


def _merge_security_assessment(conn, task, result):
    evidence_ids = _insert_evidence(conn, task["task_id"], result.get("evidence", []))
    finding_ids = []
    merged_roots = 0
    for row in result["assessments"]:
        business_intent = dict(row.get("business_intent") or {})
        if business_intent:
            business_intent["evidence_refs"] = _evidence_refs(business_intent["evidence_refs"], evidence_ids)
        security_boundary = dict(row.get("security_boundary") or {})
        if security_boundary:
            security_boundary["evidence_refs"] = _evidence_refs(security_boundary["evidence_refs"], evidence_ids)
        guards = [
            {**guard, "evidence_refs": _evidence_refs(guard["evidence_refs"], evidence_ids)}
            for guard in row["guards"]
        ]
        counter_evidence = [
            {**counter, "evidence_refs": _evidence_refs(counter["evidence_refs"], evidence_ids)}
            for counter in row["counter_evidence"]
        ]
        assessment = {
            **row, "path_id": result["path_id"], "business_intent": business_intent,
            "security_boundary": security_boundary, "guards": guards,
            "counter_evidence": counter_evidence,
            "evidence_refs": _evidence_refs(row["evidence_refs"], evidence_ids),
        }
        assessment["conclusion"] = assessment.get("impact") or assessment.get("demotion_reason") or ""
        root = assessment["root_cause"]
        assessment_id = stable_id("ASSESS", [
            result["path_id"], assessment.get("pattern_id"), assessment["category"],
            assessment.get("operation_fact_id"), root["boundary"],
        ])
        conn.execute(
            """INSERT INTO security_assessments
               (assessment_id,path_id,capability_id,pattern_id,category,operation_fact_id,classification,title,
                severity,cwe,impact,poc,boundary,controlled_property,operation_location,exploitability_json,
                business_intent_json,security_boundary_json,guards_json,counter_evidence_json,demotion_reason,
                evidence_gap,evidence_json,payload_json,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (assessment_id, result["path_id"], assessment.get("capability_id"), assessment.get("pattern_id"),
             assessment["category"], assessment.get("operation_fact_id"), assessment["classification"],
             assessment["title"], assessment.get("severity"), assessment.get("cwe"), assessment.get("impact"),
             assessment.get("poc"), root["boundary"], root["controlled_property"], root["operation_location"],
             canonical_json(assessment["exploitability"]), canonical_json(business_intent),
             canonical_json(security_boundary), canonical_json(guards), canonical_json(counter_evidence),
             assessment.get("demotion_reason"), assessment.get("evidence_gap"),
             canonical_json(assessment["evidence_refs"]), canonical_json(assessment), now()),
        )
        if assessment["classification"] in {"confirmed_vulnerability", "residual_risk"}:
            finding_id, merged = _merge_finding(conn, assessment, assessment_id)
            finding_ids.append(finding_id)
            merged_roots += int(merged)
    return {
        "assessments_created": len(result["assessments"]),
        "findings_affected": len(set(finding_ids)), "root_causes_merged": merged_roots,
    }


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
    result = build_report(run_dir)
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        stamp = now()
        conn.execute("UPDATE runs SET status='complete',updated_at=?,finalized_at=? WHERE run_id=?", (stamp, stamp, run["run_id"]))
        append_event(conn, "run_finalized", run["run_id"], result)
    update_session(paths, "complete")
    return {"ok": True, **result}


def status(run_dir):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = dict(run_row(conn))
        run["capability_filter"] = json.loads(run.pop("capability_filter_json"))
        run["component_filter"] = json.loads(run.pop("component_filter_json"))
        task_counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
        counts = {table: conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"]
                  for table in ("entries", "flows", "paths", "facts", "continuations", "security_assessments", "findings")}
        retry_categories = {}
        for row in conn.execute("SELECT payload_json FROM events WHERE event_type='task_retry'"):
            payload = json.loads(row["payload_json"])
            category = payload.get("category") or str(payload.get("error") or "unknown").split(":", 1)[0]
            retry_categories[category] = retry_categories.get(category, 0) + 1
    return {"ok": True, "run": run, "tasks": task_counts, "objects": counts,
            "retries": {"total": sum(retry_categories.values()), "by_category": retry_categories},
            "readiness": readiness(run_dir)}
