"""Transactional commands for the flow-driven audit runtime."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .common import *
from .contracts import SCHEMA_BY_TASK, normalize_submission, validate_submission
from .store import *


def _run_row(conn):
    row = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
    if row is None:
        raise ValueError("run_not_initialized")
    return row


def _project_candidate_ids(paths, conn=None):
    model = read_json(paths["project_model"], {})
    component_filter = row_json(_run_row(conn), "component_filter_json", []) if conn else []
    return [row["candidate_id"] for row in _candidate_rows(model, component_filter)]


def new_run(reports_root, target_repo, mode="full", capabilities=None, components=None):
    target = Path(target_repo).expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"target_repo_not_found:{target}")
    selected = capabilities or []
    selected_components = list(dict.fromkeys(
        str(component).strip() for component in (components or []) if str(component).strip()
    ))
    if mode == "capability" and not selected:
        raise ValueError("capability_mode_requires_filter")
    if mode == "full" and selected:
        raise ValueError("full_mode_cannot_filter_capabilities")
    load_capabilities(selected)
    root = Path(reports_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run_id = stable_id("RUN", {"target": str(target), "stamp": stamp})
    run_dir = root / f"{target.name}-{stamp}-{run_id[-6:]}"
    paths = ensure_run_dirs(run_dir)
    initialize_database(paths["db"])
    with database(paths["db"]) as conn, transaction(conn):
        stamp_iso = now()
        conn.execute(
            """INSERT INTO runs
               (run_id,target_repo,audit_mode,capability_filter_json,component_filter_json,status,created_at,updated_at,finalized_at)
               VALUES (?,?,?,?,?,?,?,?,NULL)""",
            (run_id, str(target), mode, canonical_json(selected), canonical_json(selected_components),
             "created", stamp_iso, stamp_iso),
        )
        append_event(conn, "run_created", run_id, {
            "target_repo": str(target), "mode": mode, "components": selected_components,
        })
    write_json(paths["session"], {
        "schema_version": 1, "run_id": run_id, "run_dir": str(run_dir),
        "target_repo": str(target), "mode": mode, "capabilities": selected,
        "components": selected_components,
        "status": "created", "created_at": stamp_iso,
    })
    return {"ok": True, "run_id": run_id, "run_dir": str(run_dir)}


def initialize_run(run_dir, project_model):
    paths = ensure_run_dirs(run_dir)
    source = Path(project_model).expanduser().resolve()
    model = read_json(source)
    if not isinstance(model, dict) or model.get("status") != "complete":
        raise ValueError("invalid_project_model")
    if source != paths["project_model"].resolve():
        shutil.copyfile(source, paths["project_model"])
    with database(paths["db"]) as conn, transaction(conn):
        run = _run_row(conn)
        if run["status"] != "created":
            raise ValueError(f"run_already_initialized:{run['status']}")
        component_filter = row_json(run, "component_filter_json", [])
        candidates = _candidate_rows(model, component_filter)
        task_id = enqueue_task(conn, "entry-plan", "entry_planning", payload={
            "project_model": str(paths["project_model"]), "entry_candidates": candidates,
        })
        conn.execute("UPDATE runs SET status='running',updated_at=? WHERE run_id=?", (now(), run["run_id"]))
        append_event(conn, "run_initialized", run["run_id"], {
            "entry_candidates": len(candidates), "components": component_filter,
        })
    _update_session(paths, "running")
    return {"ok": True, "task_id": task_id, "entry_candidates": len(candidates)}


def _component_aliases(candidate):
    name = str(candidate.get("component_name") or "").strip()
    module = str(candidate.get("module_name") or "").strip()
    if not name:
        return set()
    aliases = {name, name.removeprefix("./"), name.rsplit(".", 1)[-1]}
    for short_name in tuple(aliases):
        if module:
            aliases.update({f"{module}/{short_name}", f"{module}:{short_name}"})
    return aliases


def _candidate_rows(model, component_filter=None):
    rows = [
        row for row in model.get("entry_candidates", [])
        if isinstance(row, dict) and row.get("candidate_id")
    ]
    requested = list(dict.fromkeys(component_filter or []))
    if not requested:
        return rows
    matched = {target: [] for target in requested}
    for row in rows:
        aliases = _component_aliases(row)
        for target in requested:
            if target in aliases:
                matched[target].append(row)
    missing = [target for target, candidates in matched.items() if not candidates]
    if missing:
        raise ValueError("component_has_no_entry_candidates:" + ",".join(missing))
    selected_ids = {
        row["candidate_id"] for candidates in matched.values() for row in candidates
    }
    return [row for row in rows if row["candidate_id"] in selected_ids]


def claim_tasks(run_dir, limit=5, worker="harmony-auditor", lease_seconds=1800, max_workers=5):
    paths = run_paths(run_dir)
    claimed = []
    reclaimed = []
    with database(paths["db"]) as conn, transaction(conn):
        _run_row(conn)
        stamp = now()
        expired = conn.execute(
            "SELECT task_id FROM tasks WHERE status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at<?",
            (stamp,),
        ).fetchall()
        for row in expired:
            conn.execute(
                "UPDATE tasks SET status='queued',lease_owner=NULL,lease_expires_at=NULL,error=?,updated_at=? WHERE task_id=?",
                ("lease_expired", stamp, row["task_id"]),
            )
            reclaimed.append(row["task_id"])
            append_event(conn, "task_lease_expired", row["task_id"], {})

        running = conn.execute("SELECT COUNT(*) n FROM tasks WHERE status='running'").fetchone()["n"]
        capacity = max(0, int(max_workers) - running)
        claim_limit = min(max(1, min(int(limit), 32)), capacity)
        if claim_limit == 0:
            return {
                "ok": True, "tasks": [], "count": 0, "running": running,
                "capacity": 0, "reclaimed": reclaimed, "reason": "worker_pool_full",
            }
        rows = conn.execute(
            """SELECT t.* FROM tasks t
               WHERE t.status='queued' AND NOT EXISTS (
                 SELECT 1 FROM task_dependencies d JOIN tasks p ON p.task_id=d.depends_on
                 WHERE d.task_id=t.task_id AND p.status<>'completed')
               ORDER BY t.created_at,t.task_id LIMIT ?""", (claim_limit,),
        ).fetchall()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()
        for row in rows:
            conn.execute(
                "UPDATE tasks SET status='running',attempts=attempts+1,lease_owner=?,lease_expires_at=?,updated_at=? WHERE task_id=?",
                (worker, expires, now(), row["task_id"]),
            )
            updated = conn.execute("SELECT * FROM tasks WHERE task_id=?", (row["task_id"],)).fetchone()
            doc = task_document(updated)
            doc["input"] = _task_context(conn, updated)
            task_path = paths["tasks"] / f"{row['task_id']}.json"
            submission_path = paths["tasks"] / f"{row['task_id']}.submission.json"
            doc["task_file"] = str(task_path)
            doc["submission_file"] = str(submission_path)
            doc["result_schema_file"] = str(SCHEMAS_DIR / SCHEMA_BY_TASK[row["kind"]])
            submission_path.unlink(missing_ok=True)
            write_json(task_path, doc)
            claimed.append({
                "task_id": row["task_id"], "kind": row["kind"],
                "assigned_agent": row["agent"], "attempt": updated["attempts"],
                "task_file": str(task_path), "submission_file": str(submission_path),
                "result_schema_file": doc["result_schema_file"],
            })
            append_event(conn, "task_claimed", row["task_id"], {"worker": worker})
        running += len(claimed)
    return {
        "ok": True, "tasks": claimed, "count": len(claimed), "running": running,
        "capacity": max(0, int(max_workers) - running), "reclaimed": reclaimed,
    }


def _flow_context(conn, flow_id):
    flow = conn.execute("SELECT * FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
    if flow is None:
        return None
    doc = dict(flow)
    for source, target in (("controlled_values_json", "controlled_values"), ("payload_json", "payload")):
        doc[target] = json.loads(doc.pop(source))
    doc["facts"] = []
    for row in conn.execute("SELECT * FROM facts WHERE flow_id=? ORDER BY created_at,fact_id", (flow_id,)):
        fact = dict(row)
        fact["evidence_refs"] = json.loads(fact.pop("evidence_json"))
        fact["payload"] = json.loads(fact.pop("payload_json"))
        doc["facts"].append(fact)
    doc["edges"] = [dict(row) for row in conn.execute("SELECT * FROM edges WHERE flow_id=? ORDER BY created_at,edge_id", (flow_id,))]
    return doc


def _attach_ancestors(conn, flow):
    ancestors = []
    seen = {flow["flow_id"]}
    parent_id = flow.get("parent_flow_id")
    while parent_id and parent_id not in seen:
        seen.add(parent_id)
        parent = _flow_context(conn, parent_id)
        if not parent:
            break
        ancestors.append(parent)
        parent_id = parent.get("parent_flow_id")
    flow["ancestors"] = ancestors
    return flow


def _task_context(conn, task):
    payload = row_json(task, "input_json", {})
    if task["kind"] == "entry_exploration":
        return payload
    if task["kind"] in {"shared_handler", "chain_correlation"}:
        continuations = []
        for row in conn.execute("SELECT * FROM continuations WHERE task_id=? ORDER BY created_at", (task["task_id"],)):
            item = dict(row)
            item["evidence_refs"] = json.loads(item.pop("evidence_json"))
            item["parent_flow"] = _flow_context(conn, row["flow_id"])
            root_entry = conn.execute(
                "SELECT e.* FROM entries e JOIN flows f ON f.root_entry_id=e.entry_id WHERE f.flow_id=?", (row["flow_id"],)
            ).fetchone()
            profile_ids = set(row_json(root_entry, "profiles_json", [])) if root_entry else set()
            item["capability_profiles"] = [cap for cap in load_capabilities() if cap["capability_id"] in profile_ids]
            continuations.append(item)
        return {**payload, "continuations": continuations}
    if task["kind"] in {"pattern_evaluation", "flow_validation"}:
        flow = _flow_context(conn, task["subject_id"])
        if flow:
            _attach_ancestors(conn, flow)
        entry = None
        if flow:
            row = conn.execute("SELECT * FROM entries WHERE entry_id=?", (flow["root_entry_id"],)).fetchone()
            if row:
                entry = dict(row)
                entry["profiles"] = json.loads(entry.pop("profiles_json"))
                entry["discriminator"] = json.loads(entry.pop("discriminator_json"))
                entry["payload"] = json.loads(entry.pop("payload_json"))
        hypotheses = [dict(row) for row in conn.execute("SELECT * FROM hypotheses WHERE flow_id=?", (task["subject_id"],))]
        profile_ids = set((entry or {}).get("profiles", []))
        capability_profiles = [row for row in load_capabilities() if row["capability_id"] in profile_ids]
        return {**payload, "flow": flow, "entry": entry, "capability_profiles": capability_profiles, "hypotheses": hypotheses}
    return payload


def submit_result(run_dir, task_id, input_path):
    paths = run_paths(run_dir)
    result = read_json(input_path)
    if not isinstance(result, dict):
        raise ValueError("invalid_result_json")
    with database(paths["db"]) as conn, transaction(conn):
        task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if task is None:
            raise ValueError("task_not_found")
        if task["status"] != "running":
            raise ValueError(f"task_not_running:{task['status']}")
        result = normalize_submission(result, task["kind"])
        errors = validate_submission(result, task, conn, _project_candidate_ids(paths, conn))
        if errors:
            raise ValueError("invalid_submission:" + "|".join(errors))
        if task["kind"] == "entry_planning":
            summary = _merge_entry_plan(conn, task, result)
        elif task["kind"] in {"entry_exploration", "shared_handler", "chain_correlation"}:
            summary = _merge_flows(conn, task, result)
        elif task["kind"] == "pattern_evaluation":
            summary = _merge_patterns(conn, task, result)
        elif task["kind"] == "flow_validation":
            summary = _merge_validation(conn, task, result)
        else:
            raise ValueError(f"unsupported_task_kind:{task['kind']}")
        result_ref = paths["tasks"] / f"{task_id}.result.json"
        write_json(result_ref, result)
        conn.execute(
            "UPDATE tasks SET status='completed',result_ref=?,lease_owner=NULL,lease_expires_at=NULL,error=NULL,updated_at=? WHERE task_id=?",
            (str(result_ref), now(), task_id),
        )
        conn.execute("UPDATE continuations SET status='resolved',updated_at=? WHERE task_id=?", (now(), task_id))
        append_event(conn, "task_completed", task_id, summary)
    export_state(run_dir)
    submitted = Path(input_path).expanduser().resolve()
    if submitted != result_ref.resolve():
        submitted.unlink(missing_ok=True)
    return {"ok": True, "task_id": task_id, **summary}


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


def _merge_entry_plan(conn, task, result):
    evidence_ids = _insert_evidence(conn, task["task_id"], result.get("evidence", []))
    capabilities = load_capabilities(row_json(_run_row(conn), "capability_filter_json", []))
    created = []
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
        enqueue_task(conn, f"entry:{entry_id}", "entry_exploration", entry_id, {
            "entry": {**entry_payload, "entry_id": entry_id}, "capability_profiles": profile_rows,
        }, [task["task_id"]])
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
    return {"entries_created": len(created)}


def _merge_flows(conn, task, result):
    evidence_ids = _insert_evidence(conn, task["task_id"], result.get("evidence", []))
    produced = []
    for item in result["flows"]:
        item_payload = {
            **item,
            "facts": [{**row, "evidence_refs": _evidence_refs(row["evidence_refs"], evidence_ids)} for row in item["facts"]],
            "edges": [{**row, "evidence_refs": _evidence_refs(row["evidence_refs"], evidence_ids)} for row in item["edges"]],
            "continuations": [{**row, "evidence_refs": _evidence_refs(row["evidence_refs"], evidence_ids)} for row in item["continuations"]],
        }
        canonical_flow_key = flow_identity_key(item)
        flow_id = stable_id("FLOW", canonical_flow_key)
        old = conn.execute("SELECT * FROM flows WHERE flow_key=?", (canonical_flow_key,)).fetchone()
        if old and any(old[k] != item[v] for k, v in (
            ("root_entry_id", "root_entry_id"), ("branch_key", "branch_key"),
            ("controlled_property", "controlled_property"))):
            raise ValueError(f"flow_identity_conflict:{canonical_flow_key}")
        stamp = now()
        conn.execute(
            """INSERT INTO flows(flow_id,flow_key,root_entry_id,parent_flow_id,branch_key,controlled_property,current_symbol,status,controlled_values_json,payload_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(flow_key) DO UPDATE SET current_symbol=excluded.current_symbol,status=excluded.status,
                 controlled_values_json=excluded.controlled_values_json,payload_json=excluded.payload_json,updated_at=excluded.updated_at""",
            (flow_id, canonical_flow_key, item["root_entry_id"], item.get("parent_flow_id"), item["branch_key"],
             item["controlled_property"], item["current_symbol"], item["status"], canonical_json(item["controlled_values"]),
             canonical_json(item_payload), stamp, stamp),
        )
        fact_ids = {}
        for fact in item["facts"]:
            fact_id = stable_id("FACT", [flow_id, fact["fact_key"]])
            fact_ids[fact["fact_key"]] = fact_id
            fact_payload = {**fact, "evidence_refs": _evidence_refs(fact["evidence_refs"], evidence_ids)}
            conn.execute(
                """INSERT OR IGNORE INTO facts(fact_id,fact_key,flow_id,fact_type,body,location,evidence_json,payload_json,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (fact_id, fact["fact_key"], flow_id, fact["type"], fact["body"], fact.get("location"),
                 canonical_json(fact_payload["evidence_refs"]), canonical_json(fact_payload), now()),
            )
        for row in conn.execute("SELECT fact_key,fact_id FROM facts WHERE flow_id=?", (flow_id,)):
            fact_ids[row["fact_key"]] = row["fact_id"]
        parent_id = item.get("parent_flow_id")
        seen_parents = set()
        while parent_id and parent_id not in seen_parents:
            seen_parents.add(parent_id)
            for row in conn.execute("SELECT fact_key,fact_id FROM facts WHERE flow_id=?", (parent_id,)):
                fact_ids.setdefault(row["fact_key"], row["fact_id"])
            parent = conn.execute("SELECT parent_flow_id FROM flows WHERE flow_id=?", (parent_id,)).fetchone()
            parent_id = parent["parent_flow_id"] if parent else None
        for edge in item["edges"]:
            edge_id = stable_id("EDGE", [flow_id, edge["from"], edge["to"], edge["kind"]])
            conn.execute(
                "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?)",
                (edge_id, flow_id, fact_ids[edge["from"]], fact_ids[edge["to"]], edge["kind"],
                 canonical_json(_evidence_refs(edge["evidence_refs"], evidence_ids)), now()),
            )
        for continuation in item["continuations"]:
            continuation_payload = {**continuation, "evidence_refs": _evidence_refs(continuation["evidence_refs"], evidence_ids)}
            continuation_id = stable_id("CONT", [flow_id, continuation["semantic_key"]])
            if continuation["kind"] == "shared_handler":
                semantic = "shared:" + normalize_text(continuation["target"])
                kind = "shared_handler"
            else:
                semantic = "chain:" + continuation_id
                kind = "chain_correlation"
            existing_task = conn.execute("SELECT * FROM tasks WHERE semantic_key=?", (semantic,)).fetchone()
            if kind == "shared_handler" and existing_task and existing_task["status"] != "queued":
                semantic = "shared-join:" + continuation_id
                kind = "chain_correlation"
            next_task = enqueue_task(conn, semantic, kind, flow_id, {
                "parent_flow_id": flow_id, "continuation": continuation_payload,
            }, [task["task_id"]])
            conn.execute(
                """INSERT OR IGNORE INTO continuations(continuation_id,semantic_key,flow_id,kind,target,status,task_id,evidence_json,created_at,updated_at)
                   VALUES (?,?,?,?,?,'open',?,?,?,?)""",
                (continuation_id, continuation["semantic_key"], flow_id, continuation["kind"], continuation["target"],
                 next_task, canonical_json(_evidence_refs(continuation["evidence_refs"], evidence_ids)), now(), now()),
            )
        if item["status"] in TERMINAL_FLOW_STATES:
            enqueue_task(conn, f"pattern:{flow_id}", "pattern_evaluation", flow_id, {
                "flow_id": flow_id, "flow_key": canonical_flow_key}, [task["task_id"]])
        produced.append(flow_id)
    return {"flows_merged": len(produced), "flow_ids": produced}


def _merge_patterns(conn, task, result):
    for row in result["assessments"]:
        hypothesis_id = stable_id("HYP", [result["flow_id"], row["capability_id"], row["pattern_id"]])
        conn.execute(
            "INSERT INTO hypotheses VALUES (?,?,?,?,?,?,?,?,?)",
            (hypothesis_id, result["flow_id"], row["capability_id"], row["pattern_id"], row["verdict"],
             row["boundary"], row["reason"], canonical_json(row["evidence_refs"]), now()),
        )
    enqueue_task(conn, f"validate:{result['flow_id']}", "flow_validation", result["flow_id"], {
        "flow_id": result["flow_id"], "assessments": result["assessments"]}, [task["task_id"]])
    return {"hypotheses_created": len(result["assessments"])}


def _merge_validation(conn, task, result):
    root = result["root_cause"]
    root_key = canonical_json({
        "operation": normalize_location(root["operation_location"]), "branch": normalize_text(root["branch"]),
        "boundary": normalize_text(root["boundary"]), "controlled_property": normalize_text(root["controlled_property"]),
    })
    finding_id = stable_id("FIND", root_key)
    payload = {**result, "reason": result["reason"], "guards": result["guards"]}
    existing = conn.execute("SELECT * FROM findings WHERE root_cause_key=?", (root_key,)).fetchone()
    if existing:
        merged = sorted(set(row_json(existing, "evidence_json", [])) | set(result["evidence_refs"]))
        old_payload = row_json(existing, "payload_json", {})
        related = sorted(set(old_payload.get("related_flow_ids", [existing["flow_id"]])) | {result["flow_id"]})
        validations = old_payload.get("validations", [{
            "flow_id": existing["flow_id"], "classification": existing["classification"],
            "reason": old_payload.get("reason", ""),
        }])
        validations.append({"flow_id": result["flow_id"], "classification": result["classification"], "reason": result["reason"]})
        payload["related_flow_ids"] = related
        payload["validations"] = sorted(validations, key=lambda row: (row["flow_id"], row["classification"], row["reason"]))
        rank = {"benign_business_flow": 1, "insufficient_evidence": 2, "protected_exposure": 3,
                "residual_risk": 4, "confirmed_vulnerability": 5}
        if rank[result["classification"]] > rank[existing["classification"]]:
            conn.execute(
                """UPDATE findings SET flow_id=?,classification=?,title=?,severity=?,cwe=?,impact=?,poc=?,
                   boundary=?,controlled_property=?,operation_location=?,evidence_json=?,payload_json=? WHERE finding_id=?""",
                (result["flow_id"], result["classification"], result["title"], result["severity"], result["cwe"],
                 result["impact"], result["poc"], result["boundary"], root["controlled_property"],
                 root["operation_location"], canonical_json(merged), canonical_json(payload), existing["finding_id"]),
            )
        else:
            old_payload["related_flow_ids"] = related
            old_payload["validations"] = payload["validations"]
            conn.execute("UPDATE findings SET evidence_json=?,payload_json=? WHERE finding_id=?",
                         (canonical_json(merged), canonical_json(old_payload), existing["finding_id"]))
        finding_id = existing["finding_id"]
        merged_root = True
    else:
        payload["related_flow_ids"] = [result["flow_id"]]
        conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding_id, root_key, result["flow_id"], result["classification"], result["title"], result["severity"],
             result["cwe"], result["impact"], result["poc"], result["boundary"], root["controlled_property"],
             root["operation_location"], canonical_json(result["evidence_refs"]), canonical_json(payload), now()),
        )
        merged_root = False
    return {"finding_id": finding_id, "root_cause_merged": merged_root}


def fail_task(run_dir, task_id, error, retryable=False, max_attempts=2):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if task is None or task["status"] != "running":
            raise ValueError("task_not_running")
        status = "queued" if retryable and task["attempts"] < max_attempts else "failed"
        conn.execute("UPDATE tasks SET status=?,error=?,lease_owner=NULL,lease_expires_at=NULL,updated_at=? WHERE task_id=?",
                     (status, error, now(), task_id))
        append_event(conn, "task_retry" if status == "queued" else "task_failed", task_id, {"error": error})
    return {"ok": True, "task_id": task_id, "status": status}


def readiness(run_dir):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = _run_row(conn)
        counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
        open_continuations = conn.execute("SELECT COUNT(*) n FROM continuations WHERE status='open'").fetchone()["n"]
        candidates = len(_project_candidate_ids(paths, conn))
        dispositions = conn.execute("SELECT COUNT(*) n FROM entry_dispositions").fetchone()["n"]
        reasons = []
        if counts.get("queued", 0) or counts.get("running", 0): reasons.append("unfinished_tasks")
        if counts.get("failed", 0): reasons.append("failed_tasks")
        if open_continuations: reasons.append("open_continuations")
        if candidates != dispositions: reasons.append("entry_coverage_incomplete")
        if run["status"] == "created": reasons.append("run_not_initialized")
        return {"ok": not reasons, "ready": not reasons, "reasons": reasons, "task_counts": counts,
                "open_continuations": open_continuations, "candidate_coverage": {"total": candidates, "disposed": dispositions}}


def export_state(run_dir):
    from .reporting import export_state as _export
    return _export(run_dir)


def finalize_run(run_dir):
    from .reporting import build_report
    ready = readiness(run_dir)
    if not ready["ready"]:
        raise ValueError("run_not_ready:" + ",".join(ready["reasons"]))
    result = build_report(run_dir)
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        run = _run_row(conn)
        stamp = now()
        conn.execute("UPDATE runs SET status='complete',updated_at=?,finalized_at=? WHERE run_id=?", (stamp, stamp, run["run_id"]))
        append_event(conn, "run_finalized", run["run_id"], result)
    _update_session(paths, "complete")
    return {"ok": True, **result}


def _update_session(paths, status):
    session = read_json(paths["session"], {})
    session["status"] = status
    session["updated_at"] = now()
    write_json(paths["session"], session)


def status(run_dir):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = dict(_run_row(conn))
        run["capability_filter"] = json.loads(run.pop("capability_filter_json"))
        run["component_filter"] = json.loads(run.pop("component_filter_json"))
        task_counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
        counts = {table: conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"]
                  for table in ("entries", "flows", "facts", "continuations", "hypotheses", "findings")}
    return {"ok": True, "run": run, "tasks": task_counts, "objects": counts, "readiness": readiness(run_dir)}
