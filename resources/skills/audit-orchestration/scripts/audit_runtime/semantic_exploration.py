"""Range-based component exploration with durable branch work and atomic submissions."""
from __future__ import annotations

from functools import lru_cache
from graphlib import CycleError, TopologicalSorter
from pathlib import Path

from jsonschema import Draft202012Validator

from .common import SCHEMAS_DIR, canonical_json, now, read_json, run_paths, stable_id, write_json
from .store import append_event, database, row_json, transaction

ROUND_LINE_BUDGET = 2000
MAX_COMPONENT_ANALYZED_LINES = 200000
STEP_SCHEMA = "component-exploration-step.schema.json"


@lru_cache(maxsize=1)
def _validator():
    return Draft202012Validator(read_json(SCHEMAS_DIR / STEP_SCHEMA))


def _task(conn, task_id, attempt):
    task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    if not task:
        raise ValueError("task_not_found")
    if task["kind"] != "component_semantic_analysis":
        raise ValueError("task_not_component_semantic_analysis")
    if task["status"] != "running":
        raise ValueError(f"task_not_running:{task['status']}")
    if task["attempts"] != int(attempt):
        raise ValueError(f"stale_attempt:expected={task['attempts']}:actual={attempt}")
    return task


def work_rows(conn, exploration_id):
    return conn.execute(
        """SELECT w.*,n.scope_json FROM exploration_work_items w
           JOIN exploration_nodes n ON n.node_id=w.node_id
           WHERE w.exploration_id=? ORDER BY w.discovered_order,w.work_id""",
        (exploration_id,),
    ).fetchall()


def _normalize_scope(scope):
    scope = dict(scope)
    scope.setdefault("start_column", 1)
    scope.setdefault("end_column", 1)
    symbol = dict(scope["symbol"])
    if symbol.get("file_path"):
        symbol["file_path"] = symbol["file_path"].replace("\\", "/")
    scope["symbol"] = symbol
    return scope


def _normalize_state(state):
    state = dict(state)
    for key in ("controlled_properties", "security_checks"):
        state[key] = sorted(state.get(key, []), key=canonical_json)
    return state


def _identity(exploration_id, scope, state, conditions, dependencies=()):
    node_id = stable_id("XNODE", [exploration_id, _normalize_scope(scope)])
    work_id = stable_id("XWORK", [node_id, _normalize_state(state), sorted(set(conditions)), sorted(dependencies)])
    return node_id, work_id


def _insert_work(conn, exploration_id, scope, state, conditions, depth, result=None, dependencies=()):
    scope = _normalize_scope(scope)
    node_id, work_id = _identity(exploration_id, scope, state, conditions, dependencies)
    stamp = now()
    conn.execute("INSERT OR IGNORE INTO exploration_nodes VALUES (?,?,?,?)",
                 (node_id, exploration_id, canonical_json(scope), stamp))
    order = conn.execute(
        "SELECT COALESCE(MAX(discovered_order),-1)+1 FROM exploration_work_items WHERE exploration_id=?",
        (exploration_id,),
    ).fetchone()[0]
    conn.execute(
        """INSERT OR IGNORE INTO exploration_work_items
           (work_id,node_id,exploration_id,state_json,conditions_json,status,depth,
            discovered_order,result_json,dependencies_json,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (work_id, node_id, exploration_id, canonical_json(_normalize_state(state)),
         canonical_json(sorted(set(conditions))), "completed" if result else "queued",
         depth, order, canonical_json(result) if result else None,
         canonical_json(sorted(dependencies)), stamp, stamp),
    )
    return work_id


def ensure_component_exploration(conn, entry_id):
    exploration_id = stable_id("EXPLORE", entry_id)
    stamp = now()
    conn.execute(
        """INSERT OR IGNORE INTO component_explorations
           (exploration_id,entry_id,created_at,updated_at) VALUES (?,?,?,?)""",
        (exploration_id, entry_id, stamp, stamp),
    )
    scope = {"symbol": {"qualified_name": "$entry_discovery", "file_path": None,
                        "line": None, "kind": "entry"}, "start": 0, "end": 0, "kind": "entry"}
    state = {"controlled_properties": [], "security_checks": [],
             "principal": {"origin": "unknown", "immediate": "unknown",
                           "origin_binding": "unknown", "authority": "unknown"}}
    _insert_work(conn, exploration_id, scope, state, [], 0)
    return exploration_id


def release_exploration_leases(conn, task_id, attempt):
    count = conn.execute(
        """UPDATE exploration_work_items SET status='queued',lease_task_id=NULL,
           lease_attempt=NULL,updated_at=? WHERE status='leased' AND lease_task_id=?
           AND lease_attempt=?""", (now(), task_id, int(attempt)),
    ).rowcount
    if count:
        append_event(conn, "exploration_leases_released", task_id, {"work_items": count})
    return count


def closed_work_ids(conn, exploration_id):
    rows = {row["work_id"]: row for row in work_rows(conn, exploration_id)}
    children = {key: set() for key in rows}
    for edge in conn.execute("SELECT * FROM exploration_edges WHERE exploration_id=?", (exploration_id,)):
        if edge["relation"] not in {"reuse", "loop"}:
            children[edge["source_work_id"]].add(edge["target_work_id"])
    closed = set()
    for key in TopologicalSorter(children).static_order():
        if rows[key]["status"] == "completed" and children[key] <= closed:
            closed.add(key)
    return closed


def _line_count(result):
    return max(1, sum(span["end"] - span["start"] + 1 for span in (result or {}).get("checked", [])))


def next_exploration_node(run_dir, task_id, attempt, budget=ROUND_LINE_BUDGET):
    if int(budget) <= 0:
        raise ValueError("round_line_budget_must_be_positive")
    from .exploration_context import work_context
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = _task(conn, task_id, attempt)
        exp_id = ensure_component_exploration(conn, task["subject_id"])
        exp = conn.execute("SELECT * FROM component_explorations WHERE exploration_id=?", (exp_id,)).fetchone()
        rows = work_rows(conn, exp_id)
        for row in rows:
            if row["status"] == "leased" and row["lease_attempt"] != int(attempt):
                conn.execute("UPDATE exploration_work_items SET status='queued' WHERE work_id=?", (row["work_id"],))
        rows = work_rows(conn, exp_id)
        completed = [r for r in rows if r["round_no"] == exp["round_no"] + 1 and r["status"] == "completed"]
        lines = sum(_line_count(row_json(r, "result_json", {})) for r in completed)
        paused = any(row_json(r, "submission_json", {}).get("pause_requested") for r in completed)
        node = next((r for r in rows if r["status"] == "leased"), None)
        pending = [r for r in rows if r["status"] == "queued"]
        closed = closed_work_ids(conn, exp_id)
        eligible = [r for r in pending if set(row_json(r, "dependencies_json", [])) <= closed]
        if not node and not (paused or lines >= int(budget)):
            node = max(eligible, key=lambda r: (r["depth"], -r["discovered_order"]), default=None)
        if node:
            conn.execute(
                """UPDATE exploration_work_items SET status='leased',lease_task_id=?,lease_attempt=?,
                   round_no=?,updated_at=? WHERE work_id=?""",
                (task_id, int(attempt), exp["round_no"] + 1, now(), node["work_id"]),
            )
            conn.execute("UPDATE component_explorations SET status='running' WHERE exploration_id=?", (exp_id,))
            context = work_context(conn, exp_id, node["work_id"])
            return {"ok": True, "round_complete": False, "work": context,
                    "entry_assessment": {k: exp[k] for k in ("entry_status", "external_entry_status", "component_summary")} |
                    {"confirmed_external_candidate_ids": row_json(exp, "confirmed_candidates_json", [])},
                    "processed_lines": lines, "round_line_budget": int(budget),
                    "component_work_budget": MAX_COMPONENT_ANALYZED_LINES,
                    "step_schema_file": str(SCHEMAS_DIR / STEP_SCHEMA)}
        blocked = bool(pending and not eligible and not (paused or lines >= int(budget)))
        return {"ok": not blocked, "round_complete": True, "work": None,
                "reason": "dependency_blocked" if blocked else
                ("pause_requested" if paused else "line_budget_reached" if lines >= int(budget) else "no_open_work"),
                "pending_work": len(pending), "processed_lines": lines,
                "round_line_budget": int(budget)}


def _located(evidence):
    return any(e.get("location") or e.get("content_ref") for e in evidence)


def _span_covered(scope, spans):
    cursor = scope["start"]
    for span in sorted(spans, key=lambda s: (s["start"], s["end"])):
        if span["start"] > cursor:
            return False
        cursor = max(cursor, span["end"] + 1)
    return cursor > scope["end"]


def _validate_step(conn, task, row, step):
    errors = []
    scope = row_json(row, "scope_json", {})
    is_entry = scope["kind"] == "entry"
    ranges = step["ranges"]
    refs = [r["ref"] for r in ranges]
    if len(set(refs)) != len(refs) or "$current" in refs:
        errors.append("range_refs_must_be_unique")
    known = {r["work_id"]: r for r in work_rows(conn, row["exploration_id"])}
    if set(refs) & known.keys():
        errors.append("local_range_ref_conflicts_with_existing_work")
    endpoints = {"$current", *refs, *known}
    closed = closed_work_ids(conn, row["exploration_id"])
    scopes = {"$current": scope, **{r["ref"]: r["scope"] for r in ranges}}
    results = {"$current": step["result"], **{r["ref"]: r["result"] for r in ranges}}
    outgoing = {}
    for edge in step["transitions"]:
        if edge["from"] not in {"$current", *refs} or edge["to"] not in endpoints:
            errors.append("transition_reference_unknown")
        outgoing.setdefault(edge["from"], []).append(edge)
        if not _located(edge["evidence"]):
            errors.append("transition_requires_located_evidence")
        if edge["relation"] == "reuse" and edge["to"] not in closed:
            errors.append("reuse_requires_closed_existing_work")
        if edge["from"] == edge["to"] and edge["relation"] not in {"reuse", "loop"}:
            errors.append("self_transition_requires_proven_reuse")
    reached = {"$current"}
    for _ in range(len(refs) + 1):
        reached |= {e["to"] for e in step["transitions"] if e["from"] in reached}
    if set(refs) - reached:
        errors.append("ranges_without_incoming_transition")
    for item in ranges:
        if not set(item["wait_for"]) <= endpoints - {"$current", item["ref"]}:
            errors.append(f"invalid_dependencies:{item['ref']}")
        if item["scope"]["end"] < item["scope"]["start"] or not item["scope"]["symbol"].get("file_path"):
            errors.append(f"invalid_scope:{item['ref']}")
        if item["result"] and item["wait_for"]:
            errors.append("inline_result_cannot_wait_for_unfinished_work")
    for ref, result in results.items():
        if result is None:
            continue
        here = scopes[ref]
        edges = outgoing.get(ref, [])
        for span in result["checked"]:
            if span["end"] < span["start"] or span["start"] < here["start"] or span["end"] > here["end"]:
                errors.append(f"checked_span_outside_scope:{ref}")
        if here["kind"] != "entry":
            delegated = [scopes[e["to"]] for e in edges if e["to"] in scopes
                         and scopes[e["to"]]["symbol"] == here["symbol"]
                         and scopes[e["to"]]["start"] >= here["start"]
                         and scopes[e["to"]]["end"] <= here["end"]]
            if not _span_covered(here, result["checked"] + delegated) and not result["gaps"]:
                errors.append(f"unexamined_scope_requires_work_or_gap:{ref}")
        term = result["termination"]
        if term and not _located(term["evidence"]):
            errors.append(f"termination_requires_located_evidence:{ref}")
        if term and term["kind"] in {"return", "throw"} and any(e["relation"] == "sequence" for e in edges):
            errors.append(f"exit_cannot_fall_through:{ref}")
        if here["kind"] == "choice" and len([e for e in edges if e["relation"] == "branch"]) < 2:
            errors.append(f"choice_requires_all_exits:{ref}")
        if any(e["relation"] == "call" for e in edges) and not (
                any(e["relation"] in {"return", "exception"} for e in edges)
                or (term and term["kind"] in {"return", "throw"})):
            errors.append(f"call_requires_caller_continuation:{ref}")
        if term and term["kind"] in {"component_boundary", "platform_boundary", "third_party_boundary"}:
            callers = [e["from"] for e in step["transitions"] if e["to"] == ref and e["relation"] == "call"]
            continuation = any(e["relation"] in {"return", "exception"} for e in edges)
            continuation |= any(any(e["relation"] in {"return", "exception"} for e in outgoing.get(caller, []))
                                for caller in callers)
            if ref == "$current":
                continuation |= conn.execute(
                    """SELECT 1 FROM exploration_edges incoming
                       JOIN exploration_edges followup
                         ON followup.source_work_id=incoming.source_work_id
                        AND followup.exploration_id=incoming.exploration_id
                       WHERE incoming.exploration_id=? AND incoming.target_work_id=?
                         AND incoming.relation='call'
                         AND followup.relation IN ('return','exception') LIMIT 1""",
                    (row["exploration_id"], row["work_id"]),
                ).fetchone() is not None
            if not continuation:
                errors.append(f"boundary_requires_caller_continuation:{ref}")
        if not edges and not term and not result["gaps"] and here["kind"] != "entry":
            errors.append(f"range_requires_exit_or_continuation:{ref}")
        for gap in result["gaps"]:
            if not _located(gap["evidence"]):
                errors.append("gap_requires_located_evidence")
    assessment = step.get("entry_assessment")
    if is_entry and not assessment:
        errors.append("entry_assessment_required")
    if assessment:
        if not is_entry and not _located(assessment.get("evidence", [])):
            errors.append("entry_update_requires_evidence")
        if assessment["entry_status"] == "excluded" and (
                assessment["external_entry_status"] != "excluded" or ranges):
            errors.append("excluded_entry_cannot_have_work")
        if assessment["external_entry_status"] == "confirmed":
            if assessment["entry_status"] != "confirmed" or not assessment["confirmed_external_candidate_ids"]:
                errors.append("confirmed_external_entry_requires_candidate")
        elif assessment["confirmed_external_candidate_ids"]:
            errors.append("unconfirmed_external_entry_cannot_list_candidates")
        if is_entry and assessment["entry_status"] == "confirmed" and not ranges:
            errors.append("confirmed_entry_requires_ranges")
        if assessment["entry_status"] == "excluded" and any(
                row_json(r, "result_json", {}).get(key)
                for r in known.values() for key in ("operation_groups", "component_calls")):
            errors.append("excluded_entry_conflicts_with_recorded_operations")
    # State references must resolve to retained or newly declared source facts.
    checks = list(row_json(row, "state_json", {}).get("security_checks", []))
    for prior in known.values():
        checks.extend(row_json(prior, "result_json", {}).get("security_checks", []))
    for result in results.values():
        if result:
            checks.extend(result["security_checks"])
            for owner in result["operation_groups"] + result["component_calls"]:
                checks.extend(owner.get("security_checks", []))
    def check_key(check):
        return canonical_json({k: check.get(k) for k in ("location", "subject_kind", "validated_property")})
    check_keys = {check_key(c) for c in checks}
    for item in ranges:
        if any(check_key(c) not in check_keys for c in item["state"]["security_checks"]):
            errors.append(f"security_check_not_evidenced:{item['ref']}")
    # Reuse is exact-context only; branches may share code structure but not analysis.
    for edge in step["transitions"]:
        if edge["relation"] == "reuse" and edge["to"] in known:
            source = next((r for r in ranges if r["ref"] == edge["from"]), None)
            state = source["state"] if source else row_json(row, "state_json", {})
            conditions = source["conditions"] if source else row_json(row, "conditions_json", [])
            target = known[edge["to"]]
            if (_normalize_state(state) != row_json(target, "state_json", {})
                    or sorted(set(conditions)) != row_json(target, "conditions_json", [])):
                errors.append("reuse_context_mismatch")
        if edge["relation"] == "loop":
            local = {r["ref"]: r for r in ranges}
            def edge_context(ref):
                if ref in local:
                    return _normalize_state(local[ref]["state"]), sorted(set(local[ref]["conditions"]))
                target = row if ref == "$current" else known.get(ref)
                return (row_json(target, "state_json", {}), row_json(target, "conditions_json", [])) if target else None
            if edge_context(edge["from"]) != edge_context(edge["to"]):
                errors.append("loop_requires_same_relevant_state")
    if not errors:
        from .semantic_results import validate_exploration_step_semantics
        for ref, result in results.items():
            if result is not None:
                errors.extend(validate_exploration_step_semantics(conn, task, scopes[ref], step.get("entry_assessment"), result))
    return errors


def record_exploration_step(run_dir, task_id, attempt, input_path):
    step = read_json(input_path)
    if not isinstance(step, dict):
        return {"ok": True, "accepted": False, "errors": ["invalid_step_json"]}
    errors = [f"schema:{e.json_path}:{e.message}" for e in _validator().iter_errors(step)]
    if errors:
        return {"ok": True, "accepted": False, "errors": sorted(errors)}
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = _task(conn, task_id, attempt)
        exp_id = ensure_component_exploration(conn, task["subject_id"])
        rows = {r["work_id"]: r for r in work_rows(conn, exp_id)}
        row = rows.get(step["work_id"])
        if not row:
            raise ValueError("exploration_work_not_found")
        if row["status"] == "completed":
            if row_json(row, "submission_json", {}) == step:
                return {"ok": True, "accepted": True, "idempotent": True, "work_id": row["work_id"]}
            raise ValueError("exploration_work_already_recorded")
        if row["status"] != "leased" or row["lease_task_id"] != task_id or row["lease_attempt"] != int(attempt):
            raise ValueError("exploration_work_not_leased_by_task")
        errors = _validate_step(conn, task, row, step)
        if errors:
            return {"ok": True, "accepted": False, "errors": errors}
        refs = {"$current": row["work_id"], **{key: key for key in rows}}
        identities = set()
        local = {item["ref"]: item for item in step["ranges"]}
        try:
            order = list(TopologicalSorter({key: item["wait_for"] for key, item in local.items()}).static_order())
        except CycleError:
            return {"ok": True, "accepted": False, "errors": ["dependency_cycle"]}
        for key in order:
            if key not in local:
                continue
            item = local[key]
            dependencies = [refs[dependency] for dependency in item["wait_for"]]
            _, identity = _identity(exp_id, item["scope"], item["state"], item["conditions"], dependencies)
            if identity in identities:
                return {"ok": True, "accepted": False, "errors": ["duplicate_range_use_one_ref"]}
            identities.add(identity)
            if identity == row["work_id"]:
                return {"ok": True, "accepted": False, "errors": ["new_range_must_advance_or_use_existing_reference"]}
            if identity in rows and item["result"] and row_json(rows[identity], "result_json", {}) != item["result"]:
                return {"ok": True, "accepted": False, "errors": ["existing_range_result_conflict"]}
            refs[item["ref"]] = identity
        # Include coverage descendants when checking waiting dependencies.
        deps = {key: set(row_json(value, "dependencies_json", [])) for key, value in rows.items()}
        for item in step["ranges"]:
            deps[refs[item["ref"]]] = {refs[x] for x in item["wait_for"]}
        graph = {key: set(value) for key, value in deps.items()}
        for edge in conn.execute("SELECT * FROM exploration_edges WHERE exploration_id=?", (exp_id,)):
            if edge["relation"] not in {"reuse", "loop"}:
                graph.setdefault(edge["source_work_id"], set()).add(edge["target_work_id"])
        for edge in step["transitions"]:
            if edge["relation"] not in {"reuse", "loop"}:
                graph.setdefault(refs[edge["from"]], set()).add(refs[edge["to"]])
        try:
            TopologicalSorter(graph).prepare()
        except CycleError:
            return {"ok": True, "accepted": False, "errors": ["dependency_cycle"]}
        for item in step["ranges"]:
            work_id = _insert_work(conn, exp_id, item["scope"], item["state"],
                                   item["conditions"], row["depth"] + 1, item["result"],
                                   deps[refs[item["ref"]]])
            if item["result"] and work_id not in rows:
                conn.execute("UPDATE exploration_work_items SET round_no=? WHERE work_id=?", (row["round_no"], work_id))
        for edge in step["transitions"]:
            source, target = refs[edge["from"]], refs[edge["to"]]
            identity = [exp_id, source, target, edge["relation"], edge["condition"]]
            conn.execute("INSERT OR IGNORE INTO exploration_edges VALUES (?,?,?,?,?,?,?,?)",
                         (stable_id("XEDGE", identity), exp_id, source, target, edge["relation"],
                          edge["condition"], canonical_json(edge["evidence"]), now()))
        conn.execute(
            """UPDATE exploration_work_items SET status='completed',result_json=?,submission_json=?,
               updated_at=? WHERE work_id=?""",
            (canonical_json(step["result"]), canonical_json(step), now(), row["work_id"]),
        )
        assessment = step.get("entry_assessment")
        if assessment:
            conn.execute(
                """UPDATE component_explorations SET entry_status=?,external_entry_status=?,
                   confirmed_candidates_json=?,component_summary=?,updated_at=? WHERE exploration_id=?""",
                (assessment["entry_status"], assessment["external_entry_status"],
                 canonical_json(assessment["confirmed_external_candidate_ids"]),
                 assessment["component_summary"], now(), exp_id),
            )
        append_event(conn, "exploration_work_recorded", row["work_id"],
                     {"task_id": task_id, "ranges": len(step["ranges"]), "pause_requested": step["pause_requested"]})
        return {"ok": True, "accepted": True, "work_id": row["work_id"], "range_refs": refs,
                "work_status": "completed", "scope_complete": row["work_id"] in closed_work_ids(conn, exp_id)}


def finish_exploration_round(run_dir, task_id, attempt):
    from .semantic_results import build_exploration_semantic_result, materialize_semantic_result
    paths = run_paths(run_dir)
    result_ref = None
    summary = {}
    try:
        with database(paths["db"]) as conn, transaction(conn):
            task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if task and task["status"] == "completed" and task["attempts"] == int(attempt):
                return {"ok": True, "accepted": True, "task_status": "completed",
                        "task_id": task_id, "result_ref": task["result_ref"], "idempotent": True}
            task = _task(conn, task_id, attempt)
            exp_id = ensure_component_exploration(conn, task["subject_id"])
            rows = work_rows(conn, exp_id)
            if any(r["status"] == "leased" for r in rows):
                return {"ok": True, "accepted": False, "errors": ["leased_work_must_be_recorded"]}
            pending = [r for r in rows if r["status"] == "queued"]
            closed = closed_work_ids(conn, exp_id)
            if pending and not any(set(row_json(r, "dependencies_json", [])) <= closed for r in pending):
                return {"ok": True, "accepted": False, "errors": ["dependency_blocked"]}
            lines = sum(_line_count(row_json(r, "result_json", {})) for r in rows)
            if pending and lines >= MAX_COMPONENT_ANALYZED_LINES:
                for row in pending:
                    scope = row_json(row, "scope_json", {})
                    result = {"summary": "组件总工作量保护截断", "checked": [], "termination": None,
                              "facts": [], "security_checks": [], "operation_groups": [], "component_calls": [],
                              "gaps": [{"target": f"{scope['symbol']['file_path']}:{scope['start']}-{scope['end']}",
                                        "reason": "已达到组件分析行数预算，范围尚未分析", "evidence": []}]}
                    conn.execute("UPDATE exploration_work_items SET status='completed',result_json=? WHERE work_id=?",
                                 (canonical_json(result), row["work_id"]))
                pending = []
                rows = work_rows(conn, exp_id)
            exp = conn.execute("SELECT * FROM component_explorations WHERE exploration_id=?", (exp_id,)).fetchone()
            has_gap = any(row_json(r, "result_json", {}).get("gaps") for r in rows)
            status = "running" if pending else (
                "partial" if has_gap or exp["entry_status"] == "uncertain"
                or exp["external_entry_status"] == "uncertain" else "complete")
            if not pending and len(closed_work_ids(conn, exp_id)) != len(rows):
                return {"ok": True, "accepted": False, "errors": ["coverage_graph_not_closed"]}
            conn.execute("UPDATE component_explorations SET status=?,round_no=round_no+1,updated_at=? WHERE exploration_id=?",
                         (status, now(), exp_id))
            if pending:
                conn.execute("UPDATE tasks SET status='queued',attempts=0,error=NULL WHERE task_id=?", (task_id,))
                final_status = "queued"
            else:
                result = build_exploration_semantic_result(conn, task)
                summary = materialize_semantic_result(conn, task, result)
                result_ref = paths["tasks"] / f"{task_id}.result.json"
                write_json(result_ref, result)
                conn.execute("UPDATE tasks SET status='completed',result_ref=?,updated_at=? WHERE task_id=?",
                             (str(result_ref), now(), task_id))
                final_status = "completed"
            append_event(conn, "exploration_round_finished", task_id,
                         {"status": final_status, "pending_work": len(pending), "coverage": status})
    except Exception:
        if result_ref:
            Path(result_ref).unlink(missing_ok=True)
        raise
    from .reporting import refresh_live_report
    return {"ok": True, "accepted": True, "task_id": task_id, "task_status": final_status,
            "exploration_status": status, "result_ref": str(result_ref) if result_ref else None,
            "live_report": refresh_live_report(run_dir), "continuation": bool(pending), **summary}
