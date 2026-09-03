"""Transactional state machine for progressive component exploration."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from .common import SCHEMAS_DIR, canonical_json, normalize_text, now, read_json, run_paths, stable_id, write_json
from .semantic_results import remaining_unresolved, validate_exploration_step_semantics
from .store import append_event, database, row_json, transaction


ROUND_FUNCTION_BUDGET = 64
STEP_SYMBOL_BUDGET = 8
MAX_COMPONENT_WORK_NODES = 64
MAX_COMPONENT_ROUNDS = 8
STEP_SCHEMA = "component-exploration-step.schema.json"


@lru_cache(maxsize=None)
def _validator(schema_name):
    schema = read_json(SCHEMAS_DIR / schema_name)
    if not isinstance(schema, dict):
        raise ValueError(f"missing_schema:{schema_name}")
    return Draft202012Validator(schema)


def _schema_errors(schema_name, document):
    errors = []
    for error in _validator(schema_name).iter_errors(document):
        path = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in error.absolute_path
        )
        errors.append(f"schema:{path}:{error.message}")
    return sorted(errors)


def _normalize_symbol(symbol):
    return {
        "qualified_name": str(symbol.get("qualified_name") or "").strip(),
        "file_path": str(symbol["file_path"]).replace("\\", "/") if symbol.get("file_path") else None,
        "line": symbol.get("line"),
        "kind": str(symbol.get("kind") or "function").strip().lower(),
    }


def _symbol_key(symbol):
    normalized = _normalize_symbol(symbol)
    return canonical_json([
        normalize_text(normalized["qualified_name"]),
        normalize_text(normalized["file_path"]),
        normalized["line"],
        normalized["kind"],
    ])


def _normalize_state(state):
    properties = {}
    for item in state.get("controlled_properties", []):
        name = normalize_text(item.get("name"))
        if name:
            properties[name] = item.get("control_state")
    principal = state.get("principal", {})
    return {
        "controlled_properties": [
            {"name": name, "control_state": properties[name]}
            for name in sorted(properties)
        ],
        "principal": {
            "origin": normalize_text(principal.get("origin")),
            "immediate": normalize_text(principal.get("immediate")),
            "origin_binding": principal.get("origin_binding"),
            "authority": principal.get("authority"),
        },
        "security_check_ids": sorted({
            normalize_text(value) for value in state.get("security_check_ids", [])
            if normalize_text(value)
        }),
    }


def _task(conn, task_id, attempt):
    task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    if not task:
        raise ValueError("task_not_found")
    if task["kind"] != "component_semantic_analysis":
        raise ValueError("task_not_component_semantic_analysis")
    if task["status"] != "running":
        raise ValueError(f"task_not_running:{task['status']}")
    if int(attempt) != task["attempts"]:
        raise ValueError(f"stale_attempt:expected={task['attempts']}:actual={attempt}")
    if not task["subject_id"]:
        raise ValueError("task_entry_missing")
    return task


def release_exploration_leases(conn, task_id, attempt):
    """Return only the unfinished nodes owned by one failed task attempt."""
    released = conn.execute(
        """UPDATE exploration_nodes SET status='queued',lease_task_id=NULL,lease_attempt=NULL,
           updated_at=? WHERE status='leased' AND lease_task_id=? AND lease_attempt=?""",
        (now(), task_id, int(attempt)),
    ).rowcount
    if released:
        append_event(conn, "exploration_leases_released", task_id, {
            "attempt": int(attempt), "nodes": released,
        })
    return released


def ensure_component_exploration(conn, entry_id):
    """Create the component state and its entry-discovery root once."""
    if not conn.execute("SELECT 1 FROM entries WHERE entry_id=?", (entry_id,)).fetchone():
        raise ValueError(f"entry_not_found:{entry_id}")
    exploration_id = stable_id("EXPLORE", entry_id)
    stamp = now()
    created = conn.execute(
        """INSERT OR IGNORE INTO component_explorations
           (exploration_id,entry_id,status,entry_status,external_entry_status,
            confirmed_candidates_json,round_no,created_at,updated_at)
           VALUES (?,?,'pending','uncertain','uncertain','[]',0,?,?)""",
        (exploration_id, entry_id, stamp, stamp),
    ).rowcount
    root_symbol = {
        "qualified_name": "$entry_discovery", "file_path": None, "line": None, "kind": "entry",
    }
    root_state = {
        "controlled_properties": [],
        "principal": {
            "origin": "unknown", "immediate": "unknown",
            "origin_binding": "unknown", "authority": "unknown",
        },
        "security_check_ids": [],
    }
    node_id = stable_id("XNODE", [exploration_id, _symbol_key(root_symbol), canonical_json(root_state)])
    conn.execute(
        """INSERT OR IGNORE INTO exploration_nodes
           (node_id,exploration_id,parent_node_id,work_type,symbol_key,state_key,symbol_json,
            state_json,depth,discovered_order,status,created_at,updated_at)
           VALUES (?,?,NULL,'entry_discovery',?,?,?,?,0,0,'queued',?,?)""",
        (node_id, exploration_id, _symbol_key(root_symbol), canonical_json(root_state),
         canonical_json(root_symbol), canonical_json(root_state), stamp, stamp),
    )
    if created:
        append_event(conn, "component_exploration_created", exploration_id, {"entry_id": entry_id})
    return exploration_id


def _path_context(conn, node):
    path = []
    current = node
    seen = set()
    while current and current["node_id"] not in seen:
        seen.add(current["node_id"])
        observation = row_json(current, "observation_json", {})
        relevant = (
            current["work_type"] == "entry_discovery"
            or any(observation.get(key) for key in (
                "facts", "security_checks", "operation_groups", "component_calls", "gaps"
            ))
        )
        if relevant:
            path.append({
                "node_id": current["node_id"],
                "symbol": row_json(current, "symbol_json", {}),
                "summary": observation.get("summary"),
                "status": current["status"],
            })
        parent_id = current["parent_node_id"]
        current = conn.execute(
            "SELECT * FROM exploration_nodes WHERE node_id=?", (parent_id,)
        ).fetchone() if parent_id else None
    return list(reversed(path))


def _attempt_progress(conn, exploration_id, task_id, attempt):
    rows = conn.execute(
        """SELECT * FROM exploration_nodes
           WHERE exploration_id=? AND lease_task_id=? AND lease_attempt=?
           AND status IN ('completed','stopped','gap')""",
        (exploration_id, task_id, int(attempt)),
    ).fetchall()
    function_count = sum(
        1 + len(row_json(row, "observation_json", {}).get("analyzed_symbols", []))
        for row in rows if row["work_type"] == "function_analysis"
    )
    last_node = max(
        rows, key=lambda row: (row["updated_at"], row["discovered_order"]),
        default=None,
    )
    return len(rows), function_count, last_node


def _queued_continuation(conn, exploration_id, source_node_id):
    return conn.execute(
        """SELECT n.* FROM exploration_edges e
           JOIN exploration_nodes n ON n.node_id=e.target_node_id
           WHERE e.exploration_id=? AND e.source_node_id=? AND e.decision='follow'
           AND n.status='queued'
           ORDER BY n.depth DESC,n.discovered_order DESC,n.node_id LIMIT 1""",
        (exploration_id, source_node_id),
    ).fetchone()


def next_exploration_node(run_dir, task_id, attempt, budget=ROUND_FUNCTION_BUDGET):
    budget = int(budget)
    if budget <= 0:
        raise ValueError("round_function_budget_must_be_positive")
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = _task(conn, task_id, attempt)
        exploration_id = ensure_component_exploration(conn, task["subject_id"])
        conn.execute(
            """UPDATE exploration_nodes SET status='queued',lease_task_id=NULL,lease_attempt=NULL,
               updated_at=? WHERE exploration_id=? AND status='leased' AND lease_task_id=?
               AND lease_attempt<>?""",
            (now(), exploration_id, task_id, int(attempt)),
        )
        processed, processed_functions, last_node = _attempt_progress(
            conn, exploration_id, task_id, attempt,
        )
        starting_new_path = False
        node = conn.execute(
            """SELECT * FROM exploration_nodes WHERE exploration_id=? AND status='leased'
               AND lease_task_id=? AND lease_attempt=? ORDER BY depth DESC,discovered_order DESC LIMIT 1""",
            (exploration_id, task_id, int(attempt)),
        ).fetchone()
        if not node:
            continuation = _queued_continuation(
                conn, exploration_id, last_node["node_id"],
            ) if last_node else None
            if processed_functions >= budget:
                return {
                    "ok": True, "exploration_id": exploration_id, "work": None,
                    "round_complete": True,
                    "reason": (
                        "function_budget_reached_mid_path"
                        if continuation else "function_budget_reached_at_path_boundary"
                    ),
                    "continuation_saved": bool(continuation),
                    "processed_nodes": processed,
                    "processed_functions": processed_functions,
                    "round_function_budget": budget,
                }
            node = continuation
            starting_new_path = False
            if not node:
                node = conn.execute(
                    """SELECT * FROM exploration_nodes WHERE exploration_id=? AND status='queued'
                       ORDER BY depth DESC,discovered_order DESC,node_id LIMIT 1""",
                    (exploration_id,),
                ).fetchone()
                starting_new_path = bool(last_node and node)
            if node:
                conn.execute(
                    """UPDATE exploration_nodes SET status='leased',lease_task_id=?,lease_attempt=?,updated_at=?
                       WHERE node_id=?""",
                    (task_id, int(attempt), now(), node["node_id"]),
                )
                node = conn.execute(
                    "SELECT * FROM exploration_nodes WHERE node_id=?", (node["node_id"],)
                ).fetchone()
                conn.execute(
                    "UPDATE component_explorations SET status='running',updated_at=? WHERE exploration_id=?",
                    (now(), exploration_id),
                )
                append_event(conn, "exploration_node_leased", node["node_id"], {
                    "task_id": task_id, "attempt": int(attempt),
                })
        if not node:
            return {
                "ok": True, "exploration_id": exploration_id, "work": None,
                "round_complete": True, "reason": "no_open_nodes",
                "processed_nodes": processed,
                "processed_functions": processed_functions,
                "round_function_budget": budget,
            }
        return {
            "ok": True, "exploration_id": exploration_id,
            "work": {
                "node_id": node["node_id"], "work_type": node["work_type"],
                "symbol": row_json(node, "symbol_json", {}),
                "security_state": row_json(node, "state_json", {}),
                "path_context": _path_context(conn, node),
            },
            "round_complete": False, "processed_nodes": processed,
            "processed_functions": processed_functions,
            "round_function_budget": budget,
            "starting_new_path": starting_new_path,
            "step_schema_file": str(SCHEMAS_DIR / STEP_SCHEMA),
        }


def _business_errors(step, node):
    errors = []
    if step.get("node_id") != node["node_id"]:
        errors.append("node_id_mismatch")
    if step.get("work_type") != node["work_type"]:
        errors.append("work_type_mismatch")
    assessment = step.get("entry_assessment", {})
    if node["work_type"] == "entry_discovery":
        if step.get("analyzed_symbols"):
            errors.append("entry_discovery_cannot_inline_function_analysis")
        if assessment.get("entry_status") == "excluded":
            if assessment.get("external_entry_status") != "excluded":
                errors.append("excluded_entry_requires_excluded_external_entry")
            if step.get("successors"):
                errors.append("excluded_entry_cannot_have_successors")
        if assessment.get("external_entry_status") == "confirmed":
            if assessment.get("entry_status") != "confirmed":
                errors.append("confirmed_external_entry_requires_confirmed_entry")
            if not assessment.get("confirmed_external_candidate_ids"):
                errors.append("confirmed_external_entry_requires_candidate")
        elif assessment.get("confirmed_external_candidate_ids"):
            errors.append("unconfirmed_external_entry_cannot_list_candidates")
    observed = {
        symbol for query in step.get("atlas_queries", [])
        for symbol in query.get("target_symbols", [])
    }
    atlas_unresolved = {
        symbol for query in step.get("atlas_queries", [])
        for symbol in query.get("unresolved_targets", [])
    }
    analyzed = {
        symbol.get("qualified_name") for symbol in step.get("analyzed_symbols", [])
        if symbol.get("qualified_name")
    }
    decided = {
        successor.get("symbol", {}).get("qualified_name")
        for successor in step.get("successors", [])
    }
    if analyzed & decided:
        errors.append("symbol_cannot_be_analyzed_and_successor:" + ",".join(sorted(analyzed & decided)))
    covered = analyzed | decided
    relations = step.get("resolved_relations", [])
    resolved = {relation.get("target_symbol") for relation in relations}
    if observed - covered:
        errors.append("atlas_targets_without_decision:" + ",".join(sorted(observed - covered)))
    if covered - resolved:
        errors.append("targets_without_resolution:" + ",".join(sorted(covered - resolved)))
    if resolved - covered:
        errors.append("resolutions_without_target:" + ",".join(sorted(resolved - covered)))
    relation_pairs = [
        (relation.get("target_symbol"), relation.get("relation"))
        for relation in relations
    ]
    duplicate_pairs = sorted({
        f"{target}:{relation}" for target, relation in relation_pairs
        if relation_pairs.count((target, relation)) > 1
    })
    if duplicate_pairs:
        errors.append("duplicate_target_resolution:" + ",".join(duplicate_pairs))
    for index, relation in enumerate(relations):
        target = relation.get("target_symbol")
        if relation.get("resolved_by") == "atlas_index" and target not in observed:
            errors.append(f"resolved_relations[{index}]:atlas_target_not_observed:{target}")
        if relation.get("resolved_by") == "source_evidence":
            unresolved_ref = relation.get("unresolved_ref")
            if unresolved_ref and unresolved_ref not in atlas_unresolved:
                errors.append(
                    f"resolved_relations[{index}]:unresolved_ref_not_reported:{unresolved_ref}"
                )
            locations = {
                evidence.get("location") for evidence in relation.get("evidence", [])
                if evidence.get("location")
            }
            if len(locations) < 2:
                errors.append(
                    f"resolved_relations[{index}]:source_resolution_requires_two_locations"
                )
    if len(analyzed) > STEP_SYMBOL_BUDGET:
        errors.append(f"step_symbol_budget_exceeded:{len(analyzed)}>{STEP_SYMBOL_BUDGET}")
    for index, successor in enumerate(step.get("successors", [])):
        pair = (
            successor.get("symbol", {}).get("qualified_name"),
            successor.get("relation"),
        )
        if pair not in relation_pairs:
            errors.append(f"successors[{index}]:relation_resolution_missing")
        if successor.get("relation") == "component_boundary" and not (
            successor.get("decision") == "stop" and successor.get("stop_reason") == "component_boundary"
        ):
            errors.append(f"successors[{index}]:component_boundary_must_stop")
    if step.get("status") == "gap" and not step.get("gaps"):
        errors.append("gap_status_requires_gap")
    return errors


def _apply_component_work_budget(conn, exploration_id, step):
    """Turn overflow frontier work into explicit gaps instead of unbounded continuation."""
    used = conn.execute(
        """SELECT COUNT(*) n FROM exploration_nodes WHERE exploration_id=?
           AND status IN ('queued','leased','completed')""",
        (exploration_id,),
    ).fetchone()["n"]
    remaining = max(0, MAX_COMPONENT_WORK_NODES - used)
    truncated = []
    normalized = []
    for successor in step["successors"]:
        successor = dict(successor)
        if successor["decision"] != "follow":
            normalized.append(successor)
            continue
        symbol = _normalize_symbol(successor["symbol"])
        state = _normalize_state(successor["state"])
        node_id = stable_id("XNODE", [
            exploration_id, _symbol_key(symbol), canonical_json(state),
        ])
        exists = conn.execute(
            "SELECT 1 FROM exploration_nodes WHERE node_id=?", (node_id,),
        ).fetchone()
        if exists or remaining > 0:
            normalized.append(successor)
            if not exists:
                remaining -= 1
            continue
        successor["decision"] = "stop"
        successor["stop_reason"] = "resource_limit"
        normalized.append(successor)
        truncated.append(symbol["qualified_name"])
    if truncated:
        step = dict(step)
        step["successors"] = normalized
        step["gaps"] = sorted(set(step.get("gaps", [])) | set(truncated))
    return step, truncated


def _insert_successor(conn, exploration_id, source, successor):
    symbol = _normalize_symbol(successor["symbol"])
    state = _normalize_state(successor["state"])
    symbol_key = _symbol_key(symbol)
    state_key = canonical_json(state)
    node_id = stable_id("XNODE", [exploration_id, symbol_key, state_key])
    existing = conn.execute(
        "SELECT * FROM exploration_nodes WHERE node_id=?", (node_id,)
    ).fetchone()
    decision = successor["decision"]
    stamp = now()
    if not existing:
        order = conn.execute(
            "SELECT COALESCE(MAX(discovered_order),-1)+1 n FROM exploration_nodes WHERE exploration_id=?",
            (exploration_id,),
        ).fetchone()["n"]
        status = "queued" if decision == "follow" else (
            "gap" if successor.get("stop_reason") in {"unresolved", "resource_limit"} else "stopped"
        )
        conn.execute(
            """INSERT INTO exploration_nodes
               (node_id,exploration_id,parent_node_id,work_type,symbol_key,state_key,symbol_json,
                state_json,depth,discovered_order,status,stop_reason,observation_json,created_at,updated_at)
               VALUES (?,?,?,'function_analysis',?,?,?,?,?,?,?,?,?,?,?)""",
            (node_id, exploration_id, source["node_id"], symbol_key, state_key,
             canonical_json(symbol), canonical_json(state), source["depth"] + 1, order, status,
             successor.get("stop_reason"), canonical_json({"terminal_successor": successor}), stamp, stamp),
        )
        created = True
    else:
        created = False
        if decision == "follow" and existing["status"] in {"stopped", "gap"}:
            conn.execute(
                "UPDATE exploration_nodes SET status='queued',stop_reason=NULL,updated_at=? WHERE node_id=?",
                (stamp, node_id),
            )
    identity = canonical_json([
        exploration_id, source["node_id"], node_id, successor["relation"],
        normalize_text(successor["condition"]), decision,
    ])
    edge_id = stable_id("XEDGE", identity)
    conn.execute(
        """INSERT OR IGNORE INTO exploration_edges
           (edge_id,identity_key,exploration_id,source_node_id,target_node_id,relation,decision,
            condition,payload_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (edge_id, identity, exploration_id, source["node_id"], node_id,
         successor["relation"], decision, successor["condition"], canonical_json(successor), stamp),
    )
    return node_id, created


def record_exploration_step(run_dir, task_id, attempt, input_path):
    step = read_json(input_path)
    if not isinstance(step, dict):
        return {"ok": True, "accepted": False, "errors": ["invalid_step_json"]}
    errors = _schema_errors(STEP_SCHEMA, step)
    if errors:
        return {"ok": True, "accepted": False, "errors": errors}
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = _task(conn, task_id, attempt)
        exploration_id = ensure_component_exploration(conn, task["subject_id"])
        exploration = conn.execute(
            "SELECT * FROM component_explorations WHERE exploration_id=?", (exploration_id,)
        ).fetchone()
        node = conn.execute(
            "SELECT * FROM exploration_nodes WHERE node_id=? AND exploration_id=?",
            (step["node_id"], exploration_id),
        ).fetchone()
        if not node:
            raise ValueError("exploration_node_not_found")
        if node["status"] in {"completed", "stopped", "gap"}:
            if row_json(node, "observation_json", {}) == step:
                return {
                    "ok": True, "accepted": True, "idempotent": True,
                    "node_id": node["node_id"], "status": node["status"],
                }
            raise ValueError("exploration_node_already_recorded")
        if not (
            node["status"] == "leased" and node["lease_task_id"] == task_id
            and node["lease_attempt"] == int(attempt)
        ):
            raise ValueError("exploration_node_not_leased_by_task")
        errors = _business_errors(step, node)
        if not errors:
            errors.extend(validate_exploration_step_semantics(
                conn, task, node, exploration, step,
            ))
        if errors:
            return {"ok": True, "accepted": False, "errors": errors}
        effective_step, truncated = _apply_component_work_budget(
            conn, exploration_id, step,
        )
        assessment = step.get("entry_assessment")
        if assessment:
            conn.execute(
                """UPDATE component_explorations SET entry_status=?,external_entry_status=?,
                   confirmed_candidates_json=?,component_summary=?,status='running',updated_at=?
                   WHERE exploration_id=?""",
                (assessment["entry_status"], assessment["external_entry_status"],
                 canonical_json(assessment["confirmed_external_candidate_ids"]),
                 assessment["component_summary"], now(), exploration_id),
            )
        created = 0
        successor_ids = []
        for successor in effective_step["successors"]:
            successor_id, was_created = _insert_successor(conn, exploration_id, node, successor)
            successor_ids.append(successor_id)
            created += int(was_created)
        conn.execute(
            """UPDATE exploration_nodes SET status=?,stop_reason=?,observation_json=?,updated_at=?
               WHERE node_id=?""",
            (step["status"], step.get("stop_reason"), canonical_json(step), now(), node["node_id"]),
        )
        append_event(conn, "exploration_node_recorded", node["node_id"], {
            "task_id": task_id, "attempt": int(attempt), "status": step["status"],
            "successors": len(successor_ids), "created_successors": created,
        })
        return {
            "ok": True, "accepted": True, "idempotent": False,
            "node_id": node["node_id"], "status": step["status"],
            "successor_ids": successor_ids, "created_successors": created,
            "budget_truncated": truncated,
        }


def finish_exploration_round(run_dir, task_id, attempt):
    """Atomically continue the exploration or commit its final semantic result."""
    from .semantic_results import build_exploration_semantic_result, materialize_semantic_result

    paths = run_paths(run_dir)
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
                    "continuation": False, "idempotent": True,
                }
            task = _task(conn, task_id, attempt)
            exploration_id = ensure_component_exploration(conn, task["subject_id"])
            leased = conn.execute(
                """SELECT COUNT(*) n FROM exploration_nodes WHERE exploration_id=? AND status='leased'
                   AND lease_task_id=? AND lease_attempt=?""",
                (exploration_id, task_id, int(attempt)),
            ).fetchone()["n"]
            if leased:
                return {
                    "ok": True, "accepted": False, "task_id": task_id,
                    "status": "running", "errors": [f"leased_nodes_must_be_recorded:{leased}"],
                }
            processed_nodes = conn.execute(
                """SELECT COUNT(*) n FROM exploration_nodes WHERE exploration_id=?
                   AND lease_task_id=? AND lease_attempt=?
                   AND status IN ('completed','stopped','gap')""",
                (exploration_id, task_id, int(attempt)),
            ).fetchone()["n"]
            open_nodes = conn.execute(
                """SELECT COUNT(*) n FROM exploration_nodes WHERE exploration_id=?
                   AND status IN ('queued','leased')""", (exploration_id,),
            ).fetchone()["n"]
            gap_rows = conn.execute(
                """SELECT status,stop_reason,observation_json FROM exploration_nodes
                   WHERE exploration_id=?""", (exploration_id,),
            ).fetchall()
            has_gaps = any(
                row["status"] == "gap"
                or row["stop_reason"] in {"unresolved", "resource_limit"}
                or bool(remaining_unresolved(row_json(row, "observation_json", {})))
                for row in gap_rows
            )
            exploration = conn.execute(
                "SELECT * FROM component_explorations WHERE exploration_id=?", (exploration_id,)
            ).fetchone()
            next_round_no = exploration["round_no"] + 1
            if open_nodes and next_round_no >= MAX_COMPONENT_ROUNDS:
                limited = conn.execute(
                    """SELECT node_id,symbol_json FROM exploration_nodes
                       WHERE exploration_id=? AND status='queued'""", (exploration_id,),
                ).fetchall()
                for row in limited:
                    symbol = row_json(row, "symbol_json", {}).get("qualified_name")
                    observation = {
                        "node_id": row["node_id"], "work_type": "function_analysis",
                        "status": "gap", "summary": "组件探索达到轮次保护上限",
                        "stop_reason": "resource_limit", "atlas_queries": [],
                        "resolved_relations": [],
                        "analyzed_symbols": [], "facts": [], "security_checks": [],
                        "operation_groups": [], "component_calls": [], "successors": [],
                        "gaps": [symbol] if symbol else ["round_limit"],
                    }
                    conn.execute(
                        """UPDATE exploration_nodes SET status='gap',stop_reason='resource_limit',
                           observation_json=?,updated_at=? WHERE node_id=?""",
                        (canonical_json(observation), now(), row["node_id"]),
                    )
                open_nodes = 0
                has_gaps = True
            if open_nodes:
                exploration_status = "running"
            elif (has_gaps or exploration["entry_status"] == "uncertain"
                  or exploration["external_entry_status"] == "uncertain"):
                exploration_status = "partial"
            else:
                exploration_status = "complete"
            round_no = next_round_no
            conn.execute(
                """UPDATE component_explorations SET status=?,round_no=?,updated_at=?
                   WHERE exploration_id=?""",
                (exploration_status, round_no, now(), exploration_id),
            )
            if open_nodes:
                # A successful round gets a fresh retry budget. Detach its terminal
                # nodes so they are not counted against the next round's work budget.
                conn.execute(
                    """UPDATE exploration_nodes SET lease_task_id=NULL,lease_attempt=NULL,updated_at=?
                       WHERE exploration_id=? AND lease_task_id=? AND lease_attempt=?
                       AND status IN ('completed','stopped','gap')""",
                    (now(), exploration_id, task_id, int(attempt)),
                )
                conn.execute(
                    """UPDATE tasks SET status='queued',attempts=0,error=NULL,result_ref=NULL,updated_at=?
                       WHERE task_id=?""", (now(), task_id),
                )
                summary = {
                    "entry_id": task["subject_id"], "exploration_status": exploration_status,
                    "round_no": round_no, "open_nodes": open_nodes,
                    "processed_nodes": processed_nodes, "continuation": True,
                }
                append_event(conn, "exploration_round_continued", task_id, summary)
                final_status = "queued"
            else:
                result = build_exploration_semantic_result(conn, task)
                summary = materialize_semantic_result(conn, task, result)
                summary.update({
                    "exploration_status": exploration_status,
                    "round_no": round_no, "open_nodes": 0,
                    "processed_nodes": processed_nodes, "continuation": False,
                })
                result_ref = paths["tasks"] / f"{task_id}.result.json"
                write_json(result_ref, result)
                conn.execute(
                    """UPDATE tasks SET status='completed',result_ref=?,error=NULL,updated_at=?
                       WHERE task_id=?""", (str(result_ref), now(), task_id),
                )
                append_event(conn, "task_completed", task_id, summary)
                final_status = "completed"
    except Exception:
        if result_ref:
            Path(result_ref).unlink(missing_ok=True)
        raise
    from .reporting import refresh_live_report
    return {
        "ok": True, "accepted": True, "task_id": task_id,
        "status": final_status, "result_ref": str(result_ref) if result_ref else None,
        "live_report": refresh_live_report(run_dir), "idempotent": False, **summary,
    }
