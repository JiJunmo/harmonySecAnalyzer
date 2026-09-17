"""Compile canonical component semantics from accepted range results."""
from __future__ import annotations

import json

from .common import canonical_json, now, operation_group_identity, stable_id, normalize_location
from .contracts import normalize_semantic_result, schema_errors, validate_semantic_analysis
from .evidence import materialize_component_call, materialize_semantic_group
from .store import append_event, row_json


def _copy(value):
    return json.loads(json.dumps(value))


def _call_identity(call):
    return canonical_json([call.get("target_component_id"), normalize_location(call.get("call_location")),
                           call.get("invocation_control", {}), call.get("parameter_mappings", []),
                           call.get("principal_transition", {})])


def validate_semantic_result(conn, task, result):
    return schema_errors("component_semantic_analysis", result) or validate_semantic_analysis(result, task, conn)


def step_coverage_gaps(result):
    return {gap["target"] for gap in result.get("gaps", [])}


def validate_exploration_step_semantics(conn, task, scope, assessment, result):
    if scope["kind"] == "entry":
        return ["entry_discovery_cannot_emit_operations"] if result["operation_groups"] or result["component_calls"] else []
    exploration = conn.execute("SELECT * FROM component_explorations WHERE entry_id=?", (task["subject_id"],)).fetchone()
    assessment = assessment or {
        "entry_status": exploration["entry_status"],
        "external_entry_status": exploration["external_entry_status"],
        "confirmed_external_candidate_ids": row_json(exploration, "confirmed_candidates_json", []),
    }
    candidate = {
        "task_id": task["task_id"], "entry_id": task["subject_id"], "summary": result["summary"],
        "coverage": {
            **{k: assessment[k] for k in ("entry_status", "external_entry_status", "confirmed_external_candidate_ids")},
            "entry_notes": [result["summary"]],
            "entry_symbols_checked": [] if scope["kind"] == "entry" else [scope["symbol"]["qualified_name"]],
            "operation_sites_checked": [], "unresolved_targets": sorted(step_coverage_gaps(result)),
        },
        "operation_groups": _copy(result["operation_groups"]), "component_calls": _copy(result["component_calls"]),
    }
    return validate_semantic_result(conn, task, normalize_semantic_result(candidate, task["subject_id"]))


def build_exploration_semantic_result(conn, task):
    from .semantic_exploration import work_rows, closed_work_ids
    exploration = conn.execute("SELECT * FROM component_explorations WHERE entry_id=?", (task["subject_id"],)).fetchone()
    if not exploration or exploration["status"] not in {"complete", "partial"}:
        raise ValueError("component_exploration_not_closed")
    rows = work_rows(conn, exploration["exploration_id"])
    if any(r["status"] != "completed" for r in rows):
        raise ValueError("component_exploration_has_open_work")
    closed = closed_work_ids(conn, exploration["exploration_id"])
    groups, calls, notes, unresolved = [], [], [], set()
    functions = {}
    stopped = gaps = 0
    for row in rows:
        scope = row_json(row, "scope_json", {})
        result = row_json(row, "result_json", {})
        groups.extend(_copy(result.get("operation_groups", [])))
        calls.extend(_copy(result.get("component_calls", [])))
        unresolved.update(step_coverage_gaps(result))
        notes.extend(f"覆盖缺口：{g['target']}：{g['reason']}" for g in result.get("gaps", []))
        stopped += bool(result.get("termination"))
        gaps += bool(result.get("gaps"))
        if scope["kind"] != "entry":
            functions.setdefault(scope["symbol"]["qualified_name"], []).append(row)
    checked = sorted(name for name, work in functions.items()
                     if all(r["work_id"] in closed and not row_json(r, "result_json", {}).get("gaps") for r in work))
    roots = {r["work_id"] for r in rows if row_json(r, "scope_json", {})["kind"] == "entry"}
    entry_targets = {
        edge["target_work_id"] for edge in conn.execute(
            "SELECT * FROM exploration_edges WHERE exploration_id=?", (exploration["exploration_id"],))
        if edge["source_work_id"] in roots
    }
    # A confirmed callback identity is checked even when its body has a coverage gap.
    entry_symbols = {
        row_json(r, "scope_json", {})["symbol"]["qualified_name"]
        for r in rows if r["work_id"] in entry_targets
    }
    for group in groups:
        group["group_key"] = stable_id("OG", operation_group_identity(task["subject_id"], group))
    for call in calls:
        call["call_key"] = stable_id("CC", _call_identity(call))
    notes.append(f"已登记范围 {len(rows)} 个；覆盖仅表示已登记结构的处理进度，不证明源码分支穷尽")
    result = normalize_semantic_result({
        "task_id": task["task_id"], "entry_id": task["subject_id"],
        "summary": exploration["component_summary"] or "组件范围探索完成",
        "coverage": {
            "entry_status": exploration["entry_status"],
            "external_entry_status": exploration["external_entry_status"],
            "confirmed_external_candidate_ids": row_json(exploration, "confirmed_candidates_json", []),
            "entry_notes": sorted(set(notes)), "entry_symbols_checked": sorted(set(checked) | entry_symbols),
            "operation_sites_checked": [], "unresolved_targets": sorted(unresolved),
            "exploration_summary": {
                "status": exploration["status"], "rounds": exploration["round_no"],
                "total_nodes": len(rows), "completed_nodes": len(rows),
                "stopped_nodes": stopped, "gap_nodes": gaps,
                "max_depth": max((r["depth"] for r in rows), default=0),
            },
        }, "operation_groups": groups, "component_calls": calls,
    }, task["subject_id"])
    errors = validate_semantic_result(conn, task, result)
    if errors:
        raise ValueError("invalid_compiled_semantic_result:" + "|".join(errors))
    return result


def materialize_semantic_result(conn, task, result):
    """Persist a validated semantic result through the single canonical write path."""
    conn.execute(
        "INSERT INTO semantic_analyses VALUES (?,?,?,?,?)",
        (task["subject_id"], task["task_id"], result["summary"],
         canonical_json(result["coverage"]), now()),
    )
    entry = conn.execute(
        "SELECT payload_json FROM entries WHERE entry_id=?", (task["subject_id"],)
    ).fetchone()
    entry_payload = row_json(entry, "payload_json", {})
    call_ids = []
    for source in result["component_calls"]:
        component_call = materialize_component_call(conn, task["task_id"], source)
        identity = canonical_json([
            task["subject_id"], component_call["target_component_id"],
            normalize_location(component_call["call_location"]),
            component_call["invocation_control"], component_call["parameter_mappings"],
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
             canonical_json(component_call["parameter_mappings"]),
             canonical_json(component_call["security_checks"]),
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
             group.get("capability_id"), group["category"], group["title"],
             group["operation"]["body"], group["operation"]["location"],
             canonical_json(group["controlled_properties"]), canonical_json(group["context"]),
             canonical_json(group["security_checks"]), canonical_json(group["branches"]),
             canonical_json(group["evidence_refs"]), canonical_json(group), now()),
        )
        fact_ids = {}
        for fact in group["facts"]:
            fact_id = stable_id("FACT", [group_id, fact["fact_key"]])
            fact_ids[fact["fact_key"]] = fact_id
            conn.execute("INSERT INTO group_facts VALUES (?,?,?,?,?,?,?,?,?)", (
                fact_id, fact["fact_key"], group_id, fact["type"], fact["body"],
                fact.get("location"), canonical_json(fact["evidence_refs"]),
                canonical_json(fact), now(),
            ))
        for edge in group["edges"]:
            edge_id = stable_id("EDGE", [group_id, edge["from"], edge["to"], edge["kind"]])
            conn.execute("INSERT INTO group_edges VALUES (?,?,?,?,?,?,?)", (
                edge_id, group_id, fact_ids[edge["from"]], fact_ids[edge["to"]], edge["kind"],
                canonical_json(edge["evidence_refs"]), now(),
            ))
        group_ids.append(group_id)
    summary = {
        "entry_id": task["subject_id"], "operation_groups_created": len(group_ids),
        "group_ids": group_ids, "component_calls_created": len(call_ids), "call_ids": call_ids,
    }
    append_event(conn, "semantic_result_materialized", task["subject_id"], summary)
    return summary
