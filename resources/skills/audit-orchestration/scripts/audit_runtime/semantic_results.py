"""Compile, validate, and persist the canonical component semantic result."""
from __future__ import annotations

import json

from .common import (canonical_json, normalize_location, now, operation_group_identity,
                     stable_id)
from .contracts import (normalize_semantic_result, schema_errors,
                        validate_semantic_analysis)
from .evidence import materialize_component_call, materialize_semantic_group
from .store import append_event, row_json


def _copy(value):
    return json.loads(json.dumps(value))


def _call_identity(component_call):
    return canonical_json([
        component_call.get("target_component_id"),
        normalize_location(component_call.get("call_location")),
        component_call.get("invocation_control", {}),
        component_call.get("parameter_mappings", []),
        component_call.get("principal_transition", {}),
    ])


def validate_semantic_result(conn, task, result):
    errors = schema_errors("component_semantic_analysis", result)
    if not errors:
        errors.extend(validate_semantic_analysis(result, task, conn))
    return errors


def step_coverage_gaps(step):
    """Tool observations are not conclusions; only accepted step gaps are exported."""
    return {gap["target"] for gap in step.get("gaps", [])}


def validate_exploration_step_semantics(conn, task, node, exploration, step):
    """Apply the final semantic contract to one step's groups and component calls."""
    assessment = step.get("entry_assessment") or {
        "entry_status": exploration["entry_status"],
        "external_entry_status": exploration["external_entry_status"],
        "confirmed_external_candidate_ids": row_json(
            exploration, "confirmed_candidates_json", []
        ),
    }
    symbols = []
    if node["work_type"] == "entry_discovery":
        symbols = [
            row.get("symbol", {}).get("qualified_name")
            for row in step.get("successors", [])
            if row.get("symbol", {}).get("qualified_name")
        ]
    else:
        symbol = row_json(node, "symbol_json", {}).get("qualified_name")
        if symbol:
            symbols.append(symbol)
    symbols.extend(
        symbol.get("qualified_name")
        for symbol in step.get("analyzed_symbols", [])
        if isinstance(symbol, dict) and symbol.get("qualified_name")
    )
    unresolved = step_coverage_gaps(step)
    result = {
        "task_id": task["task_id"],
        "entry_id": task["subject_id"],
        "summary": step["summary"],
        "coverage": {
            "entry_status": assessment["entry_status"],
            "external_entry_status": assessment["external_entry_status"],
            "confirmed_external_candidate_ids": list(
                assessment["confirmed_external_candidate_ids"]
            ),
            "entry_notes": [step["summary"]],
            "entry_symbols_checked": sorted(set(symbols)),
            "operation_sites_checked": [],
            "unresolved_targets": sorted(unresolved),
        },
        "operation_groups": _copy(step.get("operation_groups", [])),
        "component_calls": _copy(step.get("component_calls", [])),
    }
    result = normalize_semantic_result(result, task["subject_id"])
    return validate_semantic_result(conn, task, result)


def build_exploration_semantic_result(conn, task):
    """Build one downstream semantic result after every exploration branch closes."""
    if task["kind"] != "component_semantic_analysis":
        raise ValueError("task_not_component_semantic_analysis")
    exploration = conn.execute(
        "SELECT * FROM component_explorations WHERE entry_id=?", (task["subject_id"],)
    ).fetchone()
    if not exploration:
        raise ValueError("component_exploration_not_found")
    if exploration["status"] not in {"complete", "partial"}:
        raise ValueError(f"component_exploration_not_closed:{exploration['status']}")
    open_nodes = conn.execute(
        """SELECT COUNT(*) n FROM exploration_nodes WHERE exploration_id=?
           AND status IN ('queued','leased')""",
        (exploration["exploration_id"],),
    ).fetchone()["n"]
    if open_nodes:
        raise ValueError(f"component_exploration_has_open_nodes:{open_nodes}")

    nodes = conn.execute(
        """SELECT * FROM exploration_nodes WHERE exploration_id=?
           ORDER BY depth,discovered_order,node_id""",
        (exploration["exploration_id"],),
    ).fetchall()
    observations = []
    operation_groups = []
    component_calls = []
    unresolved = set()
    checked_symbols = set()
    entry_symbols = set()
    root_notes = []
    gap_notes = set()
    for node in nodes:
        observation = row_json(node, "observation_json", {})
        if observation.get("node_id") != node["node_id"]:
            if node["status"] == "gap":
                symbol = row_json(node, "symbol_json", {}).get("qualified_name")
                if symbol:
                    unresolved.add(symbol)
                    gap_notes.add(f"覆盖缺口：{symbol}：组件探索达到总量保护上限，尚未分析")
            continue
        observations.append(observation)
        if node["work_type"] == "entry_discovery":
            root_notes.append(observation.get("summary"))
            entry_symbols.update(row["symbol"]["qualified_name"] for row in observation["successors"])
        elif not observation.get("resume"):
            symbol = row_json(node, "symbol_json", {}).get("qualified_name")
            if symbol:
                checked_symbols.add(symbol)
        checked_symbols.update(
            symbol.get("qualified_name")
            for symbol in observation.get("analyzed_symbols", [])
            if isinstance(symbol, dict) and symbol.get("qualified_name")
        )
        operation_groups.extend(_copy(observation.get("operation_groups", [])))
        component_calls.extend(_copy(observation.get("component_calls", [])))
        unresolved.update(step_coverage_gaps(observation))
        gap_notes.update(f"覆盖缺口：{gap['target']}：{gap['reason']}" for gap in observation.get("gaps", []))

    for group in operation_groups:
        if isinstance(group, dict) and isinstance(group.get("operation"), dict):
            group["group_key"] = stable_id(
                "OG", operation_group_identity(task["subject_id"], group)
            )
    for component_call in component_calls:
        if isinstance(component_call, dict):
            component_call["call_key"] = stable_id("CC", _call_identity(component_call))

    counts = {status: 0 for status in ("queued", "leased", "completed", "stopped", "gap")}
    for node in nodes:
        counts[node["status"]] = counts.get(node["status"], 0) + 1
    max_depth = max((node["depth"] for node in nodes), default=0)
    notes = [note for note in root_notes if note]
    notes.append(
        f"渐进探索已处理 {len(observations)} 个安全语义断点，"
        f"覆盖 {len(checked_symbols)} 个函数，停止 {counts['stopped']} 个，"
        f"覆盖缺口 {len(unresolved)} 个"
    )
    notes.extend(sorted(gap_notes))
    result = {
        "task_id": task["task_id"],
        "entry_id": task["subject_id"],
        "summary": exploration["component_summary"] or "组件语义探索完成",
        "coverage": {
            "entry_status": exploration["entry_status"],
            "external_entry_status": exploration["external_entry_status"],
            "confirmed_external_candidate_ids": row_json(
                exploration, "confirmed_candidates_json", []
            ),
            "entry_notes": sorted(set(notes)),
            "entry_symbols_checked": sorted(entry_symbols | checked_symbols),
            "operation_sites_checked": [],
            "unresolved_targets": sorted(unresolved),
            "exploration_summary": {
                "status": exploration["status"],
                "rounds": exploration["round_no"],
                "total_nodes": len(nodes),
                "completed_nodes": counts["completed"],
                "stopped_nodes": counts["stopped"],
                "gap_nodes": counts["gap"],
                "max_depth": max_depth,
            },
        },
        "operation_groups": operation_groups,
        "component_calls": component_calls,
    }
    result = normalize_semantic_result(result, task["subject_id"])
    result["operation_groups"] = sorted(
        result["operation_groups"],
        key=lambda group: operation_group_identity(task["subject_id"], group),
    )
    result["component_calls"] = sorted(
        result["component_calls"], key=_call_identity
    )
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
