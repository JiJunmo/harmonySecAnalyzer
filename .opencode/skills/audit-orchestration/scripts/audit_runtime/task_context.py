"""Build immutable worker task documents from canonical state."""
from __future__ import annotations

import json

from .common import handler_identity, load_capabilities, load_pattern_cards
from .store import row_json


def flow_context(conn, flow_id):
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
    doc["edges"] = []
    for row in conn.execute("SELECT * FROM edges WHERE flow_id=? ORDER BY created_at,edge_id", (flow_id,)):
        edge = dict(row)
        edge["evidence_refs"] = json.loads(edge.pop("evidence_json"))
        doc["edges"].append(edge)
    doc["continuations"] = []
    for row in conn.execute("SELECT * FROM continuations WHERE flow_id=? ORDER BY created_at,continuation_id", (flow_id,)):
        continuation = dict(row)
        continuation["evidence_refs"] = json.loads(continuation.pop("evidence_json"))
        continuation["child_flow_ids"] = json.loads(continuation.pop("child_flow_ids_json"))
        doc["continuations"].append(continuation)
    return doc


def path_context(conn, path_id):
    row = conn.execute("SELECT * FROM paths WHERE path_id=?", (path_id,)).fetchone()
    if not row:
        return None
    path = dict(row)
    flow_ids = json.loads(path.pop("flow_ids_json"))
    path["flow_ids"] = flow_ids
    path["segments"] = [flow_context(conn, flow_id) for flow_id in flow_ids]
    path["segments"] = [segment for segment in path["segments"] if segment]
    path["facts"] = [fact for segment in path["segments"] for fact in segment["facts"]]
    path["edges"] = [edge for segment in path["segments"] for edge in segment["edges"]]
    path["continuations"] = [row for segment in path["segments"] for row in segment["continuations"]]
    terminal = path["segments"][-1] if path["segments"] else None
    path["branch_key"] = terminal.get("branch_key") if terminal else None
    path["controlled_property"] = terminal.get("controlled_property") if terminal else None
    path["current_symbol"] = terminal.get("current_symbol") if terminal else None
    return path


def task_context(conn, task):
    payload = row_json(task, "input_json", {})
    if task["kind"] == "entry_path_discovery":
        return payload
    if task["kind"] == "continuation_resolution":
        continuations = []
        for row in conn.execute("SELECT * FROM continuations WHERE task_id=? ORDER BY created_at", (task["task_id"],)):
            item = dict(row)
            item["evidence_refs"] = json.loads(item.pop("evidence_json"))
            item["parent_flow"] = flow_context(conn, row["flow_id"])
            root_entry = conn.execute(
                "SELECT e.* FROM entries e JOIN flows f ON f.root_entry_id=e.entry_id WHERE f.flow_id=?", (row["flow_id"],)
            ).fetchone()
            profile_ids = set(row_json(root_entry, "profiles_json", [])) if root_entry else set()
            item["capability_profiles"] = [cap for cap in load_capabilities() if cap["capability_id"] in profile_ids]
            continuations.append(item)
        reusable = []
        for cache_task_id in payload.get("reuse_task_ids", []):
            cached_flows = [flow_context(conn, row["flow_id"]) for row in conn.execute(
                "SELECT flow_id FROM flows WHERE producer_task_id=? ORDER BY created_at,flow_id",
                (cache_task_id,),
            )]
            if cached_flows:
                reusable.append({"source": "continuation_task", "task_id": cache_task_id, "flows": cached_flows})
        handler_key = payload.get("handler_key")
        if handler_key:
            for row in conn.execute(
                """SELECT t.task_id,e.entry_key,e.symbol FROM tasks t
                   JOIN entries e ON e.entry_id=t.subject_id
                   WHERE t.kind='entry_path_discovery' AND t.status='completed'"""
            ):
                if handler_identity(row["symbol"]) != handler_key:
                    continue
                cached_flows = [flow_context(conn, item["flow_id"]) for item in conn.execute(
                    "SELECT flow_id FROM flows WHERE producer_task_id=? ORDER BY created_at,flow_id",
                    (row["task_id"],),
                )]
                if cached_flows:
                    reusable.append({
                        "source": "canonical_entry", "task_id": row["task_id"],
                        "entry_key": row["entry_key"], "flows": cached_flows,
                    })
        return {**payload, "continuations": continuations, "reusable_handler_flows": reusable}
    if task["kind"] == "security_assessment":
        path = path_context(conn, task["subject_id"])
        entry = None
        if path:
            row = conn.execute("SELECT * FROM entries WHERE entry_id=?", (path["root_entry_id"],)).fetchone()
            if row:
                entry = dict(row)
                entry["profiles"] = json.loads(entry.pop("profiles_json"))
                entry["discriminator"] = json.loads(entry.pop("discriminator_json"))
                entry["payload"] = json.loads(entry.pop("payload_json"))
        profile_ids = set(entry.get("profiles", [])) if entry else set()
        capability_profiles = [
            profile for profile in load_capabilities()
            if profile["capability_id"] in profile_ids
        ]
        return {
            **payload, "path": path, "entry": entry,
            "capability_profiles": capability_profiles,
            "pattern_cards": load_pattern_cards(capability_profiles),
        }
    return payload
