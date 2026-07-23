"""Build immutable worker task documents from canonical state."""
from __future__ import annotations

import json

from .common import handler_identity, load_capabilities, load_pattern_cards
from .store import row_json


def _payload_extras(payload, excluded):
    return {
        key: value for key, value in (payload or {}).items()
        if key not in excluded
    }


def flow_context(conn, flow_id):
    flow = conn.execute("SELECT * FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
    if flow is None:
        return None
    payload = row_json(flow, "payload_json", {})
    doc = {
        **_payload_extras(payload, {
            "root_entry_id", "parent_flow_id", "branch_key", "controlled_property",
            "current_symbol", "status", "controlled_values", "facts", "edges", "continuations",
        }),
        "flow_id": flow["flow_id"], "root_entry_id": flow["root_entry_id"],
        "parent_flow_id": flow["parent_flow_id"], "branch_key": flow["branch_key"],
        "controlled_property": flow["controlled_property"], "current_symbol": flow["current_symbol"],
        "status": flow["status"], "controlled_values": row_json(flow, "controlled_values_json", []),
    }
    doc["facts"] = []
    for row in conn.execute("SELECT * FROM facts WHERE flow_id=? ORDER BY created_at,fact_id", (flow_id,)):
        fact_payload = row_json(row, "payload_json", {})
        fact = {
            **_payload_extras(fact_payload, {"fact_key", "type", "body", "location", "evidence_refs"}),
            "fact_id": row["fact_id"], "fact_key": row["fact_key"], "flow_id": row["flow_id"],
            "fact_type": row["fact_type"], "body": row["body"], "location": row["location"],
            "evidence_refs": row_json(row, "evidence_json", []),
        }
        doc["facts"].append(fact)
    doc["edges"] = []
    for row in conn.execute("SELECT * FROM edges WHERE flow_id=? ORDER BY created_at,edge_id", (flow_id,)):
        edge = {
            "edge_id": row["edge_id"], "flow_id": row["flow_id"],
            "from_fact_id": row["from_fact_id"], "to_fact_id": row["to_fact_id"],
            "kind": row["kind"], "evidence_refs": row_json(row, "evidence_json", []),
        }
        doc["edges"].append(edge)
    continuation_payloads = {
        item.get("semantic_key"): item
        for item in payload.get("continuations", [])
        if isinstance(item, dict) and item.get("semantic_key")
    }
    doc["continuations"] = []
    for row in conn.execute("SELECT * FROM continuations WHERE flow_id=? ORDER BY created_at,continuation_id", (flow_id,)):
        original = continuation_payloads.get(row["semantic_key"], {})
        continuation = {
            **_payload_extras(original, {"semantic_key", "kind", "target", "evidence_refs"}),
            "continuation_id": row["continuation_id"], "semantic_key": row["semantic_key"],
            "kind": row["kind"], "target": row["target"], "status": row["status"],
            "evidence_refs": row_json(row, "evidence_json", []),
            "child_flow_ids": row_json(row, "child_flow_ids_json", []),
        }
        doc["continuations"].append(continuation)
    return doc


def path_context(conn, path_id, compact_segments=False):
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
    if compact_segments:
        path["segments"] = [{
            key: segment.get(key) for key in (
                "flow_id", "root_entry_id", "parent_flow_id", "branch_key",
                "controlled_property", "current_symbol", "status", "controlled_values",
            )
        } | {
            "fact_ids": [fact["fact_id"] for fact in segment["facts"]],
            "edge_ids": [edge["edge_id"] for edge in segment["edges"]],
            "continuation_ids": [row["continuation_id"] for row in segment["continuations"]],
        } for segment in path["segments"]]
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
        path = path_context(conn, task["subject_id"], compact_segments=True)
        entry = None
        if path:
            row = conn.execute("SELECT * FROM entries WHERE entry_id=?", (path["root_entry_id"],)).fetchone()
            if row:
                payload = row_json(row, "payload_json", {})
                entry = {
                    **_payload_extras(payload, {
                        "entry_key", "entry_type", "component", "symbol", "discriminator",
                        "transport", "external_reachability", "evidence_refs",
                    }),
                    "entry_id": row["entry_id"], "entry_key": row["entry_key"],
                    "entry_type": row["entry_type"], "component": row["component"],
                    "symbol": row["symbol"], "discriminator": row_json(row, "discriminator_json", {}),
                    "transport": row["transport"], "external_reachability": row["reachability"],
                    "profiles": row_json(row, "profiles_json", []),
                    "evidence_refs": payload.get("evidence_refs", []),
                }
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
