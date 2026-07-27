"""Build immutable semantic and validation task documents from canonical state."""
from __future__ import annotations

from .common import load_capabilities
from .store import row_json


def _source_file(location):
    head, separator, tail = str(location).rpartition(":")
    return head if separator and tail.isdigit() else str(location)


def entry_context(conn, entry_id):
    row = conn.execute("SELECT * FROM entries WHERE entry_id=?", (entry_id,)).fetchone()
    if not row:
        return None
    payload = row_json(row, "payload_json", {})
    return {
        **payload,
        "entry_id": row["entry_id"], "entry_key": row["entry_key"],
        "component": row["component"], "symbol": row["symbol"],
        "facets": row_json(row, "facets_json", []),
        "external_reachability": row["reachability"],
        "profiles": row_json(row, "profiles_json", []),
    }


def semantic_group_context(conn, group_id):
    row = conn.execute("SELECT * FROM operation_groups WHERE group_id=?", (group_id,)).fetchone()
    if not row:
        return None
    group = row_json(row, "payload_json", {})
    group.update({
        "group_id": group_id, "entry_id": row["entry_id"],
        "scope": row["scope"], "validation_required": bool(row["validation_required"]),
        "source_group_id": row["source_group_id"],
        "operation_location": row["operation_location"],
        "controlled_properties": row_json(row, "controlled_properties_json", []),
        "evidence_refs": row_json(row, "evidence_json", []),
    })
    group["facts"] = [{
        "fact_id": fact["fact_id"], "fact_key": fact["fact_key"], "type": fact["fact_type"],
        "body": fact["body"], "location": fact["location"],
        "evidence_refs": row_json(fact, "evidence_json", []),
    } for fact in conn.execute(
        "SELECT * FROM group_facts WHERE group_id=? ORDER BY created_at,fact_id", (group_id,)
    )]
    group["edges"] = [{
        "edge_id": edge["edge_id"], "from": edge["from_key"], "to": edge["to_key"],
        "kind": edge["kind"], "evidence_refs": row_json(edge, "evidence_json", []),
    } for edge in conn.execute(
        """SELECT e.*,src.fact_key from_key,dst.fact_key to_key
           FROM group_edges e
           JOIN group_facts src ON src.fact_id=e.from_fact_id
           JOIN group_facts dst ON dst.fact_id=e.to_fact_id
           WHERE e.group_id=? ORDER BY e.created_at,e.edge_id""", (group_id,)
    )]
    return group


def validation_context(conn, group_id):
    row = conn.execute("SELECT * FROM validation_results WHERE group_id=?", (group_id,)).fetchone()
    if not row:
        return None
    payload = row_json(row, "payload_json", {})
    payload["boundary"] = row["boundary"]
    return payload


def group_context(conn, group_id):
    """Combined read model used only by exports and reports."""
    semantic = semantic_group_context(conn, group_id)
    if not semantic:
        return None
    validation = validation_context(conn, group_id)
    if validation:
        semantic_evidence = set(semantic.get("evidence_refs", []))
        validation_evidence = set(validation.get("evidence_refs", []))
        semantic["validation"] = validation
        semantic.update(validation)
        semantic["evidence_refs"] = sorted(semantic_evidence | validation_evidence)
    return semantic


def task_context(conn, task):
    payload = row_json(task, "input_json", {})
    entry = entry_context(conn, task["subject_id"])
    if task["kind"] == "component_semantic_analysis":
        profile_ids = set(entry.get("profiles", [])) if entry else set()
        profiles = [{key: row.get(key) for key in ("capability_id", "title", "domain")}
                    for row in load_capabilities() if row["capability_id"] in profile_ids]
        return {
            **payload,
            "entry": entry,
            "audit_scope": profiles,
            "analysis_contract": {
                "task_unit": "one deterministic component analysis unit",
                "phases": ["confirm_component_inputs", "trace_within_component", "collect_operations", "record_component_handoffs", "merge_equivalent_operations", "record_gaps"],
                "group_by": ["operation_location", "controlled_properties"],
                "stop_at": "component_handoff",
                "forbidden_outputs": ["classification", "exploitability", "severity", "cwe", "poc"],
            },
        }
    if task["kind"] == "exploitability_validation":
        analysis = conn.execute(
            "SELECT * FROM semantic_analyses WHERE entry_id=?", (task["subject_id"],)
        ).fetchone()
        groups = [semantic_group_context(conn, row["group_id"]) for row in conn.execute(
            "SELECT group_id FROM operation_groups WHERE entry_id=? AND validation_required=1 ORDER BY group_id",
            (task["subject_id"],)
        )]
        coverage = row_json(analysis, "coverage_json", {})
        locations = set(coverage.get("operation_sites_checked", []))
        for group in groups:
            locations.add(group["operation"]["location"])
            for key in ("facts", "guards"):
                locations.update(row.get("location") for row in group.get(key, []) if row.get("location"))
            for branch in group.get("branches", []):
                locations.update(branch.get("locations", []))
        run = conn.execute("SELECT target_repo FROM runs LIMIT 1").fetchone()
        return {
            "semantic_analysis": {
                "summary": analysis["summary"],
                "coverage": coverage,
                "operation_groups": groups,
            },
            "verification_scope": {
                "target_repo": run["target_repo"],
                "seed_locations": sorted(locations),
                "seed_files": sorted({_source_file(location) for location in locations}),
                "seed_symbols": coverage.get("entry_symbols_checked", []),
            },
        }
    return payload
