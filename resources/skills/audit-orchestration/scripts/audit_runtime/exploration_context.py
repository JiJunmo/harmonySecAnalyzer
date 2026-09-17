"""Read-only, paginated views of durable exploration scope and evidence."""
from __future__ import annotations

from .common import run_paths
from .store import database, row_json


def work_record(row):
    return {
        "work_id": row["work_id"], "node_id": row["node_id"],
        "scope": row_json(row, "scope_json", {}),
        "state": row_json(row, "state_json", {}),
        "conditions": row_json(row, "conditions_json", []),
        "status": row["status"],
        "wait_for": row_json(row, "dependencies_json", []),
        "result": row_json(row, "result_json", None),
    }


def coverage_record(row, full=False):
    record = work_record(row)
    result = record["result"]
    record["detail_available"] = bool(result) and not full
    if result and not full:
        record["result"] = {
            "summary": result["summary"], "checked": result["checked"],
            "termination": result["termination"],
            "security_checks": result["security_checks"],
            "gaps": result["gaps"],
            "operation_groups": [
                {k: group[k] for k in ("group_key", "title") if k in group}
                for group in result["operation_groups"]
            ],
            "component_call_count": len(result["component_calls"]),
            "fact_count": len(result["facts"]),
        }
    return record


def work_context(conn, exploration_id, work_id, offset=0, limit=40):
    from .semantic_exploration import work_rows, closed_work_ids
    rows = work_rows(conn, exploration_id)
    by_id = {r["work_id"]: r for r in rows}
    if work_id not in by_id:
        raise ValueError("exploration_work_not_found")
    current = by_id[work_id]
    scope = row_json(current, "scope_json", {})
    edges = [dict(r) for r in conn.execute(
        "SELECT * FROM exploration_edges WHERE exploration_id=? ORDER BY created_at,edge_id",
        (exploration_id,),
    )]
    for edge in edges:
        edge["evidence"] = row_json(edge, "evidence_json", [])
        del edge["evidence_json"]
    ancestors = {work_id}
    while True:
        expanded = ancestors | {e["source_work_id"] for e in edges if e["target_work_id"] in ancestors}
        if expanded == ancestors:
            break
        ancestors = expanded
    related_ids = ancestors | {e["target_work_id"] for e in edges if e["source_work_id"] in ancestors}
    related = [r for r in rows if r["work_id"] in related_ids
               or row_json(r, "scope_json", {})["symbol"] == scope["symbol"]
               or r["work_id"] in row_json(current, "dependencies_json", [])]
    dependencies = set(row_json(current, "dependencies_json", []))
    direct_parents = {e["source_work_id"] for e in edges if e["target_work_id"] == work_id}
    related.sort(key=lambda r: (0 if r["work_id"] == work_id else
                               1 if r["work_id"] in dependencies else
                               2 if r["work_id"] in direct_parents else 3))
    page = related[offset:offset + limit]
    ids = {r["work_id"] for r in page}
    closed = closed_work_ids(conn, exploration_id)
    return {
        **work_record(current),
        "scope_complete": work_id in closed,
        "coverage": [{**coverage_record(r, r["work_id"] in dependencies),
                      "scope_complete": r["work_id"] in closed} for r in page if r["work_id"] != work_id],
        "transitions": [e for e in edges if e["target_work_id"] in ids],
        "pagination": {
            "offset": offset, "total": len(related),
            "next_offset": offset + limit if offset + limit < len(related) else None,
        },
        "history_rule": "Coverage is a compact index, not full evidence. Current work and return dependencies retain full results. Query a work_id only when its facts affect the current decision; pagination is optional. Runtime checks registered closure without rereading history.",
    }


def read_exploration_context(run_dir, task_id, attempt, work_id, offset=0):
    from .semantic_exploration import _task
    if offset < 0:
        raise ValueError("offset_must_be_nonnegative")
    with database(run_paths(run_dir)["db"]) as conn:
        task = _task(conn, task_id, attempt)
        exploration = conn.execute(
            "SELECT exploration_id FROM component_explorations WHERE entry_id=?",
            (task["subject_id"],),
        ).fetchone()
        if not exploration:
            raise ValueError("component_exploration_not_found")
        return {"ok": True, "work": work_context(conn, exploration[0], work_id, offset)}
