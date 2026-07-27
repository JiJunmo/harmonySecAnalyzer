"""Deterministic batch scheduling driven by submission files."""
from __future__ import annotations

from .common import MAX_CONCURRENT_TASKS, MAX_TASK_ATTEMPTS, SCHEMAS_DIR, now, read_json, run_paths, write_json
from .correlation import correlate_components, enqueue_handoff_targets
from .contracts import SCHEMA_BY_TASK
from .lifecycle import run_row
from .store import append_event, database, row_json, task_document, transaction
from .task_context import task_context


def reject_attempt(conn, task, error):
    """Retry one task, or exhaust only that task after its final attempt."""
    status = "queued" if task["attempts"] < MAX_TASK_ATTEMPTS else "exhausted"
    conn.execute(
        "UPDATE tasks SET status=?,error=?,updated_at=? WHERE task_id=?",
        (status, error, now(), task["task_id"]),
    )
    append_event(conn, "task_retry" if status == "queued" else "task_exhausted", task["task_id"], {
        "attempt": task["attempts"], "error": error,
        "category": error.split(":", 1)[0],
    })
    return status


def _handle(row, paths):
    handle = {
        "task_id": row["task_id"], "kind": row["kind"],
        "assigned_agent": row["agent"], "attempt": row["attempts"],
        "task_file": str(paths["tasks"] / f"{row['task_id']}.json"),
        "submission_file": str(paths["tasks"] / f"{row['task_id']}.attempt-{row['attempts']}.submission.json"),
        "result_schema_file": str(SCHEMAS_DIR / SCHEMA_BY_TASK[row["kind"]]),
    }
    handle["worker_prompt"] = (
        f"只处理这个 {row['kind']} 审计任务。读取 task_file={handle['task_file']}，"
        f"该文件顶层 result_schema 已内嵌完整输出契约，必须严格按它生成结果并写入 "
        f"submission_file={handle['submission_file']}。task_id={row['task_id']}，"
        f"attempt={row['attempts']}。不要处理其他任务，不要修改中央状态或报告。"
        f"在 submission_file 成功写入完整 JSON 前不得结束。"
    )
    return handle


def claim_batch(run_dir, limit=MAX_CONCURRENT_TASKS, worker="harmony-auditor"):
    """Claim one complete dispatch batch; a running batch must converge first."""
    paths = run_paths(run_dir)
    requested = min(int(limit), MAX_CONCURRENT_TASKS)
    if requested <= 0:
        raise ValueError("claim_limit_must_be_positive")
    claimed = []
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        if run["status"] != "running":
            return {"ok": False, "tasks": [], "count": 0, "reason": f"run_not_running:{run['status']}"}
        running = conn.execute("SELECT COUNT(*) n FROM tasks WHERE status='running'").fetchone()["n"]
        if running:
            return {"ok": True, "tasks": [], "count": 0, "reason": "batch_in_progress", "running": running}
        semantic_queued = conn.execute(
            "SELECT COUNT(*) n FROM tasks WHERE kind='component_semantic_analysis' AND status='queued'"
        ).fetchone()["n"]
        if run["correlation_status"] == "pending" and not semantic_queued:
            expanded = enqueue_handoff_targets(conn, paths["project_model"])
            if not expanded:
                correlate_components(conn, run["run_id"])
        rows = conn.execute(
            """SELECT * FROM tasks WHERE status='queued'
               ORDER BY created_at,task_id LIMIT ?""", (requested,),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE tasks SET status='running',attempts=attempts+1,updated_at=? WHERE task_id=?",
                (now(), row["task_id"]),
            )
            updated = conn.execute("SELECT * FROM tasks WHERE task_id=?", (row["task_id"],)).fetchone()
            handle = _handle(updated, paths)
            doc = task_document(updated)
            doc["input"] = task_context(conn, updated)
            doc.update({
                "task_file": handle["task_file"],
                "submission_file": handle["submission_file"],
                "result_schema_file": handle["result_schema_file"],
                "result_schema": read_json(handle["result_schema_file"]),
            })
            for stale in paths["tasks"].glob(f"{row['task_id']}.attempt-*.submission.json"):
                stale.unlink(missing_ok=True)
            write_json(handle["task_file"], doc)
            claimed.append(handle)
            append_event(conn, "task_claimed", row["task_id"], {
                "worker": worker, "attempt": updated["attempts"],
            })
    return {
        "ok": True, "tasks": claimed, "count": len(claimed),
        "reason": "claimed" if claimed else "no_queued",
    }


def _missing_submission(run_dir, task_id, attempt):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not task or task["status"] != "running" or task["attempts"] != attempt:
            return {"task_id": task_id, "accepted": False, "status": task["status"] if task else "missing", "ignored": True}
        status = reject_attempt(conn, task, "missing_submission")
    return {"task_id": task_id, "accepted": False, "status": status, "error": "missing_submission"}


def reconcile_batch(run_dir):
    """Accept valid files and retry or exhaust every other task in the returned batch."""
    from .commands import submit_result

    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = run_row(conn)
        if run["status"] != "running":
            return {"ok": False, "reason": f"run_not_running:{run['status']}", "tasks": []}
        running = [dict(row) for row in conn.execute(
            "SELECT task_id,attempts FROM tasks WHERE status='running' ORDER BY created_at,task_id"
        )]

    outcomes = []
    for task in running:
        submission = paths["tasks"] / f"{task['task_id']}.attempt-{task['attempts']}.submission.json"
        if submission.is_file():
            outcome = submit_result(run_dir, task["task_id"], submission, task["attempts"])
        else:
            outcome = _missing_submission(run_dir, task["task_id"], task["attempts"])
        outcomes.append(outcome)

    counts = {status: sum(row.get("status") == status for row in outcomes)
              for status in ("completed", "queued", "exhausted")}
    return {"ok": True, "tasks": outcomes, "count": len(outcomes), **counts, "readiness": readiness(run_dir)}


def readiness(run_dir):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = run_row(conn)
        counts = {row["status"]: row["n"] for row in conn.execute(
            "SELECT status,COUNT(*) n FROM tasks GROUP BY status"
        )}
        entries_without_semantics = conn.execute(
            """SELECT COUNT(*) n FROM entries e WHERE EXISTS (
                 SELECT 1 FROM tasks t WHERE t.kind='component_semantic_analysis' AND t.subject_id=e.entry_id
               ) AND NOT EXISTS (
                 SELECT 1 FROM semantic_analyses a WHERE a.entry_id=e.entry_id
               )"""
        ).fetchone()["n"]
        groups_without_validation = conn.execute(
            """SELECT COUNT(*) n FROM operation_groups g WHERE NOT EXISTS (
                 SELECT 1 FROM validation_results v WHERE v.group_id=g.group_id
               ) AND g.validation_required=1"""
        ).fetchone()["n"]
        reasons = []
        if run["status"] == "failed": reasons.append("run_failed")
        if counts.get("queued", 0) or counts.get("running", 0): reasons.append("unfinished_tasks")
        if run["status"] == "created": reasons.append("run_not_initialized")
        if run["correlation_status"] != "complete": reasons.append("component_correlation_pending")
        ready = run["status"] == "running" and not reasons
        return {
            "ok": run["status"] != "failed", "ready": ready,
            "state": "ready" if ready else run["status"], "error": run["error"],
            "reasons": reasons, "task_counts": counts,
            "coverage_gaps": {
                "exhausted_tasks": counts.get("exhausted", 0),
                "entries_without_semantics": entries_without_semantics,
                "groups_without_validation": groups_without_validation,
                "component_correlation": row_json(run, "correlation_json", {}),
            },
        }
