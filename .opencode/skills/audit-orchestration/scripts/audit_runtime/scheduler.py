"""Deterministic task scheduling and terminal failure handling."""
from __future__ import annotations

from .common import MAX_CONCURRENT_TASKS, MAX_TASK_ATTEMPTS, SCHEMAS_DIR, now, read_json, run_paths, write_json
from .contracts import SCHEMA_BY_TASK
from .lifecycle import candidate_rows, run_row, update_session
from .store import append_event, database, row_json, task_document, transaction
from .task_context import task_context


def abort_run(conn, failed_task_id, error):
    run = run_row(conn)
    stamp = now()
    if failed_task_id:
        conn.execute(
            "UPDATE tasks SET status='failed',error=?,updated_at=? WHERE task_id=?",
            (error, stamp, failed_task_id),
        )
        append_event(conn, "task_failed", failed_task_id, {
            "error": error, "category": error.split(":", 1)[0],
        })
    cancelled = conn.execute(
        "SELECT task_id FROM tasks WHERE status IN ('queued','running') AND task_id<>?",
        (failed_task_id or "",),
    ).fetchall()
    for row in cancelled:
        conn.execute(
            "UPDATE tasks SET status='cancelled',error=?,updated_at=? WHERE task_id=?",
            (f"run_aborted:{failed_task_id or 'control'}", stamp, row["task_id"]),
        )
        append_event(conn, "task_cancelled", row["task_id"], {
            "failed_task_id": failed_task_id, "error": error,
        })
    conn.execute(
        "UPDATE runs SET status='failed',error=?,updated_at=? WHERE run_id=?",
        (error, stamp, run["run_id"]),
    )
    append_event(conn, "run_failed", run["run_id"], {
        "failed_task_id": failed_task_id, "error": error,
        "cancelled_tasks": len(cancelled),
    })
    return len(cancelled)


def transition_failure(conn, task, error, retryable=True):
    if retryable and task["attempts"] < MAX_TASK_ATTEMPTS:
        conn.execute(
            "UPDATE tasks SET status='queued',error=?,updated_at=? WHERE task_id=?",
            (error, now(), task["task_id"]),
        )
        append_event(conn, "task_retry", task["task_id"], {
            "error": error, "category": error.split(":", 1)[0],
        })
        return "queued"
    abort_run(conn, task["task_id"], error)
    return "failed"


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
        f"严格按照 result_schema_file={handle['result_schema_file']} 生成结果并写入 "
        f"submission_file={handle['submission_file']}。task_id={row['task_id']}，"
        f"attempt={row['attempts']}。不要处理其他任务，不要修改中央状态或报告。"
    )
    return handle


def claim_tasks(run_dir, limit=MAX_CONCURRENT_TASKS, worker="harmony-auditor", max_workers=MAX_CONCURRENT_TASKS):
    paths = run_paths(run_dir)
    requested_limit = int(limit)
    worker_limit = int(max_workers)
    if requested_limit <= 0:
        raise ValueError("claim_limit_must_be_positive")
    if worker_limit <= 0:
        raise ValueError("max_workers_must_be_positive")
    worker_limit = min(worker_limit, MAX_CONCURRENT_TASKS)
    claimed = []
    terminal_error = None
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        if run["status"] == "failed":
            return {"ok": False, "tasks": [], "count": 0, "reason": "run_failed", "error": run["error"]}
        if run["status"] != "running":
            return {"ok": False, "tasks": [], "count": 0, "reason": f"run_not_running:{run['status']}"}
        running = conn.execute("SELECT COUNT(*) n FROM tasks WHERE status='running'").fetchone()["n"]
        capacity = max(0, worker_limit - running)
        if capacity == 0:
            return {
                "ok": True, "tasks": [], "count": 0, "running": running,
                "capacity": 0, "reason": "batch_in_progress",
            }
        claim_limit = min(requested_limit, capacity)
        rows = conn.execute(
            """SELECT t.* FROM tasks t
               WHERE t.status='queued' AND NOT EXISTS (
                 SELECT 1 FROM task_dependencies d JOIN tasks p ON p.task_id=d.depends_on
                 WHERE d.task_id=t.task_id AND p.status<>'completed')
               ORDER BY t.created_at,t.task_id LIMIT ?""", (claim_limit,),
        ).fetchall()
        if not rows and running == 0:
            queued = conn.execute("SELECT COUNT(*) n FROM tasks WHERE status='queued'").fetchone()["n"]
            if queued:
                terminal_error = "dependency_deadlock"
                abort_run(conn, None, terminal_error)
            else:
                open_continuations = conn.execute(
                    "SELECT COUNT(*) n FROM continuations WHERE status='open'"
                ).fetchone()["n"]
                model = read_json(paths["project_model"], {})
                expected = len(candidate_rows(model, row_json(run, "component_filter_json", [])))
                disposed = conn.execute("SELECT COUNT(*) n FROM entry_dispositions").fetchone()["n"]
                if open_continuations:
                    terminal_error = "orphaned_continuations"
                elif expected != disposed:
                    terminal_error = "entry_coverage_incomplete_without_tasks"
                elif conn.execute(
                    """SELECT 1 FROM flows f WHERE f.status IN ('reached','stopped','gap')
                       AND NOT EXISTS (SELECT 1 FROM paths p WHERE p.terminal_flow_id=f.flow_id) LIMIT 1"""
                ).fetchone():
                    terminal_error = "terminal_flow_without_path"
                elif conn.execute(
                    "SELECT 1 FROM continuations WHERE status='resolved' AND child_flow_ids_json='[]' LIMIT 1"
                ).fetchone():
                    terminal_error = "resolved_continuation_without_children"
                elif conn.execute(
                    """SELECT 1 FROM paths p WHERE NOT EXISTS (
                         SELECT 1 FROM tasks t WHERE t.kind='security_assessment' AND t.subject_id=p.path_id
                       ) LIMIT 1"""
                ).fetchone():
                    terminal_error = "path_without_security_assessment"
                if terminal_error:
                    abort_run(conn, None, terminal_error)
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
            })
            for stale_submission in paths["tasks"].glob(f"{row['task_id']}.attempt-*.submission.json"):
                stale_submission.unlink(missing_ok=True)
            write_json(handle["task_file"], doc)
            claimed.append(handle)
            append_event(conn, "task_claimed", row["task_id"], {
                "worker": worker, "attempt": updated["attempts"],
            })
        running += len(claimed)
    if terminal_error:
        update_session(paths, "failed", terminal_error)
        return {"ok": False, "tasks": [], "count": 0, "reason": terminal_error, "error": terminal_error}
    return {
        "ok": True, "tasks": claimed, "count": len(claimed), "running": running,
        "capacity": max(0, worker_limit - running),
        "reason": "no_ready_tasks" if not claimed else "claimed",
    }


def next_task(run_dir, worker="harmony-auditor"):
    """Reserve one slot so the orchestrator can fill a batch before dispatching it."""
    result = claim_tasks(run_dir, limit=1, worker=worker)
    if not result.get("ok"):
        return {**result, "task": None}
    if result["count"]:
        return {
            "ok": True, "task": result["tasks"][0], "reason": "claimed",
            "running": result["running"], "free_slots": result["capacity"],
        }
    reason = "worker_pool_full" if result.get("reason") == "batch_in_progress" else "no_queued"
    return {
        "ok": True, "task": None, "reason": reason,
        "running": result.get("running", 0), "free_slots": result.get("capacity", 0),
    }


def fail_task(run_dir, task_id, error, retryable=False, attempt=None):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if task is None:
            raise ValueError("task_not_found")
        if attempt is not None and int(attempt) != task["attempts"]:
            return {
                "ok": True, "accepted": False, "task_id": task_id, "status": task["status"],
                "error": f"stale_attempt:expected={task['attempts']}:actual={attempt}", "ignored": True,
            }
        if task["status"] != "running":
            return {
                "ok": True, "accepted": False, "task_id": task_id, "status": task["status"],
                "error": f"task_not_running:{task['status']}", "ignored": True,
            }
        status = transition_failure(conn, task, error, retryable)
    if status == "failed":
        update_session(paths, "failed", error)
    return {"ok": True, "accepted": True, "task_id": task_id, "status": status}


def recover_tasks(run_dir):
    paths = run_paths(run_dir)
    failed_error = None
    recovered = []
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        if run["status"] != "running":
            raise ValueError(f"run_not_recoverable:{run['status']}")
        for task in conn.execute("SELECT * FROM tasks WHERE status='running' ORDER BY created_at").fetchall():
            if task["attempts"] >= MAX_TASK_ATTEMPTS:
                failed_error = f"recovery_attempts_exhausted:{task['task_id']}"
                abort_run(conn, task["task_id"], failed_error)
                break
            conn.execute(
                "UPDATE tasks SET status='queued',error=?,updated_at=? WHERE task_id=?",
                ("orchestrator_recovered", now(), task["task_id"]),
            )
            append_event(conn, "task_recovered", task["task_id"], {"attempt": task["attempts"]})
            recovered.append(task["task_id"])
    if failed_error:
        update_session(paths, "failed", failed_error)
        return {"ok": False, "status": "failed", "error": failed_error, "recovered": recovered}
    return {"ok": True, "status": "running", "recovered": recovered}


def readiness(run_dir):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = run_row(conn)
        counts = {row["status"]: row["n"] for row in conn.execute(
            "SELECT status,COUNT(*) n FROM tasks GROUP BY status"
        )}
        open_continuations = conn.execute(
            "SELECT COUNT(*) n FROM continuations WHERE status='open'"
        ).fetchone()["n"]
        terminal_without_path = conn.execute(
            """SELECT COUNT(*) n FROM flows f WHERE f.status IN ('reached','stopped','gap')
               AND NOT EXISTS (SELECT 1 FROM paths p WHERE p.terminal_flow_id=f.flow_id)"""
        ).fetchone()["n"]
        resolved_without_children = conn.execute(
            "SELECT COUNT(*) n FROM continuations WHERE status='resolved' AND child_flow_ids_json='[]'"
        ).fetchone()["n"]
        paths_without_assessment = conn.execute(
            """SELECT COUNT(*) n FROM paths p WHERE NOT EXISTS (
                 SELECT 1 FROM tasks t WHERE t.kind='security_assessment' AND t.subject_id=p.path_id
               )"""
        ).fetchone()["n"]
        model = read_json(paths["project_model"], {})
        component_filter = row_json(run, "component_filter_json", [])
        candidates = len(candidate_rows(model, component_filter))
        dispositions = conn.execute("SELECT COUNT(*) n FROM entry_dispositions").fetchone()["n"]
        reasons = []
        if run["status"] == "failed": reasons.append("run_failed")
        if counts.get("queued", 0) or counts.get("running", 0): reasons.append("unfinished_tasks")
        if counts.get("failed", 0) or counts.get("cancelled", 0): reasons.append("failed_tasks")
        if open_continuations: reasons.append("open_continuations")
        if terminal_without_path: reasons.append("terminal_flow_without_path")
        if resolved_without_children: reasons.append("resolved_continuation_without_children")
        if paths_without_assessment: reasons.append("path_without_security_assessment")
        if candidates != dispositions: reasons.append("entry_coverage_incomplete")
        if run["status"] == "created": reasons.append("run_not_initialized")
        ready = run["status"] == "running" and not reasons
        state = "failed" if run["status"] == "failed" else ("ready" if ready else run["status"])
        return {
            "ok": run["status"] != "failed", "ready": ready, "state": state,
            "error": run["error"], "reasons": reasons, "task_counts": counts,
            "open_continuations": open_continuations,
            "path_integrity": {
                "terminal_without_path": terminal_without_path,
                "resolved_without_children": resolved_without_children,
                "paths_without_assessment": paths_without_assessment,
            },
            "candidate_coverage": {"total": candidates, "disposed": dispositions},
        }
