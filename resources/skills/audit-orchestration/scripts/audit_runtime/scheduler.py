"""Deterministic task scheduling and recovery."""
from __future__ import annotations

from .common import MAX_CONCURRENT_TASKS, MAX_TASK_ATTEMPTS, SCHEMAS_DIR, now, read_json, run_paths, write_json
from .correlation import correlate_components, enqueue_component_call_targets
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
    schema_name = (
        "component-exploration-step.schema.json"
        if row["kind"] == "component_semantic_analysis"
        else SCHEMA_BY_TASK[row["kind"]]
    )
    handle = {
        "task_id": row["task_id"], "kind": row["kind"],
        "assigned_agent": row["agent"], "attempt": row["attempts"],
        "task_file": str(paths["tasks"] / f"{row['task_id']}.json"),
        "result_schema_file": str(SCHEMAS_DIR / schema_name),
    }
    if row["kind"] == "component_semantic_analysis":
        handle["worker_prompt"] = (
            f"只处理这个组件渐进探索轮次。读取 task_file={handle['task_file']}，严格执行其中 "
            f"exploration_protocol：循环领取节点、核实源码关系、提交步骤，最后必须调用 finish 命令。"
            f"本轮容量不足时保存 stop_reason=null 的后续断点并设置 pause_requested=true；"
            f"不填写步骤 status 或后续目标 decision，不得把尚未分析写成 gaps。"
            f"task_id={row['task_id']}，attempt={row['attempts']}。不要手工生成完整组件结果，"
            f"不要修改中央状态和报告；finish 返回 accepted=true 且 task_status=queued/completed 后才能结束本轮。"
        )
    else:
        draft_file = str(
            paths["tasks"] / f"{row['task_id']}.attempt-{row['attempts']}.draft.json"
        )
        handle["worker_prompt"] = (
            f"只处理这个 {row['kind']} 审计任务。读取 task_file={handle['task_file']}，"
            f"任务文件 input.result_protocol 明确给出统一结果写入方式。把结论草稿写入 "
            f"draft_file={draft_file}，然后必须原样执行 result_protocol.commands.submit，"
            f"由 Python 规范化、校验并正式落库。accepted=false 时按 errors 修正草稿并再次调用；"
            f"只有 accepted=true 才能结束。"
            f"task_id={row['task_id']}，attempt={row['attempts']}。不要处理其他任务，"
            f"不要修改中央状态或报告。"
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
            expanded = enqueue_component_call_targets(conn, paths["project_model"])
            if not expanded:
                correlate_components(conn, run["run_id"], paths)
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
            doc["input"] = task_context(conn, updated, paths)
            doc.update({
                "task_file": handle["task_file"],
                "result_schema_file": handle["result_schema_file"],
            })
            for stale in paths["tasks"].glob(f"{row['task_id']}.attempt-*.draft.json"):
                stale.unlink(missing_ok=True)
            write_json(handle["task_file"], doc)
            claimed.append(handle)
            append_event(conn, "task_claimed", row["task_id"], {
                "worker": worker, "attempt": updated["attempts"],
            })
    from .reporting import refresh_live_report
    return {
        "ok": True, "tasks": claimed, "count": len(claimed),
        "reason": "claimed" if claimed else "no_queued",
        "live_report": refresh_live_report(run_dir),
    }


def _unfinished_task(run_dir, task_id, attempt):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn, transaction(conn):
        task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not task or task["status"] != "running" or task["attempts"] != attempt:
            return {"task_id": task_id, "accepted": False, "status": task["status"] if task else "missing", "ignored": True}
        if task["kind"] == "component_semantic_analysis":
            from .semantic_exploration import release_exploration_leases
            release_exploration_leases(conn, task_id, attempt)
        error = "worker_finished_without_commit"
        status = reject_attempt(conn, task, error)
    return {"task_id": task_id, "accepted": False, "status": status, "error": error}


def reconcile_batch(run_dir):
    """Retry workers that returned without atomically finishing or continuing their task."""
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        run = run_row(conn)
        if run["status"] != "running":
            return {"ok": False, "reason": f"run_not_running:{run['status']}", "tasks": []}
        running = [dict(row) for row in conn.execute(
            "SELECT task_id,attempts FROM tasks WHERE status='running' ORDER BY created_at,task_id"
        )]

    outcomes = [
        _unfinished_task(run_dir, task["task_id"], task["attempts"])
        for task in running
    ]

    counts = {status: sum(row.get("status") == status for row in outcomes)
              for status in ("completed", "queued", "exhausted")}
    from .reporting import refresh_live_report
    return {
        "ok": True, "tasks": outcomes, "count": len(outcomes), **counts,
        "readiness": readiness(run_dir), "live_report": refresh_live_report(run_dir),
    }


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
        # PoC generation is a delivery enhancement, not a gate: an exhausted poc
        # task surfaces as "未生成 PoC" in the report and is not a coverage gap.
        poc_exhausted = conn.execute(
            "SELECT COUNT(*) n FROM tasks WHERE status='exhausted' AND kind='poc_generation'"
        ).fetchone()["n"]
        ready = run["status"] == "running" and not reasons
        return {
            "ok": run["status"] != "failed", "ready": ready,
            "state": "ready" if ready else run["status"], "error": run["error"],
            "reasons": reasons, "task_counts": counts,
            "coverage_gaps": {
                "exhausted_tasks": max(0, counts.get("exhausted", 0) - poc_exhausted),
                "entries_without_semantics": entries_without_semantics,
                "groups_without_validation": groups_without_validation,
                "component_correlation": row_json(run, "correlation_json", {}),
            },
        }
