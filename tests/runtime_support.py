"""Test fixtures that drive component semantics through the production exploration protocol."""
from __future__ import annotations

import json
from pathlib import Path

from audit_runtime.contracts import normalize_submission, validate_submission
from audit_runtime.common import read_json
from audit_runtime.result_writer import submit_task_result
from audit_runtime.scheduler import reject_attempt
from audit_runtime.semantic_exploration import (
    finish_exploration_round,
    next_exploration_node,
    record_exploration_step,
    release_exploration_leases,
)
from audit_runtime.store import database, transaction


def _state():
    return {
        "controlled_properties": [],
        "principal": {
            "origin": "third-party application", "immediate": "third-party application",
            "origin_binding": "preserved", "authority": "origin",
        },
        "security_check_ids": [],
    }


def _symbol(qualified_name, file_path=None, line=1):
    return {
        "qualified_name": qualified_name,
        "file_path": file_path,
        "line": line if file_path else None,
        "kind": "method",
    }


def _step(work, summary, successors=None, assessment=None, groups=None, calls=None, gaps=None):
    successors = list(successors or [])
    unresolved = list(gaps or [])
    relations = {}
    for row in successors:
        target = row["symbol"]["qualified_name"]
        relations[(target, row["relation"])] = {
            "source_symbol": None if work["work_type"] == "entry_discovery"
            else work["symbol"]["qualified_name"],
            "target_symbol": target,
            "relation": row["relation"],
            "resolved_by": "atlas_index",
            "mechanism": "atlas_index",
            "unresolved_ref": None,
            "reason": "Atlas 返回该调用目标",
            "evidence": [],
        }
    document = {
        "node_id": work["node_id"], "work_type": work["work_type"],
        "status": "completed", "summary": summary, "stop_reason": None,
        "atlas_queries": [{
            "tool": "search" if work["work_type"] == "entry_discovery" else "calls",
            "source_symbol": None if work["work_type"] == "entry_discovery"
            else work["symbol"]["qualified_name"],
            "target_symbols": sorted({
                row["symbol"]["qualified_name"] for row in successors
            }),
            "unresolved_targets": unresolved,
        }],
        "resolved_relations": list(relations.values()),
        "analyzed_symbols": [],
        "facts": [], "security_checks": [],
        "operation_groups": list(groups or []), "component_calls": list(calls or []),
        "successors": successors, "gaps": unresolved,
    }
    if assessment is not None:
        document["entry_assessment"] = assessment
    return document


def submit_semantic_fixture(run_dir, task, result):
    """Submit a complete semantic fixture through entry/function exploration nodes."""
    run_dir = Path(run_dir)
    candidate = json.loads(json.dumps(result))
    with database(run_dir / "run.db") as conn, transaction(conn):
        task_row = conn.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task["task_id"],)
        ).fetchone()
        candidate = normalize_submission(candidate, task_row, conn)
        errors = validate_submission(candidate, task_row, conn)
        if errors:
            release_exploration_leases(conn, task["task_id"], task["attempt"])
            error = "invalid_semantic_fixture:" + "|".join(errors)
            status = reject_attempt(conn, task_row, error)
            return {
                "ok": True, "accepted": False, "task_id": task["task_id"],
                "status": status, "error": error,
            }

    coverage = candidate["coverage"]
    root = next_exploration_node(
        run_dir, task["task_id"], task["attempt"], budget=100,
    )["work"]
    entry_confirmed = coverage["entry_status"] != "excluded"
    entry_symbol = (
        coverage.get("entry_symbols_checked", [None])[0]
        if coverage.get("entry_symbols_checked") else task["input"]["entry"]["symbol"]
    )
    source_file = entry_symbol.rpartition(":")[0] if entry_symbol.rpartition(":")[2].isdigit() else entry_symbol
    successors = [{
        "symbol": _symbol(entry_symbol, source_file, 1), "relation": "callback",
        "condition": "组件输入进入真实回调", "decision": "follow",
        "stop_reason": None, "state": _state(),
    }] if entry_confirmed else []
    assessment = {
        "entry_status": coverage["entry_status"],
        "external_entry_status": coverage["external_entry_status"],
        "confirmed_external_candidate_ids": coverage["confirmed_external_candidate_ids"],
        "component_summary": candidate["summary"],
    }
    step_file = run_dir / "tasks" / f"{task['task_id']}.attempt-{task['attempt']}.test-step.json"
    step_file.write_text(json.dumps(_step(
        root, "测试夹具确认组件入口", successors, assessment=assessment,
    )), encoding="utf-8")
    outcome = record_exploration_step(
        run_dir, task["task_id"], task["attempt"], step_file,
    )
    if not outcome["accepted"]:
        return outcome

    if entry_confirmed:
        work = next_exploration_node(
            run_dir, task["task_id"], task["attempt"], budget=100,
        )["work"]
        boundary_successors = [{
            "symbol": _symbol(call["target_symbol"]), "relation": "component_boundary",
            "condition": call["condition"], "decision": "stop",
            "stop_reason": "component_boundary", "state": _state(),
        } for call in candidate.get("component_calls", [])]
        step_file.write_text(json.dumps(_step(
            work, "测试夹具记录组件语义", boundary_successors,
            groups=candidate["operation_groups"], calls=candidate["component_calls"],
            gaps=coverage.get("unresolved_targets", []),
        )), encoding="utf-8")
        outcome = record_exploration_step(
            run_dir, task["task_id"], task["attempt"], step_file,
        )
        if not outcome["accepted"]:
            return outcome

    return finish_exploration_round(
        run_dir, task["task_id"], task["attempt"],
    )


def submit_task_fixture(run_dir, task_id, input_path, attempt=None):
    """Route semantic test documents through exploration and all other tasks normally."""
    with database(Path(run_dir) / "run.db") as conn:
        task_row = conn.execute(
            "SELECT kind,attempts FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
    if not task_row:
        raise ValueError("task_not_found")
    if task_row["kind"] != "component_semantic_analysis":
        draft = Path(run_dir) / "tasks" / f"{task_id}.attempt-{task_row['attempts']}.draft.json"
        draft.write_text(Path(input_path).read_text(encoding="utf-8"), encoding="utf-8")
        return submit_task_result(run_dir, task_id, attempt, draft)
    task_file = Path(run_dir) / "tasks" / f"{task_id}.json"
    task = read_json(task_file)
    result = read_json(input_path)
    return submit_semantic_fixture(run_dir, task, result)
