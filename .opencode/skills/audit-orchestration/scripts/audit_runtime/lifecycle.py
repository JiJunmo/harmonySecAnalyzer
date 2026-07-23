"""Run allocation and deterministic initialization."""
from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

from .common import canonical_json, ensure_run_dirs, load_capabilities, now, read_json, run_paths, stable_id, write_json
from .store import append_event, database, enqueue_task, initialize_database, row_json, transaction


def run_row(conn):
    row = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
    if row is None:
        raise ValueError("run_not_initialized")
    return row


def validate_run_request(mode="full", capabilities=None):
    selected = list(dict.fromkeys(capabilities or []))
    if mode == "capability" and not selected:
        raise ValueError("capability_mode_requires_filter")
    if mode == "full" and selected:
        raise ValueError("full_mode_cannot_filter_capabilities")
    load_capabilities(selected)
    return selected


def component_aliases(candidate):
    name = str(candidate.get("component_name") or "").strip()
    module = str(candidate.get("module_name") or "").strip()
    if not name:
        return set()
    aliases = {name, name.removeprefix("./"), name.rsplit(".", 1)[-1]}
    for short_name in tuple(aliases):
        if module:
            aliases.update({f"{module}/{short_name}", f"{module}:{short_name}"})
    return aliases


def candidate_rows(model, component_filter=None):
    rows = [
        row for row in model.get("entry_candidates", [])
        if isinstance(row, dict) and row.get("candidate_id")
    ]
    requested = list(dict.fromkeys(component_filter or []))
    if not requested:
        return rows
    matched = {target: [] for target in requested}
    for row in rows:
        aliases = component_aliases(row)
        for target in requested:
            if target in aliases:
                matched[target].append(row)
    missing = [target for target, candidates in matched.items() if not candidates]
    if missing:
        raise ValueError("component_has_no_entry_candidates:" + ",".join(missing))
    selected_ids = {
        row["candidate_id"] for candidates in matched.values() for row in candidates
    }
    return [row for row in rows if row["candidate_id"] in selected_ids]


def update_session(paths, status, error=None):
    session = read_json(paths["session"], {})
    session["status"] = status
    session["updated_at"] = now()
    if error:
        session["error"] = error
    else:
        session.pop("error", None)
    write_json(paths["session"], session)


def new_run(reports_root, target_repo, mode="full", capabilities=None, components=None):
    target = Path(target_repo).expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"target_repo_not_found:{target}")
    selected = validate_run_request(mode, capabilities)
    selected_components = list(dict.fromkeys(
        str(component).strip() for component in (components or []) if str(component).strip()
    ))
    root = Path(reports_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run_id = stable_id("RUN", {"target": str(target), "stamp": stamp})
    run_dir = root / f"{target.name}-{stamp}-{run_id[-6:]}"
    paths = ensure_run_dirs(run_dir)
    initialize_database(paths["db"])
    with database(paths["db"]) as conn, transaction(conn):
        stamp_iso = now()
        conn.execute(
            """INSERT INTO runs
               (run_id,target_repo,audit_mode,capability_filter_json,component_filter_json,status,error,created_at,updated_at,finalized_at)
               VALUES (?,?,?,?,?,?,NULL,?,?,NULL)""",
            (run_id, str(target), mode, canonical_json(selected), canonical_json(selected_components),
             "created", stamp_iso, stamp_iso),
        )
        append_event(conn, "run_created", run_id, {
            "target_repo": str(target), "mode": mode, "components": selected_components,
        })
    write_json(paths["session"], {
        "schema_version": 1, "run_id": run_id, "run_dir": str(run_dir),
        "target_repo": str(target), "mode": mode, "capabilities": selected,
        "components": selected_components,
        "status": "created", "created_at": stamp_iso,
    })
    return {"ok": True, "run_id": run_id, "run_dir": str(run_dir)}


def initialize_run(run_dir, project_model):
    paths = ensure_run_dirs(run_dir)
    source = Path(project_model).expanduser().resolve()
    model = read_json(source)
    if not isinstance(model, dict) or model.get("status") != "complete":
        raise ValueError("invalid_project_model")
    if source != paths["project_model"].resolve():
        shutil.copyfile(source, paths["project_model"])
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        if run["status"] != "created":
            raise ValueError(f"run_already_initialized:{run['status']}")
        component_filter = row_json(run, "component_filter_json", [])
        candidates = candidate_rows(model, component_filter)
        task_id = enqueue_task(conn, "entry-resolution", "entry_resolution", payload={
            "project_model": str(paths["project_model"]), "entry_candidates": candidates,
        })
        conn.execute("UPDATE runs SET status='running',updated_at=? WHERE run_id=?", (now(), run["run_id"]))
        append_event(conn, "run_initialized", run["run_id"], {
            "entry_candidates": len(candidates), "components": component_filter,
        })
    update_session(paths, "running")
    return {"ok": True, "task_id": task_id, "entry_candidates": len(candidates)}
