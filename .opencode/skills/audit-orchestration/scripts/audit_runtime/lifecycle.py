"""Run allocation and deterministic initialization."""
from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

from .common import (canonical_json, capability_scope, ensure_run_dirs, load_capabilities, now,
                     read_json, run_paths, stable_id, write_json)
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
    if not name:
        return set()
    aliases = {name, name.removeprefix("./"), name.rsplit(".", 1)[-1]}
    for short_name in tuple(aliases):
        for qualifier in (
            candidate.get("module_id"), candidate.get("module_name"), candidate.get("module_root"),
        ):
            qualifier = str(qualifier or "").strip()
            if qualifier:
                aliases.update({f"{qualifier}/{short_name}", f"{qualifier}:{short_name}"})
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
    for target, candidates in matched.items():
        identities = {
            row.get("component_id") or canonical_json([
                row.get("module_id"), row.get("type"), row.get("location"),
            ])
            for row in candidates
        }
        if len(identities) > 1:
            choices = sorted({
                f"{row.get('module_id') or row.get('module_root') or row.get('module_name')}/"
                f"{row.get('component_name')}"
                for row in candidates
            })
            raise ValueError(f"ambiguous_component:{target}:" + ",".join(choices))
    selected_ids = {
        row["candidate_id"] for candidates in matched.values() for row in candidates
    }
    return [row for row in rows if row["candidate_id"] in selected_ids]


_TRANSPORT_BY_CANDIDATE = {
    "component_scope": "component_internal",
    "exported_component": "want",
    "deeplink": "uri",
    "implicit_want": "want",
    "extension_uri": "uri",
    "ipc_service_candidate": "ipc",
    "common_event_candidate": "common_event",
}

_CAPABILITY_ENTRY_TYPES = {
    "exported_component": {"exported_ability", "want"},
    "deeplink": {"deeplink"},
    "implicit_want": {"want"},
    "extension_uri": {"provider"},
    "ipc_service_candidate": {"ipc_transaction"},
    "common_event_candidate": {"common_event"},
}


def _capability_root(rows, capabilities):
    accepted = {
        entry_type
        for capability in capabilities
        for entry_type in capability.get("entry_types", [])
    }
    observed = {
        entry_type
        for row in rows
        for entry_type in _CAPABILITY_ENTRY_TYPES.get(row.get("type"), set())
    }
    return bool(accepted.intersection(observed))


def _candidate_groups(candidates):
    """Create deterministic component analysis units without source interpretation."""
    groups = {}
    for candidate in candidates:
        component_id = candidate.get("component_id")
        if component_id:
            key = f"component:{component_id}"
        else:
            key = canonical_json([
                "module-scope", candidate.get("module_id") or candidate.get("module_root"),
                candidate.get("type"),
            ])
        groups.setdefault(key, []).append(candidate)
    return groups


def _candidate_facet(candidate):
    entry_type = candidate.get("type") or "unknown"
    symbol = (candidate.get("src_entry") or candidate.get("component_name")
              or f"{candidate.get('module_name') or 'project'}:{entry_type}")
    return {
        "entry_type": entry_type,
        "transport": _TRANSPORT_BY_CANDIDATE.get(entry_type, "unknown"),
        "symbol": symbol,
        "discriminator": candidate.get("trigger_facts") or {},
        "external_reachability": "reachable" if candidate.get("exported") is True else "unknown",
        "project_candidate_ids": [candidate["candidate_id"]],
        "evidence_refs": [],
    }


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
    if (not isinstance(model, dict) or model.get("schema_version") != 2
            or model.get("status") != "complete"):
        raise ValueError("invalid_project_model")
    if source != paths["project_model"].resolve():
        shutil.copyfile(source, paths["project_model"])
    with database(paths["db"]) as conn, transaction(conn):
        run = run_row(conn)
        if run["status"] != "created":
            raise ValueError(f"run_already_initialized:{run['status']}")
        component_filter = row_json(run, "component_filter_json", [])
        candidates = candidate_rows(model)
        selected_candidates = candidate_rows(model, component_filter) if component_filter else candidates
        selected_candidate_ids = {row["candidate_id"] for row in selected_candidates}
        capabilities = load_capabilities(row_json(run, "capability_filter_json", []))
        profiles = capability_scope(capabilities)
        task_ids = []
        entry_ids = []
        for group_key, rows in sorted(_candidate_groups(candidates).items()):
            first = rows[0]
            facets = [_candidate_facet(row) for row in rows]
            explicitly_selected = any(row["candidate_id"] in selected_candidate_ids for row in rows)
            has_external_facet = any(row.get("type") != "component_scope" for row in rows)
            if component_filter:
                initial_task = explicitly_selected
                root_eligible = explicitly_selected and has_external_facet
            elif run["audit_mode"] == "capability":
                initial_task = _capability_root(rows, capabilities)
                root_eligible = initial_task
            else:
                initial_task = True
                root_eligible = has_external_facet
            component = (first.get("component_name")
                         or f"{first.get('module_name') or 'project'} dynamic {first.get('type')}")
            entry_key = canonical_json([
                first.get("module_id") or first.get("module_root") or first.get("module_name"),
                first.get("component_id") or group_key,
            ])
            entry_id = stable_id("ENTRY", entry_key)
            symbol = facets[0]["symbol"]
            reachability = "reachable" if any(
                row["external_reachability"] == "reachable" for row in facets
            ) else "unknown"
            payload = {
                "entry_id": entry_id, "entry_key": entry_key, "component": component,
                "component_id": first.get("component_id"), "module": first.get("module_name"),
                "module_id": first.get("module_id"), "module_root": first.get("module_root"),
                "symbol": symbol, "facets": facets, "external_reachability": reachability,
                "root_eligible": root_eligible, "initial_scope": initial_task,
                "project_candidates": rows,
                "project_candidate_ids": [row["candidate_id"] for row in rows],
                "evidence_refs": [],
            }
            conn.execute(
                "INSERT INTO entries(entry_id,entry_key,component,symbol,facets_json,reachability,profiles_json,payload_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (entry_id, entry_key, component, symbol, canonical_json(facets), reachability,
                 canonical_json(profiles), canonical_json(payload), now()),
            )
            entry_ids.append(entry_id)
            if initial_task:
                task_ids.append(enqueue_task(
                    conn, f"component-semantics:{entry_id}", "component_semantic_analysis", entry_id,
                    {"project_model": str(paths["project_model"])},
                ))
        conn.execute("UPDATE runs SET status='running',updated_at=? WHERE run_id=?", (now(), run["run_id"]))
        append_event(conn, "run_initialized", run["run_id"], {
            "entry_candidates": len(candidates), "analysis_units": len(entry_ids),
            "initial_semantic_analysis_tasks": len(task_ids),
            "components": component_filter,
        })
    update_session(paths, "running")
    return {"ok": True, "task_ids": task_ids, "entry_ids": entry_ids,
            "entry_candidates": len(candidates), "analysis_units": len(entry_ids)}
