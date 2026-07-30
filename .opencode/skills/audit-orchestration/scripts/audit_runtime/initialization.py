"""Deterministic preparation of an audit run."""
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

from .common import SKILL_DIR, read_json, run_paths, write_json
from .lifecycle import candidate_rows, initialize_run, new_run, validate_run_request


PROJECT_MODELING_SCRIPTS = SKILL_DIR.parent / "project-modeling" / "scripts"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"module_not_loadable:{path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_run(target_repo, mode="full", capabilities=None, components=None, atlas=None):
    target = Path(target_repo).expanduser().resolve()
    if not target.is_dir():
        return {"ok": False, "stage": "project_modeling", "error": f"target_repo_not_found:{target}"}
    try:
        validate_run_request(mode, capabilities)
    except ValueError as exc:
        return {"ok": False, "stage": "request_validation", "error": str(exc)}

    profiler = _load_module("harmony_project_profiler", PROJECT_MODELING_SCRIPTS / "project_profiler.py")
    model = profiler.profile_project(target)
    if model.get("status") != "complete":
        return {
            "ok": False, "stage": "project_modeling", "error": "project_model_incomplete",
            "summary": model.get("summary", {}), "diagnostics": model.get("diagnostics", []),
        }
    try:
        candidate_rows(model, components)
    except ValueError as exc:
        return {"ok": False, "stage": "request_validation", "error": str(exc)}

    incremental = None
    if mode == "incremental":
        if components:
            return {"ok": False, "stage": "request_validation", "error": "incremental_mode_cannot_filter_components"}
        try:
            from .incremental import plan_incremental
            incremental = plan_incremental(target, model)
        except ValueError as exc:
            return {"ok": False, "stage": "incremental_planning", "error": str(exc)}

    indexer = _load_module("harmony_atlas_indexer", PROJECT_MODELING_SCRIPTS / "atlas_indexer.py")
    with tempfile.TemporaryDirectory(prefix="harmony-audit-prepare-") as temp_dir:
        index_output = Path(temp_dir) / "index_status.json"
        index_status = indexer.prepare_index(target, index_output, atlas=atlas)
        if not index_status.get("ok"):
            return {
                "ok": False, "stage": "atlas_index", "error": index_status.get("error", "atlas_index_failed"),
                "index_status": index_status,
            }

    allocated = new_run(target / "reports", target, mode, capabilities, components)
    paths = run_paths(allocated["run_dir"])
    write_json(paths["project_model"], model)
    write_json(paths["root"] / "atlas" / "index_status.json", index_status)
    if incremental:
        write_json(paths["change_set"], incremental["change_set"])
        write_json(paths["impact_plan"], incremental["impact_plan"])
        write_json(paths["baseline_semantics"], incremental["baseline"]["semantic_results"])
        write_json(paths["baseline_validations"], incremental["baseline"]["validation_results"])
        write_json(paths["baseline_findings"], {
            "schema_version": 1, "items": incremental["baseline"]["findings"],
        })
    initialized = initialize_run(allocated["run_dir"], paths["project_model"])
    from .reporting import refresh_live_report
    live_report = refresh_live_report(allocated["run_dir"])
    return {
        **allocated,
        "stage": "ready",
        "project_summary": model.get("summary", {}),
        "atlas": read_json(paths["root"] / "atlas" / "index_status.json", {}),
        "initial_task_ids": initialized["task_ids"],
        "entry_candidates": initialized["entry_candidates"],
        "analysis_units": initialized["analysis_units"],
        "reused_semantic_analyses": initialized.get("reused_semantic_analyses", 0),
        "incremental": ({
            "change_set": incremental["change_set"],
            "impact_plan": incremental["impact_plan"],
        } if incremental else None),
        "live_report": live_report,
    }
