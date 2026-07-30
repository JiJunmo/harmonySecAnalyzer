"""Deterministic baselines, change detection, and component impact planning."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path

from .common import CAPABILITIES_PATH, SCHEMAS_DIR, SKILL_DIR, canonical_json, now, read_json, run_paths, write_json
from .store import database, row_json
from .task_context import validation_group_fingerprint


BASELINE_SCHEMA_VERSION = 1
BASELINE_DIR_NAME = "incremental-baseline"
SKIP_DIRS = {
    ".git", ".atlas", ".idea", ".vscode", "node_modules", "oh_modules",
    "build", "outputs", "reports", "coverage", ".hvigor", "test", "ohosTest",
}
TRACKED_SUFFIXES = {".ets", ".ts", ".js", ".json5", ".json", ".yaml", ".yml"}
TRACKED_NAMES = {"hvigorfile.ts", "oh-package-lock.json5"}
CONFIG_NAMES = {"app.json5", "module.json5", "build-profile.json5", "oh-package.json5"}


def baseline_paths(target_repo):
    root = Path(target_repo).expanduser().resolve() / "reports" / BASELINE_DIR_NAME
    return {
        "root": root,
        "metadata": root / "baseline.json",
        "project_model": root / "project_model.json",
        "semantic_results": root / "semantic_results.json",
        "validation_results": root / "validation_results.json",
        "findings": root / "findings.json",
    }


def audit_contract_hash():
    files = (
        CAPABILITIES_PATH,
        SCHEMAS_DIR / "component-semantic-result.schema.json",
        SKILL_DIR.parent.parent / "agents" / "component-semantic-analyzer.md",
    )
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.name).encode("utf-8"))
        try:
            digest.update(path.read_bytes())
        except OSError as exc:
            raise ValueError(f"audit_contract_file_missing:{path}") from exc
    return digest.hexdigest()


def _tracked_file(path):
    return path.name in TRACKED_NAMES or path.suffix.lower() in TRACKED_SUFFIXES


def file_manifest(target_repo):
    root = Path(target_repo).expanduser().resolve()
    manifest = {}
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
        for name in sorted(files):
            path = Path(current) / name
            if not _tracked_file(path) or path.is_symlink():
                continue
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                relative = path.relative_to(root).as_posix()
                manifest[relative] = {"sha256": digest.hexdigest(), "size": path.stat().st_size}
            except OSError:
                continue
    return manifest


def _git(target_repo, *args, check=True):
    completed = subprocess.run(
        ["git", "-C", str(target_repo), *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False,
    )
    if check and completed.returncode != 0:
        raise ValueError("git_command_failed:" + (completed.stderr.strip() or "unknown"))
    return completed


def git_state(target_repo):
    root = Path(target_repo).expanduser().resolve()
    top = _git(root, "rev-parse", "--show-toplevel", check=False)
    if top.returncode != 0:
        return None
    git_root = Path(top.stdout.strip()).resolve()
    try:
        prefix = root.relative_to(git_root).as_posix()
    except ValueError:
        return None
    head_result = _git(root, "rev-parse", "HEAD", check=False)
    if head_result.returncode != 0:
        return None
    head = head_result.stdout.strip()
    status = _git(
        root, "status", "--porcelain=v1", "--untracked-files=normal", "--", ".",
        ":(exclude)reports/**", ":(exclude).atlas/**",
    ).stdout.splitlines()
    return {
        "root": str(git_root), "target_prefix": "" if prefix == "." else prefix,
        "commit": head, "dirty": bool(status),
    }


def _git_range_summary(target_repo, baseline_git, current_git):
    if not baseline_git or not current_git:
        return None
    if baseline_git.get("root") != current_git.get("root"):
        raise ValueError("git_repository_changed_full_audit_required")
    base = baseline_git.get("commit")
    head = current_git.get("commit")
    ancestor = _git(target_repo, "merge-base", "--is-ancestor", base, head, check=False)
    if ancestor.returncode != 0:
        raise ValueError("git_baseline_not_ancestor_full_audit_required")
    args = ["diff", "--name-status", "-M", f"{base}..{head}"]
    prefix = current_git.get("target_prefix")
    if prefix:
        args.extend(["--", prefix])
    rows = []
    for line in _git(target_repo, *args).stdout.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        row = {"status": parts[0], "path": parts[-1]}
        if parts[0].startswith("R") and len(parts) >= 3:
            row["old_path"] = parts[-2]
        rows.append(row)
    return {"base_commit": base, "target_commit": head, "commit_changes": rows}


def load_baseline(target_repo):
    paths = baseline_paths(target_repo)
    metadata = read_json(paths["metadata"])
    model = read_json(paths["project_model"])
    semantics = read_json(paths["semantic_results"], {})
    if (not isinstance(metadata, dict) or metadata.get("schema_version") != BASELINE_SCHEMA_VERSION
            or not isinstance(model, dict) or model.get("status") != "complete"
            or not isinstance(semantics, dict)):
        return None
    findings = read_json(paths["findings"], {"items": []})
    if not isinstance(findings, dict) or not isinstance(findings.get("items", []), list):
        findings = {"items": []}
    validations = read_json(paths["validation_results"])
    if not _valid_validation_snapshot(validations):
        validations = _legacy_validation_snapshot(target_repo, metadata.get("run_id"))
    if not _valid_validation_snapshot(validations):
        raise ValueError("incremental_validation_baseline_missing_full_audit_required")
    return {
        "metadata": metadata, "project_model": model,
        "semantic_results": semantics, "validation_results": validations,
        "findings": findings["items"],
    }


def _valid_validation_snapshot(snapshot):
    return (
        isinstance(snapshot, dict)
        and snapshot.get("schema_version") == 1
        and isinstance(snapshot.get("entries"), dict)
    )


def _validation_snapshot(conn):
    entries = {}
    rows = conn.execute(
        """SELECT t.*,e.entry_key FROM tasks t
           JOIN entries e ON e.entry_id=t.subject_id
           WHERE t.kind='exploitability_validation' AND t.status='completed'
           ORDER BY e.entry_key"""
    )
    for row in rows:
        result = read_json(row["result_ref"])
        if not isinstance(result, dict):
            continue
        group_ids = sorted({
            item.get("group_id") for item in result.get("validations", [])
            if isinstance(item, dict) and item.get("group_id")
        })
        fingerprints = {group_id: validation_group_fingerprint(conn, group_id) for group_id in group_ids}
        if group_ids and all(fingerprints.values()):
            entries[row["entry_key"]] = {
                "group_fingerprints": fingerprints,
                "result": result,
            }
    return {"schema_version": 1, "entries": entries}


def _legacy_validation_snapshot(target_repo, run_id):
    if not run_id:
        return None
    reports = Path(target_repo).expanduser().resolve() / "reports"
    for session_path in sorted(reports.glob("*/session.json"), reverse=True):
        session = read_json(session_path, {})
        if session.get("run_id") != run_id:
            continue
        db_path = session_path.parent / "run.db"
        try:
            uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
            with sqlite3.connect(uri, uri=True) as conn:
                conn.row_factory = sqlite3.Row
                return _validation_snapshot(conn)
        except (OSError, ValueError, sqlite3.Error):
            return None
    return None


def _entry_groups(model):
    groups = {}
    for row in model.get("entry_candidates", []):
        component_id = row.get("component_id")
        if component_id:
            group_key = f"component:{component_id}"
        else:
            group_key = canonical_json([
                "module-scope", row.get("module_id") or row.get("module_root"), row.get("type"),
            ])
        groups.setdefault(group_key, []).append(row)
    entries = {}
    for group_key, rows in groups.items():
        first = rows[0]
        entry_key = canonical_json([
            first.get("module_id") or first.get("module_root") or first.get("module_name"),
            first.get("component_id") or group_key,
        ])
        entries[entry_key] = {
            "entry_key": entry_key, "component_id": first.get("component_id"),
            "module_id": first.get("module_id"), "module_root": first.get("module_root"),
            "candidates": rows,
        }
    return entries


def _manifest_changes(previous, current):
    previous_paths = set(previous)
    current_paths = set(current)
    added = sorted(current_paths - previous_paths)
    deleted = sorted(previous_paths - current_paths)
    modified = sorted(
        path for path in previous_paths & current_paths
        if previous[path].get("sha256") != current[path].get("sha256")
    )
    return {"added": added, "modified": modified, "deleted": deleted}


def _path_in_root(path, root):
    normalized = str(path).strip("/")
    normalized_root = str(root or ".").strip("/")
    return normalized_root in {"", "."} or normalized == normalized_root or normalized.startswith(normalized_root + "/")


def _module_configuration(module):
    """Return module-level fields; component definitions are compared as entries."""
    if not isinstance(module, dict):
        return None
    return {
        key: value for key, value in module.items()
        if key not in {"module_id", "component_ids"}
    }


def _component_sources(model):
    sources = {}
    for component in model.get("components", []):
        path = str(component.get("source_file_hint") or "").strip("/")
        component_id = component.get("component_id")
        if path and component_id:
            sources.setdefault(path, set()).add(component_id)
    return sources


def _module_impacts(changed_files, previous_model, current_model):
    current_modules = {row["module_id"]: row for row in current_model.get("modules", [])}
    previous_modules = {row["module_id"]: row for row in previous_model.get("modules", [])}
    current_modules_by_file = {row.get("file"): row for row in current_modules.values() if row.get("file")}
    previous_modules_by_file = {row.get("file"): row for row in previous_modules.values() if row.get("file")}
    component_sources = _component_sources(previous_model)
    for path, component_ids in _component_sources(current_model).items():
        component_sources.setdefault(path, set()).update(component_ids)
    affected_modules = set()
    affected_components = set()
    global_change = False
    all_modules = list(current_modules.values()) + list(previous_modules.values())
    for path in changed_files:
        normalized_path = str(path).strip("/")
        if normalized_path in component_sources:
            affected_components.update(component_sources[normalized_path])
            continue

        if Path(path).name == "module.json5":
            previous_module = previous_modules_by_file.get(normalized_path)
            current_module = current_modules_by_file.get(normalized_path)
            if previous_module and current_module:
                if _module_configuration(previous_module) != _module_configuration(current_module):
                    affected_modules.add(current_module["module_id"])
                # Component declarations are handled by added/changed/deleted entries.
                continue

        matches = [row for row in all_modules if _path_in_root(path, row.get("root"))]
        if Path(path).name in CONFIG_NAMES and not matches:
            global_change = True
        elif matches:
            deepest = max(len(str(row.get("root") or "")) for row in matches)
            affected_modules.update(
                row["module_id"] for row in matches
                if len(str(row.get("root") or "")) == deepest
            )
        else:
            global_change = True
    if global_change:
        affected_modules.update(current_modules)

    reverse = {}
    for model in (previous_model, current_model):
        for edge in model.get("module_dependencies", []):
            reverse.setdefault(edge.get("target_module_id"), set()).add(edge.get("source_module_id"))
    queue = list(affected_modules)
    while queue:
        target = queue.pop()
        for source in reverse.get(target, set()):
            if source and source not in affected_modules:
                affected_modules.add(source)
                queue.append(source)
    return affected_modules, affected_components, global_change


def plan_incremental(target_repo, current_model):
    baseline = load_baseline(target_repo)
    if baseline is None:
        raise ValueError("incremental_baseline_missing_run_full_audit_first")
    previous_model = baseline["project_model"]
    if baseline["metadata"].get("audit_contract_hash") != audit_contract_hash():
        raise ValueError("audit_contract_changed_full_audit_required")
    previous_manifest = baseline["metadata"].get("file_manifest", {})
    current_manifest = file_manifest(target_repo)
    changes = _manifest_changes(previous_manifest, current_manifest)
    changed_files = sorted(set(changes["added"] + changes["modified"] + changes["deleted"]))

    current_git = git_state(target_repo)
    baseline_type = baseline["metadata"].get("source_type")
    current_type = "git" if current_git else "snapshot"
    if baseline_type != current_type:
        raise ValueError("baseline_source_type_changed_full_audit_required")
    git_range = _git_range_summary(target_repo, baseline["metadata"].get("git"), current_git)

    previous_entries = _entry_groups(previous_model)
    current_entries = _entry_groups(current_model)
    added_entries = sorted(set(current_entries) - set(previous_entries))
    deleted_entries = sorted(set(previous_entries) - set(current_entries))
    changed_entries = sorted(
        key for key in set(previous_entries) & set(current_entries)
        if canonical_json(previous_entries[key]["candidates"]) != canonical_json(current_entries[key]["candidates"])
    )
    affected_modules, affected_components, global_change = _module_impacts(
        changed_files, previous_model, current_model
    )
    reasons = {key: [] for key in current_entries}
    for key in added_entries:
        reasons[key].append("new_entry")
    for key in changed_entries:
        reasons[key].append("entry_definition_changed")
    for key, entry in current_entries.items():
        if entry.get("module_id") in affected_modules:
            reasons[key].append("module_source_or_dependency_changed")
        if entry.get("component_id") in affected_components:
            reasons[key].append("component_source_changed")
        if key not in baseline["semantic_results"]:
            reasons[key].append("baseline_semantics_missing")

    deleted_components = {
        previous_entries[key].get("component_id") for key in deleted_entries
        if previous_entries[key].get("component_id")
    }
    if deleted_components:
        for key, snapshot in baseline["semantic_results"].items():
            if key not in current_entries:
                continue
            calls = snapshot.get("result", {}).get("component_calls", [])
            if any(call.get("target_component_id") in deleted_components for call in calls):
                reasons[key].append("called_component_deleted")

    affected_entries = sorted(key for key, values in reasons.items() if values)
    reusable_entries = sorted(set(current_entries) - set(affected_entries))
    change_set = {
        "schema_version": 1, "source_type": current_type,
        "baseline_run_id": baseline["metadata"].get("run_id"),
        "baseline_completed_at": baseline["metadata"].get("completed_at"),
        "generated_at": now(), "files": changes, "changed_file_count": len(changed_files),
        "git": git_range, "working_tree_dirty": bool(current_git and current_git.get("dirty")),
    }
    impact_plan = {
        "schema_version": 1, "generated_at": now(),
        "added_entries": added_entries, "deleted_entries": deleted_entries,
        "changed_entries": changed_entries, "affected_entries": affected_entries,
        "reusable_entries": reusable_entries, "affected_modules": sorted(affected_modules),
        "affected_components": sorted(affected_components),
        "global_change": global_change,
        "reasons": {key: sorted(set(values)) for key, values in reasons.items() if values},
    }
    return {
        "baseline": baseline, "current_manifest": current_manifest,
        "current_git": current_git, "change_set": change_set, "impact_plan": impact_plan,
    }


def _semantic_snapshot(conn):
    snapshots = {}
    rows = conn.execute(
        """SELECT e.entry_key,e.entry_id,t.result_ref
           FROM entries e JOIN semantic_analyses a ON a.entry_id=e.entry_id
           JOIN tasks t ON t.task_id=a.task_id ORDER BY e.entry_key"""
    )
    for row in rows:
        result = read_json(row["result_ref"])
        if isinstance(result, dict):
            snapshots[row["entry_key"]] = {"entry_id": row["entry_id"], "result": result}
    return snapshots


def _finding_snapshot(conn):
    rows = []
    for row in conn.execute("SELECT * FROM findings ORDER BY finding_id"):
        item = dict(row)
        item["controlled_properties"] = json.loads(item.pop("controlled_properties_json"))
        item["evidence_refs"] = json.loads(item.pop("evidence_json"))
        item["payload"] = json.loads(item.pop("payload_json"))
        item.pop("created_at", None)
        rows.append(item)
    return rows


def baseline_eligible(conn):
    run = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
    if run["audit_mode"] not in {"full", "incremental"}:
        return False, "filtered_audit"
    if row_json(run, "component_filter_json", []) or row_json(run, "capability_filter_json", []):
        return False, "filtered_audit"
    if conn.execute("SELECT COUNT(*) n FROM tasks WHERE status='exhausted'").fetchone()["n"]:
        return False, "exhausted_tasks"
    missing_semantics = conn.execute(
        "SELECT COUNT(*) n FROM entries e WHERE NOT EXISTS (SELECT 1 FROM semantic_analyses s WHERE s.entry_id=e.entry_id)"
    ).fetchone()["n"]
    if missing_semantics:
        return False, "missing_semantics"
    missing_validations = conn.execute(
        """SELECT COUNT(*) n FROM operation_groups g WHERE g.validation_required=1
           AND NOT EXISTS (SELECT 1 FROM validation_results v WHERE v.group_id=g.group_id)"""
    ).fetchone()["n"]
    if missing_validations:
        return False, "missing_validations"
    return True, None


def save_baseline(run_dir):
    paths = run_paths(run_dir)
    with database(paths["db"]) as conn:
        eligible, reason = baseline_eligible(conn)
        if not eligible:
            return {"updated": False, "reason": reason}
        run = conn.execute("SELECT * FROM runs LIMIT 1").fetchone()
        semantics = _semantic_snapshot(conn)
        validations = _validation_snapshot(conn)
        findings = _finding_snapshot(conn)
        target_repo = Path(run["target_repo"]).resolve()
        model = read_json(paths["project_model"])
        metadata = {
            "schema_version": BASELINE_SCHEMA_VERSION, "run_id": run["run_id"],
            "completed_at": now(), "source_type": "git" if git_state(target_repo) else "snapshot",
            "git": git_state(target_repo), "file_manifest": file_manifest(target_repo),
            "semantic_results": len(semantics), "audit_contract_hash": audit_contract_hash(),
            "findings": len(findings),
        }
    target = baseline_paths(target_repo)
    target["root"].mkdir(parents=True, exist_ok=True)
    write_json(target["project_model"], model)
    write_json(target["semantic_results"], semantics)
    write_json(target["validation_results"], validations)
    write_json(target["findings"], {"schema_version": 1, "items": findings})
    write_json(target["metadata"], metadata)
    return {"updated": True, "path": str(target["metadata"]), "source_type": metadata["source_type"]}
