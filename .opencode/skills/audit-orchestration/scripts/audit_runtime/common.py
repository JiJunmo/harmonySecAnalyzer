"""Shared primitives for the component-driven audit runtime."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path


RUNTIME_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = RUNTIME_DIR.parent
SKILL_DIR = SCRIPTS_DIR.parent
CONFIG_DIR = SKILL_DIR / "config"
SCHEMAS_DIR = CONFIG_DIR / "schemas"
CAPABILITIES_PATH = CONFIG_DIR / "audit_capabilities.json"

TASK_AGENTS = {
    "component_semantic_analysis": "component-semantic-analyzer",
    "exploitability_validation": "exploitability-validator",
}
TERMINAL_TASK_STATES = {"completed", "exhausted"}
MAX_TASK_ATTEMPTS = 3
MAX_CONCURRENT_TASKS = 5
FINAL_CLASSIFICATIONS = {
    "confirmed_vulnerability", "protected_exposure", "benign_business_flow",
    "insufficient_evidence", "residual_risk",
}
SIX_EXPLOITABILITY_CHECKS = (
    "externally_reachable", "attacker_controlled", "sink_reached",
    "security_check_bypassed_or_absent", "boundary_violated", "concrete_impact",
)


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_id(prefix, value, length=16):
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}"


def normalize_text(value):
    return " ".join(str(value or "").strip().replace("\\", "/").lower().split())


def normalize_location(value):
    text = normalize_text(value)
    return re.sub(r":0+(\d+)$", r":\1", text)


def operation_group_identity(entry_id, group):
    """Semantic identity excludes later security judgments and ordinary branches."""
    operation = group["operation"]
    return canonical_json([
        entry_id,
        normalize_location(operation.get("location")) or normalize_text(operation.get("body")),
        sorted(normalize_text(value) for value in group.get("controlled_properties", [])),
    ])


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, target)


def write_text(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(value, encoding="utf-8")
    os.replace(temp, target)


def run_paths(run_dir):
    root = Path(run_dir).expanduser().resolve()
    return {
        "root": root,
        "db": root / "run.db",
        "session": root / "session.json",
        "project_model": root / "project" / "project_model.json",
        "incremental": root / "incremental",
        "change_set": root / "incremental" / "change_set.json",
        "impact_plan": root / "incremental" / "impact_plan.json",
        "baseline_semantics": root / "incremental" / "baseline_semantic_results.json",
        "baseline_validations": root / "incremental" / "baseline_validation_results.json",
        "baseline_findings": root / "incremental" / "baseline_findings.json",
        "tasks": root / "tasks",
        "evidence": root / "evidence",
        "exports": root / "exports",
        "findings": root / "findings.json",
        "report_model": root / "report_model.json",
        "report_md": root / "report.md",
        "report_html": root / "report.html",
        "snapshot": root / "report_snapshot.json",
    }


def ensure_run_dirs(run_dir):
    paths = run_paths(run_dir)
    for key in ("root", "tasks", "evidence", "exports", "incremental"):
        paths[key].mkdir(parents=True, exist_ok=True)
    paths["project_model"].parent.mkdir(parents=True, exist_ok=True)
    return paths


def load_capabilities(capability_filter=None):
    doc = read_json(CAPABILITIES_PATH, {})
    selected = set(capability_filter or [])
    rows = []
    for row in doc.get("capabilities", []):
        if row.get("status") != "enabled":
            continue
        if selected and row.get("capability_id") not in selected:
            continue
        rows.append(row)
    if selected - {row.get("capability_id") for row in rows}:
        raise ValueError("unknown_or_disabled_capability:" + ",".join(sorted(selected - {row.get("capability_id") for row in rows})))
    return rows


def capability_scope(capabilities):
    """Capabilities constrain operations, not which downstream components may run."""
    return sorted(row["capability_id"] for row in capabilities)
