"""Shared primitives for the flow-driven audit runtime."""
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
    "entry_planning": "entry-planner",
    "entry_exploration": "flow-analyzer",
    "shared_handler": "flow-analyzer",
    "chain_correlation": "flow-analyzer",
    "pattern_evaluation": "flow-pattern-evaluator",
    "flow_validation": "flow-validator",
}
TERMINAL_TASK_STATES = {"completed", "failed"}
TERMINAL_FLOW_STATES = {"connected", "blocked", "benign", "gap"}
FINAL_CLASSIFICATIONS = {
    "confirmed_vulnerability", "protected_exposure", "benign_business_flow",
    "insufficient_evidence", "residual_risk",
}


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


def flow_identity_key(flow):
    return canonical_json([
        flow.get("root_entry_id"), normalize_text(flow.get("branch_key")),
        normalize_text(flow.get("controlled_property")), normalize_text(flow.get("flow_key")),
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


def run_paths(run_dir):
    root = Path(run_dir).expanduser().resolve()
    return {
        "root": root,
        "db": root / "run.db",
        "session": root / "session.json",
        "project_model": root / "project" / "project_model.json",
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
    for key in ("root", "tasks", "evidence", "exports"):
        paths[key].mkdir(parents=True, exist_ok=True)
    paths["project_model"].parent.mkdir(parents=True, exist_ok=True)
    return paths


def load_capabilities(capability_filter=None):
    doc = read_json(CAPABILITIES_PATH, {})
    selected = set(capability_filter or [])
    rows = []
    for row in doc.get("capabilities", []):
        if row.get("status") not in {"partial", "implemented"}:
            continue
        if selected and row.get("capability_id") not in selected:
            continue
        rows.append(row)
    if selected - {row.get("capability_id") for row in rows}:
        raise ValueError("unknown_or_disabled_capability:" + ",".join(sorted(selected - {row.get("capability_id") for row in rows})))
    return rows


def profiles_for_entry(entry_type, capabilities):
    return sorted(
        row["capability_id"] for row in capabilities
        if entry_type in row.get("entry_types", [])
    )
