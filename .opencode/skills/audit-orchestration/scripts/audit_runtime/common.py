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
PATTERNS_DIR = SKILL_DIR.parent / "attack-patterns" / "patterns"

TASK_AGENTS = {
    "entry_resolution": "entry-resolver",
    "entry_path_discovery": "flow-analyzer",
    "continuation_resolution": "flow-analyzer",
    "security_assessment": "security-assessor",
}
TERMINAL_TASK_STATES = {"completed", "failed", "cancelled"}
MAX_TASK_ATTEMPTS = 3
MAX_CONCURRENT_TASKS = 5
TERMINAL_FLOW_STATES = {"reached", "stopped", "gap"}
FINAL_CLASSIFICATIONS = {
    "confirmed_vulnerability", "protected_exposure", "benign_business_flow",
    "insufficient_evidence", "residual_risk",
}
SIX_EXPLOITABILITY_CHECKS = (
    "externally_reachable", "attacker_controlled", "sink_reached",
    "guard_bypassed_or_absent", "boundary_violated", "concrete_impact",
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


def handler_identity(target):
    text = normalize_text(target)
    return re.sub(r"\s*\(via\b.*\)\s*$", "", text).strip()


def flow_identity_key(flow):
    operations = sorted({
        canonical_json([normalize_location(fact.get("location"))])
        if normalize_location(fact.get("location"))
        else canonical_json([normalize_text(fact.get("body"))])
        for fact in flow.get("facts", [])
        if fact.get("type") == "operation"
    })
    terminal = operations or [normalize_text(flow.get("current_symbol"))]
    continuations = sorted(
        canonical_json([row.get("kind"), handler_identity(row.get("target"))])
        for row in flow.get("continuations", [])
    )
    return canonical_json([
        flow.get("root_entry_id"), flow.get("parent_flow_id"),
        normalize_text(flow.get("branch_key")), normalize_text(flow.get("controlled_property")),
        terminal, continuations,
    ])


def fact_identity_key(fact):
    location = normalize_location(fact.get("location"))
    identity = location or normalize_text(fact.get("body"))
    return canonical_json([fact.get("type"), identity])


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


def load_pattern_cards(capability_profiles):
    pattern_ids = sorted({
        pattern_id
        for capability in capability_profiles
        for pattern_id in capability.get("pattern_ids", [])
    })
    cards = []
    for pattern_id in pattern_ids:
        path = PATTERNS_DIR / f"{pattern_id}.md"
        if not path.is_file():
            raise ValueError(f"missing_pattern_card:{pattern_id}")
        cards.append({
            "pattern_id": pattern_id,
            "content": path.read_text(encoding="utf-8"),
        })
    return cards


def profiles_for_entry(entry_type, capabilities):
    return sorted(
        row["capability_id"] for row in capabilities
        if entry_type in row.get("entry_types", [])
    )
