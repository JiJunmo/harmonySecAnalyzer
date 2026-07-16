#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
审计流水线状态机(确定性,防偷懒)。CLI 接口,harmony-auditor 通过 bash 调用。

命令:
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py new-run <reports_root> --target-repo R [--scope S]
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py init <run_dir> [--target-repo R] [--scope S]
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py compile-matrix <run_dir>
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py enqueue-entries <run_dir>
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py enqueue <run_dir> --tasks '<JSON>'
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py next <run_dir>
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py complete <run_dir> --task <task_id>
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py retry <run_dir> --task <task_id> [--force]
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py validate-coverage <run_dir>
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py validate-ready <run_dir>
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py finalize <run_dir>
  python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py status <run_dir>

输出 JSON。harmony-auditor 解析输出推进 worker-pool + streaming pipeline 调度。
"""
import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback for future portability.
    fcntl = None


MAX_RUNNING = 5
MAX_ATTEMPTS = 3
ROUTES_PATH = Path(__file__).resolve().parent.parent / "config" / "attack_matrix_routes.json"

ENTRY_TYPE_ALIASES = {
    "exported_component": "exported_ability",
}

PATH_TERMINAL_STATES = {"candidate", "rejected", "no_path", "analysis_gap"}


def now():
    return datetime.now().isoformat()


def path_slug(value, fallback):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return slug[:64] or fallback


def project_key(target_repo):
    canonical = str(Path(target_repo).expanduser().resolve())
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
    return f"{path_slug(Path(canonical).name, 'project')}-{digest}"


def P(run):
    return {
        "session": os.path.join(run, "session.json"),
        "queue": os.path.join(run, "queue.jsonl"),
        "events": os.path.join(run, "task_events.jsonl"),
        "candidateIndex": os.path.join(run, "candidate_index.json"),
        "lock": os.path.join(run, ".lock"),
        "projectModel": os.path.join(run, "project", "project_model.json"),
        "discoveryPlan": os.path.join(run, "atlas", "discovery_plan.json"),
        "queryEvidence": os.path.join(run, "atlas", "query_evidence.jsonl"),
        "entryList": os.path.join(run, "atlas", "entry_list.json"),
        "dangerSeedList": os.path.join(run, "atlas", "danger_seed_list.json"),
        "normalizedSeeds": os.path.join(run, "analysis", "danger_seeds.json"),
        "attackMatrix": os.path.join(run, "analysis", "attack_matrix.json"),
        "tasksDir": os.path.join(run, "tasks"),
        "candidates": os.path.join(run, "paths", "candidates.jsonl"),
        "rejected": os.path.join(run, "paths", "rejected.jsonl"),
        "noPath": os.path.join(run, "paths", "no_path.jsonl"),
        "analysisGaps": os.path.join(run, "paths", "analysis_gaps.jsonl"),
        "confirmed": os.path.join(run, "validation", "confirmed.jsonl"),
        "residual": os.path.join(run, "validation", "residual.jsonl"),
        "protected": os.path.join(run, "validation", "protected_exposure.jsonl"),
        "benign": os.path.join(run, "validation", "benign_business_flow.jsonl"),
        "insufficient": os.path.join(run, "validation", "insufficient_evidence.jsonl"),
        "findings": os.path.join(run, "findings.json"),
        "report": os.path.join(run, "report.md"),
    }


VALIDATION_CLASSES = {
    "confirmed_vulnerability": "confirmed",
    "confirmed": "confirmed",
    "vulnerability": "confirmed",
    "protected_exposure": "protected",
    "protected": "protected",
    "residual_risk": "residual",
    "residual": "residual",
    "benign_business_flow": "benign",
    "benign": "benign",
    "insufficient_evidence": "insufficient",
    "insufficient": "insufficient",
    "unknown": "insufficient",
}


def normalize_validation_class(value):
    cls = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if cls in VALIDATION_CLASSES:
        return VALIDATION_CLASSES[cls]
    if "confirmed" in cls or "vulnerability" in cls:
        return "confirmed"
    if "protected" in cls:
        return "protected"
    if "benign" in cls or "business" in cls:
        return "benign"
    if "insufficient" in cls or "unknown" in cls:
        return "insufficient"
    return "residual"


@contextlib.contextmanager
def run_lock(run_dir):
    os.makedirs(run_dir, exist_ok=True)
    lock_path = P(run_dir)["lock"]
    with open(lock_path, "a+", encoding="utf-8") as lock_file:
        if fcntl:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def atomic_write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows


def write_jsonl(path, rows):
    text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    atomic_write_text(path, text)


def append_jsonl(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def write_json(path, obj):
    atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def read_json(path, default=None):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def append_event(run_dir, event, **fields):
    append_jsonl(P(run_dir)["events"], {"ts": now(), "event": event, **fields})


def empty_session(args):
    return {
        "run_id": os.path.basename(args.run_dir),
        "project_key": getattr(args, "project_key", ""),
        "run_dir": str(Path(args.run_dir).resolve()),
        "target_repo": args.target_repo or "",
        "scope": args.scope or "",
        "created_at": now(),
        "status": "initialized",
        "stats": {
            "total": 0,
            "done": 0,
            "failed": 0,
            "candidates": 0,
            "rejected": 0,
            "no_path": 0,
            "confirmed": 0,
            "protected": 0,
            "residual": 0,
            "benign": 0,
            "insufficient": 0,
        },
    }


def empty_candidate_index():
    return {"next_candidate_no": 1, "fingerprints": {}, "candidates": {}}


def task_id_for(t):
    if t["kind"] == "path_finding":
        if t.get("work_item_id"):
            return f"path-{t['work_item_id']}"
        return f"path-{t['entry_id']}"
    return f"val-{t['candidate_id']}"


def task_agent_for(kind):
    return "path-finder" if kind == "path_finding" else "path-validator"


def make_task(t):
    task_id = task_id_for(t)
    return {
        "task_id": task_id,
        "kind": t["kind"],
        "work_item_id": t.get("work_item_id"),
        "entry_id": t.get("entry_id"),
        "seed_id": t.get("seed_id"),
        "seed_key": t.get("seed_key"),
        "pattern": t.get("pattern"),
        "domain": t.get("domain"),
        "candidate_id": t.get("candidate_id"),
        "status": "queued",
        "assigned_agent": task_agent_for(t["kind"]),
        "attempts": 0,
        "created_at": now(),
        "started_at": None,
        "completed_at": None,
        "result_file": f"tasks/{task_id}.result.json",
        "classification": None,
        "error": None,
        "last_error": None,
        "retry_history": [],
    }


def enqueue_tasks(run_dir, tasks):
    p = P(run_dir)
    queue = read_jsonl(p["queue"])
    existing = {q.get("task_id") for q in queue}
    added = 0
    added_tasks = []
    for t in tasks:
        task_id = task_id_for(t)
        if task_id in existing:
            continue
        task = make_task(t)
        queue.append(task)
        existing.add(task_id)
        added += 1
        added_tasks.append(task_id)
        append_event(run_dir, "enqueue", task_id=task_id, kind=t["kind"])
    write_jsonl(p["queue"], queue)
    session = read_json(p["session"], {})
    if session:
        session["status"] = "running"
        session.setdefault("stats", {})["total"] = len(queue)
        write_json(p["session"], session)
    return {"added": added, "total": len(queue), "task_ids": added_tasks}


def load_entries(run_dir):
    raw = read_json(P(run_dir)["entryList"], [])
    return raw if isinstance(raw, list) else raw.get("entry_list", [])


def execution_entry_key(entry):
    identity = (
        entry.get("component_id") or entry.get("ability") or entry.get("analysis_unit_id"),
        entry.get("entry_function"),
        entry.get("entry_function_file"),
    )
    if not all(identity):
        return ("unmergeable", entry.get("entry_id"))
    return identity


def unique_values(values):
    seen = set()
    result = []
    for value in values:
        marker = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def stable_key(prefix, parts):
    canonical = json.dumps(list(parts), ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def normalize_entry_type(value):
    value = str(value or "").strip().lower()
    return ENTRY_TYPE_ALIASES.get(value, value)


def normalize_execution_entries(run_dir):
    p = P(run_dir)
    entry_doc = read_json(p["entryList"], {})
    if isinstance(entry_doc, list):
        entry_doc = {"entry_list": entry_doc}
    if not isinstance(entry_doc, dict):
        return {"ok": False, "error": "entry_list_missing_or_invalid"}

    groups = {}
    order = []
    for entry in entry_doc.get("entry_list", []):
        if not isinstance(entry, dict) or not entry.get("entry_id"):
            continue
        key = execution_entry_key(entry)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(entry)

    normalized = []
    alias_map = {}
    for key in order:
        rows = groups[key]
        canonical = dict(rows[0])
        canonical_id = canonical["entry_id"]
        aliases = [row["entry_id"] for row in rows]
        for alias in aliases:
            alias_map[alias] = canonical_id

        trigger_variants = []
        for row in rows:
            existing = row.get("trigger_variants")
            if isinstance(existing, list) and existing:
                trigger_variants.extend(existing)
            else:
                trigger_variants.append({
                    "source_entry_id": row["entry_id"],
                    "type": row.get("type"),
                    "project_candidate_ids": row.get("project_candidate_ids", []),
                    "reachable_condition": row.get("reachable_condition"),
                    "trigger": row.get("trigger"),
                    "external_input": row.get("external_input"),
                })

        canonical["normalized"] = True
        canonical["entry_key"] = stable_key("entry", key)
        canonical["entry_aliases"] = aliases
        canonical["entry_types"] = sorted({
            normalize_entry_type(entry_type)
            for row in rows
            for entry_type in (
                [row.get("type")]
                + [variant.get("type") for variant in row.get("trigger_variants", []) if isinstance(variant, dict)]
            )
            if entry_type
        })
        project_candidate_ids = set()
        for row in rows:
            project_candidate_ids.update(row.get("project_candidate_ids", []))
            if row.get("project_candidate_id"):
                project_candidate_ids.add(row["project_candidate_id"])
            for variant in row.get("trigger_variants", []):
                if not isinstance(variant, dict):
                    continue
                project_candidate_ids.update(variant.get("project_candidate_ids", []))
                if variant.get("project_candidate_id"):
                    project_candidate_ids.add(variant["project_candidate_id"])
        canonical["project_candidate_ids"] = sorted(project_candidate_ids)
        canonical["atlas_query_ids"] = sorted({
            query_id
            for row in rows
            for query_id in row.get("atlas_query_ids", [])
        })
        canonical["trigger_variants"] = unique_values(trigger_variants)
        canonical["reachable_conditions"] = unique_values([
            row.get("reachable_condition") for row in rows if row.get("reachable_condition")
        ])
        canonical["external_inputs"] = unique_values([
            row.get("external_input") for row in rows if row.get("external_input")
        ])
        normalized.append(canonical)

    entry_doc["entry_list"] = normalized
    entry_doc["normalization"] = {
        "strategy": "execution_symbol",
        "before": sum(len(rows) for rows in groups.values()),
        "after": len(normalized),
        "alias_map": alias_map,
    }
    write_json(p["entryList"], entry_doc)

    plan = read_json(p["discoveryPlan"])
    if isinstance(plan, dict):
        for unit in plan.get("units", []):
            if isinstance(unit, dict) and isinstance(unit.get("entry_ids"), list):
                unit["entry_ids"] = unique_values([
                    alias_map.get(entry_id, entry_id) for entry_id in unit["entry_ids"]
                ])
        write_json(p["discoveryPlan"], plan)

    return {
        "ok": True,
        "before": entry_doc["normalization"]["before"],
        "after": len(normalized),
        "entry_ids": [entry["entry_id"] for entry in normalized],
        "alias_map": alias_map,
    }


def load_raw_seeds(run_dir):
    raw = read_json(P(run_dir)["dangerSeedList"], {})
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return raw.get("danger_seed_list", [])
    return []


def danger_seed_identity(seed):
    category = str(seed.get("category") or "unknown").strip().lower()
    symbol = str(seed.get("symbol") or seed.get("call") or "").strip()
    symbol_file = str(seed.get("symbol_file") or "").strip()
    location = str(seed.get("location") or "").strip()
    sink_parameter = str(seed.get("sink_parameter") or seed.get("sensitive_argument") or "").strip()
    if not symbol and not location:
        return ("unmergeable", seed.get("seed_id"))
    return (category, symbol, symbol_file, location, sink_parameter)


def normalize_danger_seeds(run_dir):
    p = P(run_dir)
    raw_seeds = load_raw_seeds(run_dir)
    groups = {}
    order = []
    invalid = []
    for seed in raw_seeds:
        if not isinstance(seed, dict) or not seed.get("seed_id"):
            invalid.append(seed)
            continue
        key = danger_seed_identity(seed)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(seed)

    normalized = []
    alias_map = {}

    def merged_values(rows, plural_key, singular_key):
        values = set()
        for row in rows:
            plural = row.get(plural_key, [])
            if isinstance(plural, list):
                values.update(value for value in plural if value)
            singular = row.get(singular_key)
            if singular:
                values.add(singular)
        return sorted(values)

    for key in order:
        rows = groups[key]
        canonical = dict(rows[0])
        seed_id = canonical["seed_id"]
        aliases = [row["seed_id"] for row in rows]
        for alias in aliases:
            alias_map[alias] = seed_id
        canonical["normalized"] = True
        canonical["seed_key"] = stable_key("seed", key)
        canonical["seed_aliases"] = aliases
        canonical["category"] = str(canonical.get("category") or "unknown").strip().lower()
        roles = {row.get("sink_role") or "terminal" for row in rows}
        canonical["sink_role"] = (
            "terminal" if "terminal" in roles
            else "unknown" if "unknown" in roles
            else "intermediate"
        )
        canonical["tags"] = sorted({
            str(tag).strip().lower()
            for row in rows
            for tag in row.get("tags", [])
            if str(tag).strip()
        })
        canonical["atlas_query_ids"] = sorted({
            query_id
            for row in rows
            for query_id in row.get("atlas_query_ids", [])
            if query_id
        })
        canonical["discovered_from_units"] = merged_values(
            rows, "discovered_from_units", "discovered_from_unit"
        )
        canonical["reachable_from_units"] = merged_values(
            rows, "reachable_from_units", "reachable_from_unit"
        )
        normalized.append(canonical)

    document = {
        "schema_version": 1,
        "source": "atlas/danger_seed_list.json",
        "danger_seeds": normalized,
        "normalization": {
            "strategy": "sink_symbol_location_parameter",
            "before": len(raw_seeds),
            "after": len(normalized),
            "alias_map": alias_map,
            "invalid_count": len(invalid),
        },
    }
    write_json(p["normalizedSeeds"], document)
    return {
        "ok": not invalid,
        "before": len(raw_seeds),
        "after": len(normalized),
        "seed_ids": [seed["seed_id"] for seed in normalized],
        "alias_map": alias_map,
        "invalid_count": len(invalid),
    }


def route_matches(route, entry, seed):
    entry_types = set(entry.get("entry_types", []))
    if not entry_types:
        entry_types = {normalize_entry_type(entry.get("type"))}
    if not entry_types.intersection(route.get("entry_types", [])):
        return False
    if seed.get("category") not in route.get("seed_categories", []):
        return False
    required_tags = set(route.get("seed_tags_any", []))
    if required_tags and not required_tags.intersection(seed.get("tags", [])):
        return False
    return seed.get("sink_role", "terminal") != "intermediate"


def seed_relevant_to_entry(entry, seed):
    entry_unit = entry.get("analysis_unit_id")
    seed_units = set(seed.get("discovered_from_units", []))
    seed_units.update(seed.get("reachable_from_units", []))
    if not entry_unit or not seed_units:
        return True
    return entry_unit in seed_units


def load_matrix_routes():
    config = read_json(str(ROUTES_PATH))
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        return None
    routes = config.get("routes")
    return routes if isinstance(routes, list) else None


def compile_attack_matrix(run_dir):
    p = P(run_dir)
    entries = load_entries(run_dir)
    seed_doc = read_json(p["normalizedSeeds"], {})
    seeds = seed_doc.get("danger_seeds", []) if isinstance(seed_doc, dict) else []
    routes = load_matrix_routes()
    if routes is None:
        return {"ok": False, "error": "attack_matrix_routes_missing_or_invalid", "path": str(ROUTES_PATH)}

    work_items = []
    work_item_ids = set()
    routing_gaps = []
    entry_work_counts = {entry.get("entry_id"): 0 for entry in entries}
    seed_work_counts = {seed.get("seed_id"): 0 for seed in seeds}
    gap_keys = set()
    prefiltered_pairs = 0

    for entry in entries:
        for seed in seeds:
            if seed.get("sink_role") == "intermediate":
                continue
            if not seed_relevant_to_entry(entry, seed):
                prefiltered_pairs += 1
                continue
            matching = [route for route in routes if route_matches(route, entry, seed)]
            enabled = [route for route in matching if route.get("enabled") is True]
            disabled = [route for route in matching if route.get("enabled") is not True]
            for route in enabled:
                identity = (entry.get("entry_key"), seed.get("seed_key"), route.get("pattern_id"))
                work_item_id = "AW-" + stable_key("work", identity).split(":", 1)[1]
                if work_item_id in work_item_ids:
                    continue
                work_item_ids.add(work_item_id)
                work_items.append({
                    "work_item_id": work_item_id,
                    "entry_id": entry.get("entry_id"),
                    "entry_key": entry.get("entry_key"),
                    "seed_id": seed.get("seed_id"),
                    "seed_key": seed.get("seed_key"),
                    "pattern": route.get("pattern_id"),
                    "domain": route.get("domain"),
                    "status": "planned",
                    "task_id": f"path-{work_item_id}",
                    "result_ref": None,
                })
                entry_work_counts[entry.get("entry_id")] += 1
                seed_work_counts[seed.get("seed_id")] += 1
            if not enabled:
                for route in disabled:
                    gap_key = (entry.get("entry_id"), seed.get("seed_id"), route.get("pattern_id"))
                    if gap_key in gap_keys:
                        continue
                    gap_keys.add(gap_key)
                    routing_gaps.append({
                        "entry_id": entry.get("entry_id"),
                        "seed_id": seed.get("seed_id"),
                        "seed_key": seed.get("seed_key"),
                        "pattern": route.get("pattern_id"),
                        "domain": route.get("domain"),
                        "reason": route.get("gap_reason") or "route_disabled",
                    })

    for seed in seeds:
        seed_id = seed.get("seed_id")
        if seed.get("sink_role") == "intermediate":
            continue
        if seed_work_counts.get(seed_id, 0) == 0 and not any(gap.get("seed_id") == seed_id for gap in routing_gaps):
            routing_gaps.append({
                "entry_id": None,
                "seed_id": seed_id,
                "seed_key": seed.get("seed_key"),
                "pattern": None,
                "domain": seed.get("category"),
                "reason": "no_compatible_pattern_route",
            })

    matrix = {
        "schema_version": 1,
        "matrix_type": "sparse_entry_sink_pattern",
        "generated_at": now(),
        "routing_config": str(ROUTES_PATH),
        "entries": [
            {
                "entry_id": entry.get("entry_id"),
                "entry_key": entry.get("entry_key"),
                "work_item_count": entry_work_counts.get(entry.get("entry_id"), 0),
                "disposition": "planned" if entry_work_counts.get(entry.get("entry_id"), 0) else "no_applicable_route",
            }
            for entry in entries
        ],
        "seeds": [
            {
                "seed_id": seed.get("seed_id"),
                "seed_key": seed.get("seed_key"),
                "sink_role": seed.get("sink_role"),
                "work_item_count": seed_work_counts.get(seed.get("seed_id"), 0),
                "disposition": (
                    "excluded_intermediate"
                    if seed.get("sink_role") == "intermediate"
                    else "planned" if seed_work_counts.get(seed.get("seed_id"), 0) else "routing_gap"
                ),
            }
            for seed in seeds
        ],
        "work_items": sorted(work_items, key=lambda row: row["work_item_id"]),
        "routing_gaps": routing_gaps,
        "summary": {
            "entries": len(entries),
            "seeds": len(seeds),
            "work_items": len(work_items),
            "routing_gaps": len(routing_gaps),
            "excluded_intermediate": sum(1 for seed in seeds if seed.get("sink_role") == "intermediate"),
            "prefiltered_pairs": prefiltered_pairs,
        },
    }
    write_json(p["attackMatrix"], matrix)
    return {"ok": True, **matrix["summary"], "work_item_ids": [row["work_item_id"] for row in matrix["work_items"]]}


def project_model_status(model):
    if not isinstance(model, dict):
        return "missing"
    if model.get("schema_version") != 1:
        return "unsupported_schema"
    return model.get("status") or "invalid"


def entry_candidate_coverage(run_dir, project_model):
    expected = {
        row.get("candidate_id") for row in project_model.get("entry_candidates", [])
        if isinstance(row, dict) and row.get("candidate_id")
    }
    entry_doc = read_json(P(run_dir)["entryList"], {})
    if isinstance(entry_doc, list):
        entry_doc = {"entry_list": entry_doc}
    if not isinstance(entry_doc, dict):
        return {
            "expected": len(expected), "accounted": 0,
            "unaccounted": sorted(expected), "unresolved": [],
            "atlas_gaps": [], "conflicts": [], "unknown": [],
        }

    assignments = {}

    def assign(candidate_ids, disposition):
        for candidate_id in candidate_ids:
            if candidate_id:
                assignments.setdefault(candidate_id, set()).add(disposition)

    for entry in entry_doc.get("entry_list", []):
        if not isinstance(entry, dict):
            continue
        ids = set(entry.get("project_candidate_ids", []))
        if entry.get("project_candidate_id"):
            ids.add(entry["project_candidate_id"])
        assign(ids, "entry")

    def row_ids(rows):
        ids = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            ids.update(row.get("project_candidate_ids", []))
            value = row.get("project_candidate_id") or row.get("candidate_id")
            if value:
                ids.add(value)
        return ids

    excluded = row_ids(entry_doc.get("excluded_candidates", []))
    unresolved = row_ids(entry_doc.get("unresolved_candidates", []))
    atlas_gaps = row_ids(entry_doc.get("coverage_gaps", []))
    assign(excluded, "excluded")
    assign(unresolved, "unresolved")
    assign(atlas_gaps, "atlas_gap")
    accounted = set(assignments)
    return {
        "expected": len(expected),
        "accounted": len(expected & accounted),
        "unaccounted": sorted(expected - accounted),
        "unresolved": sorted(expected & unresolved),
        "atlas_gaps": sorted(expected & atlas_gaps),
        "conflicts": sorted(candidate_id for candidate_id, dispositions in assignments.items() if len(dispositions) > 1),
        "unknown": sorted(accounted - expected),
    }


def discovery_plan_coverage(run_dir):
    plan = read_json(P(run_dir)["discoveryPlan"])
    if not isinstance(plan, dict):
        return {"status": "missing", "total": 0, "by_status": {}, "blocking_units": ["<missing>"], "atlas_gaps": [], "ready": False}
    if plan.get("schema_version") != 1:
        return {"status": "unsupported_schema", "total": 0, "by_status": {}, "blocking_units": ["<unsupported_schema>"], "atlas_gaps": [], "ready": False}
    units = [unit for unit in plan.get("units", []) if isinstance(unit, dict)]
    by_status = {}
    blocking = []
    atlas_gaps = []
    terminal = {"completed", "excluded", "atlas_gap"}
    for unit in units:
        status = unit.get("status") or "invalid"
        by_status[status] = by_status.get(status, 0) + 1
        unit_id = unit.get("unit_id") or "<missing_unit_id>"
        if status not in terminal:
            blocking.append(unit_id)
        if status == "atlas_gap":
            atlas_gaps.append(unit_id)
    return {
        "status": "complete" if not blocking else "incomplete",
        "total": len(units),
        "by_status": by_status,
        "blocking_units": sorted(blocking),
        "atlas_gaps": sorted(atlas_gaps),
        "ready": not blocking,
    }


def attack_matrix_coverage(run_dir):
    matrix = read_json(P(run_dir)["attackMatrix"])
    if not isinstance(matrix, dict):
        return {
            "status": "missing", "total": 0, "by_status": {},
            "blocking_work_items": ["<missing>"], "routing_gaps": [], "ready": False,
        }
    if matrix.get("schema_version") != 1:
        return {
            "status": "unsupported_schema", "total": 0, "by_status": {},
            "blocking_work_items": ["<unsupported_schema>"], "routing_gaps": [], "ready": False,
        }
    by_status = {}
    blocking = []
    for item in matrix.get("work_items", []):
        status = item.get("status") or "invalid"
        by_status[status] = by_status.get(status, 0) + 1
        if status not in PATH_TERMINAL_STATES:
            blocking.append(item.get("work_item_id") or "<missing_work_item_id>")
    gaps = matrix.get("routing_gaps", [])
    expected_entries = {entry.get("entry_id") for entry in load_entries(run_dir) if entry.get("entry_id")}
    matrix_entries = {entry.get("entry_id") for entry in matrix.get("entries", []) if entry.get("entry_id")}
    seed_doc = read_json(P(run_dir)["normalizedSeeds"], {})
    expected_seeds = {
        seed.get("seed_id") for seed in seed_doc.get("danger_seeds", []) if seed.get("seed_id")
    } if isinstance(seed_doc, dict) else set()
    matrix_seeds = {seed.get("seed_id") for seed in matrix.get("seeds", []) if seed.get("seed_id")}
    missing_entries = sorted(expected_entries - matrix_entries)
    unknown_entries = sorted(matrix_entries - expected_entries)
    missing_seeds = sorted(expected_seeds - matrix_seeds)
    unknown_seeds = sorted(matrix_seeds - expected_seeds)
    ready = not blocking and not missing_entries and not unknown_entries and not missing_seeds and not unknown_seeds
    return {
        "status": "complete" if ready else "incomplete",
        "total": len(matrix.get("work_items", [])),
        "by_status": by_status,
        "blocking_work_items": sorted(blocking),
        "routing_gaps": gaps,
        "missing_entries": missing_entries,
        "unknown_entries": unknown_entries,
        "missing_seeds": missing_seeds,
        "unknown_seeds": unknown_seeds,
        "ready": ready,
    }


def update_matrix_work_item(run_dir, work_item_id, status, result_ref=None):
    if not work_item_id:
        return False
    p = P(run_dir)
    matrix = read_json(p["attackMatrix"])
    if not isinstance(matrix, dict):
        return False
    item = next((row for row in matrix.get("work_items", []) if row.get("work_item_id") == work_item_id), None)
    if not item:
        return False
    item["status"] = status
    if result_ref is not None:
        item["result_ref"] = result_ref
    write_json(p["attackMatrix"], matrix)
    return True


def make_candidate_fingerprint(conclusion):
    return "|".join([
        str(conclusion.get("seed_key") or conclusion.get("seed_id") or ""),
        str(conclusion.get("pattern") or ""),
    ])


def candidate_admission(conclusion):
    admission = conclusion.get("admission")
    required = (
        "external_entry_reachable",
        "seed_reachable",
        "attacker_influence",
        "end_to_end_sink",
        "attacker_control_preserved",
    )
    if not isinstance(admission, dict):
        return False, ["missing_admission"]
    failed = [key for key in required if admission.get(key) is not True]
    return not failed, failed


def allocate_candidate(index):
    candidate_id = f"CAND-{index.get('next_candidate_no', 1):03d}"
    index["next_candidate_no"] = index.get("next_candidate_no", 1) + 1
    return candidate_id


def candidate_path_variant(task, conclusion):
    return {
        "work_item_id": task.get("work_item_id"),
        "entry_id": task.get("entry_id"),
        "source_task_id": task.get("task_id"),
        "path": conclusion.get("path", []),
        "taint_flow": conclusion.get("taint_flow", ""),
        "admission": conclusion.get("admission", {}),
        "atlas_evidence": conclusion.get("atlas_evidence", {}),
    }


def promote_candidate(run_dir, queue, task, conclusion, index):
    p = P(run_dir)
    entry_id = task.get("entry_id")
    fingerprint = make_candidate_fingerprint(conclusion)
    existing_id = index.setdefault("fingerprints", {}).get(fingerprint)
    if existing_id:
        existing = index.setdefault("candidates", {}).setdefault(existing_id, {})
        existing["entry_ids"] = sorted(set(existing.get("entry_ids", []) + [entry_id]))
        existing["source_task_ids"] = sorted(set(existing.get("source_task_ids", []) + [task["task_id"]]))
        rows = read_jsonl(p["candidates"])
        for row in rows:
            if row.get("candidate_id") == existing_id:
                row["entry_ids"] = existing["entry_ids"]
                row["source_task_ids"] = existing["source_task_ids"]
                variants = row.setdefault("path_variants", [])
                if not any(variant.get("source_task_id") == task["task_id"] for variant in variants):
                    variants.append(candidate_path_variant(task, conclusion))
        write_jsonl(p["candidates"], rows)
        append_event(run_dir, "candidate_duplicate", candidate_id=existing_id, fingerprint=fingerprint, task_id=task["task_id"])
        return None

    candidate_id = allocate_candidate(index)
    validation_task_id = f"val-{candidate_id}"
    candidate = {
        **conclusion,
        "candidate_id": candidate_id,
        "fingerprint": fingerprint,
        "task_id": task["task_id"],
        "entry_id": entry_id,
        "entry_ids": [entry_id],
        "source_task_ids": [task["task_id"]],
        "path_variants": [candidate_path_variant(task, conclusion)],
    }
    append_jsonl(p["candidates"], candidate)
    index["fingerprints"][fingerprint] = candidate_id
    index.setdefault("candidates", {})[candidate_id] = {
        "fingerprint": fingerprint,
        "entry_id": entry_id,
        "entry_ids": [entry_id],
        "source_task_ids": [task["task_id"]],
        "seed_id": conclusion.get("seed_id"),
        "seed_key": conclusion.get("seed_key"),
        "pattern": conclusion.get("pattern"),
        "created_from_task": task["task_id"],
        "validation_task_id": validation_task_id,
    }

    if not any(q.get("task_id") == validation_task_id for q in queue):
        queue.append(make_task({"kind": "path_validation", "candidate_id": candidate_id}))
        append_event(run_dir, "enqueue", task_id=validation_task_id, kind="path_validation", candidate_id=candidate_id)
    append_event(run_dir, "promote_candidate", candidate_id=candidate_id, fingerprint=fingerprint, task_id=validation_task_id)
    return candidate_id


def cmd_init(args):
    p = P(args.run_dir)
    existing = []
    if os.path.isdir(args.run_dir):
        existing = sorted(name for name in os.listdir(args.run_dir) if name != ".lock")
    if existing:
        return {
            "ok": False,
            "error": "run_dir_not_empty",
            "run_dir": str(Path(args.run_dir).resolve()),
            "existing": existing,
        }
    dirs = [
        args.run_dir,
        os.path.dirname(p["projectModel"]),
        os.path.dirname(p["entryList"]),
        os.path.dirname(p["attackMatrix"]),
        p["tasksDir"],
        os.path.dirname(p["candidates"]),
        os.path.dirname(p["confirmed"]),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    write_json(p["session"], empty_session(args))
    write_json(p["candidateIndex"], empty_candidate_index())
    for f in [
        p["queue"], p["events"], p["queryEvidence"], p["candidates"], p["rejected"], p["noPath"],
        p["analysisGaps"],
        p["confirmed"], p["residual"], p["protected"], p["benign"], p["insufficient"],
    ]:
        if not os.path.exists(f):
            atomic_write_text(f, "")
    append_event(args.run_dir, "init", target_repo=args.target_repo or "", scope=args.scope or "")
    return {"ok": True, "run_dir": str(Path(args.run_dir).resolve()), "run_id": os.path.basename(args.run_dir)}


def cmd_new_run(args):
    reports_root = Path(args.reports_root).expanduser().resolve()
    repo = str(Path(args.target_repo).expanduser().resolve())
    key = project_key(repo)
    project_dir = reports_root / key
    project_dir.mkdir(parents=True, exist_ok=True)
    scope = path_slug(args.scope or "full", "full")

    for _ in range(10):
        run_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{scope}-{uuid.uuid4().hex[:8]}"
        run_dir = project_dir / run_id
        try:
            run_dir.mkdir()
        except FileExistsError:
            continue
        init_args = argparse.Namespace(
            run_dir=str(run_dir),
            target_repo=repo,
            scope=args.scope or "full",
            project_key=key,
        )
        with run_lock(str(run_dir)):
            result = cmd_init(init_args)
        return {**result, "project_key": key, "reports_root": str(reports_root)}
    return {"ok": False, "error": "unable_to_allocate_unique_run", "project_key": key}


def cmd_enqueue(args):
    result = enqueue_tasks(args.run_dir, args.tasks)
    return {"ok": True, **result}


def cmd_compile_matrix(args):
    p = P(args.run_dir)
    existing = read_json(p["attackMatrix"])
    if isinstance(existing, dict):
        return {
            "ok": True,
            "mode": "already_compiled",
            "matrix": existing.get("summary", {}),
            "added": 0,
            "total": len(read_jsonl(p["queue"])),
            "task_ids": [],
        }
    normalization = normalize_execution_entries(args.run_dir)
    if not normalization.get("ok"):
        return normalization
    seed_normalization = normalize_danger_seeds(args.run_dir)
    if not seed_normalization.get("ok"):
        return {"ok": False, "error": "danger_seed_list_contains_invalid_rows", "normalization": seed_normalization}
    matrix_result = compile_attack_matrix(args.run_dir)
    if not matrix_result.get("ok"):
        return matrix_result
    matrix = read_json(p["attackMatrix"], {})
    tasks = [
        {
            "kind": "path_finding",
            "work_item_id": item["work_item_id"],
            "entry_id": item["entry_id"],
            "seed_id": item["seed_id"],
            "seed_key": item["seed_key"],
            "pattern": item["pattern"],
            "domain": item["domain"],
        }
        for item in matrix.get("work_items", [])
    ]
    queued = enqueue_tasks(args.run_dir, tasks)
    for item in matrix.get("work_items", []):
        item["status"] = "queued"
    write_json(p["attackMatrix"], matrix)
    append_event(
        args.run_dir,
        "compile_attack_matrix",
        work_items=matrix_result["work_items"],
        routing_gaps=matrix_result["routing_gaps"],
    )
    return {
        "ok": True,
        "entry_normalization": normalization,
        "seed_normalization": seed_normalization,
        "matrix": matrix_result,
        **queued,
    }


def cmd_enqueue_entries(args):
    result = cmd_compile_matrix(args)
    result.setdefault("compatibility_note", "enqueue-entries now compiles the sparse attack matrix")
    return result


def cmd_next(args):
    p = P(args.run_dir)
    queue = read_jsonl(p["queue"])
    running = sum(1 for q in queue if q.get("status") == "running")
    if running >= MAX_RUNNING:
        return {"ok": True, "task": None, "reason": "worker_pool_full", "running": running}
    for q in queue:
        if q.get("status") == "queued":
            q["status"] = "running"
            q["started_at"] = now()
            q["completed_at"] = None
            q["error"] = None
            q["attempts"] = q.get("attempts", 0) + 1
            write_jsonl(p["queue"], queue)
            update_matrix_work_item(args.run_dir, q.get("work_item_id"), "running")
            append_event(args.run_dir, "start", task_id=q["task_id"], kind=q["kind"], attempt=q["attempts"])
            task = dict(q)
            task["result_path"] = str(Path(args.run_dir, q["result_file"]).resolve())
            return {"ok": True, "task": task, "free_slots": MAX_RUNNING - running - 1}
    return {"ok": True, "task": None, "reason": "no_queued", "running": running}


def archive_invalid_result(result_path, attempt):
    source = Path(result_path)
    if not source.exists():
        return None
    archive = source.with_name(f"{source.stem}.attempt-{attempt}.invalid.json")
    suffix = 1
    while archive.exists():
        archive = source.with_name(f"{source.stem}.attempt-{attempt}.{suffix}.invalid.json")
        suffix += 1
    os.replace(source, archive)
    return str(archive)


def fail_or_retry_task(run_dir, queue, task, error, result_path=None):
    p = P(run_dir)
    attempt = task.get("attempts", 0)
    archived_result = archive_invalid_result(result_path, attempt) if result_path else None
    failure = {
        "attempt": attempt,
        "failed_at": now(),
        "error": error,
        "archived_result": archived_result,
    }
    task.setdefault("retry_history", []).append(failure)
    task["last_error"] = error
    task["classification"] = None

    if attempt < MAX_ATTEMPTS:
        task["status"] = "queued"
        task["started_at"] = None
        task["completed_at"] = None
        task["error"] = None
        write_jsonl(p["queue"], queue)
        update_matrix_work_item(run_dir, task.get("work_item_id"), "queued")
        update_session_stats(run_dir)
        append_event(
            run_dir,
            "retry_scheduled",
            task_id=task["task_id"],
            failed_attempt=attempt,
            next_attempt=attempt + 1,
            max_attempts=MAX_ATTEMPTS,
            error=error,
            archived_result=archived_result,
        )
        return {
            "ok": True,
            "completed": False,
            "retry_scheduled": True,
            "task_id": task["task_id"],
            "failed_attempt": attempt,
            "next_attempt": attempt + 1,
            "max_attempts": MAX_ATTEMPTS,
            "error": error,
            "archived_result": archived_result,
        }

    task["status"] = "failed"
    task["completed_at"] = failure["failed_at"]
    task["error"] = error
    write_jsonl(p["queue"], queue)
    update_matrix_work_item(run_dir, task.get("work_item_id"), "failed", task.get("result_file"))
    update_session_stats(run_dir)
    append_event(
        run_dir,
        "fail",
        task_id=task["task_id"],
        attempt=attempt,
        max_attempts=MAX_ATTEMPTS,
        error=error,
        archived_result=archived_result,
    )
    return {
        "ok": False,
        "completed": False,
        "retry_scheduled": False,
        "task_id": task["task_id"],
        "attempt": attempt,
        "max_attempts": MAX_ATTEMPTS,
        "error": error,
        "archived_result": archived_result,
    }


def cmd_retry(args):
    p = P(args.run_dir)
    queue = read_jsonl(p["queue"])
    task = next((q for q in queue if q.get("task_id") == args.task), None)
    if not task:
        return {"ok": False, "error": "task_not_found", "task_id": args.task}
    if task.get("status") != "failed":
        return {"ok": False, "error": "task_not_failed", "task_id": args.task, "status": task.get("status")}
    if task.get("attempts", 0) >= MAX_ATTEMPTS and not args.force:
        return {
            "ok": False,
            "error": "max_attempts_reached",
            "task_id": args.task,
            "attempts": task.get("attempts", 0),
            "max_attempts": MAX_ATTEMPTS,
        }
    task["status"] = "queued"
    task["started_at"] = None
    task["completed_at"] = None
    task["error"] = None
    write_jsonl(p["queue"], queue)
    update_matrix_work_item(args.run_dir, task.get("work_item_id"), "queued")
    update_session_stats(args.run_dir)
    append_event(
        args.run_dir,
        "manual_retry_scheduled",
        task_id=task["task_id"],
        next_attempt=task.get("attempts", 0) + 1,
        forced=bool(args.force),
    )
    return {
        "ok": True,
        "retry_scheduled": True,
        "task_id": task["task_id"],
        "next_attempt": task.get("attempts", 0) + 1,
        "forced": bool(args.force),
    }


def cmd_complete(args):
    p = P(args.run_dir)
    queue = read_jsonl(p["queue"])
    task = next((q for q in queue if q.get("task_id") == args.task), None)
    if not task:
        return {"ok": False, "error": "task_not_found"}
    if task.get("status") != "running":
        return {
            "ok": False,
            "error": "task_not_running",
            "task_id": task["task_id"],
            "status": task.get("status"),
        }

    result_path = os.path.join(args.run_dir, task["result_file"])
    result = read_json(result_path)
    if result is None:
        return fail_or_retry_task(
            args.run_dir,
            queue,
            task,
            f"missing_or_invalid_result:{task['result_file']}",
            result_path=result_path,
        )

    if task.get("work_item_id"):
        conclusions = result.get("conclusions")
        errors = []
        if result.get("task_id") != task["task_id"]:
            errors.append("task_id_mismatch")
        if result.get("work_item_id") != task["work_item_id"]:
            errors.append("work_item_id_mismatch")
        if result.get("entry_id") != task.get("entry_id"):
            errors.append("entry_id_mismatch")
        if not isinstance(conclusions, list) or len(conclusions) != 1:
            errors.append("exactly_one_conclusion_required")
        else:
            conclusion = conclusions[0]
            if conclusion.get("seed_id") != task.get("seed_id"):
                errors.append("seed_id_mismatch")
            if conclusion.get("pattern") != task.get("pattern"):
                errors.append("pattern_mismatch")
            if conclusion.get("classification") not in PATH_TERMINAL_STATES:
                errors.append("invalid_path_classification")
            conclusion["seed_key"] = task.get("seed_key")
            conclusion["work_item_id"] = task.get("work_item_id")
        if errors:
            return fail_or_retry_task(
                args.run_dir,
                queue,
                task,
                ",".join(errors),
                result_path=result_path,
            )
    elif task.get("kind") == "path_validation":
        errors = []
        if result.get("task_id") != task["task_id"]:
            errors.append("task_id_mismatch")
        if result.get("candidate_id") != task.get("candidate_id"):
            errors.append("candidate_id_mismatch")
        raw_class = str(result.get("classification") or "").strip().lower().replace("-", "_").replace(" ", "_")
        if raw_class not in VALIDATION_CLASSES:
            errors.append("invalid_validation_classification")
        if errors:
            return fail_or_retry_task(
                args.run_dir,
                queue,
                task,
                ",".join(errors),
                result_path=result_path,
            )

    task["status"] = "done"
    task["completed_at"] = now()
    task["error"] = None
    promoted = []
    classification = None

    if task["kind"] == "path_finding":
        index = read_json(p["candidateIndex"], empty_candidate_index())
        any_candidate = False
        path_classifications = []
        for c in result.get("conclusions", []):
            cls = c.get("classification")
            if cls == "candidate":
                admitted, failed_checks = candidate_admission(c)
                if not admitted:
                    cls = "rejected"
                    c["classification"] = cls
                    c["reject_reason"] = "candidate_admission_failed: " + ",".join(failed_checks)
                    append_jsonl(p["rejected"], {
                        "task_id": task["task_id"],
                        "entry_id": task.get("entry_id"),
                        **c,
                    })
                    append_event(
                        args.run_dir,
                        "candidate_admission_rejected",
                        task_id=task["task_id"],
                        seed_id=c.get("seed_id"),
                        failed_checks=failed_checks,
                    )
                    path_classifications.append(cls)
                    continue
                any_candidate = True
                candidate_id = promote_candidate(args.run_dir, queue, task, c, index)
                if candidate_id:
                    promoted.append(candidate_id)
            elif cls == "rejected":
                append_jsonl(p["rejected"], {"task_id": task["task_id"], "entry_id": task.get("entry_id"), **c})
            elif cls == "analysis_gap":
                append_jsonl(p["analysisGaps"], {"task_id": task["task_id"], "entry_id": task.get("entry_id"), **c})
            else:
                append_jsonl(p["noPath"], {"task_id": task["task_id"], "entry_id": task.get("entry_id"), **c})
            path_classifications.append(cls)
        write_json(p["candidateIndex"], index)
        if task.get("work_item_id"):
            classification = path_classifications[0]
            update_matrix_work_item(args.run_dir, task["work_item_id"], classification, task["result_file"])
        else:
            classification = "candidate" if any_candidate else "no_path"
        task["classification"] = classification
    else:
        cls = normalize_validation_class(result.get("classification"))
        classification = cls
        task["classification"] = cls
        target_file = {
            "confirmed": p["confirmed"],
            "protected": p["protected"],
            "residual": p["residual"],
            "benign": p["benign"],
            "insufficient": p["insufficient"],
        }[cls]
        append_jsonl(target_file, {"task_id": task["task_id"], "candidate_id": task.get("candidate_id"), **result})

    write_jsonl(p["queue"], queue)
    update_session_stats(args.run_dir)
    append_event(args.run_dir, "complete", task_id=task["task_id"], kind=task["kind"], classification=classification, promoted=promoted)
    return {"ok": True, "task_id": task["task_id"], "classification": classification, "promoted_candidates": promoted}


def cmd_validate_coverage(args):
    project_model = read_json(P(args.run_dir)["projectModel"])
    model_status = project_model_status(project_model)
    candidate_coverage = entry_candidate_coverage(args.run_dir, project_model) if isinstance(project_model, dict) else {
        "expected": 0, "accounted": 0, "unaccounted": [], "unresolved": [],
        "atlas_gaps": [], "conflicts": [], "unknown": [],
    }
    discovery_coverage = discovery_plan_coverage(args.run_dir)
    matrix_coverage = attack_matrix_coverage(args.run_dir)
    partial = bool(
        discovery_coverage["atlas_gaps"]
        or candidate_coverage["atlas_gaps"]
        or matrix_coverage["routing_gaps"]
        or matrix_coverage["by_status"].get("analysis_gap", 0)
    )
    ready = (
        model_status == "complete"
        and discovery_coverage["ready"]
        and not candidate_coverage["unaccounted"]
        and not candidate_coverage["unresolved"]
        and not candidate_coverage["conflicts"]
        and not candidate_coverage["unknown"]
        and matrix_coverage["ready"]
    )
    return {
        "ok": True,
        "project_model_status": model_status,
        "discovery_plan_coverage": discovery_coverage,
        "entry_candidate_coverage": candidate_coverage,
        "attack_matrix_coverage": matrix_coverage,
        "coverage_status": "partial" if partial else "complete",
        "ready": ready,
    }


def cmd_validate_ready(args):
    p = P(args.run_dir)
    project_model = read_json(p["projectModel"])
    model_status = project_model_status(project_model)
    candidate_coverage = entry_candidate_coverage(args.run_dir, project_model) if isinstance(project_model, dict) else {
        "expected": 0, "accounted": 0, "unaccounted": [], "unresolved": [],
        "atlas_gaps": [], "conflicts": [], "unknown": [],
    }
    discovery_coverage = discovery_plan_coverage(args.run_dir)
    matrix_coverage = attack_matrix_coverage(args.run_dir)
    queue = read_jsonl(p["queue"])
    index = read_json(p["candidateIndex"], empty_candidate_index())
    validation_done = {
        q.get("candidate_id") for q in queue
        if q.get("kind") == "path_validation" and q.get("status") == "done"
    }
    candidates = set(index.get("candidates", {}).keys())
    by_status = queue_stats(queue)
    unvalidated = sorted(c for c in candidates if c not in validation_done)
    ready = model_status == "complete" and discovery_coverage["ready"] and not candidate_coverage["unaccounted"] and not candidate_coverage["unresolved"] and not candidate_coverage["conflicts"] and not candidate_coverage["unknown"] and matrix_coverage["ready"] and not unvalidated and by_status.get("queued", 0) == 0 and by_status.get("running", 0) == 0 and by_status.get("failed", 0) == 0
    partial = bool(
        discovery_coverage["atlas_gaps"]
        or candidate_coverage["atlas_gaps"]
        or matrix_coverage["routing_gaps"]
        or matrix_coverage["by_status"].get("analysis_gap", 0)
    )
    return {
        "ok": True,
        "ready": ready,
        "coverage_status": "partial" if partial else "complete",
        "project_model": {
            "status": model_status,
            "diagnostics": project_model.get("diagnostics", []) if isinstance(project_model, dict) else [],
        },
        "discovery_plan_coverage": discovery_coverage,
        "entry_candidate_coverage": candidate_coverage,
        "attack_matrix_coverage": matrix_coverage,
        "missing_entries": matrix_coverage.get("missing_entries", []),
        "unvalidated_candidates": unvalidated,
        "queue": by_status,
    }


def cmd_finalize(args):
    p = P(args.run_dir)
    session = read_json(p["session"], {})
    if session.get("status") == "completed":
        return {
            "ok": True,
            "status": "completed",
            "completed_at": session.get("completed_at"),
            "mode": "already_finalized",
        }
    readiness = cmd_validate_ready(args)
    if not readiness.get("ready"):
        return {"ok": False, "error": "run_not_ready", "readiness": readiness}
    findings = read_json(p["findings"])
    if not isinstance(findings, dict):
        return {"ok": False, "error": "findings_missing_or_invalid", "path": p["findings"]}
    if not os.path.exists(p["report"]) or not Path(p["report"]).read_text(encoding="utf-8").strip():
        return {"ok": False, "error": "report_missing_or_empty", "path": p["report"]}
    completed_at = now()
    session["status"] = "completed"
    session["completed_at"] = completed_at
    session["coverage_status"] = readiness.get("coverage_status")
    write_json(p["session"], session)
    append_event(args.run_dir, "finalize", coverage_status=readiness.get("coverage_status"))
    return {
        "ok": True,
        "status": "completed",
        "completed_at": completed_at,
        "coverage_status": readiness.get("coverage_status"),
    }


def cmd_dedup_candidates(args):
    # Compatibility command. Streaming promotion already performs incremental dedup.
    index = read_json(P(args.run_dir)["candidateIndex"], empty_candidate_index())
    return {
        "ok": True,
        "mode": "streaming",
        "before": len(index.get("fingerprints", {})),
        "after": len(index.get("fingerprints", {})),
        "note": "dedup is performed during complete(path_finding)",
    }


def cmd_enqueue_validation(args):
    # Compatibility command. Validation tasks are enqueued during complete(path_finding).
    return {
        "ok": True,
        "mode": "streaming",
        "added": 0,
        "note": "validation tasks are enqueued during complete(path_finding)",
    }


def queue_stats(queue):
    by_status = {}
    for q in queue:
        by_status[q.get("status", "unknown")] = by_status.get(q.get("status", "unknown"), 0) + 1
    return by_status


def update_session_stats(run_dir):
    p = P(run_dir)
    session = read_json(p["session"], {})
    if not session:
        return
    queue = read_jsonl(p["queue"])
    stats = session.setdefault("stats", {})
    stats["total"] = len(queue)
    stats["done"] = sum(1 for q in queue if q.get("status") == "done")
    stats["failed"] = sum(1 for q in queue if q.get("status") == "failed")
    stats["candidates"] = len(read_jsonl(p["candidates"]))
    stats["rejected"] = len(read_jsonl(p["rejected"]))
    stats["no_path"] = len(read_jsonl(p["noPath"]))
    stats["analysis_gaps"] = len(read_jsonl(p["analysisGaps"]))
    stats["confirmed"] = len(read_jsonl(p["confirmed"]))
    stats["protected"] = len(read_jsonl(p["protected"]))
    stats["residual"] = len(read_jsonl(p["residual"]))
    stats["benign"] = len(read_jsonl(p["benign"]))
    stats["insufficient"] = len(read_jsonl(p["insufficient"]))
    write_json(p["session"], session)


def cmd_status(args):
    p = P(args.run_dir)
    update_session_stats(args.run_dir)
    session = read_json(p["session"])
    queue = read_jsonl(p["queue"])
    index = read_json(p["candidateIndex"], empty_candidate_index())
    project_model = read_json(p["projectModel"])
    discovery_coverage = discovery_plan_coverage(args.run_dir)
    matrix_coverage = attack_matrix_coverage(args.run_dir)
    return {
        "ok": True,
        "session": session,
        "project_model_status": project_model_status(project_model),
        "discovery_plan_coverage": discovery_coverage,
        "attack_matrix_coverage": matrix_coverage,
        "queue_stats": queue_stats(queue),
        "candidates": len(index.get("candidates", {})),
        "confirmed": len(read_jsonl(p["confirmed"])),
        "protected": len(read_jsonl(p["protected"])),
        "residual": len(read_jsonl(p["residual"])),
        "benign": len(read_jsonl(p["benign"])),
        "insufficient": len(read_jsonl(p["insufficient"])),
    }


def run_with_lock(args, func):
    with run_lock(args.run_dir):
        return func(args)


def main():
    ap = argparse.ArgumentParser(description="审计流水线状态机")
    sub = ap.add_subparsers(dest="command", required=True)

    pnr = sub.add_parser("new-run")
    pnr.add_argument("reports_root")
    pnr.add_argument("--target-repo", required=True)
    pnr.add_argument("--scope", default="full")

    pi = sub.add_parser("init")
    pi.add_argument("run_dir")
    pi.add_argument("--target-repo")
    pi.add_argument("--scope")

    pei = sub.add_parser("enqueue-entries")
    pei.add_argument("run_dir")

    pcm = sub.add_parser("compile-matrix")
    pcm.add_argument("run_dir")

    pe = sub.add_parser("enqueue")
    pe.add_argument("run_dir")
    pe.add_argument("--tasks", required=True, help="tasks JSON")

    pn = sub.add_parser("next")
    pn.add_argument("run_dir")

    pc = sub.add_parser("complete")
    pc.add_argument("run_dir")
    pc.add_argument("--task", required=True)

    pr = sub.add_parser("retry")
    pr.add_argument("run_dir")
    pr.add_argument("--task", required=True)
    pr.add_argument("--force", action="store_true")

    pv = sub.add_parser("validate-coverage")
    pv.add_argument("run_dir")

    pvr = sub.add_parser("validate-ready")
    pvr.add_argument("run_dir")

    pf = sub.add_parser("finalize")
    pf.add_argument("run_dir")

    pd = sub.add_parser("dedup-candidates")
    pd.add_argument("run_dir")

    pev = sub.add_parser("enqueue-validation")
    pev.add_argument("run_dir")

    ps = sub.add_parser("status")
    ps.add_argument("run_dir")

    args = ap.parse_args()
    if args.command == "enqueue":
        args.tasks = json.loads(args.tasks)

    cmds = {
        "new-run": cmd_new_run,
        "init": cmd_init,
        "enqueue-entries": cmd_enqueue_entries,
        "compile-matrix": cmd_compile_matrix,
        "enqueue": cmd_enqueue,
        "next": cmd_next,
        "complete": cmd_complete,
        "retry": cmd_retry,
        "validate-coverage": cmd_validate_coverage,
        "validate-ready": cmd_validate_ready,
        "finalize": cmd_finalize,
        "dedup-candidates": cmd_dedup_candidates,
        "enqueue-validation": cmd_enqueue_validation,
        "status": cmd_status,
    }

    try:
        if args.command == "new-run":
            result = cmd_new_run(args)
        else:
            result = run_with_lock(args, cmds[args.command])
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not result.get("ok", False):
            sys.exit(1)
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()
