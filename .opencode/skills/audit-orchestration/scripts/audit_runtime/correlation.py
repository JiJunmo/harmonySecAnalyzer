"""Deterministically connect component-local semantic results without path tasks."""
from __future__ import annotations

import json
from collections import deque

from .common import (canonical_json, normalize_location, normalize_text, now, operation_group_identity,
                     read_json, stable_id, write_json)
from .store import append_event, enqueue_task, row_json
from .task_context import semantic_group_context, validation_group_fingerprint


MAX_CORRELATION_STATES_PER_ROOT = 2000
PROPAGATING_STATES = {"preserved", "constrained"}
PRINCIPAL_BINDING_RANK = {"preserved": 0, "not_observable": 1, "unknown": 2, "replaced_by_caller": 3}


def _advance_principal_state(state, component_call):
    transition = component_call.get("principal_transition", {})
    prior_binding = state.get("origin_binding", "preserved")
    next_binding = transition.get("origin_binding", "unknown")
    binding = max((prior_binding, next_binding), key=lambda value: PRINCIPAL_BINDING_RANK.get(value, 2))
    security_check_subjects = set(state.get("security_check_subjects", ()))
    security_check_subjects.update(
        security_check.get("subject_kind", "unknown") for security_check in component_call.get("security_checks", [])
    )
    return {
        "origin_binding": binding,
        "authority_used": transition.get("authority_used", "unknown"),
        "observed_principal": transition.get("callee_observed_principal", "unknown"),
        "security_check_subjects": sorted(security_check_subjects),
    }


def _principal_state_key(state):
    return canonical_json(state)


def _entry_records(conn):
    records = {}
    component_entries = {}
    for row in conn.execute("SELECT * FROM entries ORDER BY entry_id"):
        payload = row_json(row, "payload_json", {})
        record = {
            "entry_id": row["entry_id"], "component": row["component"], "symbol": row["symbol"],
            "component_id": payload.get("component_id"), "module_id": payload.get("module_id"),
            "facets": row_json(row, "facets_json", []),
            "root_eligible": payload.get("root_eligible") is True,
        }
        records[row["entry_id"]] = record
        if record["component_id"]:
            component_entries[record["component_id"]] = row["entry_id"]
    return records, component_entries


def _external_roots(conn, entries):
    roots = []
    analyses = {
        row["entry_id"]: row_json(row, "coverage_json", {})
        for row in conn.execute("SELECT entry_id,coverage_json FROM semantic_analyses")
    }
    for entry_id, entry in entries.items():
        if analyses.get(entry_id, {}).get("entry_status") != "confirmed":
            continue
        if entry["root_eligible"]:
            roots.append(entry_id)
    return sorted(roots)


def enqueue_component_call_targets(conn, project_model):
    """Expand only components reached by a control-preserving component_call."""
    component_entries = {}
    for row in conn.execute("SELECT entry_id,payload_json FROM entries ORDER BY entry_id"):
        component_id = row_json(row, "payload_json", {}).get("component_id")
        if component_id:
            component_entries[component_id] = row["entry_id"]
    existing = {
        row["subject_id"] for row in conn.execute(
            "SELECT subject_id FROM tasks WHERE kind='component_semantic_analysis'"
        )
    }
    discovered = {}
    for row in conn.execute("SELECT * FROM component_calls ORDER BY call_id"):
        mappings = row_json(row, "parameter_mappings_json", [])
        if not any(mapping.get("control_state") in PROPAGATING_STATES for mapping in mappings):
            continue
        target_entry_id = component_entries.get(row["target_component_id"])
        if target_entry_id and target_entry_id not in existing:
            discovered.setdefault(target_entry_id, []).append(row["call_id"])
    task_ids = []
    for entry_id, call_ids in sorted(discovered.items()):
        task_ids.append(enqueue_task(
            conn, f"component-semantics:{entry_id}", "component_semantic_analysis", entry_id,
            {"project_model": str(project_model), "discovered_from_component_calls": sorted(call_ids)},
        ))
    if task_ids:
        append_event(conn, "component_scope_expanded", None, {
            "semantic_tasks_created": len(task_ids), "task_ids": task_ids,
        })
    return task_ids


def _component_calls(conn, component_entries):
    adjacency = {}
    unresolved = []
    for row in conn.execute("SELECT * FROM component_calls ORDER BY source_entry_id,call_id"):
        payload = row_json(row, "payload_json", {})
        payload.update({
            "call_id": row["call_id"], "source_entry_id": row["source_entry_id"],
            "target_entry_id": component_entries.get(row["target_component_id"]),
            "target_component_id": row["target_component_id"],
            "parameter_mappings": row_json(row, "parameter_mappings_json", []),
            "security_checks": row_json(row, "security_checks_json", []),
            "evidence_refs": row_json(row, "evidence_json", []),
        })
        if not payload["target_entry_id"]:
            unresolved.append({
                "type": "target_component_not_in_analysis_scope",
                "call_id": row["call_id"], "target_component_id": row["target_component_id"],
            })
            continue
        adjacency.setdefault(row["source_entry_id"], []).append(payload)
    return adjacency, unresolved


def _local_groups(conn):
    groups = {}
    task_ids = {}
    for row in conn.execute(
        "SELECT group_id,entry_id,task_id FROM operation_groups WHERE scope='local' ORDER BY group_id"
    ):
        groups.setdefault(row["entry_id"], []).append(semantic_group_context(conn, row["group_id"]))
        task_ids[row["group_id"]] = row["task_id"]
    return groups, task_ids


def _insert_composed_group(conn, root_entry_id, sink, sink_task_id, root_property, path, principal_state, entries):
    root = entries[root_entry_id]
    refs = set(sink.get("evidence_refs", []))
    facts = []
    first_refs = path[0]["evidence_refs"] if path else sink.get("evidence_refs", [])
    facts.append({
        "fact_key": "root-entry", "type": "entrypoint",
        "body": f"External input enters {root['component'] or root_entry_id}",
        "location": root.get("symbol"), "evidence_refs": list(first_refs),
    })
    lineage = []
    principal_lineage = []
    component_chain = [root.get("component_id") or root_entry_id]
    security_checks = []
    branches = []
    for index, component_call in enumerate(path, 1):
        mapping = component_call["selected_mapping"]
        refs.update(component_call.get("evidence_refs", []))
        transition = component_call.get("principal_transition", {})
        refs.update(transition.get("evidence_refs", []))
        security_checks.extend(component_call.get("security_checks", []))
        branches.append({
            "condition": component_call["condition"], "locations": [component_call["call_location"]],
            "evidence_refs": component_call.get("evidence_refs", []),
        })
        lineage.append({
            "call_id": component_call["call_id"], "source_property": mapping["source_property"],
            "target_property": mapping["target_property"], "control_state": mapping["control_state"],
            "transform": mapping["transform"],
        })
        principal_lineage.append({
            "call_id": component_call["call_id"],
            "caller_principal": transition.get("caller_principal", "unknown"),
            "callee_observed_principal": transition.get("callee_observed_principal", "unknown"),
            "origin_binding": transition.get("origin_binding", "unknown"),
            "authority_used": transition.get("authority_used", "unknown"),
            "evidence_refs": transition.get("evidence_refs", []),
        })
        component_chain.append(component_call["target_component_id"])
        facts.append({
            "fact_key": f"component_call-{index}", "type": "transform",
            "body": (
                f"{mapping['source_property']} is passed to {component_call['target_symbol']} as "
                f"{mapping['target_property']} ({mapping['control_state']}: {mapping['transform']})"
            ),
            "location": component_call["call_location"], "evidence_refs": component_call.get("evidence_refs", []),
        })
        facts.append({
            "fact_key": f"principal-{index}", "type": "control",
            "body": (
                f"{transition.get('callee_observed_principal', 'downstream component')} observes "
                f"{transition.get('caller_principal', 'unknown caller')}; origin identity is "
                f"{transition.get('origin_binding', 'unknown')} and authority is "
                f"{transition.get('authority_used', 'unknown')}"
            ),
            "location": component_call["call_location"],
            "evidence_refs": transition.get("evidence_refs", []),
        })
    security_checks.extend(sink.get("security_checks", []))
    branches.extend(sink.get("branches", []))
    for fact in sink.get("facts", []):
        copied = dict(fact)
        copied["fact_key"] = f"sink-{fact.get('fact_key') or fact.get('fact_id')}"
        if copied.get("type") == "entrypoint":
            copied["type"] = "reachability"
        facts.append(copied)
    group = {
        "group_key": stable_id("COMPOSED", [root_entry_id, sink["group_id"], root_property]),
        "category": sink["category"], "capability_id": sink.get("capability_id"),
        "title": sink["title"], "operation": sink["operation"],
        "controlled_properties": [root_property], "context": sink["context"],
        "branches": branches, "facts": facts, "security_checks": security_checks,
        "evidence_refs": sorted(refs), "scope": "cross_component",
        "source_group_id": sink["group_id"], "component_chain": component_chain,
        "call_ids": [row["call_id"] for row in path], "parameter_lineage": lineage,
        "principal_lineage": principal_lineage, "principal_state": principal_state,
    }
    if sink.get("availability"):
        group["availability"] = sink["availability"]
    group["edges"] = [{
        "from": source["fact_key"], "to": target["fact_key"], "kind": "next",
        "evidence_refs": sorted(set(source.get("evidence_refs", [])) | set(target.get("evidence_refs", []))),
    } for source, target in zip(facts, facts[1:])]
    identity = canonical_json([
        operation_group_identity(root_entry_id, group), _principal_state_key(principal_state),
    ])
    existing = conn.execute(
        "SELECT group_id FROM operation_groups WHERE identity_key=?", (identity,)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE operation_groups SET validation_required=1 WHERE group_id=?", (existing["group_id"],)
        )
        return existing["group_id"], False
    group_id = stable_id("GROUP", identity)
    conn.execute(
        """INSERT INTO operation_groups
           (group_id,identity_key,entry_id,task_id,scope,validation_required,source_group_id,
            capability_id,category,title,operation_body,operation_location,
            controlled_properties_json,context_json,security_checks_json,branches_json,evidence_json,
            payload_json,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (group_id, identity, root_entry_id, sink_task_id, "cross_component", 1, sink["group_id"],
         group.get("capability_id"), group["category"], group["title"], group["operation"]["body"],
         group["operation"]["location"], canonical_json(group["controlled_properties"]),
         canonical_json(group["context"]), canonical_json(group["security_checks"]),
         canonical_json(group["branches"]), canonical_json(group["evidence_refs"]),
         canonical_json(group), now()),
    )
    fact_ids = {}
    for fact in facts:
        fact_id = stable_id("FACT", [group_id, fact["fact_key"]])
        fact_ids[fact["fact_key"]] = fact_id
        conn.execute("INSERT INTO group_facts VALUES (?,?,?,?,?,?,?,?,?)", (
            fact_id, fact["fact_key"], group_id, fact["type"], fact["body"], fact.get("location"),
            canonical_json(fact.get("evidence_refs", [])), canonical_json(fact), now()))
    for edge in group["edges"]:
        edge_id = stable_id("EDGE", [group_id, edge["from"], edge["to"], edge["kind"]])
        conn.execute("INSERT INTO group_edges VALUES (?,?,?,?,?,?,?)", (
            edge_id, group_id, fact_ids[edge["from"]], fact_ids[edge["to"]], edge["kind"],
            canonical_json(edge["evidence_refs"]), now()))
    return group_id, True


def _reuse_validation_task(conn, paths, task, snapshot):
    from .commands import _merge_exploitability_validation
    from .contracts import normalize_submission, validate_submission

    result = json.loads(json.dumps(snapshot.get("result", {})))
    result["task_id"] = task["task_id"]
    result["entry_id"] = task["subject_id"]
    result = normalize_submission(result, task, conn)
    errors = validate_submission(result, task, conn)
    if errors:
        append_event(conn, "validation_reuse_rejected", task["subject_id"], {"errors": errors})
        return False
    summary = _merge_exploitability_validation(conn, task, result)
    result_ref = paths["tasks"] / f"{task['task_id']}.result.json"
    write_json(result_ref, result)
    conn.execute(
        "UPDATE tasks SET status='completed',result_ref=?,error=NULL,updated_at=? WHERE task_id=?",
        (str(result_ref), now(), task["task_id"]),
    )
    append_event(conn, "validation_result_reused", task["subject_id"], summary)
    return True


def correlate_components(conn, run_id, paths=None):
    run = conn.execute("SELECT correlation_status FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if not run or run["correlation_status"] == "complete":
        return {"already_complete": True}
    active = conn.execute(
        "SELECT COUNT(*) n FROM tasks WHERE kind='component_semantic_analysis' AND status IN ('queued','running')"
    ).fetchone()["n"]
    if active:
        raise ValueError("semantic_tasks_not_terminal")

    entries, component_entries = _entry_records(conn)
    analyzed_entries = {
        row["entry_id"] for row in conn.execute("SELECT entry_id FROM semantic_analyses")
    }
    roots = _external_roots(conn, entries)
    adjacency, gaps = _component_calls(conn, component_entries)
    local_groups, group_tasks = _local_groups(conn)
    if roots:
        placeholders = ",".join("?" for _ in roots)
        conn.execute(
            f"UPDATE operation_groups SET validation_required=1 WHERE scope='local' AND entry_id IN ({placeholders})",
            roots,
        )

    composed_ids = []
    states_visited = 0
    truncated_roots = []
    missing_semantics = set()
    for root_entry_id in roots:
        queue = deque()
        visited = set()
        for component_call in adjacency.get(root_entry_id, []):
            for mapping in component_call["parameter_mappings"]:
                if mapping.get("control_state") not in PROPAGATING_STATES:
                    continue
                selected = {**component_call, "selected_mapping": mapping}
                principal_state = _advance_principal_state({}, selected)
                queue.append((
                    component_call["target_entry_id"], mapping["target_property"],
                    mapping["source_property"], [selected], principal_state,
                ))
        root_states = 0
        while queue:
            current_entry, current_property, root_property, path, principal_state = queue.popleft()
            state_key = (
                current_entry, normalize_text(current_property), normalize_text(root_property),
                _principal_state_key(principal_state),
            )
            if state_key in visited:
                continue
            visited.add(state_key)
            root_states += 1
            states_visited += 1
            if root_states > MAX_CORRELATION_STATES_PER_ROOT:
                truncated_roots.append(root_entry_id)
                break
            if current_entry not in analyzed_entries:
                gap_key = (root_entry_id, current_entry)
                if gap_key not in missing_semantics:
                    missing_semantics.add(gap_key)
                    gaps.append({
                        "type": "target_component_semantics_missing",
                        "root_entry_id": root_entry_id,
                        "target_entry_id": current_entry,
                    })
                continue
            for sink in local_groups.get(current_entry, []):
                if normalize_text(current_property) not in {
                    normalize_text(value) for value in sink.get("controlled_properties", [])
                }:
                    continue
                group_id, created = _insert_composed_group(
                    conn, root_entry_id, sink, group_tasks[sink["group_id"]], root_property,
                    path, principal_state, entries,
                )
                if created:
                    composed_ids.append(group_id)
            for component_call in adjacency.get(current_entry, []):
                for mapping in component_call["parameter_mappings"]:
                    if mapping.get("control_state") not in PROPAGATING_STATES:
                        continue
                    if normalize_text(mapping.get("source_property")) != normalize_text(current_property):
                        continue
                    selected = {**component_call, "selected_mapping": mapping}
                    next_principal_state = _advance_principal_state(principal_state, selected)
                    queue.append((
                        component_call["target_entry_id"], mapping["target_property"], root_property,
                        path + [selected], next_principal_state,
                    ))

    baseline_entries = {}
    if paths:
        run_mode = conn.execute("SELECT audit_mode FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if run_mode and run_mode["audit_mode"] == "incremental":
            baseline_entries = read_json(paths["baseline_validations"], {}).get("entries", {})
    reused_validations = 0
    for root_entry_id in roots:
        group_ids = [row["group_id"] for row in conn.execute(
            "SELECT group_id FROM operation_groups WHERE entry_id=? AND validation_required=1 ORDER BY group_id",
            (root_entry_id,),
        )]
        if group_ids:
            task_id = enqueue_task(
                conn, f"exploitability-validation:{root_entry_id}",
                "exploitability_validation", root_entry_id,
                {"semantic_group_ids": group_ids, "correlation_complete": True},
            )
            entry = conn.execute(
                "SELECT entry_key,payload_json FROM entries WHERE entry_id=?", (root_entry_id,)
            ).fetchone()
            payload = row_json(entry, "payload_json", {})
            snapshot = baseline_entries.get(entry["entry_key"], {}) if entry else {}
            current_fingerprints = {
                group_id: validation_group_fingerprint(conn, group_id) for group_id in group_ids
            }
            if (
                entry and not payload.get("initial_scope")
                and snapshot.get("group_fingerprints") == current_fingerprints
            ):
                task = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
                if _reuse_validation_task(conn, paths, task, snapshot):
                    reused_validations += 1

    if truncated_roots:
        gaps.extend({"type": "state_limit", "root_entry_id": value} for value in truncated_roots)
    summary = {
        "roots": len(roots), "component_calls": sum(len(rows) for rows in adjacency.values()),
        "states_visited": states_visited, "composed_groups": len(composed_ids),
        "validation_tasks_reused": reused_validations,
        "validation_groups": conn.execute(
            "SELECT COUNT(*) n FROM operation_groups WHERE validation_required=1"
        ).fetchone()["n"],
        "gaps": gaps,
    }
    stamp = now()
    conn.execute(
        "UPDATE runs SET correlation_status='complete',correlation_json=?,correlated_at=?,updated_at=? WHERE run_id=?",
        (canonical_json(summary), stamp, stamp, run_id),
    )
    append_event(conn, "component_correlation_completed", run_id, summary)
    return summary
