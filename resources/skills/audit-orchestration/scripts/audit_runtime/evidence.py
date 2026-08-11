"""Evidence ownership and admissibility for AI task boundaries."""
from __future__ import annotations

import json

from .common import canonical_json, now, stable_id


EVIDENCE_FIELDS = ("kind", "source", "summary", "location", "content_ref", "sha256")


def _evidence_row(row):
    return {key: row.get(key) for key in EVIDENCE_FIELDS if key in row}


def _insert_inline_evidence(conn, task_id, rows, role):
    evidence_ids = []
    for source in rows or []:
        row = _evidence_row(source)
        evidence_id = stable_id("EVID", [task_id, role, canonical_json(row)])
        conn.execute(
            """INSERT OR IGNORE INTO evidence
               (evidence_id,task_id,kind,source,location,summary,content_ref,sha256,created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (evidence_id, task_id, row["kind"], row["source"], row.get("location"), row["summary"],
             row.get("content_ref"), row.get("sha256"), now()),
        )
        evidence_ids.append(evidence_id)
    return sorted(set(evidence_ids))


def _materialize_inline_evidence(conn, task_id, value):
    if isinstance(value, list):
        return [_materialize_inline_evidence(conn, task_id, item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key == "evidence" and isinstance(item, list):
            result["evidence_refs"] = _insert_inline_evidence(conn, task_id, item, "semantic")
        elif key == "basis_evidence" and isinstance(item, list):
            result["basis_evidence_refs"] = _insert_inline_evidence(conn, task_id, item, "hypothesis")
        else:
            result[key] = _materialize_inline_evidence(conn, task_id, item)
    return result


def semantic_admissible_refs(group):
    """Return source-backed evidence that may support a security conclusion."""
    refs = list(group.get("evidence_refs", []))
    refs.extend(group.get("operation", {}).get("evidence_refs", []))
    for key in ("facts", "edges", "branches", "security_checks"):
        for row in group.get(key, []):
            refs.extend(row.get("evidence_refs", []))
    refs.extend(group.get("context", {}).get("evidence_refs", []))
    refs.extend(group.get("availability", {}).get("evidence_refs", []))
    return set(refs)


def semantic_hypothesis_refs(group):
    refs = []
    for hypothesis in group.get("context", {}).get("effect_hypotheses", []):
        refs.extend(hypothesis.get("basis_evidence_refs", []))
    return set(refs) - semantic_admissible_refs(group)


def component_call_refs(component_call):
    refs = list(component_call.get("evidence_refs", []))
    refs.extend(component_call.get("invocation_control", {}).get("evidence_refs", []))
    refs.extend(component_call.get("principal_transition", {}).get("evidence_refs", []))
    for security_check in component_call.get("security_checks", []):
        refs.extend(security_check.get("evidence_refs", []))
    return set(refs)


def materialize_semantic_group(conn, task_id, source):
    group = _materialize_inline_evidence(conn, task_id, json.loads(json.dumps(source)))
    facts = group.get("facts", [])
    group["edges"] = [{
        "from": left["fact_key"],
        "to": right["fact_key"],
        "kind": "next",
        "evidence_refs": sorted(set(left.get("evidence_refs", [])) | set(right.get("evidence_refs", []))),
    } for left, right in zip(facts, facts[1:])]
    group["evidence_refs"] = sorted(semantic_admissible_refs(group))
    return group


def materialize_component_call(conn, task_id, source):
    component_call = _materialize_inline_evidence(conn, task_id, json.loads(json.dumps(source)))
    component_call["evidence_refs"] = sorted(component_call_refs(component_call))
    return component_call


def iter_validation_supports(value):
    if isinstance(value, list):
        for item in value:
            yield from iter_validation_supports(item)
        return
    if not isinstance(value, dict):
        return
    support = value.get("evidence")
    if isinstance(support, dict) and "semantic_refs" in support and "verification" in support:
        yield support
    for key, item in value.items():
        if key != "evidence":
            yield from iter_validation_supports(item)


def validation_semantic_refs(value):
    return {
        ref
        for support in iter_validation_supports(value)
        for ref in support.get("semantic_refs", [])
    }


def materialize_validation(conn, task_id, source):
    def convert(value):
        if isinstance(value, list):
            return [convert(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key == "evidence" and isinstance(item, dict):
                semantic_refs = item.get("semantic_refs", [])
                verification_refs = _insert_inline_evidence(
                    conn, task_id, item.get("verification", []), "verification"
                )
                result["evidence_refs"] = sorted(set(semantic_refs) | set(verification_refs))
            else:
                result[key] = convert(item)
        return result

    return convert(json.loads(json.dumps(source)))


def materialize_poc(conn, task_id, source):
    """PoC artifacts use the same inline-evidence model: each symbol_ref carries
    its own evidence without IDs; the runtime numbers, dedupes, and merges refs.
    Top-level evidence_refs may only reference inherited evidence ids."""
    poc = json.loads(json.dumps(source))
    materialized_refs = []
    for symbol_ref in poc.get("symbol_refs", []):
        if isinstance(symbol_ref, dict) and isinstance(symbol_ref.get("evidence"), list):
            refs = _insert_inline_evidence(conn, task_id, symbol_ref["evidence"], "poc")
            symbol_ref["evidence_refs"] = sorted(refs)
            symbol_ref.pop("evidence", None)
            materialized_refs.extend(refs)
    poc["evidence_refs"] = sorted(set(poc.get("evidence_refs", [])) | set(materialized_refs))
    poc["assurance_status"] = "generated_unverified"
    return poc
