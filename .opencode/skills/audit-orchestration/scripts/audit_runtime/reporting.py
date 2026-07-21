"""Deterministic exports and reports derived exclusively from SQLite state."""
from __future__ import annotations

import hashlib
import html
import json
from collections import Counter

from .common import *
from .store import database


def _rows(conn, query, params=()):
    return [dict(row) for row in conn.execute(query, params)]


def _decode(row, *fields):
    value = dict(row)
    for field in fields:
        key = field + "_json"
        if key in value:
            value[field] = json.loads(value.pop(key))
    return value


def export_state(run_dir):
    paths = ensure_run_dirs(run_dir)
    with database(paths["db"]) as conn:
        entries = [_decode(row, "discriminator", "profiles", "payload") for row in _rows(conn, "SELECT * FROM entries ORDER BY entry_key")]
        flows = []
        for raw in _rows(conn, "SELECT * FROM flows ORDER BY flow_key"):
            flow = _decode(raw, "controlled_values", "payload")
            flow_id = flow["flow_id"]
            flow["facts"] = [_decode(row, "evidence", "payload") for row in _rows(conn, "SELECT * FROM facts WHERE flow_id=? ORDER BY created_at,fact_id", (flow_id,))]
            flow["edges"] = [_decode(row, "evidence") for row in _rows(conn, "SELECT * FROM edges WHERE flow_id=? ORDER BY created_at,edge_id", (flow_id,))]
            flow["continuations"] = [_decode(row, "evidence") for row in _rows(conn, "SELECT * FROM continuations WHERE flow_id=? ORDER BY created_at,continuation_id", (flow_id,))]
            flows.append(flow)
        hypotheses = [_decode(row, "evidence") for row in _rows(conn, "SELECT * FROM hypotheses ORDER BY flow_id,capability_id,pattern_id")]
        findings = [_decode(row, "evidence", "payload") for row in _rows(conn, "SELECT * FROM findings ORDER BY classification,severity,finding_id")]
        tasks = [_decode(row, "input") for row in _rows(conn, "SELECT task_id,semantic_key,kind,subject_id,status,agent,input_json,attempts,error,created_at,updated_at FROM tasks ORDER BY created_at,task_id")]
    attack_matrix = [{
        "flow_id": flow["flow_id"], "entry_id": flow["root_entry_id"], "branch": flow["branch_key"],
        "controlled_property": flow["controlled_property"], "flow_status": flow["status"],
        "capabilities": [row for row in hypotheses if row["flow_id"] == flow["flow_id"]],
        "finding_ids": [row["finding_id"] for row in findings if flow["flow_id"] in row["payload"].get("related_flow_ids", [row["flow_id"]])],
    } for flow in flows]
    artifacts = {"entries.json": entries, "flows.json": flows, "attack_matrix.json": attack_matrix, "tasks.json": tasks}
    for name, value in artifacts.items():
        write_json(paths["exports"] / name, {"schema_version": 1, "items": value})
    write_json(paths["findings"], {"schema_version": 1, "findings": findings})
    return {"ok": True, "exports": {name: str(paths["exports"] / name) for name in artifacts}, "findings": str(paths["findings"])}


def build_report(run_dir):
    paths = ensure_run_dirs(run_dir)
    export_state(run_dir)
    with database(paths["db"]) as conn:
        run = dict(conn.execute("SELECT * FROM runs LIMIT 1").fetchone())
        project = read_json(paths["project_model"], {})
        entries = _rows(conn, "SELECT entry_id,entry_key,entry_type,component,symbol,transport,reachability FROM entries ORDER BY entry_key")
        flows = _rows(conn, "SELECT flow_id,flow_key,root_entry_id,branch_key,controlled_property,current_symbol,status FROM flows ORDER BY flow_key")
        for flow in flows:
            flow["facts"] = [_decode(row, "evidence", "payload") for row in _rows(
                conn, "SELECT * FROM facts WHERE flow_id=? ORDER BY created_at,fact_id", (flow["flow_id"],))]
        findings = [_decode(row, "evidence", "payload") for row in _rows(conn, "SELECT * FROM findings ORDER BY classification,severity,title")]
        task_counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
    classification_counts = Counter(row["classification"] for row in findings)
    flow_counts = Counter(row["status"] for row in flows)
    model = {
        "schema_version": 1,
        "generated_at": now(),
        "run": {
            "run_id": run["run_id"], "target_repo": run["target_repo"], "mode": run["audit_mode"],
            "capabilities": json.loads(run["capability_filter_json"]),
            "components": json.loads(run["component_filter_json"]),
        },
        "project": {"application": project.get("application"), "summary": project.get("summary", {})},
        "summary": {
            "entries": len(entries), "flows": len(flows), "findings": len(findings),
            "flow_status": dict(sorted(flow_counts.items())),
            "classifications": dict(sorted(classification_counts.items())), "tasks": task_counts,
        },
        "entries": entries, "flows": flows, "findings": findings,
    }
    write_json(paths["report_model"], model)
    paths["report_md"].write_text(_render_markdown(model), encoding="utf-8")
    paths["report_html"].write_text(_render_html(model), encoding="utf-8")
    hashes = {}
    for key in ("report_model", "report_md", "report_html", "findings"):
        target = paths[key]
        hashes[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    snapshot = {"schema_version": 1, "generated_at": now(), "run_id": run["run_id"], "sha256": hashes}
    write_json(paths["snapshot"], snapshot)
    return {"report_markdown": str(paths["report_md"]), "report_html": str(paths["report_html"]),
            "report_model": str(paths["report_model"]), "snapshot": str(paths["snapshot"]), "summary": model["summary"]}


def _render_markdown(model):
    summary = model["summary"]
    lines = [
        "# HarmonyOS Security Audit Report", "",
        f"- Target: `{model['run']['target_repo']}`",
        f"- Run: `{model['run']['run_id']}`",
        f"- Components: `{', '.join(model['run']['components']) or 'all'}`",
        f"- Capabilities: `{', '.join(model['run']['capabilities']) or 'all'}`",
        f"- Entries: {summary['entries']}", f"- Flows: {summary['flows']}", f"- Root-cause findings: {summary['findings']}", "",
        "## Flow Status", "",
    ]
    lines.extend(f"- `{key}`: {value}" for key, value in summary["flow_status"].items())
    lines.extend(["", "## Findings", ""])
    if not model["findings"]:
        lines.append("No findings were produced.")
    for finding in model["findings"]:
        lines.extend([
            f"### {finding['finding_id']}: {finding['title']}", "",
            f"- Classification: `{finding['classification']}`", f"- Severity: `{finding.get('severity') or 'n/a'}`",
            f"- Boundary: `{finding['boundary']}`", f"- Controlled property: `{finding['controlled_property']}`",
            f"- Operation: `{finding['operation_location']}`", f"- Related flows: {', '.join(finding['payload'].get('related_flow_ids', [finding['flow_id']]))}", "",
            finding["payload"].get("reason", ""), "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _render_html(model):
    summary = model["summary"]
    cards = "".join(f'<div class="metric"><strong>{html.escape(str(value))}</strong><span>{html.escape(label)}</span></div>' for label, value in (
        ("Entries", summary["entries"]), ("Flows", summary["flows"]), ("Findings", summary["findings"])))
    flow_rows = "".join(
        f'<tr><td><a href="#{html.escape(row["flow_id"])}"><code>{html.escape(row["flow_id"])}</code></a></td><td>{html.escape(row["branch_key"])}</td><td>{html.escape(row["controlled_property"])}</td><td><span class="status">{html.escape(row["status"])}</span></td></tr>'
        for row in model["flows"])
    flow_details = "".join(
        f'<details id="{html.escape(row["flow_id"])}"><summary><code>{html.escape(row["flow_id"])}</code><span>{html.escape(row["branch_key"])} / {html.escape(row["controlled_property"])}</span></summary><ol>' +
        "".join(f'<li><b>{html.escape(fact["fact_type"])}</b> {html.escape(fact["body"])} <code>{html.escape(fact.get("location") or "")}</code></li>' for fact in row["facts"]) +
        '</ol></details>' for row in model["flows"])
    findings = "".join(
        f'<article id="{html.escape(row["finding_id"])}"><header><div><small>{html.escape(row["classification"])}</small><h2>{html.escape(row["title"])}</h2></div><span class="severity">{html.escape(row.get("severity") or "n/a")}</span></header><dl><dt>Boundary</dt><dd>{html.escape(row["boundary"])}</dd><dt>Controlled property</dt><dd>{html.escape(row["controlled_property"])}</dd><dt>Operation</dt><dd><code>{html.escape(row["operation_location"])}</code></dd></dl><p>{html.escape(row["payload"].get("reason", ""))}</p></article>'
        for row in model["findings"])
    if not findings:
        findings = '<p class="empty">No findings were produced.</p>'
    title = html.escape((model.get("project", {}).get("application") or {}).get("bundle_name") or "HarmonyOS audit")
    scope = html.escape(
        "Components: " + (", ".join(model["run"]["components"]) or "all") +
        " | Capabilities: " + (", ".join(model["run"]["capabilities"]) or "all")
    )
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>
:root{{--ink:#182026;--muted:#64717a;--line:#d8dfe3;--paper:#f7f8f6;--accent:#087f5b;--warn:#b45309}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:14px/1.55 system-ui,sans-serif}}main{{max-width:1120px;margin:auto;padding:32px 24px 72px}}h1{{font-size:28px;margin:4px 0}}h2{{font-size:17px;margin:2px 0}}a{{color:var(--accent)}}code{{font-family:ui-monospace,monospace}}.muted,small{{color:var(--muted)}}.metrics{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin:24px 0}}.metric{{background:white;padding:18px}}.metric strong{{display:block;font-size:25px}}.metric span{{color:var(--muted)}}section{{margin-top:32px}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid var(--line)}}th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line)}}th{{font-size:12px;color:var(--muted)}}details{{background:white;border:1px solid var(--line);margin:8px 0;padding:12px}}summary{{display:flex;gap:16px;cursor:pointer}}details li{{margin:6px 0}}article{{background:white;border:1px solid var(--line);border-left:4px solid var(--accent);padding:18px;margin:12px 0}}article header{{display:flex;justify-content:space-between;gap:16px}}.severity,.status{{font:12px ui-monospace,monospace;color:var(--warn)}}dl{{display:grid;grid-template-columns:150px 1fr;gap:6px;margin:16px 0}}dt{{color:var(--muted)}}dd{{margin:0;overflow-wrap:anywhere}}.empty{{padding:24px;background:white;border:1px solid var(--line)}}@media(max-width:700px){{main{{padding:20px 14px}}.metrics{{grid-template-columns:1fr}}table{{display:block;overflow:auto}}dl{{grid-template-columns:1fr}}}}
</style></head><body><main><header><div class="muted">{html.escape(model['run']['run_id'])}</div><h1>{title}</h1><div class="muted">{html.escape(model['run']['target_repo'])}</div><div class="muted">{scope}</div></header><div class="metrics">{cards}</div><section><h2>Evidence flows</h2><table><thead><tr><th>Flow</th><th>Branch</th><th>Controlled property</th><th>Status</th></tr></thead><tbody>{flow_rows}</tbody></table>{flow_details}</section><section><h2>Root-cause findings</h2>{findings}</section></main></body></html>'''
