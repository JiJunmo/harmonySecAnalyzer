"""Deterministic exports and reports derived exclusively from SQLite state."""
from __future__ import annotations

import hashlib
import html
import json
from collections import Counter, defaultdict

from .common import *
from .store import database
from .task_context import path_context


def _rows(conn, query, params=()):
    return [dict(row) for row in conn.execute(query, params)]


def _decode(row, *fields):
    value = dict(row)
    for field in fields:
        key = field + "_json"
        if key in value:
            value[field] = json.loads(value.pop(key))
    return value


CLASSIFICATION_RANK = {
    "confirmed_vulnerability": 0, "residual_risk": 1, "insufficient_evidence": 2,
    "protected_exposure": 3, "benign_business_flow": 4,
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding_sort_key(row):
    return (
        CLASSIFICATION_RANK.get(row.get("classification"), 99),
        SEVERITY_RANK.get(row.get("severity"), 99),
        row.get("title") or "",
    )


def _path_indexes(assessments, findings):
    assessments_by_path = defaultdict(list)
    finding_ids_by_path = defaultdict(list)
    for assessment in assessments:
        assessments_by_path[assessment["path_id"]].append(assessment)
    for finding in findings:
        for path_id in finding["payload"].get("related_path_ids", [finding["path_id"]]):
            finding_ids_by_path[path_id].append(finding["finding_id"])
    return assessments_by_path, finding_ids_by_path


def export_state(run_dir):
    run_paths = ensure_run_dirs(run_dir)
    with database(run_paths["db"]) as conn:
        entries = [_decode(row, "discriminator", "profiles", "payload") for row in _rows(conn, "SELECT * FROM entries ORDER BY entry_key")]
        flows = []
        for raw in _rows(conn, "SELECT * FROM flows ORDER BY identity_key"):
            flow = _decode(raw, "controlled_values", "payload")
            flow_id = flow["flow_id"]
            flow["facts"] = [_decode(row, "evidence", "payload") for row in _rows(conn, "SELECT * FROM facts WHERE flow_id=? ORDER BY created_at,fact_id", (flow_id,))]
            flow["edges"] = [_decode(row, "evidence") for row in _rows(conn, "SELECT * FROM edges WHERE flow_id=? ORDER BY created_at,edge_id", (flow_id,))]
            flow["continuations"] = [_decode(row, "evidence", "child_flow_ids") for row in _rows(conn, "SELECT * FROM continuations WHERE flow_id=? ORDER BY created_at,continuation_id", (flow_id,))]
            flows.append(flow)
        evidence_paths = [path_context(conn, row["path_id"]) for row in _rows(conn, "SELECT path_id FROM paths ORDER BY created_at,path_id")]
        assessments = [_decode(row, "exploitability", "business_intent", "security_boundary", "guards", "counter_evidence", "evidence", "payload") for row in _rows(
            conn, "SELECT * FROM security_assessments ORDER BY path_id,classification,assessment_id")]
        findings = [_decode(row, "evidence", "payload") for row in _rows(conn, "SELECT * FROM findings ORDER BY classification,severity,finding_id")]
        tasks = [_decode(row, "input") for row in _rows(conn, "SELECT task_id,semantic_key,kind,subject_id,status,agent,input_json,attempts,error,created_at,updated_at FROM tasks ORDER BY created_at,task_id")]
    assessments_by_path, finding_ids_by_path = _path_indexes(assessments, findings)
    attack_matrix = [{
        "path_id": path["path_id"], "entry_id": path["root_entry_id"], "branch": path["branch_key"],
        "controlled_property": path["controlled_property"], "path_status": path["status"],
        "flow_ids": path["flow_ids"],
        "assessments": assessments_by_path[path["path_id"]],
        "finding_ids": finding_ids_by_path[path["path_id"]],
    } for path in evidence_paths]
    artifacts = {"entries.json": entries, "flows.json": flows, "paths.json": evidence_paths,
                 "assessments.json": assessments,
                 "attack_matrix.json": attack_matrix, "tasks.json": tasks}
    for name, value in artifacts.items():
        write_json(run_paths["exports"] / name, {"schema_version": 1, "items": value})
    write_json(run_paths["findings"], {"schema_version": 1, "findings": findings})
    return {"ok": True, "exports": {name: str(run_paths["exports"] / name) for name in artifacts}, "findings": str(run_paths["findings"])}


def build_report(run_dir):
    run_paths = ensure_run_dirs(run_dir)
    export_state(run_dir)
    with database(run_paths["db"]) as conn:
        run = dict(conn.execute("SELECT * FROM runs LIMIT 1").fetchone())
        project = read_json(run_paths["project_model"], {})
        entries = _rows(conn, "SELECT entry_id,entry_key,entry_type,component,symbol,transport,reachability FROM entries ORDER BY entry_key")
        flow_segment_count = conn.execute("SELECT COUNT(*) n FROM flows").fetchone()["n"]
        evidence_paths = [path_context(conn, row["path_id"]) for row in _rows(conn, "SELECT path_id FROM paths ORDER BY created_at,path_id")]
        findings = [_decode(row, "evidence", "payload") for row in _rows(conn, "SELECT * FROM findings")]
        assessments = [_decode(row, "exploitability", "business_intent", "security_boundary", "guards", "counter_evidence", "evidence", "payload") for row in _rows(
            conn, "SELECT * FROM security_assessments ORDER BY path_id,classification,assessment_id")]
        dispositions = [_decode(row, "evidence") for row in _rows(
            conn, "SELECT * FROM entry_dispositions ORDER BY project_candidate_id")]
        continuations = [_decode(row, "evidence") for row in _rows(
            conn, "SELECT * FROM continuations ORDER BY created_at,continuation_id")]
        tasks = _rows(conn, "SELECT task_id,kind,subject_id,status,attempts,error FROM tasks ORDER BY created_at,task_id")
        task_counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
    classification_counts = Counter(row["classification"] for row in assessments)
    finding_classification_counts = Counter(row["classification"] for row in findings)
    findings.sort(key=finding_sort_key)
    path_counts = Counter(row["status"] for row in evidence_paths)
    actionable_findings = len(findings)
    entry_by_id = {row["entry_id"]: row for row in entries}
    assessments_by_path, finding_ids_by_path = _path_indexes(assessments, findings)
    for path in evidence_paths:
        path["entry"] = entry_by_id.get(path["root_entry_id"])
        path["assessments"] = assessments_by_path[path["path_id"]]
        path["finding_ids"] = finding_ids_by_path[path["path_id"]]
    disposition_counts = Counter(row["disposition"] for row in dispositions)
    continuation_counts = Counter(row["status"] for row in continuations)
    gaps = []
    for row in project.get("diagnostics", []):
        gaps.append({"type": "项目解析", "subject": row.get("file") or "project", "description": row.get("message") or str(row)})
    for row in dispositions:
        if row["disposition"] == "gap":
            gaps.append({"type": "入口覆盖", "subject": row["project_candidate_id"], "description": row.get("reason") or "入口未能完整解析"})
    for path in evidence_paths:
        if path["status"] == "gap":
            gaps.append({"type": "路径证据", "subject": path["path_id"], "description": "路径证据不足，无法完成最终判断"})
        for fact in path["facts"]:
            if fact["fact_type"] == "gap":
                gaps.append({"type": "路径证据", "subject": path["path_id"], "description": fact["body"]})
        for assessment in path["assessments"]:
            if assessment["classification"] == "insufficient_evidence":
                gaps.append({"type": "安全判定", "subject": assessment["assessment_id"], "description": assessment.get("evidence_gap") or assessment.get("demotion_reason")})
    for row in continuations:
        if row["status"] in {"open", "gap"}:
            gaps.append({"type": "跨边界追踪", "subject": row["continuation_id"], "description": f"{row['target']}：{row['status']}"})
    for row in tasks:
        if row["status"] == "failed":
            gaps.append({"type": "任务失败", "subject": row["task_id"], "description": row.get("error") or "任务执行失败"})
    coverage_status = "完整" if not gaps else "部分完成"
    model = {
        "schema_version": 1,
        "generated_at": now(),
        "run": {
            "run_id": run["run_id"], "target_repo": run["target_repo"], "mode": run["audit_mode"],
            "capabilities": json.loads(run["capability_filter_json"]),
            "components": json.loads(run["component_filter_json"]),
        },
        "project": {
            "application": project.get("application") or {}, "summary": project.get("summary", {}),
            "modules": project.get("modules", []), "components": project.get("components", []),
            "requested_permissions": project.get("requested_permissions", []),
            "defined_permissions": project.get("defined_permissions", []),
            "dependencies": project.get("dependencies", []), "diagnostics": project.get("diagnostics", []),
        },
        "summary": {
            "entries": len(entries), "paths": len(evidence_paths), "flow_segments": flow_segment_count,
            "findings": actionable_findings,
            "validation_results": len(assessments),
            "confirmed_vulnerabilities": finding_classification_counts.get("confirmed_vulnerability", 0),
            "residual_risks": finding_classification_counts.get("residual_risk", 0),
            "protected_exposures": classification_counts.get("protected_exposure", 0),
            "benign_business_flows": classification_counts.get("benign_business_flow", 0),
            "insufficient_evidence": classification_counts.get("insufficient_evidence", 0),
            "path_status": dict(sorted(path_counts.items())),
            "classifications": dict(sorted(classification_counts.items())), "tasks": task_counts,
        },
        "coverage": {
            "status": coverage_status,
            "project_candidates": len(project.get("entry_candidates", [])),
            "entry_dispositions": dict(sorted(disposition_counts.items())),
            "task_status": task_counts,
            "continuation_status": dict(sorted(continuation_counts.items())),
            "assessment_status": dict(sorted(classification_counts.items())),
            "gaps": gaps,
        },
        "entries": entries, "paths": evidence_paths, "assessments": assessments, "findings": findings,
    }
    write_json(run_paths["report_model"], model)
    run_paths["report_md"].write_text(_render_markdown(model), encoding="utf-8")
    run_paths["report_html"].write_text(_render_html(model), encoding="utf-8")
    hashes = {}
    for key in ("report_model", "report_md", "report_html", "findings"):
        target = run_paths[key]
        hashes[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    snapshot = {"schema_version": 1, "generated_at": now(), "run_id": run["run_id"], "sha256": hashes}
    write_json(run_paths["snapshot"], snapshot)
    return {"report_markdown": str(run_paths["report_md"]), "report_html": str(run_paths["report_html"]),
            "report_model": str(run_paths["report_model"]), "snapshot": str(run_paths["snapshot"]), "summary": model["summary"]}


def _render_markdown(model):
    summary = model["summary"]
    lines = [
        "# HarmonyOS Security Audit Report", "",
        f"- Target: `{model['run']['target_repo']}`",
        f"- Run: `{model['run']['run_id']}`",
        f"- Components: `{', '.join(model['run']['components']) or 'all'}`",
        f"- Capabilities: `{', '.join(model['run']['capabilities']) or 'all'}`",
        f"- Entries: {summary['entries']}", f"- Evidence paths: {summary['paths']}",
        f"- Flow segments: {summary['flow_segments']}",
        f"- Actionable findings: {summary['findings']}",
        f"- Confirmed vulnerabilities: {summary['confirmed_vulnerabilities']}",
        f"- Residual risks: {summary['residual_risks']}",
        f"- Protected exposures: {summary['protected_exposures']}",
        f"- Benign business flows: {summary['benign_business_flows']}",
        f"- Insufficient evidence: {summary['insufficient_evidence']}", "",
        "## Path Status", "",
    ]
    lines.extend(f"- `{key}`: {value}" for key, value in summary["path_status"].items())
    lines.extend(["", "## Actionable Findings", ""])
    if not model["findings"]:
        lines.append("No actionable findings were produced. Safe and inconclusive assessments remain available in the JSON and HTML reports.")
    for finding in model["findings"]:
        lines.extend([
            f"### {finding['finding_id']}: {finding['title']}", "",
            f"- Classification: `{finding['classification']}`", f"- Severity: `{finding.get('severity') or 'n/a'}`",
            f"- Boundary: `{finding['boundary']}`", f"- Controlled property: `{finding['controlled_property']}`",
            f"- Operation: `{finding['operation_location']}`", f"- Related paths: {', '.join(finding['payload'].get('related_path_ids', [finding['path_id']]))}", "",
            finding["payload"].get("conclusion", ""), "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _render_html(model):
    application = model.get("project", {}).get("application") or {}
    title = html.escape(application.get("bundle_name") or "HarmonyOS 安全审计")
    view_model = {
        "run": model["run"], "project": model["project"], "summary": model["summary"],
        "coverage": model["coverage"], "entries": model["entries"],
        "paths": [{
            key: path.get(key) for key in (
                "path_id", "flow_ids", "root_entry_id", "branch_key", "controlled_property",
                "current_symbol", "status", "entry", "finding_ids",
            )
        } | {
            "facts": [{key: fact.get(key) for key in ("fact_type", "body", "location", "evidence_refs")} for fact in path["facts"]],
            "assessments": [{key: row.get(key) for key in (
                "assessment_id", "capability_id", "pattern_id", "category", "classification",
                "title", "severity", "boundary", "operation_location", "impact", "demotion_reason",
                "evidence_gap", "exploitability", "business_intent", "security_boundary", "guards", "counter_evidence", "evidence_refs",
            )} for row in path["assessments"]],
        } for path in model["paths"]],
        "findings": [{
            key: finding.get(key) for key in (
                "finding_id", "path_id", "classification", "title", "severity", "cwe",
                "impact", "poc", "boundary", "controlled_property", "operation_location", "evidence",
            )
        } | {"payload": {
            key: finding["payload"].get(key) for key in (
                "conclusion", "exploitability", "business_intent", "security_boundary", "guards",
                "counter_evidence", "demotion_reason", "evidence_gap", "evidence_refs", "related_path_ids",
            )
        }} for finding in model["findings"]],
    }
    report_data = json.dumps(view_model, ensure_ascii=False).replace("</", "<\\/")
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><style>
:root{{--ink:#17201d;--muted:#66736e;--line:#d9e0dc;--paper:#f5f7f5;--surface:#fff;--accent:#087f5b;--danger:#b42318;--warn:#b54708;--safe:#287a50}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}}button,input,select{{font:inherit}}header.top{{background:var(--surface);border-bottom:1px solid var(--line)}}.top-inner,nav,.view{{max-width:1180px;margin:auto}}.top-inner{{padding:26px 24px 20px}}h1{{font-size:27px;margin:3px 0 7px}}h2{{font-size:18px;margin:0 0 14px}}h3{{font-size:15px;margin:0 0 8px}}.muted{{color:var(--muted)}}.runmeta{{display:flex;flex-wrap:wrap;gap:8px 20px;color:var(--muted)}}nav{{padding:0 24px}}.tabs{{display:flex;gap:2px;overflow:auto}}.tab{{border:0;border-bottom:3px solid transparent;background:transparent;padding:12px 18px;white-space:nowrap;cursor:pointer;color:var(--muted)}}.tab.active{{border-color:var(--accent);color:var(--ink);font-weight:650}}.view{{display:none;padding:26px 24px 72px}}.view.active{{display:block}}.metrics{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));border:1px solid var(--line);background:var(--line);gap:1px;margin-bottom:24px}}.metric{{background:var(--surface);padding:16px;min-width:0}}.metric strong{{display:block;font-size:25px;overflow-wrap:anywhere}}.metric span{{color:var(--muted)}}.grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}.panel{{background:var(--surface);border:1px solid var(--line);padding:18px;margin-bottom:20px}}.summary-list{{display:grid;gap:10px}}.summary-item{{border-left:3px solid var(--accent);padding:7px 10px;background:#f8faf8}}.summary-item.danger{{border-color:var(--danger)}}.summary-item h3{{margin:0}}.summary-item p{{margin:4px 0 0;color:var(--muted)}}.toolbar{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}}.control{{height:38px;border:1px solid var(--line);background:var(--surface);padding:0 11px;min-width:160px}}input.control{{flex:1;min-width:240px}}.count{{color:var(--muted);margin:0 0 8px}}.table-wrap{{overflow:auto;border:1px solid var(--line);background:var(--surface)}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{font-size:12px;color:var(--muted);background:#fafbfa;white-space:nowrap}}tr.path-row{{cursor:pointer}}tr.path-row:hover{{background:#f2f7f4}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;overflow-wrap:anywhere}}.badge{{display:inline-block;border:1px solid var(--line);padding:2px 7px;font-size:12px;white-space:nowrap}}.badge.confirmed_vulnerability{{color:var(--danger);border-color:#efb4ae;background:#fff5f4}}.badge.residual_risk,.badge.gap{{color:var(--warn);border-color:#e8c39c;background:#fff9f0}}.badge.protected_exposure,.badge.stopped{{color:var(--safe);border-color:#aed8c0;background:#f1faf5}}.badge.benign_business_flow,.badge.reached{{color:#42665a;background:#f4f8f6}}.structure-list{{display:grid;gap:10px}}.structure-item{{border-bottom:1px solid var(--line);padding:0 0 10px}}.structure-item:last-child{{border:0;padding-bottom:0}}.kv{{display:grid;grid-template-columns:150px 1fr;gap:7px 14px}}.kv dt{{color:var(--muted)}}.kv dd{{margin:0;overflow-wrap:anywhere}}.gap-list{{display:grid;gap:9px}}.gap-item{{border-left:3px solid var(--warn);background:#fffaf3;padding:10px 12px}}.empty{{padding:22px;color:var(--muted);text-align:center;background:var(--surface);border:1px solid var(--line)}}.drawer-backdrop{{display:none;position:fixed;inset:0;background:rgba(17,28,23,.34);z-index:10}}.drawer-backdrop.open{{display:block}}.drawer{{position:absolute;right:0;top:0;width:min(720px,94vw);height:100%;overflow:auto;background:var(--surface);padding:24px;box-shadow:-12px 0 40px rgba(0,0,0,.16)}}.drawer-head{{display:flex;justify-content:space-between;gap:16px;align-items:start;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:18px}}.close{{border:1px solid var(--line);background:var(--surface);width:34px;height:34px;font-size:21px;cursor:pointer}}.timeline{{list-style:none;margin:0;padding:0}}.timeline li{{position:relative;margin-left:7px;padding:0 0 16px 24px;border-left:1px solid var(--line)}}.timeline li:before{{content:"";position:absolute;left:-5px;top:5px;width:9px;height:9px;background:var(--accent)}}.timeline li:last-child{{border-left-color:transparent}}.timeline b{{display:block}}@media(max-width:900px){{.metrics{{grid-template-columns:repeat(3,minmax(0,1fr))}}.grid-2{{grid-template-columns:1fr}}}}@media(max-width:600px){{.top-inner,.view,nav{{padding-left:14px;padding-right:14px}}.metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}.kv{{grid-template-columns:1fr}}}}
</style></head><body><header class="top"><div class="top-inner"><div class="muted">HarmonyOS 白盒安全审计</div><h1>{title}</h1><div class="runmeta" id="runmeta"></div></div><nav><div class="tabs"><button class="tab active" data-view="overview">概览</button><button class="tab" data-view="paths">攻击路径</button><button class="tab" data-view="project">项目结构</button><button class="tab" data-view="coverage">覆盖与缺口</button></div></nav></header>
<main><section id="overview" class="view active"><div class="metrics" id="overview-metrics"></div><div class="grid-2"><div class="panel"><h2>分析结果</h2><div id="result-summary" class="summary-list"></div></div><div class="panel"><h2>重点结论</h2><div id="key-findings" class="summary-list"></div></div></div><div class="panel"><h2>入口与路径概况</h2><div id="entry-summary"></div></div></section>
<section id="paths" class="view"><h2>攻击路径</h2><div class="toolbar"><input id="search" class="control" placeholder="搜索入口、分支、受控参数或敏感操作"><select id="path-result" class="control"><option value="">全部结果</option></select><select id="path-severity" class="control"><option value="">全部等级</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="info">提示</option></select></div><p class="count" id="path-count"></p><div class="table-wrap"><table><thead><tr><th>结果</th><th>等级</th><th>入口</th><th>分支</th><th>受控参数</th><th>敏感操作 / 当前位置</th></tr></thead><tbody id="path-body"></tbody></table></div></section>
<section id="project" class="view"><div class="grid-2"><div class="panel"><h2>项目信息</h2><dl class="kv" id="project-info"></dl></div><div class="panel"><h2>权限与依赖</h2><div id="permission-list" class="structure-list"></div></div></div><div class="panel"><h2>模块</h2><div id="module-list" class="structure-list"></div></div><div class="panel"><h2>组件</h2><div class="table-wrap"><table><thead><tr><th>组件</th><th>类型</th><th>模块</th><th>导出</th><th>权限</th><th>源码</th></tr></thead><tbody id="component-body"></tbody></table></div></div></section>
<section id="coverage" class="view"><div class="metrics" id="coverage-metrics"></div><div class="grid-2"><div class="panel"><h2>覆盖统计</h2><div id="coverage-summary" class="structure-list"></div></div><div class="panel"><h2>任务状态</h2><div id="task-summary" class="structure-list"></div></div></div><div class="panel"><h2>缺口与分析注记</h2><div id="gap-list" class="gap-list"></div></div></section></main>
<div class="drawer-backdrop" id="drawer-backdrop"><aside class="drawer" role="dialog" aria-modal="true"><div class="drawer-head"><div><div class="muted">路径详情</div><h2 id="drawer-title"></h2></div><button class="close" id="drawer-close" aria-label="关闭">×</button></div><div id="drawer-body"></div></aside></div>
<script type="application/json" id="report-data">{report_data}</script><script>
const D=JSON.parse(document.getElementById('report-data').textContent);const arr=v=>Array.isArray(v)?v:[];const obj=v=>v&&typeof v==='object'?v:{{}};const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const labels={{confirmed_vulnerability:'已确认漏洞',residual_risk:'残余风险',protected_exposure:'已有效防护',benign_business_flow:'正常业务',insufficient_evidence:'证据不足',reached:'已到达敏感操作',stopped:'路径已终止',open:'继续追踪',gap:'证据不足',resolved_entry:'已识别',excluded:'已排除',completed:'已完成',failed:'失败',queued:'等待中',running:'执行中'}};const label=v=>labels[v]||v||'-';
const findingById=Object.fromEntries(arr(D.findings).map(x=>[x.finding_id,x]));const resultRank={{confirmed_vulnerability:5,residual_risk:4,insufficient_evidence:3,protected_exposure:2,benign_business_flow:1}};const pathResult=p=>arr(p.finding_ids).map(id=>findingById[id]).filter(Boolean)[0]||arr(p.assessments).slice().sort((a,b)=>(resultRank[b.classification]||0)-(resultRank[a.classification]||0))[0]||{{}};const metric=(v,t)=>`<div class="metric"><strong>${{esc(v)}}</strong><span>${{esc(t)}}</span></div>`;const badge=v=>`<span class="badge ${{esc(v)}}">${{esc(label(v))}}</span>`;
document.getElementById('runmeta').innerHTML=`<span>运行编号 <b>${{esc(D.run.run_id)}}</b></span><span>审计范围 <b>${{esc(arr(D.run.components).join(', ')||'全部组件')}}</b></span><span>覆盖状态 <b>${{esc(D.coverage.status)}}</b></span>`;
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.view').forEach(x=>x.classList.toggle('active',x.id===b.dataset.view));}});
const S=D.summary;document.getElementById('overview-metrics').innerHTML=metric(S.confirmed_vulnerabilities,'已确认漏洞')+metric(S.residual_risks,'残余风险')+metric(S.protected_exposures,'有效防护')+metric(S.benign_business_flows,'正常业务')+metric(S.entries,'外部入口')+metric(S.paths,'攻击路径');
const resultRows=[['confirmed_vulnerability',S.confirmed_vulnerabilities],['residual_risk',S.residual_risks],['protected_exposure',S.protected_exposures],['benign_business_flow',S.benign_business_flows],['insufficient_evidence',S.insufficient_evidence]];document.getElementById('result-summary').innerHTML=resultRows.map(([k,v])=>`<div class="summary-item"><h3>${{badge(k)}} ${{esc(v)}} 条</h3></div>`).join('');
const key=arr(D.findings).filter(x=>['confirmed_vulnerability','residual_risk'].includes(x.classification)).slice(0,6);document.getElementById('key-findings').innerHTML=key.map(x=>`<div class="summary-item danger"><h3>${{esc(x.title)}}</h3><p>${{badge(x.classification)}} · ${{esc(x.severity||'未定级')}} · ${{esc(x.operation_location)}}</p></div>`).join('')||'<div class="empty">未发现需要处置的安全问题</div>';
const entryTypes={{}};arr(D.entries).forEach(x=>entryTypes[x.entry_type]=(entryTypes[x.entry_type]||0)+1);document.getElementById('entry-summary').innerHTML=`<div class="structure-list">${{Object.entries(entryTypes).map(([k,v])=>`<div class="structure-item"><strong>${{esc(k)}}</strong><div class="muted">${{v}} 个入口</div></div>`).join('')}}</div>`;
const resultSelect=document.getElementById('path-result');[...new Set(arr(D.paths).map(p=>pathResult(p).classification||p.status))].forEach(k=>resultSelect.insertAdjacentHTML('beforeend',`<option value="${{esc(k)}}">${{esc(label(k))}}</option>`));
function renderPaths(){{const q=document.getElementById('search').value.toLowerCase(),r=resultSelect.value,s=document.getElementById('path-severity').value;const rows=arr(D.paths).filter(p=>{{const x=pathResult(p),state=x.classification||p.status,text=[p.path_id,p.branch_key,p.controlled_property,p.current_symbol,p.entry?.component,p.entry?.symbol,x.title].join(' ').toLowerCase();return(!q||text.includes(q))&&(!r||state===r)&&(!s||x.severity===s)}});document.getElementById('path-count').textContent=`显示 ${{rows.length}} / ${{arr(D.paths).length}} 条路径`;document.getElementById('path-body').innerHTML=rows.map(p=>{{const x=pathResult(p),state=x.classification||p.status;return`<tr class="path-row" data-path-id="${{esc(p.path_id)}}"><td>${{badge(state)}}</td><td>${{esc(x.severity||'-')}}</td><td><strong>${{esc(p.entry?.component||p.root_entry_id)}}</strong><br><code>${{esc(p.entry?.symbol||'')}}</code></td><td>${{esc(p.branch_key)}}</td><td><code>${{esc(p.controlled_property)}}</code></td><td>${{esc(x.operation_location||p.current_symbol)}}</td></tr>`}}).join('');document.querySelectorAll('.path-row').forEach(row=>row.onclick=()=>openPath(row.dataset.pathId));}}
['search','path-result','path-severity'].forEach(id=>document.getElementById(id).addEventListener(id==='search'?'input':'change',renderPaths));
function openPath(id){{const p=arr(D.paths).find(x=>x.path_id===id),x=pathResult(p);document.getElementById('drawer-title').textContent=x.title||`${{p.entry?.component||p.root_entry_id}} · ${{p.branch_key}}`;const refs=v=>arr(v).map(r=>`<code>${{esc(r)}}</code>`).join(' · ');const facts=arr(p.facts).map(v=>`<li><b>${{esc(v.fact_type)}} · ${{esc(v.body)}}</b><code>${{esc(v.location||'')}}</code>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</li>`).join('');const decisions=arr(p.assessments).map(v=>`<div class="structure-item"><strong>${{esc(v.pattern_id||v.category)}} · ${{badge(v.classification)}}</strong><div>${{esc(v.impact||v.demotion_reason||'')}}</div>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</div>`).join('');const checkNames={{externally_reachable:'外部可达',attacker_controlled:'关键参数可控',sink_reached:'到达敏感操作',guard_bypassed_or_absent:'防护缺失或可绕过',boundary_violated:'突破安全边界',concrete_impact:'存在具体影响'}};const checks=Object.entries(obj(x.exploitability||x.payload?.exploitability)).map(([k,v])=>`<div class="structure-item"><strong>${{esc(checkNames[k]||k)}}</strong><div class="muted">${{v?'满足':'不满足'}}</div></div>`).join('');const conclusion=x.impact||x.demotion_reason||x.payload?.conclusion;const gap=x.evidence_gap||x.payload?.evidence_gap;const boundary=x.security_boundary||x.payload?.security_boundary;const intent=x.business_intent||x.payload?.business_intent;const guards=arr(x.guards||x.payload?.guards).map(v=>`<div class="structure-item"><strong>${{esc(v.type)}} · ${{esc(v.effectiveness)}}</strong><div class="muted">${{esc(v.location||'')}} · 校验 ${{esc(v.validated_property)}}</div><div>${{esc(v.bypass_analysis?.reason||'')}}</div>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</div>`).join('');const counters=arr(x.counter_evidence||x.payload?.counter_evidence).map(v=>`<div class="structure-item"><strong>${{esc(v.kind)}}</strong><div>${{esc(v.reason)}}</div>${{arr(v.evidence_refs).length?`<div class="muted">证据：${{refs(v.evidence_refs)}}</div>`:''}}</div>`).join('');const evidence=refs(x.evidence_refs||x.evidence||x.payload?.evidence_refs);document.getElementById('drawer-body').innerHTML=`<dl class="kv"><dt>结果</dt><dd>${{badge(x.classification||p.status)}}</dd><dt>路径</dt><dd><code>${{esc(p.path_id)}}</code></dd><dt>入口</dt><dd>${{esc(p.entry?.symbol||p.root_entry_id)}}</dd><dt>分支</dt><dd>${{esc(p.branch_key)}}</dd><dt>受控参数</dt><dd><code>${{esc(p.controlled_property)}}</code></dd><dt>敏感操作</dt><dd><code>${{esc(x.operation_location||p.current_symbol)}}</code></dd><dt>安全边界</dt><dd>${{esc(boundary?.expected_boundary||x.boundary||'-')}}${{boundary?.reason?`<div class="muted">${{esc(boundary.reason)}}</div>`:''}}</dd></dl>${{conclusion?`<div class="panel"><h3>最终结论</h3><p>${{esc(conclusion)}}</p>${{gap?`<p><strong>证据缺口：</strong>${{esc(gap)}}</p>`:''}}${{evidence?`<p class="muted">判定证据：${{evidence}}</p>`:''}}</div>`:''}}${{intent?`<div class="panel"><h3>业务意图</h3><p>${{esc(intent.declared_or_inferred_purpose)}}</p></div>`:''}}${{checks?`<h3>六维有效性验证</h3><div class="structure-list">${{checks}}</div>`:''}}${{guards?`<h3>防护分析</h3><div class="structure-list">${{guards}}</div>`:''}}${{counters?`<h3>反证</h3><div class="structure-list">${{counters}}</div>`:''}}<h3>路径事实</h3><ol class="timeline">${{facts}}</ol><h3>安全判定</h3><div class="structure-list">${{decisions||'<div class="empty">未发现需要记录的安全场景</div>'}}</div>`;document.getElementById('drawer-backdrop').classList.add('open');}}
const closeDrawer=()=>document.getElementById('drawer-backdrop').classList.remove('open');document.getElementById('drawer-close').onclick=closeDrawer;document.getElementById('drawer-backdrop').onclick=e=>{{if(e.target.id==='drawer-backdrop')closeDrawer()}};
const A=obj(D.project.application);document.getElementById('project-info').innerHTML=[['Bundle Name',A.bundle_name],['版本',`${{A.version_name||'-'}} (${{A.version_code??'-'}})`],['厂商',A.vendor],['目标仓库',D.run.target_repo],['模块',D.project.summary?.modules],['组件',D.project.summary?.components]].map(([k,v])=>`<dt>${{esc(k)}}</dt><dd>${{esc(v??'-')}}</dd>`).join('');
const perms=[...arr(D.project.requested_permissions).map(x=>['申请权限',x]),...arr(D.project.defined_permissions).map(x=>['自定义权限',x])];const deps=arr(D.project.dependencies);document.getElementById('permission-list').innerHTML=perms.map(([k,x])=>`<div class="structure-item"><strong>${{esc(x.name)}}</strong><div class="muted">${{esc(k)}} · ${{esc(x.grant_mode||x.available_level||'')}}</div></div>`).join('')+deps.map(x=>`<div class="structure-item"><strong>${{esc(x.name)}} ${{esc(x.version||'')}}</strong><div class="muted">依赖 · ${{esc(x.group||'')}}</div></div>`).join('')||'<div class="empty">无权限与依赖信息</div>';
document.getElementById('module-list').innerHTML=arr(D.project.modules).map(x=>`<div class="structure-item"><strong>${{esc(x.name)}} · ${{esc(x.type)}}</strong><div class="muted">${{esc(x.source_scope||x.file)}} · ${{esc(arr(x.device_types).join(', '))}}</div></div>`).join('')||'<div class="empty">无模块信息</div>';document.getElementById('component-body').innerHTML=arr(D.project.components).map(x=>`<tr><td><strong>${{esc(x.name)}}</strong></td><td>${{esc(x.extension_type||x.kind)}}</td><td>${{esc(x.module_name)}}</td><td>${{x.exported===true?'是':x.exported===false?'否':'-'}}</td><td>${{esc(arr(x.permissions).join(', ')||'-')}}</td><td><code>${{esc(x.source_file_hint||x.src_entry||'-')}}</code></td></tr>`).join('');
const C=D.coverage,dc=obj(C.entry_dispositions),ac=obj(C.assessment_status),tc=obj(C.task_status),cc=obj(C.continuation_status);document.getElementById('coverage-metrics').innerHTML=metric(C.status,'覆盖状态')+metric(C.project_candidates,'项目候选入口')+metric(dc.resolved_entry||0,'已识别候选')+metric(dc.excluded||0,'已排除候选')+metric(dc.gap||0,'入口缺口')+metric(arr(C.gaps).length,'缺口与注记');document.getElementById('coverage-summary').innerHTML=`<div class="structure-item"><strong>安全判定</strong><div class="muted">漏洞 ${{ac.confirmed_vulnerability||0}} · 风险 ${{ac.residual_risk||0}} · 防护 ${{ac.protected_exposure||0}} · 正常 ${{ac.benign_business_flow||0}} · 缺证据 ${{ac.insufficient_evidence||0}}</div></div><div class="structure-item"><strong>跨边界追踪</strong><div class="muted">已完成 ${{cc.resolved||0}} · 待处理 ${{cc.open||0}} · 缺口 ${{cc.gap||0}}</div></div>`;document.getElementById('task-summary').innerHTML=Object.entries(tc).map(([k,v])=>`<div class="structure-item"><strong>${{esc(label(k))}}</strong><div class="muted">${{v}} 个任务</div></div>`).join('')||'<div class="empty">无任务信息</div>';document.getElementById('gap-list').innerHTML=arr(C.gaps).map(x=>`<div class="gap-item"><strong>${{esc(x.type)}} · ${{esc(x.subject)}}</strong><div>${{esc(x.description)}}</div></div>`).join('')||'<div class="empty">未发现覆盖缺口</div>';
renderPaths();
</script></body></html>'''
