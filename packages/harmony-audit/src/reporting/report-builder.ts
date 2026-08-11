import type Database from "better-sqlite3";

type Row = Record<string, unknown>;
const parse = (value: unknown): unknown => typeof value === "string" ? JSON.parse(value) : value;
const object = (value: unknown): Row => value && typeof value === "object" && !Array.isArray(value) ? value as Row : {};

export interface CoverageGap { readonly kind: string; readonly subject_id: string; readonly details: unknown; }

function operationGroups(inputJson: string): Row[] {
  const input = object(parse(inputJson));
  return Array.isArray(input.operation_groups) ? input.operation_groups as Row[] : [];
}

export function pendingValidationGroupCount(db: Database.Database): number {
  const validated = new Set((db.prepare("SELECT group_id FROM validation_results").all() as { group_id: string }[]).map((row) => row.group_id));
  const active = db.prepare("SELECT input_json FROM tasks WHERE kind='exploitability_validation' AND status IN ('queued','running')").all() as { input_json: string }[];
  return active.flatMap((task) => operationGroups(task.input_json)).filter((group) => group.group_id && !validated.has(String(group.group_id))).length;
}

export function collectCoverageGaps(db: Database.Database): CoverageGap[] {
  const gaps: CoverageGap[] = [];
  // A terminal validation task is represented by its missing operation group(s)
  // below. Counting the task as well would report the same root cause twice.
  // PoC generation is a delivery enhancement, not a gate: an exhausted poc task
  // leaves the run complete and surfaces as "未生成 PoC" in the finding report.
  for (const task of db.prepare("SELECT task_id,kind,subject_id,attempts,error FROM tasks WHERE status='exhausted' AND kind NOT IN ('exploitability_validation','poc_generation') ORDER BY task_id").all() as Row[]) gaps.push({ kind: "exhausted_task", subject_id: String(task.task_id), details: task });
  for (const row of db.prepare("SELECT s.entry_id,s.coverage_json FROM semantic_analyses s ORDER BY s.entry_id").all() as { entry_id: string; coverage_json: string }[]) {
    const coverage = object(parse(row.coverage_json)); const unresolved = Array.isArray(coverage.unresolved_targets) ? coverage.unresolved_targets : [];
    if (coverage.entry_status === "uncertain") gaps.push({ kind: "uncertain_component_input", subject_id: row.entry_id, details: coverage.entry_notes ?? [] });
    if (coverage.external_entry_status === "uncertain") gaps.push({ kind: "uncertain_external_entry", subject_id: row.entry_id, details: coverage.entry_notes ?? [] });
    if (unresolved.length) gaps.push({ kind: "unresolved_targets", subject_id: row.entry_id, details: unresolved });
  }
  const requiredGroups = new Map<string, Row>();
  const terminalTasks = db.prepare(`SELECT task_id,status,attempts,error,input_json FROM tasks
    WHERE kind='exploitability_validation' AND status NOT IN ('queued','running')
      AND NOT (status='cancelled' AND error='superseded_by_group_validation_tasks')
    ORDER BY task_id`).all() as Row[];
  for (const task of terminalTasks) {
    for (const group of operationGroups(String(task.input_json))) if (group.group_id) requiredGroups.set(String(group.group_id), {
      task_id: task.task_id, task_status: task.status, attempts: task.attempts, error: task.error,
    });
  }
  const validated = new Set((db.prepare("SELECT group_id FROM validation_results").all() as { group_id: string }[]).map((row) => row.group_id));
  for (const [groupId, details] of [...requiredGroups].filter(([id]) => !validated.has(id)).sort(([left], [right]) => left.localeCompare(right))) gaps.push({ kind: "unvalidated_operation_group", subject_id: groupId, details });
  return gaps;
}

const classificationRank = ["confirmed_vulnerability", "residual_risk", "insufficient_evidence", "protected_exposure", "no_exploitable_path", "benign_business_flow"];

function componentStatus(entryId: string, coverage: Row, groups: Row[]): string {
  const classifications = new Set(groups.filter((group) => group.entry_id === entryId).map((group) => String(group.classification ?? "verification_incomplete")));
  for (const value of classificationRank) if (classifications.has(value)) return value;
  if (coverage.external_entry_status === "excluded") return "external_entry_excluded";
  if (classifications.has("verification_incomplete")) return "verification_incomplete";
  if (coverage.entry_status === "excluded") return "entry_excluded";
  if (coverage.entry_status === "uncertain") return "entry_uncertain";
  return "no_security_relevant_operation";
}

export function buildReportModel(db: Database.Database, status: "complete" | "complete_with_gaps" | "failed" | "cancelled" | "running", projectModel: Row = {}): Row {
  const run = db.prepare("SELECT run_id,target_repo,project_model_version,audit_scope_json,created_at FROM runs").get() as Row;
  const taskCounts = Object.fromEntries((db.prepare("SELECT status,COUNT(*) count FROM tasks GROUP BY status ORDER BY status").all() as { status: string; count: number }[]).map((row) => [row.status, row.count]));
  const entries = (db.prepare(`SELECT e.entry_id,e.component_id,e.payload_json,s.semantic_analysis_id,s.summary analysis_summary,s.coverage_json,t.status task_status
    FROM entries e LEFT JOIN semantic_analyses s ON s.entry_id=e.entry_id LEFT JOIN tasks t ON t.task_id=s.task_id
    WHERE EXISTS (SELECT 1 FROM tasks scope_task WHERE scope_task.subject_id=e.entry_id AND scope_task.kind='component_semantic_analysis') ORDER BY e.entry_id`).all() as Row[]).map((row) => ({
      entry_id: row.entry_id, component_id: row.component_id, entry: parse(row.payload_json), semantic_analysis_id: row.semantic_analysis_id ?? null,
      task_status: row.task_status ?? "not_analyzed", analysis_summary: row.analysis_summary ?? null, coverage: row.coverage_json ? parse(row.coverage_json) : null,
    }));
  const evidence: Row[] = (db.prepare("SELECT evidence_id,producer_task_id,local_evidence_id,source,kind,location,content_sha256,payload_json FROM evidence ORDER BY evidence_id").all() as Row[]).map((row) => { const { payload_json: payloadJson, ...rest } = row; return { ...rest, payload: parse(payloadJson) }; });
  const groups: Row[] = (db.prepare(`SELECT g.group_id,g.semantic_analysis_id,g.capability_id,g.category,g.title,g.payload_json,s.entry_id,c.path_id,c.local_group_id
    FROM operation_groups g JOIN semantic_analyses s ON s.semantic_analysis_id=g.semantic_analysis_id
    LEFT JOIN cross_component_groups c ON c.group_id=g.group_id ORDER BY g.group_id`).all() as Row[]).map((row) => ({
      group_id: row.group_id, semantic_analysis_id: row.semantic_analysis_id, entry_id: row.entry_id, capability_id: row.capability_id,
      category: row.category, title: row.title, scope: row.path_id ? "cross_component" : "local", path_id: row.path_id ?? null,
      local_group_id: row.local_group_id ?? null, payload: parse(row.payload_json),
    }));
  const validations: Row[] = (db.prepare("SELECT validation_id,task_id,group_id,classification,capability_id,payload_json FROM validation_results ORDER BY validation_id").all() as Row[]).map((row) => { const { payload_json: payloadJson, ...rest } = row; return { ...rest, payload: parse(payloadJson) }; });
  const requiredGroupIds = new Set((db.prepare("SELECT input_json FROM tasks WHERE kind='exploitability_validation' AND NOT (status='cancelled' AND error='superseded_by_group_validation_tasks')").all() as { input_json: string }[])
    .flatMap((task) => operationGroups(task.input_json)).map((group) => String(group.group_id)));
  const validationByGroup = new Map(validations.map((validation) => [String(validation.group_id), validation]));
  for (const group of groups) {
    const validation = validationByGroup.get(String(group.group_id));
    group.classification = validation?.classification
      ?? (requiredGroupIds.has(String(group.group_id)) ? "verification_incomplete" : "not_externally_reachable");
    group.validation = validation ?? null;
  }
  const findings: Row[] = (db.prepare("SELECT finding_id,root_cause_key,title,classification,severity,cwe,impact,payload_json FROM findings ORDER BY finding_id").all() as Row[]).map((row) => {
    const { payload_json: payloadJson, ...rest } = row; return { ...rest, payload: parse(payloadJson),
      causes: (db.prepare("SELECT validation_id FROM finding_causes WHERE finding_id=? ORDER BY validation_id").all(row.finding_id) as { validation_id: string }[]).map((cause) => cause.validation_id) };
  });
  const pocArtifacts: Row[] = (db.prepare("SELECT poc_id,finding_id,entry_type,payload_json FROM poc_artifacts ORDER BY poc_id").all() as Row[]).map((row) => { const { payload_json: payloadJson, ...rest } = row; return { ...rest, payload: parse(payloadJson) }; });
  const pocByFinding = new Map<string, Row>();
  for (const poc of pocArtifacts) if (!pocByFinding.has(String(poc.finding_id))) pocByFinding.set(String(poc.finding_id), poc);
  const pocTaskByFinding = new Map((db.prepare("SELECT subject_id,status FROM tasks WHERE kind='poc_generation' ORDER BY created_at").all() as { subject_id: string; status: string }[]).map((task) => [task.subject_id, task.status]));
  for (const finding of findings) {
    const poc = pocByFinding.get(String(finding.finding_id));
    const payload = object(poc?.payload);
    const taskStatus = pocTaskByFinding.get(String(finding.finding_id));
    finding.poc_artifact = poc ?? null;
    finding.poc_status = payload.assurance_status
      ?? (taskStatus === "exhausted" ? "generation_failed" : ["queued", "running"].includes(taskStatus ?? "") ? "pending_generation" : null);
  }
  const paths: Row[] = (db.prepare("SELECT path_id,root_entry_id,target_entry_id,fingerprint,cycle,payload_json FROM component_paths ORDER BY path_id").all() as Row[]).map((row) => { const { payload_json: payloadJson, ...rest } = row; return { ...rest, cycle: Boolean(row.cycle), payload: parse(payloadJson) }; });
  const componentCalls: Row[] = (db.prepare(`SELECT c.component_call_id,c.semantic_analysis_id,c.target_component_id,c.payload_json,s.entry_id source_entry_id
    FROM component_calls c JOIN semantic_analyses s ON s.semantic_analysis_id=c.semantic_analysis_id ORDER BY c.component_call_id`).all() as Row[]).map((row) => { const { payload_json: payloadJson, ...rest } = row; return { ...rest, payload: parse(payloadJson) }; });
  const gaps = collectCoverageGaps(db);
  const attackMatrix = groups.map((group) => {
    const validation = validations.find((item) => item.group_id === group.group_id);
    const finding = findings.find((item) => (item.causes as string[]).includes(String(validation?.validation_id)));
    return {
      entry_id: group.entry_id, group_id: group.group_id, scope: group.scope, path_id: group.path_id,
      capability_id: group.capability_id, category: group.category, validation_id: validation?.validation_id ?? null,
      classification: validation?.classification ?? "not_validated", finding_id: finding?.finding_id ?? null,
    };
  });
  const componentResults = entries.map((entry) => {
    const coverage = object(entry.coverage); const relatedGroups = groups.filter((group) => group.entry_id === entry.entry_id);
    const notes: string[] = [];
    if (!entry.semantic_analysis_id) notes.push("组件语义分析未完成，当前结论不能视为安全证明。");
    if (coverage.entry_status === "uncertain") notes.push("组件输入状态仍不确定，需要人工核对触发方式与回调实现。");
    if (coverage.external_entry_status === "uncertain") notes.push("外部入口状态仍不确定，本次不会把该组件作为攻击路径起点。");
    if (Array.isArray(coverage.unresolved_targets) && coverage.unresolved_targets.length) notes.push("存在未解析调用目标，可能影响跨组件覆盖完整性。");
    if (entry.semantic_analysis_id && !relatedGroups.length) notes.push("已检查范围内未识别到安全相关操作，建议结合组件业务功能复核。");
    const payload = object(entry.entry);
    return {
      entry_id: entry.entry_id, component_id: entry.component_id, component_name: payload.component_name ?? entry.component_id,
      module_name: payload.module_name ?? null, module_id: payload.module_id ?? null, source: payload.src_entry ?? payload.location ?? null,
      exported: payload.exported ?? null, initial_scope: payload.initial_scope ?? false, facets: payload.project_candidates ?? [],
      status: componentStatus(String(entry.entry_id), coverage, groups), function_summary: entry.analysis_summary ?? "组件语义分析未完成",
      coverage, operation_groups: relatedGroups, paths: paths.filter((path) => path.root_entry_id === entry.entry_id || path.target_entry_id === entry.entry_id),
      outgoing_calls: componentCalls.filter((call) => call.source_entry_id === entry.entry_id), review_notes: notes,
    };
  });
  const classificationCounts: Row = {};
  for (const validation of validations) classificationCounts[String(validation.classification)] = Number(classificationCounts[String(validation.classification)] ?? 0) + 1;
  const severityCounts: Row = {};
  for (const finding of findings) severityCounts[String(finding.severity)] = Number(severityCounts[String(finding.severity)] ?? 0) + 1;
  return {
    schema_version: 2,
    run: { run_id: run.run_id, target_repo: run.target_repo, status, project_model_version: run.project_model_version, audit_scope: parse(run.audit_scope_json), created_at: run.created_at },
    project: projectModel,
    summary: { entries: entries.length, analyzed_components: entries.filter((entry) => entry.semantic_analysis_id).length, paths: paths.length, component_calls: componentCalls.length, operation_groups: groups.length, validations: validations.length, findings: findings.length, poc_artifacts: pocArtifacts.length, coverage_gaps: gaps.length, evidence: evidence.length, classifications: classificationCounts, severities: severityCounts },
    task_counts: taskCounts, coverage: { status: gaps.length ? "partial" : "complete", entries, gaps }, component_results: componentResults,
    component_calls: componentCalls, paths, operation_groups: groups, validations, findings, evidence, pocs: pocArtifacts, attack_matrix: attackMatrix,
  };
}

export function attackMatrixDocument(report: Row): Row {
  return { schema_version: 1, run_id: object(report.run).run_id, rows: report.attack_matrix };
}
