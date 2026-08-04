import Database from "better-sqlite3";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";

const coverage = { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["onCreate"], operation_sites_checked: ["B.ets:20"], unresolved_targets: [] };
const call = (target: string) => ({
  call_key: "a-to-b", target_component_id: target, target_symbol: "B.onCreate", transport: "startAbility", call_location: "A.ets:10", condition: "always",
  parameter_mappings: [{ source_property: "want.input", target_property: "want.forwarded", control_state: "preserved", transform: "none" }],
  principal_transition: { caller_principal: "external", callee_observed_principal: "A", origin_binding: "replaced_by_caller", authority_used: "source_component", evidence_refs: [] }, security_checks: [], evidence_refs: [],
});
const group = {
  group_key: "query", category: "injection", capability_id: "CAP-INJ-001", title: "外部参数影响查询", operation: { body: "query", location: "B.ets:20" }, controlled_properties: ["want.forwarded"],
  context: { external_actor: "third-party app", intended_behavior: "query public records", protected_assets: ["private records"], observed_effect: "query executes", evidence_refs: [] },
  branches: [{ condition: "always", locations: ["B.ets:20"], evidence_refs: [] }], facts: [{ fact_key: "sink", type: "operation", body: "query", evidence_refs: [] }], edges: [], security_checks: [], evidence_refs: [],
};
const semantic = (task: Record<string, any>, calls: Record<string, unknown>[], groups: Record<string, unknown>[], customCoverage = coverage) => ({ task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked", coverage: customCoverage, operation_groups: groups, component_calls: calls, evidence: [] });

function confirmed(groupInput: Record<string, any>): Record<string, unknown> {
  const cross = groupInput.scope === "cross_component"; const principal = groupInput.principal_state as Record<string, unknown> | undefined;
  return {
    group_id: groupInput.group_id, capability_id: groupInput.capability_id, classification: "confirmed_vulnerability", title: "外部参数影响查询", security_check_outcome: "absent",
    business_intent: { is_public_api: true, declared_or_inferred_purpose: "query public records", allowed_controls: ["recordId"], evidence_refs: [] },
    security_boundary: { type: "data_owner", expected_boundary: "private records remain isolated", violation: true, reason: "input changes query structure", evidence_refs: [] },
    ...(cross ? { principal_analysis: { origin_principal: principal!.origin_principal, target_observed_principal: principal!.target_observed_principal, authority_used: principal!.authority_used, security_check_subjects: [], origin_bound_to_observed_principal: principal!.origin_binding === "preserved", delegation_risk: principal!.origin_binding === "replaced_by_caller", reason: "deterministic path identity", evidence_refs: [] } } : {}),
    exploitability: { externally_reachable: true, attacker_controlled: true, sink_reached: true, security_check_bypassed_or_absent: true, boundary_violated: true, concrete_impact: true },
    counter_evidence: [], impact: "读取私有记录", severity: cross ? "critical" : "high", cwe: "CWE-89", poc: "demo://query?q=x", evidence_refs: [],
  };
}

async function twoComponentStore(): Promise<{ store: AuditStore; model: Awaited<ReturnType<typeof profileProject>> }> {
  const root = await mkdtemp(join(tmpdir(), "harmony-report-")); await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }, { name: 'B', exported: false }] } }`);
  const model = await profileProject(root); return { store: await AuditStore.create(root, model, { capabilities: ["CAP-INJ-001"], components: ["A"] }), model };
}

describe("deterministic reporting", () => {
  it("validates only the externally reachable cross-component group and emits stable artifacts", async () => {
    const { store, model } = await twoComponentStore(); const b = String(model.components.find((item) => item.name === "B")!.component_id);
    const [aTask] = (await store.claim(1)).tasks; store.reconcile(aTask!.task_id, aTask!.attempt, semantic(aTask as Record<string, any>, [call(b)], []));
    const [bTask] = (await store.claim(1)).tasks; store.reconcile(bTask!.task_id, bTask!.attempt, semantic(bTask as Record<string, any>, [], [group]));
    const [validationTask] = (await store.claim(5)).tasks.filter((task) => task.kind === "exploitability_validation");
    const groups = validationTask!.input.operation_groups as Record<string, any>[];
    expect(groups.map((item) => item.scope ?? "local").sort()).toEqual(["cross_component"]);
    const submittedValidations = groups.map(confirmed) as Record<string, any>[];
    submittedValidations[0]!.principal_analysis.origin_principal = "model-guessed-principal";
    submittedValidations[0]!.principal_analysis.origin_bound_to_observed_principal = true;
    submittedValidations[0]!.principal_analysis.delegation_risk = false;
    const result = { task_id: validationTask!.task_id, entry_id: validationTask!.input.entry_id, summary: "confirmed", validations: submittedValidations, evidence: [] };
    expect(store.reconcile(validationTask!.task_id, validationTask!.attempt, result)).toMatchObject({ accepted: true });
    const [pocTask] = (await store.claim(5)).tasks;
    expect(pocTask!.kind).toBe("poc_generation");
    expect(store.reconcile(pocTask!.task_id, pocTask!.attempt, {
      task_id: pocTask!.task_id, finding_id: String(pocTask!.input.finding.finding_id), entry_type: "want",
      trigger: { kind: "ability_want", payload: { action: "ohos.intent.action.QUERY", uri: "demo://query?q=x" } },
      language: "arkts", code: "startAbility({ want: { action: 'ohos.intent.action.QUERY', uri: 'demo://query?q=x' } })",
      prerequisites: [], expected_observation: "返回私有记录", limitations: "未在真机验证", evidence: [], evidence_refs: [],
    })).toMatchObject({ accepted: true });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM findings").get() as { n: number }).n).toBe(1);
    expect((db.prepare("SELECT COUNT(*) n FROM finding_causes").get() as { n: number }).n).toBe(1);
    const storedValidation = JSON.parse((db.prepare("SELECT payload_json FROM validation_results").get() as { payload_json: string }).payload_json) as Record<string, any>;
    expect(storedValidation.principal_analysis).toMatchObject({
      origin_principal: groups[0]!.principal_state.origin_principal,
      origin_bound_to_observed_principal: false,
      delegation_risk: true,
    });
    db.close();

    const report = await store.finalize();
    expect((report.summary as Record<string, unknown>)).toMatchObject({ findings: 1, operation_groups: 2, validations: 1, coverage_gaps: 0 });
    expect(report).toMatchObject({ schema_version: 2, project: { schema_version: 2 } });
    expect(report.component_results).toEqual(expect.arrayContaining([expect.objectContaining({ component_name: "A", function_summary: "checked" })]));
    expect((report.findings as Record<string, unknown>[])[0]).toMatchObject({ severity: "critical", causes: [expect.any(String)] });
    const before = await Promise.all([store.paths.reportJson, store.paths.reportMarkdown, store.paths.reportHtml, store.paths.attackMatrixJson].map((path) => readFile(path, "utf8")));
    const tamper = new Database(store.paths.db); tamper.prepare("UPDATE tasks SET result_json='not-a-report-source'").run(); tamper.close();
    await store.finalize();
    const after = await Promise.all([store.paths.reportJson, store.paths.reportMarkdown, store.paths.reportHtml, store.paths.attackMatrixJson].map((path) => readFile(path, "utf8")));
    expect(after).toEqual(before);
    expect(JSON.parse(after[3]!).rows).toHaveLength(2);
    expect(after[1]).toContain("## 2. 需要处置的安全发现");
    expect(after[1]).toContain("#### 六维有效性验证");
    expect(after[1]).toContain("## 3. 组件审计结果");
    expect(after[2]).toContain("data-view=\"components\"");
    expect(after[2]).toContain("六维有效性验证");
    expect(after[2]).toContain("项目结构");
  });

  it("marks uncertain and unresolved coverage complete_with_gaps", async () => {
    const { store } = await twoComponentStore(); const [task] = (await store.claim(1)).tasks;
    const uncertain = { entry_status: "uncertain", entry_notes: ["callback unresolved"], entry_symbols_checked: [], operation_sites_checked: [], unresolved_targets: ["DynamicTarget"] };
    store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>, [], [], uncertain));
    const report = await store.finalize(); const gaps = (report.coverage as Record<string, unknown>).gaps as Record<string, unknown>[];
    expect((report.run as Record<string, unknown>).status).toBe("complete_with_gaps");
    expect(gaps.map((gap) => gap.kind)).toEqual(["uncertain_entry", "unresolved_targets"]);
  });

  it("isolates validation failures per operation group and keeps active groups out of coverage gaps", async () => {
    const { store } = await twoComponentStore(); const [semanticTask] = (await store.claim(1)).tasks;
    const secondGroup = structuredClone(group); secondGroup.group_key = "query-secondary"; secondGroup.title = "第二个查询";
    secondGroup.operation = { body: "querySecondary", location: "A.ets:30" };
    expect(store.reconcile(semanticTask!.task_id, semanticTask!.attempt, semantic(semanticTask as Record<string, any>, [], [group, secondGroup]))).toMatchObject({ accepted: true });

    const validationTasks = (await store.claim(5)).tasks.filter((task) => task.kind === "exploitability_validation");
    expect(validationTasks).toHaveLength(2);
    expect(validationTasks.every((task) => (task.input.operation_groups as unknown[]).length === 1)).toBe(true);
    expect(store.status()).toMatchObject({ coverage_gaps: [], pending_validation_groups: 2 });

    const [failedTask, successfulTask] = validationTasks;
    expect(store.reconcile(failedTask!.task_id, failedTask!.attempt, undefined, "model_failed")).toMatchObject({ status: "queued" });
    for (let retry = 0; retry < 2; retry += 1) {
      const [task] = (await store.claim(1)).tasks;
      expect(task!.task_id).toBe(failedTask!.task_id);
      store.reconcile(task!.task_id, task!.attempt, undefined, "model_failed");
    }
    const successfulGroup = (successfulTask!.input.operation_groups as Record<string, any>[])[0]!;
    expect(store.reconcile(successfulTask!.task_id, successfulTask!.attempt, {
      task_id: successfulTask!.task_id, entry_id: successfulTask!.input.entry_id, summary: "confirmed", validations: [confirmed(successfulGroup)], evidence: [],
    })).toMatchObject({ accepted: true });

    const status = store.status(); const gaps = status.coverage_gaps as Record<string, unknown>[];
    expect(status.pending_validation_groups).toBe(0);
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toMatchObject({ kind: "unvalidated_operation_group", details: { task_status: "exhausted", attempts: 3, error: "model_failed" } });
  });

  it("splits a resumed legacy batch validation task into group-scoped tasks", async () => {
    const { store } = await twoComponentStore(); const [semanticTask] = (await store.claim(1)).tasks;
    const secondGroup = structuredClone(group); secondGroup.group_key = "query-secondary"; secondGroup.operation = { body: "querySecondary", location: "A.ets:30" };
    store.reconcile(semanticTask!.task_id, semanticTask!.attempt, semantic(semanticTask as Record<string, any>, [], [group, secondGroup]));

    const db = new Database(store.paths.db); const stamp = new Date().toISOString(); const entryId = String(semanticTask!.input.entry.candidate_id);
    const groups = (db.prepare("SELECT payload_json FROM operation_groups ORDER BY group_id").all() as { payload_json: string }[]).map((row) => JSON.parse(row.payload_json));
    db.prepare(`INSERT INTO tasks(task_id,run_id,semantic_key,kind,subject_id,status,attempts,input_json,error,created_at,updated_at)
      VALUES (?,?,?,?,?,'exhausted',3,?,'legacy_batch_failed',?,?)`).run(
      "TASK-legacy-validation", store.runId(), `validation:${entryId}`, "exploitability_validation", entryId,
      JSON.stringify({ verification_scope: { target_repo: store.paths.root }, entry_id: entryId, operation_groups: groups }), stamp, stamp,
    );
    db.close();

    expect(store.resume()).toMatchObject({ retried_tasks: 1 });
    const validationTasks = (await store.claim(5)).tasks.filter((task) => task.kind === "exploitability_validation");
    expect(validationTasks).toHaveLength(2);
    expect(validationTasks.every((task) => (task.input.operation_groups as unknown[]).length === 1)).toBe(true);
    const check = new Database(store.paths.db);
    expect(check.prepare("SELECT status,error FROM tasks WHERE task_id='TASK-legacy-validation'").get()).toEqual({ status: "cancelled", error: "superseded_by_group_validation_tasks" });
    check.close();
    expect(store.status()).toMatchObject({ coverage_gaps: [], pending_validation_groups: 2 });
  });
});
