import Database from "better-sqlite3";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";
import { validatePocSubmission } from "../src/validation/submission-validator.js";
import { admissibleRefs, effectChain, evidenceRow, sixDimensions, support } from "./p0-fixtures.js";

async function fixture(abilities = `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`, components: string[] = ["A"]): Promise<{ root: string; store: AuditStore }> {
  const root = await mkdtemp(join(tmpdir(), "harmony-poc-"));
  await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), abilities);
  return { root, store: await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-INJ-001"], components }) };
}

const semanticEvidence = () => [evidenceRow("entry reaches query")];

const semantic = (task: Record<string, any>) => ({
  task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked",
  coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["A.onNewWant"], operation_sites_checked: ["A.ets:12"], unresolved_targets: [] }, component_calls: [],
  operation_groups: [{
    group_key: "query", category: "injection", capability_id: "CAP-INJ-001", title: "query injection",
    operation: { body: "query", location: "A.ets:12", evidence: semanticEvidence() }, controlled_properties: ["want.query"],
    context: { external_actor: "third-party app", intended_behavior: "open public data", protected_assets: ["private data"], direct_observed_effect: "query executes", effect_hypotheses: [], evidence: semanticEvidence() },
    branches: [{ condition: "always", locations: ["A.ets:10"], evidence: semanticEvidence() }], security_checks: [],
    facts: [{ fact_key: "entry", type: "entrypoint", body: "external", evidence: semanticEvidence() }, { fact_key: "sink", type: "operation", body: "query", evidence: semanticEvidence() }],
  }],
});

const validation = (task: Record<string, any>, severity = "high") => {
  const group = task.input.operation_groups[0];
  const refs = admissibleRefs(group);
  const cross = group.scope === "cross_component"; const principal = group.principal_state as Record<string, any> | undefined;
  return {
    task_id: task.task_id, entry_id: task.input.entry_id, summary: "confirmed",
    validations: [{
      group_id: group.group_id, capability_id: group.capability_id, classification: "confirmed_vulnerability", title: "query injection",
      security_check_outcome: "absent",
      business_intent: { is_public_api: true, declared_or_inferred_purpose: "open public data", allowed_controls: ["id"], evidence: support(refs) },
      security_boundary: { type: "data_owner", expected_boundary: "private data is isolated", reason: "query crosses owner boundary", evidence: support(refs) },
      ...(cross ? { principal_analysis: { origin_principal: principal!.origin_principal, target_observed_principal: principal!.target_observed_principal, authority_used: principal!.authority_used, security_check_subjects: [], origin_bound_to_observed_principal: principal!.origin_binding === "preserved", delegation_risk: principal!.origin_binding === "replaced_by_caller", reason: "deterministic path identity", evidence: support(refs) } } : {}),
      exploitability: sixDimensions({}, refs), effect_chain: effectChain(refs),
      counter_evidence: [], impact: "private data disclosure", severity, cwe: "CWE-89", evidence: support(refs),
    }],
  };
};

const poc = (task: Record<string, any>, overrides: Record<string, unknown> = {}) => ({
  task_id: task.task_id, finding_id: String(task.input.finding.finding_id), entry_type: "want",
  trigger: { kind: "ability_want", payload: { action: "ohos.intent.action.QUERY", uri: "demo://x?q=1" } },
  language: "arkts", code: "startAbility({ want: { action: 'ohos.intent.action.QUERY', uri: 'demo://x?q=1' } })",
  prerequisites: ["安装 debug 包"], expected_observation: "返回越权数据", limitations: "未在真机验证",
  execution_hint: { step_by_step: ["安装 debug 包", "运行代码"], device_required: "emulator", network_required: false },
  symbol_refs: [], evidence_refs: [],
  ...overrides,
});

async function confirmedStore(): Promise<{ store: AuditStore; pocTask: Record<string, any> }> {
  const { store } = await fixture();
  const [semanticTask] = (await store.claim(1)).tasks;
  expect(store.reconcile(semanticTask!.task_id, semanticTask!.attempt, semantic(semanticTask as Record<string, any>))).toMatchObject({ accepted: true });
  const [validationTask] = (await store.claim(1)).tasks;
  expect(validationTask!.kind).toBe("exploitability_validation");
  expect(store.reconcile(validationTask!.task_id, validationTask!.attempt, validation(validationTask as Record<string, any>))).toMatchObject({ accepted: true });
  const [pocTask] = (await store.claim(1)).tasks;
  // The claimed handle carries a lightweight seed; the full task document is rebuilt at claim time.
  return { store, pocTask: await store.taskDocument(pocTask as never) as Record<string, any> };
}

describe("poc generation phase", () => {
  it("schedules a poc task only after a confirmed finding and persists a structured artifact", async () => {
    const { store, pocTask } = await confirmedStore();
    expect(pocTask).toBeDefined();
    expect(pocTask.kind).toBe("poc_generation");
    expect(pocTask.input).toMatchObject({ finding: { finding_id: expect.any(String) }, verification_scope: { target_repo: expect.any(String) } });
    expect(pocTask.input.inherited_evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ evidence_id: expect.any(String), summary: "六维阶段重新读取并核验完整效果链" }),
      expect.objectContaining({ evidence_id: expect.any(String), summary: "entry reaches query" }),
    ]));
    expect(store.reconcile(pocTask.task_id, pocTask.attempt, poc(pocTask))).toMatchObject({ accepted: true });
    const report = await store.finalize();
    expect(report.summary).toMatchObject({ findings: 1, poc_artifacts: 1 });
    const finding = (report.findings as Record<string, unknown>[])[0]!;
    expect(finding).toMatchObject({
      poc_status: "generated_unverified",
      poc_artifact: { entry_type: "want", payload: expect.objectContaining({ code: expect.stringContaining("startAbility"), expected_observation: "返回越权数据", assurance_status: "generated_unverified" }) },
    });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM poc_artifacts").get() as { n: number }).n).toBe(1);
    expect((db.pragma("foreign_key_check") as unknown[])).toHaveLength(0);
    db.close();
    const markdown = await readFile(store.paths.reportMarkdown, "utf8");
    expect(markdown).toContain("#### 验证方式 / PoC");
    expect(markdown).toContain("已生成，未编译验证");
    expect(markdown).toContain("入口类型");
    expect(markdown).toContain("逐步复现");
    expect(await readFile(store.paths.reportHtml, "utf8")).toContain("预期现象");
  });

  it("rejects a poc whose entry_type does not match the entry facets", async () => {
    const { store, pocTask } = await confirmedStore();
    const outcome = store.reconcile(pocTask.task_id, pocTask.attempt, poc(pocTask, { entry_type: "common_event" }));
    expect(outcome).toMatchObject({ accepted: false, status: "queued", error_code: "POC_ENTRY_TYPE_MISMATCH" });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM poc_artifacts").get() as { n: number }).n).toBe(0);
    db.close();
  });

  it("rejects a poc without runnable code", async () => {
    const { store, pocTask } = await confirmedStore();
    const outcome = store.reconcile(pocTask.task_id, pocTask.attempt, poc(pocTask, { code: "   " }));
    expect(outcome).toMatchObject({ accepted: false, status: "queued", error_code: "SCHEMA_INVALID" });
  });

  it("rejects a poc that omits required reproducibility fields", async () => {
    const { store, pocTask } = await confirmedStore();
    const candidate = poc(pocTask);
    delete candidate.limitations;
    delete candidate.prerequisites;
    expect(store.reconcile(pocTask.task_id, pocTask.attempt, candidate))
      .toMatchObject({ accepted: false, status: "queued", error_code: "SCHEMA_INVALID" });
  });

  it("rejects placeholder code instead of a runnable snippet", async () => {
    const { store, pocTask } = await confirmedStore();
    const outcome = store.reconcile(pocTask.task_id, pocTask.attempt, poc(pocTask, { code: "startAbility({ want: { uri: '略' } })" }));
    expect(outcome).toMatchObject({ accepted: false, status: "queued", error_code: "POC_PLACEHOLDER_FOUND" });
  });

  it("rejects re-judgement fields that belong to the validation phase", async () => {
    const { store, pocTask } = await confirmedStore();
    // schema-level guard fires first on the store path
    expect(store.reconcile(pocTask.task_id, pocTask.attempt, poc(pocTask, { severity: "critical", classification: "confirmed_vulnerability" })))
      .toMatchObject({ accepted: false, status: "queued", error_code: "SCHEMA_INVALID" });
    // validator-level guard remains for direct callers
    const candidate = poc(pocTask, { severity: "critical", classification: "confirmed_vulnerability" });
    expect(() => validatePocSubmission(candidate, { taskId: candidate.task_id, entryId: "PE-1", findingId: String(candidate.finding_id), allowedEntryTypes: new Set(["want"]), allowedEvidence: new Set() }))
      .toThrowError(expect.objectContaining<Partial<{ code: string }>>({ code: "POC_FORBIDDEN_OUTPUT" }));
    const assurance = poc(pocTask, { assurance_status: "device_verified" });
    expect(() => validatePocSubmission(assurance, { taskId: assurance.task_id, entryId: "PE-1", findingId: String(assurance.finding_id), allowedEntryTypes: new Set(["want"]), allowedEvidence: new Set() }))
      .toThrowError(expect.objectContaining<Partial<{ code: string }>>({ code: "POC_FORBIDDEN_OUTPUT" }));
  });

  it("enforces trigger form consistency: shell must be a real command, arkts must not be adb_shell", async () => {
    const { store, pocTask } = await confirmedStore();
    expect(store.reconcile(pocTask.task_id, pocTask.attempt, poc(pocTask, { language: "shell", code: "startAbility({})" })))
      .toMatchObject({ accepted: false, status: "queued", error_code: "POC_SHELL_COMMAND_REQUIRED" });
    const db0 = new Database(store.paths.db);
    db0.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(pocTask.task_id);
    db0.close();
    const [secondHandle] = (await store.claim(1)).tasks;
    const second = await store.taskDocument(secondHandle as never);
    expect(store.reconcile(second.task_id, second.attempt, poc(second as Record<string, any>, { trigger: { kind: "adb_shell", payload: { command: "ls" } } })))
      .toMatchObject({ accepted: false, status: "queued", error_code: "POC_ARKTS_TRIGGER_MISMATCH" });
    const db1 = new Database(store.paths.db);
    db1.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(second.task_id);
    db1.close();
    const [thirdHandle] = (await store.claim(1)).tasks;
    const third = await store.taskDocument(thirdHandle as never);
    expect(store.reconcile(third.task_id, third.attempt, poc(third as Record<string, any>, {
      language: "shell", trigger: { kind: "ability_want", payload: { uri: "demo://x" } },
      code: "hdc shell aa start -a ohos.intent.action.VIEW -d 'demo://x'",
    }))).toMatchObject({ accepted: true });
  });

  it("rejects unknown evidence refs and unbound symbol refs in poc submissions", () => {
    const base = { task_id: "TASK-1", finding_id: "FIND-1", entry_type: "want", trigger: { kind: "ability_want", payload: { action: "x" } }, language: "arkts", code: "startAbility({})", expected_observation: "x", evidence_refs: ["EV-missing"] };
    expect(() => validatePocSubmission(base, { taskId: "TASK-1", entryId: "PE-1", findingId: "FIND-1", allowedEntryTypes: new Set(["want"]), allowedEvidence: new Set() }))
      .toThrowError(expect.objectContaining<Partial<{ code: string }>>({ code: "UNKNOWN_EVIDENCE_REF" }));
    expect(() => validatePocSubmission({ ...base, evidence_refs: [], symbol_refs: [{ symbol: "RecordAbility.onNewWant", evidence: [], verified_by: "atlas_symbol" }] }, { taskId: "TASK-1", entryId: "PE-1", findingId: "FIND-1", allowedEntryTypes: new Set(["want"]), allowedEvidence: new Set() }))
      .toThrowError(expect.objectContaining<Partial<{ code: string }>>({ code: "SYMBOL_REF_EVIDENCE_MISSING" }));
  });

  it("does not schedule poc generation for demoted validations", async () => {
    const { store } = await fixture();
    const [semanticTask] = (await store.claim(1)).tasks;
    expect(store.reconcile(semanticTask!.task_id, semanticTask!.attempt, semantic(semanticTask as Record<string, any>))).toMatchObject({ accepted: true });
    const [validationTask] = (await store.claim(1)).tasks;
    const demoted = {
      task_id: validationTask!.task_id, entry_id: validationTask!.input.entry_id, summary: "not exploitable",
      validations: [{
        group_id: (validationTask!.input.operation_groups[0] as Record<string, unknown>).group_id,
        capability_id: "CAP-INJ-001", classification: "no_exploitable_path", title: "query injection", security_check_outcome: "unknown",
        business_intent: { is_public_api: true, declared_or_inferred_purpose: "open public data", allowed_controls: ["id"], evidence: support([]) },
        security_boundary: { type: "data_owner", expected_boundary: "private data is isolated", reason: "missing trace", evidence: support([]) },
        exploitability: sixDimensions({ externally_reachable: false, attacker_controlled: false, sink_reached: false, security_check_bypassed_or_absent: "unknown", boundary_violated: "unknown", concrete_impact: "unknown" }, []),
        counter_evidence: [], demotion_reason: "cannot confirm reachable chain", evidence_gap: "missing trace", evidence: support([]),
      }],
    };
    expect(store.reconcile(validationTask!.task_id, validationTask!.attempt, demoted)).toMatchObject({ accepted: true });
    const [next] = (await store.claim(1)).tasks;
    expect(next).toBeUndefined();
    const report = await store.finalize();
    expect(report.summary).toMatchObject({ findings: 0, poc_artifacts: 0, classifications: { no_exploitable_path: 1 } });
    expect(report.component_results).toEqual(expect.arrayContaining([expect.objectContaining({ status: "no_exploitable_path" })]));
  });

  it("schedules the poc task immediately after its entry's validation, without waiting for other validations to drain", async () => {
    const { store } = await fixture(`{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }, { name: 'B', exported: true }] } }`, ["A", "B"]);
    const [aTask, bTask] = (await store.claim(2)).tasks;
    expect([aTask!.kind, bTask!.kind]).toEqual(["component_semantic_analysis", "component_semantic_analysis"]);
    for (const task of [aTask, bTask]) expect(store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>))).toMatchObject({ accepted: true });
    const validationTasks = (await store.claim(2)).tasks.filter((task) => task.kind === "exploitability_validation");
    expect(validationTasks).toHaveLength(2);
    expect(store.reconcile(validationTasks[0]!.task_id, validationTasks[0]!.attempt, validation(validationTasks[0] as Record<string, any>))).toMatchObject({ accepted: true });
    const next = (await store.claim(5)).tasks;
    expect(next.filter((task) => task.kind === "poc_generation")).toHaveLength(1);
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM tasks WHERE kind='poc_generation'").get() as { n: number }).n).toBe(1);
    expect((db.prepare("SELECT status FROM tasks WHERE task_id=?").get(validationTasks[1]!.task_id) as { status: string }).status).toBe("running");
    db.close();
  });

  it("requeues a completed poc task when the representative validation changes", async () => {
    const { root, store } = await fixture(`{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }, { name: 'B', exported: true }] } }`, ["A", "B"]);
    const model = await profileProject(root);
    const candidates = model.entry_candidates as { candidate_id: string; component_name: string }[];
    const aId = candidates.find((item) => item.component_name === "A")!.candidate_id;
    const bId = candidates.find((item) => item.component_name === "B")!.candidate_id;
    const bComponentId = String(model.components.find((item) => item.name === "B")!.component_id);
    const [firstTask, secondTask] = (await store.claim(2)).tasks;
    const aTask = String(firstTask!.input.entry.component_name) === "A" ? firstTask! : secondTask!;
    const bTask = String(firstTask!.input.entry.component_name) === "B" ? firstTask! : secondTask!;
    const aResult = {
      ...semantic(aTask as Record<string, any>), operation_groups: [],
      component_calls: [{ call_key: "a-to-b", target_component_id: bComponentId, target_symbol: "B.onCreate", transport: "startAbility", call_location: "A.ets:10", condition: "always", parameter_mappings: [{ source_property: "want.input", target_property: "want.forwarded", control_state: "preserved", transform: "none" }], principal_transition: { caller_principal: "external", callee_observed_principal: "A", origin_binding: "replaced_by_caller", authority_used: "source_component", evidence: [] }, security_checks: [], evidence: [] }],
    };
    expect(store.reconcile(aTask.task_id, aTask.attempt, aResult)).toMatchObject({ accepted: true });
    const bSemantic = semantic(bTask as Record<string, any>);
    // controlled property must match the parameter chain carried by the A→B path so a cross-component group forms
    (bSemantic.operation_groups as Record<string, any>[])[0]!.controlled_properties = ["want.forwarded"];
    expect(store.reconcile(bTask.task_id, bTask.attempt, bSemantic)).toMatchObject({ accepted: true });
    const validationTasks = (await store.claim(5)).tasks.filter((task) => task.kind === "exploitability_validation");
    const bValidation = validationTasks.find((task) => (task.input.operation_groups as Record<string, any>[])[0]!.scope !== "cross_component")!;
    const aValidation = validationTasks.find((task) => (task.input.operation_groups as Record<string, any>[])[0]!.scope === "cross_component")!;
    expect(store.reconcile(bValidation.task_id, bValidation.attempt, validation(bValidation as Record<string, any>, "high"))).toMatchObject({ accepted: true });
    const [firstPocHandle] = (await store.claim(5)).tasks.filter((task) => task.kind === "poc_generation");
    const firstPoc = await store.taskDocument(firstPocHandle as never);
    expect(store.reconcile(firstPoc.task_id, firstPoc.attempt, poc(firstPoc as Record<string, any>))).toMatchObject({ accepted: true });
    const before = new Database(store.paths.db);
    expect((before.prepare("SELECT COUNT(*) n FROM poc_artifacts").get() as { n: number }).n).toBe(1);
    before.close();
    // A cross-component confirmation (critical) supersedes B's local representative → artifact must be repaired.
    expect(store.reconcile(aValidation.task_id, aValidation.attempt, validation(aValidation as Record<string, any>, "critical"))).toMatchObject({ accepted: true });
    const db = new Database(store.paths.db);
    expect(db.prepare("SELECT status,error FROM tasks WHERE kind='poc_generation'").get()).toMatchObject({ status: "queued", error: "poc_finding_changed" });
    expect((db.prepare("SELECT COUNT(*) n FROM poc_artifacts").get() as { n: number }).n).toBe(0);
    expect((db.prepare("SELECT COUNT(*) n FROM events WHERE event_type='poc_artifact_repair'").get() as { n: number }).n).toBe(1);
    db.close();
  });

  it("lets the run finalize without a poc artifact after the poc task is exhausted", async () => {
    const { store, pocTask } = await confirmedStore();
    store.reconcile(pocTask.task_id, pocTask.attempt, undefined, "model_failed");
    const db0 = new Database(store.paths.db);
    db0.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(pocTask.task_id);
    db0.close();
    const [retry] = (await store.claim(1)).tasks;
    store.reconcile(retry!.task_id, retry!.attempt, undefined, "model_failed");
    const db1 = new Database(store.paths.db);
    db1.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(retry!.task_id);
    db1.close();
    const [last] = (await store.claim(1)).tasks;
    store.reconcile(last!.task_id, last!.attempt, undefined, "model_failed");
    expect(store.status().tasks).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "poc_generation", status: "exhausted" })]));
    const report = await store.finalize();
    expect((report.run as Record<string, unknown>).status).toBe("complete");
    expect((report.coverage as Record<string, unknown>).gaps).toEqual([]);
    expect(report.summary).toMatchObject({ findings: 1, poc_artifacts: 0 });
    expect((report.findings as Record<string, unknown>[])[0]).toMatchObject({ poc_artifact: null, poc_status: "generation_failed" });
    const markdown = await readFile(store.paths.reportMarkdown, "utf8");
    expect(markdown).toContain("PoC 生成失败");
  });
});
