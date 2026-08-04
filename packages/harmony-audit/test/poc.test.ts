import Database from "better-sqlite3";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";
import { validatePocSubmission } from "../src/validation/submission-validator.js";

async function fixture(): Promise<{ root: string; store: AuditStore }> {
  const root = await mkdtemp(join(tmpdir(), "harmony-poc-"));
  await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
  return { root, store: await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-INJ-001"], components: ["A"] }) };
}

const semantic = (task: Record<string, any>) => ({
  task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked",
  coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["A.onNewWant"], operation_sites_checked: ["A.ets:12"], unresolved_targets: [] }, component_calls: [],
  evidence: [{ evidence_id: "EV-1", kind: "atlas_trace", source: "atlas", summary: "entry reaches query", location: "A.ets:12" }],
  operation_groups: [{
    group_key: "query", category: "injection", capability_id: "CAP-INJ-001", title: "query injection",
    operation: { body: "query", location: "A.ets:12" }, controlled_properties: ["want.query"],
    context: { external_actor: "third-party app", intended_behavior: "open public data", protected_assets: ["private data"], observed_effect: "query executes", evidence_refs: ["EV-1"] },
    branches: [{ condition: "always", locations: ["A.ets:10"], evidence_refs: ["EV-1"] }], security_checks: [], evidence_refs: ["EV-1"],
    facts: [{ fact_key: "entry", type: "entrypoint", body: "external", evidence_refs: ["EV-1"] }, { fact_key: "sink", type: "operation", body: "query", evidence_refs: ["EV-1"] }],
    edges: [{ from: "entry", to: "sink", kind: "reaches", evidence_refs: ["EV-1"] }],
  }],
});

const validation = (task: Record<string, any>) => {
  const group = task.input.operation_groups[0];
  return {
    task_id: task.task_id, entry_id: task.input.entry_id, summary: "confirmed", evidence: [],
    validations: [{
      group_id: group.group_id, capability_id: group.capability_id, classification: "confirmed_vulnerability", title: "query injection",
      security_check_outcome: "absent",
      business_intent: { is_public_api: true, declared_or_inferred_purpose: "open public data", allowed_controls: ["id"], evidence_refs: [] },
      security_boundary: { type: "data_owner", expected_boundary: "private data is isolated", violation: true, reason: "query crosses owner boundary", evidence_refs: [] },
      exploitability: { externally_reachable: true, attacker_controlled: true, sink_reached: true, security_check_bypassed_or_absent: true, boundary_violated: true, concrete_impact: true },
      counter_evidence: [], impact: "private data disclosure", severity: "high", cwe: "CWE-89", poc: "demo://x", evidence_refs: [],
    }],
  };
};

const poc = (task: Record<string, any>, overrides: Record<string, unknown> = {}) => ({
  task_id: task.task_id, finding_id: String(task.input.finding.finding_id), entry_type: "want",
  trigger: { kind: "ability_want", payload: { action: "ohos.intent.action.QUERY", uri: "demo://x?q=1" } },
  language: "arkts", code: "startAbility({ want: { action: 'ohos.intent.action.QUERY', uri: 'demo://x?q=1' } })",
  prerequisites: ["安装 debug 包"], expected_observation: "返回越权数据", limitations: "未在真机验证", evidence: [],
  evidence_refs: [], ...overrides,
});

async function confirmedStore(): Promise<{ store: AuditStore; pocTask: Record<string, any> }> {
  const { store } = await fixture();
  const [semanticTask] = (await store.claim(1)).tasks;
  expect(store.reconcile(semanticTask!.task_id, semanticTask!.attempt, semantic(semanticTask as Record<string, any>))).toMatchObject({ accepted: true });
  const [validationTask] = (await store.claim(1)).tasks;
  expect(validationTask!.kind).toBe("exploitability_validation");
  expect(store.reconcile(validationTask!.task_id, validationTask!.attempt, validation(validationTask as Record<string, any>))).toMatchObject({ accepted: true });
  const [pocTask] = (await store.claim(1)).tasks;
  return { store, pocTask: pocTask as Record<string, any> };
}

describe("poc generation phase", () => {
  it("schedules a poc task only after a confirmed finding and persists a structured artifact", async () => {
    const { store, pocTask } = await confirmedStore();
    expect(pocTask).toBeDefined();
    expect(pocTask.kind).toBe("poc_generation");
    expect(pocTask.input).toMatchObject({ finding: { finding_id: expect.any(String) }, verification_scope: { target_repo: expect.any(String) } });
    expect(store.reconcile(pocTask.task_id, pocTask.attempt, poc(pocTask))).toMatchObject({ accepted: true });
    const report = await store.finalize();
    expect(report.summary).toMatchObject({ findings: 1, poc_artifacts: 1 });
    const finding = (report.findings as Record<string, unknown>[])[0]!;
    expect(finding.poc_artifact).toMatchObject({ entry_type: "want", payload: expect.objectContaining({ code: expect.stringContaining("startAbility"), expected_observation: "返回越权数据" }) });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM poc_artifacts").get() as { n: number }).n).toBe(1);
    expect((db.pragma("foreign_key_check") as unknown[])).toHaveLength(0);
    db.close();
    expect(await readFile(store.paths.reportMarkdown, "utf8")).toContain("#### 验证方式 / PoC");
    expect(await readFile(store.paths.reportMarkdown, "utf8")).toContain("入口类型");
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

  it("rejects unknown evidence refs in poc submissions", () => {
    const candidate = { task_id: "TASK-1", finding_id: "FIND-1", entry_type: "want", trigger: { kind: "ability_want", payload: {} }, language: "arkts", code: "x()", expected_observation: "x", evidence: [], evidence_refs: ["EV-missing"] };
    expect(() => validatePocSubmission(candidate, { taskId: "TASK-1", entryId: "PE-1", findingId: "FIND-1", allowedEntryTypes: new Set(["want"]), allowedEvidence: new Set() }))
      .toThrowError(expect.objectContaining<Partial<{ code: string }>>({ code: "UNKNOWN_EVIDENCE_REF" }));
  });

  it("does not schedule poc generation for demoted validations", async () => {
    const { store } = await fixture();
    const [semanticTask] = (await store.claim(1)).tasks;
    expect(store.reconcile(semanticTask!.task_id, semanticTask!.attempt, semantic(semanticTask as Record<string, any>))).toMatchObject({ accepted: true });
    const [validationTask] = (await store.claim(1)).tasks;
    const demoted = {
      task_id: validationTask!.task_id, entry_id: validationTask!.input.entry_id, summary: "not exploitable", evidence: [],
      validations: [{
        group_id: (validationTask!.input.operation_groups[0] as Record<string, unknown>).group_id,
        capability_id: "CAP-INJ-001", classification: "insufficient_evidence", title: "query injection", security_check_outcome: "unknown",
        business_intent: { is_public_api: true, declared_or_inferred_purpose: "open public data", allowed_controls: ["id"], evidence_refs: [] },
        security_boundary: { type: "data_owner", expected_boundary: "private data is isolated", violation: false, reason: "missing trace", evidence_refs: [] },
        exploitability: { externally_reachable: false, attacker_controlled: false, sink_reached: false, security_check_bypassed_or_absent: false, boundary_violated: false, concrete_impact: false },
        counter_evidence: [], demotion_reason: "cannot confirm reachable chain", evidence_gap: "missing trace", evidence_refs: [],
      }],
    };
    expect(store.reconcile(validationTask!.task_id, validationTask!.attempt, demoted)).toMatchObject({ accepted: true });
    const [next] = (await store.claim(1)).tasks;
    expect(next).toBeUndefined();
    const report = await store.finalize();
    expect(report.summary).toMatchObject({ findings: 0, poc_artifacts: 0 });
  });

  it("schedules the poc task immediately after its entry's validation, without waiting for other validations to drain", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-poc-early-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }, { name: 'B', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-INJ-001"], components: ["A", "B"] });
    const [aTask, bTask] = (await store.claim(2)).tasks;
    expect([aTask!.kind, bTask!.kind]).toEqual(["component_semantic_analysis", "component_semantic_analysis"]);
    for (const task of [aTask, bTask]) {
      expect(store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>))).toMatchObject({ accepted: true });
    }
    const claimed = (await store.claim(2)).tasks;
    const validationTasks = claimed.filter((task) => task.kind === "exploitability_validation");
    expect(validationTasks).toHaveLength(2);
    const first = validationTasks[0]!;
    expect(store.reconcile(first.task_id, first.attempt, validation(first as Record<string, any>))).toMatchObject({ accepted: true });
    const next = (await store.claim(5)).tasks;
    expect(next.filter((task) => task.kind === "poc_generation")).toHaveLength(1);
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM tasks WHERE kind='poc_generation'").get() as { n: number }).n).toBe(1);
    expect((db.prepare("SELECT status FROM tasks WHERE task_id=?").get(validationTasks[1]!.task_id) as { status: string }).status).toBe("running");
    db.close();
  });
});
