import Database from "better-sqlite3";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveCapabilities } from "../src/capabilities.js";
import { incrementalBaselineFiles, planIncremental } from "../src/incremental.js";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";
import { effectChain, sixDimensions, validationEvidence } from "./p0-fixtures.js";

const semantic = (task: Record<string, any>) => ({
  task_id: task.task_id,
  entry_id: task.input.entry.candidate_id,
  summary: `checked ${task.input.entry.component_name}`,
  coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: [`${task.input.entry.component_name}.onCreate`], operation_sites_checked: [], unresolved_targets: [] },
  operation_groups: [], component_calls: [], evidence: [],
});

const operationGroup = {
  group_key: "owned-query", category: "provider", capability_id: "CAP-PROVIDER-001", title: "受保护的数据查询",
  operation: { body: "query owned record", location: "A.ets:30" }, controlled_properties: ["want.recordId"],
  context: { external_actor: "third-party app", intended_behavior: "query owned record", protected_assets: ["private records"], direct_observed_effect: null, effect_hypotheses: [], evidence_refs: [] },
  branches: [{ condition: "always", locations: ["A.ets:20"], evidence_refs: [] }],
  facts: [{ fact_key: "entry", type: "entrypoint", body: "external Want", location: "A.ets:10", evidence_refs: [] }, { fact_key: "operation", type: "operation", body: "query owned record", location: "A.ets:30", evidence_refs: [] }],
  edges: [{ from: "entry", to: "operation", kind: "reaches", evidence_refs: [] }],
  security_checks: [{ type: "owner check", location: "A.ets:25", protects: "private records", subject_kind: "origin_principal", validated_property: "record owner", behavior: "rejects another owner", evidence_refs: [] }],
  evidence_refs: [],
};

function protectedValidation(task: Record<string, any>) {
  const group = task.input.operation_groups[0];
  return {
    task_id: task.task_id, entry_id: task.input.entry_id, summary: "protected",
    validations: [{
      group_id: group.group_id, capability_id: group.capability_id, classification: "protected_exposure", title: "所有者校验有效", security_check_outcome: "effective",
      business_intent: { is_public_api: true, declared_or_inferred_purpose: "query one owned record", allowed_controls: ["recordId"], evidence_refs: [] },
      security_boundary: { type: "data_owner", expected_boundary: "only owner may query", violation: false, reason: "owner check rejects another caller", evidence_refs: [] },
      exploitability: sixDimensions({ security_check_bypassed_or_absent: false, boundary_violated: false, concrete_impact: false }),
      counter_evidence: [{ kind: "effective_security_check", reason: "owner check dominates query", evidence_refs: [] }],
      demotion_reason: "owner check prevents unauthorized access", evidence_refs: [],
    }], evidence: [validationEvidence],
  };
}

const pocArtifact = (task: Record<string, any>) => ({
  task_id: task.task_id, finding_id: String(task.input.finding.finding_id), entry_type: "want",
  trigger: { kind: "ability_want", payload: { action: "ohos.intent.action.QUERY", uri: "demo://record?owned=1" } },
  language: "arkts", code: "startAbility({ want: { action: 'ohos.intent.action.QUERY', uri: 'demo://record?owned=1' } })",
  prerequisites: ["安装 debug 包"], expected_observation: "返回本人记录", limitations: "未在真机验证",
  execution_hint: { step_by_step: ["安装 debug 包", "运行代码"], device_required: "emulator", network_required: false },
  symbol_refs: [], evidence: [], evidence_refs: [],
});

async function project() {
  const root = await mkdtemp(join(tmpdir(), "harmony-incremental-"));
  await mkdir(join(root, "entry/src/main/ets"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{module:{name:'entry',abilities:[
    {name:'A',srcEntry:'./ets/A.ets',exported:true},
    {name:'B',srcEntry:'./ets/B.ets',exported:true}
  ]}}`);
  await writeFile(join(root, "entry/src/main/ets/A.ets"), "export default class A {}\n");
  await writeFile(join(root, "entry/src/main/ets/B.ets"), "export default class B {}\n");
  return root;
}

describe("incremental audit migration", () => {
  it("advances a complete baseline, reanalyzes impacted code and revalidates reused semantics", async () => {
    const root = await project(); const capabilities = await resolveCapabilities([]);
    const full = await AuditStore.create(root, await profileProject(root), { mode: "full", capabilities });
    for (const task of (await full.claim(5)).tasks) expect(full.reconcile(task.task_id, task.attempt, semantic(task as Record<string, any>))).toMatchObject({ accepted: true });
    const fullReport = await full.finalize();
    expect((fullReport.run as Record<string, any>).baseline).toMatchObject({ updated: true });
    expect(JSON.parse(await readFile(incrementalBaselineFiles(root).metadata, "utf8"))).toMatchObject({ schema_version: 1, semantic_results: 4 });

    await writeFile(join(root, "entry/src/main/ets/A.ets"), "export default class A { changed = true }\n");
    const model = await profileProject(root); const plan = await planIncremental(root, model);
    expect(plan.changeSet.changed_file_count).toBe(1);
    expect(plan.impactPlan.affected_entries).toHaveLength(2);
    expect(plan.impactPlan.reusable_entries).toHaveLength(2);

    const incremental = await AuditStore.create(root, model, { mode: "incremental", capabilities }, plan);
    const db = new Database(incremental.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM semantic_analyses").get() as { n: number }).n).toBe(2);
    expect(db.prepare("SELECT status,attempts FROM tasks ORDER BY status").all()).toEqual([
      { status: "completed", attempts: 0 }, { status: "completed", attempts: 0 }, { status: "queued", attempts: 0 }, { status: "queued", attempts: 0 },
    ]);
    db.close();

    const changed = (await incremental.claim(5)).tasks;
    expect(changed.map((task) => task.input.entry.component_name).sort()).toEqual(["A", "项目级审计"]);
    for (const task of changed) expect(incremental.reconcile(task.task_id, task.attempt, semantic(task as Record<string, any>))).toMatchObject({ accepted: true });
    const report = await incremental.finalize();
    expect((report.run as Record<string, any>)).toMatchObject({
      audit_scope: { mode: "incremental" },
      incremental: { change_set: { changed_file_count: 1 }, impact_plan: { affected_entries: expect.any(Array), reusable_entries: expect.any(Array) } },
      baseline: { updated: true },
    });
    expect(await readFile(incremental.paths.reportMarkdown, "utf8")).toContain("增量审计摘要");
    expect(await readFile(incremental.paths.reportHtml, "utf8")).toContain("增量审计");
  });

  it("requires a compatible complete baseline and rejects filtered incremental requests", async () => {
    const root = await project(); const model = await profileProject(root);
    await expect(planIncremental(root, model)).rejects.toThrow("incremental_baseline_missing_run_full_audit_first");
    const capabilities = await resolveCapabilities([]);
    await expect(AuditStore.create(root, model, { mode: "incremental", capabilities, components: ["A"] }, {} as never)).rejects.toThrow("incremental_mode_cannot_filter_scope");
  });

  it("reuses six-dimensional validation only when the current operation-group fingerprints match", async () => {
    const root = await project(); const capabilities = await resolveCapabilities([]);
    const full = await AuditStore.create(root, await profileProject(root), { mode: "full", capabilities });
    for (const task of (await full.claim(5)).tasks) {
      const result = semantic(task as Record<string, any>);
      if (task.input.entry.component_name === "A") result.operation_groups = [operationGroup] as never;
      expect(full.reconcile(task.task_id, task.attempt, result)).toMatchObject({ accepted: true });
    }
    const [validation] = (await full.claim(5)).tasks;
    expect(validation!.kind).toBe("exploitability_validation");
    expect(full.reconcile(validation!.task_id, validation!.attempt, protectedValidation(validation as Record<string, any>))).toMatchObject({ accepted: true });
    await full.finalize();

    const model = await profileProject(root); const plan = await planIncremental(root, model);
    expect(plan.impactPlan.affected_entries).toEqual([]);
    const incremental = await AuditStore.create(root, model, { mode: "incremental", capabilities }, plan);
    expect((await incremental.claim(5)).tasks).toEqual([]);
    const db = new Database(incremental.paths.db);
    expect(db.prepare("SELECT status,attempts FROM tasks WHERE kind='exploitability_validation'").get()).toEqual({ status: "completed", attempts: 0 });
    expect((db.prepare("SELECT COUNT(*) n FROM validation_results").get() as { n: number }).n).toBe(1);
    db.close();
  });

  it("reuses confirmed findings and their PoC artifacts from the baseline", async () => {
    const root = await project(); const capabilities = await resolveCapabilities([]);
    const full = await AuditStore.create(root, await profileProject(root), { mode: "full", capabilities });
    for (const task of (await full.claim(5)).tasks) {
      const result = semantic(task as Record<string, any>);
      if (task.input.entry.component_name === "A") result.operation_groups = [operationGroup] as never;
      expect(full.reconcile(task.task_id, task.attempt, result)).toMatchObject({ accepted: true });
    }
    const [validation] = (await full.claim(5)).tasks;
    const confirmed = protectedValidation(validation as Record<string, any>);
    const group = (validation!.input.operation_groups as Record<string, any>[])[0];
    (confirmed.validations as Record<string, any>[])[0] = {
      group_id: group.group_id, capability_id: group.capability_id, classification: "confirmed_vulnerability", title: "受保护的数据查询",
      security_check_outcome: "bypassable",
      business_intent: { is_public_api: true, declared_or_inferred_purpose: "query one owned record", allowed_controls: ["recordId"], evidence_refs: [] },
      security_boundary: { type: "data_owner", expected_boundary: "only owner may query", violation: true, reason: "owner check can be bypassed", evidence_refs: [] },
      exploitability: sixDimensions(), effect_chain: effectChain(),
      counter_evidence: [], impact: "读取他人记录", severity: "high", cwe: "CWE-89", evidence_refs: [],
    };
    expect(full.reconcile(validation!.task_id, validation!.attempt, confirmed)).toMatchObject({ accepted: true });
    const [poc] = (await full.claim(5)).tasks;
    expect(poc!.kind).toBe("poc_generation");
    expect(full.reconcile(poc!.task_id, poc!.attempt, pocArtifact(poc as Record<string, any>))).toMatchObject({ accepted: true });
    await full.finalize();

    const model = await profileProject(root); const plan = await planIncremental(root, model);
    expect(plan.impactPlan.affected_entries).toEqual([]);
    const incremental = await AuditStore.create(root, model, { mode: "incremental", capabilities }, plan);
    expect((await incremental.claim(5)).tasks).toEqual([]);
    const db = new Database(incremental.paths.db);
    expect(db.prepare("SELECT status,attempts FROM tasks WHERE kind='poc_generation'").get()).toEqual({ status: "completed", attempts: 0 });
    expect((db.prepare("SELECT COUNT(*) n FROM poc_artifacts").get() as { n: number }).n).toBe(1);
    db.close();
  });

});
