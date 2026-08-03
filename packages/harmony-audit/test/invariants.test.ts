import Database from "better-sqlite3";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";
import { AuditInvariantError } from "../src/validation/invariant-errors.js";
import { validateExploitabilitySubmission, validateSemanticSubmission } from "../src/validation/submission-validator.js";
import { canonicalJson, stableId } from "../src/runtime/identity.js";

async function fixture(): Promise<{ root: string; store: AuditStore }> {
  const root = await mkdtemp(join(tmpdir(), "harmony-invariants-"));
  await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
  return { root, store: await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-INJ-001"], components: ["A"] }) };
}

function semantic(task: Record<string, any>): Record<string, unknown> {
  return {
    task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked",
    coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["A.onNewWant"], operation_sites_checked: ["A.ets:12"], unresolved_targets: [] }, component_calls: [],
    evidence: [{ evidence_id: "EV-1", kind: "atlas_trace", source: "atlas", summary: "entry reaches query", location: "A.ets:12" }],
    operation_groups: [{
      group_key: "query", category: "injection", capability_id: "CAP-INJ-001", title: "query injection",
      operation: { body: "query", location: "A.ets:12" }, controlled_properties: ["want.query"],
      context: { external_actor: "third-party app", intended_behavior: "open public data", protected_assets: ["private data"], observed_effect: "query executes", evidence_refs: ["EV-1"] },
      branches: [{ condition: "always", locations: ["A.ets:10"], evidence_refs: ["EV-1"] }], security_checks: [], evidence_refs: ["EV-1"],
      facts: [
        { fact_key: "entry", type: "entrypoint", body: "external", evidence_refs: ["EV-1"] },
        { fact_key: "sink", type: "operation", body: "query", evidence_refs: ["EV-1"] },
      ],
      edges: [{ from: "entry", to: "sink", kind: "reaches", evidence_refs: ["EV-1"] }],
    }],
  };
}

function validation(task: Record<string, any>): Record<string, unknown> {
  const group = task.input.operation_groups[0];
  return {
    task_id: task.task_id, entry_id: task.input.entry_id, summary: "confirmed", evidence: [],
    validations: [{
      group_id: group.group_id, capability_id: group.capability_id, classification: "confirmed_vulnerability", title: "query injection",
      security_check_outcome: "absent",
      business_intent: { is_public_api: true, declared_or_inferred_purpose: "open public data", allowed_controls: ["id"], evidence_refs: ["EV-1"] },
      security_boundary: { type: "data_owner", expected_boundary: "private data is isolated", violation: true, reason: "query crosses owner boundary", evidence_refs: ["EV-1"] },
      exploitability: { externally_reachable: true, attacker_controlled: true, sink_reached: true, security_check_bypassed_or_absent: true, boundary_violated: true, concrete_impact: true },
      counter_evidence: [], impact: "private data disclosure", severity: "high", cwe: "CWE-89", poc: "demo://x", evidence_refs: ["EV-1"],
    }],
  };
}

describe("audit domain invariants", () => {
  it("INV-CTX-002 rejects mismatched task atomically", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const candidate = semantic(task as Record<string, any>); candidate.task_id = "TASK-wrong";
    const outcome = store.reconcile(task!.task_id, task!.attempt, candidate);
    expect(outcome).toMatchObject({ accepted: false, status: "queued", error_code: "TASK_ID_MISMATCH" });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM semantic_analyses").get() as { n: number }).n).toBe(0);
    expect((db.prepare("SELECT COUNT(*) n FROM evidence").get() as { n: number }).n).toBe(0);
    db.close();
  });

  it("rejects structurally invalid submissions before writing facts", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const outcome = store.reconcile(task!.task_id, task!.attempt, { task_id: task!.task_id });
    expect(outcome).toMatchObject({ accepted: false, status: "queued", error_code: "SCHEMA_INVALID" });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM semantic_analyses").get() as { n: number }).n).toBe(0);
    db.close();
  });

  it("rolls back every semantic write before recording a rejected attempt", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const db = new Database(store.paths.db); const runId = store.runId(); const evidenceId = stableId("EV", task!.task_id, "EV-1");
    db.prepare("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?)").run(evidenceId, runId, task!.task_id, "EV-1", "atlas", "old", "A.ets:1", "old-hash", canonicalJson({ old: true }));
    db.close();
    const outcome = store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>));
    expect(outcome).toMatchObject({ accepted: false, status: "queued", error_code: "IDENTITY_COLLISION" });
    const check = new Database(store.paths.db);
    expect((check.prepare("SELECT COUNT(*) n FROM semantic_analyses").get() as { n: number }).n).toBe(0);
    expect((check.prepare("SELECT COUNT(*) n FROM operation_groups").get() as { n: number }).n).toBe(0);
    check.close();
  });

  it("keeps distinct local evidence ids even when they reference identical content", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const candidate = semantic(task as Record<string, any>);
    const first = (candidate.evidence as Record<string, unknown>[])[0]!;
    (candidate.evidence as Record<string, unknown>[]).push({ ...first, evidence_id: "EV-2" });
    expect(store.reconcile(task!.task_id, task!.attempt, candidate)).toMatchObject({ accepted: true });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM evidence WHERE producer_task_id=?").get(task!.task_id) as { n: number }).n).toBe(2);
    db.close();
  });

  it("INV-TX-001 persists normalized semantics validation and finding", async () => {
    const { store } = await fixture(); const [semanticTask] = (await store.claim(1)).tasks;
    expect(store.reconcile(semanticTask!.task_id, semanticTask!.attempt, semantic(semanticTask as Record<string, any>))).toMatchObject({ accepted: true });
    const [validationTask] = (await store.claim(1)).tasks;
    expect(validationTask!.kind).toBe("exploitability_validation");
    expect(store.reconcile(validationTask!.task_id, validationTask!.attempt, validation(validationTask as Record<string, any>))).toMatchObject({ accepted: true });
    const db = new Database(store.paths.db);
    for (const table of ["semantic_analyses", "evidence", "operation_groups", "group_facts", "group_edges", "validation_results", "findings", "finding_causes"]) {
      expect((db.prepare(`SELECT COUNT(*) n FROM ${table}`).get() as { n: number }).n, table).toBeGreaterThan(0);
    }
    expect((db.pragma("foreign_key_check") as unknown[])).toHaveLength(0);
    db.close();
  });

  it("INV-VAL-002 rejects a non-bijective validation set", () => {
    const group = { group_id: "GRP-1", capability_id: "CAP-INJ-001" };
    expect(() => validateExploitabilitySubmission({ task_id: "TASK-1", entry_id: "PE-1", evidence: [], validations: [] }, { taskId: "TASK-1", entryId: "PE-1", groups: [group], inheritedEvidence: new Set() }))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "MISSING_GROUP_VALIDATION" }));
  });

  it("rejects unknown evidence and invalid fact edges", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const unknownEvidence = semantic(task as Record<string, any>);
    ((unknownEvidence.operation_groups as Record<string, any>[])[0]!.facts[0].evidence_refs as string[]).push("EV-missing");
    expect(() => validateSemanticSubmission(unknownEvidence, { taskId: task!.task_id, entryId: String(task!.input.entry.candidate_id), capabilities: ["CAP-INJ-001"], enabledCapabilities: new Set(["CAP-INJ-001"]), componentIds: new Set([String(task!.input.entry.component_id)]) }))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "UNKNOWN_EVIDENCE_REF" }));
    const invalidEdge = semantic(task as Record<string, any>);
    (invalidEdge.operation_groups as Record<string, any>[])[0]!.edges = [{ from: "entry", to: "missing", kind: "reaches", evidence_refs: ["EV-1"] }];
    expect(() => validateSemanticSubmission(invalidEdge, { taskId: task!.task_id, entryId: String(task!.input.entry.candidate_id), capabilities: ["CAP-INJ-001"], enabledCapabilities: new Set(["CAP-INJ-001"]), componentIds: new Set([String(task!.input.entry.component_id)]) }))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "INVALID_FACT_EDGE" }));
  });

  it("rejects capability scope, category and unknown component violations", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const context = { taskId: task!.task_id, entryId: String(task!.input.entry.candidate_id), capabilities: [] as string[], enabledCapabilities: new Set(["CAP-INJ-001"]), componentIds: new Set([String(task!.input.entry.component_id)]) };
    expect(() => validateSemanticSubmission(semantic(task as Record<string, any>), context)).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "CAPABILITY_OUT_OF_SCOPE" }));
    const wrongCategory = semantic(task as Record<string, any>); (wrongCategory.operation_groups as Record<string, any>[])[0]!.category = "web";
    expect(() => validateSemanticSubmission(wrongCategory, { ...context, capabilities: ["CAP-INJ-001"], capabilityDomains: new Map([["CAP-INJ-001", "injection"]]) })).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "CAPABILITY_CATEGORY_MISMATCH" }));
    const call = semantic(task as Record<string, any>); call.component_calls = [{ call_key: "unknown", target_component_id: "CMP-missing", parameter_mappings: [] }];
    expect(() => validateSemanticSubmission(call, { ...context, capabilities: ["CAP-INJ-001"] })).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "UNKNOWN_TARGET_COMPONENT" }));
  });

  it("rejects incomplete confirmed and demoted validations", () => {
    const group = { group_id: "GRP-1", capability_id: "CAP-INJ-001" };
    const base = { task_id: "TASK-1", entry_id: "PE-1", evidence: [], validations: [{ group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "confirmed_vulnerability", exploitability: { externally_reachable: true } }] };
    expect(() => validateExploitabilitySubmission(base, { taskId: "TASK-1", entryId: "PE-1", groups: [group], inheritedEvidence: new Set() })).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "CONFIRMED_DIMENSIONS_INCOMPLETE" }));
    const demoted = { ...base, validations: [{ group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "insufficient_evidence", exploitability: {}, demotion_reason: "missing trace" }] };
    expect(() => validateExploitabilitySubmission(demoted, { taskId: "TASK-1", entryId: "PE-1", groups: [group], inheritedEvidence: new Set() })).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "EVIDENCE_GAP_MISSING" }));
  });

  it("rejects DoS confirmations without availability semantics", () => {
    const group = { group_id: "GRP-DOS", capability_id: "CAP-DOS-001" };
    const candidate = { task_id: "TASK-1", entry_id: "PE-1", evidence: [], validations: [{ group_id: "GRP-DOS", capability_id: "CAP-DOS-001", classification: "confirmed_vulnerability", security_boundary: { violation: true }, exploitability: { externally_reachable: true, attacker_controlled: true, sink_reached: true, security_check_bypassed_or_absent: true, boundary_violated: true, concrete_impact: true }, impact: "crash", severity: "high", cwe: "CWE-400", poc: "repeat" }] };
    expect(() => validateExploitabilitySubmission(candidate, { taskId: "TASK-1", entryId: "PE-1", groups: [group], inheritedEvidence: new Set() })).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "DOS_SEMANTIC_MISMATCH" }));
  });

  it("INV-PRINCIPAL validates deterministic cross-component identity", () => {
    const group = { group_id: "GRP-CROSS", capability_id: "CAP-INJ-001", scope: "cross_component", principal_state: { origin_principal: "external", target_observed_principal: "component-A", authority_used: "source_component", origin_binding: "replaced_by_caller" } };
    const validation = { group_id: "GRP-CROSS", capability_id: "CAP-INJ-001", classification: "confirmed_vulnerability", security_boundary: { violation: true }, exploitability: { externally_reachable: true, attacker_controlled: true, sink_reached: true, security_check_bypassed_or_absent: true, boundary_violated: true, concrete_impact: true }, impact: "impact", severity: "high", cwe: "CWE-441", poc: "poc", principal_analysis: { origin_principal: "external", target_observed_principal: "component-A", authority_used: "source_component", origin_bound_to_observed_principal: false, delegation_risk: true } };
    const candidate = { task_id: "TASK-1", entry_id: "PE-1", evidence: [], validations: [validation] };
    expect(() => validateExploitabilitySubmission(candidate, { taskId: "TASK-1", entryId: "PE-1", groups: [group], inheritedEvidence: new Set() })).not.toThrow();
    const invalid = structuredClone(candidate); (invalid.validations[0]!.principal_analysis as Record<string, unknown>).delegation_risk = false;
    expect(() => validateExploitabilitySubmission(invalid, { taskId: "TASK-1", entryId: "PE-1", groups: [group], inheritedEvidence: new Set() })).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "PRINCIPAL_CHAIN_INCOMPLETE" }));
  });

  it("INV-REPORT-002 marks exhausted work complete_with_gaps", async () => {
    const { store } = await fixture();
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const [task] = (await store.claim(1)).tasks;
      store.reconcile(task!.task_id, task!.attempt, undefined, "model_failed");
    }
    const report = await store.finalize();
    expect((report.run as Record<string, unknown>).status).toBe("complete_with_gaps");
    expect(((report.coverage as Record<string, unknown>).gaps as Record<string, unknown>[])).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "exhausted_task", details: expect.objectContaining({ attempts: 3 }) })]));
  });
});
