import Database from "better-sqlite3";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";
import { evidenceLocalId } from "../src/runtime/evidence.js";
import { AuditInvariantError } from "../src/validation/invariant-errors.js";
import { validateExploitabilitySubmission, validateSemanticSubmission } from "../src/validation/submission-validator.js";
import { canonicalJson, stableId } from "../src/runtime/identity.js";
import { admissibleRefs, effectChain, evidenceRow, sixDimensions, support } from "./p0-fixtures.js";

async function fixture(): Promise<{ root: string; store: AuditStore }> {
  const root = await mkdtemp(join(tmpdir(), "harmony-invariants-"));
  await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
  return { root, store: await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-INJ-001"], components: ["A"] }) };
}

const semanticEvidence = () => [evidenceRow("entry reaches query")];

function semantic(task: Record<string, any>): Record<string, unknown> {
  return {
    task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked",
    coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["A.onNewWant"], operation_sites_checked: ["A.ets:12"], unresolved_targets: [] }, component_calls: [],
    operation_groups: [{
      group_key: "query", category: "injection", capability_id: "CAP-INJ-001", title: "query injection",
      operation: { body: "query", location: "A.ets:12", evidence: semanticEvidence() }, controlled_properties: ["want.query"],
      context: { external_actor: "third-party app", intended_behavior: "open public data", protected_assets: ["private data"], direct_observed_effect: "query executes", effect_hypotheses: [], evidence: semanticEvidence() },
      branches: [{ condition: "always", locations: ["A.ets:10"], evidence: semanticEvidence() }], security_checks: [],
      facts: [
        { fact_key: "entry", type: "entrypoint", body: "external", evidence: semanticEvidence() },
        { fact_key: "sink", type: "operation", body: "query", evidence: semanticEvidence() },
      ],
    }],
  };
}

function validation(task: Record<string, any>): Record<string, unknown> {
  const group = task.input.operation_groups[0];
  const refs = admissibleRefs(group);
  return {
    task_id: task.task_id, entry_id: task.input.entry_id, summary: "confirmed",
    validations: [{
      group_id: group.group_id, capability_id: group.capability_id, classification: "confirmed_vulnerability", title: "query injection",
      security_check_outcome: "absent",
      business_intent: { is_public_api: true, declared_or_inferred_purpose: "open public data", allowed_controls: ["id"], evidence: support(refs) },
      security_boundary: { type: "data_owner", expected_boundary: "private data is isolated", violation: true, reason: "query crosses owner boundary", evidence: support(refs) },
      exploitability: sixDimensions({}, refs), effect_chain: effectChain(refs),
      counter_evidence: [], impact: "private data disclosure", severity: "high", cwe: "CWE-89", evidence: support(refs),
    }],
  };
}

const directContext = (groups: Record<string, unknown>[]) => ({
  taskId: "TASK-1", entryId: "PE-1", groups,
  admissibleEvidence: new Map<string, ReadonlySet<string>>(),
  hypothesisOnlyEvidence: new Map<string, ReadonlySet<string>>(),
});

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
    const db = new Database(store.paths.db); const runId = store.runId();
    // Pre-insert a conflicting row under the content-addressed id the fixture's evidence will produce.
    const row = evidenceRow("entry reaches query");
    const localId = evidenceLocalId(row);
    const evidenceId = stableId("EV", task!.task_id, localId);
    db.prepare("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?)").run(evidenceId, runId, task!.task_id, localId, "atlas", "old", "A.ets:1", "old-hash", canonicalJson({ old: true }));
    db.close();
    const outcome = store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>));
    expect(outcome).toMatchObject({ accepted: false, status: "queued", error_code: "IDENTITY_COLLISION" });
    const check = new Database(store.paths.db);
    expect((check.prepare("SELECT COUNT(*) n FROM semantic_analyses").get() as { n: number }).n).toBe(0);
    expect((check.prepare("SELECT COUNT(*) n FROM operation_groups").get() as { n: number }).n).toBe(0);
    check.close();
  });

  it("collapses identical inline evidence to a single row per producer task", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    // The fixture repeats the same evidence content across operation, context, branches and facts.
    expect(store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>))).toMatchObject({ accepted: true });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM evidence WHERE producer_task_id=?").get(task!.task_id) as { n: number }).n).toBe(1);
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
    expect(() => validateExploitabilitySubmission({ task_id: "TASK-1", entry_id: "PE-1", validations: [] }, directContext([group])))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "MISSING_GROUP_VALIDATION" }));
  });

  it("rejects hypotheses without basis evidence and direct effects without context evidence", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const context = { taskId: task!.task_id, entryId: String(task!.input.entry.candidate_id), capabilities: ["CAP-INJ-001"], enabledCapabilities: new Set(["CAP-INJ-001"]), componentIds: new Set([String(task!.input.entry.component_id)]) };
    const noBasis = semantic(task as Record<string, any>);
    const group = (noBasis.operation_groups as Record<string, any>[])[0]!;
    group.context.effect_hypotheses = [{ claim: "参数可能跳过安全检查", basis_evidence: [], missing_proofs: ["字段读取位置", "安全行为变化", "具体影响"] }];
    expect(() => validateSemanticSubmission(noBasis, context))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "HYPOTHESIS_BASIS_MISSING" }));
    const noDirectEvidence = semantic(task as Record<string, any>);
    ((noDirectEvidence.operation_groups as Record<string, any>[])[0]!.context.evidence as unknown[])!.splice(0);
    expect(() => validateSemanticSubmission(noDirectEvidence, context))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "DIRECT_EFFECT_EVIDENCE_MISSING" }));
  });

  it("keeps inferred effects out of semantic facts", async () => {
    const { store } = await fixture(); const [task] = (await store.claim(1)).tasks;
    const inferred = semantic(task as Record<string, any>);
    const group = (inferred.operation_groups as Record<string, any>[])[0]!;
    group.context = {
      ...group.context,
      direct_observed_effect: null,
      effect_hypotheses: [{ claim: "参数可能跳过安全检查", basis_evidence: [evidenceRow()], missing_proofs: ["字段读取位置", "安全行为变化", "具体影响"] }],
    };
    group.facts.push({ fact_key: "guessed-effect", type: "effect", body: "安全检查被跳过", evidence: [evidenceRow()] });
    expect(store.reconcile(task!.task_id, task!.attempt, inferred)).toMatchObject({ accepted: false, error_code: "SCHEMA_INVALID" });
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
    const base = { task_id: "TASK-1", entry_id: "PE-1", validations: [{ group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "confirmed_vulnerability", exploitability: { externally_reachable: true } }] };
    expect(() => validateExploitabilitySubmission(base, directContext([group]))).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "CONFIRMED_DIMENSIONS_INCOMPLETE" }));
    const demoted = { ...base, validations: [{ group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "insufficient_evidence", exploitability: {}, demotion_reason: "missing trace" }] };
    expect(() => validateExploitabilitySubmission(demoted, directContext([group]))).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "EVIDENCE_GAP_MISSING" }));
  });

  it("rejects hypothesis-backed true dimensions, out-of-scope refs and inherited-only effect chains", () => {
    const group = { group_id: "GRP-1", capability_id: "CAP-INJ-001" };
    const ctx = (admissible: ReadonlySet<string>, hypothesisOnly: ReadonlySet<string> = new Set()) => ({
      taskId: "TASK-1", entryId: "PE-1", groups: [group],
      admissibleEvidence: new Map([["GRP-1", admissible]]), hypothesisOnlyEvidence: new Map([["GRP-1", hypothesisOnly]]),
    });

    const hypothesis = sixDimensions({ sink_reached: "unknown" }, ["EV-1"]);
    hypothesis.sink_reached = { status: "true", reason: "字段名暗示会执行查询", evidence_level: "hypothesis", evidence: support(["EV-1"], []) };
    const hypothesisCandidate = {
      task_id: "TASK-1", entry_id: "PE-1", validations: [{
        group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "insufficient_evidence",
        exploitability: hypothesis, demotion_reason: "效果尚未核验", evidence_gap: "缺少实际调用证据",
      }],
    };
    expect(() => validateExploitabilitySubmission(hypothesisCandidate, ctx(new Set(["EV-1"]))))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "TRUE_DIMENSION_EVIDENCE_INSUFFICIENT" }));

    const outside = {
      task_id: "TASK-1", entry_id: "PE-1", validations: [{
        group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "insufficient_evidence",
        exploitability: sixDimensions({}, ["EV-9"]), demotion_reason: "x", evidence_gap: "y",
      }],
    };
    expect(() => validateExploitabilitySubmission(outside, ctx(new Set(["EV-1"]))))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "EVIDENCE_OUTSIDE_OPERATION_GROUP" }));

    const inadmissible = {
      task_id: "TASK-1", entry_id: "PE-1", validations: [{
        group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "insufficient_evidence",
        exploitability: sixDimensions({}, ["EV-2"]), demotion_reason: "x", evidence_gap: "y",
      }],
    };
    expect(() => validateExploitabilitySubmission(inadmissible, ctx(new Set(["EV-1"]), new Set(["EV-2"]))))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "HYPOTHESIS_EVIDENCE_NOT_ADMISSIBLE" }));

    const inheritedOnly = {
      task_id: "TASK-1", entry_id: "PE-1", validations: [{
        group_id: "GRP-1", capability_id: "CAP-INJ-001", classification: "confirmed_vulnerability",
        security_boundary: { violation: true, evidence: support(["EV-1"], []) },
        exploitability: sixDimensions({}, ["EV-1"]), effect_chain: effectChain(["EV-1"], []),
        impact: "private data disclosure", severity: "high", cwe: "CWE-89", evidence: support(["EV-1"], []),
      }],
    };
    expect(() => validateExploitabilitySubmission(inheritedOnly, ctx(new Set(["EV-1"]))))
      .toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "CONFIRMED_EFFECT_NOT_INDEPENDENTLY_VERIFIED" }));
  });

  it("rejects DoS confirmations without availability semantics", () => {
    const group = { group_id: "GRP-DOS", capability_id: "CAP-DOS-001" };
    const candidate = { task_id: "TASK-1", entry_id: "PE-1", validations: [{ group_id: "GRP-DOS", capability_id: "CAP-DOS-001", classification: "confirmed_vulnerability", security_boundary: { violation: true }, exploitability: sixDimensions(), effect_chain: effectChain(), impact: "crash", severity: "high", cwe: "CWE-400" }] };
    expect(() => validateExploitabilitySubmission(candidate, directContext([group]))).toThrowError(expect.objectContaining<Partial<AuditInvariantError>>({ code: "DOS_SEMANTIC_MISMATCH" }));
  });

  it("INV-PRINCIPAL validates deterministic cross-component identity", () => {
    const group = { group_id: "GRP-CROSS", capability_id: "CAP-INJ-001", scope: "cross_component", principal_state: { origin_principal: "external", target_observed_principal: "component-A", authority_used: "source_component", origin_binding: "replaced_by_caller" } };
    const validation = { group_id: "GRP-CROSS", capability_id: "CAP-INJ-001", classification: "confirmed_vulnerability", security_boundary: { violation: true }, exploitability: sixDimensions(), effect_chain: effectChain(), impact: "impact", severity: "high", cwe: "CWE-441", principal_analysis: { origin_principal: "external", target_observed_principal: "component-A", authority_used: "source_component", origin_bound_to_observed_principal: false, delegation_risk: true } };
    const candidate = { task_id: "TASK-1", entry_id: "PE-1", validations: [validation] };
    expect(() => validateExploitabilitySubmission(candidate, directContext([group]))).not.toThrow();
    const invalid = structuredClone(candidate); (invalid.validations[0]!.principal_analysis as Record<string, unknown>).delegation_risk = false;
    try {
      validateExploitabilitySubmission(invalid, directContext([group]));
      throw new Error("expected principal mismatch");
    } catch (error) {
      expect(error).toMatchObject<Partial<AuditInvariantError>>({ code: "PRINCIPAL_CHAIN_INCOMPLETE", details: expect.objectContaining({ mismatched_fields: ["delegation_risk"] }) });
    }
  });

  it("INV-REPORT-002 marks exhausted work complete_with_gaps", async () => {
    const { store } = await fixture();
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const [task] = (await store.claim(1)).tasks;
      store.reconcile(task!.task_id, task!.attempt, undefined, "model_failed");
      const db = new Database(store.paths.db);
      db.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(task!.task_id);
      db.close();
    }
    const report = await store.finalize();
    expect((report.run as Record<string, unknown>).status).toBe("complete_with_gaps");
    expect(((report.coverage as Record<string, unknown>).gaps as Record<string, unknown>[])).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "exhausted_task", details: expect.objectContaining({ attempts: 3 }) })]));
  });
});
