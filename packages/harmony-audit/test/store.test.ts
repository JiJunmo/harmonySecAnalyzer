import Database from "better-sqlite3";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditStore } from "../src/runtime/store.js";
import { profileProject } from "../src/project/profiler.js";

const emptySemantic = (task: Record<string, any>, overrides: Record<string, unknown> = {}) => ({
  task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked",
  coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["A.onCreate"], operation_sites_checked: [], unresolved_targets: [] },
  operation_groups: [], component_calls: [], evidence: [], ...overrides,
});

describe("audit store", () => {
  it("owns task transitions and creates deterministic reports", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-store-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root));
    while (true) {
      const claim = await store.claim(5);
      if (!claim.tasks.length) break;
      for (const task of claim.tasks) {
        store.appendTaskTrace(task.task_id, task.attempt, { type: "agent_started", timestamp: new Date().toISOString(), payload: { model: "test/audit" } });
        store.appendTaskTrace(task.task_id, task.attempt, { type: "tool_call_started", timestamp: new Date().toISOString(), payload: { tool: "search", arguments: { query: "A" } } });
        store.appendTaskTrace(task.task_id, task.attempt, { type: "agent_completed", timestamp: new Date().toISOString() });
        store.reconcile(task.task_id, task.attempt, emptySemantic(task as Record<string, any>));
        const detail = store.execution(task.task_id);
        expect(detail.execution).toMatchObject({ id: task.task_id, status: "succeeded", attempt: 1 });
        expect(detail.events.map((event) => event.type)).toEqual(expect.arrayContaining(["agent_started", "tool_call_started", "agent_completed", "task_completed"]));
      }
    }
    const report = await store.finalize();
    expect((report.run as Record<string, unknown>).status).toBe("complete");
    expect(store.snapshot().findings).toBe(0);
    expect(store.executions()).toEqual(expect.arrayContaining([expect.objectContaining({ title: "路径发现", status: "succeeded" })]));
  });

  it("applies component scope before creating tasks", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-scope-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }, { name: 'B', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { components: ["B"] });
    const claim = await store.claim(5);
    expect(claim.tasks.length).toBe(1);
    expect(claim.tasks.every((task) => ((task.input as Record<string, unknown>).entry as Record<string, unknown>).component_name === "B")).toBe(true);
  });

  it("uses capability entry types to select only v3.1-compatible initial roots", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-capability-roots-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [
      { name: 'Home', exported: true },
      { name: 'DeepLink', exported: false, skills: [{ uris: ['demo://open'] }] }
    ] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { mode: "capability", capabilities: ["CAP-FS-001"] });
    const claim = await store.claim(5);
    expect(claim.tasks.map((task) => ((task.input as Record<string, any>).entry as Record<string, unknown>).component_name)).toEqual(["Home"]);
  });

  it("routes project capabilities to one project-scoped analysis unit", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-project-capability-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { mode: "capability", capabilities: ["CAP-CRYPTO-001"] });
    const claim = await store.claim(5);
    expect(claim.tasks).toHaveLength(1);
    expect((await store.taskDocument(claim.tasks[0]!)).input).toMatchObject({
      entry: { project_candidates: [expect.objectContaining({ type: "project_scope" })] },
      audit_scope: [expect.objectContaining({ capability_id: "CAP-CRYPTO-001", analysis_scope: "project", guidance: expect.any(Array) })],
      project_context: { modules: expect.any(Array), dependencies: expect.any(Array) },
    });
  });

  it("builds the v3.1-compatible semantic task context and carries retry feedback", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-task-context-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-FS-001"], components: ["A"] });
    const [first] = (await store.claim(1)).tasks;
    const firstDocument = await store.taskDocument(first!);
    expect(firstDocument).toMatchObject({
      previous_error: null,
      input: {
        audit_scope: [{ capability_id: "CAP-FS-001", domain: "filesystem" }],
        entry: { component: "A", project_candidates: expect.any(Array), facets: expect.any(Array) },
        analysis_contract: { stop_at: "component_call" },
      },
    });
    store.reconcile(first!.task_id, first!.attempt, undefined, "SCHEMA_INVALID:category");
    // A rejected task backs off before it may be claimed again; clear the gate to observe retry feedback.
    const db = new Database(store.paths.db);
    db.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(first!.task_id);
    db.close();
    const [retry] = (await store.claim(1)).tasks;
    expect(await store.taskDocument(retry!)).toMatchObject({ previous_error: "SCHEMA_INVALID:category" });
  });

  it("backs off rejected tasks before the rolling pool may reclaim them", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-backoff-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-FS-001"], components: ["A"] });
    const [first] = (await store.claim(1)).tasks;
    store.reconcile(first!.task_id, first!.attempt, undefined, "SCHEMA_INVALID:category");

    // Not claimable while the backoff window is open.
    expect((await store.claim(1)).tasks).toHaveLength(0);
    const db = new Database(store.paths.db);
    const gate = db.prepare("SELECT retry_after,status FROM tasks WHERE task_id=?").get(first!.task_id) as { retry_after: string | null; status: string };
    expect(gate.status).toBe("queued");
    expect(gate.retry_after).not.toBeNull();
    expect(new Date(gate.retry_after!).getTime() - Date.now()).toBeGreaterThan(20_000);

    // Once the gate passes the task is claimable again and the gate is cleared.
    db.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(first!.task_id);
    db.close();
    const [retry] = (await store.claim(1)).tasks;
    expect(retry!.task_id).toBe(first!.task_id);
    const cleared = new Database(store.paths.db);
    expect(cleared.prepare("SELECT retry_after FROM tasks WHERE task_id=?").get(first!.task_id)).toEqual({ retry_after: null });
    cleared.close();
  });

  it("does not back off an exhausted task", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-backoff-exhaust-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-FS-001"], components: ["A"] });
    const [first] = (await store.claim(1)).tasks;
    store.reconcile(first!.task_id, first!.attempt, undefined, "model_failed");
    const db = new Database(store.paths.db);
    db.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(first!.task_id);
    db.close();
    const [second] = (await store.claim(1)).tasks;
    store.reconcile(second!.task_id, second!.attempt, undefined, "model_failed");
    const db2 = new Database(store.paths.db);
    db2.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(first!.task_id);
    db2.close();
    const [third] = (await store.claim(1)).tasks;
    expect(store.reconcile(third!.task_id, third!.attempt, undefined, "model_failed")).toMatchObject({ status: "exhausted" });
    const final = new Database(store.paths.db);
    expect(final.prepare("SELECT status,retry_after FROM tasks WHERE task_id=?").get(first!.task_id)).toEqual({ status: "exhausted", retry_after: null });
    final.close();
  });

  it("normalizes capability domain and ordered fact edges before validation", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-normalize-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }] } }`);
    const store = await AuditStore.create(root, await profileProject(root), { capabilities: ["CAP-INJ-001"], components: ["A"] });
    const [task] = (await store.claim(1)).tasks;
    const candidate = emptySemantic(task as Record<string, any>, {
      operation_groups: [{
        group_key: "query", category: "sql", capability_id: "CAP-INJ-001", title: "查询",
        operation: { body: "query", location: "A.ets:12" }, controlled_properties: ["want.id"],
        context: { external_actor: "外部应用", intended_behavior: "查询", protected_assets: ["数据"], direct_observed_effect: "执行查询", effect_hypotheses: [], evidence_refs: ["E1"] },
        branches: [{ condition: "always", locations: ["A.ets:10"], evidence_refs: ["E1"] }],
        facts: [{ fact_key: "entry", type: "entrypoint", body: "入口", evidence_refs: ["E1"] }],
        security_checks: [], evidence_refs: ["E1"],
      }],
      evidence: [{ evidence_id: "E1", kind: "atlas_trace", source: "atlas", summary: "trace", location: "A.ets:12" }],
    });
    const normalizedOutcome = store.reconcile(task!.task_id, task!.attempt, candidate);
    expect(normalizedOutcome, JSON.stringify(normalizedOutcome)).toMatchObject({ accepted: true });
    const db = new (await import("better-sqlite3")).default(store.paths.db);
    const group = db.prepare("SELECT category,payload_json FROM operation_groups").get() as { category: string; payload_json: string };
    expect(group.category).toBe("injection");
    expect(JSON.parse(group.payload_json).edges).toHaveLength(1);
    db.close();
  });

  it("expands a recorded component call into a new semantic task", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-call-"));
    await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }, { name: 'B', exported: false }] } }`);
    const model = await profileProject(root);
    const target = model.components.find((item) => item.name === "B")!;
    const store = await AuditStore.create(root, model, { components: ["A"] });
    const [source] = (await store.claim(5)).tasks;
    const outcome = store.reconcile(source!.task_id, source!.attempt, emptySemantic(source as Record<string, any>, {
      summary: "calls B",
      component_calls: [{
        call_key: "call-b", target_component_id: target.component_id, target_symbol: "B.onCreate", transport: "startAbility",
        call_location: "A.ets:10", condition: "always", parameter_mappings: [{ source_property: "want.x", target_property: "want.x", control_state: "preserved", transform: "none" }],
        principal_transition: { caller_principal: "external", callee_observed_principal: "A", origin_binding: "replaced_by_caller", authority_used: "source_component", evidence_refs: [] },
        security_checks: [], evidence_refs: [],
      }],
    }));
    expect(outcome.accepted).toBe(true);
    const expanded = await store.claim(5);
    expect(expanded.tasks).toHaveLength(1);
    expect(expanded.tasks[0]!.input.entry.component_name).toBe("B");
    expect(expanded.tasks[0]!.input.upstream_calls).toHaveLength(1);
  });
});
