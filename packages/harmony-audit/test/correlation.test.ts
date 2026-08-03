import Database from "better-sqlite3";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildCrossComponentGroup, extendPath, seedPath } from "../src/correlation/engine.js";
import { profileProject, type ProjectModel } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";

const coverage = { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["onCreate"], operation_sites_checked: [], unresolved_targets: [] };
const principal = (caller: string, observed: string, binding: "preserved" | "replaced_by_caller" = "preserved") => ({ caller_principal: caller, callee_observed_principal: observed, origin_binding: binding, authority_used: binding === "preserved" ? "origin" : "source_component", evidence_refs: [] });
const mapping = (source: string, target: string, state: "preserved" | "constrained" | "constant" | "unknown" = "preserved") => ({ source_property: source, target_property: target, control_state: state, transform: state === "constrained" ? "allowlist" : "none" });
const call = (key: string, target: string, sourceProperty: string, targetProperty: string, binding: "preserved" | "replaced_by_caller" = "preserved") => ({
  call_key: key, target_component_id: target, target_symbol: "Target.onCreate", transport: "startAbility", call_location: `${key}.ets:10`, condition: "always",
  parameter_mappings: [mapping(sourceProperty, targetProperty)], principal_transition: principal("external", binding === "preserved" ? "external" : "source-component", binding), security_checks: [], evidence_refs: [],
});
const semantic = (task: Record<string, any>, calls: Record<string, unknown>[] = [], groups: Record<string, unknown>[] = []) => ({
  task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked", coverage, operation_groups: groups, component_calls: calls, evidence: [],
});
const group = (key: string, property: string) => ({
  group_key: key, category: "injection", capability_id: "CAP-INJ-001", title: "query", operation: { body: "query", location: "Sink.ets:20" },
  controlled_properties: [property], context: { external_actor: "caller", intended_behavior: "query", protected_assets: ["records"], observed_effect: "query runs", evidence_refs: [] },
  branches: [{ condition: "always", locations: ["Sink.ets:20"], evidence_refs: [] }],
  facts: [{ fact_key: "sink", type: "operation", body: "query", evidence_refs: [] }], edges: [], security_checks: [], evidence_refs: [],
});

async function project(names: string[]): Promise<{ root: string; model: ProjectModel; store: AuditStore }> {
  const root = await mkdtemp(join(tmpdir(), "harmony-correlation-")); await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [${names.map((name) => `{ name: '${name}', exported: true }`).join(",")}] } }`);
  const model = await profileProject(root); return { root, model, store: await AuditStore.create(root, model, { capabilities: ["CAP-INJ-001"], components: [names[0]!] }) };
}
const component = (model: ProjectModel, name: string) => String(model.components.find((item) => item.name === name)!.component_id);

describe("deterministic cross-component correlation", () => {
  it("composes control and principal state across multiple hops", () => {
    const first = seedPath({ sourceEntryId: "PE-A", sourceComponentId: "CMP-A", sourceTaskId: "TASK-A", targetEntryId: "PE-B", targetComponentId: "CMP-B", call: call("ab", "CMP-B", "want.input", "want.forwarded") });
    const second = extendPath(first, { sourceEntryId: "PE-B", sourceComponentId: "CMP-B", sourceTaskId: "TASK-B", targetEntryId: "PE-C", targetComponentId: "CMP-C", call: { ...call("bc", "CMP-C", "want.forwarded", "query", "replaced_by_caller"), parameter_mappings: [mapping("want.forwarded", "query", "constrained")], security_checks: [{ type: "permission", location: "B.ets:8", protects: "call", subject_kind: "immediate_caller", validated_property: "permission", behavior: "reject", evidence_refs: [] }] } });
    expect(second.parameter_chains[0]).toMatchObject({ origin_property: "want.input", current_property: "query", control_state: "constrained", transforms: ["none", "allowlist"] });
    expect(second.principal_state).toMatchObject({ origin_principal: "external", immediate_caller: "CMP-B", origin_binding: "replaced_by_caller", authority_used: "source_component" });
    expect(second.security_checks[0]).toMatchObject({ source_component_id: "CMP-B", hop_index: 1, applies_to_origin: false });
    const cross = buildCrossComponentGroup(second, group("query", "query"));
    expect(cross).toMatchObject({ scope: "cross_component", controlled_properties: ["want.input"] });
  });

  it("marks a cycle and stops parameter propagation when properties no longer connect", () => {
    const first = seedPath({ sourceEntryId: "PE-A", sourceComponentId: "CMP-A", sourceTaskId: "TASK-A", targetEntryId: "PE-B", targetComponentId: "CMP-B", call: call("ab", "CMP-B", "x", "y") });
    const cycle = extendPath(first, { sourceEntryId: "PE-B", sourceComponentId: "CMP-B", sourceTaskId: "TASK-B", targetEntryId: "PE-A", targetComponentId: "CMP-A", call: call("ba", "CMP-A", "unrelated", "x") });
    expect(cycle.cycle).toBe(true); expect(cycle.parameter_chains).toHaveLength(0);
    expect(buildCrossComponentGroup(cycle, group("sink", "x"))).toBeUndefined();
  });

  it("persists multi-hop paths and materializes cross-component groups", async () => {
    const { model, store } = await project(["A", "B", "C"]); const b = component(model, "B"); const c = component(model, "C");
    const [aTask] = (await store.claim(1)).tasks;
    expect(store.reconcile(aTask!.task_id, aTask!.attempt, semantic(aTask as Record<string, any>, [call("ab", b, "want.input", "want.forwarded")]))).toMatchObject({ accepted: true });
    const [bTask] = (await store.claim(1)).tasks;
    expect(store.reconcile(bTask!.task_id, bTask!.attempt, semantic(bTask as Record<string, any>, [call("bc", c, "want.forwarded", "query")], [group("b-query", "want.forwarded")]))).toMatchObject({ accepted: true });
    const db = new Database(store.paths.db);
    const paths = (db.prepare("SELECT payload_json FROM component_paths ORDER BY rowid").all() as { payload_json: string }[]).map((row) => JSON.parse(row.payload_json));
    expect(paths).toHaveLength(2); expect(paths[1].component_ids).toHaveLength(3);
    expect(paths[1].parameter_chains[0]).toMatchObject({ origin_property: "want.input", current_property: "query" });
    expect((db.prepare("SELECT COUNT(*) n FROM cross_component_groups").get() as { n: number }).n).toBe(1);
    expect(db.pragma("foreign_key_check") as unknown[]).toHaveLength(0); db.close();
  });

  it("merges two source paths into one queued target task", async () => {
    const root = await mkdtemp(join(tmpdir(), "harmony-merge-")); await mkdir(join(root, "entry/src/main"), { recursive: true });
    await writeFile(join(root, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A', exported: true }, { name: 'C', exported: true }, { name: 'B', exported: false }] } }`);
    const model = await profileProject(root); const b = component(model, "B");
    const store = await AuditStore.create(root, model, { capabilities: ["CAP-INJ-001"], components: ["A", "C"] });
    const sources = (await store.claim(5)).tasks;
    for (const source of sources) expect(store.reconcile(source.task_id, source.attempt, semantic(source as Record<string, any>, [call(`${source.input.entry.component_name}-b`, b, "input", "forwarded")]))).toMatchObject({ accepted: true });
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM component_paths WHERE target_entry_id=(SELECT entry_id FROM analysis_units WHERE component_id=?)").get(b) as { n: number }).n).toBe(2);
    const target = db.prepare("SELECT input_json FROM tasks WHERE semantic_key=?").get(`semantic:${b}`) as { input_json: string };
    expect(JSON.parse(target.input_json).upstream_calls).toHaveLength(2); db.close();
  });

  it("records cycles without creating another semantic task", async () => {
    const { model, store } = await project(["A", "B"]); const a = component(model, "A"); const b = component(model, "B");
    const [aTask] = (await store.claim(1)).tasks;
    store.reconcile(aTask!.task_id, aTask!.attempt, semantic(aTask as Record<string, any>, [call("ab", b, "x", "y")], [group("a-sink", "x")]));
    const bTask = (await store.claim(5)).tasks.find((task) => task.kind === "component_semantic_analysis");
    expect(bTask).toBeDefined();
    store.reconcile(bTask!.task_id, bTask!.attempt, semantic(bTask as Record<string, any>, [call("ba", a, "y", "x")]));
    const db = new Database(store.paths.db);
    expect((db.prepare("SELECT COUNT(*) n FROM component_paths WHERE cycle=1").get() as { n: number }).n).toBe(1);
    expect((db.prepare("SELECT COUNT(*) n FROM tasks WHERE kind='component_semantic_analysis'").get() as { n: number }).n).toBe(2);
    expect((db.prepare("SELECT COUNT(*) n FROM cross_component_groups").get() as { n: number }).n).toBeGreaterThan(0); db.close();
  });
});
