import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GraphApplication, GraphRegistry, type AgentPoolBackend, type ChildExecutionResult, type SubAgentInstance } from "@agent-platform/core";
import { HarmonyAuditGraphPlugin } from "../src/graph.js";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";
import type { HarmonyPoolBackend } from "../src/pool-backend.js";

const emptySemantic = (instance: SubAgentInstance) => {
  const input = instance.handle.input as Record<string, unknown>;
  return { task_id: instance.taskId, entry_id: (input.entry as Record<string, unknown>).candidate_id, summary: "checked", coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["A.onCreate"], operation_sites_checked: [], unresolved_targets: [] }, operation_groups: [], component_calls: [] };
};

describe("Harmony LangGraph plugin", () => {
  it("runs the parent state machine around the rolling pool", async () => {
    const target = await mkdtemp(join(tmpdir(), "harmony-graph-"));
    await mkdir(join(target, "entry/src/main"), { recursive: true });
    await writeFile(join(target, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A' }] } }`);
    const store = await AuditStore.create(target, await profileProject(target));
    const backend: AgentPoolBackend<Record<string, unknown>, Record<string, unknown>> = {
      claim: (_directory, limit) => store.claim(limit),
      execute: async (_directory, instance): Promise<ChildExecutionResult> => ({ instance, status: "completed" }),
      reconcile: (_directory, instance) => store.reconcile(instance.taskId, instance.attempt, emptySemantic(instance)),
      snapshot: () => store.snapshot(),
      pendingCounts: (snapshot) => { const tasks = snapshot.tasks as Record<string, number>; return { queued: tasks.queued ?? 0, running: tasks.running ?? 0 }; },
    };
    const plugin = new HarmonyAuditGraphPlugin(store, backend as HarmonyPoolBackend, 5);
    const output = await new GraphApplication(new GraphRegistry().register(plugin)).run(plugin.name, store.runDirectory) as Record<string, unknown>;
    expect(output.phase).toBe("complete");
    expect((store.snapshot().run as Record<string, unknown>).status).toBe("complete");
  });

  it("persists a failed run when the pool cannot claim work", async () => {
    const target = await mkdtemp(join(tmpdir(), "harmony-graph-fail-"));
    await mkdir(join(target, "entry/src/main"), { recursive: true });
    await writeFile(join(target, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A' }] } }`);
    const store = await AuditStore.create(target, await profileProject(target));
    const backend: AgentPoolBackend<Record<string, unknown>, Record<string, unknown>> = {
      claim: () => ({ ok: false, reason: "database_unavailable", tasks: [] }),
      execute: async (_directory, instance) => ({ instance, status: "failed" }), reconcile: () => ({}),
      snapshot: () => ({ tasks: { queued: 1, running: 0 } }), pendingCounts: () => ({ queued: 1, running: 0 }),
    };
    const plugin = new HarmonyAuditGraphPlugin(store, backend as HarmonyPoolBackend, 1);
    const output = await new GraphApplication(new GraphRegistry().register(plugin)).run(plugin.name, store.runDirectory) as Record<string, unknown>;
    expect(output.phase).toBe("failed");
    expect((store.snapshot().run as Record<string, unknown>)).toMatchObject({ status: "failed", error: "pool_claim_failed:database_unavailable" });
  });

  it("resumes from run.db when a failed checkpoint already exists", async () => {
    const target = await mkdtemp(join(tmpdir(), "harmony-graph-resume-")); await mkdir(join(target, "entry/src/main"), { recursive: true });
    await writeFile(join(target, "entry/src/main/module.json5"), `{ module: { name: 'entry', abilities: [{ name: 'A' }] } }`);
    const store = await AuditStore.create(target, await profileProject(target), { components: ["A"] });
    const failing: AgentPoolBackend<Record<string, unknown>, Record<string, unknown>> = {
      claim: () => ({ ok: false, reason: "worker_crashed", tasks: [] }), execute: async (_directory, instance) => ({ instance, status: "failed" }),
      reconcile: () => ({}), snapshot: () => ({ tasks: { queued: 1 } }), pendingCounts: () => ({ queued: 1, running: 0 }),
    };
    const first = new HarmonyAuditGraphPlugin(store, failing as HarmonyPoolBackend, 1);
    expect((await new GraphApplication(new GraphRegistry().register(first)).run(first.name, store.runDirectory) as Record<string, unknown>).phase).toBe("failed");
    store.resume();
    const healthy: AgentPoolBackend<Record<string, unknown>, Record<string, unknown>> = {
      claim: (_directory, limit) => store.claim(limit), execute: async (_directory, instance) => ({ instance, status: "completed" }),
      reconcile: (_directory, instance) => store.reconcile(instance.taskId, instance.attempt, emptySemantic(instance)), snapshot: () => store.snapshot(),
      pendingCounts: (snapshot) => { const tasks = snapshot.tasks as Record<string, number>; return { queued: tasks.queued ?? 0, running: tasks.running ?? 0 }; },
    };
    const resumed = new HarmonyAuditGraphPlugin(store, healthy as HarmonyPoolBackend, 1);
    const output = await new GraphApplication(new GraphRegistry().register(resumed)).run(resumed.name, store.runDirectory) as Record<string, unknown>;
    expect(output.phase).toBe("complete"); expect((store.status().run as Record<string, unknown>).status).toBe("complete");
  });
});
