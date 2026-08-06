import { mkdir, mkdtemp, readFile, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { activatePlugin } from "@agent-platform/core";
import { describe, expect, it, vi } from "vitest";
import { createHarmonyAuditPlugin } from "../src/plugin.js";
import { inspectHarmonyAuditReadiness } from "../src/readiness.js";
import type { HarmonyAuditOptions } from "../src/orchestrator.js";
import { HARMONY_MAX_AGENT_CAPACITY, harmonyAgentCapacity } from "../src/pool-policy.js";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";

async function projectFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "harmony-plugin-"));
  await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{module:{name:'entry',abilities:[{name:'MainAbility',exported:true}]}}`);
  return root;
}

const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

describe("HarmonyAuditPlugin adapter", () => {
  it("reports Atlas, Pi model and bundled Skill readiness before a run", async () => {
    const root = await projectFixture();
    const agentDir = join(root, "pi-agent");
    await mkdir(agentDir);
    process.env.TEST_HARMONY_READINESS_KEY = "runtime-only";
    await writeFile(join(agentDir, "settings.json"), JSON.stringify({ defaultProvider: "test", defaultModel: "audit-model" }));
    await writeFile(join(agentDir, "models.json"), JSON.stringify({ providers: { test: {
      baseUrl: "http://unused.invalid/v1", api: "openai-completions", apiKey: "$TEST_HARMONY_READINESS_KEY", models: [{ id: "audit-model" }],
    } } }));
    try {
      const readiness = await inspectHarmonyAuditReadiness({ atlasExecutable: process.execPath, piAgentDir: agentDir, piCwd: root, capacity: 5 });
      expect(readiness).toMatchObject({ ready: true, defaults: { capacity: 5, model: "test/audit-model" } });
      expect(readiness.checks.map((check) => check.id)).toEqual(["atlas", "model", "skills"]);
    } finally {
      delete process.env.TEST_HARMONY_READINESS_KEY;
    }
  });

  it("owns and enforces the five-slot audit policy", () => {
    expect(HARMONY_MAX_AGENT_CAPACITY).toBe(5);
    expect(harmonyAgentCapacity()).toBe(5);
    expect(() => harmonyAgentCapacity(6)).toThrow("harmony_audit_capacity_must_be_1_to_5");
  });

  it("contributes Harmony CLI commands without requiring platform branches", async () => {
    const definition = createHarmonyAuditPlugin();
    expect(definition.cli?.map((command) => command.name)).toEqual([
      "audit", "status", "resume", "cancel", "report", "capabilities", "components",
    ]);
    const audit = definition.cli?.find((command) => command.name === "audit");
    expect(await audit?.invoke(["/project", "--capacity", "3", "--component", "MainAbility"])).toEqual({
      kind: "run",
      payload: { target: "/project", capabilities: [], components: ["MainAbility"], capacity: 3 },
    });
    expect(await audit?.invoke(["/project", "--incremental"])).toEqual({
      kind: "run", payload: { target: "/project", incremental: true, capabilities: [], components: [] },
    });
    expect(() => audit?.invoke(["/project", "--incremental", "--component", "MainAbility"])).toThrow("usage:incremental_mode_cannot_filter_scope");
    expect(() => audit?.invoke(["/project", "--capacity", "9"])).toThrow("usage:capacity_must_be_1_to_5");
    const status = definition.cli?.find((command) => command.name === "status");
    expect(await status?.invoke(["/run"])).toEqual({ kind: "inspect", run: { id: "/run" } });
  });

  it("maps create, adopt, events, actions and reports to Plugin Contract v1", async () => {
    const root = await projectFixture();
    let receivedOptions: HarmonyAuditOptions | undefined;
    const definition = createHarmonyAuditPlugin({
      inspectReadiness: async () => ({
        ready: true,
        checks: [{ id: "atlas", ok: true, message: "atlas_ready" }, { id: "model", ok: true, message: "model_ready" }, { id: "skills", ok: true, message: "skills_ready" }],
        defaults: { capacity: 5, model: "test/audit-model" },
      }),
      createOrchestrator: (options) => {
        receivedOptions = options;
        return ({
        async run(context) {
          const target = String(context.request.metadata?.target);
          const store = await AuditStore.create(target, await profileProject(target));
          options.onRunCreated?.({ runId: store.runId(), runDirectory: store.runDirectory, target });
          return { runDirectory: store.runDirectory };
        },
        async resume(runDirectory) {
          return AuditStore.openExisting(runDirectory).resume();
        },
      });
      },
    });
    const activation = {
      config: { atlasExecutable: "atlas-test", allowedRoots: [root], capacity: 5, eventPollIntervalMs: 10 },
      sharedConfig: {
        pi: { agentDir: "/tmp/pi-agent", cwd: root },
        mcp: { maxSessions: 5 },
        skills: { roots: [] },
      },
      signal: new AbortController().signal,
      logger,
    };
    const runtime = await activatePlugin(definition, activation);
    expect(await runtime.operation({ name: "readiness" })).toMatchObject({ ready: true, allowedRoots: [await realpath(root)] });
    const created = await runtime.createRun({
      requestId: "request-1",
      payload: { target: root, components: ["MainAbility"], capabilities: [] },
    });

    expect(receivedOptions).toMatchObject({ piAgentDir: "/tmp/pi-agent", piCwd: root, mcp: activation.sharedConfig.mcp, skills: activation.sharedConfig.skills });

    expect(created.status).toBe("running");
    expect(created.run.id).toMatch(/\/reports\/harmony-audit-/);
    expect(created.progress?.completed).toBe(0);
    expect(created.progress?.total).toBeGreaterThan(0);
    expect((created.details as Record<string, unknown>).task_counts).toEqual({ queued: created.progress?.total });
    const executions = await runtime.executions?.(created.run);
    expect(executions).toEqual(expect.arrayContaining([expect.objectContaining({ kind: "component_semantic_analysis", status: "queued", title: "路径发现" })]));
    const execution = await runtime.execution?.(created.run, executions![0]!.id);
    expect(execution).toMatchObject({ execution: { id: executions![0]!.id }, input: { target_repo: await realpath(root) }, attempts: [], events: [] });

    const cancelled = await runtime.action(created.run, { name: "cancel", payload: { reason: "adapter-test" } });
    expect(cancelled.status).toBe("cancelled");
    const events = [];
    for await (const event of runtime.events(created.run)) events.push(event);
    expect(events.at(-1)).toMatchObject({ type: "run_cancelled", payload: { data: { reason: "adapter-test", cancelled_tasks: created.progress?.total } } });

    await runtime.action(created.run, { name: "rebuild-report" });
    expect((await runtime.artifacts(created.run)).map((artifact) => artifact.id).sort()).toEqual([
      "attack-matrix", "report-html", "report-json", "report-markdown",
    ]);
    const html = await runtime.openArtifact(created.run, "report-html");
    expect(new TextDecoder().decode(html.body as Uint8Array)).toContain("<!doctype html>");
    await runtime.dispose();

    const restarted = await activatePlugin(definition, activation);
    const adopted = await restarted.adoptRun(created.run);
    expect(adopted.status).toBe("cancelled");
    expect(adopted.run).toEqual(created.run);
    await restarted.dispose();
  });

  it("enforces plugin-owned path authorization and artifact ids", async () => {
    const root = await projectFixture();
    const outside = await projectFixture();
    const store = await AuditStore.create(root, await profileProject(root));
    const definition = createHarmonyAuditPlugin();
    const runtime = await activatePlugin(definition, {
      config: { atlasExecutable: "atlas-test", allowedRoots: [root] },
      signal: new AbortController().signal,
      logger,
    });

    await expect(runtime.adoptRun({ id: outside })).rejects.toThrow("harmony_audit_path_outside_allowed_roots");
    await expect(runtime.openArtifact({ id: store.runDirectory }, "../../run.db")).rejects.toThrow("harmony_audit_artifact_not_found");
    await runtime.dispose();
    expect(await readFile(store.paths.db)).toBeInstanceOf(Buffer);
  });

  it("discovers durable runs and marks orphaned running work recoverable after restart", async () => {
    const root = await projectFixture();
    const store = await AuditStore.create(root, await profileProject(root));
    expect((await store.claim(1)).tasks).toHaveLength(1);
    const runtime = await activatePlugin(createHarmonyAuditPlugin(), {
      config: { atlasExecutable: "atlas-test", allowedRoots: [root], discoverHistory: true },
      signal: new AbortController().signal, logger,
    });
    expect(await runtime.discoverRuns?.()).toEqual([{ id: await realpath(store.runDirectory) }]);
    expect(AuditStore.openExisting(store.runDirectory).status()).toMatchObject({
      run: { status: "failed", error: "gateway_restarted_execution_interrupted" },
      task_counts: { queued: expect.any(Number) }, recoverable: true,
    });
    await runtime.dispose();
  });
});

  it("restores the original capacity and model when a run is resumed", async () => {
    const root = await projectFixture();
    const received: HarmonyAuditOptions[] = [];
    const definition = createHarmonyAuditPlugin({
      inspectReadiness: async () => ({ ready: true, checks: [], defaults: { capacity: 5, model: "test/audit-model" } }),
      createOrchestrator: (options) => {
        received.push(options);
        return {
          async run(context) {
            const target = String(context.request.metadata?.target);
            const store = await AuditStore.create(target, await profileProject(target));
            options.onRunCreated?.({ runId: store.runId(), runDirectory: store.runDirectory, target });
            return { runDirectory: store.runDirectory };
          },
          async resume(runDirectory) {
            return AuditStore.openExisting(runDirectory).resume();
          },
        };
      },
    });
    const runtime = await activatePlugin(definition, {
      config: { atlasExecutable: "atlas-test", allowedRoots: [root], capacity: 5, model: "test/audit-model", eventPollIntervalMs: 10 },
      sharedConfig: { pi: { agentDir: "/tmp/pi-agent", cwd: root }, mcp: { maxSessions: 5 }, skills: { roots: [] } },
      signal: new AbortController().signal,
      logger,
    });

    const created = await runtime.createRun({ requestId: "request-cap", payload: { target: root, capacity: 2, model: "test/strong-model" } });
    expect(received[0]).toMatchObject({ capacity: 2, model: "test/strong-model" });

    // Resume without explicit parameters restores the run's original settings.
    await runtime.action(created.run, { name: "resume" });
    expect(received[1]).toMatchObject({ capacity: 2, model: "test/strong-model" });

    // Explicit action parameters still win over the stored settings.
    await new Promise((done) => setTimeout(done, 5));
    await runtime.action(created.run, { name: "resume", payload: { capacity: 4 } });
    expect(received[2]).toMatchObject({ capacity: 4, model: "test/strong-model" });
    await runtime.dispose();
  });
