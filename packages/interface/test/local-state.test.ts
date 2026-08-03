import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LocalGatewayState, PluginHostService, type HostRunView } from "../src/index.js";
import { plugin as dummyPlugin } from "../../dummy-plugin/src/index.js";

const hostRun = (id: string, updatedAt: string): HostRunView => ({
  id, pluginId: "dummy", pluginRun: { id: `plugin-${id}` }, status: "succeeded",
  createdAt: updatedAt, updatedAt,
});

describe("local gateway reliability state", () => {
  it("persists host runs, subagent traces and prunes terminal history without touching artifacts", async () => {
    const root = await mkdtemp(join(tmpdir(), "gateway-state-"));
    const state = await LocalGatewayState.open(root, { retentionDays: 1, maxHostRuns: 1, maxSubagentRuns: 1 });
    const repository = state.hostRuns();
    repository.save(hostRun("old", "2020-01-01T00:00:00.000Z"));
    repository.save(hostRun("new", new Date().toISOString()));
    state.saveSubagent({
      id: "SUB-1", parentSessionId: "parent", task: "done", status: "succeeded", model: "test/model", tools: ["read"],
      result: "ok", createdAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
      trace: [{ sequence: 1, type: "agent_completed", timestamp: new Date().toISOString(), payload: { result: "ok" } }],
    });
    expect(state.prune()).toMatchObject({ hostRuns: 1, subagentRuns: 0 });
    expect(repository.load().map((run) => run.id)).toEqual(["new"]);
    expect(state.restoredSubagents()[0]).toMatchObject({ id: "SUB-1", trace: [{ type: "agent_completed" }] });
    expect(await state.diagnostics()).toMatchObject({ status: "ok", hostRuns: 1, subagentRuns: 1 });
    state.close();
  });

  it("marks a host job interrupted before plugin initialization as failed after restart", async () => {
    const root = await mkdtemp(join(tmpdir(), "gateway-host-restore-"));
    const state = await LocalGatewayState.open(root);
    state.hostRuns().save({ id: "JOB-interrupted", pluginId: "dummy", status: "accepted", createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-01T00:00:00.000Z" });
    const host = await PluginHostService.create({ plugins: [dummyPlugin], runRepository: state.hostRuns() });
    expect(host.listRuns()).toEqual([expect.objectContaining({ id: "JOB-interrupted", status: "failed", error: { code: "gateway_restarted", message: expect.any(String) } })]);
    await host.dispose(); state.close();
  });
});
