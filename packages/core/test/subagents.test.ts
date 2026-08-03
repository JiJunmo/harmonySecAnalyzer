import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fauxAssistantMessage, fauxProvider } from "@earendil-works/pi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { PiSessionFactory, SubagentRuntime } from "../src/index.js";

const runtimes: SubagentRuntime[] = [];
afterEach(async () => {
  await Promise.all(runtimes.splice(0).map((runtime) => runtime.dispose()));
  delete process.env.TEST_SUBAGENT_KEY;
});

describe("domain-neutral SubagentRuntime", () => {
  it("runs an isolated Pi worker and exposes its lifecycle result", async () => {
    process.env.TEST_SUBAGENT_KEY = "runtime-only";
    const sessions = await PiSessionFactory.create({ models: {
      default: "general",
      providers: { test: { type: "faux", baseUrl: "http://unused.invalid/v1", apiKeyEnv: "TEST_SUBAGENT_KEY" } },
      catalog: { general: { provider: "test", id: "general-model" } },
    } });
    const faux = fauxProvider({ provider: "test", api: "faux", models: [{ id: "general-model" }] });
    sessions.models.runtime.registerNativeProvider(faux.provider);
    faux.setResponses([fauxAssistantMessage("isolated result")]);
    const runtime = new SubagentRuntime({ sessions, cwd: await mkdtemp(join(tmpdir(), "subagent-runtime-")), tools: ["read"] });
    runtimes.push(runtime);

    const observed: string[] = [];
    runtime.subscribe((run) => observed.push(run.status));
    const result = await runtime.run("parent-1", "Inspect one bounded concern");

    expect(result).toMatchObject({ parentSessionId: "parent-1", status: "succeeded", result: "isolated result", tools: ["read"] });
    expect(observed).toEqual(["queued", "running", "succeeded"]);
    expect(result.trace).toBeUndefined();
    const detail = runtime.get(result.id);
    expect(detail).toMatchObject(result);
    expect(detail.trace?.map((event) => event.type)).toEqual(expect.arrayContaining([
      "run_queued", "run_started", "agent_started", "assistant_message", "agent_completed",
    ]));
    expect(detail.trace?.find((event) => event.type === "assistant_message")?.payload).toMatchObject({
      content: [{ type: "text", text: "isolated result" }],
    });
    expect(detail.trace?.every((event, index) => index === 0 || event.sequence > detail.trace![index - 1]!.sequence)).toBe(true);
  });

  it("restores persisted history and closes an interrupted run after gateway restart", async () => {
    process.env.TEST_SUBAGENT_KEY = "runtime-only";
    const sessions = await PiSessionFactory.create({ models: {
      default: "general",
      providers: { test: { type: "faux", baseUrl: "http://unused.invalid/v1", apiKeyEnv: "TEST_SUBAGENT_KEY" } },
      catalog: { general: { provider: "test", id: "general-model" } },
    } });
    const persisted: any[] = [];
    const runtime = new SubagentRuntime({
      sessions, cwd: await mkdtemp(join(tmpdir(), "subagent-restore-")),
      restoredRuns: [{ id: "SUB-interrupted", parentSessionId: "parent", task: "unfinished", status: "running", model: "test/general", tools: ["read"], createdAt: "2026-01-01T00:00:00.000Z", startedAt: "2026-01-01T00:00:01.000Z", trace: [] }],
      persistRun: (run) => persisted.push(run),
    });
    runtimes.push(runtime);
    expect(runtime.list()).toEqual([expect.objectContaining({ id: "SUB-interrupted", status: "aborted", error: "gateway_restarted" })]);
    expect(runtime.get("SUB-interrupted").trace).toEqual([expect.objectContaining({ type: "run_aborted", payload: { error: "gateway_restarted" } })]);
    expect(persisted.at(-1)).toMatchObject({ status: "aborted" });
  });
});
