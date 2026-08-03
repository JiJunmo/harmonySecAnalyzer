import { activatePlugin, PluginRegistry } from "@agent-platform/core";
import { describe, expect, it, vi } from "vitest";
import { plugin } from "../src/index.js";

const logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

describe("domain-neutral dummy plugin", () => {
  it("registers, activates and round-trips opaque payloads through the v1 contract", async () => {
    const registry = new PluginRegistry().register(plugin);
    expect(registry.get("dummy").manifest.apiVersion).toBe("1");

    const runtime = await activatePlugin(plugin, {
      config: { prefix: "probe" },
      signal: new AbortController().signal,
      logger,
    });
    const payload = { nested: { value: 42 }, list: ["a", "b"] };
    const created = await runtime.createRun({ requestId: "request-1", payload });

    expect(created.run.id).toBe("probe-1");
    expect(created.details).toBe(payload);
    expect((await runtime.adoptRun(created.run)).status).toBe("running");

    const events = [];
    for await (const event of runtime.events(created.run)) events.push(event);
    expect(events).toHaveLength(1);
    expect(events[0]?.payload).toBe(payload);

    const completed = await runtime.action(created.run, { name: "complete" });
    expect(completed.status).toBe("succeeded");
    const artifacts = await runtime.artifacts(created.run);
    expect(artifacts).toEqual([{ id: "result", name: "result.json", mediaType: "application/json", size: expect.any(Number) }]);

    const artifact = await runtime.openArtifact(created.run, "result");
    expect(JSON.parse(new TextDecoder().decode(artifact.body as Uint8Array))).toEqual({
      prefix: "probe",
      payload,
      status: "succeeded",
    });

    await runtime.dispose();
    await expect(runtime.getRun(created.run)).rejects.toThrow("dummy_plugin_disposed");
  });

  it("rejects invalid plugin configuration before activation", async () => {
    await expect(activatePlugin(plugin, {
      config: { prefix: "", unexpected: true },
      signal: new AbortController().signal,
      logger,
    })).rejects.toThrow("plugin_config_invalid:dummy");
  });
});
