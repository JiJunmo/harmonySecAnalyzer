import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PluginDefinition } from "@agent-platform/core";
import { describe, expect, it, vi } from "vitest";
import { plugin as dummyPlugin } from "../../dummy-plugin/src/index.js";
import { PluginHostService } from "../src/index.js";

const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };

describe("domain-neutral PluginHostService", () => {
  it("hosts plugins and delegates opaque runs, events, actions and artifacts", async () => {
    const host = await PluginHostService.create({
      plugins: [dummyPlugin],
      configs: { dummy: { prefix: "host" } },
      logger,
    });
    expect(host.listPlugins().map((manifest) => manifest.id)).toEqual(["dummy"]);

    const emitted: string[] = [];
    const unsubscribe = host.subscribe((event) => emitted.push(event.type));
    const accepted = await host.createRun("dummy", { nested: { value: 42 } });
    expect(accepted).toMatchObject({ pluginId: "dummy", status: "accepted" });

    const completed = await host.action(accepted.id, { name: "complete" });
    expect(completed).toMatchObject({ pluginId: "dummy", status: "succeeded", pluginRun: { id: "host-1" } });
    expect(host.listRuns()).toHaveLength(1);
    expect((await host.getRun(accepted.id)).status).toBe("succeeded");

    const events = [];
    for await (const event of host.events(accepted.id)) events.push(event);
    expect(events.map((event) => event.type)).toEqual(["run.created", "run.succeeded"]);
    expect((await host.artifacts(accepted.id)).map((artifact) => artifact.id)).toEqual(["result"]);
    expect(await host.executions(accepted.id)).toEqual([]);
    await expect(host.execution(accepted.id, "missing")).rejects.toThrow("plugin_execution_not_supported:dummy");
    const artifact = await host.openArtifact(accepted.id, "result");
    expect(JSON.parse(new TextDecoder().decode(artifact.body as Uint8Array))).toMatchObject({ status: "succeeded" });
    expect(emitted).toContain("run_initialized");
    expect(emitted).toContain("run_updated");

    unsubscribe();
    await host.dispose();
    expect(() => host.listPlugins()).toThrow("plugin_host_disposed");
  });

  it("validates plugin configuration and rejects unknown plugins", async () => {
    await expect(PluginHostService.create({
      plugins: [dummyPlugin],
      configs: { dummy: { prefix: "", unexpected: true } },
    })).rejects.toThrow("plugin_config_invalid:dummy");

    const host = await PluginHostService.create({ plugins: [dummyPlugin], configs: { dummy: {} } });
    await expect(host.createRun("missing", {})).rejects.toThrow("plugin_not_registered:missing");
    await host.dispose();
  });

  it("passes shared platform configuration to plugins without copying it into plugin config", async () => {
    let received: Readonly<Record<string, unknown>> | undefined;
    const observingPlugin: PluginDefinition = {
      ...dummyPlugin,
      activate(context) {
        received = context.sharedConfig;
        return dummyPlugin.activate(context);
      },
    };
    const sharedConfig = { models: { default: "fast" }, mcp: { maxSessions: 5 } };
    const host = await PluginHostService.create({ plugins: [observingPlugin], configs: { dummy: {} }, sharedConfig });
    expect(received).toBe(sharedConfig);
    await host.dispose();
  });

  it("lists Web contributions without exposing resource roots and safely opens assets", async () => {
    const assetsRoot = await mkdtemp(join(tmpdir(), "plugin-contribution-"));
    await writeFile(join(assetsRoot, "index.html"), "<h1>Dummy console</h1>");
    const pluginWithWeb: PluginDefinition = {
      ...dummyPlugin,
      manifest: { ...dummyPlugin.manifest, contributes: ["runs", "web"] },
      web: [{ id: "console", title: "Dummy Console", entry: "index.html", assetsRoot }],
    };
    const host = await PluginHostService.create({ plugins: [pluginWithWeb], configs: { dummy: {} } });

    expect(host.listWebContributions()).toEqual([{
      pluginId: "dummy", id: "console", title: "Dummy Console", entry: "index.html",
    }]);
    const asset = await host.openWebAsset("dummy", "console", "index.html");
    expect(new TextDecoder().decode(asset.body)).toContain("Dummy console");
    await expect(host.openWebAsset("dummy", "console", "../secret.txt")).rejects.toThrow("web_asset_path_invalid");
    await expect(host.openWebAsset("dummy", "missing", "index.html")).rejects.toThrow("web_contribution_not_found");

    await host.dispose();
  });
});
