import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PLUGIN_API_VERSION, PluginRegistry, configSection, discoverPlugins, loadConfig, setMcpServerEnabled, type PluginConfigDocument, type PluginDefinition } from "../src/index.js";

describe("configuration-driven plugins", () => {
  it("loads plugin modules without core domain registration", async () => {
    const root = await mkdtemp(join(tmpdir(), "agent-plugin-"));
    await writeFile(join(root, "example.mjs"), `export const plugin={manifest:{apiVersion:'1',id:'example',version:'1.0.0',displayName:'Example',contributes:['runs']},activate:()=>({})}`);
    await writeFile(join(root, "agent-platform.json"), JSON.stringify({ plugins: { modules: ["./example.mjs"] } }));
    const config = await loadConfig(join(root, "agent-platform.json"));
    const document = configSection<PluginConfigDocument>(config, "plugins");
    const registry = await discoverPlugins(document.modules ?? [], root);
    expect(registry.list().map((item) => item.manifest.id)).toEqual(["example"]);
  });

  it("rejects incompatible API versions and duplicate plugin ids", () => {
    const definition: PluginDefinition = {
      manifest: {
        apiVersion: PLUGIN_API_VERSION,
        id: "example",
        version: "1.0.0",
        displayName: "Example",
        contributes: ["runs"],
      },
      activate: () => ({}) as never,
    };
    const registry = new PluginRegistry().register(definition);
    expect(() => registry.register(definition)).toThrow("plugin_already_registered:example");
    expect(() => new PluginRegistry().register({
      ...definition,
      manifest: { ...definition.manifest, apiVersion: "2" },
    })).toThrow("plugin_api_incompatible:example:2:1");
  });

  it("persists MCP enabled state in the platform-only config", async () => {
    const root = await mkdtemp(join(tmpdir(), "agent-mcp-config-"));
    const path = join(root, "agent-platform.json");
    await writeFile(path, JSON.stringify({ mcp: { servers: { example: { command: "example-server" } } }, plugins: {} }));
    await setMcpServerEnabled(path, "example", false);
    expect(JSON.parse(await (await import("node:fs/promises")).readFile(path, "utf8"))).toMatchObject({
      mcp: { servers: { example: { command: "example-server", enabled: false } } },
    });
  });
});
