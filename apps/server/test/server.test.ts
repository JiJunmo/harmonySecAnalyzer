import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { PluginDefinition } from "@agent-platform/core";
import { PiSessionFactory } from "@agent-platform/core";
import { fauxAssistantMessage, fauxProvider } from "@earendil-works/pi-ai";
import { AssistantSessionService, PluginHostService } from "@agent-platform/interface";
import { afterEach, describe, expect, it } from "vitest";
import { plugin as dummyPlugin } from "../../../packages/dummy-plugin/src/index.js";
import { createPluginWebServer } from "../src/server.js";

const resources: { server: ReturnType<typeof createPluginWebServer>; host: PluginHostService; assistant?: AssistantSessionService }[] = [];
afterEach(async () => {
  try {
    await Promise.all(resources.splice(0).map(async ({ server, host, assistant }) => {
      await new Promise<void>((done) => server.close(() => done()));
      await Promise.all([host.dispose(), assistant?.dispose()]);
    }));
  } finally {
    delete process.env.TEST_SERVER_ASSISTANT_KEY;
  }
});

describe("generic plugin host web API", () => {
  it("serves authenticated plugin, run, operation, action and artifact APIs", async () => {
    const webRoot = await mkdtemp(join(tmpdir(), "plugin-web-"));
    await writeFile(join(webRoot, "index.html"), "<h1>Plugin Host</h1>");
    const contributionRoot = await mkdtemp(join(tmpdir(), "plugin-contribution-"));
    await writeFile(join(contributionRoot, "index.html"), "<h1>Dummy console</h1>");
    const pluginWithWeb: PluginDefinition = {
      ...dummyPlugin,
      manifest: { ...dummyPlugin.manifest, contributes: ["runs", "web"] },
      web: [{ id: "console", title: "Dummy Console", entry: "index.html", assetsRoot: contributionRoot }],
      activate(context) {
        const runtime = dummyPlugin.activate(context);
        const html = new TextEncoder().encode("<!doctype html><button id='tab'>Tab</button><script>document.querySelector('#tab').dataset.ready='true'</script>");
        return new Proxy(runtime, {
          get(target, property) {
            if (property === "artifacts") return async (run: Parameters<typeof target.artifacts>[0]) => [
              ...await target.artifacts(run),
              { id: "report", name: "report.html", mediaType: "text/html; charset=utf-8", size: html.byteLength },
            ];
            if (property === "openArtifact") return async (run: Parameters<typeof target.openArtifact>[0], artifactId: string) => artifactId === "report" ? {
              descriptor: { id: "report", name: "report.html", mediaType: "text/html; charset=utf-8", size: html.byteLength }, body: html,
            } : target.openArtifact(run, artifactId);
            const value = Reflect.get(target, property, target) as unknown;
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
      },
    };
    const host = await PluginHostService.create({ plugins: [pluginWithWeb], configs: { dummy: { prefix: "web" } } });
    const reliability = { diagnostics: async () => ({ status: "ok", hostRuns: 1, subagentRuns: 2 }), prune: () => ({ hostRuns: 0, subagentRuns: 1 }) };
    const server = createPluginWebServer(host, { webRoot, token: "test-token", reliability }); resources.push({ server, host });
    await new Promise<void>((done, reject) => {
      server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.off("error", reject); done(); });
    });
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    expect(await (await fetch(origin)).text()).toContain("Plugin Host");
    expect((await fetch(`${origin}/api/plugins`)).status).toBe(401);
    const headers = { authorization: "Bearer test-token", "content-type": "application/json" };

    expect(await (await fetch(`${origin}/api/plugins`, { headers })).json()).toMatchObject({ plugins: [{ id: "dummy" }] });
    expect(await (await fetch(`${origin}/api/web-contributions`, { headers })).json()).toEqual({ contributions: [{
      pluginId: "dummy", id: "console", title: "Dummy Console", entry: "index.html",
    }] });
    expect(await (await fetch(`${origin}/plugins/dummy/console/index.html`)).text()).toContain("Dummy console");
    expect(await (await fetch(`${origin}/api/plugins/dummy/operations/echo`, {
      method: "POST", headers, body: JSON.stringify({ untouched: [1, 2, 3] }),
    })).json()).toEqual({ untouched: [1, 2, 3] });

    const accepted = await (await fetch(`${origin}/api/runs`, {
      method: "POST", headers, body: JSON.stringify({ pluginId: "dummy", payload: { value: 42 } }),
    })).json() as { id: string };
    const completed = await (await fetch(`${origin}/api/runs/${accepted.id}/actions/complete`, {
      method: "POST", headers, body: "{}",
    })).json();
    expect(completed).toMatchObject({ pluginId: "dummy", status: "succeeded", pluginRun: { id: "web-1" } });
    expect(await (await fetch(`${origin}/api/runs`, { headers })).json()).toMatchObject({ runs: [{ id: accepted.id }] });
    const artifactList = await (await fetch(`${origin}/api/runs/${accepted.id}/artifacts`, { headers })).json() as { artifacts: { id: string }[] };
    expect(artifactList.artifacts.map((artifact) => artifact.id)).toEqual(["result", "report"]);
    expect(await (await fetch(`${origin}/api/runs/${accepted.id}/executions`, { headers })).json()).toEqual({ executions: [] });
    expect(await (await fetch(`${origin}/api/runs/${accepted.id}/artifacts/result?token=test-token`)).json()).toEqual({
      prefix: "web", payload: { value: 42 }, status: "succeeded",
    });
    const htmlReport = await fetch(`${origin}/api/runs/${accepted.id}/artifacts/report?token=test-token`);
    expect(htmlReport.headers.get("content-security-policy")).toContain("script-src 'unsafe-inline'");
    expect(await htmlReport.text()).toContain("document.querySelector('#tab')");
    const staleEvents = await fetch(`${origin}/api/runs/JOB-stale/events`, { headers });
    expect(staleEvents.status).toBe(404);
    expect(await staleEvents.json()).toEqual({ ok: false, error: "host_run_not_found:JOB-stale" });
    expect((await fetch(`${origin}/api/health`, { headers })).status).toBe(200);
    expect(await (await fetch(`${origin}/api/reliability`, { headers })).json()).toMatchObject({ status: "ok", hostRuns: 1, subagentRuns: 2 });
    expect(await (await fetch(`${origin}/api/reliability/actions/prune`, { method: "POST", headers, body: "{}" })).json()).toEqual({ hostRuns: 0, subagentRuns: 1 });
  });

  it("serves assistant sessions independently of plugin runs", async () => {
    process.env.TEST_SERVER_ASSISTANT_KEY = "runtime-only";
    const sessions = await PiSessionFactory.create({ models: {
      default: "general",
      providers: { test: { type: "faux", baseUrl: "http://unused.invalid/v1", apiKeyEnv: "TEST_SERVER_ASSISTANT_KEY" } },
      catalog: { general: { provider: "test", id: "general-model" } },
    } });
    const faux = fauxProvider({ provider: "test", api: "faux", models: [{ id: "general-model" }] });
    sessions.models.runtime.registerNativeProvider(faux.provider);
    faux.setResponses([fauxAssistantMessage("Web assistant response")]);
    const assistant = await AssistantSessionService.create({ sessions, cwd: await mkdtemp(join(tmpdir(), "server-assistant-")) });
    const host = await PluginHostService.create({ plugins: [] });
    const webRoot = await mkdtemp(join(tmpdir(), "assistant-web-"));
    await writeFile(join(webRoot, "index.html"), "<h1>Assistant</h1>");
    const server = createPluginWebServer(host, { webRoot, assistant }); resources.push({ server, host, assistant });
    await new Promise<void>((done, reject) => {
      server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.off("error", reject); done(); });
    });
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    expect(await (await fetch(`${origin}/api/health`)).json()).toMatchObject({ assistant: true, pluginCount: 0 });
    expect(await (await fetch(`${origin}/api/assistant/capabilities`)).json()).toMatchObject({ capabilities: expect.any(Array) });
    expect(await (await fetch(`${origin}/api/assistant/subagents`)).json()).toEqual({ subagents: [] });
    const created = await (await fetch(`${origin}/api/assistant/sessions`, {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}",
    })).json() as { id: string };
    expect((await fetch(`${origin}/api/assistant/sessions/${created.id}/messages`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ content: "hello" }),
    })).status).toBe(202);
    for (let attempt = 0; attempt < 50; attempt++) {
      const current = await (await fetch(`${origin}/api/assistant/sessions/${created.id}`)).json() as { status: string; messages: unknown[] };
      if (current.status === "idle" && current.messages.length === 2) {
        expect(current).toMatchObject({ messages: [{ role: "user" }, { role: "assistant", content: [{ text: "Web assistant response" }] }] });
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
      if (attempt === 49) throw new Error("assistant_response_timeout");
    }
    expect((await fetch(`${origin}/api/runs`)).status).toBe(200);
    const staleEvents = await fetch(`${origin}/api/assistant/sessions/stale/events`);
    expect(staleEvents.status).toBe(404);
    expect(await staleEvents.json()).toEqual({ ok: false, error: "assistant_session_not_found:stale" });
    expect((await fetch(`${origin}/api/health`)).status).toBe(200);
  });
});
