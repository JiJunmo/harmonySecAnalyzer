import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import type { AssistantSessionService, PluginHostService } from "@agent-platform/interface";
import type { PluginLogger } from "@agent-platform/core";

const jsonHeaders = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const contentTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};
const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);
const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

async function body(request: IncomingMessage): Promise<unknown> {
  let size = 0; const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const value = Buffer.from(chunk); size += value.length;
    if (size > 1_048_576) throw new Error("request_body_too_large");
    chunks.push(value);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown; }
  catch { throw new Error("invalid_json_body"); }
}

function send(response: ServerResponse, status: number, document: unknown): void {
  response.writeHead(status, jsonHeaders); response.end(`${JSON.stringify(document)}\n`);
}

export interface WebServerOptions {
  readonly token?: string; readonly webRoot: string; readonly assistant?: AssistantSessionService;
  readonly reliability?: { diagnostics(): Promise<Readonly<Record<string, unknown>>>; prune(): unknown };
  readonly logger?: PluginLogger;
}

export function createPluginWebServer(host: PluginHostService, options: WebServerOptions): Server {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
      if (url.pathname.startsWith("/api/") && options.token) {
        const supplied = request.headers.authorization?.replace(/^Bearer\s+/i, "") ?? url.searchParams.get("token");
        if (supplied !== options.token) { send(response, 401, { ok: false, error: "unauthorized" }); return; }
      }
      if (request.method === "GET" && url.pathname === "/api/health") {
        const reliability = await options.reliability?.diagnostics();
        send(response, 200, { ok: true, service: "agent-platform", assistant: !!options.assistant, pluginCount: host.listPlugins().length, ...(reliability ? { reliability: { status: reliability.status, hostRuns: reliability.hostRuns, subagentRuns: reliability.subagentRuns } } : {}) }); return;
      }
      if (request.method === "GET" && url.pathname === "/api/reliability") {
        if (!options.reliability) throw new Error("reliability_not_configured");
        send(response, 200, await options.reliability.diagnostics()); return;
      }
      if (request.method === "POST" && url.pathname === "/api/reliability/actions/prune") {
        if (!options.reliability) throw new Error("reliability_not_configured");
        send(response, 200, options.reliability.prune()); return;
      }
      if (request.method === "GET" && url.pathname === "/api/assistant") {
        if (!options.assistant) throw new Error("assistant_not_configured");
        send(response, 200, options.assistant.capabilities()); return;
      }
      if (request.method === "GET" && url.pathname === "/api/assistant/capabilities") {
        if (!options.assistant) throw new Error("assistant_not_configured");
        send(response, 200, { capabilities: await options.assistant.capabilityViews() }); return;
      }
      if (request.method === "POST" && url.pathname === "/api/assistant/capabilities") {
        if (!options.assistant) throw new Error("assistant_not_configured");
        const value = await body(request);
        const kinds = new Set(["skill", "extension", "package", "mcp"]);
        if (!isRecord(value) || typeof value.kind !== "string" || !kinds.has(value.kind) || typeof value.id !== "string" || typeof value.enabled !== "boolean") {
          throw new Error("assistant_capability_request_invalid");
        }
        send(response, 200, { capabilities: await options.assistant.setCapabilityEnabled(value.kind as "skill" | "extension" | "package" | "mcp", value.id, value.enabled) }); return;
      }
      if (request.method === "GET" && url.pathname === "/api/assistant/subagents") {
        if (!options.assistant) throw new Error("assistant_not_configured");
        send(response, 200, { subagents: options.assistant.listSubagents(url.searchParams.get("parentSessionId") ?? undefined) }); return;
      }
      const subagentRoute = /^\/api\/assistant\/subagents\/([^/]+)(?:\/(.*))?$/.exec(url.pathname);
      if (subagentRoute) {
        if (!options.assistant) throw new Error("assistant_not_configured");
        const id = decodeURIComponent(subagentRoute[1]!); const tail = subagentRoute[2] ?? "";
        if (request.method === "GET" && !tail) { send(response, 200, options.assistant.getSubagent(id)); return; }
        if (request.method === "POST" && tail === "actions/abort") {
          send(response, 200, await options.assistant.abortSubagent(id)); return;
        }
      }
      if (request.method === "GET" && url.pathname === "/api/assistant/sessions") {
        if (!options.assistant) throw new Error("assistant_not_configured");
        send(response, 200, { sessions: options.assistant.list() }); return;
      }
      if (request.method === "POST" && url.pathname === "/api/assistant/sessions") {
        if (!options.assistant) throw new Error("assistant_not_configured");
        const value = await body(request);
        if (!isRecord(value)) throw new Error("assistant_session_request_invalid");
        send(response, 201, await options.assistant.createSession({
          ...(typeof value.title === "string" ? { title: value.title } : {}),
          ...(typeof value.model === "string" ? { model: value.model } : {}),
        })); return;
      }
      const assistantRoute = /^\/api\/assistant\/sessions\/([^/]+)(?:\/(.*))?$/.exec(url.pathname);
      if (assistantRoute) {
        if (!options.assistant) throw new Error("assistant_not_configured");
        const id = decodeURIComponent(assistantRoute[1]!); const tail = assistantRoute[2] ?? "";
        if (request.method === "GET" && !tail) { send(response, 200, options.assistant.get(id)); return; }
        if (request.method === "DELETE" && !tail) {
          await options.assistant.delete(id); response.writeHead(204, { "cache-control": "no-store" }); response.end(); return;
        }
        if (request.method === "POST" && tail === "messages") {
          const value = await body(request);
          if (!isRecord(value) || typeof value.content !== "string") throw new Error("assistant_message_required");
          send(response, 202, options.assistant.prompt(id, value.content)); return;
        }
        if (request.method === "POST" && tail === "actions/abort") {
          send(response, 200, await options.assistant.abort(id)); return;
        }
        if (request.method === "POST" && tail === "actions/rename") {
          const value = await body(request);
          if (!isRecord(value) || typeof value.name !== "string") throw new Error("assistant_session_name_required");
          send(response, 200, options.assistant.rename(id, value.name)); return;
        }
        if (request.method === "GET" && tail === "events") {
          const snapshot = options.assistant.get(id);
          response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive", "x-content-type-options": "nosniff" });
          response.write(`event: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`);
          const unsubscribe = options.assistant.subscribe((event) => {
            if (event.session.id === id && !response.destroyed) response.write(`event: session_event\ndata: ${JSON.stringify(event)}\n\n`);
          });
          const heartbeat = setInterval(() => { if (!response.destroyed) response.write(": heartbeat\n\n"); }, 15_000);
          heartbeat.unref();
          request.on("close", () => { clearInterval(heartbeat); unsubscribe(); });
          return;
        }
      }
      if (request.method === "GET" && url.pathname === "/api/plugins") {
        send(response, 200, { plugins: host.listPlugins() }); return;
      }
      if (request.method === "GET" && url.pathname === "/api/web-contributions") {
        send(response, 200, { contributions: host.listWebContributions() }); return;
      }
      const operationRoute = /^\/api\/plugins\/([^/]+)\/operations\/([^/]+)$/.exec(url.pathname);
      if (request.method === "POST" && operationRoute) {
        const pluginId = decodeURIComponent(operationRoute[1]!); const name = decodeURIComponent(operationRoute[2]!);
        send(response, 200, await host.operation(pluginId, { name, payload: await body(request) })); return;
      }
      if (request.method === "GET" && url.pathname === "/api/runs") {
        send(response, 200, { runs: host.listRuns() }); return;
      }
      if (request.method === "POST" && url.pathname === "/api/runs") {
        const value = await body(request);
        if (!isRecord(value) || typeof value.pluginId !== "string") throw new Error("plugin_id_required");
        send(response, 202, await host.createRun(value.pluginId, value.payload)); return;
      }
      if (request.method === "POST" && url.pathname === "/api/runs/adopt") {
        const value = await body(request);
        if (!isRecord(value) || typeof value.pluginId !== "string") throw new Error("plugin_id_required");
        const reference = typeof value.pluginRun === "string" ? { id: value.pluginRun }
          : isRecord(value.pluginRun) && typeof value.pluginRun.id === "string" ? { id: value.pluginRun.id }
            : undefined;
        if (!reference) throw new Error("plugin_run_reference_required");
        send(response, 200, await host.adoptRun(value.pluginId, reference)); return;
      }
      const runRoute = /^\/api\/runs\/([^/]+)(?:\/(.*))?$/.exec(url.pathname);
      if (runRoute) {
        const id = decodeURIComponent(runRoute[1]!); const tail = runRoute[2] ?? "";
        if (request.method === "GET" && !tail) { send(response, 200, await host.getRun(id)); return; }
        if (request.method === "GET" && tail === "executions") {
          send(response, 200, { executions: await host.executions(id) }); return;
        }
        const executionRoute = /^executions\/([^/]+)$/.exec(tail);
        if (request.method === "GET" && executionRoute) {
          send(response, 200, await host.execution(id, decodeURIComponent(executionRoute[1]!))); return;
        }
        const actionRoute = /^actions\/([^/]+)$/.exec(tail);
        if (request.method === "POST" && actionRoute) {
          send(response, 200, await host.action(id, { name: decodeURIComponent(actionRoute[1]!), payload: await body(request) })); return;
        }
        if (request.method === "GET" && tail === "artifacts") {
          send(response, 200, { artifacts: await host.artifacts(id) }); return;
        }
        const artifactRoute = /^artifacts\/([^/]+)$/.exec(tail);
        if (request.method === "GET" && artifactRoute) {
          const artifact = await host.openArtifact(id, decodeURIComponent(artifactRoute[1]!));
          response.writeHead(200, {
            "content-type": artifact.descriptor.mediaType,
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
            "content-disposition": `inline; filename*=UTF-8''${encodeURIComponent(artifact.descriptor.name)}`,
            ...(artifact.descriptor.mediaType.startsWith("text/html") ? { "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'" } : {}),
          });
          if (artifact.body instanceof Uint8Array) response.end(Buffer.from(artifact.body));
          else { for await (const chunk of artifact.body) response.write(Buffer.from(chunk)); response.end(); }
          return;
        }
        if (request.method === "GET" && tail === "events") {
          const snapshot = await host.getRun(id);
          response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive", "x-content-type-options": "nosniff" });
          response.write(`event: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`);
          const streamAbort = new AbortController();
          const unsubscribe = host.subscribe((event) => {
            if (event.run.id === id && !response.destroyed) response.write(`event: host_event\ndata: ${JSON.stringify(event)}\n\n`);
          });
          const heartbeat = setInterval(() => { if (!response.destroyed) response.write(": heartbeat\n\n"); }, 15_000);
          heartbeat.unref();
          request.on("close", () => { clearInterval(heartbeat); unsubscribe(); streamAbort.abort(); });
          void (async () => {
            try {
              for await (const event of host.events(id, { signal: streamAbort.signal })) {
                if (response.destroyed) break;
                response.write(`event: plugin_event\ndata: ${JSON.stringify(event)}\n\n`);
              }
            } catch (error) {
              if (!streamAbort.signal.aborted && !response.destroyed) response.write(`event: stream_error\ndata: ${JSON.stringify({ error: errorMessage(error) })}\n\n`);
            }
          })();
          return;
        }
      }
      const webContributionRoute = /^\/plugins\/([^/]+)\/([^/]+)\/(.+)$/.exec(url.pathname);
      if (request.method === "GET" && webContributionRoute) {
        const pluginId = decodeURIComponent(webContributionRoute[1]!);
        const contributionId = decodeURIComponent(webContributionRoute[2]!);
        const assetPath = webContributionRoute[3]!.split("/").map(decodeURIComponent).join("/");
        const asset = await host.openWebAsset(pluginId, contributionId, assetPath);
        const mediaType = contentTypes[extname(asset.name)] ?? "application/octet-stream";
        response.writeHead(200, {
          "content-type": mediaType,
          "cache-control": asset.name === "index.html" ? "no-cache" : "public, max-age=300",
          "x-content-type-options": "nosniff",
          ...(mediaType.startsWith("text/html") ? {
            "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-src 'self'; frame-ancestors 'self'",
          } : {}),
        });
        response.end(Buffer.from(asset.body)); return;
      }
      if (request.method === "GET" && !url.pathname.startsWith("/api/")) {
        const requested = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
        if (!/^[a-zA-Z0-9._/-]+$/.test(requested) || requested.includes("..")) { send(response, 404, { ok: false, error: "not_found" }); return; }
        const path = resolve(options.webRoot, requested); const content = await readFile(path);
        response.writeHead(200, { "content-type": contentTypes[extname(path)] ?? "application/octet-stream", "cache-control": requested === "index.html" ? "no-cache" : "public, max-age=300", "x-content-type-options": "nosniff" });
        response.end(content); return;
      }
      send(response, 404, { ok: false, error: "not_found" });
    } catch (error) {
      if (response.headersSent) {
        if (!response.writableEnded) response.end();
        return;
      }
      const value = errorMessage(error);
      options.logger?.error("http request failed", { method: request.method ?? "unknown", path: request.url ?? "", error: value });
      const status = /not_found|not_registered|not_configured/.test(value) ? 404 : /required|invalid|outside|absolute|capacity|not_supported|busy/.test(value) ? 400 : 500;
      send(response, status, { ok: false, error: value });
    }
  });
}
