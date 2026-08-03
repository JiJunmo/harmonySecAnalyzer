#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PiSessionFactory,
  configSection,
  discoverPlugins,
  loadConfig,
  setMcpServerEnabled,
  type McpPolicyConfig,
  type McpServerConfig,
  type PluginConfigDocument,
} from "@agent-platform/core";
import { AssistantSessionService, LocalGatewayState, PluginHostService, type AssistantSubagentConfig, type LocalReliabilityConfig } from "@agent-platform/interface";
import { createPluginWebServer } from "./server.js";

const configPath = resolve(process.env.AGENT_PLATFORM_CONFIG ?? "agent-platform.json");
const config = await loadConfig(configPath);
const configRoot = dirname(configPath);
const reliabilityConfig = configSection<LocalReliabilityConfig>(config, "reliability");
const reliability = await LocalGatewayState.open(resolve(configRoot, reliabilityConfig.dataDirectory ?? ".agent-platform"), reliabilityConfig);
const logger = reliability.logger();
const pluginConfig = configSection<PluginConfigDocument>(config, "plugins");
const registry = await discoverPlugins(pluginConfig.modules ?? [], configRoot);
const host = await PluginHostService.create({
  plugins: registry.list(),
  ...(pluginConfig.configs ? { configs: pluginConfig.configs } : {}),
  sharedConfig: { pi: { agentDir: resolve(process.env.AGENT_PLATFORM_PI_DIR ?? resolve(configRoot, "pi-agent")), cwd: process.cwd() }, mcp: config.mcp },
  runRepository: reliability.hostRuns(),
  logger,
});
const mcpConfig = configSection<McpPolicyConfig & { readonly servers?: Readonly<Record<string, McpServerConfig>> }>(config, "mcp");
const subagentConfig = configSection<AssistantSubagentConfig>(config, "subagents");
const piAgentDir = resolve(process.env.AGENT_PLATFORM_PI_DIR ?? resolve(configRoot, "pi-agent"));
const assistant = await AssistantSessionService.create({
    sessions: await PiSessionFactory.create({ agentDir: piAgentDir, cwd: process.cwd() }),
    cwd: process.cwd(),
    mcp: mcpConfig,
    mcpServers: Object.fromEntries(Object.entries(mcpConfig.servers ?? {}).map(([name, server]) => [name, {
      ...server,
      ...(server.cwd ? { cwd: resolve(configRoot, server.cwd) } : {}),
    }])),
    persistMcpEnabled: (name, enabled) => setMcpServerEnabled(configPath, name, enabled),
    subagents: subagentConfig,
    restoredSubagents: reliability.restoredSubagents(),
    persistSubagent: (run) => reliability.saveSubagent(run),
  });
const webRoot = fileURLToPath(new URL("../../web/public/", import.meta.url));
const server = createPluginWebServer(host, {
  webRoot,
  assistant,
  reliability,
  logger,
  ...(process.env.AGENT_PLATFORM_WEB_TOKEN ? { token: process.env.AGENT_PLATFORM_WEB_TOKEN } : {}),
});
const port = Number(process.env.AGENT_PLATFORM_WEB_PORT ?? 4173);
const bind = process.env.AGENT_PLATFORM_WEB_HOST ?? "127.0.0.1";
server.listen(port, bind, () => {
  logger.info("gateway started", { bind, port, plugins: host.listPlugins().map((plugin) => plugin.id) });
  process.stdout.write(`Agent Platform: http://${bind}:${port}\nAssistant: ${assistant ? "enabled" : "disabled"}\nPlugins: ${host.listPlugins().map((plugin) => plugin.id).join(", ") || "none"}\nState: ${reliability.databasePath}\n`);
});

const shutdown = () => {
  server.close(() => { void Promise.allSettled([host.dispose(), assistant?.dispose()]).finally(() => { logger.info("gateway stopped"); reliability.close(); process.exitCode = 0; }); });
};
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
