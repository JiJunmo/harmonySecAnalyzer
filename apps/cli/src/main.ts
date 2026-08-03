#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  configSection,
  discoverPlugins,
  loadConfig,
  type PluginCliCommand,
  type PluginCliInvocation,
  type PluginConfigDocument,
  type PluginDefinition,
  type PluginRunStatus,
} from "@agent-platform/core";
import { PluginHostService, type HostRunView } from "@agent-platform/interface";

const usageText = `Usage:
  pnpm agent -- plugins --config agent-platform.json
  pnpm agent -- <plugin-command> [arguments] --config agent-platform.json
  pnpm agent -- <plugin-id>:<plugin-command> [arguments] --config agent-platform.json

Plugin commands are contributed by dynamically loaded plugins.`;

const terminal = new Set<PluginRunStatus>(["succeeded", "failed", "cancelled"]);

function globalArguments(argv: readonly string[]): { args: string[]; configPath: string } {
  const index = argv.indexOf("--config");
  const configured = index >= 0 ? argv[index + 1] : process.env.AGENT_PLATFORM_CONFIG;
  if (index >= 0 && !configured) throw new Error("usage:config_path_required");
  const args = index >= 0 ? argv.filter((_, position) => position !== index && position !== index + 1) : [...argv];
  return { args, configPath: resolve(configured ?? "agent-platform.json") };
}

function commands(plugins: readonly PluginDefinition[]): Map<string, { pluginId: string; command: PluginCliCommand }> {
  const result = new Map<string, { pluginId: string; command: PluginCliCommand }>();
  const ambiguous = new Set<string>();
  for (const plugin of plugins) for (const command of plugin.cli ?? []) {
    const qualified = `${plugin.manifest.id}:${command.name}`;
    result.set(qualified, { pluginId: plugin.manifest.id, command });
    if (result.has(command.name)) { result.delete(command.name); ambiguous.add(command.name); }
    else if (!ambiguous.has(command.name)) result.set(command.name, { pluginId: plugin.manifest.id, command });
  }
  return result;
}

async function waitForTerminal(host: PluginHostService, id: string): Promise<HostRunView> {
  let run = await host.getRun(id);
  while (!terminal.has(run.status)) {
    await new Promise((done) => setTimeout(done, Number(process.env.AGENT_PLATFORM_CLI_POLL_MS ?? 250)));
    run = await host.getRun(id);
  }
  return run;
}

async function execute(host: PluginHostService, pluginId: string, invocation: PluginCliInvocation): Promise<unknown> {
  switch (invocation.kind) {
    case "operation": return host.operation(pluginId, invocation.operation);
    case "run": {
      const accepted = await host.createRun(pluginId, invocation.payload, invocation.subject);
      return waitForTerminal(host, accepted.id);
    }
    case "inspect": {
      const adopted = await host.adoptRun(pluginId, invocation.run);
      return host.getRun(adopted.id);
    }
    case "action": {
      const adopted = await host.adoptRun(pluginId, invocation.run);
      const updated = await host.action(adopted.id, invocation.action);
      return invocation.wait && !terminal.has(updated.status) ? waitForTerminal(host, adopted.id) : updated;
    }
    case "artifacts": {
      const adopted = await host.adoptRun(pluginId, invocation.run);
      return { run: await host.getRun(adopted.id), artifacts: await host.artifacts(adopted.id) };
    }
  }
}

export async function runCli(argv: readonly string[]): Promise<unknown> {
  const { args, configPath } = globalArguments(argv);
  const [name, ...commandArgs] = args;
  if (!name) throw new Error("usage:missing_command");
  const config = await loadConfig(configPath);
  const document = configSection<PluginConfigDocument>(config, "plugins");
  if (!document.modules?.length) throw new Error("plugin_modules_required");
  const registry = await discoverPlugins(document.modules, dirname(configPath));
  const definitions = registry.list();
  const host = await PluginHostService.create({
    plugins: definitions,
    ...(document.configs ? { configs: document.configs } : {}),
    sharedConfig: { pi: { agentDir: resolve(process.env.AGENT_PLATFORM_PI_DIR ?? resolve(dirname(configPath), "pi-agent")), cwd: process.cwd() }, mcp: config.mcp },
  });
  try {
    if (name === "plugins") return { plugins: host.listPlugins() };
    const contribution = commands(definitions).get(name);
    if (!contribution) throw new Error(`usage:unknown_command:${name}`);
    return await execute(host, contribution.pluginId, await contribution.command.invoke(commandArgs));
  } finally {
    await host.dispose();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(await runCli(process.argv.slice(2)), null, 2)}\n`); }
  catch (error) {
    const value = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${value.startsWith("usage:") ? `${usageText}\n` : ""}${JSON.stringify({ ok: false, error: value })}\n`);
    process.exitCode = value.startsWith("usage:") ? 2 : 1;
  }
}
