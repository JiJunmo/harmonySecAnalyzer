import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";
import { execa } from "execa";
import type { McpServerConfig } from "@agent-platform/core";

export const SEMANTIC_TOOLS = ["search", "symbol", "explore", "calls", "path", "trace", "impact", "file_dependencies"] as const;
export const VALIDATION_TOOLS = ["symbol", "explore", "calls", "path", "trace"] as const;

export class AtlasProfile {
  constructor(readonly executable: string) {}
  async validate(): Promise<void> {
    if (this.executable.includes("/")) await access(resolve(this.executable), constants.X_OK);
    else {
      const result = await execa(this.executable, ["--version"], { reject: false, timeout: 10_000 });
      if (result.exitCode !== 0) throw new Error(`atlas_executable_not_found:${this.executable}`);
    }
  }
  indexCommand(target: string, sync: boolean): string[] { return [this.executable, sync ? "sync" : "index", "--project", resolve(target), "--analysis", "full"]; }
  statusCommand(target: string): string[] { return [this.executable, "status", "--project", resolve(target)]; }
  mcpServer(target: string, allowedTools: readonly string[]): McpServerConfig {
    const projectPath = resolve(target);
    return { command: this.executable, args: ["mcp"], cwd: projectPath, allowedTools, setupCalls: [{ name: "project", arguments: { action: "open", project_path: projectPath } }] };
  }
}

export async function prepareAtlasIndex(target: string, profile: AtlasProfile, force = false): Promise<Record<string, unknown>> {
  const root = resolve(target);
  const database = resolve(root, ".atlas/atlas.db");
  let sync = !force;
  try { await access(database); } catch { sync = false; }
  const command = profile.indexCommand(root, sync);
  const index = await execa(command[0]!, command.slice(1), { cwd: root, timeout: 900_000, reject: false });
  const statusCommand = profile.statusCommand(root);
  const status = await execa(statusCommand[0]!, statusCommand.slice(1), { cwd: root, timeout: 60_000, reject: false });
  const count = /Files indexed:\s+(\d+)/.exec(`${status.stdout}\n${status.stderr}`)?.[1];
  const ok = index.exitCode === 0 && status.exitCode === 0 && Number(count) > 0;
  return { ok, status: ok ? "ready" : "failed", action: sync ? "sync" : "index", analysis: "full", files_indexed: count ? Number(count) : null, output_tail: `${index.stdout}\n${index.stderr}`.split("\n").slice(-200) };
}
