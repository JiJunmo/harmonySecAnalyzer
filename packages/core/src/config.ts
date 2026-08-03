import { readFile, rename, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

export interface AgentConfig {
  readonly mcp: Readonly<Record<string, unknown>>;
  readonly plugins: Readonly<Record<string, unknown>>;
  readonly subagents: Readonly<Record<string, unknown>>;
  readonly reliability: Readonly<Record<string, unknown>>;
}

export interface AssistantConfigDocument {
  readonly cwd?: string;
  readonly sessionDirectory?: string;
  readonly systemPrompt?: string;
  readonly model?: string;
  readonly tools?: readonly string[];
  readonly excludeTools?: readonly string[];
}

export interface ModelConfigDocument {
  readonly default?: string;
  readonly tasks?: Readonly<Record<string, string>>;
  readonly providers?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly catalog?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
}

export interface McpPolicyConfig {
  readonly maxSessions?: number;
  readonly connectRetries?: number;
  readonly retryDelayMs?: number;
  readonly healthCheck?: boolean;
}

export interface SkillConfigDocument {
  readonly roots?: readonly string[];
  readonly tasks?: Readonly<Record<string, string>>;
}

export interface PluginConfigDocument {
  readonly modules?: readonly string[];
  readonly configs?: Readonly<Record<string, unknown>>;
}

const sections = ["mcp", "plugins", "subagents", "reliability"] as const;

export async function loadConfig(path: string): Promise<AgentConfig> {
  const source = resolve(path);
  const parsed = JSON.parse(await readFile(source, "utf8")) as Record<string, unknown>;
  return Object.fromEntries(sections.map((name) => {
    const value = parsed[name];
    if (value !== undefined && (typeof value !== "object" || value === null || Array.isArray(value))) {
      throw new Error(`config_section_must_be_table:${name}`);
    }
    return [name, Object.freeze({ ...((value as Record<string, unknown> | undefined) ?? {}) })];
  })) as unknown as AgentConfig;
}

export function configSection<T>(config: AgentConfig, name: keyof AgentConfig): T {
  return config[name] as T;
}

export async function setMcpServerEnabled(path: string, name: string, enabled: boolean): Promise<void> {
  const source = resolve(path);
  const parsed = JSON.parse(await readFile(source, "utf8")) as Record<string, unknown>;
  const mcp = parsed.mcp;
  if (!mcp || typeof mcp !== "object" || Array.isArray(mcp)) throw new Error("mcp_config_missing");
  const servers = (mcp as Record<string, unknown>).servers;
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) throw new Error("mcp_servers_config_missing");
  const server = (servers as Record<string, unknown>)[name];
  if (!server || typeof server !== "object" || Array.isArray(server)) throw new Error(`mcp_server_not_registered:${name}`);
  (servers as Record<string, unknown>)[name] = { ...(server as Record<string, unknown>), enabled };
  const temporary = `${source}.tmp`;
  await writeFile(temporary, `${JSON.stringify(parsed, null, 2)}\n`, "utf8");
  await rename(temporary, source);
}
