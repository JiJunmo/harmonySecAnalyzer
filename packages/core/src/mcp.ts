import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { McpPolicyConfig } from "./config.js";

export interface McpServerConfig {
  readonly enabled?: boolean;
  readonly command: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly allowedTools?: readonly string[];
  readonly timeoutMs?: number;
  readonly setupCalls?: readonly { readonly name: string; readonly arguments: Readonly<Record<string, unknown>> }[];
}

function renderContent(content: readonly Record<string, unknown>[]): { type: "text"; text: string }[] {
  return content.map((item) => {
    if (item.type === "text" && typeof item.text === "string") return { type: "text", text: item.text };
    return { type: "text", text: JSON.stringify(item) };
  });
}

export class McpSession {
  #closed = false;
  constructor(readonly client: Client, readonly transport: StdioClientTransport, readonly config: McpServerConfig, readonly onClose?: () => void) {}
  async tools(): Promise<AgentTool[]> {
    const listed = await this.client.listTools();
    const allowed = this.config.allowedTools ? new Set(this.config.allowedTools) : undefined;
    return listed.tools.filter((tool) => !allowed || allowed.has(tool.name)).map((tool) => ({
      name: tool.name,
      label: tool.annotations?.title ?? tool.name,
      description: tool.description ?? `MCP tool ${tool.name}`,
      parameters: Type.Unsafe(tool.inputSchema),
      executionMode: tool.annotations?.readOnlyHint === false ? "sequential" : "parallel",
      execute: async (_id, params, signal) => {
        const result = await this.client.callTool(
          { name: tool.name, arguments: params as Record<string, unknown> },
          undefined,
          { ...(signal ? { signal } : {}), timeout: this.config.timeoutMs ?? 60_000 },
        );
        if (!("content" in result)) return { content: [{ type: "text", text: JSON.stringify(result.toolResult) }], details: result };
        if (result.isError) throw new Error(`mcp_tool_error:${tool.name}:${JSON.stringify(result.content)}`);
        return { content: renderContent(result.content as Record<string, unknown>[]), details: result };
      },
    }));
  }
  async close(): Promise<void> {
    if (this.#closed) return; this.#closed = true;
    try { await this.client.close(); } finally { this.onClose?.(); }
  }
  async call(name: string, args: Readonly<Record<string, unknown>>): Promise<unknown> {
    return this.client.callTool({ name, arguments: { ...args } });
  }
}

export class McpManager {
  readonly #policy: Required<McpPolicyConfig>;
  readonly #sessions = new Set<McpSession>();
  readonly #waiters: (() => void)[] = [];
  #active = 0;
  #closed = false;
  constructor(policy: McpPolicyConfig = {}) {
    this.#policy = {
      maxSessions: policy.maxSessions ?? 5, connectRetries: policy.connectRetries ?? 2,
      retryDelayMs: policy.retryDelayMs ?? 100, healthCheck: policy.healthCheck ?? true,
    };
    if (!Number.isInteger(this.#policy.maxSessions) || this.#policy.maxSessions < 1) throw new Error("mcp_policy_invalid:maxSessions");
    if (!Number.isInteger(this.#policy.connectRetries) || this.#policy.connectRetries < 0) throw new Error("mcp_policy_invalid:connectRetries");
  }

  status(): Readonly<Record<string, unknown>> {
    return Object.freeze({ active: this.#active, waiting: this.#waiters.length, maxSessions: this.#policy.maxSessions, closed: this.#closed });
  }

  async #acquire(): Promise<void> {
    if (this.#closed) throw new Error("mcp_manager_closed");
    if (this.#active >= this.#policy.maxSessions) await new Promise<void>((resolve) => this.#waiters.push(resolve));
    if (this.#closed) throw new Error("mcp_manager_closed");
    this.#active++;
  }

  #release(): void { this.#active--; this.#waiters.shift()?.(); }

  async connect(name: string, config: McpServerConfig): Promise<McpSession> {
    await this.#acquire();
    let last: unknown;
    for (let attempt = 0; attempt <= this.#policy.connectRetries; attempt++) {
      try { return await this.#connectOnce(name, config); }
      catch (error) {
        last = error;
        if (attempt < this.#policy.connectRetries) await new Promise((resolve) => setTimeout(resolve, this.#policy.retryDelayMs * (attempt + 1)));
      }
    }
    this.#release(); throw new Error(`mcp_connect_exhausted:${name}`, { cause: last });
  }

  async #connectOnce(name: string, config: McpServerConfig): Promise<McpSession> {
    const client = new Client({ name: `agent-platform-${name}`, version: "3.2.0" });
    const transport = new StdioClientTransport({
      command: config.command,
      ...(config.args ? { args: [...config.args] } : {}),
      ...(config.cwd ? { cwd: config.cwd } : {}),
      ...(config.env ? { env: { ...process.env, ...config.env } as Record<string, string> } : {}),
      stderr: "pipe",
    });
    try {
      await client.connect(transport);
      const session = new McpSession(client, transport, config, () => { this.#sessions.delete(session); this.#release(); });
      if (this.#policy.healthCheck) await client.listTools();
      for (const setup of config.setupCalls ?? []) await session.call(setup.name, setup.arguments);
      this.#sessions.add(session); return session;
    } catch (error) { await client.close().catch(() => undefined); throw error; }
  }

  async close(): Promise<void> {
    this.#closed = true;
    while (this.#waiters.length) this.#waiters.shift()?.();
    await Promise.all([...this.#sessions].map((session) => session.close()));
  }
}
