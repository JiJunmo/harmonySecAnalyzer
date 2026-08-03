import { randomUUID } from "node:crypto";
import { unlink } from "node:fs/promises";
import {
  McpManager,
  PiSessionFactory,
  SubagentRuntime,
  type McpPolicyConfig,
  type McpServerConfig,
  type McpSession,
  type PlatformAgentSession,
  type SubagentRunView,
} from "@agent-platform/core";

export type AssistantSessionStatus = "idle" | "running" | "error";

export interface AssistantMessageContent {
  readonly type: string;
  readonly text?: string;
  readonly name?: string;
  readonly arguments?: unknown;
}

export interface AssistantMessageView {
  readonly role: string;
  readonly content: readonly AssistantMessageContent[];
  readonly timestamp?: string;
  readonly toolName?: string;
  readonly isError?: boolean;
}

export interface AssistantSessionView {
  readonly id: string;
  readonly title: string;
  readonly status: AssistantSessionStatus;
  readonly model: string;
  readonly cwd: string;
  readonly activeTools: readonly string[];
  readonly messages: readonly AssistantMessageView[];
  readonly error?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface AssistantSessionEvent {
  readonly id: string;
  readonly type: "session_created" | "session_updated" | "session_deleted";
  readonly cause: string;
  readonly session: AssistantSessionView;
  readonly timestamp: string;
}

export interface AssistantSessionCreateRequest {
  readonly title?: string;
  readonly model?: string;
}

export interface AssistantSessionServiceOptions {
  readonly sessions: PiSessionFactory;
  readonly cwd: string;
  readonly sessionDirectory?: string;
  readonly systemPrompt?: string;
  readonly model?: string;
  readonly tools?: readonly string[];
  readonly excludeTools?: readonly string[];
  readonly skillPaths?: readonly string[];
  readonly mcp?: McpPolicyConfig;
  readonly mcpServers?: Readonly<Record<string, McpServerConfig>>;
  readonly persistMcpEnabled?: (name: string, enabled: boolean) => Promise<void>;
  readonly subagents?: AssistantSubagentConfig;
  readonly restoredSubagents?: readonly SubagentRunView[];
  readonly persistSubagent?: (run: SubagentRunView) => void;
}

export interface AssistantSubagentConfig {
  readonly enabled?: boolean;
  readonly model?: string;
  readonly tools?: readonly string[];
  readonly maxConcurrent?: number;
  readonly maxRetained?: number;
  readonly systemPrompt?: string;
}

export interface AssistantCapabilityView {
  readonly kind: "skill" | "extension" | "package" | "mcp";
  readonly id: string;
  readonly name: string;
  readonly enabled: boolean;
  readonly loaded: boolean;
  readonly source: string;
  readonly details?: readonly string[];
  readonly error?: string;
}

interface MutableAssistantSession {
  id: string;
  title: string;
  model: string;
  status: AssistantSessionStatus;
  error?: string | undefined;
  createdAt: string;
  updatedAt: string;
  session: PlatformAgentSession;
  unsubscribe: () => void;
  pending?: Promise<void> | undefined;
}

const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value)
  ? value as Record<string, unknown>
  : {};
const message = (error: unknown) => error instanceof Error ? error.message : String(error);

function content(value: unknown): readonly AssistantMessageContent[] {
  if (typeof value === "string") return [{ type: "text", text: value }];
  if (!Array.isArray(value)) return [];
  return value.map((entry) => {
    const block = record(entry);
    const type = typeof block.type === "string" ? block.type : "unknown";
    return Object.freeze({
      type,
      ...(typeof block.text === "string" ? { text: block.text } : {}),
      ...(typeof block.name === "string" ? { name: block.name } : {}),
      ...(block.arguments !== undefined ? { arguments: block.arguments } : {}),
    });
  });
}

function messages(values: readonly unknown[]): readonly AssistantMessageView[] {
  return values.map((value) => {
    const item = record(value);
    const timestamp = typeof item.timestamp === "number" ? new Date(item.timestamp).toISOString() : undefined;
    return Object.freeze({
      role: typeof item.role === "string" ? item.role : "unknown",
      content: content(item.content),
      ...(timestamp ? { timestamp } : {}),
      ...(typeof item.toolName === "string" ? { toolName: item.toolName } : {}),
      ...(typeof item.isError === "boolean" ? { isError: item.isError } : {}),
    });
  });
}

export class AssistantSessionService {
  readonly #options: AssistantSessionServiceOptions;
  readonly #mcp: McpManager;
  readonly #mcpSessions = new Map<string, McpSession>();
  readonly #mcpTools = new Map<string, readonly Awaited<ReturnType<McpSession["tools"]>>[number][]>();
  readonly #mcpEnabled = new Set<string>();
  readonly #subagents?: SubagentRuntime;
  readonly #sessions = new Map<string, MutableAssistantSession>();
  readonly #listeners = new Set<(event: AssistantSessionEvent) => void>();
  #disposed = false;

  private constructor(options: AssistantSessionServiceOptions, mcp: McpManager) {
    this.#options = options;
    this.#mcp = mcp;
    if (options.subagents?.enabled !== false) this.#subagents = new SubagentRuntime({
      sessions: options.sessions,
      cwd: options.cwd,
      ...(options.subagents?.model ? { model: options.subagents.model } : {}),
      ...(options.subagents?.tools ? { tools: options.subagents.tools } : {}),
      ...(options.subagents?.maxConcurrent !== undefined ? { maxConcurrent: options.subagents.maxConcurrent } : {}),
      ...(options.subagents?.maxRetained !== undefined ? { maxRetained: options.subagents.maxRetained } : {}),
      ...(options.subagents?.systemPrompt ? { systemPrompt: options.subagents.systemPrompt } : {}),
      ...(options.restoredSubagents ? { restoredRuns: options.restoredSubagents } : {}),
      ...(options.persistSubagent ? { persistRun: options.persistSubagent } : {}),
      ...(options.skillPaths ? { skillPaths: options.skillPaths } : {}),
      customTools: () => this.#activeMcpTools(),
    });
  }

  static async create(options: AssistantSessionServiceOptions): Promise<AssistantSessionService> {
    const configuredServers = Object.entries(options.mcpServers ?? {});
    const servers = configuredServers.filter(([, config]) => config.enabled !== false);
    const maxSessions = options.mcp?.maxSessions ?? 5;
    if (configuredServers.length > maxSessions) throw new Error(`global_mcp_server_capacity_exceeded:${configuredServers.length}:${maxSessions}`);
    const mcp = new McpManager(options.mcp);
    try {
      const service = new AssistantSessionService(options, mcp);
      for (const [name, config] of servers) {
        const session = await mcp.connect(name, config);
        const tools = await session.tools();
        service.#assertToolNamesAvailable(name, tools);
        service.#mcpSessions.set(name, session);
        service.#mcpTools.set(name, tools);
        service.#mcpEnabled.add(name);
      }
      await service.#restore();
      return service;
    } catch (error) {
      await mcp.close();
      throw error;
    }
  }

  capabilities(): Readonly<Record<string, unknown>> {
    this.#assertActive();
    return Object.freeze({
      models: this.#options.sessions.models.aliases,
      defaultModel: this.#options.model ?? this.#options.sessions.models.defaultAlias,
      mcpServers: Object.keys(this.#options.mcpServers ?? {}).sort(),
      mcpTools: this.#activeMcpTools().map((tool) => tool.name).sort(),
      subagents: !!this.#subagents,
    });
  }

  async capabilityViews(): Promise<readonly AssistantCapabilityView[]> {
    this.#assertActive();
    const pi = await this.#options.sessions.resources(this.#options.cwd);
    const values: AssistantCapabilityView[] = pi.resources.map((resource) => Object.freeze({
      kind: resource.kind, id: resource.id, name: resource.name, enabled: resource.enabled,
      loaded: resource.loaded, source: resource.source, ...(resource.error ? { error: resource.error } : {}),
    }));
    for (const [name, config] of Object.entries(this.#options.mcpServers ?? {})) values.push(Object.freeze({
      kind: "mcp", id: name, name, enabled: this.#mcpEnabled.has(name), loaded: this.#mcpSessions.has(name),
      source: config.command, details: Object.freeze(this.#mcpTools.get(name)?.map((tool) => tool.name) ?? []),
    }));
    return Object.freeze(values.sort((a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name)));
  }

  async setCapabilityEnabled(kind: AssistantCapabilityView["kind"], id: string, enabled: boolean): Promise<readonly AssistantCapabilityView[]> {
    this.#assertActive();
    if (kind !== "mcp") {
      await this.#options.sessions.setResourceEnabled(this.#options.cwd, kind, id, enabled);
      return this.capabilityViews();
    }
    const config = this.#options.mcpServers?.[id];
    if (!config) throw new Error(`mcp_server_not_registered:${id}`);
    if (enabled && !this.#mcpSessions.has(id)) {
      const session = await this.#mcp.connect(id, config);
      try {
        const tools = await session.tools();
        this.#assertToolNamesAvailable(id, tools);
        this.#mcpSessions.set(id, session); this.#mcpTools.set(id, tools);
      } catch (error) { await session.close(); throw error; }
    }
    await this.#options.persistMcpEnabled?.(id, enabled);
    if (enabled) this.#mcpEnabled.add(id); else this.#mcpEnabled.delete(id);
    return this.capabilityViews();
  }

  list(): readonly AssistantSessionView[] {
    this.#assertActive();
    return Object.freeze([...this.#sessions.values()].map((item) => this.#view(item)).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
  }

  listSubagents(parentSessionId?: string): readonly SubagentRunView[] {
    this.#assertActive();
    return this.#subagents?.list(parentSessionId) ?? Object.freeze([]);
  }

  getSubagent(id: string): SubagentRunView {
    this.#assertActive();
    if (!this.#subagents) throw new Error("subagents_not_configured");
    return this.#subagents.get(id);
  }

  async abortSubagent(id: string): Promise<SubagentRunView> {
    this.#assertActive();
    if (!this.#subagents) throw new Error("subagents_not_configured");
    return this.#subagents.abort(id);
  }

  get(id: string): AssistantSessionView {
    this.#assertActive();
    return this.#view(this.#required(id));
  }

  subscribe(listener: (event: AssistantSessionEvent) => void): () => void {
    this.#assertActive();
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async createSession(request: AssistantSessionCreateRequest = {}): Promise<AssistantSessionView> {
    this.#assertActive();
    const model = request.model ?? this.#options.model ?? this.#options.sessions.models.defaultAlias;
    this.#options.sessions.models.resolve(model);
    let sessionId = "";
    const customTools = this.#sessionTools(() => sessionId);
    const session = await this.#options.sessions.createSession({
      profile: "interactive",
      cwd: this.#options.cwd,
      model,
      ...(this.#options.sessionDirectory ? { sessionDirectory: this.#options.sessionDirectory } : {}),
      ...(this.#options.systemPrompt ? { systemPrompt: this.#options.systemPrompt } : {}),
      ...(this.#options.tools ? { tools: this.#options.tools } : {}),
      ...(this.#options.excludeTools ? { excludeTools: this.#options.excludeTools } : {}),
      ...(customTools.length ? { customTools } : {}),
      ...(this.#options.skillPaths ? { skillPaths: this.#options.skillPaths } : {}),
    });
    sessionId = session.id;
    const stamp = new Date().toISOString();
    const item = this.#register(session, request.title?.trim() || "新对话", model, stamp, stamp);
    this.#emit("session_created", "create", item);
    return this.#view(item);
  }

  prompt(id: string, text: string): AssistantSessionView {
    this.#assertActive();
    const item = this.#required(id);
    const prompt = text.trim();
    if (!prompt) throw new Error("assistant_message_required");
    if (item.pending || item.session.streaming) throw new Error(`assistant_session_busy:${id}`);
    if (item.title === "新对话") {
      item.title = prompt.replace(/\s+/g, " ").slice(0, 48);
      item.session.setName(item.title);
    }
    item.status = "running";
    item.error = undefined;
    item.updatedAt = new Date().toISOString();
    const pending = item.session.prompt(prompt).catch((error: unknown) => {
      item.status = "error";
      item.error = message(error);
      this.#emit("session_updated", "prompt_error", item);
    }).finally(() => {
      item.pending = undefined;
      if (item.status === "running") item.status = "idle";
      item.updatedAt = new Date().toISOString();
      this.#emit("session_updated", "prompt_settled", item);
    });
    item.pending = pending;
    this.#emit("session_updated", "prompt", item);
    return this.#view(item);
  }

  async abort(id: string): Promise<AssistantSessionView> {
    const item = this.#required(id);
    await item.session.abort();
    item.status = "idle";
    item.updatedAt = new Date().toISOString();
    this.#emit("session_updated", "abort", item);
    return this.#view(item);
  }

  rename(id: string, name: string): AssistantSessionView {
    const item = this.#required(id);
    const title = name.trim();
    if (!title) throw new Error("assistant_session_name_required");
    item.session.setName(title);
    item.title = title;
    item.updatedAt = new Date().toISOString();
    this.#emit("session_updated", "rename", item);
    return this.#view(item);
  }

  async delete(id: string): Promise<void> {
    const item = this.#required(id);
    await item.session.abort();
    await item.pending?.catch(() => undefined);
    item.unsubscribe();
    await item.session.dispose();
    this.#sessions.delete(id);
    this.#emit("session_deleted", "delete", item);
    if (item.session.sessionFile) await unlink(item.session.sessionFile).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    const values = [...this.#sessions.values()];
    for (const item of values) item.unsubscribe();
    await Promise.allSettled(values.map(async (item) => {
      await item.session.abort();
      await item.pending?.catch(() => undefined);
      await item.session.dispose();
    }));
    this.#sessions.clear();
    this.#listeners.clear();
    await this.#subagents?.dispose();
    await this.#mcp.close();
  }

  #view(item: MutableAssistantSession): AssistantSessionView {
    return Object.freeze({
      id: item.id,
      title: item.title,
      status: item.status,
      model: item.model,
      cwd: this.#options.cwd,
      activeTools: Object.freeze([...item.session.activeTools]),
      messages: messages(item.session.messages),
      ...(item.error ? { error: item.error } : {}),
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
    });
  }

  async #restore(): Promise<void> {
    const infos = await this.#options.sessions.listSessions(this.#options.cwd, this.#options.sessionDirectory);
    for (const info of infos) {
      let sessionId = info.id;
      const customTools = this.#sessionTools(() => sessionId);
      const session = await this.#options.sessions.createSession({
        profile: "interactive",
        cwd: this.#options.cwd,
        sessionFile: info.path,
        ...(this.#options.sessionDirectory ? { sessionDirectory: this.#options.sessionDirectory } : {}),
        ...(this.#options.systemPrompt ? { systemPrompt: this.#options.systemPrompt } : {}),
        ...(this.#options.tools ? { tools: this.#options.tools } : {}),
        ...(this.#options.excludeTools ? { excludeTools: this.#options.excludeTools } : {}),
        ...(customTools.length ? { customTools } : {}),
        ...(this.#options.skillPaths ? { skillPaths: this.#options.skillPaths } : {}),
      });
      sessionId = session.id;
      this.#register(
        session,
        info.name || info.firstMessage.replace(/\s+/g, " ").slice(0, 48) || "历史对话",
        session.modelReference ?? this.#options.sessions.models.defaultAlias,
        info.createdAt,
        info.updatedAt,
      );
    }
  }

  #register(session: PlatformAgentSession, title: string, model: string, createdAt: string, updatedAt: string): MutableAssistantSession {
    const item: MutableAssistantSession = {
      id: session.id, title, model, status: "idle", createdAt, updatedAt, session, unsubscribe: () => undefined,
    };
    item.unsubscribe = session.subscribe((event) => {
      if (!this.#sessions.has(item.id)) return;
      item.updatedAt = new Date().toISOString();
      if (event.type === "agent_start") item.status = "running";
      if (event.type === "agent_settled" && item.status !== "error") item.status = "idle";
      this.#emit("session_updated", event.type, item);
    });
    this.#sessions.set(item.id, item);
    return item;
  }

  #activeMcpTools(): Awaited<ReturnType<McpSession["tools"]>>[number][] {
    return [...this.#mcpEnabled].flatMap((name) => [...(this.#mcpTools.get(name) ?? [])]);
  }

  #sessionTools(parentSessionId: () => string) {
    return [...this.#activeMcpTools(), ...(this.#subagents ? [this.#subagents.delegationTool(parentSessionId)] : [])];
  }

  #assertToolNamesAvailable(owner: string, tools: readonly Awaited<ReturnType<McpSession["tools"]>>[number][]): void {
    const existing = new Set([...this.#mcpTools.entries()].filter(([name]) => name !== owner).flatMap(([, values]) => values.map((tool) => tool.name)));
    for (const tool of tools) {
      if (this.#subagents && tool.name === "delegate_task") throw new Error("global_tool_name_conflict:delegate_task");
      if (existing.has(tool.name)) throw new Error(`global_tool_name_conflict:${tool.name}`);
      existing.add(tool.name);
    }
  }

  #required(id: string): MutableAssistantSession {
    const item = this.#sessions.get(id);
    if (!item) throw new Error(`assistant_session_not_found:${id}`);
    return item;
  }

  #assertActive(): void {
    if (this.#disposed) throw new Error("assistant_service_disposed");
  }

  #emit(type: AssistantSessionEvent["type"], cause: string, item: MutableAssistantSession): void {
    const event = Object.freeze({ id: `EVENT-${randomUUID()}`, type, cause, session: this.#view(item), timestamp: new Date().toISOString() });
    for (const listener of this.#listeners) listener(event);
  }
}
