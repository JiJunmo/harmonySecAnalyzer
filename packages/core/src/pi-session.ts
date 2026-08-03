import { basename, dirname, join, resolve } from "node:path";
import type { AgentTool, ThinkingLevel } from "@earendil-works/pi-agent-core";
import { InMemoryCredentialStore, Type, type Api, type Model } from "@earendil-works/pi-ai";
import {
  DefaultResourceLoader,
  DefaultPackageManager,
  ModelRuntime,
  SessionManager,
  SettingsManager,
  createAgentSession,
  defineTool,
  type AgentSession,
  type AgentSessionEvent,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import type { ModelConfigDocument } from "./config.js";
import { sanitizeAgentTraceValue, type AgentTraceEvent, type AgentTraceSink } from "./agent-trace.js";

export type PiSessionProfile = "interactive" | "workflow-worker";

interface CatalogModel {
  readonly alias: string;
  readonly providerId: string;
  readonly id: string;
}

export interface PiModelCatalog {
  readonly runtime: ModelRuntime;
  readonly defaultAlias: string;
  readonly taskAliases: Readonly<Record<string, string>>;
  readonly aliases: readonly string[];
  resolve(alias?: string): Model<Api>;
  resolveFor(taskKind: string, override?: string): Model<Api>;
}

export interface PiSessionFactoryOptions {
  /** Compatibility only. New callers use Pi's settings.json/models.json/auth.json under agentDir. */
  readonly models?: ModelConfigDocument;
  readonly agentDir?: string;
  readonly cwd?: string;
}

export interface PiSessionRequest {
  readonly profile: PiSessionProfile;
  readonly cwd: string;
  readonly model?: string;
  readonly taskKind?: string;
  readonly systemPrompt?: string;
  readonly thinkingLevel?: ThinkingLevel;
  readonly tools?: readonly string[];
  readonly excludeTools?: readonly string[];
  readonly customTools?: readonly ToolDefinition[];
  readonly skillPaths?: readonly string[];
  /** Interactive sessions are in-memory unless a platform-owned directory is explicitly supplied. */
  readonly sessionDirectory?: string;
  readonly sessionFile?: string;
}

export interface PiSessionInfo {
  readonly path: string;
  readonly id: string;
  readonly name?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly messageCount: number;
  readonly firstMessage: string;
}

export type PiManagedResourceKind = "skill" | "extension" | "package";
export interface PiManagedResource {
  readonly kind: PiManagedResourceKind;
  readonly id: string;
  readonly name: string;
  readonly enabled: boolean;
  readonly loaded: boolean;
  readonly scope: string;
  readonly source: string;
  readonly error?: string;
}

export interface PiResourceSnapshot {
  readonly resources: readonly PiManagedResource[];
  readonly diagnostics: readonly { readonly type: string; readonly message: string; readonly path?: string }[];
}

export interface PiStructuredRunRequest<T> {
  readonly cwd: string;
  readonly systemPrompt: string;
  readonly task: unknown;
  readonly tools: readonly AgentTool[];
  readonly outputSchema: AnySchema;
  readonly model?: string;
  readonly taskKind?: string;
  readonly signal?: AbortSignal;
  readonly submissionToolName?: string;
  /** Receives provider-visible messages and tool activity. It never exposes hidden model state. */
  readonly trace?: AgentTraceSink;
}

export interface PlatformAgentSession {
  readonly id: string;
  readonly profile: PiSessionProfile;
  readonly sessionFile: string | undefined;
  readonly activeTools: readonly string[];
  readonly messages: readonly unknown[];
  readonly streaming: boolean;
  readonly name: string | undefined;
  readonly modelReference: string | undefined;
  prompt(text: string): Promise<void>;
  steer(text: string): Promise<void>;
  followUp(text: string): Promise<void>;
  abort(): Promise<void>;
  subscribe(listener: (event: AgentSessionEvent) => void): () => void;
  setName(name: string): void;
  dispose(): Promise<void>;
}

interface ProviderDocument {
  readonly baseUrl: string;
  readonly apiKeyEnv: string;
  readonly type?: string;
  readonly name?: string;
  readonly contextWindow?: number;
  readonly maxTokens?: number;
  readonly reasoning?: boolean;
}

const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value)
  ? value as Record<string, unknown>
  : {};

function required(value: unknown, error: string): string {
  if (typeof value !== "string" || !value) throw new Error(error);
  return value;
}

function api(value: unknown): Api {
  const name = String(value ?? "openai");
  if (name === "openai" || name === "openai-compatible") return "openai-completions";
  return name as Api;
}

function modelDefinition(provider: ProviderDocument, raw: Record<string, unknown>) {
  const id = required(raw.id, "model_config_invalid:id");
  return {
    id,
    name: typeof raw.name === "string" ? raw.name : id,
    reasoning: typeof raw.reasoning === "boolean" ? raw.reasoning : provider.reasoning ?? true,
    input: ["text"] as ("text" | "image")[],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: typeof raw.contextWindow === "number" ? raw.contextWindow : provider.contextWindow ?? 1_000_000,
    maxTokens: typeof raw.maxTokens === "number" ? raw.maxTokens : provider.maxTokens ?? 65_536,
  };
}

export async function createPiModelCatalog(document: ModelConfigDocument): Promise<PiModelCatalog> {
  const runtime = await ModelRuntime.create({
    credentials: new InMemoryCredentialStore(),
    modelsPath: null,
    allowModelNetwork: false,
  });
  const catalog = new Map<string, CatalogModel>();
  const configuredProviders = document.providers ?? {};
  const configuredModels = document.catalog ?? {};

  if (Object.keys(configuredModels).length) {
    const grouped = new Map<string, { provider: ProviderDocument; models: Record<string, unknown>[] }>();
    for (const [alias, rawModel] of Object.entries(configuredModels)) {
      const model = record(rawModel);
      const providerId = required(model.provider, `model_config_invalid:${alias}:provider`);
      const rawProvider = configuredProviders[providerId];
      if (!rawProvider) throw new Error(`model_provider_not_registered:${providerId}`);
      const providerValue = record(rawProvider);
      const provider: ProviderDocument = {
        baseUrl: required(providerValue.baseUrl, `model_provider_config_invalid:${providerId}:baseUrl`),
        apiKeyEnv: required(providerValue.apiKeyEnv, `model_provider_config_invalid:${providerId}:apiKeyEnv`),
        ...(typeof providerValue.type === "string" ? { type: providerValue.type } : {}),
        ...(typeof providerValue.name === "string" ? { name: providerValue.name } : {}),
        ...(typeof providerValue.contextWindow === "number" ? { contextWindow: providerValue.contextWindow } : {}),
        ...(typeof providerValue.maxTokens === "number" ? { maxTokens: providerValue.maxTokens } : {}),
        ...(typeof providerValue.reasoning === "boolean" ? { reasoning: providerValue.reasoning } : {}),
      };
      const group = grouped.get(providerId) ?? { provider, models: [] };
      group.models.push(model); grouped.set(providerId, group);
      catalog.set(alias, { alias, providerId, id: required(model.id, `model_config_invalid:${alias}:id`) });
    }
    for (const [providerId, group] of grouped) {
      const key = process.env[group.provider.apiKeyEnv];
      if (!key) throw new Error(`model_api_key_missing:${group.provider.apiKeyEnv}`);
      runtime.registerProvider(providerId, {
        name: group.provider.name ?? providerId,
        baseUrl: group.provider.baseUrl.replace(/\/$/, ""),
        api: api(group.provider.type),
        models: group.models.map((model) => modelDefinition(group.provider, model)),
      });
      await runtime.setRuntimeApiKey(providerId, key);
    }
  } else {
    // Compatibility with the milestone-5 format where each entry contains both connection and model data.
    for (const [alias, raw] of Object.entries(configuredProviders)) {
      const value = record(raw);
      const providerId = `configured-${alias}`;
      const provider: ProviderDocument = {
        baseUrl: required(value.baseUrl, `model_config_invalid:${alias}:baseUrl`),
        apiKeyEnv: required(value.apiKeyEnv, `model_config_invalid:${alias}:apiKeyEnv`),
        ...(typeof value.provider === "string" ? { type: value.provider } : {}),
      };
      const key = process.env[provider.apiKeyEnv];
      if (!key) throw new Error(`model_api_key_missing:${provider.apiKeyEnv}`);
      const model = modelDefinition(provider, value);
      runtime.registerProvider(providerId, {
        name: alias, baseUrl: provider.baseUrl.replace(/\/$/, ""), api: api(provider.type), models: [model],
      });
      await runtime.setRuntimeApiKey(providerId, key);
      catalog.set(alias, { alias, providerId, id: model.id });
    }
  }

  const aliases = Object.freeze([...catalog.keys()].sort());
  const defaultAlias = document.default ?? aliases[0];
  if (!defaultAlias) throw new Error("model_not_selected");
  if (!catalog.has(defaultAlias)) throw new Error(`model_not_registered:${defaultAlias}`);
  for (const alias of Object.values(document.tasks ?? {})) {
    if (!catalog.has(alias)) throw new Error(`model_not_registered:${alias}`);
  }
  const resolveModel = (alias = defaultAlias): Model<Api> => {
    const item = catalog.get(alias);
    if (!item) throw new Error(`model_not_registered:${alias}`);
    const model = runtime.getModel(item.providerId, item.id);
    if (!model) throw new Error(`pi_model_not_registered:${alias}`);
    return model;
  };
  return Object.freeze({
    runtime,
    defaultAlias,
    taskAliases: Object.freeze({ ...(document.tasks ?? {}) }),
    aliases,
    resolve: resolveModel,
    resolveFor(taskKind: string, override?: string) {
      return resolveModel(override ?? document.tasks?.[taskKind] ?? defaultAlias);
    },
  });
}

async function createOfficialPiModelCatalog(agentDir: string, cwd: string): Promise<PiModelCatalog> {
  const runtime = await ModelRuntime.create({
    authPath: join(agentDir, "auth.json"),
    modelsPath: join(agentDir, "models.json"),
    allowModelNetwork: false,
  });
  const settings = SettingsManager.create(cwd, agentDir, { projectTrusted: true });
  const models = runtime.getModels();
  const findModel = (reference: string): Model<Api> | undefined => {
    const canonical = models.find((model) => `${model.provider}/${model.id}` === reference);
    if (canonical) return canonical;
    const bare = models.filter((model) => model.id === reference);
    return bare.length === 1 ? bare[0] : undefined;
  };
  const references = Object.freeze(models.map((model) => `${model.provider}/${model.id}`).sort());
  const configuredProvider = settings.getDefaultProvider();
  const configuredModel = settings.getDefaultModel();
  const configuredReference = configuredProvider && configuredModel ? `${configuredProvider}/${configuredModel}` : configuredModel;
  const defaultModel = configuredReference ? findModel(configuredReference) : models[0];
  if (!defaultModel) throw new Error(configuredReference ? `model_not_registered:${configuredReference}` : "model_not_selected");
  const defaultAlias = `${defaultModel.provider}/${defaultModel.id}`;
  const resolveModel = (reference = defaultAlias): Model<Api> => {
    const model = findModel(reference);
    if (!model) throw new Error(`model_not_registered:${reference}`);
    return model;
  };
  return Object.freeze({
    runtime,
    defaultAlias,
    taskAliases: Object.freeze({}),
    aliases: references,
    resolve: resolveModel,
    resolveFor(_taskKind: string, override?: string) { return resolveModel(override); },
  });
}

class PiBackedSession implements PlatformAgentSession {
  #disposed = false;
  constructor(readonly profile: PiSessionProfile, readonly session: AgentSession) {}
  get id(): string { return this.session.sessionId; }
  get sessionFile(): string | undefined { return this.session.sessionFile; }
  get activeTools(): readonly string[] { return this.session.getActiveToolNames(); }
  get messages(): readonly unknown[] { return this.session.messages; }
  get streaming(): boolean { return this.session.isStreaming; }
  get name(): string | undefined { return this.session.sessionName; }
  get modelReference(): string | undefined { const model = this.session.model; return model ? `${model.provider}/${model.id}` : undefined; }
  prompt(text: string): Promise<void> { return this.session.prompt(text); }
  steer(text: string): Promise<void> { return this.session.steer(text); }
  followUp(text: string): Promise<void> { return this.session.followUp(text); }
  abort(): Promise<void> { return this.session.abort(); }
  subscribe(listener: (event: AgentSessionEvent) => void): () => void { return this.session.subscribe(listener); }
  setName(name: string): void { this.session.setSessionName(name); }
  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    await this.session.abort();
    this.session.dispose();
  }
}

export class PiSessionFactory {
  readonly #models: PiModelCatalog;
  readonly #agentDir: string;
  readonly #officialSettings: boolean;
  private constructor(models: PiModelCatalog, agentDir: string, officialSettings: boolean) {
    this.#models = models; this.#agentDir = agentDir; this.#officialSettings = officialSettings;
  }

  static async create(options: PiSessionFactoryOptions): Promise<PiSessionFactory> {
    const agentDir = resolve(options.agentDir ?? process.env.PI_CODING_AGENT_DIR ?? ".pi/agent");
    const official = !options.models;
    const models = options.models
      ? await createPiModelCatalog(options.models)
      : await createOfficialPiModelCatalog(agentDir, resolve(options.cwd ?? process.cwd()));
    return new PiSessionFactory(models, agentDir, official);
  }

  get models(): PiModelCatalog { return this.#models; }

  async resources(cwd: string): Promise<PiResourceSnapshot> {
    const root = resolve(cwd);
    const settings = SettingsManager.create(root, this.#agentDir, { projectTrusted: true });
    const loader = new DefaultResourceLoader({ cwd: root, agentDir: this.#agentDir, settingsManager: settings });
    await loader.reload();
    const loadedSkills = loader.getSkills();
    const loadedExtensions = loader.getExtensions();
    const packageManager = new DefaultPackageManager({ cwd: root, agentDir: this.#agentDir, settingsManager: settings });
    const resources: PiManagedResource[] = [];
    const skillPaths = settings.getSkillPaths();
    const extensionPaths = settings.getExtensionPaths();
    for (const skill of loadedSkills.skills) resources.push(Object.freeze({
      kind: "skill", id: skill.filePath, name: skill.name, enabled: true, loaded: true,
      scope: skill.sourceInfo.scope, source: skill.sourceInfo.source,
    }));
    for (const value of skillPaths.filter((path) => path.startsWith("-"))) resources.push(Object.freeze({
      kind: "skill", id: value.slice(1), name: basename(value.slice(1)).toLowerCase() === "skill.md" ? basename(dirname(value.slice(1))) : basename(value.slice(1)),
      enabled: false, loaded: false, scope: "user", source: "settings",
    }));
    for (const extension of loadedExtensions.extensions) resources.push(Object.freeze({
      kind: "extension", id: extension.resolvedPath, name: extension.resolvedPath.split(/[\\/]/).filter(Boolean).at(-1) ?? extension.path,
      enabled: true, loaded: true, scope: extension.sourceInfo.scope, source: extension.sourceInfo.source,
    }));
    for (const value of extensionPaths.filter((path) => path.startsWith("-"))) resources.push(Object.freeze({
      kind: "extension", id: value.slice(1), name: value.slice(1).split(/[\\/]/).filter(Boolean).at(-1) ?? value.slice(1),
      enabled: false, loaded: false, scope: "user", source: "settings",
    }));
    const installedPackages = new Map(packageManager.listConfiguredPackages().map((pkg) => [pkg.source, pkg]));
    for (const configured of settings.getPackages()) {
      const id = typeof configured === "string" ? configured : configured.source;
      const pkg = installedPackages.get(id);
      resources.push(Object.freeze({
        kind: "package", id, name: id, enabled: typeof configured === "string" || configured.autoload !== false,
        loaded: !!pkg?.installedPath, scope: pkg?.scope ?? "user", source: pkg?.installedPath ?? id,
      }));
    }
    for (const error of loadedExtensions.errors) resources.push(Object.freeze({
      kind: "extension", id: error.path, name: error.path.split(/[\\/]/).filter(Boolean).at(-1) ?? error.path,
      enabled: true, loaded: false, scope: "unknown", source: error.path, error: error.error,
    }));
    const diagnostics = loadedSkills.diagnostics.map((item) => Object.freeze({
      type: item.type, message: item.message, ...(item.path ? { path: item.path } : {}),
    }));
    return Object.freeze({ resources: Object.freeze(resources), diagnostics: Object.freeze(diagnostics) });
  }

  async setResourceEnabled(cwd: string, kind: PiManagedResourceKind, id: string, enabled: boolean): Promise<PiResourceSnapshot> {
    const root = resolve(cwd);
    const current = await this.resources(root);
    if (!current.resources.some((resource) => resource.kind === kind && resource.id === id)) throw new Error(`pi_resource_not_found:${kind}:${id}`);
    const settings = SettingsManager.create(root, this.#agentDir, { projectTrusted: true });
    if (kind === "package") {
      const next = settings.getPackages().map((value) => {
        const source = typeof value === "string" ? value : value.source;
        if (source !== id) return value;
        if (enabled) return typeof value === "string" ? value : { ...value, autoload: true };
        return typeof value === "string"
          ? { source: value, autoload: false, extensions: [], skills: [], prompts: [], themes: [] }
          : { ...value, autoload: false };
      });
      settings.setPackages(next);
      await settings.flush();
      const errors = settings.drainErrors();
      if (errors.length) throw new Error(`pi_settings_write_failed:${errors.map((item) => item.error.message).join(";")}`);
      return this.resources(root);
    }
    const values = kind === "skill" ? settings.getSkillPaths() : settings.getExtensionPaths();
    const exclusion = `-${id}`;
    const next = enabled ? values.filter((value) => value !== exclusion) : [...values.filter((value) => value !== exclusion), exclusion];
    if (kind === "skill") settings.setSkillPaths(next); else settings.setExtensionPaths(next);
    await settings.flush();
    const errors = settings.drainErrors();
    if (errors.length) throw new Error(`pi_settings_write_failed:${errors.map((item) => item.error.message).join(";")}`);
    return this.resources(root);
  }

  async listSessions(cwd: string, sessionDirectory?: string): Promise<readonly PiSessionInfo[]> {
    if (!this.#officialSettings) return Object.freeze([]);
    const root = resolve(cwd);
    const settings = SettingsManager.create(root, this.#agentDir, { projectTrusted: true });
    const configured = sessionDirectory ?? settings.getSessionDir();
    const values = await SessionManager.list(root, configured ? resolve(root, configured) : undefined);
    return Object.freeze(values.map((value) => Object.freeze({
      path: value.path,
      id: value.id,
      ...(value.name ? { name: value.name } : {}),
      createdAt: value.created.toISOString(),
      updatedAt: value.modified.toISOString(),
      messageCount: value.messageCount,
      firstMessage: value.firstMessage,
    })));
  }

  async createSession(request: PiSessionRequest): Promise<PlatformAgentSession> {
    const cwd = resolve(request.cwd);
    const worker = request.profile === "workflow-worker";
    const settingsManager = !worker && this.#officialSettings
      ? SettingsManager.create(cwd, this.#agentDir, { projectTrusted: true })
      : SettingsManager.inMemory({
        compaction: { enabled: !worker },
        retry: { enabled: true, maxRetries: worker ? 0 : 2 },
        steeringMode: "all",
        followUpMode: "all",
      });
    const skillPaths = (request.skillPaths ?? []).map((path) => resolve(path));
    const resourceLoader = new DefaultResourceLoader({
      cwd,
      agentDir: this.#agentDir,
      settingsManager,
      additionalSkillPaths: skillPaths,
      ...(request.systemPrompt ? { systemPrompt: request.systemPrompt } : {}),
      ...(worker ? {
        noExtensions: true,
        noPromptTemplates: true,
        noThemes: true,
        noContextFiles: true,
        skillsOverride: (base) => ({
          skills: base.skills.filter((skill) => skillPaths.some((path) => skill.filePath.startsWith(path))),
          diagnostics: base.diagnostics,
        }),
      } : {}),
    });
    await resourceLoader.reload();
    const configuredSessionDirectory = request.sessionDirectory ?? (!worker ? settingsManager.getSessionDir() : undefined);
    const sessionManager = request.sessionFile
      ? SessionManager.open(resolve(request.sessionFile), configuredSessionDirectory ? resolve(cwd, configuredSessionDirectory) : undefined, cwd)
      : !worker && (this.#officialSettings || configuredSessionDirectory)
      ? SessionManager.create(cwd, configuredSessionDirectory ? resolve(cwd, configuredSessionDirectory) : undefined)
      : SessionManager.inMemory(cwd);
    const restoredModel = request.sessionFile ? sessionManager.buildSessionContext().model : null;
    const modelReference = request.model ?? (restoredModel ? `${restoredModel.provider}/${restoredModel.modelId}` : undefined);
    const model = request.taskKind
      ? this.#models.resolveFor(request.taskKind, modelReference)
      : this.#models.resolve(modelReference);
    const result = await createAgentSession({
      cwd,
      agentDir: this.#agentDir,
      model,
      modelRuntime: this.#models.runtime,
      resourceLoader,
      sessionManager,
      settingsManager,
      scopedModels: this.#models.aliases.map((alias) => ({ model: this.#models.resolve(alias) })),
      ...(request.thinkingLevel ? { thinkingLevel: request.thinkingLevel } : {}),
      ...(request.tools ? { tools: [...request.tools] } : {}),
      ...(request.excludeTools ? { excludeTools: [...request.excludeTools] } : {}),
      ...(request.customTools ? { customTools: [...request.customTools] } : {}),
      ...(worker && !request.tools ? { noTools: "builtin" as const } : {}),
    });
    return new PiBackedSession(request.profile, result.session);
  }

  async runStructured<T>(request: PiStructuredRunRequest<T>): Promise<T> {
    let submission: T | undefined;
    let traceQueue = Promise.resolve();
    const trace = (type: AgentTraceEvent["type"], payload?: unknown) => {
      if (!request.trace) return;
      const event: AgentTraceEvent = Object.freeze({
        type,
        timestamp: new Date().toISOString(),
        ...(payload === undefined ? {} : { payload: sanitizeAgentTraceValue(payload) }),
      });
      traceQueue = traceQueue.then(() => request.trace!(event)).then(() => undefined, () => undefined);
    };
    const flushTrace = () => traceQueue;
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const validate = ajv.compile<T>(request.outputSchema);
    const submissionToolName = request.submissionToolName ?? "submit_result";
    const submit = defineTool({
      name: submissionToolName,
      label: "Submit result",
      description: "Submit the final structured result. Call exactly once when the task is complete.",
      parameters: Type.Unsafe(request.outputSchema as Record<string, unknown>),
      executionMode: "sequential",
      async execute(_id, params) {
        trace("submission_started", { tool: submissionToolName });
        if (!validate(params)) {
          const error = `invalid_submission:${ajv.errorsText(validate.errors)}`;
          trace("submission_rejected", { tool: submissionToolName, error, value: params });
          throw new Error(error);
        }
        submission = structuredClone(params) as T;
        trace("submission_accepted", { tool: submissionToolName, value: params });
        return { content: [{ type: "text" as const, text: "result accepted" }], details: {}, terminate: true };
      },
    });
    const tools = [...request.tools] as unknown as ToolDefinition[];
    const session = await this.createSession({
      profile: "workflow-worker",
      cwd: request.cwd,
      systemPrompt: request.systemPrompt,
      ...(request.model ? { model: request.model } : {}),
      ...(request.taskKind ? { taskKind: request.taskKind } : {}),
      tools: [...tools.map((tool) => tool.name), submissionToolName],
      customTools: [...tools, submit],
    });
    const unsubscribe = session.subscribe((event) => {
      if (event.type === "agent_start") trace("agent_started", { model: session.modelReference, tools: session.activeTools });
      if (event.type === "tool_execution_start") trace("tool_call_started", { callId: event.toolCallId, tool: event.toolName, arguments: event.args });
      if (event.type === "tool_execution_end") trace("tool_call_completed", {
        callId: event.toolCallId, tool: event.toolName, isError: event.isError, result: event.result,
      });
      if (event.type === "message_end") {
        const message = event.message as unknown as Record<string, unknown>;
        if (message.role === "assistant") {
          const content = Array.isArray(message.content)
            ? message.content.filter((block) => block && typeof block === "object" && ["text", "thinking"].includes(String((block as Record<string, unknown>).type)))
            : message.content;
          if ((Array.isArray(content) && content.length) || (!Array.isArray(content) && content)) {
            trace("assistant_message", { content, stopReason: message.stopReason, errorMessage: message.errorMessage });
          } else if (message.errorMessage) trace("assistant_message", { errorMessage: message.errorMessage, stopReason: message.stopReason });
        }
      }
    });
    const abort = () => { void session.abort(); };
    request.signal?.addEventListener("abort", abort, { once: true });
    try {
      if (request.signal?.aborted) await session.abort();
      else await session.prompt(`Complete this task and call ${submissionToolName} with the final answer:\n${JSON.stringify(request.task)}`);
      if (submission === undefined) trace("agent_failed", { error: "agent_did_not_submit_result" });
      else trace("agent_completed", { submitted: true });
    } catch (error) {
      trace("agent_failed", { error: error instanceof Error ? error.message : String(error) });
      throw error;
    } finally {
      request.signal?.removeEventListener("abort", abort);
      unsubscribe();
      await session.dispose();
      await flushTrace();
    }
    if (submission === undefined) throw new Error("agent_did_not_submit_result");
    return submission;
  }
}
