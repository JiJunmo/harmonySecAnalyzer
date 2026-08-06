import { readFileSync, writeFileSync } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import fg from "fast-glob";
import {
  PLUGIN_API_VERSION,
  type McpPolicyConfig,
  type PluginActivationContext,
  type PluginArtifactContent,
  type PluginArtifactDescriptor,
  type PluginCliCommand,
  type PluginDefinition,
  type PluginEvent,
  type PluginEventOptions,
  type PluginOperation,
  type PluginRunAction,
  type PluginRunReference,
  type PluginRunRequest,
  type PluginRunSnapshot,
  type PluginRunStatus,
  type PluginRuntime,
  type SkillConfigDocument,
} from "@agent-platform/core";
import { HarmonyAuditOrchestrator, type HarmonyAuditOptions } from "./orchestrator.js";
import { listCapabilities } from "./capabilities.js";
import { profileProject } from "./project/profiler.js";
import { inspectHarmonyAuditReadiness, type HarmonyAuditReadiness } from "./readiness.js";
import { HARMONY_DEFAULT_AGENT_CAPACITY, HARMONY_MAX_AGENT_CAPACITY, harmonyAgentCapacity } from "./pool-policy.js";
import { AuditStore } from "./runtime/store.js";

export interface HarmonyAuditPluginConfig {
  readonly atlasExecutable: string;
  readonly allowedRoots: readonly string[];
  readonly capacity?: number;
  readonly model?: string;
  readonly piAgentDir?: string;
  readonly piCwd?: string;
  readonly mcp?: McpPolicyConfig;
  readonly skills?: SkillConfigDocument;
  readonly eventPollIntervalMs?: number;
  readonly discoverHistory?: boolean;
  readonly historyMaxRuns?: number;
}

export interface HarmonyAuditRunPayload {
  readonly target: string;
  readonly incremental?: boolean;
  readonly capabilities?: readonly string[];
  readonly components?: readonly string[];
  readonly capacity?: number;
  readonly model?: string;
}

export interface HarmonyAuditPluginDependencies {
  readonly createOrchestrator: (options: HarmonyAuditOptions) => Pick<HarmonyAuditOrchestrator, "run" | "resume">;
  readonly inspectReadiness?: (options: HarmonyAuditOptions) => Promise<HarmonyAuditReadiness>;
}

const defaultDependencies: HarmonyAuditPluginDependencies = {
  createOrchestrator: (options) => new HarmonyAuditOrchestrator(options),
  inspectReadiness: inspectHarmonyAuditReadiness,
};

const harmonyWebRoot = fileURLToPath(new URL("../resources/web", import.meta.url));

const terminal = new Set<PluginRunStatus>(["succeeded", "failed", "cancelled"]);
const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);

const artifactDefinitions = Object.freeze({
  "report-json": { path: "reportJson", name: "report.json", mediaType: "application/json" },
  "report-markdown": { path: "reportMarkdown", name: "report.md", mediaType: "text/markdown; charset=utf-8" },
  "report-html": { path: "reportHtml", name: "report.html", mediaType: "text/html; charset=utf-8" },
  "attack-matrix": { path: "attackMatrixJson", name: "attack-matrix.json", mediaType: "application/json" },
} as const);

type ArtifactId = keyof typeof artifactDefinitions;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

// Execution settings (agent pool capacity, model) are run-level policy, not audit
// facts, so they live in a sidecar next to run.db instead of the schema. Resume
// restores them so a recovered run keeps the concurrency it was created with.
const RUN_EXECUTION_SETTINGS_FILE = "run-capacity.json";

interface RunExecutionSettings {
  readonly schema_version: number;
  readonly capacity?: number;
  readonly model?: string;
}

function persistRunExecutionSettings(runDirectory: string, settings: { capacity: number; model?: string | undefined }): void {
  try {
    writeFileSync(join(runDirectory, RUN_EXECUTION_SETTINGS_FILE), `${JSON.stringify({ schema_version: 1, ...settings }, null, 2)}\n`, "utf8");
  } catch { /* Persisting settings must never fail run creation. */ }
}

function readRunExecutionSettings(runDirectory: string): RunExecutionSettings | undefined {
  try {
    const parsed = JSON.parse(readFileSync(join(runDirectory, RUN_EXECUTION_SETTINGS_FILE), "utf8")) as Partial<RunExecutionSettings>;
    if (parsed?.schema_version !== 1) return undefined;
    return {
      schema_version: 1,
      ...(typeof parsed.capacity === "number" ? { capacity: parsed.capacity } : {}),
      ...(typeof parsed.model === "string" && parsed.model ? { model: parsed.model } : {}),
    };
  } catch { return undefined; }
}

function stringList(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) throw new Error(`harmony_audit_payload_invalid:${field}`);
  return value.map(String);
}

function capacity(value: unknown, fallback: number): number {
  return harmonyAgentCapacity(value === undefined ? fallback : value);
}

function cliValue(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function cliValues(args: readonly string[], flag: string): string[] {
  return args.flatMap((value, index) => value === flag && args[index + 1] ? [args[index + 1]!] : []);
}

function cliTarget(args: readonly string[], usage: string): string {
  const target = args[0];
  if (!target || target.startsWith("--")) throw new Error(`usage:${usage}`);
  return target;
}

function cliCapacity(value: string): number {
  const result = Number(value);
  if (!Number.isInteger(result) || result < 1 || result > HARMONY_MAX_AGENT_CAPACITY) throw new Error(`usage:capacity_must_be_1_to_${HARMONY_MAX_AGENT_CAPACITY}`);
  return result;
}

const harmonyCliCommands: readonly PluginCliCommand[] = Object.freeze([
  {
    name: "audit", description: "Start a HarmonyOS white-box audit", usage: "audit <repository> [--incremental] [--capability ID] [--component NAME] [--capacity 1..5] [--model ALIAS]",
    invoke(args) {
      const target = cliTarget(args, this.usage); const rawCapacity = cliValue(args, "--capacity");
      const incremental = args.includes("--incremental");
      const capabilities = cliValues(args, "--capability"); const components = cliValues(args, "--component");
      if (incremental && (capabilities.length || components.length)) throw new Error("usage:incremental_mode_cannot_filter_scope");
      return { kind: "run", payload: {
        target, ...(incremental ? { incremental: true } : {}), capabilities, components,
        ...(rawCapacity !== undefined ? { capacity: cliCapacity(rawCapacity) } : {}),
        ...(cliValue(args, "--model") ? { model: cliValue(args, "--model") } : {}),
      } };
    },
  },
  { name: "status", description: "Inspect an existing audit run", usage: "status <run-directory>", invoke(args) { return { kind: "inspect", run: { id: cliTarget(args, this.usage) } }; } },
  { name: "resume", description: "Resume an audit run", usage: "resume <run-directory> [--capacity 1..5]", invoke(args) { const raw = cliValue(args, "--capacity"); return { kind: "action", run: { id: cliTarget(args, this.usage) }, action: { name: "resume", payload: raw === undefined ? {} : { capacity: cliCapacity(raw) } }, wait: true }; } },
  { name: "cancel", description: "Cancel an audit run", usage: "cancel <run-directory>", invoke(args) { return { kind: "action", run: { id: cliTarget(args, this.usage) }, action: { name: "cancel" } }; } },
  { name: "report", description: "Rebuild audit reports", usage: "report <run-directory>", invoke(args) { return { kind: "action", run: { id: cliTarget(args, this.usage) }, action: { name: "rebuild-report" } }; } },
  {
    name: "capabilities", description: "List Harmony audit capabilities", usage: "capabilities [--status enabled|planned|deferred]",
    invoke(args) {
      const status = cliValue(args, "--status");
      if (status && !["enabled", "planned", "deferred"].includes(status)) throw new Error("usage:invalid_capability_status");
      return { kind: "operation", operation: { name: "capabilities", payload: status ? { status } : {} } };
    },
  },
  { name: "components", description: "Profile HarmonyOS project components", usage: "components <repository>", invoke(args) { return { kind: "operation", operation: { name: "profile", payload: { target: cliTarget(args, this.usage) } } }; } },
]);

function statusOf(value: unknown): PluginRunStatus {
  switch (String(value)) {
    case "created": return "accepted";
    case "running": return "running";
    case "complete":
    case "complete_with_gaps": return "succeeded";
    case "failed": return "failed";
    case "cancelled": return "cancelled";
    default: return "preparing";
  }
}

async function waitForPoll(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return;
  await new Promise<void>((done) => {
    const finish = () => { clearTimeout(timer); signal?.removeEventListener("abort", finish); done(); };
    const timer = setTimeout(finish, milliseconds);
    timer.unref();
    signal?.addEventListener("abort", finish, { once: true });
  });
}

class HarmonyAuditPluginRuntime implements PluginRuntime {
  readonly #config: HarmonyAuditPluginConfig;
  readonly #allowedRoots: readonly string[];
  readonly #context: PluginActivationContext;
  readonly #dependencies: HarmonyAuditPluginDependencies;
  readonly #executions = new Map<string, Promise<void>>();
  readonly #preparing = new Set<string>();
  readonly #abortHandler: () => void;
  #disposed = false;

  private constructor(config: HarmonyAuditPluginConfig, allowedRoots: readonly string[], context: PluginActivationContext, dependencies: HarmonyAuditPluginDependencies) {
    this.#config = config;
    this.#allowedRoots = allowedRoots;
    this.#context = context;
    this.#dependencies = dependencies;
    this.#abortHandler = () => { void this.dispose(); };
    context.signal.addEventListener("abort", this.#abortHandler, { once: true });
  }

  static async create(config: HarmonyAuditPluginConfig, context: PluginActivationContext, dependencies: HarmonyAuditPluginDependencies): Promise<HarmonyAuditPluginRuntime> {
    const roots = await Promise.all(config.allowedRoots.map((root) => realpath(resolve(root))));
    return new HarmonyAuditPluginRuntime(config, Object.freeze(roots), context, dependencies);
  }

  #assertActive(): void {
    if (this.#disposed) throw new Error("harmony_audit_plugin_disposed");
    if (this.#context.signal.aborted) throw new Error("harmony_audit_plugin_aborted");
  }

  async #authorize(path: string): Promise<string> {
    this.#assertActive();
    if (!isAbsolute(path)) throw new Error("harmony_audit_absolute_path_required");
    const target = await realpath(resolve(path));
    if (!this.#allowedRoots.some((root) => {
      const child = relative(root, target);
      return child === "" || (!child.startsWith("..") && !isAbsolute(child));
    })) throw new Error("harmony_audit_path_outside_allowed_roots");
    return target;
  }

  #options(runCapacity: number, model: string | undefined, onRunCreated?: HarmonyAuditOptions["onRunCreated"]): HarmonyAuditOptions {
    return {
      atlasExecutable: this.#config.atlasExecutable,
      capacity: runCapacity,
      ...(model ?? this.#config.model ? { model: model ?? this.#config.model } : {}),
      ...(this.#config.piAgentDir ? { piAgentDir: this.#config.piAgentDir } : {}),
      ...(this.#config.piCwd ? { piCwd: this.#config.piCwd } : {}),
      ...(this.#config.mcp ? { mcp: this.#config.mcp } : {}),
      ...(this.#config.skills ? { skills: this.#config.skills } : {}),
      ...(onRunCreated ? { onRunCreated } : {}),
    };
  }

  async operation(operation: PluginOperation): Promise<unknown> {
    this.#assertActive();
    if (operation.name === "readiness") {
      const inspect = this.#dependencies.inspectReadiness ?? inspectHarmonyAuditReadiness;
      const readiness = await inspect(this.#options(this.#config.capacity ?? HARMONY_DEFAULT_AGENT_CAPACITY, this.#config.model));
      return Object.freeze({ ...readiness, allowedRoots: Object.freeze([...this.#allowedRoots]) });
    }
    if (operation.name === "capabilities") {
      const capabilities = await listCapabilities();
      const requested = isRecord(operation.payload) && typeof operation.payload.status === "string" ? operation.payload.status : undefined;
      return { capabilities: requested ? capabilities.filter((item) => item.status === requested) : capabilities };
    }
    if (operation.name === "profile") {
      if (!isRecord(operation.payload) || typeof operation.payload.target !== "string") throw new Error("harmony_audit_payload_invalid:target");
      return profileProject(await this.#authorize(operation.payload.target));
    }
    throw new Error(`harmony_audit_operation_not_supported:${operation.name}`);
  }

  async createRun(request: PluginRunRequest): Promise<PluginRunSnapshot> {
    this.#assertActive();
    if (!isRecord(request.payload) || typeof request.payload.target !== "string") throw new Error("harmony_audit_payload_invalid:target");
    const payload: HarmonyAuditRunPayload = {
      target: await this.#authorize(request.payload.target),
      incremental: request.payload.incremental === true,
      capabilities: stringList(request.payload.capabilities, "capabilities"),
      components: stringList(request.payload.components, "components"),
      capacity: capacity(request.payload.capacity, this.#config.capacity ?? HARMONY_DEFAULT_AGENT_CAPACITY),
      ...(typeof request.payload.model === "string" && request.payload.model ? { model: request.payload.model } : {}),
    };
    if (payload.incremental && (payload.capabilities?.length || payload.components?.length)) throw new Error("incremental_mode_cannot_filter_scope");
    let createdDirectory: string | undefined;
    let resolveCreated!: (snapshot: PluginRunSnapshot) => void;
    let rejectCreated!: (error: unknown) => void;
    const created = new Promise<PluginRunSnapshot>((resolvePromise, rejectPromise) => {
      resolveCreated = resolvePromise;
      rejectCreated = rejectPromise;
    });
    let execution!: Promise<void>;
    const orchestrator = this.#dependencies.createOrchestrator(this.#options(payload.capacity!, payload.model, (run) => {
      createdDirectory = run.runDirectory;
      persistRunExecutionSettings(run.runDirectory, {
        capacity: payload.capacity!, model: payload.model ?? this.#config.model,
      });
      resolveCreated(this.#snapshot(AuditStore.openExisting(run.runDirectory)));
      queueMicrotask(() => this.#executions.set(run.runDirectory, execution));
    }));
    execution = Promise.resolve(orchestrator.run({ request: {
      prompt: `/audit ${payload.target}`,
      orchestrator: "harmony-audit",
      cwd: payload.target,
      metadata: { target: payload.target, incremental: payload.incremental, capabilities: payload.capabilities, components: payload.components },
    } })).then(() => {
      if (!createdDirectory) rejectCreated(new Error("harmony_audit_run_not_initialized"));
    }).catch((error: unknown) => {
      if (!createdDirectory) rejectCreated(error);
      else {
        try { AuditStore.openExisting(createdDirectory).markFailed(errorMessage(error)); } catch { /* Preserve the original execution error. */ }
        this.#context.logger.error("harmony audit execution failed", { run: createdDirectory, error: errorMessage(error) });
      }
    }).finally(() => {
      if (createdDirectory) this.#executions.delete(createdDirectory);
    });
    return created;
  }

  async adoptRun(run: PluginRunReference): Promise<PluginRunSnapshot> {
    return this.getRun(run);
  }

  async discoverRuns(): Promise<readonly PluginRunReference[]> {
    this.#assertActive();
    if (this.#config.discoverHistory === false) return Object.freeze([]);
    const maximum = this.#config.historyMaxRuns ?? 500;
    const directories = new Set<string>();
    for (const root of this.#allowedRoots) {
      const databases = await fg(["**/reports/harmony-audit-*/run.db"], {
        cwd: root, absolute: true, onlyFiles: true, followSymbolicLinks: false,
        ignore: ["**/.git/**", "**/node_modules/**", "**/oh_modules/**", "**/build/**", "**/outputs/**"],
      });
      for (const database of databases.sort()) {
        if (directories.size >= maximum) break;
        const directory = await realpath(dirname(database)).catch(() => undefined);
        if (!directory) continue;
        try {
          const authorized = await this.#authorize(directory);
          const store = AuditStore.openExisting(authorized);
          store.markGatewayRestarted();
          directories.add(authorized);
        } catch (error) {
          this.#context.logger.warn("ignored invalid harmony audit history", { directory, error: errorMessage(error) });
        }
      }
    }
    return Object.freeze([...directories].sort().map((id) => Object.freeze({ id })));
  }

  async getRun(run: PluginRunReference): Promise<PluginRunSnapshot> {
    const directory = await this.#authorize(run.id);
    return this.#snapshot(AuditStore.openExisting(directory));
  }

  async executions(run: PluginRunReference) {
    const directory = await this.#authorize(run.id);
    return AuditStore.openExisting(directory).executions();
  }

  async execution(run: PluginRunReference, executionId: string) {
    const directory = await this.#authorize(run.id);
    return AuditStore.openExisting(directory).execution(executionId);
  }

  async *events(run: PluginRunReference, options: PluginEventOptions = {}): AsyncIterable<PluginEvent> {
    const directory = await this.#authorize(run.id);
    const store = AuditStore.openExisting(directory);
    let cursor = Number(options.after?.split(":").at(-1) ?? 0);
    if (!Number.isInteger(cursor) || cursor < 0) throw new Error("harmony_audit_event_cursor_invalid");
    while (!this.#disposed && !this.#context.signal.aborted && !options.signal?.aborted) {
      const events = store.eventsAfter(cursor);
      for (const event of events) {
        cursor = event.event_id;
        yield Object.freeze({
          id: `${store.runId()}:${event.event_id}`,
          run: Object.freeze({ id: directory }),
          type: event.event_type,
          timestamp: event.created_at,
          payload: Object.freeze({ subjectId: event.subject_id, data: event.payload }),
        });
      }
      if (terminal.has(this.#snapshot(store).status)) return;
      await waitForPoll(this.#config.eventPollIntervalMs ?? 500, options.signal ?? this.#context.signal);
    }
  }

  async action(run: PluginRunReference, action: PluginRunAction): Promise<PluginRunSnapshot> {
    const directory = await this.#authorize(run.id);
    const store = AuditStore.openExisting(directory);
    if (action.name === "cancel") {
      store.cancel(isRecord(action.payload) && typeof action.payload.reason === "string" ? action.payload.reason : undefined);
      return this.#snapshot(store);
    }
    if (action.name === "rebuild-report") {
      await store.rebuildReport();
      return this.#snapshot(store);
    }
    if (action.name === "resume") {
      if (this.#executions.has(directory)) throw new Error("harmony_audit_run_execution_active");
      // Explicit action parameters win; otherwise restore the settings the run
      // was created with, falling back to the plugin defaults for legacy runs.
      const stored = readRunExecutionSettings(directory);
      const requestedCapacity = isRecord(action.payload) ? action.payload.capacity : undefined;
      const runCapacity = capacity(requestedCapacity ?? stored?.capacity, this.#config.capacity ?? HARMONY_DEFAULT_AGENT_CAPACITY);
      const requestedModel = isRecord(action.payload) && typeof action.payload.model === "string" && action.payload.model ? action.payload.model : undefined;
      const runModel = requestedModel ?? stored?.model ?? this.#config.model;
      this.#preparing.add(directory);
      const orchestrator = this.#dependencies.createOrchestrator(this.#options(runCapacity, runModel));
      const execution = Promise.resolve(orchestrator.resume(directory)).then(() => undefined).catch((error: unknown) => {
        try { store.markFailed(errorMessage(error)); } catch { /* Preserve the original execution error. */ }
        this.#context.logger.error("harmony audit resume failed", { run: directory, error: errorMessage(error) });
      }).finally(() => {
        this.#executions.delete(directory);
        this.#preparing.delete(directory);
      });
      this.#executions.set(directory, execution);
      return this.#snapshot(store);
    }
    throw new Error(`harmony_audit_action_not_supported:${action.name}`);
  }

  async artifacts(run: PluginRunReference): Promise<readonly PluginArtifactDescriptor[]> {
    const directory = await this.#authorize(run.id);
    const store = AuditStore.openExisting(directory);
    const artifacts: PluginArtifactDescriptor[] = [];
    for (const [id, definition] of Object.entries(artifactDefinitions) as [ArtifactId, typeof artifactDefinitions[ArtifactId]][]) {
      const path = store.paths[definition.path];
      const metadata = await stat(path).catch(() => undefined);
      if (metadata?.isFile()) artifacts.push(Object.freeze({ id, name: definition.name, mediaType: definition.mediaType, size: metadata.size }));
    }
    return Object.freeze(artifacts);
  }

  async openArtifact(run: PluginRunReference, artifactId: string): Promise<PluginArtifactContent> {
    const definition = artifactDefinitions[artifactId as ArtifactId];
    if (!definition) throw new Error(`harmony_audit_artifact_not_found:${artifactId}`);
    const directory = await this.#authorize(run.id);
    const store = AuditStore.openExisting(directory);
    const path = store.paths[definition.path];
    const metadata = await stat(path).catch(() => undefined);
    if (!metadata?.isFile()) throw new Error(`harmony_audit_artifact_not_found:${artifactId}`);
    return {
      descriptor: Object.freeze({ id: artifactId, name: definition.name, mediaType: definition.mediaType, size: metadata.size }),
      body: new Uint8Array(await readFile(path)),
    };
  }

  #snapshot(store: AuditStore): PluginRunSnapshot {
    const details = store.status();
    const run = details.run as Record<string, unknown>;
    const counts = details.task_counts as Record<string, number>;
    const total = Object.values(counts).reduce((sum, value) => sum + Number(value), 0);
    const completed = Number(counts.completed ?? 0) + Number(counts.exhausted ?? 0) + Number(counts.cancelled ?? 0);
    let status = statusOf(run.status);
    if (this.#preparing.has(store.runDirectory) && status !== "running") status = "preparing";
    if (status === "running") this.#preparing.delete(store.runDirectory);
    return Object.freeze({
      run: Object.freeze({ id: store.runDirectory }),
      status,
      createdAt: String(run.created_at),
      updatedAt: String(run.updated_at),
      progress: Object.freeze({ completed, total }),
      details,
      ...(status === "failed" ? { error: Object.freeze({ code: "harmony_audit_failed", message: String(run.error ?? "audit failed") }) } : {}),
    });
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#context.signal.removeEventListener("abort", this.#abortHandler);
    await Promise.allSettled([...this.#executions.values()]);
    this.#executions.clear();
    this.#preparing.clear();
  }
}

export function createHarmonyAuditPlugin(dependencies: HarmonyAuditPluginDependencies = defaultDependencies): PluginDefinition {
  return {
    manifest: Object.freeze({
      apiVersion: PLUGIN_API_VERSION,
      id: "harmony-audit",
      version: "3.2.0",
      displayName: "HarmonyOS White-box Security Audit",
      description: "HarmonyOS project profiling, path discovery and six-dimensional security validation",
      contributes: Object.freeze(["runs", "cli", "web"] as const),
    }),
    configSchema: {
      type: "object",
      required: ["atlasExecutable", "allowedRoots"],
      properties: {
        atlasExecutable: { type: "string", minLength: 1 },
        allowedRoots: { type: "array", minItems: 1, items: { type: "string", minLength: 1 } },
        capacity: { type: "integer", minimum: 1, maximum: HARMONY_MAX_AGENT_CAPACITY },
        model: { type: "string", minLength: 1 },
        mcp: { type: "object" },
        skills: { type: "object" },
        eventPollIntervalMs: { type: "integer", minimum: 10 },
        discoverHistory: { type: "boolean" },
        historyMaxRuns: { type: "integer", minimum: 1 },
      },
      additionalProperties: false,
    },
    cli: harmonyCliCommands,
    web: Object.freeze([{
      id: "console",
      title: "HarmonyOS White-box Security Audit",
      entry: "index.html",
      assetsRoot: harmonyWebRoot,
    }]),
    async activate(context) {
      const configured = context.config as HarmonyAuditPluginConfig;
      const shared = context.sharedConfig ?? {};
      const pi = isRecord(shared.pi) ? shared.pi : {};
      const mcp = configured.mcp ?? (isRecord(shared.mcp) ? shared.mcp as McpPolicyConfig : undefined);
      const skills = configured.skills ?? (isRecord(shared.skills) ? shared.skills as SkillConfigDocument : undefined);
      return HarmonyAuditPluginRuntime.create({
        ...configured,
        ...(typeof pi.agentDir === "string" ? { piAgentDir: pi.agentDir } : {}),
        ...(typeof pi.cwd === "string" ? { piCwd: pi.cwd } : {}),
        ...(mcp ? { mcp } : {}),
        ...(skills ? { skills } : {}),
      }, context, dependencies);
    },
  };
}

export const plugin = createHarmonyAuditPlugin();
