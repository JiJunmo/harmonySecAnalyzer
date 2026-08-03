import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";

export const PLUGIN_API_VERSION = "1" as const;

export type PluginContributionKind = "runs" | "cli" | "web";

export interface PluginManifest {
  readonly apiVersion: string;
  readonly id: string;
  readonly version: string;
  readonly displayName: string;
  readonly description?: string;
  readonly entry?: string;
  readonly contributes: readonly PluginContributionKind[];
}

export interface PluginLogger {
  debug(message: string, data?: Readonly<Record<string, unknown>>): void;
  info(message: string, data?: Readonly<Record<string, unknown>>): void;
  warn(message: string, data?: Readonly<Record<string, unknown>>): void;
  error(message: string, data?: Readonly<Record<string, unknown>>): void;
}

export interface PluginActivationContext {
  readonly config: unknown;
  readonly sharedConfig?: Readonly<Record<string, unknown>>;
  readonly signal: AbortSignal;
  readonly logger: PluginLogger;
}

export interface PluginSubject {
  readonly id: string;
  readonly attributes?: Readonly<Record<string, unknown>>;
}

export interface PluginRunRequest {
  readonly requestId: string;
  readonly payload: unknown;
  readonly subject?: PluginSubject;
}

/** The value is opaque to the platform and meaningful only to its owning plugin. */
export interface PluginRunReference {
  readonly id: string;
}

export type PluginRunStatus = "accepted" | "preparing" | "running" | "succeeded" | "failed" | "cancelled";

export interface PluginRunProgress {
  readonly completed: number;
  readonly total?: number;
  readonly message?: string;
}

export interface PluginRunError {
  readonly code: string;
  readonly message: string;
}

export interface PluginRunSnapshot {
  readonly run: PluginRunReference;
  readonly status: PluginRunStatus;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly progress?: PluginRunProgress;
  readonly details?: unknown;
  readonly error?: PluginRunError;
}

export interface PluginEvent {
  readonly id: string;
  readonly run: PluginRunReference;
  readonly type: string;
  readonly timestamp: string;
  readonly payload?: unknown;
}

export interface PluginEventOptions {
  readonly after?: string;
  readonly signal?: AbortSignal;
}

export type PluginExecutionStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

/** A domain-neutral unit of agent work owned by a plugin run. */
export interface PluginExecutionUnit {
  readonly id: string;
  readonly kind: string;
  readonly title: string;
  readonly status: PluginExecutionStatus;
  readonly subject?: string;
  readonly attempt: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly error?: string;
}

export interface PluginExecutionAttempt {
  readonly attempt: number;
  readonly status: PluginExecutionStatus;
  readonly startedAt?: string;
  readonly completedAt?: string;
  readonly error?: string;
}

export interface PluginExecutionTraceEvent {
  readonly id: string;
  readonly attempt: number;
  readonly type: string;
  readonly timestamp: string;
  readonly payload?: unknown;
}

export interface PluginExecutionDetail {
  readonly execution: PluginExecutionUnit;
  readonly input?: unknown;
  readonly result?: unknown;
  readonly attempts: readonly PluginExecutionAttempt[];
  readonly events: readonly PluginExecutionTraceEvent[];
}

export interface PluginRunAction {
  readonly name: string;
  readonly payload?: unknown;
  readonly subject?: PluginSubject;
}

/** A plugin-level operation that is not tied to an existing run. */
export interface PluginOperation {
  readonly name: string;
  readonly payload?: unknown;
  readonly subject?: PluginSubject;
}

export type PluginCliInvocation =
  | { readonly kind: "operation"; readonly operation: PluginOperation }
  | { readonly kind: "run"; readonly payload: unknown; readonly subject?: PluginSubject }
  | { readonly kind: "inspect"; readonly run: PluginRunReference }
  | { readonly kind: "action"; readonly run: PluginRunReference; readonly action: PluginRunAction; readonly wait?: boolean }
  | { readonly kind: "artifacts"; readonly run: PluginRunReference };

export interface PluginCliCommand {
  readonly name: string;
  readonly description: string;
  readonly usage: string;
  invoke(args: readonly string[]): PluginCliInvocation | Promise<PluginCliInvocation>;
}

export interface PluginWebContribution {
  readonly id: string;
  readonly title: string;
  readonly entry: string;
  readonly assetsRoot: string;
}

export interface PluginArtifactDescriptor {
  readonly id: string;
  readonly name: string;
  readonly mediaType: string;
  readonly size?: number;
}

export interface PluginArtifactContent {
  readonly descriptor: PluginArtifactDescriptor;
  readonly body: Uint8Array | AsyncIterable<Uint8Array>;
}

export interface PluginRuntime {
  operation(operation: PluginOperation): Promise<unknown>;
  createRun(request: PluginRunRequest): Promise<PluginRunSnapshot>;
  adoptRun(run: PluginRunReference): Promise<PluginRunSnapshot>;
  getRun(run: PluginRunReference): Promise<PluginRunSnapshot>;
  events(run: PluginRunReference, options?: PluginEventOptions): AsyncIterable<PluginEvent>;
  action(run: PluginRunReference, action: PluginRunAction): Promise<PluginRunSnapshot>;
  artifacts(run: PluginRunReference): Promise<readonly PluginArtifactDescriptor[]>;
  openArtifact(run: PluginRunReference, artifactId: string): Promise<PluginArtifactContent>;
  /** Optional multi-agent observability contribution. */
  executions?(run: PluginRunReference): Promise<readonly PluginExecutionUnit[]>;
  execution?(run: PluginRunReference, executionId: string): Promise<PluginExecutionDetail>;
  /** Optional plugin-owned discovery of durable runs after a host restart. */
  discoverRuns?(): Promise<readonly PluginRunReference[]>;
  dispose(): Promise<void>;
}

export interface PluginDefinition {
  readonly manifest: PluginManifest;
  readonly configSchema?: AnySchema;
  readonly defaultConfig?: unknown;
  activate(context: PluginActivationContext): PluginRuntime | Promise<PluginRuntime>;
  readonly cli?: readonly PluginCliCommand[];
  readonly web?: readonly PluginWebContribution[];
}

/** @deprecated Use PluginDefinition. */
export type AgentPlugin = PluginDefinition;

function assertNonEmptyString(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`plugin_manifest_invalid:${field}`);
}

export function validatePluginDefinition(plugin: PluginDefinition): void {
  if (!plugin || typeof plugin !== "object") throw new Error("plugin_manifest_invalid:definition");
  const manifest = plugin.manifest;
  if (!manifest || typeof manifest !== "object") throw new Error("plugin_manifest_invalid:manifest");
  assertNonEmptyString(manifest.id, "id");
  if (!/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(manifest.id)) throw new Error("plugin_manifest_invalid:id");
  assertNonEmptyString(manifest.version, "version");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version)) throw new Error("plugin_manifest_invalid:version");
  assertNonEmptyString(manifest.displayName, "displayName");
  assertNonEmptyString(manifest.apiVersion, "apiVersion");
  if (manifest.apiVersion !== PLUGIN_API_VERSION) {
    throw new Error(`plugin_api_incompatible:${manifest.id}:${manifest.apiVersion}:${PLUGIN_API_VERSION}`);
  }
  if (!Array.isArray(manifest.contributes) || new Set(manifest.contributes).size !== manifest.contributes.length) {
    throw new Error("plugin_manifest_invalid:contributes");
  }
  const validContributions = new Set<PluginContributionKind>(["runs", "cli", "web"]);
  if (manifest.contributes.some((item) => !validContributions.has(item))) throw new Error("plugin_manifest_invalid:contributes");
  if (!manifest.contributes.includes("runs")) throw new Error("plugin_manifest_invalid:contributes_runs_required");
  if (typeof plugin.activate !== "function") throw new Error("plugin_manifest_invalid:activate");
  if (manifest.contributes.includes("cli")) {
    if (!plugin.cli?.length) throw new Error("plugin_manifest_invalid:cli_contribution_required");
    const names = plugin.cli.map((command) => command.name);
    if (new Set(names).size !== names.length || plugin.cli.some((command) => !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(command.name) || typeof command.invoke !== "function")) {
      throw new Error("plugin_manifest_invalid:cli");
    }
  }
  if (manifest.contributes.includes("web")) {
    if (!plugin.web?.length) throw new Error("plugin_manifest_invalid:web_contribution_required");
    const ids = plugin.web.map((contribution) => contribution.id);
    if (new Set(ids).size !== ids.length || plugin.web.some((contribution) =>
      !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(contribution.id)
      || typeof contribution.title !== "string" || !contribution.title
      || typeof contribution.entry !== "string" || !contribution.entry
      || typeof contribution.assetsRoot !== "string" || !contribution.assetsRoot
    )) throw new Error("plugin_manifest_invalid:web");
  }
}

export function validatePluginConfig(plugin: PluginDefinition, config: unknown): void {
  if (!plugin.configSchema) return;
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const validate = ajv.compile(plugin.configSchema);
  if (!validate(config)) throw new Error(`plugin_config_invalid:${plugin.manifest.id}:${ajv.errorsText(validate.errors)}`);
}

function validatePluginRuntime(pluginId: string, runtime: PluginRuntime): void {
  const methods: readonly (keyof PluginRuntime)[] = [
    "operation", "createRun", "adoptRun", "getRun", "events", "action", "artifacts", "openArtifact", "dispose",
  ];
  for (const method of methods) {
    if (typeof runtime?.[method] !== "function") throw new Error(`plugin_runtime_invalid:${pluginId}:${method}`);
  }
}

export async function activatePlugin(plugin: PluginDefinition, context: PluginActivationContext): Promise<PluginRuntime> {
  validatePluginDefinition(plugin);
  validatePluginConfig(plugin, context.config);
  const runtime = await plugin.activate(context);
  validatePluginRuntime(plugin.manifest.id, runtime);
  return runtime;
}

export class PluginRegistry {
  readonly #plugins = new Map<string, PluginDefinition>();

  register(plugin: PluginDefinition): this {
    validatePluginDefinition(plugin);
    const id = plugin.manifest.id;
    if (this.#plugins.has(id)) throw new Error(`plugin_already_registered:${id}`);
    this.#plugins.set(id, plugin);
    return this;
  }

  get(id: string): PluginDefinition {
    const plugin = this.#plugins.get(id);
    if (!plugin) throw new Error(`plugin_not_registered:${id}`);
    return plugin;
  }

  list(): PluginDefinition[] {
    return [...this.#plugins.values()].sort((a, b) => a.manifest.id.localeCompare(b.manifest.id));
  }
}

export async function discoverPlugins(modules: readonly string[], cwd = process.cwd()): Promise<PluginRegistry> {
  const registry = new PluginRegistry();
  for (const specifier of modules) {
    const target = specifier.startsWith(".") || isAbsolute(specifier) ? pathToFileURL(resolve(cwd, specifier)).href : specifier;
    const loaded = await import(target) as {
      plugin?: PluginDefinition;
      createPlugin?: () => PluginDefinition | Promise<PluginDefinition>;
    };
    const plugin = loaded.plugin ?? await loaded.createPlugin?.();
    if (!plugin) throw new Error(`plugin_manifest_invalid:${specifier}`);
    registry.register(plugin);
  }
  return registry;
}
