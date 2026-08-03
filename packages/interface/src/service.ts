import { randomUUID } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import {
  PluginRegistry,
  activatePlugin,
  type PluginArtifactContent,
  type PluginArtifactDescriptor,
  type PluginDefinition,
  type PluginEvent,
  type PluginEventOptions,
  type PluginExecutionDetail,
  type PluginExecutionUnit,
  type PluginLogger,
  type PluginManifest,
  type PluginOperation,
  type PluginRunAction,
  type PluginRunReference,
  type PluginRunSnapshot,
  type PluginRunStatus,
  type PluginRuntime,
  type PluginSubject,
} from "@agent-platform/core";

export interface PluginHostOptions {
  readonly plugins: readonly PluginDefinition[];
  readonly configs?: Readonly<Record<string, unknown>>;
  readonly sharedConfig?: Readonly<Record<string, unknown>>;
  readonly logger?: PluginLogger;
  readonly runRepository?: HostRunRepository;
}

export interface HostRunRepository {
  load(): readonly HostRunView[];
  save(run: HostRunView): void;
}

export interface HostRunError {
  readonly code: string;
  readonly message: string;
}

export interface HostRunView {
  readonly id: string;
  readonly pluginId: string;
  readonly pluginRun?: PluginRunReference;
  readonly status: PluginRunStatus;
  readonly snapshot?: PluginRunSnapshot;
  readonly error?: HostRunError;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface HostRunEvent {
  readonly id: string;
  readonly type: "run_accepted" | "run_initialized" | "run_updated" | "run_failed" | "run_adopted";
  readonly run: HostRunView;
  readonly timestamp: string;
}

export interface HostWebContribution {
  readonly pluginId: string;
  readonly id: string;
  readonly title: string;
  readonly entry: string;
}

export interface HostWebAsset {
  readonly name: string;
  readonly body: Uint8Array;
}

interface MutableHostRun {
  id: string;
  pluginId: string;
  status: PluginRunStatus;
  pluginRun?: PluginRunReference | undefined;
  snapshot?: PluginRunSnapshot | undefined;
  error?: HostRunError | undefined;
  createdAt: string;
  updatedAt: string;
  initialization?: Promise<void> | undefined;
}

const noopLogger: PluginLogger = Object.freeze({
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
});

const message = (error: unknown) => error instanceof Error ? error.message : String(error);

export class PluginHostService {
  readonly #registry: PluginRegistry;
  readonly #runtimes: ReadonlyMap<string, PluginRuntime>;
  readonly #runs = new Map<string, MutableHostRun>();
  readonly #listeners = new Set<(event: HostRunEvent) => void>();
  readonly #abortController: AbortController;
  #disposed = false;

  readonly #repository: HostRunRepository | undefined;

  private constructor(registry: PluginRegistry, runtimes: ReadonlyMap<string, PluginRuntime>, abortController: AbortController, repository?: HostRunRepository) {
    this.#registry = registry;
    this.#runtimes = runtimes;
    this.#abortController = abortController;
    this.#repository = repository;
  }

  static async create(options: PluginHostOptions): Promise<PluginHostService> {
    const registry = new PluginRegistry();
    for (const plugin of options.plugins) registry.register(plugin);
    const abortController = new AbortController();
    const runtimes = new Map<string, PluginRuntime>();
    try {
      for (const plugin of registry.list()) {
        const id = plugin.manifest.id;
        const configured = options.configs && Object.prototype.hasOwnProperty.call(options.configs, id)
          ? options.configs[id]
          : plugin.defaultConfig ?? {};
        const runtime = await activatePlugin(plugin, {
          config: configured,
          ...(options.sharedConfig ? { sharedConfig: options.sharedConfig } : {}),
          signal: abortController.signal,
          logger: options.logger ?? noopLogger,
        });
        runtimes.set(id, runtime);
      }
    } catch (error) {
      abortController.abort();
      await Promise.allSettled([...runtimes.values()].map((runtime) => runtime.dispose()));
      throw error;
    }
    const service = new PluginHostService(registry, runtimes, abortController, options.runRepository);
    const repository = options.runRepository;
    for (const saved of repository?.load() ?? []) {
      if (!runtimes.has(saved.pluginId)) continue;
      const interruptedInitialization = !saved.pluginRun && ["accepted", "preparing", "running"].includes(saved.status);
      const restored: MutableHostRun = {
        id: saved.id, pluginId: saved.pluginId, status: interruptedInitialization ? "failed" : saved.status,
        ...(saved.pluginRun ? { pluginRun: saved.pluginRun } : {}), ...(saved.snapshot ? { snapshot: saved.snapshot } : {}),
        ...(interruptedInitialization ? { error: { code: "gateway_restarted", message: "网关重启前插件任务尚未完成初始化" } } : saved.error ? { error: saved.error } : {}),
        createdAt: saved.createdAt, updatedAt: interruptedInitialization ? new Date().toISOString() : saved.updatedAt,
      };
      service.#runs.set(saved.id, restored);
      repository?.save(service.#view(restored));
    }
    for (const [pluginId, runtime] of runtimes) {
      if (!runtime.discoverRuns) continue;
      try {
        for (const reference of await runtime.discoverRuns()) await service.adoptRun(pluginId, reference);
      } catch (error) {
        (options.logger ?? noopLogger).warn("plugin run discovery failed", { pluginId, error: message(error) });
      }
    }
    return service;
  }

  listPlugins(): readonly PluginManifest[] {
    this.#assertActive();
    return Object.freeze(this.#registry.list().map((plugin) => plugin.manifest));
  }

  listWebContributions(): readonly HostWebContribution[] {
    this.#assertActive();
    return Object.freeze(this.#registry.list().flatMap((plugin) => (plugin.web ?? []).map((contribution) => Object.freeze({
      pluginId: plugin.manifest.id,
      id: contribution.id,
      title: contribution.title,
      entry: contribution.entry,
    }))));
  }

  async openWebAsset(pluginId: string, contributionId: string, assetPath: string): Promise<HostWebAsset> {
    this.#assertActive();
    const plugin = this.#registry.get(pluginId);
    const contribution = plugin.web?.find((candidate) => candidate.id === contributionId);
    if (!contribution) throw new Error(`web_contribution_not_found:${pluginId}:${contributionId}`);
    this.#assertWebAssetPath(assetPath);
    const root = await realpath(resolve(contribution.assetsRoot));
    const target = await realpath(resolve(root, assetPath)).catch(() => {
      throw new Error(`web_asset_not_found:${pluginId}:${contributionId}:${assetPath}`);
    });
    const child = relative(root, target);
    if (child === "" || child.startsWith("..") || isAbsolute(child)) throw new Error("web_asset_path_invalid");
    const metadata = await stat(target);
    if (!metadata.isFile()) throw new Error(`web_asset_not_found:${pluginId}:${contributionId}:${assetPath}`);
    return Object.freeze({ name: assetPath, body: new Uint8Array(await readFile(target)) });
  }

  listRuns(): readonly HostRunView[] {
    this.#assertActive();
    return Object.freeze([...this.#runs.values()].map((run) => this.#view(run)).sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  }

  subscribe(listener: (event: HostRunEvent) => void): () => void {
    this.#assertActive();
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  async operation(pluginId: string, operation: PluginOperation): Promise<unknown> {
    this.#assertActive();
    return this.#runtime(pluginId).operation(operation);
  }

  async createRun(pluginId: string, payload: unknown, subject?: PluginSubject): Promise<HostRunView> {
    this.#assertActive();
    const runtime = this.#runtime(pluginId);
    const stamp = new Date().toISOString();
    const run: MutableHostRun = {
      id: `JOB-${randomUUID()}`,
      pluginId,
      status: "accepted",
      createdAt: stamp,
      updatedAt: stamp,
    };
    this.#runs.set(run.id, run);
    this.#emit("run_accepted", run);
    const initialization = runtime.createRun({
      requestId: run.id,
      payload,
      ...(subject ? { subject } : {}),
    }).then((snapshot) => {
      run.pluginRun = snapshot.run;
      run.snapshot = snapshot;
      run.status = snapshot.status;
      run.error = snapshot.error;
      this.#touch(run);
      this.#emit("run_initialized", run);
    }).catch((error: unknown) => {
      run.status = "failed";
      run.error = Object.freeze({ code: "plugin_run_create_failed", message: message(error) });
      this.#touch(run);
      this.#emit("run_failed", run);
    }).finally(() => {
      run.initialization = undefined;
    });
    run.initialization = initialization;
    return this.#view(run);
  }

  async adoptRun(pluginId: string, pluginRun: PluginRunReference): Promise<HostRunView> {
    this.#assertActive();
    const existing = [...this.#runs.values()].find((run) => run.pluginId === pluginId && run.pluginRun?.id === pluginRun.id);
    if (existing) { await this.#refresh(existing); return this.#view(existing); }
    const snapshot = await this.#runtime(pluginId).adoptRun(pluginRun);
    const run: MutableHostRun = {
      id: `JOB-${randomUUID()}`,
      pluginId,
      pluginRun: snapshot.run,
      snapshot,
      status: snapshot.status,
      error: snapshot.error,
      createdAt: snapshot.createdAt,
      updatedAt: snapshot.updatedAt,
    };
    this.#runs.set(run.id, run);
    this.#emit("run_adopted", run);
    return this.#view(run);
  }

  async getRun(id: string): Promise<HostRunView> {
    this.#assertActive();
    const run = this.#required(id);
    if (run.pluginRun) await this.#refresh(run);
    return this.#view(run);
  }

  async action(id: string, action: PluginRunAction): Promise<HostRunView> {
    this.#assertActive();
    const run = this.#required(id);
    await this.#initialized(run);
    if (!run.pluginRun) throw new Error(`host_run_not_initialized:${id}`);
    const snapshot = await this.#runtime(run.pluginId).action(run.pluginRun, action);
    this.#update(run, snapshot);
    this.#emit("run_updated", run);
    return this.#view(run);
  }

  async artifacts(id: string): Promise<readonly PluginArtifactDescriptor[]> {
    const run = this.#required(id);
    await this.#initialized(run);
    if (!run.pluginRun) throw new Error(`host_run_not_initialized:${id}`);
    return this.#runtime(run.pluginId).artifacts(run.pluginRun);
  }

  async openArtifact(id: string, artifactId: string): Promise<PluginArtifactContent> {
    const run = this.#required(id);
    await this.#initialized(run);
    if (!run.pluginRun) throw new Error(`host_run_not_initialized:${id}`);
    return this.#runtime(run.pluginId).openArtifact(run.pluginRun, artifactId);
  }

  async executions(id: string): Promise<readonly PluginExecutionUnit[]> {
    const run = this.#required(id);
    await this.#initialized(run);
    if (!run.pluginRun) throw new Error(`host_run_not_initialized:${id}`);
    const method = this.#runtime(run.pluginId).executions;
    return method ? method.call(this.#runtime(run.pluginId), run.pluginRun) : Object.freeze([]);
  }

  async execution(id: string, executionId: string): Promise<PluginExecutionDetail> {
    const run = this.#required(id);
    await this.#initialized(run);
    if (!run.pluginRun) throw new Error(`host_run_not_initialized:${id}`);
    const method = this.#runtime(run.pluginId).execution;
    if (!method) throw new Error(`plugin_execution_not_supported:${run.pluginId}`);
    return method.call(this.#runtime(run.pluginId), run.pluginRun, executionId);
  }

  async *events(id: string, options?: PluginEventOptions): AsyncIterable<PluginEvent> {
    const run = this.#required(id);
    await this.#initialized(run);
    if (!run.pluginRun) throw new Error(`host_run_not_initialized:${id}`);
    yield* this.#runtime(run.pluginId).events(run.pluginRun, options);
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#abortController.abort();
    this.#listeners.clear();
    await Promise.allSettled([
      ...[...this.#runs.values()].flatMap((run) => run.initialization ? [run.initialization] : []),
      ...[...this.#runtimes.values()].map((runtime) => runtime.dispose()),
    ]);
  }

  #assertActive(): void {
    if (this.#disposed) throw new Error("plugin_host_disposed");
  }

  #assertWebAssetPath(assetPath: string): void {
    if (!assetPath || isAbsolute(assetPath) || assetPath.split(/[\\/]/).some((part) => part === ".." || part === "")) {
      throw new Error("web_asset_path_invalid");
    }
  }

  #runtime(pluginId: string): PluginRuntime {
    const runtime = this.#runtimes.get(pluginId);
    if (!runtime) throw new Error(`plugin_not_registered:${pluginId}`);
    return runtime;
  }

  #required(id: string): MutableHostRun {
    const run = this.#runs.get(id);
    if (!run) throw new Error(`host_run_not_found:${id}`);
    return run;
  }

  async #initialized(run: MutableHostRun): Promise<void> {
    await run.initialization;
    if (run.error && !run.pluginRun) throw new Error(run.error.message);
  }

  async #refresh(run: MutableHostRun): Promise<void> {
    if (!run.pluginRun) return;
    const snapshot = await this.#runtime(run.pluginId).getRun(run.pluginRun);
    this.#update(run, snapshot);
  }

  #update(run: MutableHostRun, snapshot: PluginRunSnapshot): void {
    run.pluginRun = snapshot.run;
    run.snapshot = snapshot;
    run.status = snapshot.status;
    run.error = snapshot.error;
    run.updatedAt = snapshot.updatedAt;
    this.#repository?.save(this.#view(run));
  }

  #touch(run: MutableHostRun): void {
    run.updatedAt = new Date().toISOString();
  }

  #view(run: MutableHostRun): HostRunView {
    return Object.freeze({
      id: run.id,
      pluginId: run.pluginId,
      status: run.status,
      ...(run.pluginRun ? { pluginRun: run.pluginRun } : {}),
      ...(run.snapshot ? { snapshot: run.snapshot } : {}),
      ...(run.error ? { error: run.error } : {}),
      createdAt: run.createdAt,
      updatedAt: run.updatedAt,
    });
  }

  #emit(type: HostRunEvent["type"], run: MutableHostRun): void {
    this.#repository?.save(this.#view(run));
    const event = Object.freeze({
      id: `EVENT-${randomUUID()}`,
      type,
      run: this.#view(run),
      timestamp: new Date().toISOString(),
    });
    for (const listener of this.#listeners) listener(event);
  }
}
