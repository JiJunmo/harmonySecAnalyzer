import {
  PLUGIN_API_VERSION,
  type PluginArtifactContent,
  type PluginArtifactDescriptor,
  type PluginDefinition,
  type PluginEvent,
  type PluginEventOptions,
  type PluginRunAction,
  type PluginRunReference,
  type PluginRunRequest,
  type PluginRunSnapshot,
  type PluginRuntime,
} from "@agent-platform/core";

interface DummyConfig {
  readonly prefix?: string;
}

interface DummyRun {
  snapshot: PluginRunSnapshot;
  readonly payload: unknown;
  readonly events: PluginEvent[];
}

class DummyRuntime implements PluginRuntime {
  readonly #runs = new Map<string, DummyRun>();
  readonly #prefix: string;
  #sequence = 0;
  #disposed = false;

  constructor(config: DummyConfig) {
    this.#prefix = config.prefix ?? "dummy";
  }

  #assertActive(): void {
    if (this.#disposed) throw new Error("dummy_plugin_disposed");
  }

  #get(reference: PluginRunReference): DummyRun {
    this.#assertActive();
    const run = this.#runs.get(reference.id);
    if (!run) throw new Error(`dummy_run_not_found:${reference.id}`);
    return run;
  }

  async operation(operation: { readonly name: string; readonly payload?: unknown }): Promise<unknown> {
    this.#assertActive();
    if (operation.name !== "echo") throw new Error(`dummy_operation_not_supported:${operation.name}`);
    return operation.payload;
  }

  async createRun(request: PluginRunRequest): Promise<PluginRunSnapshot> {
    this.#assertActive();
    const id = `${this.#prefix}-${++this.#sequence}`;
    const timestamp = new Date().toISOString();
    const reference = Object.freeze({ id });
    const snapshot: PluginRunSnapshot = Object.freeze({
      run: reference,
      status: "running",
      createdAt: timestamp,
      updatedAt: timestamp,
      progress: Object.freeze({ completed: 0, total: 1 }),
      details: request.payload,
    });
    const event: PluginEvent = Object.freeze({
      id: `${id}:1`,
      run: reference,
      type: "run.created",
      timestamp,
      payload: request.payload,
    });
    this.#runs.set(id, { snapshot, payload: request.payload, events: [event] });
    return snapshot;
  }

  async adoptRun(run: PluginRunReference): Promise<PluginRunSnapshot> {
    return this.#get(run).snapshot;
  }

  async getRun(run: PluginRunReference): Promise<PluginRunSnapshot> {
    return this.#get(run).snapshot;
  }

  async *events(run: PluginRunReference, options: PluginEventOptions = {}): AsyncIterable<PluginEvent> {
    const events = this.#get(run).events;
    const start = options.after ? events.findIndex((event) => event.id === options.after) + 1 : 0;
    for (const event of events.slice(Math.max(0, start))) {
      if (options.signal?.aborted) return;
      yield event;
    }
  }

  async action(reference: PluginRunReference, action: PluginRunAction): Promise<PluginRunSnapshot> {
    const run = this.#get(reference);
    const status = action.name === "complete" ? "succeeded"
      : action.name === "cancel" ? "cancelled"
        : action.name === "resume" ? "running"
          : undefined;
    if (!status) throw new Error(`dummy_action_not_supported:${action.name}`);
    const timestamp = new Date().toISOString();
    run.snapshot = Object.freeze({
      ...run.snapshot,
      status,
      updatedAt: timestamp,
      progress: Object.freeze({ completed: status === "succeeded" ? 1 : 0, total: 1 }),
    });
    run.events.push(Object.freeze({
      id: `${reference.id}:${run.events.length + 1}`,
      run: reference,
      type: `run.${status}`,
      timestamp,
      payload: action.payload,
    }));
    return run.snapshot;
  }

  async artifacts(run: PluginRunReference): Promise<readonly PluginArtifactDescriptor[]> {
    const value = this.#get(run);
    const body = this.#artifactBody(value);
    return [Object.freeze({ id: "result", name: "result.json", mediaType: "application/json", size: body.byteLength })];
  }

  async openArtifact(run: PluginRunReference, artifactId: string): Promise<PluginArtifactContent> {
    if (artifactId !== "result") throw new Error(`dummy_artifact_not_found:${artifactId}`);
    const value = this.#get(run);
    const body = this.#artifactBody(value);
    return {
      descriptor: Object.freeze({ id: "result", name: "result.json", mediaType: "application/json", size: body.byteLength }),
      body,
    };
  }

  #artifactBody(run: DummyRun): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({ prefix: this.#prefix, payload: run.payload, status: run.snapshot.status }));
  }

  async dispose(): Promise<void> {
    this.#disposed = true;
    this.#runs.clear();
  }
}

export const plugin: PluginDefinition = {
  manifest: Object.freeze({
    apiVersion: PLUGIN_API_VERSION,
    id: "dummy",
    version: "1.0.0",
    displayName: "Dummy Plugin",
    description: "Domain-neutral contract and host verification plugin",
    contributes: Object.freeze(["runs"] as const),
  }),
  configSchema: {
    type: "object",
    properties: { prefix: { type: "string", minLength: 1 } },
    additionalProperties: false,
  },
  defaultConfig: Object.freeze({ prefix: "dummy" }),
  activate(context) {
    return new DummyRuntime(context.config as DummyConfig);
  },
};

export const createPlugin = (): PluginDefinition => plugin;
