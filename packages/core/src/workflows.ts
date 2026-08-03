import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { SqliteSaver } from "@langchain/langgraph-checkpoint-sqlite";

export interface InvokableGraph<TInput, TOutput> {
  invoke(input: TInput, config: Readonly<Record<string, unknown>>): Promise<TOutput>;
}

export interface GraphPlugin<TInput = unknown, TOutput = unknown> {
  readonly name: string;
  readonly checkpointFilename: string;
  threadId(runDirectory: string): string;
  initialInput(runDirectory: string): TInput;
  invocationConfig(runDirectory: string): Readonly<Record<string, unknown>>;
  build(options: { checkpointer: SqliteSaver; interruptBefore: readonly string[] }): InvokableGraph<TInput, TOutput>;
}

export class GraphRegistry {
  readonly #plugins = new Map<string, GraphPlugin>();
  register(plugin: GraphPlugin): this {
    if (this.#plugins.has(plugin.name)) throw new Error(`graph_already_registered:${plugin.name}`);
    this.#plugins.set(plugin.name, plugin);
    return this;
  }
  get(name: string): GraphPlugin {
    const plugin = this.#plugins.get(name);
    if (!plugin) throw new Error(`graph_not_registered:${name}`);
    return plugin;
  }
  names(): string[] { return [...this.#plugins.keys()]; }
}

export class GraphApplication {
  constructor(readonly registry: GraphRegistry) {}
  async run(name: string, runDirectory: string, interruptBefore: readonly string[] = []): Promise<unknown> {
    const plugin = this.registry.get(name);
    const checkpointPath = join(runDirectory, plugin.checkpointFilename);
    await mkdir(dirname(checkpointPath), { recursive: true });
    const checkpointer = SqliteSaver.fromConnString(checkpointPath);
    const graph = plugin.build({ checkpointer, interruptBefore });
    const config = {
      ...plugin.invocationConfig(runDirectory),
      configurable: { thread_id: plugin.threadId(runDirectory) },
    };
    return graph.invoke(plugin.initialInput(runDirectory), config);
  }
}
