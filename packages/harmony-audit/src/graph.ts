import { Annotation, END, START, StateGraph } from "@langchain/langgraph";
import type { SqliteSaver } from "@langchain/langgraph-checkpoint-sqlite";
import { RollingAgentPool, type GraphPlugin } from "@agent-platform/core";
import type { AuditStore } from "./runtime/store.js";
import type { HarmonyPoolBackend } from "./pool-backend.js";
import { HARMONY_DEFAULT_AGENT_CAPACITY, harmonyAgentCapacity } from "./pool-policy.js";

const State = Annotation.Root({
  runDirectory: Annotation<string>,
  runId: Annotation<string>,
  phase: Annotation<string>,
  poolResult: Annotation<Record<string, unknown> | undefined>,
  finalResult: Annotation<Record<string, unknown> | undefined>,
  error: Annotation<string | undefined>,
});

export class HarmonyAuditGraphPlugin implements GraphPlugin<Record<string, unknown>, Record<string, unknown>> {
  readonly name = "harmony-audit";
  readonly checkpointFilename = "graph.db";
  readonly capacity: number;
  constructor(readonly store: AuditStore, readonly backend: HarmonyPoolBackend, capacity = HARMONY_DEFAULT_AGENT_CAPACITY) {
    this.capacity = harmonyAgentCapacity(capacity);
  }
  threadId(): string { return this.store.graphThreadId(); }
  initialInput(runDirectory: string): Record<string, unknown> { return { runDirectory, runId: this.store.runId(), phase: "created" }; }
  invocationConfig(): Readonly<Record<string, unknown>> { return { recursionLimit: 20 }; }
  build(options: { checkpointer: SqliteSaver; interruptBefore: readonly string[] }) {
    const graph = new StateGraph(State)
      .addNode("load", async () => ({ phase: "loaded" }))
      .addNode("pool", async (state) => {
        try {
          const result = await new RollingAgentPool(this.backend, this.capacity).run(state.runDirectory, state.runId);
          return { phase: "pool_drained", poolResult: result as unknown as Record<string, unknown> };
        } catch (error) { return { phase: "failed", error: error instanceof Error ? error.message : String(error) }; }
      })
      .addNode("finalize", async () => {
        try {
          const finalResult = await this.store.finalize();
          return { phase: String((finalResult.run as Record<string, unknown>).status), finalResult };
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error); this.store.markFailed(message);
          return { phase: "failed", error: message };
        }
      })
      .addNode("fail", async (state) => {
        const error = state.error ?? "graph_failed"; this.store.markFailed(error);
        return { phase: "failed", error };
      })
      .addEdge(START, "load")
      .addEdge("load", "pool")
      .addConditionalEdges("pool", (state) => state.error ? "fail" : "finalize", { fail: "fail", finalize: "finalize" })
      .addEdge("finalize", END)
      .addEdge("fail", END);
    return graph.compile({ checkpointer: options.checkpointer, interruptBefore: [...options.interruptBefore] as never, name: "harmony-security-audit" });
  }
}
