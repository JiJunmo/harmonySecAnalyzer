import type { AgentPoolBackend, ChildExecutionResult, PoolClaim, SubAgentInstance } from "@agent-platform/core";
import type { AuditStore } from "./runtime/store.js";
import type { HarmonyAuditWorker } from "./worker.js";

export class HarmonyPoolBackend implements AgentPoolBackend<Record<string, unknown>, Record<string, unknown>> {
  constructor(readonly store: AuditStore, readonly worker: HarmonyAuditWorker) {}
  claim(_directory: string, limit: number): Promise<PoolClaim> { return this.store.claim(limit); }
  execute(_directory: string, instance: SubAgentInstance): Promise<ChildExecutionResult> { return this.worker.execute(instance); }
  reconcile(_directory: string, instance: SubAgentInstance, result: ChildExecutionResult): Record<string, unknown> {
    return this.store.reconcile(instance.taskId, instance.attempt, this.worker.take(instance.agentId), result.error);
  }
  snapshot(): Record<string, unknown> { return this.store.snapshot(); }
  pendingCounts(snapshot: Record<string, unknown>): { queued: number; running: number } {
    const tasks = snapshot.tasks as Record<string, number> | undefined;
    return { queued: tasks?.queued ?? 0, running: tasks?.running ?? 0 };
  }
}
