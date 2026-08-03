export interface PoolTaskHandle {
  readonly task_id: string;
  readonly kind: string;
  readonly attempt: number;
  readonly [key: string]: unknown;
}

export interface PoolClaim { readonly ok: boolean; readonly reason: string; readonly tasks: readonly PoolTaskHandle[]; }

export interface SubAgentInstance {
  readonly agentId: string;
  readonly taskId: string;
  readonly kind: string;
  readonly attempt: number;
  readonly handle: PoolTaskHandle;
}

export interface ChildExecutionResult {
  readonly instance: SubAgentInstance;
  readonly status: "completed" | "reused" | "failed";
  readonly error?: string;
}

export interface AgentPoolBackend<TSnapshot = unknown, TReconcile = unknown> {
  claim(runDirectory: string, limit: number): Promise<PoolClaim> | PoolClaim;
  execute(runDirectory: string, instance: SubAgentInstance): Promise<ChildExecutionResult>;
  reconcile(runDirectory: string, instance: SubAgentInstance, result: ChildExecutionResult): Promise<TReconcile> | TReconcile;
  snapshot(runDirectory: string): Promise<TSnapshot> | TSnapshot;
  pendingCounts(snapshot: TSnapshot): { queued: number; running: number };
}

export interface PoolRunResult<TReconcile = unknown> {
  readonly dispatchRecords: readonly Record<string, unknown>[];
  readonly reconciliationRecords: readonly { agentId: string; taskId: string; attempt: number; outcome: TReconcile }[];
  readonly tasksStarted: number;
  readonly tasksFinished: number;
  readonly refillCount: number;
  readonly maxActive: number;
}

function instanceFrom(runId: string, handle: PoolTaskHandle): SubAgentInstance {
  return {
    agentId: `${runId}:${handle.task_id}:${handle.attempt}`,
    taskId: handle.task_id,
    kind: handle.kind,
    attempt: handle.attempt,
    handle,
  };
}

function failure(instance: SubAgentInstance, error: unknown): ChildExecutionResult {
  return { instance, status: "failed", error: error instanceof Error ? `${error.name}:${error.message}` : String(error) };
}

export class RollingAgentPool<TSnapshot = unknown, TReconcile = unknown> {
  constructor(readonly backend: AgentPoolBackend<TSnapshot, TReconcile>, readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1) throw new Error("pool_capacity_must_be_positive_integer");
  }

  async run(runDirectory: string, runId: string): Promise<PoolRunResult<TReconcile>> {
    const active = new Map<string, Promise<ChildExecutionResult>>();
    const dispatchRecords: Record<string, unknown>[] = [];
    const reconciliationRecords: { agentId: string; taskId: string; attempt: number; outcome: TReconcile }[] = [];
    let tasksStarted = 0;
    let tasksFinished = 0;
    let refillCount = 0;
    let maxActive = 0;

    while (true) {
      const free = this.capacity - active.size;
      if (free > 0) {
        const claim = await this.backend.claim(runDirectory, free);
        if (!claim.ok) throw new Error(`pool_claim_failed:${claim.reason}`);
        if (claim.tasks.length > free) throw new Error(`pool_claim_exceeded_limit:${claim.tasks.length}:${free}`);
        if (claim.tasks.length > 0 && tasksStarted > 0) refillCount += 1;
        for (const handle of claim.tasks) {
          const instance = instanceFrom(runId, handle);
          const task = this.backend.execute(runDirectory, instance).catch((error: unknown) => failure(instance, error));
          active.set(instance.agentId, task);
          tasksStarted += 1;
        }
        maxActive = Math.max(maxActive, active.size);
      }

      if (active.size === 0) {
        const counts = this.backend.pendingCounts(await this.backend.snapshot(runDirectory));
        if (counts.queued === 0 && counts.running === 0) break;
        throw new Error(`pool_stalled:queued=${counts.queued}:running=${counts.running}`);
      }

      const settled = await Promise.race([...active.entries()].map(async ([id, task]) => ({ id, result: await task })));
      active.delete(settled.id);
      const { instance } = settled.result;
      dispatchRecords.push({
        agent_id: instance.agentId, task_id: instance.taskId, kind: instance.kind,
        attempt: instance.attempt, status: settled.result.status,
        ...(settled.result.error ? { error: settled.result.error } : {}),
      });
      const outcome = await this.backend.reconcile(runDirectory, instance, settled.result);
      reconciliationRecords.push({ agentId: instance.agentId, taskId: instance.taskId, attempt: instance.attempt, outcome });
      tasksFinished += 1;
    }

    return { dispatchRecords, reconciliationRecords, tasksStarted, tasksFinished, refillCount, maxActive };
  }
}
