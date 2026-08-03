import { describe, expect, it } from "vitest";
import { RollingAgentPool, type AgentPoolBackend, type ChildExecutionResult, type PoolTaskHandle, type SubAgentInstance } from "../src/index.js";

describe("RollingAgentPool", () => {
  it("keeps the configured slots full and refills before slow children finish", async () => {
    const queue: PoolTaskHandle[] = Array.from({ length: 12 }, (_, index) => ({ task_id: `t${index}`, kind: "test", attempt: 1 }));
    let running = 0;
    let maximum = 0;
    const startTimes: number[] = [];
    const backend: AgentPoolBackend<{ queued: number; running: number }, string> = {
      claim(_directory, limit) { return { ok: true, reason: "claimed", tasks: queue.splice(0, limit) }; },
      async execute(_directory, instance): Promise<ChildExecutionResult> {
        running += 1; maximum = Math.max(maximum, running); startTimes.push(Date.now());
        await new Promise((resolve) => setTimeout(resolve, instance.taskId === "t0" ? 80 : 5));
        running -= 1;
        return { instance, status: "completed" };
      },
      reconcile(_directory, instance) { return instance.taskId; },
      snapshot() { return { queued: queue.length, running }; },
      pendingCounts(snapshot) { return snapshot; },
    };
    const result = await new RollingAgentPool(backend, 3).run("/run", "r1");
    expect(result.tasksStarted).toBe(12);
    expect(result.tasksFinished).toBe(12);
    expect(result.maxActive).toBe(3);
    expect(maximum).toBe(3);
    expect(result.refillCount).toBeGreaterThan(0);
    expect(startTimes[3]! - startTimes[0]!).toBeLessThan(70);
  });

  it("accepts domain-supplied capacities and only rejects non-positive integers", () => {
    expect(new RollingAgentPool({} as AgentPoolBackend, 32).capacity).toBe(32);
    expect(() => new RollingAgentPool({} as AgentPoolBackend, 0)).toThrow("pool_capacity_must_be_positive_integer");
    expect(() => new RollingAgentPool({} as AgentPoolBackend, 1.5)).toThrow("pool_capacity_must_be_positive_integer");
  });
});
