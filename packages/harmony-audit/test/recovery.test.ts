import Database from "better-sqlite3";
import { access, mkdir, mkdtemp, readFile, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { profileProject } from "../src/project/profiler.js";
import { AuditStore } from "../src/runtime/store.js";

async function fixture(): Promise<AuditStore> {
  const root = await mkdtemp(join(tmpdir(), "harmony-recovery-")); await mkdir(join(root, "entry/src/main"), { recursive: true });
  await writeFile(join(root, "entry/src/main/module.json5"), `{module:{name:'entry',abilities:[{name:'A',exported:true}]}}`);
  return AuditStore.create(root, await profileProject(root), { components: ["A"] });
}

const semantic = (task: Record<string, any>) => ({ task_id: task.task_id, entry_id: task.input.entry.candidate_id, summary: "checked", coverage: { entry_status: "confirmed", entry_notes: [], entry_symbols_checked: ["A.onCreate"], operation_sites_checked: [], unresolved_targets: [] }, operation_groups: [], component_calls: [] });

describe("run recovery lifecycle", () => {
  it("recovers an expired lease and rejects the stale execution", async () => {
    const store = await fixture(); const [stale] = (await store.claim(1, "crashed-worker", -1)).tasks;
    expect(store.recoverExpiredTasks()).toBe(1);
    expect(store.reconcile(stale!.task_id, stale!.attempt, semantic(stale as Record<string, any>))).toMatchObject({ accepted: false, ignored: true, error_code: "TASK_NOT_RUNNING" });
    // A reclaimed lease backs off briefly before the pool may claim it again.
    const db = new Database(store.paths.db);
    db.prepare("UPDATE tasks SET retry_after=NULL WHERE task_id=?").run(stale!.task_id);
    db.close();
    const [reclaimed] = (await store.claim(1, "replacement-worker")).tasks;
    expect(reclaimed).toMatchObject({ task_id: stale!.task_id, attempt: 2 });
  });

  it("resumes failed work by reclaiming running tasks", async () => {
    const store = await fixture(); await store.claim(1, "dead-process"); store.markFailed("process_crashed");
    const recovery = store.resume(); expect(recovery).toMatchObject({ previous_status: "failed", status: "running", reclaimed_tasks: 1 });
    const [task] = (await store.claim(1)).tasks; expect(store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>))).toMatchObject({ accepted: true });
    expect((await store.finalize()).run).toMatchObject({ status: "complete" });
  });

  it("removes pre-atomic-reconcile partial facts before retrying a failed run", async () => {
    const store = await fixture(); const [task] = (await store.claim(1, "old-runtime")).tasks;
    const db = new (await import("better-sqlite3")).default(store.paths.db);
    db.prepare("INSERT INTO semantic_analyses VALUES (?,?,?,?,?,?,?)").run("SEM-partial", task!.task_id, task!.input.entry.candidate_id, 1, "partial", JSON.stringify({ entry_status: "confirmed" }), new Date().toISOString());
    db.close();
    store.markFailed("old_partial_commit");
    expect(store.resume()).toMatchObject({ status: "running", reclaimed_tasks: 1 });
    const repaired = new (await import("better-sqlite3")).default(store.paths.db);
    expect((repaired.prepare("SELECT COUNT(*) n FROM semantic_analyses WHERE task_id=?").get(task!.task_id) as { n: number }).n).toBe(0);
    repaired.close();
  });

  it("cancels queued work and prevents resume", async () => {
    const store = await fixture(); expect(store.cancel()).toMatchObject({ status: "cancelled", cancelled_tasks: 1 });
    expect((store.status().run as Record<string, unknown>).status).toBe("cancelled");
    expect(() => store.resume()).toThrow("ILLEGAL_STATE_TRANSITION");
  });

  it("rebuilds reports from run.db when graph.db is absent", async () => {
    const store = await fixture(); const [task] = (await store.claim(1)).tasks; store.reconcile(task!.task_id, task!.attempt, semantic(task as Record<string, any>)); await store.finalize();
    await unlink(join(store.runDirectory, "graph.db")).catch(() => undefined); const before = await readFile(store.paths.reportJson, "utf8");
    await store.rebuildReport(); expect(await readFile(store.paths.reportJson, "utf8")).toBe(before); await access(store.paths.attackMatrixJson);
  });
});
