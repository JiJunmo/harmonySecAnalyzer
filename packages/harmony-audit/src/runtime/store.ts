import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type {
  AgentTraceEvent,
  PluginExecutionAttempt,
  PluginExecutionDetail,
  PluginExecutionStatus,
  PluginExecutionTraceEvent,
  PluginExecutionUnit,
  PoolClaim,
  PoolTaskHandle,
} from "@agent-platform/core";
import { buildCrossComponentGroup, extendPath, seedPath, type ComponentPath } from "../correlation/engine.js";
import { listCapabilities } from "../capabilities.js";
import {
  attachIncrementalReport,
  incrementalRunFiles,
  persistIncrementalPlan,
  saveIncrementalBaseline,
  validationGroupFingerprint,
  type IncrementalPlan,
} from "../incremental.js";
import { HARMONY_MAX_AGENT_CAPACITY } from "../pool-policy.js";
import { attackMatrixDocument, buildReportModel, collectCoverageGaps, pendingValidationGroupCount } from "../reporting/report-builder.js";
import { renderHtml, renderMarkdown } from "../reporting/renderers.js";
import type { ProjectModel } from "../project/profiler.js";
import { AuditInvariantError } from "../validation/invariant-errors.js";
import { validateSubmissionSchema } from "../validation/schema-validator.js";
import { validateExploitabilitySubmission, validatePocSubmission, validateSemanticSubmission } from "../validation/submission-validator.js";
import { normalizePocSubmission, normalizeSemanticSubmission, normalizeValidationSubmission } from "../validation/submission-normalizer.js";
import { canonicalJson, contentHash, stableId } from "./identity.js";
import { pocTaskInput, semanticTaskInput, validationTaskInput } from "./task-context.js";

const now = () => new Date().toISOString();
/** Task-level retry backoff: a rejected task becomes claimable after attempt * this delay. */
const RETRY_BACKOFF_MS = 30_000;
/** Lease-expired tasks are reclaimed after a short delay so an unavailable model does not churn. */
const LEASE_RECLAIM_BACKOFF_MS = 10_000;
const rows = (value: unknown): Record<string, unknown>[] => Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => !!item && typeof item === "object") : [];
const refs = (value: Record<string, unknown>): string[] => Array.isArray(value.evidence_refs) ? value.evidence_refs.filter((item): item is string => typeof item === "string") : [];
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const executionStatus = (status: string): PluginExecutionStatus => ({
  queued: "queued", running: "running", completed: "succeeded", exhausted: "failed", cancelled: "cancelled",
}[status] as PluginExecutionStatus | undefined) ?? "failed";
const executionTitle = (kind: string): string => kind === "component_semantic_analysis" ? "路径发现" : kind === "exploitability_validation" ? "六维验证" : "PoC 生成";

const schema = `
PRAGMA foreign_keys=ON;
CREATE TABLE schema_meta(version INTEGER PRIMARY KEY CHECK(version=4),contract_version TEXT NOT NULL,migrated_at TEXT NOT NULL);
CREATE TABLE runs(run_id TEXT PRIMARY KEY,target_repo TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('created','running','complete','complete_with_gaps','failed','cancelled')),error TEXT,project_model_version TEXT NOT NULL,audit_scope_json TEXT NOT NULL,resume_generation INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,finalized_at TEXT);
CREATE TABLE tasks(task_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),semantic_key TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('component_semantic_analysis','exploitability_validation','poc_generation')),subject_id TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('queued','running','completed','exhausted','cancelled')),attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),input_json TEXT NOT NULL,result_json TEXT,error TEXT,retry_after TEXT,claimed_at TEXT,lease_expires_at TEXT,worker_id TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(run_id,semantic_key));
CREATE TABLE analysis_units(component_id TEXT PRIMARY KEY,entry_id TEXT NOT NULL,input_json TEXT NOT NULL);
CREATE TABLE entries(entry_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),component_id TEXT NOT NULL,candidate_key TEXT NOT NULL,payload_json TEXT NOT NULL,UNIQUE(run_id,candidate_key));
CREATE TABLE entry_facets(facet_id TEXT PRIMARY KEY,entry_id TEXT NOT NULL REFERENCES entries(entry_id),facet_type TEXT NOT NULL,payload_sha256 TEXT NOT NULL,payload_json TEXT NOT NULL,UNIQUE(entry_id,facet_type,payload_sha256));
CREATE TABLE semantic_analyses(semantic_analysis_id TEXT PRIMARY KEY,task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),entry_id TEXT NOT NULL REFERENCES entries(entry_id),accepted_attempt INTEGER NOT NULL,summary TEXT NOT NULL,coverage_json TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE evidence(evidence_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),producer_task_id TEXT NOT NULL REFERENCES tasks(task_id),local_evidence_id TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,location TEXT,content_sha256 TEXT NOT NULL,payload_json TEXT NOT NULL,UNIQUE(producer_task_id,local_evidence_id));
CREATE TABLE component_calls(component_call_id TEXT PRIMARY KEY,semantic_analysis_id TEXT NOT NULL REFERENCES semantic_analyses(semantic_analysis_id),call_key TEXT NOT NULL,target_component_id TEXT NOT NULL,payload_json TEXT NOT NULL,UNIQUE(semantic_analysis_id,call_key));
CREATE TABLE call_parameters(component_call_id TEXT NOT NULL REFERENCES component_calls(component_call_id),ordinal INTEGER NOT NULL,source_property TEXT NOT NULL,target_property TEXT NOT NULL,control_state TEXT NOT NULL CHECK(control_state IN ('preserved','constrained','constant','unknown')),transform TEXT NOT NULL,PRIMARY KEY(component_call_id,ordinal));
CREATE TABLE component_paths(path_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),root_entry_id TEXT NOT NULL REFERENCES entries(entry_id),target_entry_id TEXT NOT NULL REFERENCES entries(entry_id),fingerprint TEXT NOT NULL,cycle INTEGER NOT NULL CHECK(cycle IN (0,1)),payload_json TEXT NOT NULL,UNIQUE(run_id,fingerprint));
CREATE TABLE operation_groups(group_id TEXT PRIMARY KEY,semantic_analysis_id TEXT NOT NULL REFERENCES semantic_analyses(semantic_analysis_id),group_key TEXT NOT NULL,capability_id TEXT NOT NULL,category TEXT NOT NULL,title TEXT NOT NULL,payload_json TEXT NOT NULL,UNIQUE(semantic_analysis_id,group_key));
CREATE TABLE cross_component_groups(group_id TEXT PRIMARY KEY REFERENCES operation_groups(group_id),path_id TEXT NOT NULL REFERENCES component_paths(path_id),local_group_id TEXT NOT NULL REFERENCES operation_groups(group_id),UNIQUE(path_id,local_group_id));
CREATE TABLE group_facts(group_id TEXT NOT NULL REFERENCES operation_groups(group_id),fact_key TEXT NOT NULL,type TEXT NOT NULL,body TEXT NOT NULL,location TEXT,payload_json TEXT NOT NULL,PRIMARY KEY(group_id,fact_key));
CREATE TABLE group_edges(group_id TEXT NOT NULL,from_fact_key TEXT NOT NULL,to_fact_key TEXT NOT NULL,kind TEXT NOT NULL,payload_json TEXT NOT NULL,PRIMARY KEY(group_id,from_fact_key,to_fact_key,kind),FOREIGN KEY(group_id,from_fact_key) REFERENCES group_facts(group_id,fact_key),FOREIGN KEY(group_id,to_fact_key) REFERENCES group_facts(group_id,fact_key));
CREATE TABLE security_checks(security_check_id TEXT PRIMARY KEY,group_id TEXT REFERENCES operation_groups(group_id),component_call_id TEXT REFERENCES component_calls(component_call_id),subject_kind TEXT NOT NULL,validated_property TEXT NOT NULL,payload_json TEXT NOT NULL,CHECK((group_id IS NULL)!=(component_call_id IS NULL)));
CREATE TABLE validation_results(validation_id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(task_id),group_id TEXT NOT NULL UNIQUE REFERENCES operation_groups(group_id),classification TEXT NOT NULL,capability_id TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE validation_counter_evidence(counter_evidence_id TEXT PRIMARY KEY,validation_id TEXT NOT NULL REFERENCES validation_results(validation_id),kind TEXT NOT NULL,reason TEXT NOT NULL,payload_json TEXT NOT NULL);
CREATE TABLE findings(finding_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),root_cause_key TEXT NOT NULL,title TEXT NOT NULL,classification TEXT NOT NULL,severity TEXT NOT NULL,cwe TEXT NOT NULL,impact TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(run_id,root_cause_key));
CREATE TABLE poc_artifacts(poc_id TEXT PRIMARY KEY,run_id TEXT NOT NULL REFERENCES runs(run_id),finding_id TEXT NOT NULL UNIQUE REFERENCES findings(finding_id),producer_task_id TEXT NOT NULL REFERENCES tasks(task_id),entry_type TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE finding_causes(finding_id TEXT NOT NULL REFERENCES findings(finding_id),validation_id TEXT NOT NULL UNIQUE REFERENCES validation_results(validation_id),PRIMARY KEY(finding_id,validation_id));
CREATE TABLE evidence_refs(owner_type TEXT NOT NULL,owner_id TEXT NOT NULL,evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),PRIMARY KEY(owner_type,owner_id,evidence_id));
CREATE TABLE events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,run_id TEXT NOT NULL REFERENCES runs(run_id),event_type TEXT NOT NULL,subject_id TEXT,payload_json TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE INDEX idx_tasks_status ON tasks(run_id,status,created_at);
`;

export interface RunPaths { root: string; db: string; tasks: string; reportJson: string; reportMarkdown: string; reportHtml: string; attackMatrixJson: string; incremental: ReturnType<typeof incrementalRunFiles>; }
export interface AuditScope { readonly mode?: "full" | "capability" | "incremental"; readonly capabilities?: readonly string[]; readonly components?: readonly string[]; }
interface PocFindingRow {
  finding_id: string; classification: string; finding_payload: string;
}
export interface AuditStoredEvent {
  readonly event_id: number;
  readonly event_type: string;
  readonly subject_id: string | null;
  readonly payload: unknown;
  readonly created_at: string;
}
export const runPaths = (root: string): RunPaths => ({ root: resolve(root), db: resolve(root, "run.db"), tasks: resolve(root, "tasks"), reportJson: resolve(root, "report.json"), reportMarkdown: resolve(root, "report.md"), reportHtml: resolve(root, "report.html"), attackMatrixJson: resolve(root, "attack-matrix.json"), incremental: incrementalRunFiles(root) });

export class AuditStore {
  constructor(readonly runDirectory: string) {}
  get paths(): RunPaths { return runPaths(this.runDirectory); }
  open(): Database.Database {
    const db = new Database(this.paths.db); db.pragma("foreign_keys = ON"); db.pragma("journal_mode = WAL"); db.pragma("busy_timeout = 30000");
    const version = (db.prepare("SELECT version FROM schema_meta").get() as { version: number } | undefined)?.version;
    if (version !== 4) { db.close(); throw new AuditInvariantError("UNSUPPORTED_SCHEMA_VERSION", { version }); }
    return db;
  }

  static async create(target: string, model: ProjectModel, scope: AuditScope = {}, incrementalPlan?: IncrementalPlan): Promise<AuditStore> {
    const mode = scope.mode ?? "full";
    const capabilityRows = await listCapabilities();
    const enabledCapabilities = capabilityRows.filter((item) => item.status === "enabled").map((item) => item.capability_id);
    const runScope: AuditScope = !scope.capabilities?.length ? { ...scope, capabilities: enabledCapabilities } : scope;
    if (mode === "incremental" && !incrementalPlan) throw new Error("incremental_plan_required");
    if (mode !== "incremental" && incrementalPlan) throw new Error("incremental_plan_unexpected");
    if (mode === "incremental" && (runScope.components?.length || runScope.capabilities?.length !== enabledCapabilities.length || enabledCapabilities.some((id) => !runScope.capabilities?.includes(id)))) throw new Error("incremental_mode_cannot_filter_scope");
    const runId = `${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
    const root = resolve(target, "reports", `harmony-audit-${runId}`);
    const store = new AuditStore(root);
    await mkdir(store.paths.tasks, { recursive: true });
    if (incrementalPlan) await persistIncrementalPlan(root, incrementalPlan);
    const db = new Database(store.paths.db);
    try {
      db.exec(schema);
      const stamp = now();
      db.prepare("INSERT INTO schema_meta VALUES (?,?,?)").run(4, "audit-contract-v1", stamp);
      const normalizedScope = { ...runScope, mode };
      db.prepare("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)").run(runId, resolve(target), "created", null, `project-model-v${model.schema_version}`, canonicalJson(normalizedScope), 0, stamp, stamp, null);
      const units = new Map<string, Record<string, unknown>[]>();
      for (const entry of model.entry_candidates) {
        const componentId = String(entry.component_id ?? entry.candidate_id);
        const entries = units.get(componentId) ?? []; entries.push(entry); units.set(componentId, entries);
      }
      const selectedEntryTypes = new Set(capabilityRows.filter((item) => runScope.capabilities?.includes(item.capability_id)).flatMap((item) => item.entry_types ?? []));
      const candidateEntryTypes: Record<string, readonly string[]> = {
        exported_component: ["exported_ability", "want"], deeplink: ["deeplink"], implicit_want: ["want"],
        extension_uri: ["provider"], ipc_service_candidate: ["ipc_transaction"],
        project_scope: ["project"],
      };
      const affectedEntries = new Set((incrementalPlan?.impactPlan.affected_entries as string[] | undefined) ?? []);
      const reusableEntries = new Set((incrementalPlan?.impactPlan.reusable_entries as string[] | undefined) ?? []);
      const selected = [...units].filter(([componentId, entries]) => {
        if (mode === "incremental") return affectedEntries.has(`component:${componentId}`) || !reusableEntries.has(`component:${componentId}`);
        if (runScope.components?.length) return entries[0]?.type !== "project_scope" && (runScope.components.includes(String(entries[0]?.component_id)) || runScope.components.includes(String(entries[0]?.component_name)));
        if (runScope.mode !== "capability") return true;
        return entries.some((entry) => (candidateEntryTypes[String(entry.type)] ?? []).some((type) => selectedEntryTypes.has(type)));
      }).filter(([, entries]) => {
        const projectUnit = entries.some((entry) => entry.type === "project_scope");
        return capabilityRows.some((item) => runScope.capabilities?.includes(item.capability_id) && (item.analysis_scope === "project") === projectUnit);
      });
      if (!selected.length && mode !== "incremental") throw new Error("audit_scope_has_no_entry_candidates");
      const selectedComponents = new Set(selected.map(([componentId]) => componentId));
      const insertEntry = db.prepare("INSERT INTO entries VALUES (?,?,?,?,?)");
      const insertFacet = db.prepare("INSERT INTO entry_facets VALUES (?,?,?,?,?)");
      const insertUnit = db.prepare("INSERT INTO analysis_units VALUES (?,?,?)");
      const insertTask = db.prepare("INSERT INTO tasks(task_id,run_id,semantic_key,kind,subject_id,status,attempts,input_json,created_at,updated_at) VALUES (?,?,?,?,?,'queued',0,?,?,?)");
      const capabilityDomains = Object.fromEntries(capabilityRows.filter((item) => item.domain).map((item) => [item.capability_id, item.domain]));
      for (const [componentId, entries] of units) {
        const entryId = String(entries[0]!.candidate_id);
        const hasExternalFacet = entries.some((entry) => entry.type !== "component_scope");
        const entryKey = `component:${componentId}`;
        const initialScope = selectedComponents.has(componentId);
        const reused = mode === "incremental" && reusableEntries.has(entryKey);
        const entryPayload = { ...entries[0], project_candidates: entries, initial_scope: initialScope, root_eligible: (mode === "incremental" || initialScope) && hasExternalFacet, incremental_reused: reused };
        insertEntry.run(entryId, runId, componentId, `component:${componentId}`, canonicalJson(entryPayload));
        for (const facet of entries) {
          const hash = contentHash(facet);
          insertFacet.run(stableId("FACET", entryId, facet.type, hash), entryId, String(facet.type), hash, canonicalJson(facet));
        }
        const projectUnit = entries.some((entry) => entry.type === "project_scope");
        const unitCapabilities = capabilityRows.filter((item) => runScope.capabilities?.includes(item.capability_id) && (item.analysis_scope === "project") === projectUnit).map((item) => item.capability_id);
        const input = {
          target_repo: resolve(target), audit_scope: { mode, capabilities: unitCapabilities, components: runScope.components ?? [] }, capability_domains: capabilityDomains,
          entry: entryPayload, entry_candidates: entries, project_summary: model.summary,
          project_context: projectUnit ? { application: model.application, build: model.build, modules: model.modules, dependencies: model.dependencies, requested_permissions: model.requested_permissions, defined_permissions: model.defined_permissions } : {},
          component_directory: model.components, upstream_calls: [],
        };
        insertUnit.run(componentId, entryId, canonicalJson(input));
      }
      const selectedIds = new Set(selected.map(([componentId]) => componentId));
      const scheduled = mode === "incremental" ? [...units].filter(([componentId, entries]) => {
        const projectUnit = entries.some((entry) => entry.type === "project_scope");
        return capabilityRows.some((item) => runScope.capabilities?.includes(item.capability_id) && (item.analysis_scope === "project") === projectUnit);
      }) : [...units].filter(([componentId]) => selectedIds.has(componentId));
      for (const [componentId] of scheduled) {
        const unit = db.prepare("SELECT entry_id,input_json FROM analysis_units WHERE component_id=?").get(componentId) as { entry_id: string; input_json: string };
        const key = `semantic:${componentId}`;
        insertTask.run(stableId("TASK", runId, key), runId, key, "component_semantic_analysis", unit.entry_id, unit.input_json, stamp, stamp);
      }
      if (mode === "incremental") {
        for (const componentId of [...units.keys()].sort()) {
          const entryKey = `component:${componentId}`;
          if (!reusableEntries.has(entryKey)) continue;
          const snapshot = incrementalPlan!.baseline.semanticResults[entryKey];
          const task = db.prepare("SELECT * FROM tasks WHERE semantic_key=?").get(`semantic:${componentId}`) as Record<string, unknown>;
          try {
            db.transaction(() => {
              const candidate = structuredClone((snapshot?.result ?? {}) as Record<string, unknown>);
              candidate.task_id = task.task_id; candidate.entry_id = task.subject_id;
              const normalized = store.normalizeSemantic(candidate, task);
              validateSubmissionSchema("component_semantic_analysis", normalized);
              store.ingestSemantic(db, task, 0, normalized);
              db.prepare("UPDATE tasks SET status='completed',attempts=0,result_json=?,error=NULL,updated_at=? WHERE task_id=?").run(canonicalJson(normalized), now(), task.task_id);
              store.event(db, "semantic_result_reused", String(task.task_id), { entry_key: entryKey });
            })();
          } catch (error) {
            db.prepare("UPDATE tasks SET status='queued',attempts=0,error=?,updated_at=? WHERE task_id=?").run(`semantic_reuse_rejected:${error instanceof Error ? error.message : String(error)}`, now(), task.task_id);
            store.event(db, "semantic_reuse_rejected", String(task.task_id), { entry_key: entryKey, error: error instanceof Error ? error.message : String(error) });
          }
        }
      }
      db.prepare("UPDATE runs SET status='running',updated_at=? WHERE run_id=?").run(now(), runId);
    } finally { db.close(); }
    await writeFile(join(root, "project-model.json"), `${JSON.stringify(model, null, 2)}\n`, "utf8");
    return store;
  }

  runId(): string { const db = this.open(); try { return String((db.prepare("SELECT run_id FROM runs").get() as { run_id: string }).run_id); } finally { db.close(); } }
  graphThreadId(): string { const db = this.open(); try { const run = db.prepare("SELECT run_id,resume_generation FROM runs").get() as { run_id: string; resume_generation: number }; return `${run.run_id}:g${run.resume_generation}`; } finally { db.close(); } }

  static openExisting(runDirectory: string): AuditStore { const store = new AuditStore(resolve(runDirectory)); const db = store.open(); db.close(); return store; }

  async claim(limit: number, workerId = `pid-${process.pid}`, leaseMs = 300_000): Promise<PoolClaim> {
    const db = this.open();
    try {
      const runStatus = String((db.prepare("SELECT status FROM runs").get() as { status: string }).status);
      if (runStatus !== "running") return { ok: false, reason: `run_not_running:${runStatus}`, tasks: [] };
      const tasks = db.transaction(() => {
        const running = (db.prepare("SELECT COUNT(*) n FROM tasks WHERE status='running'").get() as { n: number }).n;
        const queued = (db.prepare("SELECT COUNT(*) n FROM tasks WHERE status='queued'").get() as { n: number }).n;
        if (running === 0 && queued === 0) { this.ensureValidationTasks(db); this.ensurePocTasks(db); }
        const available = Math.max(0, Math.min(limit, HARMONY_MAX_AGENT_CAPACITY - running));
        const selected = db.prepare("SELECT * FROM tasks WHERE status='queued' AND (retry_after IS NULL OR retry_after<=?) ORDER BY created_at,task_id LIMIT ?").all(now(), available) as Record<string, unknown>[];
        return selected.map((row) => {
          const attempt = Number(row.attempts) + 1; const stamp = now();
          const expires = new Date(Date.now() + leaseMs).toISOString();
          db.prepare("UPDATE tasks SET status='running',attempts=?,claimed_at=?,lease_expires_at=?,worker_id=?,retry_after=NULL,updated_at=? WHERE task_id=?").run(attempt, stamp, expires, workerId, stamp, row.task_id);
          return { task_id: String(row.task_id), kind: String(row.kind), attempt, input: JSON.parse(String(row.input_json)) } satisfies PoolTaskHandle;
        });
      })();
      return { ok: true, reason: tasks.length ? "claimed" : "no_queued", tasks };
    } finally { db.close(); }
  }

  async taskDocument(handle: PoolTaskHandle): Promise<Record<string, unknown>> {
    const schemaName = handle.kind === "component_semantic_analysis" ? "component-semantic-result.schema.json" : handle.kind === "exploitability_validation" ? "exploitability-validation-result.schema.json" : "poc-result.schema.json";
    const db = this.open();
    try {
      const task = db.prepare("SELECT error,subject_id FROM tasks WHERE task_id=?").get(handle.task_id) as { error: string | null; subject_id: string };
      const input = handle.kind === "component_semantic_analysis"
        ? semanticTaskInput(handle.input as Record<string, unknown>, await listCapabilities())
        : handle.kind === "exploitability_validation"
          ? validationTaskInput(db, handle.input as Record<string, unknown>, task.subject_id)
          : pocTaskInput(db, handle.input as Record<string, unknown>, task.subject_id);
      return { task_id: handle.task_id, kind: handle.kind, attempt: handle.attempt, previous_error: task.error, input, result_schema: JSON.parse(await readFile(new URL(`../../resources/schemas/${schemaName}`, import.meta.url), "utf8")) };
    } finally { db.close(); }
  }

  reconcile(taskId: string, attempt: number, candidate: Record<string, unknown> | undefined, error?: string): Record<string, unknown> {
    const db = this.open();
    try {
      const accept = db.transaction(() => {
        const task = db.prepare("SELECT * FROM tasks WHERE task_id=?").get(taskId) as Record<string, unknown> | undefined;
        if (!task || task.status !== "running") return { accepted: false, ignored: true, error_code: "TASK_NOT_RUNNING" };
        if (Number(task.attempts) !== attempt) return { accepted: false, ignored: true, error_code: "STALE_TASK_ATTEMPT" };
        if (!candidate) return this.rejectAttempt(db, task, attempt, error ?? "missing_submission");
        const normalized = task.kind === "component_semantic_analysis" ? this.normalizeSemantic(candidate, task)
          : task.kind === "exploitability_validation" ? this.normalizeValidation(candidate, task) : normalizePocSubmission(candidate);
        validateSubmissionSchema(String(task.kind), normalized);
        if (task.kind === "component_semantic_analysis") this.ingestSemantic(db, task, attempt, normalized);
        else if (task.kind === "exploitability_validation") this.ingestValidation(db, task, attempt, normalized);
        else this.ingestPoc(db, task, attempt, normalized);
        db.prepare("UPDATE tasks SET status='completed',result_json=?,error=NULL,claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE task_id=?").run(canonicalJson(normalized), now(), taskId);
        this.event(db, "task_completed", taskId, { attempt, kind: task.kind });
        return { accepted: true, status: "completed" };
      });
      try { return accept(); }
      catch (caught) {
        if (!(caught instanceof AuditInvariantError)) throw caught;
        return db.transaction(() => {
          const task = db.prepare("SELECT * FROM tasks WHERE task_id=?").get(taskId) as Record<string, unknown> | undefined;
          if (!task || task.status !== "running" || Number(task.attempts) !== attempt) return { accepted: false, ignored: true, error_code: "TASK_NOT_RUNNING" };
          return this.rejectAttempt(db, task, attempt, caught.message, caught.code);
        })();
      }
    } finally { db.close(); }
  }

  private rejectAttempt(db: Database.Database, task: Record<string, unknown>, attempt: number, error: string, code?: string): Record<string, unknown> {
    const status = attempt < 3 ? "queued" : "exhausted";
    // A retryable rejection backs off so a rate-limited or failing model is not
    // hammered by the rolling pool: attempt 1 waits 30s, attempt 2 waits 60s.
    const retryAfter = status === "queued" ? new Date(Date.now() + attempt * RETRY_BACKOFF_MS).toISOString() : null;
    db.prepare("UPDATE tasks SET status=?,error=?,retry_after=?,claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE task_id=?").run(status, error, retryAfter, now(), task.task_id);
    this.event(db, "task_rejected", String(task.task_id), { attempt, status, error_code: code ?? null, retry_after: retryAfter });
    return { accepted: false, status, error, ...(code ? { error_code: code } : {}) };
  }

  private ingestSemantic(db: Database.Database, task: Record<string, unknown>, attempt: number, candidate: Record<string, unknown>): void {
    const input = JSON.parse(String(task.input_json)) as Record<string, unknown>;
    const scope = (input.audit_scope as Record<string, unknown> | undefined) ?? {};
    const capabilities = Array.isArray(scope.capabilities) ? scope.capabilities.map(String) : [];
    const componentIds = new Set((db.prepare("SELECT component_id FROM analysis_units").all() as { component_id: string }[]).map((row) => row.component_id));
    const capabilityDomains = new Map(Object.entries((input.capability_domains as Record<string, string> | undefined) ?? {}));
    validateSemanticSubmission(candidate, { taskId: String(task.task_id), entryId: String(task.subject_id), capabilities, enabledCapabilities: new Set(capabilities), componentIds, capabilityDomains });
    const semanticId = stableId("SEM", this.runIdFrom(db), task.task_id, attempt);
    db.prepare("INSERT INTO semantic_analyses VALUES (?,?,?,?,?,?,?)").run(semanticId, task.task_id, task.subject_id, attempt, candidate.summary, canonicalJson(candidate.coverage), now());
    const evidenceMap = this.insertEvidence(db, task, rows(candidate.evidence));
    for (const call of rows(candidate.component_calls)) this.insertCall(db, semanticId, call, evidenceMap);
    const normalizedGroups = rows(candidate.operation_groups).map((group) => this.insertGroup(db, semanticId, group, evidenceMap));
    const incomingPaths = this.pathsToEntry(db, String(task.subject_id));
    incomingPaths.flatMap((path) => normalizedGroups.flatMap((group) => {
      const cross = buildCrossComponentGroup(path, group); return cross ? [this.insertCrossGroup(db, semanticId, String(group.group_id), path, cross)] : [];
    }));
    this.propagateCalls(db, task, input, rows(candidate.component_calls), incomingPaths);
  }

  private normalizeSemantic(candidate: Record<string, unknown>, task: Record<string, unknown>): Record<string, unknown> {
    const input = JSON.parse(String(task.input_json)) as Record<string, unknown>;
    const domains = new Map(Object.entries((input.capability_domains as Record<string, string> | undefined) ?? {}));
    return normalizeSemanticSubmission(candidate, String(task.subject_id), domains);
  }

  private normalizeValidation(candidate: Record<string, unknown>, task: Record<string, unknown>): Record<string, unknown> {
    const normalized = normalizeValidationSubmission(candidate, String(task.subject_id));
    const input = JSON.parse(String(task.input_json)) as Record<string, unknown>;
    const groups = new Map(rows(input.operation_groups).map((group) => [String(group.group_id), group]));
    for (const validation of rows(normalized.validations)) {
      const group = groups.get(String(validation.group_id));
      if (group?.scope !== "cross_component") continue;
      const expected = (group.principal_state as Record<string, unknown> | undefined) ?? {};
      const principal = (validation.principal_analysis as Record<string, unknown> | undefined) ?? {};
      validation.principal_analysis = {
        ...principal,
        origin_principal: expected.origin_principal,
        target_observed_principal: expected.target_observed_principal,
        authority_used: expected.authority_used,
        origin_bound_to_observed_principal: expected.origin_binding === "preserved",
        delegation_risk: expected.origin_binding === "replaced_by_caller",
      };
    }
    return normalized;
  }

  private pathsToEntry(db: Database.Database, entryId: string): ComponentPath[] {
    return (db.prepare("SELECT payload_json FROM component_paths WHERE target_entry_id=? ORDER BY fingerprint").all(entryId) as { payload_json: string }[]).map((row) => JSON.parse(row.payload_json) as ComponentPath);
  }

  private propagateCalls(db: Database.Database, task: Record<string, unknown>, input: Record<string, unknown>, calls: Record<string, unknown>[], incoming: ComponentPath[]): void {
    const source = db.prepare("SELECT component_id,payload_json FROM entries WHERE entry_id=?").get(task.subject_id) as { component_id: string; payload_json: string };
    const rootEligible = (JSON.parse(source.payload_json) as Record<string, unknown>).root_eligible === true;
    for (const call of calls) {
      const targetComponentId = String(call.target_component_id);
      const unit = db.prepare("SELECT entry_id,input_json FROM analysis_units WHERE component_id=?").get(targetComponentId) as { entry_id: string; input_json: string };
      const args = { sourceEntryId: String(task.subject_id), sourceComponentId: source.component_id, sourceTaskId: String(task.task_id), targetEntryId: unit.entry_id, targetComponentId, call };
      const paths = incoming.length ? incoming.map((path) => extendPath(path, args)) : rootEligible ? [seedPath(args)] : [];
      if (paths.length) for (const path of paths) this.persistAndDispatchPath(db, path, unit, input.target_repo);
      else this.dispatchSemanticTarget(db, targetComponentId, unit);
    }
  }

  private dispatchSemanticTarget(db: Database.Database, targetComponentId: string, unit: { entry_id: string; input_json: string }): void {
    const key = `semantic:${targetComponentId}`;
    const existing = db.prepare("SELECT task_id FROM tasks WHERE run_id=? AND semantic_key=?").get(this.runIdFrom(db), key) as { task_id: string } | undefined;
    if (!existing) db.prepare("INSERT INTO tasks(task_id,run_id,semantic_key,kind,subject_id,status,attempts,input_json,created_at,updated_at) VALUES (?,?,?,?,?,'queued',0,?,?,?)").run(stableId("TASK", this.runIdFrom(db), key), this.runIdFrom(db), key, "component_semantic_analysis", unit.entry_id, unit.input_json, now(), now());
  }

  private persistAndDispatchPath(db: Database.Database, path: ComponentPath, unit: { entry_id: string; input_json: string }, targetRepo: unknown): void {
    const inserted = db.prepare("INSERT OR IGNORE INTO component_paths VALUES (?,?,?,?,?,?,?)").run(path.path_id, this.runIdFrom(db), path.root_entry_id, path.target_entry_id, path.fingerprint, path.cycle ? 1 : 0, canonicalJson(path));
    if (!inserted.changes) return;
    const targetInput = JSON.parse(unit.input_json) as Record<string, unknown>; const upstream = Array.isArray(targetInput.upstream_calls) ? targetInput.upstream_calls : [];
    upstream.push({ association_key: path.fingerprint, path_context: path }); targetInput.upstream_calls = upstream;
    db.prepare("UPDATE analysis_units SET input_json=? WHERE entry_id=?").run(canonicalJson(targetInput), unit.entry_id);
    const targetComponentId = path.component_ids.at(-1)!; const key = `semantic:${targetComponentId}`;
    const existing = db.prepare("SELECT task_id,status FROM tasks WHERE run_id=? AND semantic_key=?").get(this.runIdFrom(db), key) as { task_id: string; status: string } | undefined;
    if (!existing && !path.cycle) db.prepare("INSERT INTO tasks(task_id,run_id,semantic_key,kind,subject_id,status,attempts,input_json,created_at,updated_at) VALUES (?,?,?,?,?,'queued',0,?,?,?)").run(stableId("TASK", this.runIdFrom(db), key), this.runIdFrom(db), key, "component_semantic_analysis", unit.entry_id, canonicalJson(targetInput), now(), now());
    else if (existing?.status === "queued") db.prepare("UPDATE tasks SET input_json=?,updated_at=? WHERE task_id=?").run(canonicalJson(targetInput), now(), existing.task_id);
    else if (existing?.status === "completed") this.correlateCompletedTarget(db, path, targetRepo);
  }

  private correlateCompletedTarget(db: Database.Database, path: ComponentPath, targetRepo: unknown): void {
    const semantic = db.prepare("SELECT semantic_analysis_id,task_id FROM semantic_analyses WHERE entry_id=? ORDER BY created_at DESC LIMIT 1").get(path.target_entry_id) as { semantic_analysis_id: string; task_id: string } | undefined;
    if (!semantic) return;
    const locals = db.prepare("SELECT g.group_id,g.payload_json FROM operation_groups g LEFT JOIN cross_component_groups c ON c.group_id=g.group_id WHERE g.semantic_analysis_id=? AND c.group_id IS NULL ORDER BY g.group_id").all(semantic.semantic_analysis_id) as { group_id: string; payload_json: string }[];
    locals.flatMap((row) => { const cross = buildCrossComponentGroup(path, JSON.parse(row.payload_json)); return cross ? [this.insertCrossGroup(db, semantic.semantic_analysis_id, row.group_id, path, cross)] : []; });
  }

  private insertCrossGroup(db: Database.Database, semanticId: string, localGroupId: string, path: ComponentPath, group: Record<string, unknown>): Record<string, unknown> {
    const id = stableId("GRP", semanticId, group.group_key); const normalized = { ...group, group_id: id };
    const inserted = db.prepare("INSERT OR IGNORE INTO operation_groups VALUES (?,?,?,?,?,?,?)").run(id, semanticId, group.group_key, group.capability_id, group.category, group.title, canonicalJson(normalized));
    if (inserted.changes) {
      for (const fact of rows(group.facts)) db.prepare("INSERT INTO group_facts VALUES (?,?,?,?,?,?)").run(id, fact.fact_key, fact.type, fact.body, fact.location ?? null, canonicalJson(fact));
      for (const edge of rows(group.edges)) db.prepare("INSERT INTO group_edges VALUES (?,?,?,?,?)").run(id, edge.from, edge.to, edge.kind, canonicalJson(edge));
      db.prepare("INSERT INTO cross_component_groups VALUES (?,?,?)").run(id, path.path_id, localGroupId);
    }
    return normalized;
  }

  private scheduleValidation(db: Database.Database, key: string, entryId: string, groups: Record<string, unknown>[], targetRepo: unknown, producerTaskIds: string[]): void {
    const evidenceRows = producerTaskIds.length ? db.prepare(`SELECT DISTINCT local_evidence_id FROM evidence WHERE producer_task_id IN (${producerTaskIds.map(() => "?").join(",")})`).all(...producerTaskIds) as { local_evidence_id: string }[] : [];
    const input = { verification_scope: { target_repo: targetRepo }, entry_id: entryId, operation_groups: groups, inherited_evidence_ids: evidenceRows.map((row) => row.local_evidence_id), inherited_evidence_task_ids: producerTaskIds };
    db.prepare("INSERT OR IGNORE INTO tasks(task_id,run_id,semantic_key,kind,subject_id,status,attempts,input_json,created_at,updated_at) VALUES (?,?,?,?,?,'queued',0,?,?,?)").run(stableId("TASK", this.runIdFrom(db), key), this.runIdFrom(db), key, "exploitability_validation", entryId, canonicalJson(input), now(), now());
  }

  /** v3.1 phase barrier: validation is planned only after semantic discovery and correlation drain. */
  private ensureValidationTasks(db: Database.Database): void {
    const unfinishedSemantics = (db.prepare("SELECT COUNT(*) n FROM tasks WHERE kind='component_semantic_analysis' AND status IN ('queued','running')").get() as { n: number }).n;
    if (unfinishedSemantics) return;
    const targetRepo = (db.prepare("SELECT target_repo FROM runs").get() as { target_repo: string }).target_repo;
    const candidates = db.prepare(`SELECT g.group_id,g.payload_json,s.entry_id,s.task_id,s.coverage_json,c.path_id
      FROM operation_groups g
      JOIN semantic_analyses s ON s.semantic_analysis_id=g.semantic_analysis_id
      LEFT JOIN cross_component_groups c ON c.group_id=g.group_id
      ORDER BY s.entry_id,g.group_id`).all() as { group_id: string; payload_json: string; entry_id: string; task_id: string; coverage_json: string; path_id: string | null }[];
    const eligible: { entryId: string; group: Record<string, unknown>; producerTaskIds: string[] }[] = [];
    for (const row of candidates) {
      const coverage = JSON.parse(row.coverage_json) as Record<string, unknown>;
      if (coverage.entry_status !== "confirmed") continue;
      if (!row.path_id) {
        const entry = db.prepare("SELECT payload_json FROM entries WHERE entry_id=?").get(row.entry_id) as { payload_json: string };
        if ((JSON.parse(entry.payload_json) as Record<string, unknown>).root_eligible !== true) continue;
      }
      const group = JSON.parse(row.payload_json) as Record<string, unknown>;
      const producerTaskIds = new Set<string>([row.task_id]);
      const path = group.path_context as ComponentPath | undefined;
      for (const producer of path?.producer_task_ids ?? []) producerTaskIds.add(producer);
      eligible.push({ entryId: row.entry_id, group, producerTaskIds: [...producerTaskIds] });
    }
    const entries = new Set(eligible.map((item) => item.entryId));
    const splitLegacyEntries = new Set<string>();
    for (const entryId of entries) {
      const key = `validation:${entryId}`;
      const legacy = db.prepare("SELECT task_id,status,error FROM tasks WHERE semantic_key=?").get(key) as { task_id: string; status: string; error: string | null } | undefined;
      if (!legacy) continue;
      const alreadySplit = legacy.status === "cancelled" && legacy.error === "superseded_by_group_validation_tasks";
      const canSplit = ["queued", "exhausted"].includes(legacy.status);
      if (!canSplit && !alreadySplit) continue;
      if (canSplit) db.prepare("UPDATE tasks SET status='cancelled',error='superseded_by_group_validation_tasks',claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE task_id=?").run(now(), legacy.task_id);
      splitLegacyEntries.add(entryId);
    }
    let reused = 0;
    let scheduled = 0;
    for (const item of eligible) {
      const legacy = db.prepare("SELECT status,error FROM tasks WHERE semantic_key=?").get(`validation:${item.entryId}`) as { status: string; error: string | null } | undefined;
      if (legacy && !splitLegacyEntries.has(item.entryId)) continue;
      const groupId = String(item.group.group_id);
      const key = `validation:${item.entryId}:${groupId}`;
      this.scheduleValidation(db, key, item.entryId, [item.group], targetRepo, item.producerTaskIds);
      const task = db.prepare("SELECT * FROM tasks WHERE semantic_key=?").get(key) as Record<string, unknown> | undefined;
      if (task && this.tryReuseValidation(db, task, [item.group])) reused += 1;
      scheduled += 1;
    }
    if (eligible.length) this.event(db, "validation_phase_planned", this.runIdFrom(db), { entries: entries.size, operation_groups: eligible.length, tasks: scheduled, reused });
  }

  private tryReuseValidation(db: Database.Database, task: Record<string, unknown>, groups: Record<string, unknown>[]): boolean {
    if (task.status !== "queued") return false;
    const run = db.prepare("SELECT audit_scope_json FROM runs").get() as { audit_scope_json: string };
    const scope = JSON.parse(run.audit_scope_json) as Record<string, unknown>;
    if (scope.mode !== "incremental") return false;
    const entry = db.prepare("SELECT candidate_key,payload_json FROM entries WHERE entry_id=?").get(task.subject_id) as { candidate_key: string; payload_json: string } | undefined;
    if (!entry || (JSON.parse(entry.payload_json) as Record<string, unknown>).incremental_reused !== true) return false;
    let document: Record<string, unknown>;
    try { document = JSON.parse(readFileSync(this.paths.incremental.baselineValidations, "utf8")) as Record<string, unknown>; }
    catch { return false; }
    const entries = document.entries && typeof document.entries === "object" ? document.entries as Record<string, Record<string, unknown>> : {};
    const snapshot = entries[entry.candidate_key];
    if (!snapshot || !snapshot.result || typeof snapshot.result !== "object" || !snapshot.group_fingerprints || typeof snapshot.group_fingerprints !== "object") return false;
    const oldFingerprints = snapshot.group_fingerprints as Record<string, string>;
    const currentByFingerprint = new Map(groups.map((group) => [validationGroupFingerprint(group), String(group.group_id)]));
    const reusableValidations = rows((snapshot.result as Record<string, unknown>).validations).filter((validation) => {
      const fingerprint = oldFingerprints[String(validation.group_id)];
      return !!fingerprint && currentByFingerprint.has(fingerprint);
    });
    if (reusableValidations.length !== groups.length) return false;
    try {
      db.transaction(() => {
        const candidate = structuredClone(snapshot.result as Record<string, unknown>);
        candidate.task_id = task.task_id; candidate.entry_id = task.subject_id;
        candidate.validations = reusableValidations.map((validation) => structuredClone(validation));
        for (const validation of rows(candidate.validations)) {
          const fingerprint = oldFingerprints[String(validation.group_id)];
          const currentId = fingerprint ? currentByFingerprint.get(fingerprint) : undefined;
          if (!currentId) throw new Error(`validation_group_fingerprint_missing:${String(validation.group_id)}`);
          validation.group_id = currentId;
        }
        const normalized = normalizeValidationSubmission(candidate, String(task.subject_id));
        validateSubmissionSchema("exploitability_validation", normalized);
        this.ingestValidation(db, task, 0, normalized);
        db.prepare("UPDATE tasks SET status='completed',attempts=0,result_json=?,error=NULL,updated_at=? WHERE task_id=?").run(canonicalJson(normalized), now(), task.task_id);
        this.event(db, "validation_result_reused", String(task.task_id), { entry_key: entry.candidate_key, groups: groups.length });
      })();
      return true;
    } catch (error) {
      this.event(db, "validation_reuse_rejected", String(task.task_id), { entry_key: entry.candidate_key, error: error instanceof Error ? error.message : String(error) });
      return false;
    }
  }

  private insertEvidence(db: Database.Database, task: Record<string, unknown>, evidenceRows: Record<string, unknown>[]): Map<string, string> {
    const result = new Map<string, string>(); const runId = this.runIdFrom(db);
    for (const evidence of evidenceRows) {
      const localId = String(evidence.evidence_id); const hash = String(evidence.sha256 ?? contentHash(evidence.content_ref ?? evidence.summary ?? evidence));
      // v3.1 identity: a local evidence id is private to its producer task. Two
      // aliases may legitimately point at identical source content.
      const id = stableId("EV", task.task_id, localId);
      const payload = canonicalJson(evidence);
      const byId = db.prepare("SELECT payload_json FROM evidence WHERE evidence_id=?").get(id) as { payload_json: string } | undefined;
      const byLocal = db.prepare("SELECT evidence_id,payload_json FROM evidence WHERE producer_task_id=? AND local_evidence_id=?").get(task.task_id, localId) as { evidence_id: string; payload_json: string } | undefined;
      if ((byId && byId.payload_json !== payload) || (byLocal && (byLocal.evidence_id !== id || byLocal.payload_json !== payload))) throw new AuditInvariantError("IDENTITY_COLLISION", { entity: "evidence", localId, id });
      if (!byId) db.prepare("INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?)").run(id, runId, task.task_id, localId, evidence.source, evidence.kind, evidence.location ?? null, hash, payload);
      result.set(localId, id);
    }
    return result;
  }

  private addRefs(db: Database.Database, ownerType: string, ownerId: string, values: string[], evidence: Map<string, string>): void {
    const insert = db.prepare("INSERT OR IGNORE INTO evidence_refs VALUES (?,?,?)");
    for (const local of values) insert.run(ownerType, ownerId, evidence.get(local)!);
  }

  private insertCall(db: Database.Database, semanticId: string, call: Record<string, unknown>, evidence: Map<string, string>): void {
    const id = stableId("CALL", semanticId, call.call_key);
    db.prepare("INSERT INTO component_calls VALUES (?,?,?,?,?)").run(id, semanticId, call.call_key, call.target_component_id, canonicalJson(call));
    rows(call.parameter_mappings).forEach((mapping, index) => db.prepare("INSERT INTO call_parameters VALUES (?,?,?,?,?,?)").run(id, index, mapping.source_property, mapping.target_property, mapping.control_state, mapping.transform));
    this.addRefs(db, "component_call", id, [...refs(call), ...refs((call.principal_transition as Record<string, unknown> | undefined) ?? {}), ...rows(call.security_checks).flatMap(refs)], evidence);
    rows(call.security_checks).forEach((check, index) => this.insertSecurityCheck(db, { callId: id }, check, index, evidence));
  }

  private insertGroup(db: Database.Database, semanticId: string, group: Record<string, unknown>, evidence: Map<string, string>): Record<string, unknown> {
    const id = stableId("GRP", semanticId, group.group_key); const normalized = { ...group, group_id: id };
    db.prepare("INSERT INTO operation_groups VALUES (?,?,?,?,?,?,?)").run(id, semanticId, group.group_key, group.capability_id, group.category, group.title, canonicalJson(normalized));
    for (const fact of rows(group.facts)) {
      db.prepare("INSERT INTO group_facts VALUES (?,?,?,?,?,?)").run(id, fact.fact_key, fact.type, fact.body, fact.location ?? null, canonicalJson(fact));
      this.addRefs(db, "group_fact", `${id}:${String(fact.fact_key)}`, refs(fact), evidence);
    }
    for (const edge of rows(group.edges)) {
      const owner = `${id}:${String(edge.from)}:${String(edge.to)}:${String(edge.kind)}`;
      db.prepare("INSERT INTO group_edges VALUES (?,?,?,?,?)").run(id, edge.from, edge.to, edge.kind, canonicalJson(edge));
      this.addRefs(db, "group_edge", owner, refs(edge), evidence);
    }
    rows(group.security_checks).forEach((check, index) => this.insertSecurityCheck(db, { groupId: id }, check, index, evidence));
    this.addRefs(db, "operation_group", id, [
      ...refs(group), ...refs((group.context as Record<string, unknown> | undefined) ?? {}), ...refs((group.availability as Record<string, unknown> | undefined) ?? {}),
      ...rows(((group.context as Record<string, unknown> | undefined) ?? {}).effect_hypotheses).flatMap((hypothesis) => strings(hypothesis.basis_evidence_refs)),
      ...rows(group.branches).flatMap(refs), ...rows(group.facts).flatMap(refs), ...rows(group.edges).flatMap(refs), ...rows(group.security_checks).flatMap(refs),
    ], evidence);
    return normalized;
  }

  private insertSecurityCheck(db: Database.Database, owner: { groupId?: string; callId?: string }, check: Record<string, unknown>, index: number, evidence: Map<string, string>): void {
    const ownerId = owner.groupId ?? owner.callId!; const id = stableId("CHECK", ownerId, index, check.type, check.location);
    db.prepare("INSERT INTO security_checks VALUES (?,?,?,?,?,?)").run(id, owner.groupId ?? null, owner.callId ?? null, check.subject_kind, check.validated_property, canonicalJson(check));
    this.addRefs(db, "security_check", id, refs(check), evidence);
  }

  private ingestValidation(db: Database.Database, task: Record<string, unknown>, attempt: number, candidate: Record<string, unknown>): void {
    const input = JSON.parse(String(task.input_json)) as Record<string, unknown>;
    const groups = rows(input.operation_groups); const inherited = new Set(Array.isArray(input.inherited_evidence_ids) ? input.inherited_evidence_ids.map(String) : []);
    const semantic = db.prepare("SELECT coverage_json FROM semantic_analyses WHERE entry_id=? ORDER BY created_at DESC LIMIT 1").get(task.subject_id) as { coverage_json: string } | undefined;
    const entryStatus = semantic ? String((JSON.parse(semantic.coverage_json) as Record<string, unknown>).entry_status ?? "") : undefined;
    validateExploitabilitySubmission(candidate, { taskId: String(task.task_id), entryId: String(task.subject_id), groups, inheritedEvidence: inherited, ...(entryStatus ? { entryStatus } : {}) });
    const localEvidence = this.insertEvidence(db, task, rows(candidate.evidence));
    const producerTaskIds = Array.isArray(input.inherited_evidence_task_ids) ? input.inherited_evidence_task_ids.map(String) : [String(input.inherited_evidence_task_id ?? "")].filter(Boolean);
    const inheritedRows = producerTaskIds.length ? db.prepare(`SELECT local_evidence_id,evidence_id FROM evidence WHERE producer_task_id IN (${producerTaskIds.map(() => "?").join(",")})`).all(...producerTaskIds) as { local_evidence_id: string; evidence_id: string }[] : [];
    const evidence = new Map(inheritedRows.map((row) => [row.local_evidence_id, row.evidence_id])); for (const [key, value] of localEvidence) evidence.set(key, value);
    const affectedRoots = new Set<string>();
    for (const validation of rows(candidate.validations)) {
      const id = stableId("VAL", task.task_id, validation.group_id);
      db.prepare("INSERT INTO validation_results VALUES (?,?,?,?,?,?,?)").run(id, task.task_id, validation.group_id, validation.classification, validation.capability_id, canonicalJson(validation), now());
      this.addRefs(db, "validation", id, [
        ...refs(validation), ...refs((validation.business_intent as Record<string, unknown> | undefined) ?? {}), ...refs((validation.security_boundary as Record<string, unknown> | undefined) ?? {}),
        ...refs((validation.principal_analysis as Record<string, unknown> | undefined) ?? {}), ...refs((validation.availability_analysis as Record<string, unknown> | undefined) ?? {}), ...rows(validation.counter_evidence).flatMap(refs),
        ...Object.values((validation.exploitability as Record<string, unknown> | undefined) ?? {}).flatMap((dimension) => refs((dimension as Record<string, unknown> | undefined) ?? {})),
        ...Object.values((validation.effect_chain as Record<string, unknown> | undefined) ?? {}).flatMap((proof) => refs((proof as Record<string, unknown> | undefined) ?? {})),
      ], evidence);
      rows(validation.counter_evidence).forEach((counter, index) => {
        const counterId = stableId("COUNTER", id, index, counter.kind, counter.reason);
        db.prepare("INSERT INTO validation_counter_evidence VALUES (?,?,?,?,?)").run(counterId, id, counter.kind, counter.reason, canonicalJson(counter));
        this.addRefs(db, "counter_evidence", counterId, refs(counter), evidence);
      });
      if (validation.classification === "confirmed_vulnerability") {
        const cross = db.prepare("SELECT local_group_id FROM cross_component_groups WHERE group_id=?").get(validation.group_id) as { local_group_id: string } | undefined;
        affectedRoots.add(cross?.local_group_id ?? String(validation.group_id));
      }
    }
    for (const root of affectedRoots) {
      const finding = this.rebuildFinding(db, root);
      if (finding) this.schedulePocForFinding(db, finding.finding_id);
    }
  }

  /** v3.2: PoC tasks are scheduled per-finding as soon as the confirming validation lands; this drain-time reconciler fills gaps and repairs stale artifacts whose representative validation changed. */
  private ensurePocTasks(db: Database.Database): void {
    const unfinishedValidation = (db.prepare("SELECT COUNT(*) n FROM tasks WHERE kind='exploitability_validation' AND status IN ('queued','running')").get() as { n: number }).n;
    if (unfinishedValidation) return;
    const findings = this.pocFindingRows(db);
    if (!findings.length) return;
    let scheduled = 0; let reused = 0; let repaired = 0;
    for (const row of findings) {
      const outcome = this.schedulePocForFinding(db, row.finding_id);
      scheduled += outcome.scheduled ? 1 : 0;
      reused += outcome.reused ? 1 : 0;
      repaired += outcome.repaired ? 1 : 0;
    }
    this.event(db, "poc_phase_planned", this.runIdFrom(db), { findings: findings.length, scheduled, reused, repaired });
  }

  private pocFindingRows(db: Database.Database): PocFindingRow[] {
    return db.prepare("SELECT finding_id,classification,payload_json finding_payload FROM findings WHERE classification IN ('confirmed_vulnerability','residual_risk') ORDER BY finding_id").all() as PocFindingRow[];
  }

  /** Insert or refresh the PoC task for one finding; a completed artifact whose finding changed is requeued for regeneration. */
  private schedulePocForFinding(db: Database.Database, findingId: string): { scheduled: boolean; reused: boolean; repaired: boolean } {
    const row = this.pocFindingRows(db).find((item) => item.finding_id === findingId);
    if (!row) return { scheduled: false, reused: false, repaired: false };
    const key = `poc:${findingId}`;
    // Lightweight seed: the full task document is rebuilt from canonical state at claim time
    // by task-context.pocTaskInput, exactly like the validation task two-stage pattern.
    const input = { _finding_hash: stableId("POCIN", row.finding_payload), finding_id: findingId };
    const existing = db.prepare("SELECT * FROM tasks WHERE semantic_key=?").get(key) as Record<string, unknown> | undefined;
    let repaired = false;
    if (existing?.status === "completed") {
      const storedInput = JSON.parse(String(existing.input_json)) as Record<string, unknown>;
      if (storedInput._finding_hash === input._finding_hash) return { scheduled: false, reused: false, repaired: false };
      const pocs = db.prepare("SELECT poc_id FROM poc_artifacts WHERE finding_id=?").all(findingId) as { poc_id: string }[];
      for (const poc of pocs) db.prepare("DELETE FROM evidence_refs WHERE owner_type='poc_artifact' AND owner_id=?").run(poc.poc_id);
      db.prepare("DELETE FROM poc_artifacts WHERE finding_id=?").run(findingId);
      db.prepare("UPDATE tasks SET status='queued',attempts=0,error='poc_finding_changed',result_json=NULL,input_json=?,updated_at=? WHERE task_id=?").run(canonicalJson(input), now(), existing.task_id);
      this.event(db, "poc_artifact_repair", String(existing.task_id), { finding_id: findingId });
      repaired = true;
    } else if (!existing) {
      db.prepare("INSERT INTO tasks(task_id,run_id,semantic_key,kind,subject_id,status,attempts,input_json,created_at,updated_at) VALUES (?,?,?,?,?,'queued',0,?,?,?)").run(stableId("TASK", this.runIdFrom(db), key), this.runIdFrom(db), key, "poc_generation", findingId, canonicalJson(input), now(), now());
    } else if (existing.status === "queued") {
      db.prepare("UPDATE tasks SET input_json=?,updated_at=? WHERE task_id=?").run(canonicalJson(input), now(), existing.task_id);
    }
    const current = db.prepare("SELECT * FROM tasks WHERE semantic_key=?").get(key) as Record<string, unknown> | undefined;
    const reused = current && current.status === "queued" ? this.tryReusePoc(db, current) : false;
    return { scheduled: !existing, reused, repaired };
  }

  private tryReusePoc(db: Database.Database, task: Record<string, unknown>): boolean {
    const run = db.prepare("SELECT audit_scope_json FROM runs").get() as { audit_scope_json: string };
    const scope = JSON.parse(run.audit_scope_json) as Record<string, unknown>;
    if (scope.mode !== "incremental") return false;
    const finding = db.prepare("SELECT root_cause_key FROM findings WHERE finding_id=?").get(task.subject_id) as { root_cause_key: string } | undefined;
    if (!finding) return false;
    const rootCauseKey = finding.root_cause_key;
    const group = db.prepare("SELECT semantic_analysis_id,payload_json FROM operation_groups WHERE group_id=?").get(rootCauseKey) as { semantic_analysis_id: string; payload_json: string } | undefined;
    if (!group) return false;
    const semantic = db.prepare("SELECT entry_id FROM semantic_analyses WHERE semantic_analysis_id=?").get(group.semantic_analysis_id) as { entry_id: string } | undefined;
    if (!semantic) return false;
    const entry = db.prepare("SELECT candidate_key,payload_json FROM entries WHERE entry_id=?").get(semantic.entry_id) as { candidate_key: string; payload_json: string } | undefined;
    if (!entry || (JSON.parse(entry.payload_json) as Record<string, unknown>).incremental_reused !== true) return false;
    let document: Record<string, unknown>;
    try { document = JSON.parse(readFileSync(this.paths.incremental.baselinePocs, "utf8")) as Record<string, unknown>; }
    catch { return false; }
    const items = Array.isArray(document.items) ? document.items as Record<string, unknown>[] : [];
    const currentFingerprint = validationGroupFingerprint(JSON.parse(group.payload_json));
    const snapshot = items.find((item) => String(item.group_fingerprint) === currentFingerprint);
    if (!snapshot || !snapshot.result || typeof snapshot.result !== "object") return false;
    try {
      db.transaction(() => {
        const candidate = structuredClone(snapshot.result as Record<string, unknown>);
        candidate.task_id = task.task_id; candidate.finding_id = String(task.subject_id);
        const normalized = normalizePocSubmission(candidate);
        validateSubmissionSchema("poc_generation", normalized);
        this.ingestPoc(db, task, 0, normalized);
        db.prepare("UPDATE tasks SET status='completed',attempts=0,result_json=?,error=NULL,updated_at=? WHERE task_id=?").run(canonicalJson(normalized), now(), task.task_id);
        this.event(db, "poc_result_reused", String(task.task_id), { root_cause_key: rootCauseKey });
      })();
      return true;
    } catch (error) {
      this.event(db, "poc_reuse_rejected", String(task.task_id), { root_cause_key: rootCauseKey, error: error instanceof Error ? error.message : String(error) });
      return false;
    }
  }

  private ingestPoc(db: Database.Database, task: Record<string, unknown>, attempt: number, candidate: Record<string, unknown>): void {
    // The seed input is lightweight; rebuild the full context from canonical state,
    // exactly as claim-time taskDocument does, so validation and ingestion agree.
    const input = JSON.parse(String(task.input_json)) as Record<string, unknown>;
    const context = pocTaskInput(db, input, String(task.subject_id));
    const finding = (context.finding as Record<string, unknown> | undefined) ?? {};
    const allowedEntryTypes = new Set(Array.isArray(context.allowed_entry_types) ? context.allowed_entry_types.map(String) : []);
    if (!allowedEntryTypes.size) {
      const entryDocument = (context.entry as Record<string, unknown> | undefined) ?? {};
      const candidates = Array.isArray(entryDocument.project_candidates) ? entryDocument.project_candidates as Record<string, unknown>[] : Array.isArray(entryDocument.facets) ? entryDocument.facets as Record<string, unknown>[] : [];
      for (const candidate of candidates) {
        const type = String(candidate.type ?? candidate.entry_type ?? "");
        ({ exported_component: ["exported_ability", "want"], deeplink: ["deeplink"], implicit_want: ["want"], extension_uri: ["provider"], ipc_service_candidate: ["ipc_transaction"], project_scope: ["project"] } as Record<string, string[]>)[type]?.forEach((item) => allowedEntryTypes.add(item));
      }
    }
    const localEvidence = this.insertEvidence(db, task, rows(candidate.evidence));
    const producerTaskIds = Array.isArray(context.inherited_evidence_task_ids) ? context.inherited_evidence_task_ids.map(String) : [];
    const inheritedRows = producerTaskIds.length ? db.prepare(`SELECT local_evidence_id,evidence_id FROM evidence WHERE producer_task_id IN (${producerTaskIds.map(() => "?").join(",")})`).all(...producerTaskIds) as { local_evidence_id: string; evidence_id: string }[] : [];
    const evidence = new Map(inheritedRows.map((row) => [row.local_evidence_id, row.evidence_id])); for (const [key, value] of localEvidence) evidence.set(key, value);
    validatePocSubmission(candidate, {
      taskId: String(task.task_id), entryId: String(task.subject_id),
      findingId: String(finding.finding_id), allowedEntryTypes, allowedEvidence: new Set(evidence.keys()),
    });
    const pocId = stableId("POC", task.task_id);
    db.prepare("INSERT INTO poc_artifacts VALUES (?,?,?,?,?,?,?)").run(pocId, this.runIdFrom(db), String(finding.finding_id), task.task_id, String(candidate.entry_type), canonicalJson(candidate), now());
    this.addRefs(db, "poc_artifact", pocId, refs(candidate), evidence);
  }

  private rebuildFinding(db: Database.Database, rootCause: string): { finding_id: string; representative_validation_id: string } | undefined {
    const candidates = db.prepare(`SELECT v.validation_id,v.payload_json FROM validation_results v
      JOIN operation_groups g ON g.group_id=v.group_id LEFT JOIN cross_component_groups c ON c.group_id=g.group_id
      WHERE v.classification='confirmed_vulnerability' AND COALESCE(c.local_group_id,g.group_id)=? ORDER BY v.validation_id`).all(rootCause) as { validation_id: string; payload_json: string }[];
    if (!candidates.length) return undefined;
    const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    const parsed = candidates.map((row) => ({ id: row.validation_id, value: JSON.parse(row.payload_json) as Record<string, unknown> }));
    parsed.sort((left, right) => (rank[String(right.value.severity)] ?? 0) - (rank[String(left.value.severity)] ?? 0) || left.id.localeCompare(right.id));
    const representative = parsed[0]!; const group = db.prepare("SELECT title FROM operation_groups WHERE group_id=?").get(rootCause) as { title: string };
    const findingId = stableId("FIND", this.runIdFrom(db), rootCause);
    const payload = { root_cause_key: rootCause, title: group.title, severity: representative.value.severity, cwe: representative.value.cwe, impact: representative.value.impact, representative_validation_id: representative.id, validation_ids: candidates.map((row) => row.validation_id) };
    db.prepare(`INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id,root_cause_key) DO UPDATE SET
      title=excluded.title,classification=excluded.classification,severity=excluded.severity,cwe=excluded.cwe,impact=excluded.impact,payload_json=excluded.payload_json`).run(
      findingId, this.runIdFrom(db), rootCause, group.title, "confirmed_vulnerability", representative.value.severity, representative.value.cwe, representative.value.impact, canonicalJson(payload), now(),
    );
    const insertCause = db.prepare("INSERT OR IGNORE INTO finding_causes VALUES (?,?)"); for (const candidate of candidates) insertCause.run(findingId, candidate.validation_id);
    return { finding_id: findingId, representative_validation_id: representative.id };
  }

  private runIdFrom(db: Database.Database): string { return String((db.prepare("SELECT run_id FROM runs").get() as { run_id: string }).run_id); }
  private event(db: Database.Database, type: string, subject: string, payload: unknown): void { db.prepare("INSERT INTO events(run_id,event_type,subject_id,payload_json,created_at) VALUES (?,?,?,?,?)").run(this.runIdFrom(db), type, subject, canonicalJson(payload), now()); }

  snapshot(): Record<string, unknown> {
    const db = this.open();
    try {
      const tasks = Object.fromEntries((db.prepare("SELECT status,COUNT(*) n FROM tasks GROUP BY status").all() as { status: string; n: number }[]).map((row) => [row.status, row.n]));
      return { run: db.prepare("SELECT * FROM runs").get(), tasks, findings: (db.prepare("SELECT COUNT(*) n FROM findings").get() as { n: number }).n, poc_artifacts: (db.prepare("SELECT COUNT(*) n FROM poc_artifacts").get() as { n: number }).n };
    } finally { db.close(); }
  }

  status(): Record<string, unknown> {
    const db = this.open();
    try {
      const run = db.prepare("SELECT * FROM runs").get() as Record<string, unknown>;
      const taskCounts = Object.fromEntries((db.prepare("SELECT status,COUNT(*) count FROM tasks GROUP BY status ORDER BY status").all() as { status: string; count: number }[]).map((row) => [row.status, row.count]));
      const tasks = db.prepare("SELECT task_id,kind,subject_id,status,attempts,worker_id,claimed_at,lease_expires_at,updated_at,error FROM tasks ORDER BY created_at,task_id").all();
      const findings = db.prepare("SELECT finding_id,title,severity,cwe,classification,created_at FROM findings ORDER BY severity DESC,finding_id").all();
      return { run, task_counts: taskCounts, tasks, findings, coverage_gaps: collectCoverageGaps(db), pending_validation_groups: pendingValidationGroupCount(db), paths: this.paths, recoverable: ["running", "failed", "complete_with_gaps"].includes(String(run.status)) };
    } finally { db.close(); }
  }

  eventsAfter(eventId = 0): AuditStoredEvent[] {
    const db = this.open();
    try {
      const events = db.prepare("SELECT event_id,event_type,subject_id,payload_json,created_at FROM events WHERE event_id>? ORDER BY event_id").all(eventId) as {
        event_id: number; event_type: string; subject_id: string | null; payload_json: string; created_at: string;
      }[];
      return events.map(({ payload_json, ...event }) => Object.freeze({ ...event, payload: JSON.parse(payload_json) as unknown }));
    } finally { db.close(); }
  }

  appendTaskTrace(taskId: string, attempt: number, event: AgentTraceEvent): void {
    const db = this.open();
    try {
      const exists = db.prepare("SELECT 1 FROM tasks WHERE task_id=?").get(taskId);
      if (!exists) throw new Error(`audit_task_not_found:${taskId}`);
      this.event(db, "agent_trace", taskId, { attempt, event });
    } finally { db.close(); }
  }

  executions(): readonly PluginExecutionUnit[] {
    const db = this.open();
    try {
      const values = db.prepare("SELECT task_id,kind,subject_id,status,attempts,error,created_at,updated_at FROM tasks ORDER BY created_at,task_id").all() as Record<string, unknown>[];
      return Object.freeze(values.map((task) => Object.freeze({
        id: String(task.task_id),
        kind: String(task.kind),
        title: executionTitle(String(task.kind)),
        status: executionStatus(String(task.status)),
        subject: String(task.subject_id),
        attempt: Number(task.attempts),
        createdAt: String(task.created_at),
        updatedAt: String(task.updated_at),
        ...(task.error ? { error: String(task.error) } : {}),
      })));
    } finally { db.close(); }
  }

  execution(taskId: string): PluginExecutionDetail {
    const db = this.open();
    try {
      const task = db.prepare("SELECT * FROM tasks WHERE task_id=?").get(taskId) as Record<string, unknown> | undefined;
      if (!task) throw new Error(`audit_task_not_found:${taskId}`);
      const unit: PluginExecutionUnit = Object.freeze({
        id: String(task.task_id), kind: String(task.kind),
        title: executionTitle(String(task.kind)),
        status: executionStatus(String(task.status)), subject: String(task.subject_id), attempt: Number(task.attempts),
        createdAt: String(task.created_at), updatedAt: String(task.updated_at),
        ...(task.error ? { error: String(task.error) } : {}),
      });
      const stored = db.prepare("SELECT event_id,event_type,payload_json,created_at FROM events WHERE subject_id=? AND event_type IN ('agent_trace','task_completed','task_rejected','task_lease_recovered') ORDER BY event_id").all(taskId) as {
        event_id: number; event_type: string; payload_json: string; created_at: string;
      }[];
      const attempts = new Map<number, { attempt: number; status: PluginExecutionStatus; startedAt?: string; completedAt?: string; error?: string }>();
      const events: PluginExecutionTraceEvent[] = [];
      for (const row of stored) {
        const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
        const trace = row.event_type === "agent_trace" && payload.event && typeof payload.event === "object" ? payload.event as Record<string, unknown> : undefined;
        const attempt = Number(payload.attempt ?? task.attempts ?? 0);
        const type = trace ? String(trace.type) : row.event_type;
        const timestamp = trace && typeof trace.timestamp === "string" ? trace.timestamp : row.created_at;
        const eventPayload = trace ? trace.payload : payload;
        events.push(Object.freeze({ id: String(row.event_id), attempt, type, timestamp, ...(eventPayload === undefined ? {} : { payload: eventPayload }) }));
        if (attempt <= 0) continue;
        const current = attempts.get(attempt) ?? { attempt, status: "running" as const };
        if (!current.startedAt) current.startedAt = timestamp;
        if (["agent_completed", "task_completed"].includes(type)) { current.status = "succeeded"; current.completedAt = timestamp; }
        if (["agent_failed", "task_rejected", "task_lease_recovered"].includes(type)) {
          current.status = "failed"; current.completedAt = timestamp;
          const detail = eventPayload && typeof eventPayload === "object" ? eventPayload as Record<string, unknown> : {};
          if (detail.error) current.error = String(detail.error);
        }
        attempts.set(attempt, current);
      }
      if (!attempts.size && Number(task.attempts) > 0) attempts.set(Number(task.attempts), {
        attempt: Number(task.attempts), status: unit.status, ...(task.claimed_at ? { startedAt: String(task.claimed_at) } : {}),
        ...(task.status !== "running" ? { completedAt: String(task.updated_at) } : {}), ...(task.error ? { error: String(task.error) } : {}),
      });
      return Object.freeze({
        execution: unit,
        input: JSON.parse(String(task.input_json)),
        ...(task.result_json ? { result: JSON.parse(String(task.result_json)) } : {}),
        attempts: Object.freeze([...attempts.values()].sort((a, b) => a.attempt - b.attempt).map((item) => Object.freeze(item as PluginExecutionAttempt))),
        events: Object.freeze(events),
      });
    } finally { db.close(); }
  }

  recoverExpiredTasks(at = new Date()): number {
    const db = this.open();
    try {
      return db.transaction(() => {
        const expired = db.prepare("SELECT task_id,attempts FROM tasks WHERE status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at<=? ORDER BY task_id").all(at.toISOString()) as { task_id: string; attempts: number }[];
        for (const task of expired) {
          const retryAfter = new Date(Date.now() + LEASE_RECLAIM_BACKOFF_MS).toISOString();
          db.prepare("UPDATE tasks SET status='queued',error='lease_expired',retry_after=?,claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE task_id=?").run(retryAfter, now(), task.task_id);
          this.event(db, "task_lease_recovered", task.task_id, { attempts: task.attempts, retry_after: retryAfter });
        }
        return expired.length;
      })();
    } finally { db.close(); }
  }

  markGatewayRestarted(): Readonly<Record<string, unknown>> {
    const db = this.open();
    try {
      return db.transaction(() => {
        const run = db.prepare("SELECT run_id,status FROM runs").get() as { run_id: string; status: string };
        if (!["created", "running"].includes(run.status)) return Object.freeze({ changed: false, run_id: run.run_id, status: run.status });
        const stamp = now();
        const requeued = db.prepare("UPDATE tasks SET status='queued',error='gateway_restarted',claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE status='running'").run(stamp).changes;
        db.prepare("UPDATE runs SET status='failed',error='gateway_restarted_execution_interrupted',updated_at=? WHERE run_id=?").run(stamp, run.run_id);
        this.event(db, "gateway_restarted", run.run_id, { previous_status: run.status, requeued_tasks: requeued });
        return Object.freeze({ changed: true, run_id: run.run_id, previous_status: run.status, status: "failed", requeued_tasks: requeued });
      })();
    } finally { db.close(); }
  }

  resume(options: { retryExhausted?: boolean; reclaimRunning?: boolean } = {}): Record<string, unknown> {
    const db = this.open();
    try {
      return db.transaction(() => {
        const run = db.prepare("SELECT * FROM runs").get() as Record<string, unknown>; const status = String(run.status);
        if (status === "complete") throw new AuditInvariantError("ILLEGAL_STATE_TRANSITION", { from: status, to: "running" });
        if (status === "cancelled") throw new AuditInvariantError("ILLEGAL_STATE_TRANSITION", { from: status, to: "running" });
        const incomplete = db.prepare("SELECT task_id,kind FROM tasks WHERE status IN ('queued','running','exhausted')").all() as { task_id: string; kind: string }[];
        for (const task of incomplete) this.cleanupPartialTaskFacts(db, task.task_id, task.kind);
        let reclaimed = 0; let retried = 0;
        if (options.reclaimRunning ?? true) reclaimed = db.prepare("UPDATE tasks SET status='queued',error='process_recovered',claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE status='running'").run(now()).changes;
        if (options.retryExhausted ?? true) retried = db.prepare("UPDATE tasks SET status='queued',attempts=0,error=NULL,claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE status='exhausted'").run(now()).changes;
        db.prepare("UPDATE runs SET status='running',error=NULL,resume_generation=resume_generation+1,updated_at=?,finalized_at=NULL").run(now());
        // Resuming a database created by an older build must migrate a queued
        // entry-wide validation batch before claim() can pick it up again.
        this.ensureValidationTasks(db);
        this.ensurePocTasks(db);
        this.event(db, "run_resumed", this.runIdFrom(db), { previous_status: status, reclaimed, retried });
        return { run_id: this.runIdFrom(db), previous_status: status, status: "running", reclaimed_tasks: reclaimed, retried_tasks: retried };
      })();
    } finally { db.close(); }
  }

  /** Repair databases written by pre-atomic-reconcile builds before requeueing work. */
  private cleanupPartialTaskFacts(db: Database.Database, taskId: string, kind: string): void {
    const deleteEvidence = () => {
      const evidenceIds = (db.prepare("SELECT evidence_id FROM evidence WHERE producer_task_id=?").all(taskId) as { evidence_id: string }[]).map((row) => row.evidence_id);
      for (const id of evidenceIds) db.prepare("DELETE FROM evidence_refs WHERE evidence_id=?").run(id);
      db.prepare("DELETE FROM evidence WHERE producer_task_id=?").run(taskId);
    };
    if (kind === "poc_generation") {
      const pocs = (db.prepare("SELECT poc_id FROM poc_artifacts WHERE producer_task_id=?").all(taskId) as { poc_id: string }[]).map((row) => row.poc_id);
      for (const id of pocs) db.prepare("DELETE FROM evidence_refs WHERE owner_type='poc_artifact' AND owner_id=?").run(id);
      db.prepare("DELETE FROM poc_artifacts WHERE producer_task_id=?").run(taskId);
      deleteEvidence();
      return;
    }
    if (kind === "exploitability_validation") {
      const validations = (db.prepare("SELECT validation_id FROM validation_results WHERE task_id=?").all(taskId) as { validation_id: string }[]).map((row) => row.validation_id);
      for (const id of validations) {
        db.prepare("DELETE FROM evidence_refs WHERE owner_type='validation' AND owner_id=?").run(id);
        const counters = (db.prepare("SELECT counter_evidence_id FROM validation_counter_evidence WHERE validation_id=?").all(id) as { counter_evidence_id: string }[]).map((row) => row.counter_evidence_id);
        for (const counter of counters) db.prepare("DELETE FROM evidence_refs WHERE owner_type='counter_evidence' AND owner_id=?").run(counter);
        db.prepare("DELETE FROM validation_counter_evidence WHERE validation_id=?").run(id);
        db.prepare("DELETE FROM finding_causes WHERE validation_id=?").run(id);
      }
      db.prepare("DELETE FROM validation_results WHERE task_id=?").run(taskId);
      db.prepare("DELETE FROM findings WHERE finding_id NOT IN (SELECT finding_id FROM finding_causes)").run();
      deleteEvidence();
      return;
    }
    const semantics = (db.prepare("SELECT semantic_analysis_id FROM semantic_analyses WHERE task_id=?").all(taskId) as { semantic_analysis_id: string }[]).map((row) => row.semantic_analysis_id);
    for (const semanticId of semantics) {
      const groupIds = (db.prepare("SELECT group_id FROM operation_groups WHERE semantic_analysis_id=?").all(semanticId) as { group_id: string }[]).map((row) => row.group_id);
      const callIds = (db.prepare("SELECT component_call_id FROM component_calls WHERE semantic_analysis_id=?").all(semanticId) as { component_call_id: string }[]).map((row) => row.component_call_id);
      for (const groupId of groupIds) {
        const validations = (db.prepare("SELECT validation_id,task_id FROM validation_results WHERE group_id=?").all(groupId) as { validation_id: string; task_id: string }[]);
        for (const validation of validations) {
          db.prepare("DELETE FROM finding_causes WHERE validation_id=?").run(validation.validation_id);
          db.prepare("DELETE FROM validation_counter_evidence WHERE validation_id=?").run(validation.validation_id);
          db.prepare("DELETE FROM evidence_refs WHERE owner_type='validation' AND owner_id=?").run(validation.validation_id);
          db.prepare("DELETE FROM validation_results WHERE validation_id=?").run(validation.validation_id);
        }
        const checks = (db.prepare("SELECT security_check_id FROM security_checks WHERE group_id=?").all(groupId) as { security_check_id: string }[]).map((row) => row.security_check_id);
        for (const check of checks) db.prepare("DELETE FROM evidence_refs WHERE owner_type='security_check' AND owner_id=?").run(check);
        for (const ownerType of ["operation_group", "group_fact", "group_edge"]) db.prepare("DELETE FROM evidence_refs WHERE owner_type=? AND (owner_id=? OR owner_id LIKE ?)").run(ownerType, groupId, `${groupId}:%`);
        db.prepare("DELETE FROM security_checks WHERE group_id=?").run(groupId);
        db.prepare("DELETE FROM group_edges WHERE group_id=?").run(groupId);
        db.prepare("DELETE FROM group_facts WHERE group_id=?").run(groupId);
        db.prepare("DELETE FROM cross_component_groups WHERE group_id=?").run(groupId);
        db.prepare("DELETE FROM operation_groups WHERE group_id=?").run(groupId);
      }
      for (const callId of callIds) {
        const checks = (db.prepare("SELECT security_check_id FROM security_checks WHERE component_call_id=?").all(callId) as { security_check_id: string }[]).map((row) => row.security_check_id);
        for (const check of checks) db.prepare("DELETE FROM evidence_refs WHERE owner_type='security_check' AND owner_id=?").run(check);
        db.prepare("DELETE FROM evidence_refs WHERE owner_type='component_call' AND owner_id=?").run(callId);
        db.prepare("DELETE FROM security_checks WHERE component_call_id=?").run(callId);
        db.prepare("DELETE FROM call_parameters WHERE component_call_id=?").run(callId);
        db.prepare("DELETE FROM component_calls WHERE component_call_id=?").run(callId);
      }
      db.prepare("DELETE FROM semantic_analyses WHERE semantic_analysis_id=?").run(semanticId);
    }
    db.prepare("DELETE FROM findings WHERE finding_id NOT IN (SELECT finding_id FROM finding_causes)").run();
    deleteEvidence();
  }

  cancel(reason = "cancelled_by_user"): Record<string, unknown> {
    const db = this.open();
    try {
      return db.transaction(() => {
        const run = db.prepare("SELECT * FROM runs").get() as Record<string, unknown>;
        if (["complete", "cancelled"].includes(String(run.status))) throw new AuditInvariantError("ILLEGAL_STATE_TRANSITION", { from: run.status, to: "cancelled" });
        const tasks = db.prepare("UPDATE tasks SET status='cancelled',error=?,claimed_at=NULL,lease_expires_at=NULL,worker_id=NULL,updated_at=? WHERE status IN ('queued','running')").run(reason, now()).changes;
        db.prepare("UPDATE runs SET status='cancelled',error=?,updated_at=?").run(reason, now()); this.event(db, "run_cancelled", this.runIdFrom(db), { reason, cancelled_tasks: tasks });
        return { run_id: this.runIdFrom(db), status: "cancelled", cancelled_tasks: tasks };
      })();
    } finally { db.close(); }
  }

  markFailed(error: string): Record<string, unknown> {
    const db = this.open();
    try {
      const changed = db.prepare("UPDATE runs SET status='failed',error=?,updated_at=? WHERE status IN ('created','running')").run(error, now()).changes;
      if (changed) this.event(db, "run_failed", this.runIdFrom(db), { error });
      return db.prepare("SELECT * FROM runs").get() as Record<string, unknown>;
    } finally { db.close(); }
  }

  async finalize(): Promise<Record<string, unknown>> {
    const projectModel = JSON.parse(await readFile(join(this.runDirectory, "project-model.json"), "utf8")) as Record<string, unknown>;
    const db = this.open(); let report: Record<string, unknown>; let status: "complete" | "complete_with_gaps";
    try {
      const unfinished = (db.prepare("SELECT COUNT(*) n FROM tasks WHERE status IN ('queued','running')").get() as { n: number }).n;
      if (unfinished) throw new Error(`run_not_ready:unfinished_tasks=${unfinished}`);
      status = collectCoverageGaps(db).length ? "complete_with_gaps" : "complete";
      report = buildReportModel(db, status, projectModel);
    } finally { db.close(); }
    report = await attachIncrementalReport(this.runDirectory, report);
    await this.writeReportArtifacts(report);
    const completion = this.open();
    try { completion.transaction(() => { const stamp = now(); completion.prepare("UPDATE runs SET status=?,error=NULL,updated_at=?,finalized_at=? WHERE status IN ('running','complete','complete_with_gaps')").run(status, stamp, stamp); this.event(completion, "run_finalized", this.runIdFrom(completion), { status }); })(); } finally { completion.close(); }
    let baseline: Record<string, unknown>;
    try { baseline = await saveIncrementalBaseline(this.runDirectory, report); }
    catch (error) { baseline = { updated: false, reason: "baseline_write_failed", error: error instanceof Error ? error.message : String(error) }; }
    const baselineDb = this.open();
    try { this.event(baselineDb, baseline.updated ? "incremental_baseline_updated" : "incremental_baseline_skipped", this.runIdFrom(baselineDb), baseline); } finally { baselineDb.close(); }
    (report.run as Record<string, unknown>).baseline = baseline;
    return report;
  }

  async rebuildReport(): Promise<Record<string, unknown>> {
    const projectModel = JSON.parse(await readFile(join(this.runDirectory, "project-model.json"), "utf8")) as Record<string, unknown>;
    const db = this.open(); let report: Record<string, unknown>;
    try {
      const status = String((db.prepare("SELECT status FROM runs").get() as { status: string }).status) as "complete" | "complete_with_gaps" | "failed" | "cancelled" | "running";
      report = buildReportModel(db, status, projectModel);
    } finally { db.close(); }
    report = await attachIncrementalReport(this.runDirectory, report);
    await this.writeReportArtifacts(report); return report;
  }

  private async writeReportArtifacts(report: Record<string, unknown>): Promise<void> {
    await writeArtifactsAtomically([
      [this.paths.reportJson, `${JSON.stringify(report, null, 2)}\n`], [this.paths.reportMarkdown, renderMarkdown(report)],
      [this.paths.reportHtml, renderHtml(report)], [this.paths.attackMatrixJson, `${JSON.stringify(attackMatrixDocument(report), null, 2)}\n`],
    ]);
  }
}

async function writeArtifactsAtomically(artifacts: readonly (readonly [string, string])[]): Promise<void> {
  const pending = artifacts.map(([path, content]) => ({ path, content, temporary: `${path}.tmp-${randomUUID()}` }));
  try {
    await Promise.all(pending.map((item) => writeFile(item.temporary, item.content, "utf8")));
    for (const item of pending) await rename(item.temporary, item.path);
  } catch (error) {
    await Promise.all(pending.map((item) => unlink(item.temporary).catch(() => undefined)));
    throw error;
  }
}
