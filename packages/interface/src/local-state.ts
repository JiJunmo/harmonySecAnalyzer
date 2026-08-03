import { appendFileSync } from "node:fs";
import { mkdir, rename, stat, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import Database from "better-sqlite3";
import { sanitizeAgentTraceValue, type PluginLogger, type SubagentRunView } from "@agent-platform/core";
import type { HostRunRepository, HostRunView } from "./service.js";

export interface LocalReliabilityConfig {
  readonly dataDirectory?: string;
  readonly retentionDays?: number;
  readonly maxHostRuns?: number;
  readonly maxSubagentRuns?: number;
  readonly logMaxBytes?: number;
}

export interface LocalPruneResult {
  readonly hostRuns: number;
  readonly subagentRuns: number;
  readonly cutoff: string;
}

const schema = `
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS host_runs(id TEXT PRIMARY KEY,plugin_id TEXT NOT NULL,status TEXT NOT NULL,document_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_host_runs_updated ON host_runs(updated_at);
CREATE TABLE IF NOT EXISTS subagent_runs(id TEXT PRIMARY KEY,parent_session_id TEXT NOT NULL,status TEXT NOT NULL,document_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_subagent_runs_updated ON subagent_runs(updated_at);
CREATE TABLE IF NOT EXISTS gateway_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
`;

const terminalHost = new Set(["succeeded", "failed", "cancelled"]);
const terminalSubagent = new Set(["succeeded", "failed", "aborted"]);
const positive = (value: number | undefined, fallback: number, name: string): number => {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < 1) throw new Error(`reliability_${name}_invalid`);
  return result;
};

export class LocalGatewayState {
  readonly directory: string;
  readonly databasePath: string;
  readonly logPath: string;
  readonly #db: Database.Database;
  readonly #retentionDays: number;
  readonly #maxHostRuns: number;
  readonly #maxSubagentRuns: number;
  readonly #logMaxBytes: number;
  #closed = false;

  private constructor(directory: string, db: Database.Database, config: LocalReliabilityConfig) {
    this.directory = directory;
    this.databasePath = join(directory, "gateway.db");
    this.logPath = join(directory, "gateway.log");
    this.#db = db;
    this.#retentionDays = positive(config.retentionDays, 90, "retention_days");
    this.#maxHostRuns = positive(config.maxHostRuns, 500, "max_host_runs");
    this.#maxSubagentRuns = positive(config.maxSubagentRuns, 500, "max_subagent_runs");
    this.#logMaxBytes = positive(config.logMaxBytes, 10 * 1024 * 1024, "log_max_bytes");
  }

  static async open(directory: string, config: LocalReliabilityConfig = {}): Promise<LocalGatewayState> {
    const root = resolve(directory);
    await mkdir(root, { recursive: true, mode: 0o700 });
    const logPath = join(root, "gateway.log");
    const logSize = (await stat(logPath).catch(() => undefined))?.size ?? 0;
    if (logSize > (config.logMaxBytes ?? 10 * 1024 * 1024)) {
      await unlink(`${logPath}.1`).catch(() => undefined);
      await rename(logPath, `${logPath}.1`);
    }
    const db = new Database(join(root, "gateway.db"));
    db.pragma("journal_mode = WAL"); db.pragma("foreign_keys = ON"); db.pragma("busy_timeout = 5000");
    db.exec(schema);
    const version = db.prepare("SELECT version FROM schema_meta LIMIT 1").get() as { version: number } | undefined;
    if (!version) db.prepare("INSERT INTO schema_meta VALUES (?,?)").run(1, new Date().toISOString());
    else if (version.version !== 1) { db.close(); throw new Error(`gateway_state_schema_unsupported:${version.version}`); }
    const state = new LocalGatewayState(root, db, config);
    state.#db.prepare("INSERT OR REPLACE INTO gateway_meta VALUES ('last_started_at',?)").run(new Date().toISOString());
    state.prune();
    return state;
  }

  hostRuns(): HostRunRepository {
    const parse = <T>(value: string): T | undefined => { try { return JSON.parse(value) as T; } catch { return undefined; } };
    return Object.freeze({
      load: () => Object.freeze((this.#db.prepare("SELECT document_json FROM host_runs ORDER BY created_at DESC LIMIT ?").all(this.#maxHostRuns) as { document_json: string }[]).map((row) => parse<HostRunView>(row.document_json)).filter((run): run is HostRunView => !!run)),
      save: (run: HostRunView) => this.#db.prepare("INSERT INTO host_runs VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET plugin_id=excluded.plugin_id,status=excluded.status,document_json=excluded.document_json,updated_at=excluded.updated_at")
        .run(run.id, run.pluginId, run.status, JSON.stringify(run), run.createdAt, run.updatedAt),
    });
  }

  restoredSubagents(): readonly SubagentRunView[] {
    return Object.freeze((this.#db.prepare("SELECT document_json FROM subagent_runs ORDER BY created_at DESC LIMIT ?").all(this.#maxSubagentRuns) as { document_json: string }[]).flatMap((row) => {
      try { return [JSON.parse(row.document_json) as SubagentRunView]; } catch { return []; }
    }));
  }

  saveSubagent(run: SubagentRunView): void {
    const updatedAt = run.finishedAt ?? run.startedAt ?? run.createdAt;
    this.#db.prepare("INSERT INTO subagent_runs VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET parent_session_id=excluded.parent_session_id,status=excluded.status,document_json=excluded.document_json,updated_at=excluded.updated_at")
      .run(run.id, run.parentSessionId, run.status, JSON.stringify(run), run.createdAt, updatedAt);
  }

  logger(): PluginLogger {
    const write = (level: string, message: string, data?: Readonly<Record<string, unknown>>) => {
      if (this.#closed) return;
      const line = JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...(data ? { data: sanitizeAgentTraceValue(data) } : {}) });
      try { appendFileSync(this.logPath, `${line}\n`, { encoding: "utf8", mode: 0o600 }); } catch { /* Logging must not crash the gateway. */ }
    };
    const logger: PluginLogger = {
      debug: (message: string, data?: Readonly<Record<string, unknown>>) => write("debug", message, data),
      info: (message: string, data?: Readonly<Record<string, unknown>>) => write("info", message, data),
      warn: (message: string, data?: Readonly<Record<string, unknown>>) => write("warn", message, data),
      error: (message: string, data?: Readonly<Record<string, unknown>>) => write("error", message, data),
    };
    return Object.freeze(logger);
  }

  prune(at = new Date()): LocalPruneResult {
    const cutoff = new Date(at.getTime() - this.#retentionDays * 86_400_000).toISOString();
    const remove = (table: "host_runs" | "subagent_runs", terminal: ReadonlySet<string>, maximum: number): number => {
      let deleted = 0;
      const old = this.#db.prepare(`SELECT id,status FROM ${table} WHERE updated_at<? ORDER BY updated_at`).all(cutoff) as { id: string; status: string }[];
      for (const row of old) if (terminal.has(row.status)) deleted += this.#db.prepare(`DELETE FROM ${table} WHERE id=?`).run(row.id).changes;
      const overflow = this.#db.prepare(`SELECT id,status FROM ${table} ORDER BY updated_at DESC LIMIT -1 OFFSET ?`).all(maximum) as { id: string; status: string }[];
      for (const row of overflow) if (terminal.has(row.status)) deleted += this.#db.prepare(`DELETE FROM ${table} WHERE id=?`).run(row.id).changes;
      return deleted;
    };
    const result = { hostRuns: remove("host_runs", terminalHost, this.#maxHostRuns), subagentRuns: remove("subagent_runs", terminalSubagent, this.#maxSubagentRuns), cutoff };
    this.#db.prepare("INSERT OR REPLACE INTO gateway_meta VALUES ('last_pruned_at',?)").run(at.toISOString());
    return Object.freeze(result);
  }

  async diagnostics(): Promise<Readonly<Record<string, unknown>>> {
    const scalar = (table: string) => Number((this.#db.prepare(`SELECT COUNT(*) count FROM ${table}`).get() as { count: number }).count);
    const meta = Object.fromEntries((this.#db.prepare("SELECT key,value FROM gateway_meta").all() as { key: string; value: string }[]).map((row) => [row.key, row.value]));
    return Object.freeze({
      status: "ok", dataDirectory: this.directory, databasePath: this.databasePath, logPath: this.logPath,
      databaseBytes: (await stat(this.databasePath).catch(() => undefined))?.size ?? 0,
      logBytes: (await stat(this.logPath).catch(() => undefined))?.size ?? 0,
      hostRuns: scalar("host_runs"), subagentRuns: scalar("subagent_runs"),
      retention: { days: this.#retentionDays, maxHostRuns: this.#maxHostRuns, maxSubagentRuns: this.#maxSubagentRuns }, ...meta,
    });
  }

  close(): void { if (this.#closed) return; this.#closed = true; this.#db.close(); }
}
