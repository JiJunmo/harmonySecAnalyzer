"""SQLite-backed canonical state for semantic evidence and security validation."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

from .common import *


SCHEMA_VERSION = 13

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
  run_id TEXT PRIMARY KEY,
  target_repo TEXT NOT NULL,
  audit_mode TEXT NOT NULL CHECK(audit_mode IN ('full','capability')),
  capability_filter_json TEXT NOT NULL,
  component_filter_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('created','running','complete','failed')),
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finalized_at TEXT
);
CREATE TABLE IF NOT EXISTS entries(
  entry_id TEXT PRIMARY KEY,
  entry_key TEXT NOT NULL UNIQUE,
  component TEXT,
  symbol TEXT NOT NULL,
  facets_json TEXT NOT NULL,
  reachability TEXT NOT NULL,
  profiles_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks(
  task_id TEXT PRIMARY KEY,
  semantic_key TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  subject_id TEXT,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','exhausted')),
  agent TEXT NOT NULL,
  input_json TEXT NOT NULL,
  result_ref TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence(
  evidence_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  kind TEXT NOT NULL,
  source TEXT NOT NULL,
  location TEXT,
  summary TEXT NOT NULL,
  content_ref TEXT,
  sha256 TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS semantic_analyses(
  entry_id TEXT PRIMARY KEY REFERENCES entries(entry_id) ON DELETE CASCADE,
  task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
  summary TEXT NOT NULL,
  coverage_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operation_groups(
  group_id TEXT PRIMARY KEY,
  identity_key TEXT NOT NULL UNIQUE,
  entry_id TEXT NOT NULL REFERENCES entries(entry_id) ON DELETE CASCADE,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  capability_id TEXT,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  operation_body TEXT NOT NULL,
  operation_location TEXT NOT NULL,
  controlled_properties_json TEXT NOT NULL,
  context_json TEXT NOT NULL,
  guards_json TEXT NOT NULL,
  branches_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS validation_results(
  group_id TEXT PRIMARY KEY REFERENCES operation_groups(group_id) ON DELETE CASCADE,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  capability_id TEXT,
  pattern_id TEXT,
  classification TEXT NOT NULL CHECK(classification IN ('confirmed_vulnerability','protected_exposure','benign_business_flow','insufficient_evidence','residual_risk')),
  title TEXT NOT NULL,
  guard_outcome TEXT NOT NULL CHECK(guard_outcome IN ('absent','bypassable','effective','unknown')),
  boundary TEXT NOT NULL,
  exploitability_json TEXT NOT NULL,
  business_intent_json TEXT NOT NULL,
  security_boundary_json TEXT NOT NULL,
  counter_evidence_json TEXT NOT NULL,
  severity TEXT,
  cwe TEXT,
  impact TEXT,
  poc TEXT,
  demotion_reason TEXT,
  evidence_gap TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_facts(
  fact_id TEXT PRIMARY KEY,
  fact_key TEXT NOT NULL,
  group_id TEXT NOT NULL REFERENCES operation_groups(group_id) ON DELETE CASCADE,
  fact_type TEXT NOT NULL CHECK(fact_type IN ('entrypoint','reachability','control','transform','guard','operation','effect','dead_end','gap')),
  body TEXT NOT NULL,
  location TEXT,
  evidence_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(group_id, fact_key)
);
CREATE TABLE IF NOT EXISTS group_edges(
  edge_id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL REFERENCES operation_groups(group_id) ON DELETE CASCADE,
  from_fact_id TEXT NOT NULL REFERENCES group_facts(fact_id),
  to_fact_id TEXT NOT NULL REFERENCES group_facts(fact_id),
  kind TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(group_id, from_fact_id, to_fact_id, kind),
  CHECK(from_fact_id <> to_fact_id)
);
CREATE TABLE IF NOT EXISTS findings(
  finding_id TEXT PRIMARY KEY,
  root_cause_key TEXT NOT NULL UNIQUE,
  group_id TEXT NOT NULL REFERENCES operation_groups(group_id),
  classification TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT,
  cwe TEXT,
  impact TEXT,
  poc TEXT,
  boundary TEXT NOT NULL,
  controlled_properties_json TEXT NOT NULL,
  operation_location TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  subject_id TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, created_at);
CREATE INDEX IF NOT EXISTS idx_groups_entry ON operation_groups(entry_id, category);
CREATE INDEX IF NOT EXISTS idx_validations_class ON validation_results(classification);
CREATE INDEX IF NOT EXISTS idx_group_facts_type ON group_facts(group_id, fact_type);
"""


def connect(db_path):
    conn = sqlite3.connect(str(db_path), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


@contextmanager
def database(db_path):
    conn = connect(db_path)
    try:
        try:
            row = conn.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
        except sqlite3.OperationalError as error:
            raise ValueError("missing_runtime_schema") from error
        if row is None or row["version"] != SCHEMA_VERSION:
            actual = row["version"] if row else "missing"
            raise ValueError(f"unsupported_schema_version:{actual}:expected:{SCHEMA_VERSION}")
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(conn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()


def initialize_database(db_path):
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
        if row is None:
            conn.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
        elif row["version"] != SCHEMA_VERSION:
            raise ValueError(f"unsupported_schema_version:{row['version']}")
    finally:
        conn.close()


def append_event(conn, event_type, subject_id=None, payload=None):
    conn.execute(
        "INSERT INTO events(event_type,subject_id,payload_json,created_at) VALUES (?,?,?,?)",
        (event_type, subject_id, canonical_json(payload or {}), now()),
    )


def enqueue_task(conn, semantic_key, kind, subject_id=None, payload=None):
    task_id = stable_id("TASK", semantic_key)
    stamp = now()
    cursor = conn.execute(
        """INSERT OR IGNORE INTO tasks
           (task_id,semantic_key,kind,subject_id,status,agent,input_json,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (task_id, semantic_key, kind, subject_id, "queued", TASK_AGENTS[kind], canonical_json(payload or {}), stamp, stamp),
    )
    if cursor.rowcount:
        append_event(conn, "task_planned", task_id, {"semantic_key": semantic_key, "kind": kind})
    return task_id


def row_json(row, key, default=None):
    try:
        return json.loads(row[key])
    except (KeyError, TypeError, ValueError):
        return default


def task_document(row):
    return {
        "task_id": row["task_id"],
        "semantic_key": row["semantic_key"],
        "kind": row["kind"],
        "subject_id": row["subject_id"],
        "assigned_agent": row["agent"],
        "attempt": row["attempts"],
        "previous_error": row["error"],
        "input": row_json(row, "input_json", {}),
    }
