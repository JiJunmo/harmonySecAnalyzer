import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".opencode/skills/audit-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_runtime.commands import claim_tasks, finalize_run, initialize_run, new_run, readiness, status, submit_result
from audit_runtime.store import database, enqueue_task, transaction


class FlowRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.model = self.root / "project_model.json"
        self.model.write_text(json.dumps({
            "schema_version": 1,
            "status": "complete",
            "target_repo": str(self.target),
            "application": {"bundle_name": "com.example.flow"},
            "summary": {"modules": 1, "entry_candidates": 1},
            "entry_candidates": [{"candidate_id": "PE-001", "type": "deeplink"}],
        }), encoding="utf-8")
        allocated = new_run(self.root / "reports", self.target, "capability", ["CAP-INJ-001"])
        self.run = Path(allocated["run_dir"])
        initialize_run(self.run, self.model)

    def tearDown(self):
        self.temp.cleanup()

    def write_result(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def claim_one(self, kind):
        payload = claim_tasks(self.run, 5)
        self.assertEqual(payload["count"], 1, payload)
        handle = payload["tasks"][0]
        self.assertEqual(handle["kind"], kind)
        self.assertNotIn("input", handle)
        self.assertTrue(Path(handle["submission_file"]).is_absolute())
        task = json.loads(Path(handle["task_file"]).read_text(encoding="utf-8"))
        self.assertEqual(task["submission_file"], handle["submission_file"])
        self.assertEqual(task["result_schema_file"], handle["result_schema_file"])
        return task

    def test_complete_flow_and_report(self):
        planner = self.claim_one("entry_planning")
        submit_result(self.run, planner["task_id"], self.write_result("entry.json", {
            "task_id": planner["task_id"],
            "entries": [{
                "entry_key": "deeplink|EntryAbility.onNewWant|scheme=demo",
                "entry_type": "deeplink", "component": "EntryAbility", "symbol": "EntryAbility.onNewWant",
                "discriminator": {"scheme": "demo"}, "transport": "uri", "external_reachability": "reachable",
                "project_candidate_ids": ["PE-001"], "evidence_refs": ["EV-ENTRY"],
            }],
            "excluded_candidates": [], "gaps": [],
            "evidence": [{"evidence_id": "EV-ENTRY", "kind": "atlas_symbol", "source": "atlas", "summary": "onNewWant handles demo URI"}],
        }))

        explorer = self.claim_one("entry_exploration")
        entry_id = explorer["subject_id"]
        submit_result(self.run, explorer["task_id"], self.write_result("flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-FLOW", "kind": "atlas_path", "source": "atlas", "summary": "URI reaches dynamic query"}],
            "flows": [{
                "flow_key": "flow|demo|query", "root_entry_id": entry_id, "branch_key": "route=demo",
                "controlled_property": "uri.query", "current_symbol": "Db.query", "status": "connected",
                "controlled_values": ["uri.query"],
                "facts": [
                    {"fact_key": "f-entry", "type": "entrypoint", "body": "external URI", "evidence_refs": ["EV-FLOW"]},
                    {"fact_key": "f-op", "type": "operation", "body": "dynamic database query", "location": "Db.ets:42", "evidence_refs": ["EV-FLOW"]},
                    {"fact_key": "f-effect", "type": "effect", "body": "records returned", "evidence_refs": ["EV-FLOW"]},
                ],
                "edges": [
                    {"from": "f-entry", "to": "f-op", "kind": "carry", "evidence_refs": ["EV-FLOW"]},
                    {"from": "f-op", "to": "f-effect", "kind": "causes", "evidence_refs": ["EV-FLOW"]},
                ],
                "continuations": [],
            }],
        }))

        evaluator = self.claim_one("pattern_evaluation")
        flow_id = evaluator["subject_id"]
        flow_evidence = evaluator["input"]["flow"]["facts"][0]["evidence_refs"][0]
        submit_result(self.run, evaluator["task_id"], self.write_result("pattern.json", {
            "task_id": evaluator["task_id"], "flow_id": flow_id,
            "assessments": [{
                "capability_id": "CAP-INJ-001", "pattern_id": "deeplink-injection", "verdict": "supported",
                "boundary": "database_query", "reason": "Untrusted query reaches dynamic operation", "evidence_refs": [flow_evidence],
            }],
        }))

        validator = self.claim_one("flow_validation")
        submit_result(self.run, validator["task_id"], self.write_result("validation.json", {
            "task_id": validator["task_id"], "flow_id": flow_id, "classification": "confirmed_vulnerability",
            "title": "Untrusted deeplink query reaches database", "severity": "high", "cwe": "CWE-89",
            "impact": "Unauthorized record disclosure", "poc": "demo://host?q=...", "boundary": "database_query",
            "gates": {"externally_reachable": True, "attacker_controlled": True, "operation_reached": True,
                      "guard_absent_or_bypassed": True, "boundary_violated": True, "observable_effect": True},
            "root_cause": {"operation_location": "Db.ets:42", "branch": "route=demo", "boundary": "database_query", "controlled_property": "uri.query"},
            "guards": [], "reason": "All exploitability gates are evidenced", "evidence_refs": [flow_evidence],
        }))

        self.assertTrue(readiness(self.run)["ready"])
        final = finalize_run(self.run)
        self.assertEqual(final["summary"]["findings"], 1)
        self.assertTrue((self.run / "report.html").is_file())
        self.assertTrue((self.run / "exports/attack_matrix.json").is_file())
        html = (self.run / "report.html").read_text(encoding="utf-8")
        self.assertIn(f'href="#{flow_id}"', html)
        self.assertIn(f'<details id="{flow_id}"', html)

    def test_invalid_submission_is_atomic(self):
        planner = self.claim_one("entry_planning")
        with self.assertRaisesRegex(ValueError, "unaccounted_project_candidates"):
            submit_result(self.run, planner["task_id"], self.write_result("bad.json", {
                "task_id": planner["task_id"], "entries": [], "excluded_candidates": [], "gaps": []
            }))
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT status FROM tasks WHERE task_id=?", (planner["task_id"],)).fetchone()[0], "running")

    def test_one_project_candidate_can_expand_to_multiple_canonical_entries(self):
        planner = self.claim_one("entry_planning")
        base = {
            "entry_type": "ipc_transaction", "component": "BackupService", "symbol": "onRemoteRequest",
            "transport": "ipc", "external_reachability": "reachable",
            "project_candidate_ids": ["PE-001"], "evidence_refs": ["EV-ENTRY"],
        }
        submit_result(self.run, planner["task_id"], self.write_result("split-entry.json", {
            "task_id": planner["task_id"],
            "entries": [
                {**base, "entry_key": "ipc|BackupService|code=100", "discriminator": {"code": 100}},
                {**base, "entry_key": "ipc|BackupService|code=200", "discriminator": {"code": 200}},
            ],
            "excluded_candidates": [], "gaps": [],
            "evidence": [{
                "evidence_id": "EV-ENTRY", "kind": "atlas_symbol", "source": "atlas",
                "summary": "IPC dispatcher",
            }],
        }))
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 2)
            disposition = conn.execute(
                "SELECT disposition,entry_id FROM entry_dispositions WHERE project_candidate_id='PE-001'"
            ).fetchone()
            self.assertEqual(disposition, ("resolved_entry", None))

    def test_continuation_can_link_to_ancestor_fact(self):
        planner = self.claim_one("entry_planning")
        submit_result(self.run, planner["task_id"], self.write_result("continuation-entry.json", {
            "task_id": planner["task_id"],
            "entries": [{
                "entry_key": "deeplink|EntryAbility.onNewWant|scheme=demo", "entry_type": "deeplink",
                "component": "EntryAbility", "symbol": "EntryAbility.onNewWant",
                "discriminator": {"scheme": "demo"}, "transport": "uri",
                "external_reachability": "reachable", "project_candidate_ids": ["PE-001"],
                "evidence_refs": ["EV-ENTRY"],
            }],
            "excluded_candidates": [], "gaps": [],
            "evidence": [{"evidence_id": "EV-ENTRY", "kind": "atlas_symbol", "source": "atlas", "summary": "entry"}],
        }))

        explorer = self.claim_one("entry_exploration")
        entry_id = explorer["subject_id"]
        submit_result(self.run, explorer["task_id"], self.write_result("parent-flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-PARENT", "kind": "atlas_path", "source": "atlas", "summary": "dispatch"}],
            "flows": [{
                "flow_key": "parent", "root_entry_id": entry_id, "branch_key": "code=CODE(1)",
                "controlled_property": "uri.query", "current_symbol": "Shared.run", "status": "connected",
                "controlled_values": ["uri.query"],
                "facts": [{"fact_key": "f-entry", "type": "entrypoint", "body": "external URI", "evidence_refs": ["EV-PARENT"]}],
                "edges": [],
                "continuations": [{
                    "semantic_key": "shared-run", "kind": "shared_handler", "target": "Shared.run",
                    "reason": "shared dispatch", "evidence_refs": ["EV-PARENT"],
                }],
            }],
        }))
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            self.assertEqual(conn.execute("SELECT status FROM flows WHERE flow_key LIKE '%parent%' ").fetchone()[0], "open")

        continuation = self.claim_one("shared_handler")
        parent_flow_id = continuation["input"]["continuations"][0]["parent_flow"]["flow_id"]
        submit_result(self.run, continuation["task_id"], self.write_result("child-flow.json", {
            "task_id": continuation["task_id"],
            "evidence": [{"evidence_id": "EV-CHILD", "kind": "atlas_path", "source": "atlas", "summary": "effect"}],
            "flows": [{
                "flow_key": "child", "root_entry_id": entry_id, "parent_flow_id": parent_flow_id,
                "branch_key": "code=CODE(1)", "controlled_property": "uri.query",
                "current_symbol": "Db.query", "status": "connected", "controlled_values": ["uri.query"],
                "facts": [
                    {"fact_key": "f-op", "type": "operation", "body": "query", "evidence_refs": ["EV-CHILD"]},
                    {"fact_key": "f-effect", "type": "effect", "body": "records", "evidence_refs": ["EV-CHILD"]},
                ],
                "edges": [
                    {"from": "f-entry", "to": "f-op", "kind": "enables", "evidence_refs": ["EV-CHILD"]},
                    {"from": "f-op", "to": "f-effect", "kind": "causes", "evidence_refs": ["EV-CHILD"]},
                ],
                "continuations": [],
            }],
        }))

    def test_duplicate_runs_are_isolated(self):
        other = new_run(self.root / "reports", self.target)
        self.assertNotEqual(str(self.run), other["run_dir"])

    def test_model_can_be_initialized_in_place(self):
        allocated = new_run(self.root / "reports", self.target)
        run = Path(allocated["run_dir"])
        destination = run / "project/project_model.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.model.read_text(encoding="utf-8"), encoding="utf-8")
        result = initialize_run(run, destination)
        self.assertTrue(result["ok"])

    def test_component_filter_selects_candidates_before_entry_planning(self):
        model = self.root / "component-model.json"
        model.write_text(json.dumps({
            "schema_version": 1, "status": "complete", "target_repo": str(self.target),
            "entry_candidates": [
                {"candidate_id": "PE-ENTRY", "type": "exported_component", "module_name": "entry", "component_name": "EntryAbility"},
                {"candidate_id": "PE-SERVICE", "type": "ipc_service_candidate", "module_name": "service", "component_name": "BackupExtensionAbility"},
            ],
        }), encoding="utf-8")
        allocated = new_run(
            self.root / "component-reports", self.target, "capability", ["CAP-INJ-001"],
            ["service/BackupExtensionAbility"],
        )
        run = Path(allocated["run_dir"])
        initialized = initialize_run(run, model)
        self.assertEqual(initialized["entry_candidates"], 1)
        handle = claim_tasks(run, 5)["tasks"][0]
        task = json.loads(Path(handle["task_file"]).read_text(encoding="utf-8"))
        self.assertEqual([row["candidate_id"] for row in task["input"]["entry_candidates"]], ["PE-SERVICE"])
        run_status = status(run)["run"]
        self.assertEqual(run_status["component_filter"], ["service/BackupExtensionAbility"])
        self.assertEqual(run_status["capability_filter"], ["CAP-INJ-001"])

    def test_component_filter_rejects_unknown_or_non_auditable_component(self):
        allocated = new_run(self.root / "missing-reports", self.target, components=["MissingAbility"])
        with self.assertRaisesRegex(ValueError, "component_has_no_entry_candidates:MissingAbility"):
            initialize_run(allocated["run_dir"], self.model)

    def test_claim_enforces_global_worker_pool_and_reclaims_expired_lease(self):
        first = claim_tasks(self.run, 5)
        self.assertEqual(first["running"], 1)
        with database(self.run / "run.db") as conn, transaction(conn):
            for index in range(7):
                enqueue_task(conn, f"pool-test-{index}", "entry_planning")

        claimed = claim_tasks(self.run, 5)
        self.assertEqual(claimed["count"], 4)
        self.assertEqual(claimed["running"], 5)
        full = claim_tasks(self.run, 5)
        self.assertEqual(full["reason"], "worker_pool_full")
        self.assertEqual(full["count"], 0)

        expired_id = claimed["tasks"][0]["task_id"]
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            conn.execute("UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE task_id=?", (expired_id,))
            conn.commit()
        recovered = claim_tasks(self.run, 5)
        self.assertIn(expired_id, recovered["reclaimed"])
        self.assertEqual(recovered["running"], 5)

    def test_retry_task_carries_previous_error_and_discards_stale_submission(self):
        claimed = self.claim_one("entry_planning")
        stale = Path(claimed["submission_file"])
        stale.write_text("{}", encoding="utf-8")
        from audit_runtime.commands import fail_task
        fail_task(self.run, claimed["task_id"], "conflicting_project_candidates:PE-001", retryable=True)

        retried = claim_tasks(self.run, 5)["tasks"][0]
        task = json.loads(Path(retried["task_file"]).read_text(encoding="utf-8"))
        self.assertEqual(task["attempt"], 2)
        self.assertEqual(task["previous_error"], "conflicting_project_candidates:PE-001")
        self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
