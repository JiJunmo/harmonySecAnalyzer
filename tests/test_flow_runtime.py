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

from audit_runtime.commands import (
    build_report_ready, claim_tasks, finalize_run, initialize_run, new_run,
    readiness, status, submit_result,
)
from audit_runtime.cli import parser as runtime_parser
from audit_runtime.common import SIX_EXPLOITABILITY_CHECKS, flow_identity_key, handler_identity
from audit_runtime.contracts import validate_security_assessment, validate_submission
from audit_runtime.initialization import prepare_run
from audit_runtime.reporting import finding_sort_key
from audit_runtime.scheduler import next_task, recover_tasks
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

    def create_assessment_task(self):
        resolver = self.claim_one("entry_resolution")
        accepted = submit_result(self.run, resolver["task_id"], self.write_result("gap-entry.json", {
            "task_id": resolver["task_id"],
            "entries": [{
                "entry_key": "deeplink|EntryAbility.onNewWant|scheme=demo",
                "entry_type": "deeplink", "component": "EntryAbility",
                "symbol": "EntryAbility.onNewWant", "discriminator": {"scheme": "demo"},
                "transport": "uri", "external_reachability": "reachable",
                "project_candidate_ids": ["PE-001"], "evidence_refs": [],
            }],
            "excluded_candidates": [], "gaps": [],
        }))
        self.assertTrue(accepted["accepted"], accepted)
        explorer = self.claim_one("entry_path_discovery")
        accepted = submit_result(self.run, explorer["task_id"], self.write_result("gap-flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-GAP", "kind": "atlas_path", "source": "atlas", "summary": "path"}],
            "flows": [{
                "root_entry_id": explorer["subject_id"], "branch_key": "route=demo",
                "controlled_property": "uri.query", "current_symbol": "Db.query",
                "status": "reached", "controlled_values": ["uri.query"],
                "facts": [
                    {"fact_key": "f-op", "type": "operation", "body": "query", "location": "Db.ets:42", "evidence_refs": ["EV-GAP"]},
                    {"fact_key": "f-effect", "type": "effect", "body": "records", "evidence_refs": ["EV-GAP"]},
                ],
                "edges": [{"from": "f-op", "to": "f-effect", "kind": "causes", "evidence_refs": ["EV-GAP"]}],
                "continuations": [],
            }],
        }))
        self.assertTrue(accepted["accepted"], accepted)
        return self.claim_one("security_assessment")

    @staticmethod
    def exploitability(**values):
        return {name: values.get(name, True) for name in SIX_EXPLOITABILITY_CHECKS}

    def assessment(self, task, classification, evidence_ref, operation_fact_id, **check_values):
        path = task["input"]["path"]
        operation = next((fact for fact in path["facts"] if fact["fact_id"] == operation_fact_id), None)
        result = {
            "capability_id": "CAP-INJ-001", "pattern_id": "deeplink-injection",
            "category": "injection", "operation_fact_id": operation_fact_id,
            "classification": classification, "title": "Deeplink database assessment",
            "exploitability": self.exploitability(**check_values),
            "root_cause": {
                "operation_location": (operation or {}).get("location") or path["current_symbol"],
                "branch": path["branch_key"], "boundary": "database_query",
                "controlled_property": path["controlled_property"],
            },
            "guards": [], "counter_evidence": [], "evidence_refs": [evidence_ref],
        }
        if classification == "confirmed_vulnerability":
            result.update({
                "security_boundary": {
                    "type": "data_owner", "expected_boundary": "External callers cannot query private records",
                    "violation": True, "reason": "Controlled query crosses record ownership",
                    "evidence_refs": [evidence_ref],
                },
                "impact": "Unauthorized record disclosure", "severity": "high", "cwe": "CWE-89",
                "poc": "demo://host?q=...",
            })
        else:
            result["demotion_reason"] = "The path does not cross the expected security boundary"
            result["security_boundary"] = {
                "type": "business_authorization", "expected_boundary": "Only public records may be selected",
                "violation": result["exploitability"]["boundary_violated"],
                "reason": "The selected route remains within the public business contract",
                "evidence_refs": [evidence_ref],
            }
        if classification == "benign_business_flow":
            result["business_intent"] = {
                "is_public_api": True, "declared_or_inferred_purpose": "Open a public record",
                "allowed_controls": ["recordId"], "evidence_refs": [evidence_ref],
            }
            result["counter_evidence"] = [{
                "kind": "business_intent", "reason": "The input selects only a public record",
                "evidence_refs": [evidence_ref],
            }]
        return result

    def test_complete_flow_and_report(self):
        resolver = self.claim_one("entry_resolution")
        submit_result(self.run, resolver["task_id"], self.write_result("entry.json", {
            "task_id": resolver["task_id"],
            "entries": [{
                "entry_key": "deeplink|EntryAbility.onNewWant|scheme=demo",
                "entry_type": "deeplink", "component": "EntryAbility", "symbol": "EntryAbility.onNewWant",
                "discriminator": {"scheme": "demo"}, "transport": "uri", "external_reachability": "reachable",
                "project_candidate_ids": ["PE-001"], "evidence_refs": ["EV-ENTRY"],
            }],
            "excluded_candidates": [], "gaps": [],
            "evidence": [{"evidence_id": "EV-ENTRY", "kind": "atlas_symbol", "source": "atlas", "summary": "onNewWant handles demo URI"}],
        }))

        explorer = self.claim_one("entry_path_discovery")
        entry_id = explorer["subject_id"]
        submit_result(self.run, explorer["task_id"], self.write_result("flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-FLOW", "kind": "atlas_path", "source": "atlas", "summary": "URI reaches dynamic query"}],
            "flows": [{
                "root_entry_id": "EntryAbility", "branch_key": "route=demo",
                "controlled_property": "uri.query", "current_symbol": "Db.query", "status": "reached",
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

        assessor = self.claim_one("security_assessment")
        path_id = assessor["subject_id"]
        self.assertEqual(
            [row["pattern_id"] for row in assessor["input"]["pattern_cards"]],
            ["deeplink-injection"],
        )
        self.assertIn("## 必须证明", assessor["input"]["pattern_cards"][0]["content"])
        flow_evidence = assessor["input"]["path"]["facts"][0]["evidence_refs"][0]
        operation_fact_id = next(
            fact["fact_id"] for fact in assessor["input"]["path"]["facts"] if fact["fact_type"] == "operation"
        )
        submit_result(self.run, assessor["task_id"], self.write_result("assessment.json", {
            "task_id": assessor["task_id"], "path_id": path_id,
            "summary": "The path matches injection and all six exploitability checks pass.",
            "assessments": [self.assessment(
                assessor, "confirmed_vulnerability", flow_evidence, operation_fact_id,
            )],
            "evidence": [],
        }))

        self.assertTrue(readiness(self.run)["ready"])
        final = finalize_run(self.run)
        self.assertEqual(final["summary"]["findings"], 1)
        self.assertEqual(final["summary"]["validation_results"], 1)
        self.assertEqual(final["summary"]["confirmed_vulnerabilities"], 1)
        self.assertTrue((self.run / "report.html").is_file())
        self.assertTrue((self.run / "exports/attack_matrix.json").is_file())
        exported = json.loads((self.run / "exports/assessments.json").read_text(encoding="utf-8"))["items"][0]
        self.assertTrue(all(exported["exploitability"].values()))
        self.assertTrue(exported["security_boundary"]["violation"])
        self.assertEqual(exported["counter_evidence"], [])
        html = (self.run / "report.html").read_text(encoding="utf-8")
        self.assertIn(path_id, html)
        for view in ("概览", "攻击路径", "项目结构", "覆盖与缺口"):
            self.assertIn(view, html)
        self.assertIn('id="path-body"', html)
        self.assertIn('id="drawer-backdrop"', html)
        for detail in ("六维有效性验证", "判定证据", "路径事实"):
            self.assertIn(detail, html)

    def test_report_finding_sort_uses_security_severity_order(self):
        rows = [
            {"classification": "confirmed_vulnerability", "severity": severity, "title": severity}
            for severity in ("low", "critical", "medium", "high")
        ]
        self.assertEqual(
            [row["severity"] for row in sorted(rows, key=finding_sort_key)],
            ["critical", "high", "medium", "low"],
        )

    def test_build_report_requires_ready_run(self):
        with self.assertRaisesRegex(ValueError, "run_not_ready:unfinished_tasks"):
            build_report_ready(self.run)
        self.assertFalse((self.run / "report.html").exists())

    def test_empty_security_assessment_completes_path_without_finding(self):
        resolver = self.claim_one("entry_resolution")
        submit_result(self.run, resolver["task_id"], self.write_result("negative-entry.json", {
            "task_id": resolver["task_id"],
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
        explorer = self.claim_one("entry_path_discovery")
        entry_id = explorer["subject_id"]
        submit_result(self.run, explorer["task_id"], self.write_result("negative-flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-FLOW", "kind": "atlas_path", "source": "atlas", "summary": "guarded query"}],
            "flows": [{
                "root_entry_id": entry_id, "branch_key": "route=demo",
                "controlled_property": "uri.query", "current_symbol": "Db.query", "status": "stopped",
                "controlled_values": ["uri.query"],
                "facts": [
                    {"fact_key": "f-entry", "type": "entrypoint", "body": "external URI", "evidence_refs": ["EV-FLOW"]},
                    {"fact_key": "f-guard", "type": "guard", "body": "allowlist rejects input", "evidence_refs": ["EV-FLOW"]},
                ],
                "edges": [{"from": "f-entry", "to": "f-guard", "kind": "blocked_by", "evidence_refs": ["EV-FLOW"]}],
                "continuations": [],
            }],
        }))
        assessor = self.claim_one("security_assessment")
        result = submit_result(self.run, assessor["task_id"], self.write_result("negative-assessment.json", {
            "task_id": assessor["task_id"], "path_id": assessor["subject_id"],
            "summary": "The path terminates at the allowlist and exposes no security scenario.",
            "assessments": [], "evidence": [],
        }))
        self.assertTrue(result["accepted"])
        self.assertEqual(claim_tasks(self.run, 5)["count"], 0)
        self.assertTrue(readiness(self.run)["ready"])
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM security_assessments").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 0)

    def test_confirmed_vulnerability_requires_all_six_checks(self):
        resolver = self.claim_one("entry_resolution")
        submit_result(self.run, resolver["task_id"], self.write_result("six-entry.json", {
            "task_id": resolver["task_id"],
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
        explorer = self.claim_one("entry_path_discovery")
        submit_result(self.run, explorer["task_id"], self.write_result("six-flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-FLOW", "kind": "atlas_path", "source": "atlas", "summary": "path"}],
            "flows": [{
                "root_entry_id": explorer["subject_id"], "branch_key": "route=demo",
                "controlled_property": "uri.query", "current_symbol": "Db.query", "status": "reached",
                "controlled_values": ["uri.query"],
                "facts": [
                    {"fact_key": "f-op", "type": "operation", "body": "query", "location": "Db.ets:42", "evidence_refs": ["EV-FLOW"]},
                    {"fact_key": "f-effect", "type": "effect", "body": "records", "evidence_refs": ["EV-FLOW"]},
                ], "edges": [], "continuations": [],
            }],
        }))
        assessor = self.claim_one("security_assessment")
        evidence_ref = assessor["input"]["path"]["facts"][0]["evidence_refs"][0]
        operation_fact_id = next(f["fact_id"] for f in assessor["input"]["path"]["facts"] if f["fact_type"] == "operation")
        result = {
            "task_id": assessor["task_id"], "path_id": assessor["subject_id"], "summary": "candidate",
            "assessments": [self.assessment(
                assessor, "confirmed_vulnerability", evidence_ref, operation_fact_id,
                boundary_violated=False,
            )], "evidence": [],
        }
        with database(self.run / "run.db") as conn:
            errors = validate_security_assessment(result, {"subject_id": assessor["subject_id"]}, conn)
        self.assertTrue(any("confirmed_requires_all_six_checks" in error for error in errors), errors)
        result["assessments"][0]["exploitability"]["boundary_violated"] = True
        result["assessments"][0]["security_boundary"]["violation"] = True
        result["assessments"][0]["counter_evidence"] = [{
            "kind": "no_boundary_violation", "reason": "counterexample", "evidence_refs": [evidence_ref],
        }]
        with database(self.run / "run.db") as conn:
            errors = validate_security_assessment(result, {"subject_id": assessor["subject_id"]}, conn)
        self.assertTrue(any("confirmed_cannot_have_counter_evidence" in error for error in errors), errors)

    def test_protected_exposure_requires_an_effective_guard(self):
        resolver = self.claim_one("entry_resolution")
        submit_result(self.run, resolver["task_id"], self.write_result("guard-entry.json", {
            "task_id": resolver["task_id"],
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
        explorer = self.claim_one("entry_path_discovery")
        submit_result(self.run, explorer["task_id"], self.write_result("guard-flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-FLOW", "kind": "atlas_path", "source": "atlas", "summary": "guarded path"}],
            "flows": [{
                "root_entry_id": explorer["subject_id"], "branch_key": "route=demo",
                "controlled_property": "uri.query", "current_symbol": "Db.query", "status": "reached",
                "controlled_values": ["uri.query"],
                "facts": [
                    {"fact_key": "f-op", "type": "operation", "body": "query", "location": "Db.ets:42", "evidence_refs": ["EV-FLOW"]},
                    {"fact_key": "f-effect", "type": "effect", "body": "public records", "evidence_refs": ["EV-FLOW"]},
                ], "edges": [], "continuations": [],
            }],
        }))
        assessor = self.claim_one("security_assessment")
        evidence_ref = assessor["input"]["path"]["facts"][0]["evidence_refs"][0]
        operation_fact_id = next(f["fact_id"] for f in assessor["input"]["path"]["facts"] if f["fact_type"] == "operation")
        protected = self.assessment(
            assessor, "protected_exposure", evidence_ref, operation_fact_id,
            guard_bypassed_or_absent=False, boundary_violated=False,
        )
        protected["guards"] = [{
            "type": "parameter_allowlist", "location": "Db.ets:40", "protects": "Db.query",
            "applies_before_sink": True, "validated_property": "uri.query", "effectiveness": "effective",
            "bypass_analysis": {"known_bypass": False, "checked_cases": ["unknown field"], "reason": "Only fixed fields are accepted"},
            "evidence_refs": [evidence_ref],
        }]
        payload = {
            "task_id": assessor["task_id"], "path_id": assessor["subject_id"], "summary": "effective guard",
            "assessments": [protected], "evidence": [],
        }
        with database(self.run / "run.db") as conn:
            self.assertEqual(validate_submission(payload, assessor, conn), [])
            protected["guards"][0]["effectiveness"] = "unknown"
            errors = validate_submission(payload, assessor, conn)
        self.assertTrue(any("protected_requires_effective_guard" in error for error in errors), errors)

    def test_invalid_submission_is_atomic(self):
        resolver = self.claim_one("entry_resolution")
        result = submit_result(self.run, resolver["task_id"], self.write_result("bad.json", {
            "task_id": resolver["task_id"], "entries": [], "excluded_candidates": [], "gaps": []
        }))
        self.assertTrue(result["ok"])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "queued")
        self.assertIn("unaccounted_project_candidates", result["error"])
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 0)
            task = conn.execute("SELECT status,error FROM tasks WHERE task_id=?", (resolver["task_id"],)).fetchone()
            self.assertEqual(task[0], "queued")
            self.assertEqual(task[1], result["error"])

    def test_flow_submission_reports_schema_and_semantic_errors_together(self):
        resolver = self.claim_one("entry_resolution")
        accepted = submit_result(self.run, resolver["task_id"], self.write_result("entry-for-invalid-flow.json", {
            "task_id": resolver["task_id"],
            "entries": [{
                "entry_key": "deeplink|EntryAbility.onNewWant|scheme=demo",
                "entry_type": "deeplink", "component": "EntryAbility",
                "symbol": "EntryAbility.onNewWant", "discriminator": {"scheme": "demo"},
                "transport": "uri", "external_reachability": "reachable",
                "project_candidate_ids": ["PE-001"], "evidence_refs": [],
            }],
            "excluded_candidates": [], "gaps": [],
        }))
        self.assertTrue(accepted["accepted"], accepted)
        explorer = self.claim_one("entry_path_discovery")
        rejected = submit_result(self.run, explorer["task_id"], self.write_result("invalid-flow-layers.json", {
            "task_id": explorer["task_id"], "evidence": [{
                "evidence_id": "EV-FLOW", "kind": "atlas_path", "source": "atlas", "summary": "path",
            }],
            "flows": [{
                "root_entry_id": explorer["subject_id"], "branch_key": "default",
                "controlled_property": "want.parameters", "current_symbol": "Db.query",
                "status": "reached", "controlled_values": [""],
                "facts": [
                    {"fact_key": "f-entry", "type": "entrypoint", "body": "external input", "evidence_refs": ["EV-FLOW"]},
                    {"fact_key": "f-op", "type": "operation", "body": "query", "evidence_refs": ["EV-FLOW"]},
                ],
                "edges": [{
                    "from": "EntryAbility.onNewWant", "to": "Db.query",
                    "kind": "calls", "evidence_refs": ["EV-FLOW"],
                }],
                "continuations": [],
            }],
        }))
        self.assertEqual(rejected["status"], "queued")
        self.assertIn("controlled_values", rejected["error"])
        self.assertIn("edge_unknown_fact", rejected["error"])

    def test_assessment_operation_location_is_deterministically_normalized(self):
        assessor = self.create_assessment_task()
        operation = next(fact for fact in assessor["input"]["path"]["facts"] if fact["fact_type"] == "operation")
        evidence_ref = operation["evidence_refs"][0]
        assessment = self.assessment(
            assessor, "benign_business_flow", evidence_ref, operation["fact_id"],
            guard_bypassed_or_absent=False, boundary_violated=False, concrete_impact=False,
        )
        assessment["root_cause"]["operation_location"] = operation["fact_key"]
        accepted = submit_result(self.run, assessor["task_id"], self.write_result("normalized-assessment.json", {
            "task_id": assessor["task_id"], "path_id": assessor["subject_id"],
            "summary": "location normalization", "assessments": [assessment], "evidence": [],
        }))
        self.assertTrue(accepted["accepted"], accepted)
        stored = json.loads((self.run / "tasks" / f"{assessor['task_id']}.result.json").read_text())
        self.assertEqual(stored["assessments"][0]["root_cause"]["operation_location"], operation["location"])

    def test_third_invalid_assessment_degrades_only_its_path(self):
        assessor = self.create_assessment_task()
        invalid = {
            "task_id": assessor["task_id"], "path_id": assessor["subject_id"],
            "summary": "invalid", "assessments": [{}], "evidence": [],
        }
        first = submit_result(self.run, assessor["task_id"], self.write_result("bad-assessment-1.json", invalid))
        self.assertEqual(first["status"], "queued")
        second_task = self.claim_one("security_assessment")
        second = submit_result(self.run, second_task["task_id"], self.write_result("bad-assessment-2.json", invalid))
        self.assertEqual(second["status"], "queued")
        third_task = self.claim_one("security_assessment")
        third = submit_result(self.run, third_task["task_id"], self.write_result("bad-assessment-3.json", invalid))
        self.assertTrue(third["accepted"], third)
        self.assertTrue(third["degraded"], third)
        self.assertEqual(third["status"], "completed")
        self.assertEqual(status(self.run)["run"]["status"], "running")
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            classification = conn.execute(
                "SELECT classification FROM security_assessments WHERE path_id=?", (assessor["subject_id"],)
            ).fetchone()[0]
        self.assertEqual(classification, "insufficient_evidence")
        self.assertTrue(readiness(self.run)["ready"])

    def test_one_project_candidate_can_expand_to_multiple_canonical_entries(self):
        resolver = self.claim_one("entry_resolution")
        base = {
            "entry_type": "ipc_transaction", "component": "BackupService", "symbol": "onRemoteRequest",
            "transport": "ipc", "external_reachability": "reachable",
            "project_candidate_ids": ["PE-001"], "evidence_refs": ["EV-ENTRY"],
        }
        submit_result(self.run, resolver["task_id"], self.write_result("split-entry.json", {
            "task_id": resolver["task_id"],
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
        resolver = self.claim_one("entry_resolution")
        submit_result(self.run, resolver["task_id"], self.write_result("continuation-entry.json", {
            "task_id": resolver["task_id"],
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

        explorer = self.claim_one("entry_path_discovery")
        entry_id = explorer["subject_id"]
        submit_result(self.run, explorer["task_id"], self.write_result("parent-flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{"evidence_id": "EV-PARENT", "kind": "atlas_path", "source": "atlas", "summary": "dispatch"}],
            "flows": [
                {
                    "root_entry_id": entry_id, "branch_key": "mode=raw",
                    "controlled_property": "uri.query", "current_symbol": "Shared.run", "status": "open",
                    "controlled_values": ["uri.query"],
                    "facts": [{"fact_key": "f-entry", "type": "entrypoint", "body": "external URI", "evidence_refs": ["EV-PARENT"]}],
                    "edges": [],
                    "continuations": [{
                        "semantic_key": "shared-run-raw", "kind": "shared_handler",
                        "target": "Shared.run (via IMPORT_RAW)",
                        "reason": "raw dispatch", "evidence_refs": ["EV-PARENT"],
                    }],
                },
                {
                    "root_entry_id": entry_id, "branch_key": "mode=file",
                    "controlled_property": "uri.query", "current_symbol": "Shared.run", "status": "open",
                    "controlled_values": ["uri.query"],
                    "facts": [{"fact_key": "f-entry", "type": "entrypoint", "body": "external URI", "evidence_refs": ["EV-PARENT"]}],
                    "edges": [],
                    "continuations": [{
                        "semantic_key": "shared-run-file", "kind": "shared_handler",
                        "target": "Shared.run (via IMPORT_FILE)",
                        "reason": "file dispatch", "evidence_refs": ["EV-PARENT"],
                    }],
                },
            ],
        }))
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            self.assertEqual(
                {row[0] for row in conn.execute("SELECT status FROM flows WHERE parent_flow_id IS NULL")},
                {"open"},
            )
            handler_tasks = conn.execute("SELECT COUNT(*) FROM tasks WHERE kind='continuation_resolution'").fetchone()[0]
            linked = conn.execute("SELECT COUNT(DISTINCT task_id),COUNT(*) FROM continuations").fetchone()
            self.assertEqual(handler_tasks, 1)
            self.assertEqual(linked, (1, 2))

        continuation = self.claim_one("continuation_resolution")
        self.assertEqual(len(continuation["input"]["continuations"]), 2)
        parent_flows = {
            item["parent_flow"]["branch_key"]: (
                item["parent_flow"]["flow_id"], item["parent_flow"]["facts"][0]["fact_key"]
            )
            for item in continuation["input"]["continuations"]
        }
        child = lambda branch, parent_id, parent_fact_key: {
            "root_entry_id": entry_id, "parent_flow_id": parent_id,
            "branch_key": branch, "controlled_property": "uri.query",
            "current_symbol": "Db.query", "status": "reached", "controlled_values": ["uri.query"],
            "facts": [
                {"fact_key": "f-op", "type": "operation", "body": "query", "evidence_refs": ["EV-CHILD"]},
                {"fact_key": "f-effect", "type": "effect", "body": "records", "evidence_refs": ["EV-CHILD"]},
            ],
            "edges": [
                {"from": parent_fact_key, "to": "f-op", "kind": "enables", "evidence_refs": ["EV-CHILD"]},
                {"from": "f-op", "to": "f-effect", "kind": "causes", "evidence_refs": ["EV-CHILD"]},
            ],
            "continuations": [],
        }
        incomplete = {
            "task_id": continuation["task_id"],
            "evidence": [{"evidence_id": "EV-CHILD", "kind": "atlas_path", "source": "atlas", "summary": "effect"}],
            "flows": [child("mode=raw", *parent_flows["mode=raw"])],
        }
        rejected = submit_result(
            self.run, continuation["task_id"], self.write_result("incomplete-child-flow.json", incomplete)
        )
        self.assertEqual(rejected["status"], "queued")
        self.assertIn("unaccounted_continuation_parents", rejected["error"])
        continuation = self.claim_one("continuation_resolution")
        accepted = submit_result(self.run, continuation["task_id"], self.write_result("child-flow.json", {
            **incomplete,
            "flows": [
                child("mode=raw", *parent_flows["mode=raw"]),
                child("mode=file", *parent_flows["mode=file"]),
            ],
        }))
        self.assertTrue(accepted["accepted"], accepted)
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            path_rows = conn.execute("SELECT flow_ids_json,status FROM paths ORDER BY path_id").fetchall()
            self.assertEqual(len(path_rows), 2)
            self.assertTrue(all(len(json.loads(row[0])) == 2 for row in path_rows))
            self.assertEqual({row[1] for row in path_rows}, {"reached"})
            continuation_rows = conn.execute(
                "SELECT status,child_flow_ids_json FROM continuations ORDER BY continuation_id"
            ).fetchall()
            self.assertTrue(all(row[0] == "resolved" and len(json.loads(row[1])) == 1 for row in continuation_rows))

        assessment_batch = claim_tasks(self.run, 5)
        self.assertEqual(assessment_batch["count"], 2)
        self.assertEqual({handle["kind"] for handle in assessment_batch["tasks"]}, {"security_assessment"})
        for handle in assessment_batch["tasks"]:
            task = json.loads(Path(handle["task_file"]).read_text(encoding="utf-8"))
            evidence_ref = task["input"]["path"]["facts"][0]["evidence_refs"][0]
            operation_fact_id = next(
                fact["fact_id"] for fact in task["input"]["path"]["facts"] if fact["fact_type"] == "operation"
            )
            accepted = submit_result(self.run, task["task_id"], self.write_result(f"{task['task_id']}-assessment.json", {
                "task_id": task["task_id"], "path_id": task["subject_id"],
                "summary": "The complete path is bounded to an expected query route.",
                "assessments": [self.assessment(
                    task, "benign_business_flow", evidence_ref, operation_fact_id,
                    guard_bypassed_or_absent=False, boundary_violated=False,
                )],
                "evidence": [],
            }))
            self.assertTrue(accepted["accepted"], accepted)

        self.assertEqual(claim_tasks(self.run, 5)["count"], 0)
        report = build_report_ready(self.run)
        self.assertEqual(report["summary"]["paths"], 2)
        self.assertEqual(report["summary"]["flow_segments"], 4)
        report_model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertTrue(all(len(path["segments"]) == 2 for path in report_model["paths"]))
        self.assertTrue(all(
            path["assessments"][0]["business_intent"]["is_public_api"]
            and path["assessments"][0]["counter_evidence"][0]["kind"] == "business_intent"
            for path in report_model["paths"]
        ))

    def test_handler_identity_ignores_dispatch_labels(self):
        self.assertEqual(
            handler_identity("AutomationEventManager.importDocument (via IMPORT_RAW)"),
            handler_identity("AutomationEventManager.importDocument (via IMPORT_SHARED)"),
        )
        self.assertNotEqual(
            handler_identity("AutomationEventManager.importDocument"),
            handler_identity("AutomationEventManager.deleteSnapshot"),
        )

    def test_duplicate_runs_are_isolated(self):
        other = new_run(self.root / "reports", self.target)
        self.assertNotEqual(str(self.run), other["run_dir"])

    def test_prepare_is_the_single_initialization_entrypoint(self):
        target = self.root / "prepared-target"
        manifest = target / "entry/src/main/module.json5"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("""{
          module: { name: 'entry', type: 'entry', abilities: [{
            name: 'EntryAbility', exported: true, srcEntry: './ets/EntryAbility.ets'
          }] }
        }""", encoding="utf-8")
        atlas = self.root / "fake-atlas"
        atlas.write_text("""#!/bin/sh
command="$1"
project="$3"
if [ "$command" = "index" ] || [ "$command" = "sync" ]; then
  mkdir -p "$project/.atlas"
  printf 'db' > "$project/.atlas/atlas.db"
  echo 'index complete'
elif [ "$command" = "status" ]; then
  echo 'Files indexed:   3'
fi
""", encoding="utf-8")
        atlas.chmod(0o755)

        prepared = prepare_run(target, atlas=str(atlas))

        self.assertTrue(prepared["ok"], prepared)
        self.assertEqual(prepared["stage"], "ready")
        run = Path(prepared["run_dir"])
        self.assertEqual(run.parent.resolve(), (target / "reports").resolve())
        self.assertTrue((run / "project/project_model.json").is_file())
        self.assertTrue((run / "atlas/index_status.json").is_file())
        self.assertEqual(status(run)["tasks"], {"queued": 1})

        existing_runs = {path.name for path in (target / "reports").iterdir()}
        rejected = prepare_run(target, components=["MissingAbility"], atlas=str(atlas))
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["stage"], "request_validation")
        self.assertEqual(existing_runs, {path.name for path in (target / "reports").iterdir()})

    def test_model_can_be_initialized_in_place(self):
        allocated = new_run(self.root / "reports", self.target)
        run = Path(allocated["run_dir"])
        destination = run / "project/project_model.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.model.read_text(encoding="utf-8"), encoding="utf-8")
        result = initialize_run(run, destination)
        self.assertTrue(result["ok"])

    def test_component_filter_selects_candidates_before_entry_resolution(self):
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

    def test_command_modes_preserve_full_capability_component_and_combined_arguments(self):
        cases = [
            (["prepare", "--target-repo", str(self.target)], "full", [], []),
            (["prepare", "--target-repo", str(self.target), "--mode", "capability",
              "--capability", "CAP-WEB-001"], "capability", ["CAP-WEB-001"], []),
            (["prepare", "--target-repo", str(self.target), "--component", "EntryAbility"],
             "full", [], ["EntryAbility"]),
            (["prepare", "--target-repo", str(self.target), "--mode", "capability",
              "--capability", "CAP-WEB-001", "--capability", "CAP-WEB-002",
              "--component", "entry/EntryAbility"],
             "capability", ["CAP-WEB-001", "CAP-WEB-002"], ["entry/EntryAbility"]),
        ]
        for argv, mode, capabilities, components in cases:
            with self.subTest(argv=argv):
                args = runtime_parser().parse_args(argv)
                self.assertEqual(args.mode, mode)
                self.assertEqual(args.capability, capabilities)
                self.assertEqual(args.component, components)

    def test_capability_mode_does_not_create_path_tasks_for_unrelated_entries(self):
        allocated = new_run(
            self.root / "scoped-reports", self.target, "capability", ["CAP-IPC-001"],
        )
        run = Path(allocated["run_dir"])
        initialize_run(run, self.model)
        resolver = claim_tasks(run, 5)["tasks"][0]
        accepted = submit_result(run, resolver["task_id"], self.write_result("scoped-entry.json", {
            "task_id": resolver["task_id"],
            "entries": [{
                "entry_key": "deeplink|EntryAbility.onNewWant|scheme=demo",
                "entry_type": "deeplink", "component": "EntryAbility",
                "symbol": "EntryAbility.onNewWant", "discriminator": {"scheme": "demo"},
                "transport": "uri", "external_reachability": "reachable",
                "project_candidate_ids": ["PE-001"], "evidence_refs": [],
            }],
            "excluded_candidates": [], "gaps": [],
        }))
        self.assertTrue(accepted["accepted"], accepted)
        self.assertEqual(accepted["path_tasks_created"], 0)
        self.assertEqual(accepted["entries_outside_capability_scope"], 1)
        self.assertEqual(claim_tasks(run, 5)["count"], 0)
        self.assertTrue(readiness(run)["ready"])

    def test_full_mode_limits_task_knowledge_to_profiles_for_the_entry(self):
        allocated = new_run(self.root / "full-reports", self.target)
        run = Path(allocated["run_dir"])
        initialize_run(run, self.model)
        resolver = claim_tasks(run, 5)["tasks"][0]
        submit_result(run, resolver["task_id"], self.write_result("full-entry.json", {
            "task_id": resolver["task_id"],
            "entries": [{
                "entry_key": "deeplink|EntryAbility.onNewWant|scheme=demo",
                "entry_type": "deeplink", "component": "EntryAbility",
                "symbol": "EntryAbility.onNewWant", "discriminator": {"scheme": "demo"},
                "transport": "uri", "external_reachability": "reachable",
                "project_candidate_ids": ["PE-001"], "evidence_refs": [],
            }],
            "excluded_candidates": [], "gaps": [],
        }))
        explorer_handle = claim_tasks(run, 5)["tasks"][0]
        explorer = json.loads(Path(explorer_handle["task_file"]).read_text(encoding="utf-8"))
        profile_ids = {
            row["capability_id"] for row in explorer["input"]["capability_profiles"]
        }
        self.assertEqual(profile_ids, {"CAP-INJ-001", "CAP-WEB-001", "CAP-WEB-002"})

        submit_result(run, explorer["task_id"], self.write_result("full-flow.json", {
            "task_id": explorer["task_id"],
            "evidence": [{
                "evidence_id": "EV-FULL", "kind": "atlas_path", "source": "atlas",
                "summary": "Deeplink reaches a completed public route",
            }],
            "flows": [{
                "root_entry_id": explorer["subject_id"], "branch_key": "route=public",
                "controlled_property": "uri.path", "current_symbol": "Router.open",
                "status": "stopped", "controlled_values": ["/public"],
                "facts": [{
                    "fact_key": "f-entry", "type": "entrypoint", "body": "external URI",
                    "evidence_refs": ["EV-FULL"],
                }],
                "edges": [], "continuations": [],
            }],
        }))
        assessor_handle = claim_tasks(run, 5)["tasks"][0]
        assessor = json.loads(Path(assessor_handle["task_file"]).read_text(encoding="utf-8"))
        self.assertEqual(
            {row["capability_id"] for row in assessor["input"]["capability_profiles"]},
            profile_ids,
        )
        self.assertEqual(
            {row["pattern_id"] for row in assessor["input"]["pattern_cards"]},
            {"deeplink-injection", "web-untrusted-navigation", "web-jsbridge-origin-exposure"},
        )

    def test_claim_enforces_batch_capacity_and_explicit_recovery(self):
        first = claim_tasks(self.run, 5)
        self.assertEqual(first["running"], 1)
        with database(self.run / "run.db") as conn, transaction(conn):
            for index in range(7):
                enqueue_task(conn, f"pool-test-{index}", "entry_resolution")

        claimed = claim_tasks(self.run, 5)
        self.assertEqual(claimed["count"], 4)
        self.assertNotIn("groups", claimed)
        self.assertTrue(all("batch_key" not in task for task in claimed["tasks"]))
        self.assertEqual(claimed["running"], 5)
        full = claim_tasks(self.run, 5)
        self.assertEqual(full["reason"], "batch_in_progress")
        self.assertEqual(full["count"], 0)

        recovered = recover_tasks(self.run)
        self.assertEqual(len(recovered["recovered"]), 5)
        reclaimed = claim_tasks(self.run, 5)
        self.assertEqual(reclaimed["count"], 5)
        self.assertTrue(all(row["attempt"] == 2 for row in reclaimed["tasks"]))

    def test_next_fills_five_slots_before_batch_dispatch(self):
        with database(self.run / "run.db") as conn, transaction(conn):
            for index in range(6):
                enqueue_task(conn, f"next-protocol-{index}", "entry_resolution")
        handles = []
        for expected_running in range(1, 6):
            result = next_task(self.run)
            self.assertEqual(result["reason"], "claimed")
            self.assertEqual(result["running"], expected_running)
            self.assertIn("worker_prompt", result["task"])
            self.assertIn(result["task"]["task_file"], result["task"]["worker_prompt"])
            handles.append(result["task"])
        self.assertEqual(len({handle["task_id"] for handle in handles}), 5)
        full = next_task(self.run)
        self.assertIsNone(full["task"])
        self.assertEqual(full["reason"], "worker_pool_full")
        self.assertEqual(full["running"], 5)

    def test_claim_respects_worker_limit_and_rejects_invalid_capacity(self):
        claimed = claim_tasks(self.run, 5, max_workers=2)
        self.assertEqual(claimed["count"], 1)
        self.assertEqual(claimed["capacity"], 1)
        with self.assertRaisesRegex(ValueError, "claim_limit_must_be_positive"):
            claim_tasks(self.run, 0)
        with self.assertRaisesRegex(ValueError, "max_workers_must_be_positive"):
            claim_tasks(self.run, 1, max_workers=0)

    def test_dependency_deadlock_fails_run_instead_of_spinning(self):
        with database(self.run / "run.db") as conn, transaction(conn):
            first = conn.execute("SELECT task_id FROM tasks").fetchone()["task_id"]
            second = enqueue_task(conn, "deadlock-peer", "entry_resolution")
            conn.execute("INSERT INTO task_dependencies(task_id,depends_on) VALUES (?,?)", (first, second))
            conn.execute("INSERT INTO task_dependencies(task_id,depends_on) VALUES (?,?)", (second, first))
        result = claim_tasks(self.run, 5)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "dependency_deadlock")
        self.assertEqual(readiness(self.run)["state"], "failed")

    def test_retry_task_carries_previous_error_and_discards_stale_submission(self):
        claimed = self.claim_one("entry_resolution")
        stale = Path(claimed["submission_file"])
        stale.write_text("{}", encoding="utf-8")
        from audit_runtime.commands import fail_task
        fail_task(self.run, claimed["task_id"], "conflicting_project_candidates:PE-001", retryable=True)

        retried = claim_tasks(self.run, 5)["tasks"][0]
        task = json.loads(Path(retried["task_file"]).read_text(encoding="utf-8"))
        self.assertEqual(task["attempt"], 2)
        self.assertEqual(task["previous_error"], "conflicting_project_candidates:PE-001")
        self.assertFalse(stale.exists())

    def test_third_invalid_submission_fails_without_manual_fail(self):
        first = self.claim_one("entry_resolution")
        invalid = {"task_id": first["task_id"], "entries": [], "excluded_candidates": [], "gaps": []}
        first_result = submit_result(self.run, first["task_id"], self.write_result("invalid-1.json", invalid))
        self.assertEqual(first_result["status"], "queued")
        second = self.claim_one("entry_resolution")
        with database(self.run / "run.db") as conn, transaction(conn):
            dependent_id = enqueue_task(
                conn, "blocked-dependent", "entry_resolution", dependencies=[second["task_id"]]
            )
        second_result = submit_result(self.run, second["task_id"], self.write_result("invalid-2.json", invalid))
        self.assertEqual(second_result["status"], "queued")
        third = self.claim_one("entry_resolution")
        third_result = submit_result(self.run, third["task_id"], self.write_result("invalid-3.json", invalid))
        self.assertEqual(third_result["status"], "failed")
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            events = conn.execute(
                "SELECT event_type,payload_json FROM events WHERE subject_id=? AND event_type IN ('task_retry','task_failed') ORDER BY event_id",
                (first["task_id"],),
            ).fetchall()
            run_state = conn.execute("SELECT status FROM runs").fetchone()[0]
            dependent_state = conn.execute(
                "SELECT status FROM tasks WHERE task_id=?", (dependent_id,)
            ).fetchone()[0]
        self.assertEqual([row[0] for row in events], ["task_retry", "task_retry", "task_failed"])
        self.assertTrue(all("unaccounted_project_candidates" in row[1] for row in events))
        self.assertEqual(run_state, "failed")
        self.assertEqual(dependent_state, "cancelled")
        self.assertEqual(readiness(self.run)["state"], "failed")

    def test_stale_attempt_submission_is_ignored(self):
        first = self.claim_one("entry_resolution")
        from audit_runtime.commands import fail_task
        fail_task(self.run, first["task_id"], "worker_timeout", retryable=True)
        second_handle = claim_tasks(self.run, 5)["tasks"][0]
        stale_result = submit_result(
            self.run, first["task_id"], self.write_result("stale.json", {}), attempt=1,
        )
        self.assertTrue(stale_result["ignored"])
        self.assertIn("stale_attempt", stale_result["error"])
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            task = conn.execute("SELECT status,attempts FROM tasks WHERE task_id=?", (first["task_id"],)).fetchone()
        self.assertEqual(task, ("running", 2))
        self.assertEqual(second_handle["attempt"], 2)

    def test_recovering_third_attempt_fails_run_without_loop(self):
        first = self.claim_one("entry_resolution")
        from audit_runtime.commands import fail_task
        fail_task(self.run, first["task_id"], "worker_timeout", retryable=True)
        second = claim_tasks(self.run, 5)["tasks"][0]
        second_recovery = recover_tasks(self.run)
        self.assertTrue(second_recovery["ok"])
        third = claim_tasks(self.run, 5)["tasks"][0]
        recovered = recover_tasks(self.run)
        self.assertFalse(recovered["ok"])
        self.assertEqual(recovered["status"], "failed")
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            status_value = conn.execute("SELECT status FROM tasks WHERE task_id=?", (third["task_id"],)).fetchone()[0]
            run_status = conn.execute("SELECT status FROM runs").fetchone()[0]
        self.assertEqual(status_value, "failed")
        self.assertEqual(run_status, "failed")
        self.assertEqual(claim_tasks(self.run, 5)["reason"], "run_failed")

    def test_flow_identity_ignores_model_label(self):
        base = {
            "root_entry_id": "ENTRY-1", "parent_flow_id": None,
            "branch_key": "route=demo", "controlled_property": "uri.query",
            "current_symbol": "Db.query", "continuations": [],
            "facts": [{"type": "operation", "body": "database query", "location": "Db.ets:42"}],
        }
        self.assertEqual(
            flow_identity_key({**base, "display_label": "model-label-a"}),
            flow_identity_key({**base, "display_label": "another-label"}),
        )

    def test_stale_failure_is_ignored(self):
        first = self.claim_one("entry_resolution")
        from audit_runtime.commands import fail_task
        fail_task(self.run, first["task_id"], "worker_timeout", retryable=True, attempt=1)
        second = claim_tasks(self.run, 5)["tasks"][0]
        stale = fail_task(self.run, first["task_id"], "late_worker_failure", retryable=True, attempt=1)
        self.assertTrue(stale["ignored"])
        with closing(sqlite3.connect(self.run / "run.db")) as conn:
            task = conn.execute("SELECT status,error FROM tasks WHERE task_id=?", (first["task_id"],)).fetchone()
        self.assertEqual(task, ("running", "worker_timeout"))
        self.assertEqual(second["attempt"], 2)


if __name__ == "__main__":
    unittest.main()
