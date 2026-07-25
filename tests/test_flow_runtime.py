import json
import io
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / ".opencode/skills/audit-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_runtime.commands import build_report_ready, finalize_run, status, submit_result
from audit_runtime.cli import dispatch as runtime_dispatch, parser as runtime_parser
from audit_runtime.common import SIX_EXPLOITABILITY_CHECKS
from audit_runtime.lifecycle import initialize_run, new_run
from audit_runtime.scheduler import claim_batch, readiness, reconcile_batch
from audit_runtime.store import SCHEMA_VERSION, database


class SplitPipelineRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.model = self.root / "project_model.json"
        self.model.write_text(json.dumps({
            "schema_version": 1, "status": "complete", "target_repo": str(self.target),
            "application": {"bundle_name": "com.example.component"},
            "summary": {"modules": 1, "entry_candidates": 1},
            "entry_candidates": [{
                "candidate_id": "PE-001", "component_id": "CMP-001",
                "component_name": "EntryAbility", "module_name": "entry", "type": "deeplink",
                "src_entry": "./ets/EntryAbility.ets", "trigger_facts": {"scheme": "demo"},
            }],
        }), encoding="utf-8")
        allocated = new_run(self.root / "reports", self.target, "capability", ["CAP-INJ-001"])
        self.run = Path(allocated["run_dir"])
        initialize_run(self.run, self.model)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def write_submission(task, value):
        path = Path(task["submission_file"])
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def claim(self, kind, run=None):
        result = claim_batch(run or self.run, 5)
        self.assertEqual(result["count"], 1, result)
        handle = result["tasks"][0]
        self.assertEqual(handle["kind"], kind)
        return json.loads(Path(handle["task_file"]).read_text(encoding="utf-8"))

    @staticmethod
    def semantic_group(branches=None):
        return {
            "group_key": "query-private-records", "category": "injection",
            "capability_id": "CAP-INJ-001", "title": "外部参数影响数据库查询",
            "operation": {"body": "database query", "location": "Db.ets:42"},
            "controlled_properties": ["want.parameters.query"],
            "context": {
                "external_actor": "third-party application",
                "intended_behavior": "open a public record",
                "protected_assets": ["private records"],
                "observed_effect": "query result is returned to the caller",
                "evidence_refs": ["EV-TRACE"],
            },
            "branches": branches or [{
                "condition": "action == query", "locations": ["EntryAbility.ets:20"],
                "evidence_refs": ["EV-TRACE"],
            }],
            "facts": [
                {"fact_key": "entry", "type": "entrypoint", "body": "external deeplink",
                 "location": "EntryAbility.ets:10", "evidence_refs": ["EV-TRACE"]},
                {"fact_key": "control", "type": "control", "body": "query comes from Want",
                 "location": "EntryAbility.ets:20", "evidence_refs": ["EV-TRACE"]},
                {"fact_key": "operation", "type": "operation", "body": "database query",
                 "location": "Db.ets:42", "evidence_refs": ["EV-TRACE"]},
                {"fact_key": "effect", "type": "effect", "body": "records returned",
                 "location": "Db.ets:45", "evidence_refs": ["EV-TRACE"]},
            ],
            "edges": [
                {"from": "entry", "to": "control", "kind": "carries", "evidence_refs": ["EV-TRACE"]},
                {"from": "control", "to": "operation", "kind": "reaches", "evidence_refs": ["EV-TRACE"]},
                {"from": "operation", "to": "effect", "kind": "causes", "evidence_refs": ["EV-TRACE"]},
            ],
            "guards": [], "evidence_refs": ["EV-TRACE"],
        }

    def semantic_result(self, task, groups, entry_status="confirmed"):
        return {
            "task_id": task["task_id"], "entry_id": task["subject_id"], "summary": "语义分析完成",
            "coverage": {
                "entry_status": entry_status, "entry_notes": ["callback checked"],
                "entry_symbols_checked": ["EntryAbility.onNewWant"] if entry_status == "confirmed" else [],
                "operation_sites_checked": sorted({group["operation"]["location"] for group in groups}),
                "unresolved_targets": [],
            },
            "operation_groups": groups,
            "evidence": [{
                "evidence_id": "EV-TRACE", "kind": "atlas_trace", "source": "atlas",
                "summary": "entry reaches database query", "location": "Db.ets:42",
            }],
        }

    def submit_semantics(self, groups, entry_status="confirmed"):
        task = self.claim("component_semantic_analysis")
        result = self.semantic_result(task, groups, entry_status)
        submitted = submit_result(self.run, task["task_id"], self.write_submission(task, result), task["attempt"])
        self.assertTrue(submitted["accepted"], submitted)
        return task, submitted

    @staticmethod
    def validation_for(group, classification="confirmed_vulnerability"):
        confirmed = classification == "confirmed_vulnerability"
        checks = {name: confirmed for name in SIX_EXPLOITABILITY_CHECKS}
        evidence = list(group["evidence_refs"])
        validation = {
            "group_id": group["group_id"], "capability_id": group.get("capability_id"),
            "pattern_id": "deeplink-injection", "classification": classification,
            "title": "外部参数可控制私有数据查询",
            "guard_outcome": "absent" if confirmed else "effective",
            "business_intent": {
                "is_public_api": True, "declared_or_inferred_purpose": "打开公开内容",
                "allowed_controls": ["recordId"], "evidence_refs": evidence,
            },
            "security_boundary": {
                "type": "data_owner", "expected_boundary": "外部调用者不能查询私有记录",
                "violation": confirmed, "reason": "查询是否越过私有数据边界", "evidence_refs": evidence,
            },
            "exploitability": checks, "counter_evidence": [], "evidence_refs": evidence,
        }
        if confirmed:
            validation.update({
                "impact": "未授权读取私有记录", "severity": "high",
                "cwe": "CWE-89", "poc": "demo://query?q=x",
            })
        else:
            validation.update({
                "demotion_reason": "防护阻止了越权查询",
                "counter_evidence": [{"kind": "effective_guard", "reason": "校验覆盖受控参数",
                                      "evidence_refs": evidence}],
            })
        return validation

    def submit_validation(self, classification="confirmed_vulnerability"):
        task = self.claim("exploitability_validation")
        semantic = task["input"]["semantic_analysis"]
        validations = [self.validation_for(group, classification) for group in semantic["operation_groups"]]
        for validation in validations:
            validation["evidence_refs"].append("EV-VERIFY")
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "六维验证完成", "validations": validations,
                  "evidence": [{"evidence_id": "EV-VERIFY", "kind": "source_read", "source": "validator",
                                "summary": "verified concrete query construction", "location": "Db.ets:44"}]}
        submitted = submit_result(self.run, task["task_id"], self.write_submission(task, result), task["attempt"])
        return task, submitted

    def test_semantics_are_persisted_before_small_validation_task(self):
        semantic_task, submitted = self.submit_semantics([self.semantic_group()])
        self.assertIsNotNone(submitted["validation_task_id"])
        validation_task = self.claim("exploitability_validation")
        self.assertEqual(set(validation_task["input"]), {"semantic_analysis", "verification_scope"})
        self.assertNotIn("pattern_cards", validation_task["input"])
        self.assertNotIn("project_model", validation_task["input"])
        self.assertNotIn("entry", validation_task["input"]["semantic_analysis"])
        self.assertIn("Db.ets", validation_task["input"]["verification_scope"]["seed_files"])
        self.assertEqual(len(validation_task["input"]["semantic_analysis"]["operation_groups"]), 1)
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM semantic_analyses").fetchone()["n"], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM validation_results").fetchone()["n"], 0)
        self.assertEqual(semantic_task["input"]["analysis_contract"]["forbidden_outputs"],
                         ["classification", "exploitability", "severity", "cwe", "poc"])
        self.assertFalse({"pattern_ids", "expected_guards", "security_boundaries"} &
                         set(semantic_task["input"]["audit_scope"][0]))
        self.assertEqual(semantic_task["result_schema"]["required"],
                         ["task_id", "entry_id", "summary", "coverage", "operation_groups", "evidence"])

    def test_malformed_legacy_shape_returns_schema_error_without_runtime_crash(self):
        task = self.claim("component_semantic_analysis")
        legacy = {
            "task_id": task["task_id"], "conclusion": "confirmed", "reasoning": "legacy",
            "coverage": {"unresolved_targets": []},
            "operation_groups": [{
                "operation_location": "Db.ets:42", "controlled_properties": ["query"],
                "branches": [{"facts": ["external input reaches query"]}],
            }],
        }
        submitted = submit_result(
            self.run, task["task_id"], self.write_submission(task, legacy), task["attempt"]
        )
        self.assertFalse(submitted["accepted"])
        self.assertEqual(submitted["status"], "queued")
        self.assertIn("schema:", submitted["error"])

    def test_full_pipeline_produces_finding_and_report_path(self):
        self.submit_semantics([self.semantic_group()])
        _, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)
        self.assertTrue(readiness(self.run)["ready"])
        report = finalize_run(self.run)
        self.assertEqual(report["summary"]["operation_groups"], 1)
        self.assertEqual(report["summary"]["paths"], 1)
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["paths"][0]["path_id"], model["operation_groups"][0]["group_id"])
        self.assertTrue((self.run / "exports" / "semantic_analyses.json").is_file())
        self.assertTrue((self.run / "exports" / "validation_results.json").is_file())

    def test_many_ordinary_branches_remain_one_semantic_group(self):
        branches = [{"condition": f"route == {index}", "locations": [f"Router.ets:{20 + index}"],
                     "evidence_refs": ["EV-TRACE"]} for index in range(12)]
        self.submit_semantics([self.semantic_group(branches)])
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM operation_groups").fetchone()["n"], 1)

    def test_semantic_runtime_builds_operation_fact_edges_and_coverage(self):
        task = self.claim("component_semantic_analysis")
        group = self.semantic_group()
        group["controlled_properties"] = []
        group["facts"] = [fact for fact in group["facts"] if fact["type"] != "operation"]
        group["edges"] = [{
            "from": "model-local-id", "to": "missing-id", "kind": "reaches",
            "evidence_refs": ["EV-TRACE"],
        }]
        result = self.semantic_result(task, [group])
        result["coverage"]["operation_sites_checked"] = []
        submitted = submit_result(
            self.run, task["task_id"], self.write_submission(task, result), task["attempt"]
        )
        self.assertTrue(submitted["accepted"], submitted)
        persisted = json.loads((self.run / "tasks" / f"{task['task_id']}.result.json").read_text())
        normalized = persisted["operation_groups"][0]
        self.assertEqual(normalized["controlled_properties"], [])
        self.assertEqual(sum(fact["type"] == "operation" for fact in normalized["facts"]), 1)
        self.assertEqual(normalized["facts"][-1]["location"], "Db.ets:42")
        self.assertEqual(len(normalized["edges"]), len(normalized["facts"]) - 1)
        self.assertEqual(persisted["coverage"]["operation_sites_checked"], ["Db.ets:42"])

    def test_equivalent_semantic_groups_are_merged(self):
        task = self.claim("component_semantic_analysis")
        first = self.semantic_group()
        second = self.semantic_group()
        second["group_key"] = "same-operation-different-wording"
        result = self.semantic_result(task, [first, second])
        submitted = submit_result(self.run, task["task_id"], self.write_submission(task, result), task["attempt"])
        self.assertTrue(submitted["accepted"], submitted)
        self.assertEqual(submitted["operation_groups_created"], 1)

    def test_confirmed_validation_does_not_require_redundant_effect_fact(self):
        group = self.semantic_group()
        group["facts"] = [fact for fact in group["facts"] if fact["type"] != "effect"]
        self.submit_semantics([group])
        task = self.claim("exploitability_validation")
        semantic_group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(semantic_group)
        validation["demotion_reason"] = ""
        validation["evidence_gap"] = ""
        validation["evidence_refs"].append("EV-ANALYSIS")
        result = {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "六维验证完成", "validations": [validation],
            "evidence": [{
                "evidence_id": "EV-ANALYSIS", "kind": "atlas_call_graph", "source": "atlas",
                "summary": "调用链整体核验结论", "location": None,
            }],
        }
        submitted = submit_result(
            self.run, task["task_id"], self.write_submission(task, result), task["attempt"]
        )
        self.assertTrue(submitted["accepted"], submitted)

    def test_excluded_entry_finishes_without_validation_task(self):
        self.submit_semantics([], "excluded")
        self.assertTrue(readiness(self.run)["ready"])
        build_report_ready(self.run)
        report = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(report["coverage"]["entry_status"], {"excluded": 1})
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM tasks").fetchone()["n"], 1)

    def test_validation_must_cover_every_semantic_group(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "missing validation", "validations": [], "evidence": []}
        submitted = submit_result(self.run, task["task_id"], self.write_submission(task, result), task["attempt"])
        self.assertFalse(submitted["accepted"])
        self.assertIn("unvalidated_operation_groups", submitted["error"])

    def test_validation_cannot_invent_source_evidence(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group)
        validation["evidence_refs"] = ["EVID-INVENTED"]
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "invalid evidence", "validations": [validation], "evidence": []}
        submitted = submit_result(self.run, task["task_id"], self.write_submission(task, result), task["attempt"])
        self.assertFalse(submitted["accepted"])
        self.assertIn("unknown_semantic_evidence", submitted["error"])

    def test_validation_can_follow_existing_call_chain_beyond_seed_files(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group)
        validation["evidence_refs"].append("EV-OUTSIDE")
        result = {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "followed a shared helper", "validations": [validation],
            "evidence": [{"evidence_id": "EV-OUTSIDE", "kind": "source_read", "source": "validator",
                          "summary": "shared policy implementation", "location": "SharedPolicy.ets:9"}],
        }
        submitted = submit_result(self.run, task["task_id"], self.write_submission(task, result), task["attempt"])
        self.assertTrue(submitted["accepted"], submitted)

    def test_old_schema_version_is_rejected(self):
        with sqlite3.connect(self.run / "run.db") as conn:
            conn.execute("UPDATE schema_meta SET version=?", (SCHEMA_VERSION - 1,))
        with self.assertRaisesRegex(ValueError, "unsupported_schema_version"):
            status(self.run)

    def test_reconcile_accepts_submission_without_worker_text(self):
        task = self.claim("component_semantic_analysis")
        self.write_submission(task, self.semantic_result(task, [], "excluded"))
        result = reconcile_batch(self.run)
        self.assertEqual(result["completed"], 1, result)
        self.assertTrue(result["tasks"][0]["accepted"])

    def test_missing_submission_exhausts_only_task_and_report_is_generated(self):
        for attempt in range(3):
            task = self.claim("component_semantic_analysis")
            result = reconcile_batch(self.run)
            expected = "queued" if attempt < 2 else "exhausted"
            self.assertEqual(result["tasks"][0]["status"], expected, result)
        self.assertTrue(readiness(self.run)["ready"])
        report = finalize_run(self.run)
        self.assertTrue(Path(report["report_html"]).is_file())
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["coverage"]["status"], "部分完成")
        self.assertEqual(model["summary"]["tasks"], {"exhausted": 1})

    def test_batch_cli_replaces_per_task_control_commands(self):
        args = runtime_parser().parse_args(["claim-batch", str(self.run)])
        claimed = runtime_dispatch(args)
        self.assertEqual(claimed["count"], 1)
        for removed in ("next", "submit", "fail", "recover", "validate-ready"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runtime_parser().parse_args([removed, str(self.run)])

    def test_six_components_fill_five_semantic_slots(self):
        candidates = [{"candidate_id": f"PE-{index}", "component_id": f"CMP-{index}",
                       "component_name": f"Ability{index}", "module_name": "entry",
                       "type": "exported_component"} for index in range(6)]
        model = self.root / "many-components.json"
        model.write_text(json.dumps({"schema_version": 1, "status": "complete",
                                     "entry_candidates": candidates}), encoding="utf-8")
        run = Path(new_run(self.root / "many-reports", self.target)["run_dir"])
        initialize_run(run, model)
        batch = claim_batch(run, 5)
        self.assertEqual(batch["count"], 5)
        self.assertEqual({row["kind"] for row in batch["tasks"]}, {"component_semantic_analysis"})

    def test_multiple_candidates_for_component_form_one_semantic_task(self):
        candidates = [
            {"candidate_id": "PE-A", "component_id": "CMP-A", "component_name": "SearchAbility",
             "module_name": "entry", "type": "exported_component"},
            {"candidate_id": "PE-B", "component_id": "CMP-A", "component_name": "SearchAbility",
             "module_name": "entry", "type": "deeplink"},
        ]
        model = self.root / "grouped.json"
        model.write_text(json.dumps({"schema_version": 1, "status": "complete",
                                     "entry_candidates": candidates}), encoding="utf-8")
        run = Path(new_run(self.root / "grouped-reports", self.target)["run_dir"])
        initialize_run(run, model)
        task = self.claim("component_semantic_analysis", run)
        self.assertEqual({row["entry_type"] for row in task["input"]["entry"]["facets"]},
                         {"exported_component", "deeplink"})

    def test_large_candidate_ledger_becomes_eight_semantic_tasks(self):
        candidates = []
        for component_index in range(7):
            for candidate_index in range(3):
                candidates.append({
                    "candidate_id": f"PE-{component_index}-{candidate_index}",
                    "component_id": f"CMP-{component_index}", "component_name": f"Ability{component_index}",
                    "module_name": "entry", "type": "deeplink",
                })
        candidates.append({"candidate_id": "PE-DYNAMIC", "component_id": None,
                           "module_name": "entry", "type": "common_event_candidate"})
        model = self.root / "large.json"
        model.write_text(json.dumps({"schema_version": 1, "status": "complete",
                                     "entry_candidates": candidates}), encoding="utf-8")
        run = Path(new_run(self.root / "large-reports", self.target)["run_dir"])
        initialized = initialize_run(run, model)
        self.assertEqual(initialized["analysis_units"], 8)
        self.assertEqual(len(initialized["task_ids"]), 8)

    def test_full_capability_and_component_cli_modes_remain_available(self):
        parser = runtime_parser()
        full = parser.parse_args(["prepare", "--target-repo", str(self.target), "--mode", "full"])
        capability = parser.parse_args(["prepare", "--target-repo", str(self.target), "--mode", "capability",
                                        "--capability", "CAP-INJ-001"])
        component = parser.parse_args(["prepare", "--target-repo", str(self.target), "--mode", "full",
                                       "--component", "EntryAbility"])
        self.assertEqual(full.mode, "full")
        self.assertEqual(capability.capability, ["CAP-INJ-001"])
        self.assertEqual(component.component, ["EntryAbility"])


if __name__ == "__main__":
    unittest.main()
