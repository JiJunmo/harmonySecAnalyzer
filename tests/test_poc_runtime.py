"""PoC generation phase: scheduling, contract defenses, repair, non-gate semantics, reuse."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "resources/skills/audit-orchestration/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from audit_runtime.commands import _ensure_poc_task, finalize_run, submit_result
from audit_runtime.common import SIX_EXPLOITABILITY_CHECKS, run_paths, write_json
from audit_runtime.incremental import plan_incremental
from audit_runtime.lifecycle import initialize_run, new_run
from audit_runtime.scheduler import claim_batch, readiness, reconcile_batch
from audit_runtime.store import database, transaction

from test_flow_runtime import SplitPipelineRuntimeTest
from test_incremental_runtime import IncrementalRuntimeTest


SCHEMA_ENTRY_TYPES = {"deeplink", "want", "exported_ability", "provider", "common_event", "ipc_transaction", "project"}


def poc_result_for(task, **overrides):
    finding_id = task["input"]["finding"]["finding_id"]
    allowed = task["input"]["allowed_entry_types"]
    entry_type = next((value for value in allowed if value in SCHEMA_ENTRY_TYPES), "want")
    result = {
        "task_id": task["task_id"], "finding_id": finding_id,
        "entry_type": entry_type,
        "trigger": {"kind": "ability_want", "payload": {"uri": "demo://query?q=1"}},
        "language": "arkts", "code": "startAbility({ want: { uri: 'demo://query?q=1' } })",
        "expected_observation": "返回私有记录", "limitations": "未在真机验证",
        "execution_hint": {"step_by_step": ["安装 debug 包", "运行代码"],
                           "device_required": "emulator", "network_required": False},
        "symbol_refs": [], "evidence_refs": [],
    }
    result.update(overrides)
    return result


class PocGenerationTest(SplitPipelineRuntimeTest):
    def submit_poc_result(self, task, result):
        return submit_result(self.run, task["task_id"], self.write_submission(task, result), task["attempt"])

    def test_schedules_poc_task_after_confirmed_validation_and_persists_artifact(self):
        self.submit_semantics([self.semantic_group()])
        validation_task, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)
        self.assertTrue(validation_task["input"]["validation_contract"]["poc_produced_by_later_phase"])

        poc_task, accepted = self.submit_poc()
        self.assertTrue(accepted["accepted"], accepted)
        self.assertEqual(poc_task["input"]["finding"]["classification"], "confirmed_vulnerability")
        self.assertEqual(poc_task["input"]["finding"]["severity"], "high")
        self.assertIn("allowed_entry_types", poc_task["input"])
        self.assertIn("inherited_evidence", poc_task["input"])
        self.assertIn("output_contract", poc_task["input"])
        finding_id = poc_task["input"]["finding"]["finding_id"]
        with database(self.run / "run.db") as conn:
            row = conn.execute(
                "SELECT * FROM poc_artifacts WHERE finding_id=?", (finding_id,)
            ).fetchone()
            self.assertIsNotNone(row)
            payload = json.loads(row["payload_json"])
            self.assertEqual(payload["code"], "hdc shell aa start -a ohos.intent.action.VIEW -d 'demo://query?q=1'")

        report = finalize_run(self.run)
        self.assertEqual(report["summary"]["poc_artifacts"], 1)
        markdown = (self.run / "report.md").read_text(encoding="utf-8")
        self.assertIn("#### 验证方式 / PoC", markdown)
        self.assertIn("逐步复现", markdown)
        self.assertIn("入口类型", markdown)
        html = (self.run / "report.html").read_text(encoding="utf-8")
        self.assertIn("验证方式 / PoC", html)

    def test_rejects_placeholder_and_forbidden_output(self):
        self.submit_semantics([self.semantic_group()])
        _, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)

        task = self.claim("poc_generation")
        base = poc_result_for(task)

        rejected = self.submit_poc_result(task, {**base, "code": "startAbility({ uri: '略' })"})
        self.assertFalse(rejected["accepted"])
        self.assertIn("poc_placeholder_found", rejected["error"])
        task = self.claim("poc_generation")

        rejected = self.submit_poc_result(task, {**base, "severity": "critical"})
        self.assertFalse(rejected["accepted"])
        # schema additionalProperties fires before the domain guard on the runtime path
        self.assertIn("Additional properties", rejected["error"])

    def test_enforces_trigger_form_consistency(self):
        self.submit_semantics([self.semantic_group()])
        _, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)

        task = self.claim("poc_generation")
        base = poc_result_for(task)

        rejected = self.submit_poc_result(task, {**base, "trigger": {"kind": "adb_shell", "payload": {"cmd": "ls"}}})
        self.assertFalse(rejected["accepted"])
        self.assertIn("poc_arkts_trigger_mismatch", rejected["error"])
        task = self.claim("poc_generation")

        rejected = self.submit_poc_result(task, {**base, "language": "shell", "code": "startAbility()"})
        self.assertFalse(rejected["accepted"])
        self.assertIn("poc_shell_command_required", rejected["error"])
        task = self.claim("poc_generation")

        accepted = self.submit_poc_result(task, {**base, "language": "shell",
                                                 "code": "hdc shell aa start -a ohos.intent.action.VIEW -d 'demo://query?q=1'"})
        self.assertTrue(accepted["accepted"], accepted)

    def test_rejects_unknown_evidence_refs_and_unbound_symbol_refs(self):
        self.submit_semantics([self.semantic_group()])
        _, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)
        task = self.claim("poc_generation")

        rejected = self.submit_poc_result(task, poc_result_for(task, evidence_refs=["EV-MISSING"]))
        self.assertFalse(rejected["accepted"])
        self.assertIn("unknown_evidence", rejected["error"])
        task = self.claim("poc_generation")

        rejected = self.submit_poc_result(task, poc_result_for(
            task, symbol_refs=[{"symbol": "EntryAbility.onNewWant", "evidence": [],
                                "verified_by": "atlas_symbol"}]))
        self.assertFalse(rejected["accepted"])
        self.assertIn("symbol_ref_evidence_missing", rejected["error"])
        task = self.claim("poc_generation")

        accepted = self.submit_poc_result(task, poc_result_for(
            task, symbol_refs=[{"symbol": "EntryAbility.onNewWant",
                                "evidence": [self.source_evidence()],
                                "verified_by": "atlas_symbol"}]))
        self.assertTrue(accepted["accepted"], accepted)
        finding_id = task["input"]["finding"]["finding_id"]
        with database(self.run / "run.db") as conn:
            row = conn.execute(
                "SELECT payload_json FROM poc_artifacts WHERE finding_id=?", (finding_id,)
            ).fetchone()
            payload = json.loads(row["payload_json"])
            refs = payload["symbol_refs"][0]["evidence_refs"]
            self.assertEqual(len(refs), 1)
            self.assertTrue(refs[0].startswith("EVID-"))
            self.assertNotIn("evidence", payload["symbol_refs"][0])
            self.assertIn(refs[0], payload["evidence_refs"])
            evidence = conn.execute("SELECT * FROM evidence WHERE evidence_id=?", (refs[0],)).fetchone()
            self.assertEqual(evidence["summary"], "entry reaches database query")
            self.assertEqual(evidence["task_id"], task["task_id"])

    def test_exhausted_poc_does_not_block_run_completion(self):
        self.submit_semantics([self.semantic_group()])
        _, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)

        for _ in range(3):
            self.claim("poc_generation")
            reconcile_batch(self.run)
        ready = readiness(self.run)
        self.assertTrue(ready["ready"], ready)
        self.assertEqual(ready["coverage_gaps"]["exhausted_tasks"], 0)

        report = finalize_run(self.run)
        self.assertEqual(report["summary"]["poc_artifacts"], 0)
        markdown = (self.run / "report.md").read_text(encoding="utf-8")
        self.assertIn("未生成 PoC", markdown)

    def test_repairs_completed_poc_task_when_finding_changes(self):
        self.submit_semantics([self.semantic_group()])
        _, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)
        task, accepted = self.submit_poc()
        self.assertTrue(accepted["accepted"], accepted)
        finding_id = task["input"]["finding"]["finding_id"]

        with database(self.run / "run.db") as conn:
            row = conn.execute("SELECT payload_json FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
            changed = json.loads(row["payload_json"])
            changed["title"] = "changed"
            with transaction(conn):
                conn.execute("UPDATE findings SET payload_json=? WHERE finding_id=?",
                             (json.dumps(changed, ensure_ascii=False), finding_id))
        with database(self.run / "run.db") as conn, transaction(conn):
            _ensure_poc_task(conn, finding_id)
        with database(self.run / "run.db") as conn:
            task_row = conn.execute("SELECT status,error FROM tasks WHERE subject_id=?", (finding_id,)).fetchone()
            self.assertEqual(task_row["status"], "queued")
            self.assertEqual(task_row["error"], "poc_finding_changed")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) n FROM poc_artifacts WHERE finding_id=?", (finding_id,)
            ).fetchone()["n"], 0)


class PocIncrementalReuseTest(IncrementalRuntimeTest):
    def test_reuses_poc_artifact_when_group_fingerprint_matches(self):
        model = self.model(("entry",))
        model_path = self.root / "poc-reuse-model.json"
        write_json(model_path, model)
        full = Path(new_run(self.target / "reports", self.target, "full")["run_dir"])
        initialize_run(full, model_path)

        semantic_handle = claim_batch(full, 5)["tasks"][0]
        semantic_task = json.loads(Path(semantic_handle["task_file"]).read_text(encoding="utf-8"))
        semantic = self.semantic_result(semantic_task["subject_id"], semantic_task["task_id"], "EntryAbility.onCreate")
        source_evidence = [self.source_evidence()]
        group = {
            "group_key": "query", "category": "data_access",
            "capability_id": "CAP-PROVIDER-001", "title": "外部参数影响查询",
            "operation": {"body": "query private records", "location": "EntryAbility.ets:42",
                          "evidence": source_evidence},
            "controlled_properties": ["want.parameters.recordId"],
            "context": {
                "external_actor": "third-party application", "intended_behavior": "query one record",
                "protected_assets": ["private records"], "direct_observed_effect": "record is returned",
                "effect_hypotheses": [], "evidence": source_evidence,
            },
            "branches": [{"condition": "always", "locations": ["EntryAbility.ets:20"],
                          "evidence": source_evidence}],
            "facts": [
                {"fact_key": "entry", "type": "entrypoint", "body": "external Want",
                 "location": "EntryAbility.ets:10", "evidence": source_evidence},
                {"fact_key": "operation", "type": "operation", "body": "query private records",
                 "location": "EntryAbility.ets:42", "evidence": source_evidence},
            ],
            "security_checks": [],
        }
        semantic["operation_groups"] = [group]
        semantic["coverage"]["operation_sites_checked"] = ["EntryAbility.ets:42"]
        Path(semantic_handle["submission_file"]).write_text(json.dumps(semantic), encoding="utf-8")
        accepted = submit_result(full, semantic_task["task_id"], Path(semantic_handle["submission_file"]),
                                 semantic_task["attempt"])
        self.assertTrue(accepted["accepted"], accepted)

        validation_handle = claim_batch(full, 5)["tasks"][0]
        validation_task = json.loads(Path(validation_handle["task_file"]).read_text(encoding="utf-8"))
        persisted_group = validation_task["input"]["semantic_analysis"]["operation_groups"][0]
        evidence = self.evidence_support(persisted_group)
        verification = [self.verification_evidence()]
        checks = {name: {
            "status": "true", "reason": "源码核验成立", "evidence_level": "direct",
            "evidence": evidence,
        } for name in SIX_EXPLOITABILITY_CHECKS}
        validation = {
            "group_id": persisted_group["group_id"], "capability_id": "CAP-PROVIDER-001",
            "classification": "confirmed_vulnerability", "title": "外部参数影响查询",
            "security_check_outcome": "absent",
            "business_intent": {
                "is_public_api": True, "declared_or_inferred_purpose": "query one record",
                "allowed_controls": ["recordId"], "evidence": evidence,
            },
            "security_boundary": {
                "type": "data_owner", "expected_boundary": "only the owner may query the record",
                "violation": True, "reason": "recordId is not owner-checked", "evidence": evidence,
            },
            "exploitability": checks,
            "effect_chain": {
                key: {"description": description, "location": "EntryAbility.ets:44",
                      "evidence": self.evidence_support(persisted_group, verification)}
                for key, description in {
                    "controlled_value_use": "recordId 在查询构造中被读取",
                    "security_behavior_change": "recordId 改变查询范围",
                    "protected_operation": "查询读取私有记录",
                    "concrete_impact": "记录返回给外部调用者",
                }.items()
            },
            "counter_evidence": [],
            "impact": "读取他人记录", "severity": "high", "cwe": "CWE-639",
            "evidence": evidence,
        }
        validation_result = {
            "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
            "summary": "六维验证完成", "validations": [validation],
        }
        Path(validation_handle["submission_file"]).write_text(json.dumps(validation_result), encoding="utf-8")
        accepted = submit_result(full, validation_task["task_id"], Path(validation_handle["submission_file"]),
                                 validation_task["attempt"])
        self.assertTrue(accepted["accepted"], accepted)

        poc_handle = claim_batch(full, 5)["tasks"][0]
        poc_task = json.loads(Path(poc_handle["task_file"]).read_text(encoding="utf-8"))
        poc = poc_result_for(poc_task)
        poc["symbol_refs"] = [{
            "symbol": "EntryAbility.onCreate",
            "evidence": [self.source_evidence("核验 PoC 使用的应用入口符号", "EntryAbility.ets:10")],
            "verified_by": "atlas_symbol",
        }]
        Path(poc_handle["submission_file"]).write_text(json.dumps(poc), encoding="utf-8")
        accepted = submit_result(full, poc_task["task_id"], Path(poc_handle["submission_file"]),
                                 poc_task["attempt"])
        self.assertTrue(accepted["accepted"], accepted)
        self.assertTrue(finalize_run(full)["baseline"]["updated"])

        plan = plan_incremental(self.target, model)
        incremental = Path(new_run(self.target / "reports", self.target, "incremental")["run_dir"])
        paths = run_paths(incremental)
        write_json(paths["project_model"], model)
        write_json(paths["change_set"], plan["change_set"])
        write_json(paths["impact_plan"], plan["impact_plan"])
        write_json(paths["baseline_semantics"], plan["baseline"]["semantic_results"])
        write_json(paths["baseline_validations"], plan["baseline"]["validation_results"])
        write_json(paths["baseline_findings"], {"schema_version": 1, "items": []})
        write_json(paths["baseline_pocs"], {"schema_version": 1, "items": plan["baseline"]["pocs"]})
        initialized = initialize_run(incremental, paths["project_model"])
        self.assertEqual(initialized["task_ids"], [])
        self.assertEqual(claim_batch(incremental, 5)["count"], 0)
        with database(paths["db"]) as conn:
            poc_task_row = conn.execute(
                "SELECT status,attempts FROM tasks WHERE kind='poc_generation'"
            ).fetchone()
            self.assertEqual(dict(poc_task_row), {"status": "completed", "attempts": 0})
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM poc_artifacts").fetchone()["n"], 1)
            payload = json.loads(conn.execute("SELECT payload_json FROM poc_artifacts").fetchone()["payload_json"])
            self.assertEqual(payload["symbol_refs"][0]["symbol"], "EntryAbility.onCreate")
            self.assertNotIn("evidence", payload["symbol_refs"][0])
            self.assertEqual(len(payload["symbol_refs"][0]["evidence_refs"]), 1)


if __name__ == "__main__":
    unittest.main()
