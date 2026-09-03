import json
import io
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "resources/skills/audit-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_runtime.commands import (_merge_finding, build_report_ready, finalize_run, resume_run,
                                    status)
from audit_runtime.cli import dispatch as runtime_dispatch, parser as runtime_parser
from audit_runtime.common import SIX_EXPLOITABILITY_CHECKS
from audit_runtime.lifecycle import candidate_rows, initialize_run, new_run
from audit_runtime.reporting import refresh_live_report
from audit_runtime.result_writer import submit_task_result
from audit_runtime.scheduler import claim_batch, readiness, reconcile_batch
from audit_runtime.store import SCHEMA_VERSION, database
from audit_runtime.store import transaction
from audit_runtime.task_context import group_context
from tests.runtime_support import submit_semantic_fixture, submit_task_fixture as submit_result


class SplitPipelineRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.model = self.root / "project_model.json"
        self.model.write_text(json.dumps({
            "schema_version": 2, "status": "complete", "target_repo": str(self.target),
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
    def write_result(task, value):
        path = Path(task["task_file"]).with_name(
            f"{task['task_id']}.attempt-{task['attempt']}.test-result.json"
        )
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def claim(self, kind, run=None):
        result = claim_batch(run or self.run, 5)
        self.assertEqual(result["count"], 1, result)
        handle = result["tasks"][0]
        self.assertEqual(handle["kind"], kind)
        task = json.loads(Path(handle["task_file"]).read_text(encoding="utf-8"))
        return task

    @staticmethod
    def source_evidence(summary="entry reaches database query", location="Db.ets:42"):
        return {"kind": "atlas_trace", "source": "atlas", "summary": summary, "location": location}

    @staticmethod
    def verification_evidence(summary="verified concrete query construction", location="Db.ets:44"):
        return {"kind": "source_read", "source": "validator", "summary": summary, "location": location}

    @staticmethod
    def evidence_support(group, verification=None):
        semantic_refs = [row["evidence_id"] for row in group["evidence_scope"]["admissible"]]
        return {"semantic_refs": semantic_refs, "verification": list(verification or [])}

    @classmethod
    def semantic_group(cls, branches=None):
        evidence = [cls.source_evidence()]
        return {
            "group_key": "query-private-records", "category": "injection",
            "capability_id": "CAP-INJ-001", "title": "外部参数影响数据库查询",
            "operation": {"body": "database query", "location": "Db.ets:42", "evidence": evidence},
            "controlled_properties": ["want.parameters.query"],
            "context": {
                "external_actor": "third-party application",
                "intended_behavior": "open a public record",
                "protected_assets": ["private records"],
                "direct_observed_effect": "query result is returned to the caller",
                "effect_hypotheses": [],
                "evidence": evidence,
            },
            "branches": branches or [{
                "condition": "action == query", "locations": ["EntryAbility.ets:20"],
                "evidence": evidence,
            }],
            "facts": [
                {"fact_key": "entry", "type": "entrypoint", "body": "external deeplink",
                 "location": "EntryAbility.ets:10", "evidence": evidence},
                {"fact_key": "control", "type": "control", "body": "query comes from Want",
                 "location": "EntryAbility.ets:20", "evidence": evidence},
                {"fact_key": "operation", "type": "operation", "body": "database query",
                 "location": "Db.ets:42", "evidence": evidence},
            ],
            "security_checks": [],
        }

    @classmethod
    def dos_group(cls):
        group = cls.semantic_group()
        group.update({
            "group_key": "unbounded-worker-allocation",
            "category": "availability",
            "capability_id": "CAP-DOS-001",
            "title": "外部数量参数触发无界任务分配",
            "operation": {"body": "allocate worker tasks in a caller-sized loop", "location": "Worker.ets:42",
                          "evidence": [cls.source_evidence(location="Worker.ets:42")]},
            "controlled_properties": ["want.parameters.count"],
            "context": {
                "external_actor": "三方应用",
                "intended_behavior": "按请求数量创建后台处理任务",
                "protected_assets": ["应用进程可用性", "任务队列"],
                "direct_observed_effect": "任务数量随外部 count 线性增长直至进程资源耗尽",
                "effect_hypotheses": [],
                "evidence": [cls.source_evidence(location="Worker.ets:42")],
            },
            "availability": {
                "resource_or_failure": "任务队列和内存持续增长，最终导致应用进程不可用",
                "attacker_influence": "外部调用者完全控制 count",
                "limit_or_amplification": "count 未设置上限，每次调用按 count 创建任务",
                "exception_or_isolation": "任务创建没有异常捕获，也没有独立进程隔离",
                "repeat_trigger": "导出组件可被三方应用重复调用",
                "affected_scope": "应用主进程及其全部组件",
                "recovery": "需要系统终止并重启应用进程",
                "evidence": [cls.source_evidence(location="Worker.ets:42")],
            },
        })
        group["facts"][1]["body"] = "count comes from Want"
        group["facts"][2].update({
            "body": "allocate worker tasks in a caller-sized loop", "location": "Worker.ets:42",
        })
        return group

    def semantic_result(self, task, groups, entry_status="confirmed", component_calls=None,
                        external_entry_status=None):
        external_candidate_ids = sorted({
            row["candidate_id"]
            for row in task["input"]["entry"].get("project_candidates", [])
            if row.get("type") != "component_scope" and row.get("candidate_id")
        })
        if external_entry_status is None:
            if entry_status == "excluded" or not external_candidate_ids:
                external_entry_status = "excluded"
            else:
                external_entry_status = entry_status
        return {
            "task_id": task["task_id"], "entry_id": task["subject_id"], "summary": "语义分析完成",
            "coverage": {
                "entry_status": entry_status, "external_entry_status": external_entry_status,
                "confirmed_external_candidate_ids": (
                    external_candidate_ids if external_entry_status == "confirmed" else []
                ),
                "entry_notes": ["callback checked"],
                "entry_symbols_checked": ["EntryAbility.onNewWant"] if entry_status == "confirmed" else [],
                "operation_sites_checked": sorted({group["operation"]["location"] for group in groups}),
                "unresolved_targets": [],
            },
            "operation_groups": groups, "component_calls": component_calls or [],
        }

    def submit_semantics(self, groups, entry_status="confirmed"):
        task = self.claim("component_semantic_analysis")
        result = self.semantic_result(task, groups, entry_status)
        submitted = submit_result(self.run, task["task_id"], self.write_result(task, result), task["attempt"])
        self.assertTrue(submitted["accepted"], submitted)
        return task, submitted

    @staticmethod
    def validation_for(group, classification="confirmed_vulnerability", include_verification=True):
        confirmed = classification == "confirmed_vulnerability"
        verification = [SplitPipelineRuntimeTest.verification_evidence()] if include_verification else []
        evidence = SplitPipelineRuntimeTest.evidence_support(group)
        statuses = {
            "confirmed_vulnerability": dict.fromkeys(SIX_EXPLOITABILITY_CHECKS, "true"),
            "protected_exposure": {
                "externally_reachable": "true", "attacker_controlled": "true", "sink_reached": "false",
                "security_check_bypassed_or_absent": "false", "boundary_violated": "false",
                "concrete_impact": "false",
            },
            "no_exploitable_path": {
                "externally_reachable": "false", "attacker_controlled": "unknown", "sink_reached": "unknown",
                "security_check_bypassed_or_absent": "unknown", "boundary_violated": "unknown",
                "concrete_impact": "unknown",
            },
            "benign_business_flow": {
                "externally_reachable": "true", "attacker_controlled": "true", "sink_reached": "true",
                "security_check_bypassed_or_absent": "true", "boundary_violated": "false",
                "concrete_impact": "false",
            },
            "residual_risk": {
                "externally_reachable": "true", "attacker_controlled": "true", "sink_reached": "true",
                "security_check_bypassed_or_absent": "unknown", "boundary_violated": "unknown",
                "concrete_impact": "unknown",
            },
            "insufficient_evidence": dict.fromkeys(SIX_EXPLOITABILITY_CHECKS, "unknown"),
        }[classification]
        checks = {name: {
            "status": statuses[name],
            "reason": "源码事实支持当前状态",
            "evidence_level": "direct",
            "evidence": evidence,
        } for name in SIX_EXPLOITABILITY_CHECKS}
        outcome = {
            "confirmed_vulnerability": "absent", "protected_exposure": "effective",
            "no_exploitable_path": "unknown", "benign_business_flow": "absent",
            "residual_risk": "unknown", "insufficient_evidence": "unknown",
        }[classification]
        validation = {
            "group_id": group["group_id"], "capability_id": group.get("capability_id"),
            "classification": classification,
            "title": "外部参数可控制私有数据查询",
            "security_check_outcome": outcome,
            "business_intent": {
                "is_public_api": True, "declared_or_inferred_purpose": "打开公开内容",
                "allowed_controls": ["recordId"], "evidence": evidence,
            },
            "security_boundary": {
                "type": "data_owner", "expected_boundary": "外部调用者不能查询私有记录",
                "reason": "查询是否越过私有数据边界", "evidence": evidence,
            },
            "exploitability": checks, "counter_evidence": [], "evidence": evidence,
        }
        if confirmed:
            validation.update({
                "impact": "未授权读取私有记录", "severity": "high",
                "cwe": "CWE-89",
                "effect_chain": {
                    key: {"description": description, "location": "Db.ets:44",
                          "evidence": SplitPipelineRuntimeTest.evidence_support(group, verification)}
                    for key, description in {
                        "controlled_value_use": "受控查询参数在查询构造中被读取",
                        "security_behavior_change": "受控参数改变查询选择范围",
                        "protected_operation": "变化后的查询读取私有记录",
                        "concrete_impact": "查询结果返回给外部调用者",
                    }.items()
                },
            })
        else:
            validation["demotion_reason"] = "六维条件未达到确认漏洞标准"
            if classification == "protected_exposure":
                validation["counter_evidence"] = [{
                    "kind": "effective_security_check", "reason": "校验覆盖受控参数", "evidence": evidence,
                }]
            if classification in {"residual_risk", "insufficient_evidence"}:
                validation["evidence_gap"] = "仍缺少关键源码或运行时证明"
        if group.get("scope") == "cross_component":
            principal_state = group.get("principal_state", {})
            validation["principal_analysis"] = {
                "origin_principal": "external caller of the root component",
                "target_observed_principal": principal_state.get("observed_principal", "unknown"),
                "authority_used": principal_state.get("authority_used", "unknown"),
                "security_check_subjects": sorted({
                    security_check.get("subject_kind", "unknown") for security_check in group.get("security_checks", [])
                }),
                "origin_bound_to_observed_principal": principal_state.get("origin_binding") == "preserved",
                "delegation_risk": principal_state.get("origin_binding") == "replaced_by_caller",
                "reason": "downstream observes the component identity instead of the external origin",
                "evidence": evidence,
            }
        return validation

    def submit_validation(self, classification="confirmed_vulnerability"):
        task = self.claim("exploitability_validation")
        semantic = task["input"]["semantic_analysis"]
        validations = [self.validation_for(group, classification) for group in semantic["operation_groups"]]
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "六维验证完成", "validations": validations}
        submitted = submit_result(self.run, task["task_id"], self.write_result(task, result), task["attempt"])
        return task, submitted

    def submit_poc(self, run=None):
        task = self.claim("poc_generation", run)
        finding_id = task["input"]["finding"]["finding_id"]
        allowed = task["input"]["allowed_entry_types"]
        entry_type = allowed[0] if allowed else "want"
        result = {
            "task_id": task["task_id"], "finding_id": finding_id,
            "entry_type": entry_type,
            "trigger": {"kind": "ability_want", "payload": {"uri": "demo://query?q=1"}},
            "language": "shell", "code": "hdc shell aa start -a ohos.intent.action.VIEW -d 'demo://query?q=1'",
            "expected_observation": "返回私有记录", "limitations": "未在真机验证",
            "prerequisites": [],
            "execution_hint": {"step_by_step": ["安装 debug 包", "执行命令", "观察返回"],
                               "device_required": "emulator", "network_required": False},
            "symbol_refs": [], "evidence_refs": [],
        }
        submitted = submit_result(run or self.run, task["task_id"],
                                  self.write_result(task, result), task["attempt"])
        return task, submitted

    def test_semantics_are_persisted_before_small_validation_task(self):
        semantic_task, submitted = self.submit_semantics([self.semantic_group()])
        self.assertNotIn("decision_contract", semantic_task["input"]["analysis_contract"])
        self.assertNotIn("validation_task_id", submitted)
        validation_task = self.claim("exploitability_validation")
        self.assertEqual(set(validation_task["input"]), {
            "semantic_analysis", "verification_scope", "validation_contract", "result_protocol",
        })
        protocol = validation_task["input"]["result_protocol"]
        self.assertEqual(protocol["writer"], "audit_orchestrator.py task-submit")
        self.assertEqual(protocol["commands"]["submit"][2], "task-submit")
        self.assertTrue(protocol["draft_file"].endswith(".draft.json"))
        self.assertNotIn("submission_file", validation_task)
        self.assertNotIn("draft_file", validation_task)
        self.assertNotIn("decision_contract", validation_task["input"]["validation_contract"])
        self.assertNotIn("pattern_cards", validation_task["input"])
        self.assertNotIn("project_model", validation_task["input"])
        self.assertNotIn("entry", validation_task["input"]["semantic_analysis"])
        self.assertIn("Db.ets", validation_task["input"]["verification_scope"]["seed_files"])
        self.assertEqual(len(validation_task["input"]["semantic_analysis"]["operation_groups"]), 1)
        evidence_scope = validation_task["input"]["semantic_analysis"]["operation_groups"][0]["evidence_scope"]
        self.assertEqual(len(evidence_scope["admissible"]), 1)
        self.assertEqual(evidence_scope["hypothesis_only"], [])
        self.assertTrue(all(row["evidence_id"].startswith("EVID-") for row in evidence_scope["admissible"]))
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM semantic_analyses").fetchone()["n"], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM validation_results").fetchone()["n"], 0)
        self.assertEqual(semantic_task["input"]["analysis_contract"]["forbidden_outputs"],
                         ["classification", "exploitability", "severity", "cwe", "poc"])
        self.assertEqual(
            set(semantic_task["input"]["audit_scope"][0]),
            {"capability_id", "title", "domain", "entry_types", "analysis_scope"},
        )
        self.assertEqual(semantic_task["input"]["audit_scope"][0]["entry_types"], ["deeplink", "want"])
        self.assertIn("never component exclusion", semantic_task["input"]["analysis_contract"]["capability_entry_types"])
        self.assertIn("all implementations needed", validation_task["input"]["validation_contract"]["source_read_scope"])
        self.assertNotIn("result_schema", semantic_task)
        self.assertTrue(semantic_task["result_schema_file"].endswith(
            "component-exploration-step.schema.json"
        ))
        self.assertIn("exploration_protocol", semantic_task["input"])
        self.assertNotIn("edges", validation_task["input"]["semantic_analysis"]["operation_groups"][0])
        self.assertEqual(
            set(validation_task["input"]["semantic_analysis"]["coverage"]),
            {"entry_status", "external_entry_status", "confirmed_external_candidate_ids",
             "entry_notes", "unresolved_targets"},
        )

    def test_result_writer_normalizes_and_commits_validation_draft(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group)
        validation.pop("group_id")
        validation.pop("capability_id")
        validation["unused_agent_field"] = "ignored"
        validation["evidence"]["semantic_refs"].append("EVID-OUTSIDE-GROUP")
        validation["business_intent"]["evidence"].pop("verification")
        draft = Path(task["input"]["result_protocol"]["draft_file"])
        draft.write_text(json.dumps({"validations": [validation], "extra": True}), encoding="utf-8")

        prepared = submit_task_result(
            self.run, task["task_id"], task["attempt"], draft,
        )
        self.assertTrue(prepared["accepted"], prepared)
        self.assertTrue(any("removed_out_of_scope_evidence" in row for row in prepared["warnings"]))
        canonical = json.loads(Path(prepared["result_ref"]).read_text(encoding="utf-8"))
        self.assertEqual(canonical["task_id"], task["task_id"])
        self.assertEqual(canonical["entry_id"], task["subject_id"])
        self.assertEqual(canonical["validations"][0]["group_id"], group["group_id"])
        self.assertEqual(canonical["validations"][0]["capability_id"], group["capability_id"])
        self.assertNotIn("unused_agent_field", canonical["validations"][0])
        self.assertNotIn("EVID-OUTSIDE-GROUP", json.dumps(canonical))
        self.assertEqual(reconcile_batch(self.run)["count"], 0)

    def test_scheduler_retries_worker_that_bypasses_result_writer(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        direct = {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "试图直接提交", "validations": [self.validation_for(group)],
        }
        self.write_result(task, direct)

        reconciled = reconcile_batch(self.run)
        self.assertEqual(reconciled["queued"], 1, reconciled)
        self.assertEqual(reconciled["tasks"][0]["error"], "worker_finished_without_commit")
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) n FROM validation_results"
            ).fetchone()["n"], 0)

    def test_result_writer_keeps_semantic_validation_errors_strict(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group)
        validation["exploitability"]["concrete_impact"]["status"] = "false"
        draft = Path(task["input"]["result_protocol"]["draft_file"])
        draft.write_text(json.dumps({"validations": [validation]}), encoding="utf-8")

        prepared = submit_task_result(
            self.run, task["task_id"], task["attempt"], draft,
        )
        self.assertTrue(prepared["ok"], prepared)
        self.assertFalse(prepared["accepted"], prepared)
        self.assertTrue(any("'true' was expected" in row for row in prepared["errors"]))
        result_ref = Path(task["task_file"]).with_name(f"{task['task_id']}.result.json")
        self.assertFalse(result_ref.exists())
        with database(self.run / "run.db") as conn:
            current = conn.execute(
                "SELECT status,attempts FROM tasks WHERE task_id=?", (task["task_id"],)
            ).fetchone()
            self.assertEqual(dict(current), {"status": "running", "attempts": 1})

    def test_dos_capability_requires_availability_evidence_and_validation(self):
        allocated = new_run(self.root / "dos-reports", self.target, "capability", ["CAP-DOS-001"])
        run = Path(allocated["run_dir"])
        initialize_run(run, self.model)

        semantic_task = self.claim("component_semantic_analysis", run)
        self.assertEqual([row["capability_id"] for row in semantic_task["input"]["audit_scope"]], ["CAP-DOS-001"])
        self.assertIn("availability_requirements", semantic_task["input"]["analysis_contract"])
        group = self.dos_group()
        without_availability = json.loads(json.dumps(group))
        without_availability.pop("availability")
        rejected = submit_result(
            run, semantic_task["task_id"],
            self.write_result(semantic_task, self.semantic_result(semantic_task, [without_availability])),
            semantic_task["attempt"],
        )
        self.assertFalse(rejected["accepted"])
        self.assertIn("availability", rejected["error"])

        semantic_task = self.claim("component_semantic_analysis", run)
        accepted = submit_result(
            run, semantic_task["task_id"],
            self.write_result(semantic_task, self.semantic_result(semantic_task, [group])),
            semantic_task["attempt"],
        )
        self.assertTrue(accepted["accepted"], accepted)

        validation_task = self.claim("exploitability_validation", run)
        persisted_group = validation_task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(persisted_group)
        validation.update({
            "title": "外部数量参数可耗尽应用任务资源",
            "impact": "三方应用可使目标应用主进程失去可用性",
            "cwe": "CWE-400",
            "availability_analysis": {
                "single_trigger_fatal_or_repeatable": True,
                "amplified_consumption_or_fatal_failure": True,
                "effective_containment": True,
                "material_availability_loss": True,
                "affected_scope": "应用主进程及其全部组件",
                "recovery": "需要系统终止并重启应用进程",
                "reason": "外部 count 无上限并直接决定任务分配数量",
                "evidence": self.evidence_support(persisted_group),
            },
        })
        rejected = submit_result(
            run, validation_task["task_id"], self.write_result(validation_task, {
                "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
                "summary": "DoS 六维验证完成", "validations": [validation],
            }), validation_task["attempt"],
        )
        self.assertFalse(rejected["accepted"])
        self.assertIn("effective_containment", rejected["error"])

        validation["availability_analysis"]["effective_containment"] = False
        accepted = submit_result(
            run, validation_task["task_id"], self.write_result(validation_task, {
                "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
                "summary": "DoS 六维验证完成", "validations": [validation],
            }), validation_task["attempt"],
        )
        self.assertTrue(accepted["accepted"], accepted)
        _, poc_submitted = self.submit_poc(run)
        self.assertTrue(poc_submitted["accepted"], poc_submitted)
        report = build_report_ready(run)
        self.assertTrue(report["ok"], report)
        model = json.loads((run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["component_results"][0]["operation_groups"][0]["availability"]["affected_scope"],
                         "应用主进程及其全部组件")
        self.assertFalse(model["component_results"][0]["operation_groups"][0]
                         ["availability_analysis"]["effective_containment"])

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
            self.run, task["task_id"], self.write_result(task, legacy), task["attempt"]
        )
        self.assertFalse(submitted["accepted"])
        self.assertEqual(submitted["status"], "queued")
        self.assertIn("schema:", submitted["error"])

    def test_component_filter_requires_module_identity_when_names_are_ambiguous(self):
        candidates = []
        for index, module_id in enumerate(("MOD-a", "MOD-b"), 1):
            candidates.append({
                "candidate_id": f"PE-{index}", "component_id": f"CMP-{index}",
                "component_name": "SharedAbility", "module_name": "shared",
                "module_id": module_id, "module_root": f"modules/{index}",
                "type": "exported_component",
            })
        model = {"entry_candidates": candidates}
        with self.assertRaisesRegex(ValueError, "ambiguous_component:SharedAbility"):
            candidate_rows(model, ["SharedAbility"])
        selected = candidate_rows(model, ["MOD-b/SharedAbility"])
        self.assertEqual([row["candidate_id"] for row in selected], ["PE-2"])

    def test_full_pipeline_produces_finding_and_report_path(self):
        self.submit_semantics([self.semantic_group()])
        _, submitted = self.submit_validation()
        self.assertTrue(submitted["accepted"], submitted)
        poc_task, poc_submitted = self.submit_poc()
        self.assertTrue(poc_submitted["accepted"], poc_submitted)
        self.assertEqual(poc_task["input"]["finding"]["classification"], "confirmed_vulnerability")
        self.assertTrue(readiness(self.run)["ready"])
        report = finalize_run(self.run)
        self.assertEqual(report["summary"]["operation_groups"], 1)
        self.assertEqual(report["summary"]["paths"], 1)
        self.assertEqual(report["summary"]["poc_artifacts"], 1)
        self.assertIn("验证方式 / PoC", (self.run / "report.md").read_text(encoding="utf-8"))
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["paths"][0]["path_id"], model["operation_groups"][0]["group_id"])
        self.assertEqual(model["component_results"][0]["status"], "confirmed_vulnerability")
        self.assertTrue((self.run / "exports" / "semantic_analyses.json").is_file())
        self.assertTrue((self.run / "exports" / "validation_results.json").is_file())
        report_html = (self.run / "report.html").read_text(encoding="utf-8")
        self.assertIn('"type": "entrypoint"', report_html)
        self.assertIn("组件审计结果", report_html)

    def test_live_report_does_not_treat_unvalidated_operation_as_safe(self):
        self.submit_semantics([self.semantic_group()])
        refresh_live_report(self.run)
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        component = model["component_results"][0]
        self.assertEqual(component["status"], "verification_incomplete")
        self.assertEqual(component["operation_groups"][0].get("classification"), None)
        self.assertEqual(model["summary"]["components_without_findings"], 0)
        self.assertIn("正在等待六维有效性验证", component["review_notes"][-1])
        report_html = (self.run / "report.html").read_text(encoding="utf-8")
        self.assertIn("result=g.classification||'verification_incomplete'", report_html)

    def test_protected_component_is_visible_with_function_and_security_checks(self):
        group = self.semantic_group()
        group["security_checks"] = [{
            "type": "白名单检查", "location": "EntryAbility.ets:30",
            "protects": "私有记录查询", "subject_kind": "origin_principal",
            "validated_property": "caller bundle name", "behavior": "只允许受信任调用者继续查询",
            "evidence": [self.source_evidence(location="EntryAbility.ets:30")],
        }]
        task = self.claim("component_semantic_analysis")
        result = self.semantic_result(task, [group])
        result["summary"] = "处理深度链接并根据记录编号查询内容"
        submitted = submit_result(
            self.run, task["task_id"], self.write_result(task, result), task["attempt"]
        )
        self.assertTrue(submitted["accepted"], submitted)
        _, validated = self.submit_validation("protected_exposure")
        self.assertTrue(validated["accepted"], validated)
        finalize_run(self.run)
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        component = model["component_results"][0]
        self.assertEqual(component["status"], "protected_exposure")
        self.assertEqual(component["function_summary"], "处理深度链接并根据记录编号查询内容")
        self.assertEqual(component["security_checks"][0]["type"], "白名单检查")
        self.assertEqual(model["summary"]["components_without_findings"], 1)
        markdown = (self.run / "report.md").read_text(encoding="utf-8")
        self.assertIn("# HarmonyOS 应用安全审计报告", markdown)
        self.assertIn("## 组件审计结果", markdown)
        self.assertIn("已有有效防护", markdown)
        self.assertIn("白名单检查", markdown)
        report_html = (self.run / "report.html").read_text(encoding="utf-8")
        self.assertIn("组件审计", report_html)
        self.assertIn("处理深度链接并根据记录编号查询内容", report_html)

    def test_finding_merge_keeps_columns_and_payload_on_same_strongest_result(self):
        self.submit_semantics([self.semantic_group()])
        self.submit_validation("confirmed_vulnerability")
        with database(self.run / "run.db") as conn, transaction(conn):
            row = conn.execute("SELECT group_id FROM findings").fetchone()
            group = group_context(conn, row["group_id"])
            weaker = json.loads(json.dumps(group["validation"]))
            weaker["classification"] = "residual_risk"
            weaker["title"] = "需要进一步确认的查询风险"
            weaker["demotion_reason"] = "现有证据不足以维持确认结论"
            weaker["evidence_gap"] = "需要更多运行时证据"
            _merge_finding(conn, row["group_id"], group, weaker)
        with database(self.run / "run.db") as conn:
            finding = conn.execute("SELECT * FROM findings").fetchone()
            payload = json.loads(finding["payload_json"])
        self.assertEqual(finding["classification"], "confirmed_vulnerability")
        self.assertEqual(payload["classification"], "confirmed_vulnerability")
        self.assertEqual(finding["title"], payload["title"])

    def test_many_ordinary_branches_remain_one_semantic_group(self):
        branches = [{"condition": f"route == {index}", "locations": [f"Router.ets:{20 + index}"],
                     "evidence": [self.source_evidence(location=f"Router.ets:{20 + index}")]}
                    for index in range(12)]
        self.submit_semantics([self.semantic_group(branches)])
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM operation_groups").fetchone()["n"], 1)

    def test_semantic_runtime_builds_operation_fact_edges_and_coverage(self):
        task = self.claim("component_semantic_analysis")
        group = self.semantic_group()
        group["controlled_properties"] = []
        group["facts"] = [fact for fact in group["facts"] if fact["type"] != "operation"]
        result = self.semantic_result(task, [group])
        result["coverage"]["operation_sites_checked"] = []
        submitted = submit_result(
            self.run, task["task_id"], self.write_result(task, result), task["attempt"]
        )
        self.assertTrue(submitted["accepted"], submitted)
        persisted = json.loads((self.run / "tasks" / f"{task['task_id']}.result.json").read_text())
        normalized = persisted["operation_groups"][0]
        self.assertEqual(normalized["controlled_properties"], [])
        self.assertEqual(sum(fact["type"] == "operation" for fact in normalized["facts"]), 1)
        self.assertEqual(normalized["facts"][-1]["location"], "Db.ets:42")
        with database(self.run / "run.db") as conn:
            stored = group_context(conn, submitted["group_ids"][0])
        self.assertEqual(len(stored["edges"]), len(stored["facts"]) - 1)
        self.assertEqual(persisted["coverage"]["operation_sites_checked"], ["Db.ets:42"])

    def test_equivalent_semantic_groups_are_merged(self):
        task = self.claim("component_semantic_analysis")
        first = self.semantic_group()
        second = self.semantic_group()
        second["group_key"] = "same-operation-different-wording"
        result = self.semantic_result(task, [first, second])
        submitted = submit_result(self.run, task["task_id"], self.write_result(task, result), task["attempt"])
        self.assertTrue(submitted["accepted"], submitted)
        self.assertEqual(submitted["operation_groups_created"], 1)

    def test_security_distinct_operation_groups_are_not_merged(self):
        task = self.claim("component_semantic_analysis")
        guarded = self.semantic_group()
        guarded["group_key"] = "guarded-query"
        guarded["security_checks"] = [{
            "type": "owner check", "location": "Db.ets:35", "protects": "private records",
            "subject_kind": "origin_principal", "validated_property": "record owner",
            "behavior": "rejects records owned by another caller",
            "evidence": [self.source_evidence("owner check", "Db.ets:35")],
        }]
        result = self.semantic_result(task, [self.semantic_group(), guarded])
        submitted = submit_result(
            self.run, task["task_id"], self.write_result(task, result), task["attempt"]
        )
        self.assertTrue(submitted["accepted"], submitted)
        self.assertEqual(submitted["operation_groups_created"], 2)

    def test_confirmed_validation_requires_independent_effect_chain_not_effect_fact(self):
        group = self.semantic_group()
        group["facts"] = [fact for fact in group["facts"] if fact["type"] != "effect"]
        self.submit_semantics([group])
        task = self.claim("exploitability_validation")
        semantic_group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(semantic_group)
        validation["demotion_reason"] = ""
        validation["evidence_gap"] = ""
        result = {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "六维验证完成", "validations": [validation],
        }
        submitted = submit_result(
            self.run, task["task_id"], self.write_result(task, result), task["attempt"]
        )
        self.assertTrue(submitted["accepted"], submitted)

    def test_inferred_effect_cannot_be_persisted_as_semantic_fact(self):
        task = self.claim("component_semantic_analysis")
        group = self.semantic_group()
        group["context"].update({
            "direct_observed_effect": None,
            "effect_hypotheses": [{
                "claim": "参数可能跳过安全检查",
                "basis_evidence": [self.source_evidence("字段名提供待核查线索", "Db.ets:45")],
                "missing_proofs": ["字段读取位置", "安全行为变化", "具体影响"],
            }],
        })
        group["facts"].append({
            "fact_key": "guessed-effect", "type": "effect", "body": "安全检查被跳过",
            "location": "Db.ets:45", "evidence": [self.source_evidence(location="Db.ets:45")],
        })
        submitted = submit_result(
            self.run, task["task_id"], self.write_result(task, self.semantic_result(task, [group])),
            task["attempt"],
        )
        self.assertFalse(submitted["accepted"])
        self.assertIn("schema:", submitted["error"])

    def test_hypothesis_cannot_mark_dimension_true_and_semantic_evidence_cannot_confirm_effect(self):
        semantic_group = self.semantic_group()
        semantic_group["context"]["effect_hypotheses"] = [{
            "claim": "字段名可能暗示安全效果",
            "basis_evidence": [self.source_evidence("仅观察到可疑字段名", "Db.ets:46")],
            "missing_proofs": ["字段的真实使用", "具体安全影响"],
        }]
        self.submit_semantics([semantic_group])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        hypothesis_id = group["evidence_scope"]["hypothesis_only"][0]["evidence_id"]
        validation = self.validation_for(group, "residual_risk")
        validation["evidence_gap"] = "缺少实际安全效果证据"
        validation["evidence"]["semantic_refs"] = [hypothesis_id]
        validation["exploitability"]["sink_reached"].update({
            "status": "true", "reason": "字段名暗示到达操作", "evidence_level": "hypothesis",
        })
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "效果尚未确认", "validations": [validation]}
        rejected = submit_result(
            self.run, task["task_id"], self.write_result(task, result), task["attempt"]
        )
        self.assertFalse(rejected["accepted"])
        self.assertIn("true_dimension_evidence_insufficient:sink_reached", rejected["error"])
        self.assertTrue(any(
            "removed_out_of_scope_evidence" in warning
            for warning in rejected["warnings"]
        ))

        inherited_only = self.validation_for(group, include_verification=False)
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "仅复用语义证据", "validations": [inherited_only]}
        rejected = submit_result(
            self.run, task["task_id"], self.write_result(task, result), task["attempt"]
        )
        self.assertFalse(rejected["accepted"])
        self.assertIn("confirmed_effect_not_independently_verified", rejected["error"])

    def test_false_dimension_requires_counter_evidence(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group, "protected_exposure")
        validation["exploitability"]["sink_reached"]["evidence"] = {
            "semantic_refs": [], "verification": [],
        }
        rejected = submit_result(self.run, task["task_id"], self.write_result(task, {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "缺少反证", "validations": [validation],
        }), task["attempt"])
        self.assertFalse(rejected["accepted"])
        self.assertIn("false_dimension_evidence_insufficient:sink_reached", rejected["error"])

    def test_decisive_core_false_has_its_own_classification(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group, "no_exploitable_path")
        accepted = submit_result(self.run, task["task_id"], self.write_result(task, {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "入口存在明确反证", "validations": [validation],
        }), task["attempt"])
        self.assertTrue(accepted["accepted"], accepted)
        report = build_report_ready(self.run)
        self.assertEqual(report["summary"]["no_exploitable_paths"], 1)
        self.assertEqual(report["summary"]["findings"], 0)
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["component_results"][0]["status"], "no_exploitable_path")

    def test_excluded_entry_finishes_without_validation_task(self):
        self.submit_semantics([], "excluded")
        self.assertEqual(claim_batch(self.run)["reason"], "no_queued")
        self.assertTrue(readiness(self.run)["ready"])
        build_report_ready(self.run)
        report = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(report["coverage"]["entry_status"], {"excluded": 1})
        self.assertEqual(report["component_results"][0]["status"], "entry_excluded")
        self.assertEqual(report["component_results"][0]["operation_groups"], [])
        self.assertIn("组件审计结果", (self.run / "report.html").read_text(encoding="utf-8"))
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM tasks").fetchone()["n"], 1)

    def test_component_input_without_confirmed_external_entry_is_not_a_validation_root(self):
        task = self.claim("component_semantic_analysis")
        result = self.semantic_result(
            task, [self.semantic_group()], external_entry_status="excluded"
        )
        submitted = submit_result(
            self.run, task["task_id"], self.write_result(task, result), task["attempt"]
        )
        self.assertTrue(submitted["accepted"], submitted)
        self.assertEqual(claim_batch(self.run)["reason"], "no_queued")
        with database(self.run / "run.db") as conn:
            correlation = json.loads(conn.execute(
                "SELECT correlation_json FROM runs"
            ).fetchone()["correlation_json"])
            self.assertEqual(correlation["roots"], 0)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) n FROM operation_groups WHERE validation_required=1"
            ).fetchone()["n"], 0)

    def test_validation_must_cover_every_semantic_group(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "missing validation", "validations": []}
        submitted = submit_result(self.run, task["task_id"], self.write_result(task, result), task["attempt"])
        self.assertFalse(submitted["accepted"])
        self.assertIn("unvalidated_operation_groups", submitted["error"])

    def test_validation_cannot_invent_source_evidence(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group)
        validation["evidence"]["semantic_refs"] = ["EVID-INVENTED"]
        result = {"task_id": task["task_id"], "entry_id": task["subject_id"],
                  "summary": "invalid evidence", "validations": [validation]}
        submitted = submit_result(self.run, task["task_id"], self.write_result(task, result), task["attempt"])
        self.assertFalse(submitted["accepted"])
        self.assertIn("true_dimension_evidence_insufficient", submitted["error"])
        self.assertTrue(any(
            "removed_out_of_scope_evidence" in warning
            for warning in submitted["warnings"]
        ))

    def test_validation_cannot_borrow_evidence_from_sibling_operation_group(self):
        first = self.semantic_group()
        second = self.semantic_group()
        second["group_key"] = "delete-private-records"
        second["operation"] = {
            "body": "delete private records", "location": "Delete.ets:72",
            "evidence": [self.source_evidence("entry reaches delete operation", "Delete.ets:72")],
        }
        second["facts"][-1] = {
            "fact_key": "operation", "type": "operation", "body": "delete private records",
            "location": "Delete.ets:72",
            "evidence": [self.source_evidence("entry reaches delete operation", "Delete.ets:72")],
        }
        self.submit_semantics([first, second])
        task = self.claim("exploitability_validation")
        groups = task["input"]["semantic_analysis"]["operation_groups"]
        self.assertEqual(len(groups), 2)
        query_group = next(group for group in groups if group["operation"]["location"] == "Db.ets:42")
        delete_group = next(group for group in groups if group["operation"]["location"] == "Delete.ets:72")
        query_ids = {row["evidence_id"] for row in query_group["evidence_scope"]["admissible"]}
        delete_ids = {row["evidence_id"] for row in delete_group["evidence_scope"]["admissible"]}
        sibling_only_id = next(iter(delete_ids - query_ids))
        validations = [self.validation_for(group, "protected_exposure") for group in groups]
        query_validation = next(row for row in validations if row["group_id"] == query_group["group_id"])
        query_validation["evidence"]["semantic_refs"] = [sibling_only_id]
        submitted = submit_result(self.run, task["task_id"], self.write_result(task, {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "错误复用了相邻操作组证据", "validations": validations,
        }), task["attempt"])
        self.assertFalse(submitted["accepted"])
        self.assertIn("dimension_evidence_insufficient", submitted["error"])
        self.assertTrue(any(
            "removed_out_of_scope_evidence" in warning
            for warning in submitted["warnings"]
        ))

    def test_validation_can_follow_existing_call_chain_beyond_seed_files(self):
        self.submit_semantics([self.semantic_group()])
        task = self.claim("exploitability_validation")
        group = task["input"]["semantic_analysis"]["operation_groups"][0]
        validation = self.validation_for(group)
        outside = self.verification_evidence("shared policy implementation", "SharedPolicy.ets:9")
        for proof in validation["effect_chain"].values():
            proof["evidence"]["verification"] = [outside]
        result = {
            "task_id": task["task_id"], "entry_id": task["subject_id"],
            "summary": "followed a shared helper", "validations": [validation],
        }
        submitted = submit_result(self.run, task["task_id"], self.write_result(task, result), task["attempt"])
        self.assertTrue(submitted["accepted"], submitted)

    def test_component_correlation_connects_three_components_and_stops_cycle(self):
        components = [{
            "component_id": f"CMP-{name}", "module_id": "MOD-entry", "module_name": "entry",
            "module_root": "entry", "kind": "ability", "name": f"{name}Ability",
            "src_entry": f"./ets/{name}Ability.ets", "source_file_hint": f"entry/src/main/ets/{name}Ability.ets",
        } for name in ("A", "B", "C")]
        candidates = []
        for name in ("A", "B", "C"):
            candidates.append({
                "candidate_id": f"PE-{name}-SCOPE", "component_id": f"CMP-{name}",
                "component_name": f"{name}Ability", "module_id": "MOD-entry",
                "module_name": "entry", "module_root": "entry", "type": "component_scope",
                "src_entry": f"./ets/{name}Ability.ets", "trigger_facts": {"component_scope": True},
            })
        candidates.append({
            "candidate_id": "PE-A-EXTERNAL", "component_id": "CMP-A", "component_name": "AAbility",
            "module_id": "MOD-entry", "module_name": "entry", "module_root": "entry",
            "type": "exported_component", "src_entry": "./ets/AAbility.ets",
            "exported": True, "trigger_facts": {"exported": True},
        })
        model = self.root / "cross-component.json"
        model.write_text(json.dumps({
            "schema_version": 2, "status": "complete", "target_repo": str(self.target),
            "components": components, "entry_candidates": candidates,
        }), encoding="utf-8")
        run = Path(new_run(self.root / "cross-reports", self.target)["run_dir"])
        initialize_run(run, model)
        batch = claim_batch(run, 5)
        self.assertEqual(batch["count"], 3)
        tasks = {}
        for handle in batch["tasks"]:
            task = json.loads(Path(handle["task_file"]).read_text(encoding="utf-8"))
            tasks[task["input"]["entry"]["component"]] = task

        def component_call(key, target, source_property, target_property, location, state="preserved",
                           invocation_state="preserved"):
            evidence = [self.source_evidence("组件调用及参数映射", location)]
            return {
                "call_key": key, "target_component_id": target,
                "target_symbol": f"{target}.onCreate", "transport": "startAbility",
                "call_location": location, "condition": "always",
                "invocation_control": {
                    "control_state": invocation_state, "condition": "caller input selects this call",
                    "evidence": evidence,
                },
                "parameter_mappings": [{
                    "source_property": source_property, "target_property": target_property,
                    "control_state": state, "transform": "direct copy",
                }],
                "principal_transition": {
                    "caller_principal": key.split("-to-")[0].upper() + " component",
                    "callee_observed_principal": key.split("-to-")[0].upper() + " component",
                    "origin_binding": "replaced_by_caller",
                    "authority_used": "source_component",
                    "evidence": evidence,
                },
                "security_checks": [], "evidence": evidence,
            }

        results = {
            "AAbility": self.semantic_result(tasks["AAbility"], [], component_calls=[
                component_call("a-to-b", "CMP-B", "want.parameters.path", "want.parameters.forwardedPath", "A.ets:20"),
                component_call("a-to-c-constant", "CMP-C", "want.parameters.path", "want.parameters.filePath", "A.ets:25", "constant", "independent"),
            ]),
            "BAbility": self.semantic_result(tasks["BAbility"], [], component_calls=[
                component_call("b-to-a", "CMP-A", "want.parameters.forwardedPath", "want.parameters.path", "B.ets:30"),
                component_call("b-to-c", "CMP-C", "want.parameters.forwardedPath", "want.parameters.filePath", "B.ets:40"),
            ]),
            "CAbility": self.semantic_result(tasks["CAbility"], [self.semantic_group()]),
        }
        results["CAbility"]["operation_groups"][0]["controlled_properties"] = ["want.parameters.filePath"]
        results["CAbility"]["operation_groups"][0]["security_checks"] = [{
            "type": "component whitelist", "location": "C.ets:35",
            "protects": "private file operation", "subject_kind": "immediate_caller",
            "validated_property": "calling component identity",
            "behavior": "allows B component", "evidence": [self.source_evidence(location="C.ets:35")],
        }]
        for name, task in tasks.items():
            submitted = submit_result(
                run, task["task_id"], self.write_result(task, results[name]), task["attempt"]
            )
            self.assertTrue(submitted["accepted"], submitted)

        validation_batch = claim_batch(run, 5)
        self.assertEqual(validation_batch["count"], 1, validation_batch)
        validation_task = json.loads(Path(validation_batch["tasks"][0]["task_file"]).read_text())
        groups = validation_task["input"]["semantic_analysis"]["operation_groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["scope"], "cross_component")
        self.assertEqual(groups[0]["controlled_properties"], ["want.parameters.path"])
        self.assertEqual(groups[0]["component_chain"], ["CMP-A", "CMP-B", "CMP-C"])
        self.assertEqual(len(groups[0]["call_ids"]), 2)
        self.assertEqual(len(groups[0]["principal_lineage"]), 2)
        self.assertEqual(groups[0]["principal_state"]["origin_binding"], "replaced_by_caller")
        self.assertEqual(groups[0]["security_checks"][0]["subject_kind"], "immediate_caller")
        validation = self.validation_for(groups[0])
        validation["security_check_outcome"] = "bypassable"
        submitted = submit_result(
            run, validation_task["task_id"], self.write_result(validation_task, {
                "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
                "summary": "delegated authority validated", "validations": [validation],
            }), validation_task["attempt"],
        )
        self.assertTrue(submitted["accepted"], submitted)
        with database(run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM component_calls").fetchone()["n"], 4)
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM operation_groups WHERE scope='cross_component'").fetchone()["n"], 1)
            correlation = json.loads(conn.execute("SELECT correlation_json FROM runs").fetchone()["correlation_json"])
            self.assertLessEqual(correlation["states_visited"], 6)

    def test_component_correlation_keeps_trigger_only_calls_without_parameter_mapping(self):
        model_data = self.cross_component_model()
        model_data["entry_candidates"] = [
            row for row in model_data["entry_candidates"]
            if row["candidate_id"] != "PE-B-EXTERNAL"
        ]
        model = self.root / "trigger-only-component.json"
        model.write_text(json.dumps(model_data), encoding="utf-8")
        run = Path(new_run(
            self.root / "trigger-only-reports", self.target, "full", [], ["AAbility"]
        )["run_dir"])
        initialize_run(run, model)

        first = json.loads(Path(claim_batch(run, 5)["tasks"][0]["task_file"]).read_text())
        evidence = [self.source_evidence("外部请求决定是否启动下游组件", "A.ets:20")]
        component_call = {
            "call_key": "a-triggers-b", "target_component_id": "CMP-B",
            "target_symbol": "BAbility.onCreate", "transport": "startAbility",
            "call_location": "A.ets:20", "condition": "action == reset",
            "invocation_control": {
                "control_state": "constrained", "condition": "action == reset", "evidence": evidence,
            },
            "parameter_mappings": [],
            "principal_transition": {
                "caller_principal": "A component", "callee_observed_principal": "A component",
                "origin_binding": "replaced_by_caller", "authority_used": "source_component",
                "evidence": evidence,
            },
            "security_checks": [], "evidence": evidence,
        }
        accepted = submit_result(
            run, first["task_id"],
            self.write_result(first, self.semantic_result(first, [], component_calls=[component_call])),
            first["attempt"],
        )
        self.assertTrue(accepted["accepted"], accepted)

        second = json.loads(Path(claim_batch(run, 5)["tasks"][0]["task_file"]).read_text())
        sink = self.semantic_group()
        sink["controlled_properties"] = []
        accepted = submit_result(
            run, second["task_id"],
            self.write_result(second, self.semantic_result(second, [sink])),
            second["attempt"],
        )
        self.assertTrue(accepted["accepted"], accepted)

        validation = json.loads(Path(claim_batch(run, 5)["tasks"][0]["task_file"]).read_text())
        groups = validation["input"]["semantic_analysis"]["operation_groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["scope"], "cross_component")
        self.assertEqual(groups[0]["control_mode"], "invocation")
        self.assertEqual(groups[0]["controlled_properties"], ["$invocation"])
        self.assertEqual(groups[0]["parameter_lineage"][0]["control_kind"], "invocation")

    def test_all_command_modes_select_the_right_initial_component_scope(self):
        model = self.root / "command-modes.json"
        model.write_text(json.dumps(self.cross_component_model()), encoding="utf-8")
        cases = (
            ("full", [], [], 2),
            ("capability", ["CAP-IPC-001"], [], 2),
            ("full", [], ["AAbility"], 1),
        )
        for index, (mode, capabilities, components, expected_tasks) in enumerate(cases):
            with self.subTest(mode=mode, capabilities=capabilities, components=components):
                allocated = new_run(
                    self.root / f"mode-reports-{index}", self.target,
                    mode, capabilities, components,
                )
                initialized = initialize_run(Path(allocated["run_dir"]), model)
                self.assertEqual(initialized["analysis_units"], 2)
                self.assertEqual(len(initialized["task_ids"]), expected_tasks)

    def test_component_mode_expands_only_reached_components(self):
        model = self.root / "scoped-cross-component.json"
        model.write_text(json.dumps(self.cross_component_model()), encoding="utf-8")
        cases = (("full", [], ["AAbility"]),)
        for index, (mode, capabilities, components) in enumerate(cases):
            with self.subTest(mode=mode, components=components):
                allocated = new_run(
                    self.root / f"scope-reports-{index}", self.target,
                    mode, capabilities, components,
                )
                run = Path(allocated["run_dir"])
                initialize_run(run, model)
                first_batch = claim_batch(run, 5)
                self.assertEqual(first_batch["count"], 1)
                first = json.loads(Path(first_batch["tasks"][0]["task_file"]).read_text())
                self.assertEqual(first["input"]["entry"]["component"], "AAbility")
                component_call = {
                    "call_key": "a-to-b", "target_component_id": "CMP-B",
                    "target_symbol": "BAbility.onCreate", "transport": "startAbility",
                    "call_location": "A.ets:20", "condition": "always",
                    "invocation_control": {
                        "control_state": "preserved", "condition": "caller input selects this call",
                        "evidence": [self.source_evidence("组件调用受入口控制", "A.ets:20")],
                    },
                    "parameter_mappings": [{
                        "source_property": "want.parameters.path",
                        "target_property": "want.parameters.forwardedPath",
                        "control_state": "preserved", "transform": "direct copy",
                    }],
                    "principal_transition": {
                        "caller_principal": "A component",
                        "callee_observed_principal": "A component",
                        "origin_binding": "replaced_by_caller",
                        "authority_used": "source_component",
                        "evidence": [self.source_evidence("组件调用及参数映射", "A.ets:20")],
                    },
                    "security_checks": [],
                    "evidence": [self.source_evidence("组件调用及参数映射", "A.ets:20")],
                }
                result = self.semantic_result(first, [], component_calls=[component_call])
                submitted = submit_result(
                    run, first["task_id"], self.write_result(first, result), first["attempt"]
                )
                self.assertTrue(submitted["accepted"], submitted)

                second_batch = claim_batch(run, 5)
                self.assertEqual(second_batch["count"], 1, second_batch)
                second = json.loads(Path(second_batch["tasks"][0]["task_file"]).read_text())
                self.assertEqual(second["input"]["entry"]["component"], "BAbility")
                self.assertEqual(second["input"]["discovered_from_component_calls"], submitted["call_ids"])
                group = self.semantic_group()
                group["capability_id"] = "CAP-IPC-001"
                group["category"] = "ipc_rpc"
                group["controlled_properties"] = ["want.parameters.forwardedPath"]
                result = self.semantic_result(second, [group])
                submitted = submit_result(
                    run, second["task_id"], self.write_result(second, result), second["attempt"]
                )
                self.assertTrue(submitted["accepted"], submitted)

                validation_batch = claim_batch(run, 5)
                self.assertEqual(validation_batch["count"], 1, validation_batch)
                validation = json.loads(Path(validation_batch["tasks"][0]["task_file"]).read_text())
                groups = validation["input"]["semantic_analysis"]["operation_groups"]
                self.assertEqual(len(groups), 1)
                self.assertEqual(groups[0]["scope"], "cross_component")
                self.assertEqual(groups[0]["component_chain"], ["CMP-A", "CMP-B"])
                with database(run / "run.db") as conn:
                    semantic_tasks = conn.execute(
                        "SELECT COUNT(*) n FROM tasks WHERE kind='component_semantic_analysis'"
                    ).fetchone()["n"]
                    roots = json.loads(conn.execute(
                        "SELECT correlation_json FROM runs"
                    ).fetchone()["correlation_json"])["roots"]
                self.assertEqual(semantic_tasks, 2)
                self.assertEqual(roots, 1)

    def test_capability_mode_does_not_filter_components_by_entry_type(self):
        model = self.root / "capability-all-components.json"
        model.write_text(json.dumps(self.cross_component_model()), encoding="utf-8")
        allocated = new_run(
            self.root / "capability-all-components-reports", self.target,
            "capability", ["CAP-IPC-001"], [],
        )
        run = Path(allocated["run_dir"])
        initialize_run(run, model)

        batch = claim_batch(run, 5)
        self.assertEqual(batch["count"], 2, batch)
        tasks = [json.loads(Path(handle["task_file"]).read_text()) for handle in batch["tasks"]]
        self.assertEqual(sorted(task["input"]["entry"]["component"] for task in tasks),
                         ["AAbility", "BAbility"])
        for task in tasks:
            profile = task["input"]["audit_scope"][0]
            self.assertEqual(profile["entry_types"], ["ipc_transaction"])
            self.assertEqual(profile["analysis_scope"], "component")

    @staticmethod
    def cross_component_model():
        components = [{
            "component_id": f"CMP-{name}", "module_id": "MOD-entry",
            "module_name": "entry", "module_root": "entry", "kind": "ability",
            "name": f"{name}Ability", "src_entry": f"./ets/{name}Ability.ets",
            "source_file_hint": f"entry/src/main/ets/{name}Ability.ets",
        } for name in ("A", "B")]
        candidates = []
        for name in ("A", "B"):
            candidates.extend([
                {
                    "candidate_id": f"PE-{name}-SCOPE", "component_id": f"CMP-{name}",
                    "component_name": f"{name}Ability", "module_id": "MOD-entry",
                    "module_name": "entry", "module_root": "entry", "type": "component_scope",
                    "src_entry": f"./ets/{name}Ability.ets", "trigger_facts": {"component_scope": True},
                },
                {
                    "candidate_id": f"PE-{name}-EXTERNAL", "component_id": f"CMP-{name}",
                    "component_name": f"{name}Ability", "module_id": "MOD-entry",
                    "module_name": "entry", "module_root": "entry", "type": "exported_component",
                    "src_entry": f"./ets/{name}Ability.ets", "exported": True,
                    "trigger_facts": {"exported": True},
                },
            ])
        candidates.append({
            "candidate_id": "PE-A-IPC", "component_id": "CMP-A", "component_name": "AAbility",
            "module_id": "MOD-entry", "module_name": "entry", "module_root": "entry",
            "type": "ipc_service_candidate", "src_entry": "./ets/AAbility.ets",
            "trigger_facts": {"requires_stub_publication_evidence": True},
        })
        return {
            "schema_version": 2, "status": "complete",
            "components": components, "entry_candidates": candidates,
        }

    def test_old_schema_version_is_rejected(self):
        with sqlite3.connect(self.run / "run.db") as conn:
            conn.execute("UPDATE schema_meta SET version=?", (SCHEMA_VERSION - 1,))
        with self.assertRaisesRegex(ValueError, "unsupported_schema_version"):
            status(self.run)

    def test_worker_commit_completes_before_batch_reconciliation(self):
        task = self.claim("component_semantic_analysis")
        initial_model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(initial_model["run"]["status"], "running")
        self.assertEqual(initial_model["summary"]["tasks"], {"running": 1})
        committed = submit_semantic_fixture(
            self.run, task, self.semantic_result(task, [], "excluded"),
        )
        self.assertEqual(committed["task_status"], "completed")
        result = reconcile_batch(self.run)
        self.assertEqual(result["count"], 0, result)
        self.assertTrue(result["live_report"]["ok"], result)
        updated_model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(updated_model["summary"]["analyzed_components"], 1)
        self.assertEqual(updated_model["summary"]["tasks"], {"completed": 1})

    def test_unfinished_worker_exhausts_only_task_and_report_is_generated(self):
        for attempt in range(3):
            task = self.claim("component_semantic_analysis")
            result = reconcile_batch(self.run)
            expected = "queued" if attempt < 2 else "exhausted"
            self.assertEqual(result["tasks"][0]["status"], expected, result)
        self.assertEqual(claim_batch(self.run)["reason"], "no_queued")
        self.assertTrue(readiness(self.run)["ready"])
        report = finalize_run(self.run)
        self.assertTrue(Path(report["report_html"]).is_file())
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["run"]["status"], "complete")
        self.assertEqual(model["coverage"]["status"], "部分完成")
        self.assertEqual(model["summary"]["tasks"], {"exhausted": 1})

        resumed = resume_run(self.run)
        self.assertEqual(resumed["requeued_task_ids"], [task["task_id"]])
        self.assertEqual(status(self.run)["run"]["status"], "running")
        retried = self.claim("component_semantic_analysis")
        submit_semantic_fixture(
            self.run, retried, self.semantic_result(retried, [], "excluded"),
        )
        reconciled = reconcile_batch(self.run)
        self.assertEqual(reconciled["count"], 0)
        self.assertTrue(readiness(self.run)["ready"])
        finalize_run(self.run)
        self.assertEqual(status(self.run)["tasks"], {"completed": 1})

    def test_batch_cli_replaces_per_task_control_commands(self):
        args = runtime_parser().parse_args(["claim-batch", str(self.run)])
        claimed = runtime_dispatch(args)
        self.assertEqual(claimed["count"], 1)
        for removed in ("next", "submit", "fail", "recover", "validate-ready"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runtime_parser().parse_args([removed, str(self.run)])
        resumed = runtime_parser().parse_args(["resume", str(self.run)])
        self.assertEqual(resumed.command, "resume")
        task_submit = runtime_parser().parse_args([
            "task-submit", str(self.run), "--task-id", "TASK-1",
            "--attempt", "1", "--input", "/tmp/result.draft.json",
        ])
        self.assertEqual(task_submit.command, "task-submit")

    def test_six_components_fill_five_semantic_slots(self):
        candidates = [{"candidate_id": f"PE-{index}", "component_id": f"CMP-{index}",
                       "component_name": f"Ability{index}", "module_name": "entry",
                       "type": "exported_component"} for index in range(6)]
        model = self.root / "many-components.json"
        model.write_text(json.dumps({"schema_version": 2, "status": "complete",
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
        model.write_text(json.dumps({"schema_version": 2, "status": "complete",
                                     "entry_candidates": candidates}), encoding="utf-8")
        run = Path(new_run(self.root / "grouped-reports", self.target)["run_dir"])
        initialize_run(run, model)
        task = self.claim("component_semantic_analysis", run)
        self.assertEqual({row["entry_type"] for row in task["input"]["entry"]["facets"]},
                         {"exported_component", "deeplink"})

    def test_large_candidate_ledger_becomes_seven_component_tasks(self):
        candidates = []
        for component_index in range(7):
            for candidate_index in range(3):
                candidates.append({
                    "candidate_id": f"PE-{component_index}-{candidate_index}",
                    "component_id": f"CMP-{component_index}", "component_name": f"Ability{component_index}",
                    "module_name": "entry", "type": "deeplink",
                })
        model = self.root / "large.json"
        model.write_text(json.dumps({"schema_version": 2, "status": "complete",
                                     "entry_candidates": candidates}), encoding="utf-8")
        run = Path(new_run(self.root / "large-reports", self.target)["run_dir"])
        initialized = initialize_run(run, model)
        self.assertEqual(initialized["analysis_units"], 7)
        self.assertEqual(len(initialized["task_ids"]), 7)

    def test_full_capability_and_component_cli_modes_remain_available(self):
        parser = runtime_parser()
        full = parser.parse_args(["prepare", "--target-repo", str(self.target), "--mode", "full"])
        capability = parser.parse_args(["prepare", "--target-repo", str(self.target), "--mode", "capability",
                                        "--capability", "CAP-INJ-001"])
        component = parser.parse_args(["prepare", "--target-repo", str(self.target), "--mode", "full",
                                       "--component", "EntryAbility"])
        incremental = parser.parse_args(["prepare", "--target-repo", str(self.target), "--mode", "incremental"])
        self.assertEqual(full.mode, "full")
        self.assertEqual(capability.capability, ["CAP-INJ-001"])
        self.assertEqual(component.component, ["EntryAbility"])
        self.assertEqual(incremental.mode, "incremental")


if __name__ == "__main__":
    unittest.main()
