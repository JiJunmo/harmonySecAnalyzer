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

from audit_runtime.commands import _merge_finding, build_report_ready, finalize_run, status, submit_result
from audit_runtime.cli import dispatch as runtime_dispatch, parser as runtime_parser
from audit_runtime.common import SIX_EXPLOITABILITY_CHECKS
from audit_runtime.lifecycle import candidate_rows, initialize_run, new_run
from audit_runtime.scheduler import claim_batch, readiness, reconcile_batch
from audit_runtime.store import SCHEMA_VERSION, database
from audit_runtime.store import transaction
from audit_runtime.task_context import group_context


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
            "security_checks": [], "evidence_refs": ["EV-TRACE"],
        }

    @classmethod
    def dos_group(cls):
        group = cls.semantic_group()
        group.update({
            "group_key": "unbounded-worker-allocation",
            "category": "availability",
            "capability_id": "CAP-DOS-001",
            "title": "外部数量参数触发无界任务分配",
            "operation": {"body": "allocate worker tasks in a caller-sized loop", "location": "Worker.ets:42"},
            "controlled_properties": ["want.parameters.count"],
            "context": {
                "external_actor": "三方应用",
                "intended_behavior": "按请求数量创建后台处理任务",
                "protected_assets": ["应用进程可用性", "任务队列"],
                "observed_effect": "任务数量随外部 count 线性增长直至进程资源耗尽",
                "evidence_refs": ["EV-TRACE"],
            },
            "availability": {
                "resource_or_failure": "任务队列和内存持续增长，最终导致应用进程不可用",
                "attacker_influence": "外部调用者完全控制 count",
                "limit_or_amplification": "count 未设置上限，每次调用按 count 创建任务",
                "exception_or_isolation": "任务创建没有异常捕获，也没有独立进程隔离",
                "repeat_trigger": "导出组件可被三方应用重复调用",
                "affected_scope": "应用主进程及其全部组件",
                "recovery": "需要系统终止并重启应用进程",
                "evidence_refs": ["EV-TRACE"],
            },
        })
        group["facts"][1]["body"] = "count comes from Want"
        group["facts"][2].update({
            "body": "allocate worker tasks in a caller-sized loop", "location": "Worker.ets:42",
        })
        group["facts"][3].update({
            "body": "task queue and memory grow until process failure", "location": "Worker.ets:48",
        })
        return group

    def semantic_result(self, task, groups, entry_status="confirmed", component_calls=None):
        return {
            "task_id": task["task_id"], "entry_id": task["subject_id"], "summary": "语义分析完成",
            "coverage": {
                "entry_status": entry_status, "entry_notes": ["callback checked"],
                "entry_symbols_checked": ["EntryAbility.onNewWant"] if entry_status == "confirmed" else [],
                "operation_sites_checked": sorted({group["operation"]["location"] for group in groups}),
                "unresolved_targets": [],
            },
            "operation_groups": groups, "component_calls": component_calls or [],
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
            "classification": classification,
            "title": "外部参数可控制私有数据查询",
            "security_check_outcome": "absent" if confirmed else "effective",
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
                "counter_evidence": [{"kind": "effective_security_check", "reason": "校验覆盖受控参数",
                                      "evidence_refs": evidence}],
            })
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
                "evidence_refs": evidence,
            }
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
        self.assertNotIn("validation_task_id", submitted)
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
        self.assertEqual(
            set(semantic_task["input"]["audit_scope"][0]),
            {"capability_id", "title", "domain"},
        )
        self.assertEqual(semantic_task["result_schema"]["required"],
                         ["task_id", "entry_id", "summary", "coverage", "operation_groups", "component_calls", "evidence"])

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
            self.write_submission(semantic_task, self.semantic_result(semantic_task, [without_availability])),
            semantic_task["attempt"],
        )
        self.assertFalse(rejected["accepted"])
        self.assertIn("availability", rejected["error"])

        semantic_task = self.claim("component_semantic_analysis", run)
        accepted = submit_result(
            run, semantic_task["task_id"],
            self.write_submission(semantic_task, self.semantic_result(semantic_task, [group])),
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
            "poc": "Repeatedly invoke the exported component with an unbounded count value",
            "availability_analysis": {
                "single_trigger_fatal_or_repeatable": True,
                "amplified_consumption_or_fatal_failure": True,
                "effective_containment": True,
                "material_availability_loss": True,
                "affected_scope": "应用主进程及其全部组件",
                "recovery": "需要系统终止并重启应用进程",
                "reason": "外部 count 无上限并直接决定任务分配数量",
                "evidence_refs": persisted_group["evidence_refs"],
            },
        })
        rejected = submit_result(
            run, validation_task["task_id"], self.write_submission(validation_task, {
                "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
                "summary": "DoS 六维验证完成", "validations": [validation], "evidence": [],
            }), validation_task["attempt"],
        )
        self.assertFalse(rejected["accepted"])
        self.assertIn("effective_containment", rejected["error"])

        validation_task = self.claim("exploitability_validation", run)
        validation["availability_analysis"]["effective_containment"] = False
        accepted = submit_result(
            run, validation_task["task_id"], self.write_submission(validation_task, {
                "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
                "summary": "DoS 六维验证完成", "validations": [validation], "evidence": [],
            }), validation_task["attempt"],
        )
        self.assertTrue(accepted["accepted"], accepted)
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
            self.run, task["task_id"], self.write_submission(task, legacy), task["attempt"]
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
        self.assertTrue(readiness(self.run)["ready"])
        report = finalize_run(self.run)
        self.assertEqual(report["summary"]["operation_groups"], 1)
        self.assertEqual(report["summary"]["paths"], 1)
        model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(model["paths"][0]["path_id"], model["operation_groups"][0]["group_id"])
        self.assertEqual(model["component_results"][0]["status"], "confirmed_vulnerability")
        self.assertTrue((self.run / "exports" / "semantic_analyses.json").is_file())
        self.assertTrue((self.run / "exports" / "validation_results.json").is_file())
        report_html = (self.run / "report.html").read_text(encoding="utf-8")
        self.assertIn('"type": "entrypoint"', report_html)
        self.assertIn("组件审计结果", report_html)

    def test_protected_component_is_visible_with_function_and_security_checks(self):
        group = self.semantic_group()
        group["security_checks"] = [{
            "type": "白名单检查", "location": "EntryAbility.ets:30",
            "protects": "私有记录查询", "subject_kind": "origin_principal",
            "validated_property": "caller bundle name", "behavior": "只允许受信任调用者继续查询",
            "evidence_refs": ["EV-TRACE"],
        }]
        task = self.claim("component_semantic_analysis")
        result = self.semantic_result(task, [group])
        result["summary"] = "处理深度链接并根据记录编号查询内容"
        submitted = submit_result(
            self.run, task["task_id"], self.write_submission(task, result), task["attempt"]
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
            weaker = self.validation_for(group, "residual_risk")
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

        def component_call(key, target, source_property, target_property, location, state="preserved"):
            return {
                "call_key": key, "target_component_id": target,
                "target_symbol": f"{target}.onCreate", "transport": "startAbility",
                "call_location": location, "condition": "always",
                "parameter_mappings": [{
                    "source_property": source_property, "target_property": target_property,
                    "control_state": state, "transform": "direct copy",
                }],
                "principal_transition": {
                    "caller_principal": key.split("-to-")[0].upper() + " component",
                    "callee_observed_principal": key.split("-to-")[0].upper() + " component",
                    "origin_binding": "replaced_by_caller",
                    "authority_used": "source_component",
                    "evidence_refs": ["EV-TRACE"],
                },
                "security_checks": [], "evidence_refs": ["EV-TRACE"],
            }

        results = {
            "AAbility": self.semantic_result(tasks["AAbility"], [], component_calls=[
                component_call("a-to-b", "CMP-B", "want.parameters.path", "want.parameters.forwardedPath", "A.ets:20"),
                component_call("a-to-c-constant", "CMP-C", "want.parameters.path", "want.parameters.filePath", "A.ets:25", "constant"),
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
            "behavior": "allows B component", "evidence_refs": ["EV-TRACE"],
        }]
        for name, task in tasks.items():
            submitted = submit_result(
                run, task["task_id"], self.write_submission(task, results[name]), task["attempt"]
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
            run, validation_task["task_id"], self.write_submission(validation_task, {
                "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
                "summary": "delegated authority validated", "validations": [validation], "evidence": [],
            }), validation_task["attempt"],
        )
        self.assertTrue(submitted["accepted"], submitted)
        with database(run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM component_calls").fetchone()["n"], 4)
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM operation_groups WHERE scope='cross_component'").fetchone()["n"], 1)
            correlation = json.loads(conn.execute("SELECT correlation_json FROM runs").fetchone()["correlation_json"])
            self.assertLessEqual(correlation["states_visited"], 4)

    def test_all_command_modes_select_the_right_initial_component_scope(self):
        model = self.root / "command-modes.json"
        model.write_text(json.dumps(self.cross_component_model()), encoding="utf-8")
        cases = (
            ("full", [], [], 2),
            ("capability", ["CAP-IPC-001"], [], 1),
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

    def test_capability_and_component_modes_expand_only_reached_components(self):
        model = self.root / "scoped-cross-component.json"
        model.write_text(json.dumps(self.cross_component_model()), encoding="utf-8")
        cases = (
            ("capability", ["CAP-IPC-001"], []),
            ("full", [], ["AAbility"]),
        )
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
                        "evidence_refs": ["EV-TRACE"],
                    },
                    "security_checks": [], "evidence_refs": ["EV-TRACE"],
                }
                result = self.semantic_result(first, [], component_calls=[component_call])
                submitted = submit_result(
                    run, first["task_id"], self.write_submission(first, result), first["attempt"]
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
                    run, second["task_id"], self.write_submission(second, result), second["attempt"]
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

    def test_reconcile_accepts_submission_without_worker_text(self):
        task = self.claim("component_semantic_analysis")
        initial_model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(initial_model["run"]["status"], "running")
        self.assertEqual(initial_model["summary"]["tasks"], {"running": 1})
        self.write_submission(task, self.semantic_result(task, [], "excluded"))
        result = reconcile_batch(self.run)
        self.assertEqual(result["completed"], 1, result)
        self.assertTrue(result["tasks"][0]["accepted"])
        self.assertTrue(result["live_report"]["ok"], result)
        updated_model = json.loads((self.run / "report_model.json").read_text(encoding="utf-8"))
        self.assertEqual(updated_model["summary"]["analyzed_components"], 1)
        self.assertEqual(updated_model["summary"]["tasks"], {"completed": 1})

    def test_missing_submission_exhausts_only_task_and_report_is_generated(self):
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
        model.write_text(json.dumps({"schema_version": 2, "status": "complete",
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
