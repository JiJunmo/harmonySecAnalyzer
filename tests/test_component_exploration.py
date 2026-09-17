import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "resources/skills/audit-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_runtime.cli import dispatch, parser
from audit_runtime.correlation import _entry_records, _external_roots
from audit_runtime.lifecycle import initialize_run, new_run
from audit_runtime.reporting import export_state, refresh_live_report
from audit_runtime.scheduler import claim_batch
from audit_runtime.semantic_exploration import (
    finish_exploration_round,
    next_exploration_node,
    record_exploration_step,
)
from audit_runtime.store import database, transaction


class ComponentExplorationStateTest(unittest.TestCase):
    def test_step_schema_is_valid_json_schema(self):
        from jsonschema import Draft202012Validator
        schema = SCRIPTS.parent / "config/schemas/component-exploration-step.schema.json"
        Draft202012Validator.check_schema(json.loads(schema.read_text(encoding="utf-8")))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        model = self.root / "project_model.json"
        model.write_text(json.dumps({
            "schema_version": 2,
            "status": "complete",
            "target_repo": str(self.target),
            "application": {"bundle_name": "com.example.exploration"},
            "summary": {"modules": 1, "entry_candidates": 1},
            "components": [
                {"component_id": "CMP-001", "name": "EntryAbility"},
                {"component_id": "CMP-002", "name": "TargetAbility"},
            ],
            "entry_candidates": [{
                "candidate_id": "PE-001",
                "component_id": "CMP-001",
                "component_name": "EntryAbility",
                "module_name": "entry",
                "module_root": "entry",
                "type": "deeplink",
                "src_entry": "./ets/EntryAbility.ets",
                "trigger_facts": {"scheme": "demo"},
            }],
        }), encoding="utf-8")
        allocated = new_run(self.root / "reports", self.target)
        self.run = Path(allocated["run_dir"])
        initialize_run(self.run, model)
        claimed = claim_batch(self.run, 1)
        self.assertEqual(claimed["count"], 1, claimed)
        self.task = claimed["tasks"][0]
        self.step_file = self.run / "tasks" / "exploration-step.json"

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def state():
        return {"controlled_properties": [{"name": "want.value", "control_state": "preserved"}],
                "principal": {"origin": "external", "immediate": "external",
                              "origin_binding": "preserved", "authority": "origin"},
                "security_checks": []}

    @staticmethod
    def evidence(location="EntryAbility.ets:10"):
        return {"kind": "source", "source": "source_inspection",
                "summary": "源码位置证明该事实", "location": location}

    @staticmethod
    def scope(start=10, end=30, name="EntryAbility.handle", kind="function"):
        return {"symbol": {"qualified_name": name, "file_path": "EntryAbility.ets",
                           "line": 10 if name == "EntryAbility.handle" else start, "kind": "method"},
                "start": start, "end": end, "kind": kind}

    def result(self, scope, terminal=True, groups=None):
        return {"summary": "已检查该范围",
                "checked": [] if scope["kind"] == "entry" else [{"start": scope["start"], "end": scope["end"]}],
                "termination": {"kind": "return", "reason": "当前范围返回",
                                "evidence": [self.evidence()]} if terminal else None,
                "facts": [], "security_checks": [], "operation_groups": groups or [],
                "component_calls": [], "gaps": []}

    def range(self, ref, start=10, end=30, name="EntryAbility.handle", kind="block",
              conditions=None, done=False, wait_for=None):
        scope = self.scope(start, end, name, kind)
        return {"ref": ref, "scope": scope, "state": self.state(),
                "conditions": conditions or [], "wait_for": wait_for or [],
                "result": self.result(scope) if done else None}

    def edge(self, target, source="$current", relation="sequence", condition="always"):
        return {"from": source, "to": target, "relation": relation,
                "condition": condition, "evidence": [self.evidence()]}

    def step(self, work, ranges=None, edges=None, terminal=None, pause=False, groups=None):
        ranges, edges = ranges or [], edges or []
        if terminal is None:
            terminal = not edges and work["scope"]["kind"] != "entry"
        return {"work_id": work["work_id"], "pause_requested": pause,
                "result": self.result(work["scope"], terminal, groups),
                "ranges": ranges, "transitions": edges}

    def next(self, budget=2000):
        return next_exploration_node(self.run, self.task["task_id"], self.task["attempt"], budget)

    def record(self, document):
        self.step_file.write_text(json.dumps(document), encoding="utf-8")
        return record_exploration_step(self.run, self.task["task_id"], self.task["attempt"], self.step_file)

    def seed(self, kind="function"):
        root = self.next()["work"]
        entry = self.range("entry", kind=kind)
        doc = self.step(root, [entry], [self.edge("entry", relation="callback")])
        doc["entry_assessment"] = {
            "entry_status": "confirmed", "external_entry_status": "confirmed",
            "confirmed_external_candidate_ids": ["PE-001"], "component_summary": "组件输入分析"}
        outcome = self.record(doc)
        self.assertTrue(outcome["accepted"], outcome)
        return self.next()["work"]

    def finish(self):
        return finish_exploration_round(self.run, self.task["task_id"], self.task["attempt"])

    def renew(self):
        outcome = self.finish()
        self.assertEqual(outcome["task_status"], "queued", outcome)
        self.task = claim_batch(self.run, 1)["tasks"][0]

    @classmethod
    def operation_group(cls, key, location, security_checks=None):
        evidence = [cls.evidence(location)]
        return {
            "group_key": key,
            "category": "sensitive_operation",
            "capability_id": None,
            "title": f"外部输入到达 {location}",
            "operation": {"body": "perform sensitive operation", "location": location,
                          "evidence": evidence},
            "controlled_properties": ["want.parameters.value"],
            "context": {
                "external_actor": "third-party application",
                "intended_behavior": "handle caller request",
                "protected_assets": ["application data"],
                "direct_observed_effect": "sensitive operation executes",
                "effect_hypotheses": [],
                "evidence": evidence,
            },
            "branches": [{"condition": "always", "locations": [location], "evidence": evidence}],
            "facts": [
                {"fact_key": "entry", "type": "entrypoint", "body": "external Want input",
                 "location": "EntryAbility.ets:10", "evidence": evidence},
                {"fact_key": "operation", "type": "operation",
                 "body": "perform sensitive operation", "location": location,
                 "evidence": evidence},
            ],
            "security_checks": list(security_checks or []),
        }


    def test_branch_progress_survives_round_with_all_prior_facts(self):
        work = self.seed()
        left = self.range("left", 11, 18, conditions=["action=read"], done=True)
        left["result"]["operation_groups"] = [self.operation_group("read", "EntryAbility.ets:15")]
        right = self.range("right", 19, 25, conditions=["action=delete"])
        tail = self.range("tail", 26, 30, kind="join", wait_for=["right"])
        doc = self.step(work, [left, right, tail],
                        [self.edge("left", relation="branch", condition="read"),
                         self.edge("right", relation="branch", condition="delete"),
                         self.edge("tail", relation="return")], pause=True)
        out = self.record(doc)
        self.assertTrue(out["accepted"], out)
        self.assertFalse(out["scope_complete"])
        self.assertTrue(self.record(doc)["idempotent"])
        self.assertEqual(self.next()["reason"], "pause_requested")
        self.renew()
        right_work = self.next()["work"]
        self.assertEqual(right_work["conditions"], ["action=delete"])
        left_record = next(r for r in right_work["coverage"] if r["conditions"] == ["action=read"])
        self.assertEqual(left_record["result"]["operation_groups"][0]["group_key"], "read")
        self.assertEqual(left_record["result"]["termination"]["kind"], "return")
        self.assertTrue(any(e["condition"] == "read" for e in right_work["transitions"]))
        self.assertTrue(self.record(self.step(right_work))["accepted"])
        tail_work = self.next()["work"]
        self.assertEqual(tail_work["scope"]["kind"], "join")
        self.assertTrue(self.record(self.step(tail_work))["accepted"])
        final = self.finish()
        self.assertEqual(final["exploration_status"], "complete", final)
        data = json.loads(Path(final["result_ref"]).read_text())
        self.assertEqual(len(data["operation_groups"]), 1)

    def test_same_function_under_different_conditions_remains_distinct(self):
        work = self.seed()
        first = self.range("read", 50, 60, "Helper.run", conditions=["mode=read"], done=True)
        second = self.range("delete", 50, 60, "Helper.run", conditions=["mode=delete"])
        doc = self.step(work, [first, second], [self.edge("read", relation="callback"),
                                               self.edge("delete", relation="callback")])
        out = self.record(doc)
        self.assertTrue(out["accepted"], out)
        with database(self.run / "run.db") as conn:
            counts = conn.execute(
                "SELECT COUNT(DISTINCT node_id),COUNT(*) FROM exploration_work_items WHERE conditions_json!='[]'"
            ).fetchone()
            self.assertEqual(tuple(counts), (1, 2))
        next_work = self.next()["work"]
        self.assertEqual(next_work["conditions"], ["mode=delete"])

    def test_partial_scope_without_saved_remainder_is_rejected(self):
        work = self.seed()
        doc = self.step(work)
        doc["result"]["checked"] = [{"start": 10, "end": 15}]
        outcome = self.record(doc)
        self.assertFalse(outcome["accepted"])
        self.assertTrue(any("unexamined_scope" in e for e in outcome["errors"]))
        self.assertEqual(self.next()["work"]["work_id"], work["work_id"])

    def test_partial_scope_can_delegate_multiple_remaining_branches(self):
        work = self.seed()
        ranges = [self.range("a", 16, 20), self.range("b", 21, 30)]
        doc = self.step(work, ranges, [self.edge("a"), self.edge("b")])
        doc["result"]["checked"] = [{"start": 10, "end": 15}]
        self.assertTrue(self.record(doc)["accepted"])
        self.assertEqual(self.finish()["task_status"], "queued")

    def test_choice_requires_two_explicit_exits(self):
        work = self.seed(kind="choice")
        doc = self.step(work, [self.range("a", 11, 30)], [self.edge("a", relation="branch")])
        out = self.record(doc)
        self.assertFalse(out["accepted"])
        self.assertIn("choice_requires_all_exits:$current", out["errors"])

    def test_return_does_not_allow_normal_fallthrough(self):
        work = self.seed()
        doc = self.step(work, [self.range("tail", 31, 40)], [self.edge("tail")], terminal=True)
        self.assertIn("exit_cannot_fall_through:$current", self.record(doc)["errors"])

    def test_call_requires_return_position(self):
        work = self.seed()
        doc = self.step(work, [self.range("callee", 50, 60, "Helper.run")],
                        [self.edge("callee", relation="call")])
        self.assertIn("call_requires_caller_continuation:$current", self.record(doc)["errors"])

    def test_call_return_waits_for_callee_then_continues_after_pause(self):
        work = self.seed()
        ranges = [self.range("callee", 50, 60, "Helper.run"),
                  self.range("after", 20, 30, wait_for=["callee"])]
        doc = self.step(work, ranges, [self.edge("callee", relation="call"),
                                      self.edge("after", relation="return")], pause=True)
        self.assertTrue(self.record(doc)["accepted"])
        self.renew()
        callee = self.next()["work"]
        self.assertEqual(callee["scope"]["symbol"]["qualified_name"], "Helper.run")
        self.assertTrue(self.record(self.step(callee))["accepted"])
        after = self.next()["work"]
        self.assertEqual(after["scope"]["start"], 20)
        self.assertTrue(any(r["work_id"] == callee["work_id"] and r["result"] for r in after["coverage"]))
        group = self.operation_group("after", "EntryAbility.ets:25")
        self.assertTrue(self.record(self.step(after, groups=[group]))["accepted"])
        self.assertEqual(self.finish()["exploration_status"], "complete")

    def test_termination_needs_located_proof(self):
        work = self.seed()
        doc = self.step(work)
        doc["result"]["termination"]["evidence"] = [
            {"kind": "source", "source": "source", "summary": "没有源码位置"}]
        self.assertIn("termination_requires_located_evidence:$current", self.record(doc)["errors"])

    def test_boundary_uses_caller_continuation_saved_in_previous_round(self):
        work = self.seed()
        doc = self.step(work, [self.range("callee", 50, 60, "Library.run"),
                               self.range("after", 20, 30, wait_for=["callee"])],
                        [self.edge("callee", relation="call"),
                         self.edge("after", relation="return")], pause=True)
        self.assertTrue(self.record(doc)["accepted"])
        self.renew()
        callee = self.next()["work"]
        doc = self.step(callee)
        doc["result"]["termination"]["kind"] = "third_party_boundary"
        outcome = self.record(doc)
        self.assertTrue(outcome["accepted"], outcome)
        self.assertEqual(self.next()["work"]["scope"]["start"], 20)

    def test_platform_boundary_keeps_caller_continuation(self):
        work = self.seed()
        boundary = self.range("platform", 1, 1, "system.open", done=True)
        boundary["result"]["termination"]["kind"] = "platform_boundary"
        tail = self.range("after", 20, 30)
        out = self.record(self.step(work, [boundary, tail],
                                   [self.edge("platform", relation="call"), self.edge("after", relation="return")]))
        self.assertTrue(out["accepted"], out)
        self.assertEqual(self.next()["work"]["scope"]["start"], 20)

    def test_dependency_cycle_is_rejected_atomically(self):
        work = self.seed()
        ranges = [self.range("a", 11, 15, wait_for=["b"]), self.range("b", 16, 30, wait_for=["a"])]
        out = self.record(self.step(work, ranges, [self.edge("a"), self.edge("b")]))
        self.assertIn("dependency_cycle", out["errors"])
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM exploration_work_items").fetchone()[0], 2)

    def test_shared_work_exposes_all_incoming_edges(self):
        work = self.seed()
        ranges = [self.range("left", 11, 15, done=True), self.range("right", 16, 20, done=True),
                  self.range("join", 21, 30)]
        for item in ranges[:2]:
            item["result"]["termination"] = None
        edges = [self.edge("left", relation="branch"), self.edge("right", relation="branch"),
                 self.edge("join", source="left"), self.edge("join", source="right")]
        out = self.record(self.step(work, ranges, edges))
        self.assertTrue(out["accepted"], out)
        join = self.next()["work"]
        incoming = [e for e in join["transitions"] if e["target_work_id"] == join["work_id"]]
        self.assertEqual(len(incoming), 2)
        self.assertTrue(self.record(self.step(join))["accepted"])
        self.assertEqual(self.finish()["exploration_status"], "complete")

    def test_many_inline_branches_do_not_spawn_agents_or_hit_old_node_cap(self):
        work = self.seed()
        ranges = [self.range(f"branch-{i}", 100 + i, 100 + i,
                             conditions=[f"case={i}"], done=True) for i in range(80)]
        out = self.record(self.step(work, ranges, [self.edge(r["ref"], relation="branch") for r in ranges]))
        self.assertTrue(out["accepted"], out)
        self.assertEqual(self.finish()["exploration_status"], "complete")
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM tasks WHERE kind='component_semantic_analysis'").fetchone()[0], 1)

    def test_context_pages_preserve_range_results(self):
        from audit_runtime.exploration_context import read_exploration_context
        work = self.seed()
        ranges = [self.range(f"r{i}", 100 + i, 100 + i, done=i < 45) for i in range(46)]
        self.assertTrue(self.record(self.step(work, ranges, [self.edge(r["ref"]) for r in ranges]))["accepted"])
        active = self.next()["work"]
        self.assertIsNotNone(active["pagination"]["next_offset"])
        page = read_exploration_context(self.run, self.task["task_id"], self.task["attempt"],
                                        active["work_id"], active["pagination"]["next_offset"])["work"]
        self.assertTrue(page["coverage"])
        self.assertIsNone(page["pagination"]["next_offset"])

    def test_budget_pauses_without_losing_work(self):
        work = self.seed()
        self.assertTrue(self.record(self.step(work, [self.range("tail", 31, 40)], [self.edge("tail")]))["accepted"])
        self.assertEqual(self.next(budget=1)["reason"], "line_budget_reached")
        self.renew()
        self.assertEqual(self.next()["work"]["scope"]["start"], 31)

    def test_finished_work_has_no_unrecorded_lease(self):
        self.seed()
        self.assertFalse(self.finish()["accepted"])

    def test_retry_releases_only_unfinished_range(self):
        from audit_runtime.semantic_exploration import release_exploration_leases
        work = self.seed()
        with database(self.run / "run.db") as conn, transaction(conn):
            self.assertEqual(release_exploration_leases(conn, self.task["task_id"], self.task["attempt"]), 1)
        self.assertEqual(self.next()["work"]["work_id"], work["work_id"])

    def test_old_step_protocol_is_rejected(self):
        self.seed()
        out = self.record({"node_id": "old", "resume": None, "successors": []})
        self.assertFalse(out["accepted"])

    def test_unresolved_body_finishes_as_partial_not_export_failure(self):
        work = self.seed()
        doc = self.step(work, terminal=False)
        doc["result"]["checked"] = []
        doc["result"]["gaps"] = [{"target": "dynamic.handler", "reason": "调用点与注册源码核实后仍未知",
                                  "evidence": [self.evidence()]}]
        self.assertTrue(self.record(doc)["accepted"])
        out = self.finish()
        self.assertEqual(out["exploration_status"], "partial", out)
        result = json.loads(Path(out["result_ref"]).read_text())
        self.assertIn("dynamic.handler", result["coverage"]["unresolved_targets"])

    def test_partial_dynamic_resolution_keeps_proven_target_and_gap(self):
        work = self.seed()
        target = self.range("known", 70, 80, "Dynamic.run")
        doc = self.step(work, [target], [self.edge("known", relation="callback")])
        doc["result"]["gaps"] = [{"target": "registry.otherHandlers", "reason": "部分注册来自缺失依赖",
                                  "evidence": [self.evidence()]}]
        self.assertTrue(self.record(doc)["accepted"])
        target_work = self.next()["work"]
        self.assertEqual(target_work["scope"]["symbol"]["qualified_name"], "Dynamic.run")
        self.assertTrue(self.record(self.step(target_work))["accepted"])
        self.assertEqual(self.finish()["exploration_status"], "partial")

    def test_next_helper_sees_prior_inline_helper_result(self):
        work = self.seed()
        first = self.range("first", 50, 60, "First.run", done=True)
        first["result"]["operation_groups"] = [self.operation_group("first-op", "EntryAbility.ets:55")]
        second = self.range("second", 70, 80, "Second.run")
        out = self.record(self.step(work, [first, second],
                                   [self.edge("first", relation="callback"),
                                    self.edge("second", relation="callback")]))
        self.assertTrue(out["accepted"], out)
        next_work = self.next()["work"]
        prior = next(r for r in next_work["coverage"] if r["scope"]["symbol"]["qualified_name"] == "First.run")
        self.assertEqual(prior["result"]["operation_groups"][0]["group_key"], "first-op")
        self.assertTrue(prior["detail_available"])
        self.assertNotIn("facts", prior["result"])
        self.assertNotIn("context", prior["result"]["operation_groups"][0])
        from audit_runtime.exploration_context import read_exploration_context
        detail = read_exploration_context(self.run, self.task["task_id"], self.task["attempt"],
                                          prior["work_id"])["work"]
        self.assertIn("context", detail["result"]["operation_groups"][0])

    def test_return_dependency_keeps_complete_evidence(self):
        work = self.seed()
        ranges = [self.range("callee", 50, 60, "Helper.run"),
                  self.range("after", 20, 30, wait_for=["callee"])]
        doc = self.step(work, ranges, [self.edge("callee", relation="call"),
                                      self.edge("after", relation="return")])
        self.assertTrue(self.record(doc)["accepted"])
        callee = self.next()["work"]
        group = self.operation_group("callee-op", "EntryAbility.ets:55")
        self.assertTrue(self.record(self.step(callee, groups=[group]))["accepted"])
        after = self.next()["work"]
        dependency = next(r for r in after["coverage"] if r["work_id"] == callee["work_id"])
        self.assertFalse(dependency["detail_available"])
        self.assertEqual(dependency["result"]["operation_groups"][0], group)

    def test_inline_helper_evidence_needs_no_separate_work(self):
        work = self.seed()
        group = self.operation_group("helper-operation", "Helper.ets:50")
        out = self.record(self.step(work, groups=[group]))
        self.assertTrue(out["accepted"], out)
        self.assertEqual(self.finish()["exploration_status"], "complete")
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM exploration_work_items").fetchone()[0], 2)

    def test_loop_backedge_preserves_exit_without_reexpansion(self):
        work = self.seed(kind="choice")
        body = self.range("body", 11, 20, done=True)
        body["result"]["termination"] = None
        exit_range = self.range("exit", 21, 30)
        edges = [self.edge("body", relation="branch", condition="loop condition"),
                 self.edge("exit", relation="branch", condition="loop exits"),
                 self.edge("$current", source="body", relation="loop", condition="same relevant state")]
        out = self.record(self.step(work, [body, exit_range], edges))
        self.assertTrue(out["accepted"], out)
        exit_work = self.next()["work"]
        self.assertEqual(exit_work["scope"]["start"], 21)
        self.assertTrue(self.record(self.step(exit_work))["accepted"])
        self.assertEqual(self.finish()["exploration_status"], "complete")

    def test_distinct_columns_keep_same_line_branches_separate(self):
        work = self.seed()
        left = self.range("left", 15, 15, done=True)
        right = self.range("right", 15, 15, done=True)
        left["scope"]["start_column"] = 5
        right["scope"]["start_column"] = 30
        out = self.record(self.step(work, [left, right],
                                   [self.edge("left", relation="branch"), self.edge("right", relation="branch")]))
        self.assertTrue(out["accepted"], out)
        self.assertNotEqual(out["range_refs"]["left"], out["range_refs"]["right"])

    def test_wait_context_is_part_of_work_identity(self):
        work = self.seed()
        a = self.range("callee-a", 50, 60, "Helper.a")
        b = self.range("callee-b", 70, 80, "Helper.b")
        after_a = self.range("after-a", 20, 30, wait_for=["callee-a"])
        after_b = self.range("after-b", 20, 30, wait_for=["callee-b"])
        edges = [self.edge("callee-a", relation="call"), self.edge("callee-b", relation="call"),
                 self.edge("after-a", relation="return"), self.edge("after-b", relation="return")]
        out = self.record(self.step(work, [a, b, after_a, after_b], edges))
        self.assertTrue(out["accepted"], out)
        self.assertNotEqual(out["range_refs"]["after-a"], out["range_refs"]["after-b"])

    def test_total_budget_records_unfinished_ranges_as_gaps(self):
        work = self.seed()
        doc = self.step(work, [self.range("tail", 31, 40)], [self.edge("tail")])
        self.assertTrue(self.record(doc)["accepted"])
        with patch("audit_runtime.semantic_exploration.MAX_COMPONENT_ANALYZED_LINES", 1):
            out = self.finish()
        self.assertEqual(out["exploration_status"], "partial", out)
        result = json.loads(Path(out["result_ref"]).read_text())
        self.assertTrue(any("31-40" in x for x in result["coverage"]["unresolved_targets"]))

    def test_boundary_cannot_close_caller_without_continuation(self):
        work = self.seed()
        doc = self.step(work)
        doc["result"]["termination"]["kind"] = "platform_boundary"
        self.assertIn("boundary_requires_caller_continuation:$current", self.record(doc)["errors"])

    def test_unproven_security_check_cannot_enter_state(self):
        work = self.seed()
        child = self.range("child", 31, 40)
        child["state"]["security_checks"] = [
            {"location": "EntryAbility.ets:2", "subject_kind": "immediate_caller",
             "validated_property": "caller"}]
        out = self.record(self.step(work, [child], [self.edge("child")]))
        self.assertIn("security_check_not_evidenced:child", out["errors"])

    def test_stale_attempt_cannot_claim_work(self):
        self.seed()
        with self.assertRaisesRegex(ValueError, "stale_attempt"):
            next_exploration_node(self.run, self.task["task_id"], self.task["attempt"] + 1)

    def test_entry_update_requires_source_evidence(self):
        work = self.seed()
        doc = self.step(work)
        doc["entry_assessment"] = {"entry_status": "confirmed", "external_entry_status": "excluded",
                                   "confirmed_external_candidate_ids": [], "component_summary": "仅内部"}
        self.assertIn("entry_update_requires_evidence", self.record(doc)["errors"])

    def test_report_exposes_ranges_conditions_and_stop_evidence(self):
        work = self.seed()
        self.assertTrue(self.record(self.step(work))["accepted"])
        out = self.finish()
        self.assertEqual(out["exploration_status"], "complete")
        report = (self.run / "report.html")
        htmls = list(self.run.rglob("*.html"))
        self.assertTrue(htmls)
        text = htmls[0].read_text()
        self.assertIn("进入条件", text)
        self.assertIn("停止依据", text)
        self.assertIn("renderExplorationRange", text)
