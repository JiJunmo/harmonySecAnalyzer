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
    def state(checks=None, control_state="preserved"):
        return {
            "controlled_properties": [{
                "name": "want.parameters.value",
                "control_state": control_state,
            }],
            "principal": {
                "origin": "third-party application",
                "immediate": "third-party application",
                "origin_binding": "preserved",
                "authority": "origin",
            },
            "security_check_ids": list(checks or []),
        }

    @staticmethod
    def symbol(name, line=1):
        return {
            "qualified_name": name,
            "file_path": "entry/src/main/ets/EntryAbility.ets",
            "line": line,
            "kind": "method",
        }

    @classmethod
    def successor(cls, name, line=1, state=None, decision="follow", reason=None,
                  relation="call"):
        return {
            "symbol": cls.symbol(name, line),
            "relation": relation,
            "condition": "always",
            "decision": decision,
            "stop_reason": reason,
            "state": state or cls.state(),
        }

    def step(self, work, successors=None, status="completed", stop_reason=None,
             assessment=None, gaps=None, operation_groups=None, component_calls=None,
             analyzed_symbols=None):
        successors = list(successors or [])
        analyzed_symbols = list(analyzed_symbols or [])
        document = {
            "node_id": work["node_id"],
            "work_type": work["work_type"],
            "status": status,
            "summary": "已完成当前节点源码分析",
            "stop_reason": stop_reason,
            "atlas_queries": [{
                "tool": "search" if work["work_type"] == "entry_discovery" else "calls",
                "source_symbol": None if work["work_type"] == "entry_discovery"
                else work["symbol"]["qualified_name"],
                "target_symbols": sorted(
                    {row["symbol"]["qualified_name"] for row in successors}
                    | {row["qualified_name"] for row in analyzed_symbols}
                ),
                "unresolved_targets": [],
            }],
            "analyzed_symbols": analyzed_symbols,
            "facts": [],
            "security_checks": [],
            "operation_groups": list(operation_groups or []),
            "component_calls": list(component_calls or []),
            "successors": successors,
            "gaps": list(gaps or []),
        }
        if work["work_type"] == "entry_discovery":
            document["entry_assessment"] = assessment or {
                "entry_status": "confirmed",
                "external_entry_status": "confirmed",
                "confirmed_external_candidate_ids": ["PE-001"],
                "component_summary": "处理外部 Want 输入",
            }
        return document

    @staticmethod
    def evidence(location="EntryAbility.ets:42"):
        return {
            "kind": "atlas_trace", "source": "atlas",
            "summary": "入口数据到达安全相关操作", "location": location,
        }

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

    @classmethod
    def component_call(cls):
        evidence = [cls.evidence("EntryAbility.ets:50")]
        return {
            "call_key": "to-target", "target_component_id": "CMP-002",
            "target_symbol": "TargetAbility.onCreate", "transport": "startAbility",
            "call_location": "EntryAbility.ets:50", "condition": "always",
            "invocation_control": {
                "control_state": "preserved", "condition": "external input selects target",
                "evidence": evidence,
            },
            "parameter_mappings": [{
                "source_property": "want.parameters.value",
                "target_property": "want.parameters.forwardedValue",
                "control_state": "preserved", "transform": "direct copy",
            }],
            "principal_transition": {
                "caller_principal": "third-party application",
                "callee_observed_principal": "EntryAbility",
                "origin_binding": "replaced_by_caller",
                "authority_used": "source_component", "evidence": evidence,
            },
            "security_checks": [], "evidence": evidence,
        }

    def close_and_build(self):
        outcome = finish_exploration_round(
            self.run, self.task["task_id"], self.task["attempt"],
        )
        self.assertIn(outcome["exploration_status"], {"complete", "partial"})
        self.assertEqual(outcome["status"], "completed")
        return json.loads(Path(outcome["result_ref"]).read_text(encoding="utf-8"))

    def record(self, document):
        self.step_file.write_text(json.dumps(document), encoding="utf-8")
        return record_exploration_step(
            self.run, self.task["task_id"], self.task["attempt"], self.step_file,
        )

    def next(self, budget=64):
        return next_exploration_node(
            self.run, self.task["task_id"], self.task["attempt"], budget,
        )

    def seed_entry(self, successors):
        root = self.next(budget=100)
        self.assertEqual(root["work"]["work_type"], "entry_discovery")
        outcome = self.record(self.step(root["work"], successors))
        self.assertTrue(outcome["accepted"], outcome)

    def test_depth_first_cycle_deduplication_and_idempotent_record(self):
        self.seed_entry([
            self.successor("EntryAbility.first", 10),
            self.successor("EntryAbility.second", 20),
        ])
        second = self.next(budget=100)["work"]
        self.assertEqual(second["symbol"]["qualified_name"], "EntryAbility.second")
        second_step = self.step(second, [self.successor("EntryAbility.deep", 30)])
        first_submit = self.record(second_step)
        duplicate_submit = self.record(second_step)
        self.assertTrue(first_submit["accepted"])
        self.assertTrue(duplicate_submit["idempotent"])

        deep = self.next(budget=100)["work"]
        self.assertEqual(deep["symbol"]["qualified_name"], "EntryAbility.deep")
        self.assertTrue(self.record(self.step(
            deep, [self.successor("EntryAbility.second", 20)],
        ))["accepted"])

        first = self.next(budget=100)["work"]
        self.assertEqual(first["symbol"]["qualified_name"], "EntryAbility.first")
        self.assertTrue(self.record(self.step(first))["accepted"])
        self.assertTrue(self.next(budget=100)["round_complete"])

        with database(self.run / "run.db") as conn:
            names = [
                json.loads(row["symbol_json"])["qualified_name"]
                for row in conn.execute("SELECT symbol_json FROM exploration_nodes")
            ]
            self.assertEqual(names.count("EntryAbility.second"), 1)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) n FROM exploration_edges"
            ).fetchone()["n"], 4)

    def test_same_symbol_with_different_security_state_is_not_merged(self):
        self.seed_entry([
            self.successor("EntryAbility.handle", 10, self.state()),
            self.successor("EntryAbility.handle", 10, self.state(["CHECK-owner"])),
        ])
        with database(self.run / "run.db") as conn:
            rows = conn.execute(
                """SELECT state_key FROM exploration_nodes
                   WHERE symbol_json LIKE '%EntryAbility.handle%'"""
            ).fetchall()
            self.assertEqual(len(rows), 2)
            self.assertNotEqual(rows[0]["state_key"], rows[1]["state_key"])

    def test_stopped_boundary_is_visible_but_not_queued(self):
        self.seed_entry([self.successor("EntryAbility.handle", 10)])
        current = self.next(budget=100)["work"]
        platform = self.successor(
            "system.openUrl", 40, decision="stop", reason="platform_boundary",
        )
        self.assertTrue(self.record(self.step(current, [platform]))["accepted"])
        self.assertTrue(self.next(budget=100)["round_complete"])
        result = finish_exploration_round(
            self.run, self.task["task_id"], self.task["attempt"],
        )
        self.assertEqual(result["exploration_status"], "complete")
        self.assertEqual(result["open_nodes"], 0)
        self.assertTrue(finish_exploration_round(
            self.run, self.task["task_id"], self.task["attempt"],
        )["idempotent"])
        with database(self.run / "run.db") as conn:
            boundary = conn.execute(
                "SELECT status,stop_reason FROM exploration_nodes WHERE stop_reason='platform_boundary'"
            ).fetchone()
            self.assertEqual(dict(boundary), {
                "status": "stopped", "stop_reason": "platform_boundary",
            })

    def test_long_path_is_paused_after_evidence_is_recorded(self):
        self.seed_entry([self.successor("EntryAbility.one", 10)])
        current = self.next(budget=1)["work"]
        self.assertTrue(self.record(self.step(
            current, [self.successor("EntryAbility.two", 20)],
        ))["accepted"])
        paused = self.next(budget=1)
        self.assertTrue(paused["round_complete"])
        self.assertEqual(paused["reason"], "function_budget_reached_mid_path")
        self.assertTrue(paused["continuation_saved"])
        self.assertEqual(paused["processed_functions"], 1)
        result = finish_exploration_round(
            self.run, self.task["task_id"], self.task["attempt"],
        )
        self.assertEqual(result["exploration_status"], "running")
        self.assertEqual(result["open_nodes"], 1)

    def test_short_path_continues_with_next_path_in_same_round(self):
        self.seed_entry([
            self.successor("EntryAbility.first", 10),
            self.successor("EntryAbility.second", 20),
        ])
        second = self.next(budget=64)
        self.assertEqual(second["work"]["symbol"]["qualified_name"], "EntryAbility.second")
        self.assertTrue(self.record(self.step(second["work"]))["accepted"])

        following = self.next(budget=64)
        self.assertFalse(following["round_complete"])
        self.assertTrue(following["starting_new_path"])
        self.assertEqual(
            following["work"]["symbol"]["qualified_name"], "EntryAbility.first",
        )

    def test_function_budget_stops_at_closed_path_before_next_path(self):
        self.seed_entry([
            self.successor("EntryAbility.first", 10),
            self.successor("EntryAbility.second", 20),
        ])
        second = self.next(budget=1)["work"]
        self.assertTrue(self.record(self.step(second))["accepted"])

        paused = self.next(budget=1)
        self.assertTrue(paused["round_complete"])
        self.assertEqual(
            paused["reason"], "function_budget_reached_at_path_boundary",
        )
        self.assertFalse(paused["continuation_saved"])
        with database(self.run / "run.db") as conn:
            queued = conn.execute(
                "SELECT COUNT(*) n FROM exploration_nodes WHERE status='queued'"
            ).fetchone()["n"]
            self.assertEqual(queued, 1)

    def test_long_ordinary_chain_is_compacted_into_bounded_checkpoints(self):
        self.seed_entry([self.successor("EntryAbility.level1", 1)])
        checkpoint = 1
        checkpoint_count = 0
        while checkpoint <= 50:
            work = self.next(budget=100)["work"]
            self.assertEqual(
                work["symbol"]["qualified_name"], f"EntryAbility.level{checkpoint}",
            )
            analyzed_levels = list(range(checkpoint + 1, min(checkpoint + 9, 51)))
            next_checkpoint = checkpoint + 9
            successors = [
                self.successor(f"EntryAbility.level{next_checkpoint}", next_checkpoint)
            ] if next_checkpoint <= 50 else []
            analyzed = [
                self.symbol(f"EntryAbility.level{level}", level)
                for level in analyzed_levels
            ]
            self.assertTrue(self.record(self.step(
                work, successors, analyzed_symbols=analyzed,
            ))["accepted"])
            checkpoint_count += 1
            checkpoint = next_checkpoint
        self.assertEqual(self.next(budget=100)["reason"], "no_open_nodes")
        result = finish_exploration_round(
            self.run, self.task["task_id"], self.task["attempt"],
        )
        self.assertEqual(result["exploration_status"], "complete")
        self.assertEqual(checkpoint_count, 6)
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute(
                "SELECT MAX(depth) depth FROM exploration_nodes"
            ).fetchone()["depth"], 6)
        compiled = json.loads(Path(result["result_ref"]).read_text(encoding="utf-8"))
        self.assertEqual(len(compiled["coverage"]["entry_symbols_checked"]), 50)

    def test_ordinary_functions_are_analyzed_inside_one_checkpoint(self):
        self.seed_entry([self.successor("EntryAbility.handle", 10)])
        work = self.next(budget=100)["work"]
        analyzed = [
            self.symbol("EntryAbility.parseInput", 20),
            self.symbol("EntryAbility.normalizeValue", 30),
        ]
        outcome = self.record(self.step(work, analyzed_symbols=analyzed))
        self.assertTrue(outcome["accepted"], outcome)
        self.assertTrue(self.next(budget=100)["round_complete"])

        result = self.close_and_build()
        self.assertEqual(result["coverage"]["entry_symbols_checked"], [
            "EntryAbility.handle",
            "EntryAbility.normalizeValue",
            "EntryAbility.parseInput",
        ])
        with database(self.run / "run.db") as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) n FROM exploration_nodes"
            ).fetchone()["n"], 2)

    def test_symbol_cannot_be_both_inlined_and_deferred(self):
        self.seed_entry([self.successor("EntryAbility.handle", 10)])
        work = self.next(budget=100)["work"]
        shared = self.symbol("EntryAbility.shared", 20)
        outcome = self.record(self.step(
            work,
            successors=[self.successor("EntryAbility.shared", 20)],
            analyzed_symbols=[shared],
        ))
        self.assertFalse(outcome["accepted"])
        self.assertTrue(any(
            "symbol_cannot_be_analyzed_and_successor" in row
            for row in outcome["errors"]
        ))

    def test_component_work_limit_becomes_visible_coverage_gap(self):
        with patch(
            "audit_runtime.semantic_exploration.MAX_COMPONENT_WORK_NODES", 2,
        ):
            self.seed_entry([self.successor("EntryAbility.handle", 10)])
            work = self.next(budget=100)["work"]
            outcome = self.record(self.step(
                work, [self.successor("EntryAbility.deep", 20)],
            ))
        self.assertTrue(outcome["accepted"], outcome)
        self.assertEqual(outcome["budget_truncated"], ["EntryAbility.deep"])
        self.assertTrue(self.record(self.step(
            work, [self.successor("EntryAbility.deep", 20)],
        ))["idempotent"])
        self.assertTrue(self.next(budget=100)["round_complete"])
        result = self.close_and_build()
        self.assertEqual(result["coverage"]["exploration_summary"]["status"], "partial")
        self.assertIn("EntryAbility.deep", result["coverage"]["unresolved_targets"])

    def test_component_round_limit_closes_remaining_work_as_gap(self):
        self.seed_entry([self.successor("EntryAbility.handle", 10)])
        with patch("audit_runtime.semantic_exploration.MAX_COMPONENT_ROUNDS", 1):
            outcome = finish_exploration_round(
                self.run, self.task["task_id"], self.task["attempt"],
            )
        self.assertEqual(outcome["status"], "completed", outcome)
        self.assertEqual(outcome["exploration_status"], "partial")
        result = json.loads(Path(outcome["result_ref"]).read_text(encoding="utf-8"))
        self.assertIn("EntryAbility.handle", result["coverage"]["unresolved_targets"])

    def test_invalid_step_and_stale_attempt_do_not_change_state(self):
        root = self.next()["work"]
        invalid = self.step(root, [self.successor("EntryAbility.handle", 10)])
        invalid["atlas_queries"][0]["target_symbols"] = []
        outcome = self.record(invalid)
        self.assertFalse(outcome["accepted"])
        self.assertTrue(any("symbols_not_observed_by_atlas" in row for row in outcome["errors"]))
        with database(self.run / "run.db") as conn:
            node = conn.execute(
                "SELECT status FROM exploration_nodes WHERE node_id=?", (root["node_id"],)
            ).fetchone()
            self.assertEqual(node["status"], "leased")
        with self.assertRaisesRegex(ValueError, "stale_attempt"):
            next_exploration_node(self.run, self.task["task_id"], self.task["attempt"] + 1)

    def test_retry_reclaims_the_node_leased_by_previous_attempt(self):
        first = self.next()["work"]
        with database(self.run / "run.db") as conn, transaction(conn):
            conn.execute(
                "UPDATE tasks SET status='queued' WHERE task_id=?", (self.task["task_id"],)
            )
        claimed = claim_batch(self.run, 1)
        retried = claimed["tasks"][0]
        self.assertEqual(retried["attempt"], self.task["attempt"] + 1)
        resumed = next_exploration_node(
            self.run, retried["task_id"], retried["attempt"],
        )
        self.assertEqual(resumed["work"]["node_id"], first["node_id"])
        with database(self.run / "run.db") as conn:
            node = conn.execute(
                "SELECT status,lease_attempt FROM exploration_nodes WHERE node_id=?",
                (first["node_id"],),
            ).fetchone()
            self.assertEqual(dict(node), {"status": "leased", "lease_attempt": retried["attempt"]})

    def test_cli_exposes_exploration_commands(self):
        args = parser().parse_args([
            "explore-next", str(self.run), "--task-id", self.task["task_id"],
            "--attempt", str(self.task["attempt"]),
        ])
        result = dispatch(args)
        self.assertEqual(result["work"]["work_type"], "entry_discovery")

    def test_compiler_merges_only_equivalent_operations_across_nodes(self):
        self.seed_entry([
            self.successor("EntryAbility.first", 10),
            self.successor("EntryAbility.second", 20),
        ])
        base = self.operation_group("base", "EntryAbility.ets:42")
        second_operation = self.operation_group("second", "EntryAbility.ets:70")
        second = self.next(budget=100)["work"]
        self.assertTrue(self.record(self.step(
            second, operation_groups=[base, second_operation],
        ))["accepted"])

        protected = self.operation_group("protected", "EntryAbility.ets:42", [{
            "type": "caller whitelist", "location": "EntryAbility.ets:35",
            "protects": "sensitive operation", "subject_kind": "origin_principal",
            "validated_property": "caller bundle name", "behavior": "allow trusted callers",
            "evidence": [self.evidence("EntryAbility.ets:35")],
        }])
        duplicate = json.loads(json.dumps(base))
        duplicate["group_key"] = "duplicate-in-another-node"
        first = self.next(budget=100)["work"]
        self.assertTrue(self.record(self.step(
            first, operation_groups=[duplicate, protected],
        ))["accepted"])
        self.assertTrue(self.next(budget=100)["round_complete"])

        result = self.close_and_build()
        self.assertEqual(len(result["operation_groups"]), 3)
        locations = [row["operation"]["location"] for row in result["operation_groups"]]
        self.assertEqual(locations.count("EntryAbility.ets:42"), 2)
        self.assertIn("EntryAbility.ets:70", locations)
        self.assertEqual(len({row["group_key"] for row in result["operation_groups"]}), 3)
        self.assertEqual(result["coverage"]["exploration_summary"]["max_depth"], 1)

    def test_compiler_carries_component_calls_and_gaps(self):
        self.seed_entry([self.successor("EntryAbility.forward", 50)])
        work = self.next(budget=100)["work"]
        unresolved = self.successor(
            "UnknownSdk.dispatch", 90, decision="stop", reason="unresolved",
        )
        self.assertTrue(self.record(self.step(
            work, successors=[unresolved], component_calls=[self.component_call()],
        ))["accepted"])
        self.assertTrue(self.next(budget=100)["round_complete"])

        result = self.close_and_build()
        self.assertEqual(len(result["component_calls"]), 1)
        self.assertEqual(result["component_calls"][0]["target_component_id"], "CMP-002")
        self.assertIn("UnknownSdk.dispatch", result["coverage"]["unresolved_targets"])
        self.assertEqual(result["coverage"]["exploration_summary"]["status"], "partial")

    def test_step_rejects_malformed_semantic_output_before_persistence(self):
        self.seed_entry([self.successor("EntryAbility.handle", 10)])
        work = self.next(budget=100)["work"]
        outcome = self.record(self.step(work, operation_groups=[{"group_key": "incomplete"}]))
        self.assertTrue(outcome["ok"], outcome)
        self.assertFalse(outcome["accepted"])
        self.assertTrue(any("schema:$.operation_groups[0]" in row for row in outcome["errors"]))
        with database(self.run / "run.db") as conn:
            status = conn.execute(
                "SELECT status FROM exploration_nodes WHERE node_id=?", (work["node_id"],)
            ).fetchone()["status"]
            self.assertEqual(status, "leased")

    def test_compiled_result_enters_existing_validation_pipeline(self):
        self.seed_entry([self.successor("EntryAbility.handle", 10)])
        work = self.next(budget=100)["work"]
        self.assertTrue(self.record(self.step(
            work, operation_groups=[self.operation_group("operation", "EntryAbility.ets:42")],
        ))["accepted"])
        self.assertTrue(self.next(budget=100)["round_complete"])
        result = self.close_and_build()
        self.assertEqual(len(result["operation_groups"]), 1)
        claimed = claim_batch(self.run, 5)
        self.assertEqual(claimed["count"], 1, claimed)
        self.assertEqual(claimed["tasks"][0]["kind"], "exploitability_validation")

    def test_formal_scheduler_continues_rounds_and_compiles_final_result(self):
        self.seed_entry([self.successor("EntryAbility.level1", 10)])
        level1 = self.next(budget=1)["work"]
        self.assertTrue(self.record(self.step(
            level1, [self.successor("EntryAbility.level2", 20)],
        ))["accepted"])
        self.assertEqual(
            self.next(budget=1)["reason"], "function_budget_reached_mid_path",
        )
        first_round = finish_exploration_round(
            self.run, self.task["task_id"], self.task["attempt"],
        )
        self.assertEqual(first_round["status"], "queued", first_round)
        self.assertTrue(first_round["continuation"])
        second_batch = claim_batch(self.run, 1)
        self.assertEqual(second_batch["count"], 1, second_batch)
        second = second_batch["tasks"][0]
        self.assertEqual(second["task_id"], self.task["task_id"])
        self.assertEqual(second["attempt"], 1)
        task_doc = json.loads(Path(second["task_file"]).read_text(encoding="utf-8"))
        self.assertEqual(task_doc["input"]["exploration_protocol"]["round_no"], 2)
        self.assertEqual(
            task_doc["input"]["exploration_protocol"]["round_function_budget"], 64,
        )
        self.assertEqual(
            task_doc["input"]["exploration_protocol"]["step_symbol_budget"], 8,
        )
        self.assertEqual(
            task_doc["input"]["exploration_protocol"]["component_checkpoint_limit"], 64,
        )
        self.assertEqual(
            task_doc["input"]["exploration_protocol"]["component_round_limit"], 8,
        )
        self.assertTrue(second["result_schema_file"].endswith(
            "component-exploration-step.schema.json"
        ))

        level2 = next_exploration_node(
            self.run, second["task_id"], second["attempt"], budget=1,
        )["work"]
        self.step_file.write_text(json.dumps(self.step(level2)), encoding="utf-8")
        self.assertTrue(record_exploration_step(
            self.run, second["task_id"], second["attempt"], self.step_file,
        )["accepted"])
        final_round = finish_exploration_round(self.run, second["task_id"], second["attempt"])
        self.assertEqual(final_round["status"], "completed", final_round)
        self.assertFalse(final_round["continuation"])
        with database(self.run / "run.db") as conn:
            task = conn.execute(
                "SELECT status,result_ref FROM tasks WHERE task_id=?", (second["task_id"],)
            ).fetchone()
            self.assertEqual(task["status"], "completed")
            result = json.loads(Path(task["result_ref"]).read_text(encoding="utf-8"))
            self.assertEqual(result["coverage"]["exploration_summary"]["rounds"], 2)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) n FROM semantic_analyses"
            ).fetchone()["n"], 1)

        exported = export_state(self.run)
        graph_path = Path(exported["exports"]["exploration_graph.json"])
        graph = json.loads(graph_path.read_text(encoding="utf-8"))["items"]
        self.assertEqual(len(graph["components"]), 1)
        self.assertEqual(graph["components"][0]["rounds"], 2)
        self.assertEqual(len(graph["nodes"]), 3)

        refreshed = refresh_live_report(self.run)
        self.assertTrue(refreshed["ok"], refreshed)
        report_html = Path(refreshed["report_html"]).read_text(encoding="utf-8")
        self.assertIn("渐进探索过程", report_html)
        self.assertIn("EntryAbility.level2", report_html)


if __name__ == "__main__":
    unittest.main()
