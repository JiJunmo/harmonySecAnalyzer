import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_discovery", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DiscoveryStreamingTests(unittest.TestCase):
    def make_run(self, td):
        run = Path(td) / "run"
        MODULE.cmd_init(SimpleNamespace(
            run_dir=str(run), target_repo="/tmp/target", scope="full",
        ))
        paths = MODULE.P(str(run))
        MODULE.write_json(paths["projectModel"], {
            "schema_version": 1,
            "status": "complete",
            "entry_candidates": [
                {"candidate_id": "PE-001"},
                {"candidate_id": "PE-002"},
            ],
        })
        MODULE.write_json(paths["discoveryPlan"], {
            "schema_version": 1,
            "project_model_schema_version": 1,
            "units": [
                {
                    "unit_id": "AU-001", "component_id": "CMP-001",
                    "entry_candidate_ids": ["PE-001"], "status": "planned",
                    "resolved_symbols": [], "atlas_query_ids": [], "gaps": [],
                },
                {
                    "unit_id": "AU-002", "component_id": "CMP-002",
                    "entry_candidate_ids": ["PE-002"], "status": "planned",
                    "resolved_symbols": [], "atlas_query_ids": [], "gaps": [],
                },
            ],
        })
        return run

    @staticmethod
    def discovery_result(task, status="completed", entries=None, seeds=None, excluded=None):
        return {
            "task_id": task["task_id"],
            "unit_id": task["unit_id"],
            "status": status,
            "resolved_symbols": ["EntryAbility.onNewWant"] if entries else [],
            "atlas_query_ids": [f"q-{task['unit_id']}"] if entries else [],
            "gaps": [],
            "entry_list": entries or [],
            "excluded_candidates": excluded or [],
            "unresolved_candidates": [],
            "coverage_gaps": [],
            "danger_seed_list": seeds or [],
            "query_evidence": [{
                "unit_id": task["unit_id"], "tool": "atlas_search",
                "query_id": f"q-{task['unit_id']}", "outcome": "matched",
            }] if entries else [],
        }

    def test_unit_completion_streams_path_work_and_preserves_terminal_matrix_state(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            paths = MODULE.P(str(run))
            enqueued = MODULE.cmd_enqueue_discovery(SimpleNamespace(run_dir=str(run)))
            first = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            self.assertEqual(first["kind"], "attack_surface_discovery")
            self.assertEqual(first["unit_id"], "AU-001")

            entry = {
                "component_id": "CMP-001",
                "project_candidate_ids": ["PE-001"],
                "type": "deeplink",
                "ability": "EntryAbility",
                "entry_function": "EntryAbility.onNewWant",
                "entry_function_file": "entry/EntryAbility.ets",
                "reachable_condition": "exported=true; scheme=demo",
            }
            seed = {
                "category": "sql", "operation": "query", "symbol": "Db.query",
                "symbol_file": "entry/Db.ets", "location": "entry/Db.ets:20",
                "sink_role": "terminal", "sink_parameter": "sql",
            }
            MODULE.write_json(first["result_path"], self.discovery_result(
                first, entries=[entry], seeds=[seed],
            ))
            completed_first = MODULE.cmd_complete(SimpleNamespace(
                run_dir=str(run), task=first["task_id"],
            ))

            self.assertEqual(enqueued["added"], 2)
            self.assertEqual(completed_first["added_path_tasks"], 1)
            shared_entries = MODULE.read_json(paths["entryList"])["entry_list"]
            shared_seeds = MODULE.read_json(paths["dangerSeedList"])["danger_seed_list"]
            self.assertTrue(shared_entries[0]["entry_id"].startswith("E-"))
            self.assertTrue(shared_seeds[0]["seed_id"].startswith("D-"))

            second = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            path_task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            self.assertEqual(second["unit_id"], "AU-002")
            self.assertEqual(path_task["kind"], "path_finding")

            MODULE.write_json(path_task["result_path"], {
                "task_id": path_task["task_id"],
                "work_item_id": path_task["work_item_id"],
                "entry_id": path_task["entry_id"],
                "conclusions": [{
                    "seed_id": path_task["seed_id"],
                    "pattern": path_task["pattern"],
                    "classification": "no_path",
                }],
            })
            MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=path_task["task_id"]))

            MODULE.write_json(second["result_path"], self.discovery_result(
                second,
                status="excluded",
                excluded=[{"project_candidate_id": "PE-002", "reason": "not externally reachable"}],
            ))
            completed_second = MODULE.cmd_complete(SimpleNamespace(
                run_dir=str(run), task=second["task_id"],
            ))
            matrix = MODULE.read_json(paths["attackMatrix"])
            coverage = MODULE.discovery_plan_coverage(str(run))

            self.assertTrue(completed_second["ok"])
            self.assertEqual(matrix["work_items"][0]["status"], "no_path")
            self.assertEqual(completed_second["added_path_tasks"], 0)
            self.assertTrue(coverage["ready"])
            self.assertEqual(coverage["by_status"], {"completed": 1, "excluded": 1})

    def test_discovery_result_must_account_for_every_unit_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            MODULE.cmd_enqueue_discovery(SimpleNamespace(run_dir=str(run)))
            task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(task["result_path"], self.discovery_result(task))

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))

            self.assertTrue(result["retry_scheduled"])
            self.assertIn("unaccounted_project_candidates:PE-001", result["error"])


if __name__ == "__main__":
    unittest.main()
