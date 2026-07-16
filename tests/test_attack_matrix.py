import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_matrix", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AttackMatrixTests(unittest.TestCase):
    def make_run(self, td, entry_type="deeplink", seeds=None):
        run = Path(td) / "run"
        MODULE.cmd_init(SimpleNamespace(run_dir=str(run), target_repo="/tmp/target", scope="full"))
        paths = MODULE.P(str(run))
        MODULE.write_json(paths["entryList"], {
            "entry_list": [{
                "entry_id": "E-001",
                "analysis_unit_id": "AU-001",
                "component_id": "CMP-001",
                "ability": "EntryAbility",
                "entry_function": "EntryAbility.onNewWant",
                "entry_function_file": "EntryAbility.ets",
                "type": entry_type,
                "project_candidate_ids": ["PE-001"],
            }],
            "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
        })
        MODULE.write_json(paths["dangerSeedList"], {"danger_seed_list": seeds or []})
        MODULE.write_json(paths["discoveryPlan"], {
            "schema_version": 1,
            "units": [{"unit_id": "AU-001", "status": "completed", "entry_ids": ["E-001"]}],
        })
        return run

    @staticmethod
    def sql_seed(seed_id, location="Db.ets:20"):
        return {
            "seed_id": seed_id,
            "category": "sql",
            "operation": "execute query",
            "symbol": "Database.query",
            "symbol_file": "Db.ets",
            "location": location,
            "sink_parameter": "sql",
        }

    def test_compiler_normalizes_duplicate_sinks_and_builds_sparse_work_item(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001"), self.sql_seed("D-002")])

            result = MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            paths = MODULE.P(str(run))
            seeds = MODULE.read_json(paths["normalizedSeeds"])
            matrix = MODULE.read_json(paths["attackMatrix"])
            queue = MODULE.read_jsonl(paths["queue"])

            self.assertTrue(result["ok"])
            self.assertEqual(result["seed_normalization"]["before"], 2)
            self.assertEqual(result["seed_normalization"]["after"], 1)
            self.assertEqual(seeds["danger_seeds"][0]["seed_aliases"], ["D-001", "D-002"])
            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["pattern"], "deeplink-injection")
            self.assertEqual(queue[0]["work_item_id"], matrix["work_items"][0]["work_item_id"])

    def test_incompatible_pair_is_not_added_as_cartesian_work(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, entry_type="exported_ability", seeds=[self.sql_seed("D-001")])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(matrix["work_items"], [])
            self.assertEqual(matrix["routing_gaps"][0]["reason"], "no_compatible_pattern_route")

    def test_intermediate_seed_is_excluded_without_routing_gap(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-001", "category": "network", "symbol": "State.write",
                "symbol_file": "State.ets", "location": "State.ets:10", "sink_role": "intermediate",
                "tags": ["web"], "discovered_from_unit": "AU-001",
            }
            run = self.make_run(td, entry_type="exported_ability", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(matrix["work_items"], [])
            self.assertEqual(matrix["routing_gaps"], [])
            self.assertEqual(matrix["seeds"][0]["disposition"], "excluded_intermediate")
            self.assertEqual(matrix["summary"]["excluded_intermediate"], 1)

    def test_discovery_unit_prefilter_avoids_unrelated_entry_sink_pair(self):
        with tempfile.TemporaryDirectory() as td:
            seed = self.sql_seed("D-001")
            seed["discovered_from_unit"] = "AU-001"
            run = self.make_run(td, seeds=[seed])
            paths = MODULE.P(str(run))
            entry_doc = MODULE.read_json(paths["entryList"])
            entry_doc["entry_list"].append({
                "entry_id": "E-002", "analysis_unit_id": "AU-002", "component_id": "CMP-002",
                "ability": "OtherAbility", "entry_function": "OtherAbility.onCreate",
                "entry_function_file": "OtherAbility.ets", "type": "deeplink",
                "project_candidate_ids": ["PE-002"],
            })
            MODULE.write_json(paths["entryList"], entry_doc)

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(paths["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["entry_id"], "E-001")
            self.assertEqual(matrix["summary"]["prefiltered_pairs"], 1)

    def test_seed_normalization_merges_unit_arrays_and_preserves_terminal_role(self):
        with tempfile.TemporaryDirectory() as td:
            first = self.sql_seed("D-001")
            first.update({"sink_role": "intermediate", "discovered_from_units": ["AU-001"]})
            second = self.sql_seed("D-002")
            second.update({"sink_role": "terminal", "reachable_from_unit": "AU-002"})
            run = self.make_run(td, seeds=[first, second])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            seed = MODULE.read_json(MODULE.P(str(run))["normalizedSeeds"])["danger_seeds"][0]

            self.assertEqual(seed["sink_role"], "terminal")
            self.assertEqual(seed["discovered_from_units"], ["AU-001"])
            self.assertEqual(seed["reachable_from_units"], ["AU-002"])

    def test_work_item_result_must_match_matrix_identity(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001")])
            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(run / task["result_file"], {
                "task_id": task["task_id"],
                "work_item_id": task["work_item_id"],
                "entry_id": task["entry_id"],
                "conclusions": [{
                    "seed_id": "D-WRONG",
                    "pattern": task["pattern"],
                    "classification": "no_path",
                }],
            })

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))
            coverage = MODULE.attack_matrix_coverage(str(run))

            self.assertTrue(result["ok"])
            self.assertTrue(result["retry_scheduled"])
            self.assertIn("seed_id_mismatch", result["error"])
            self.assertEqual(coverage["by_status"], {"queued": 1})
            self.assertFalse(coverage["ready"])
            self.assertTrue(Path(result["archived_result"]).is_file())

    def test_terminal_no_path_closes_matrix_work_item(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001")])
            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(run / task["result_file"], {
                "task_id": task["task_id"],
                "work_item_id": task["work_item_id"],
                "entry_id": task["entry_id"],
                "conclusions": [{
                    "seed_id": task["seed_id"],
                    "pattern": task["pattern"],
                    "classification": "no_path",
                    "atlas_evidence": {"query_id": "q-1"},
                }],
            })

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))
            coverage = MODULE.attack_matrix_coverage(str(run))

            self.assertTrue(result["ok"])
            self.assertEqual(result["classification"], "no_path")
            self.assertTrue(coverage["ready"])
            self.assertEqual(coverage["by_status"], {"no_path": 1})

    def test_analysis_gap_is_terminal_but_remains_visible(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001")])
            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(run / task["result_file"], {
                "task_id": task["task_id"],
                "work_item_id": task["work_item_id"],
                "entry_id": task["entry_id"],
                "conclusions": [{
                    "seed_id": task["seed_id"],
                    "pattern": task["pattern"],
                    "classification": "analysis_gap",
                    "evidence_gap": "Atlas returned terminal partial",
                }],
            })

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))
            coverage = MODULE.attack_matrix_coverage(str(run))
            gaps = MODULE.read_jsonl(MODULE.P(str(run))["analysisGaps"])

            self.assertTrue(result["ok"])
            self.assertTrue(coverage["ready"])
            self.assertEqual(coverage["by_status"], {"analysis_gap": 1})
            self.assertEqual(gaps[0]["work_item_id"], task["work_item_id"])


if __name__ == "__main__":
    unittest.main()
