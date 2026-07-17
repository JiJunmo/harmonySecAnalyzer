import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_normalization", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def args(**values):
    return SimpleNamespace(**values)


def admitted_candidate(seed_id="D-001", end_to_end=True, branch="channel=external"):
    return {
        "seed_id": seed_id,
        "classification": "candidate",
        "pattern": "web-untrusted-navigation",
        "root_cause": {
            "boundary": "origin",
            "mechanism": "missing_guard",
            "file": "Entry.ets",
            "symbol": "Entry.openExternalPage",
            "branch": branch,
            "controlled_property": "want.parameters.url",
            "location": "20",
        },
        "admission": {
            "external_entry_reachable": True,
            "seed_reachable": True,
            "attacker_influence": True,
            "end_to_end_sink": end_to_end,
            "attacker_control_preserved": True,
            "influence_mode": "data",
        },
        "path": [
            {"stage": "entrypoint", "node": "Entry.onCreate", "file": "Entry.ets"},
            {"stage": "sink", "node": "WebPage.build/Web.src", "file": "WebPage.ets"},
        ],
        "taint_flow": "want.url -> Web.src",
    }


class EntryNormalizationTests(unittest.TestCase):
    def test_premerged_trigger_variants_contribute_types_and_candidate_ids(self):
        with tempfile.TemporaryDirectory() as td:
            run = Path(td) / "run"
            MODULE.cmd_init(args(run_dir=str(run), target_repo="/tmp/target", scope="full"))
            paths = MODULE.P(str(run))
            MODULE.write_json(paths["entryList"], {
                "entry_list": [{
                    "entry_id": "E-001", "analysis_unit_id": "AU-001", "component_id": "CMP-001",
                    "ability": "EntryAbility", "entry_function": "EntryAbility.onCreate",
                    "entry_function_file": "EntryAbility.ets", "type": "exported_ability",
                    "project_candidate_ids": ["PE-001"],
                    "trigger_variants": [
                        {"type": "exported_ability", "project_candidate_id": "PE-001"},
                        {"type": "implicit_want", "project_candidate_id": "PE-002"},
                        {"type": "deeplink", "project_candidate_ids": ["PE-003"]},
                    ],
                }],
            })

            result = MODULE.normalize_execution_entries(str(run))
            entry = MODULE.load_entries(str(run))[0]

            self.assertTrue(result["ok"])
            self.assertEqual(entry["entry_types"], ["deeplink", "exported_ability", "implicit_want"])
            self.assertEqual(entry["project_candidate_ids"], ["PE-001", "PE-002", "PE-003"])

    def test_compile_matrix_merges_manifest_aliases_by_execution_symbol(self):
        with tempfile.TemporaryDirectory() as td:
            run = Path(td) / "run"
            MODULE.cmd_init(args(run_dir=str(run), target_repo="/tmp/target", scope="full"))
            paths = MODULE.P(str(run))
            common = {
                "analysis_unit_id": "AU-001",
                "ability": "EntryAbility",
                "entry_function": "EntryAbility.onCreate",
                "entry_function_file": "EntryAbility.ets",
                "external_input": "want.parameters",
            }
            MODULE.write_json(paths["entryList"], {
                "entry_list": [
                    {**common, "entry_id": "E-001", "type": "exported_ability", "project_candidate_ids": ["PE-001"], "trigger": "explicit"},
                    {**common, "entry_id": "E-002", "type": "implicit_want", "project_candidate_ids": ["PE-002"], "trigger": "home"},
                    {**common, "entry_id": "E-003", "type": "implicit_want", "project_candidate_ids": ["PE-003"], "trigger": "service"},
                    {
                        "entry_id": "E-004", "analysis_unit_id": "AU-002", "ability": "CallerAbility",
                        "entry_function": "CallerAbility.onCreate", "entry_function_file": "CallerAbility.ets",
                        "type": "exported_ability", "project_candidate_ids": ["PE-004"], "trigger": "caller",
                    },
                ],
                "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
            })
            MODULE.write_json(paths["discoveryPlan"], {
                "schema_version": 1,
                "units": [
                    {"unit_id": "AU-001", "status": "completed", "entry_ids": ["E-001", "E-002", "E-003"]},
                    {"unit_id": "AU-002", "status": "completed", "entry_ids": ["E-004"]},
                ],
            })
            MODULE.write_json(paths["dangerSeedList"], {
                "danger_seed_list": [{
                    "seed_id": "D-001", "category": "fs", "operation": "bridge file read",
                    "symbol": "WebBridge.openFile", "symbol_file": "WebBridge.ets", "location": "WebBridge.ets:42",
                    "sink_role": "terminal", "sink_parameter": "path", "tags": ["web", "jsbridge"],
                }],
            })

            result = MODULE.cmd_compile_matrix(args(run_dir=str(run)))
            entries = MODULE.load_entries(str(run))
            queue = MODULE.read_jsonl(paths["queue"])
            plan = MODULE.read_json(paths["discoveryPlan"])

            self.assertTrue(result["ok"])
            self.assertEqual(result["entry_normalization"]["before"], 4)
            self.assertEqual(result["entry_normalization"]["after"], 2)
            self.assertEqual({row["entry_id"] for row in queue}, {"E-001", "E-004"})
            self.assertTrue(all(row["work_item_id"].startswith("AW-") for row in queue))
            self.assertEqual(entries[0]["project_candidate_ids"], ["PE-001", "PE-002", "PE-003"])
            self.assertEqual(entries[0]["entry_types"], ["exported_ability", "implicit_want"])
            self.assertEqual(len(entries[0]["trigger_variants"]), 3)
            self.assertEqual(plan["units"][0]["entry_ids"], ["E-001"])

    def test_ipc_transactions_keep_distinct_entry_identity(self):
        with tempfile.TemporaryDirectory() as td:
            run = Path(td) / "run"
            MODULE.cmd_init(args(run_dir=str(run), target_repo="/tmp/target", scope="full"))
            paths = MODULE.P(str(run))
            common = {
                "analysis_unit_id": "AU-IPC", "component_id": "CMP-IPC",
                "ability": "AccountStub", "entry_function": "AccountStub.onRemoteMessageRequest",
                "entry_function_file": "service/AccountStub.ets", "type": "ipc_stub_transaction",
                "project_candidate_ids": ["PE-IPC"], "ipc_stub_class": "AccountStub",
                "ipc_descriptor": "ohos.demo.IAccount", "publication_point": "AccountService.onConnect",
            }
            MODULE.write_json(paths["entryList"], {
                "entry_list": [
                    {**common, "entry_id": "E-IPC-1", "transaction_code": 1},
                    {**common, "entry_id": "E-IPC-2", "transaction_code": 2},
                ],
            })

            result = MODULE.normalize_execution_entries(str(run))
            entries = MODULE.load_entries(str(run))

            self.assertTrue(result["ok"])
            self.assertEqual(result["before"], 2)
            self.assertEqual(result["after"], 2)
            self.assertEqual({row["transaction_code"] for row in entries}, {1, 2})
            self.assertEqual(len({row["entry_key"] for row in entries}), 2)


class CandidateAdmissionAndDedupTests(unittest.TestCase):
    def make_run(self, td):
        run = Path(td) / "run"
        MODULE.cmd_init(args(run_dir=str(run), target_repo="/tmp/target", scope="full"))
        MODULE.enqueue_tasks(str(run), [
            {"kind": "path_finding", "entry_id": "E-001"},
            {"kind": "path_finding", "entry_id": "E-002"},
        ])
        return run

    def write_result(self, run, entry_id, conclusion):
        MODULE.write_json(
            run / "tasks" / f"path-{entry_id}.result.json",
            {"task_id": f"path-{entry_id}", "entry_id": entry_id, "conclusions": [conclusion]},
        )

    def test_same_root_cause_from_multiple_entries_has_one_validator(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            self.write_result(run, "E-001", admitted_candidate())
            self.write_result(run, "E-002", admitted_candidate())

            MODULE.cmd_next(args(run_dir=str(run)))
            first = MODULE.cmd_complete(args(run_dir=str(run), task="path-E-001"))
            MODULE.cmd_next(args(run_dir=str(run)))
            second = MODULE.cmd_complete(args(run_dir=str(run), task="path-E-002"))
            paths = MODULE.P(str(run))
            index = MODULE.read_json(paths["candidateIndex"])
            candidates = MODULE.read_jsonl(paths["candidates"])
            validation_tasks = [row for row in MODULE.read_jsonl(paths["queue"]) if row["kind"] == "path_validation"]

            self.assertEqual(first["promoted_candidates"], ["CAND-001"])
            self.assertEqual(second["promoted_candidates"], [])
            self.assertEqual(len(index["candidates"]), 1)
            self.assertEqual(len(validation_tasks), 1)
            self.assertEqual(candidates[0]["entry_ids"], ["E-001", "E-002"])
            self.assertEqual(len(candidates[0]["path_variants"]), 2)

    def test_same_root_cause_from_multiple_seeds_keeps_seed_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            self.write_result(run, "E-001", admitted_candidate(seed_id="D-OPEN"))
            self.write_result(run, "E-002", admitted_candidate(seed_id="D-READ"))

            MODULE.cmd_next(args(run_dir=str(run)))
            MODULE.cmd_complete(args(run_dir=str(run), task="path-E-001"))
            MODULE.cmd_next(args(run_dir=str(run)))
            MODULE.cmd_complete(args(run_dir=str(run), task="path-E-002"))
            paths = MODULE.P(str(run))
            index = MODULE.read_json(paths["candidateIndex"])
            candidate = MODULE.read_jsonl(paths["candidates"])[0]

            self.assertEqual(len(index["candidates"]), 1)
            self.assertTrue(candidate["fingerprint"].startswith("root:"))
            self.assertEqual(candidate["seed_ids"], ["D-OPEN", "D-READ"])
            self.assertEqual(
                [variant["seed_id"] for variant in candidate["path_variants"]],
                ["D-OPEN", "D-READ"],
            )

    def test_distinct_root_branches_to_same_sink_remain_separate(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            self.write_result(run, "E-001", admitted_candidate(seed_id="D-OPEN", branch="channel=partner"))
            self.write_result(run, "E-002", admitted_candidate(seed_id="D-OPEN", branch="channel=workspace"))

            MODULE.cmd_next(args(run_dir=str(run)))
            MODULE.cmd_complete(args(run_dir=str(run), task="path-E-001"))
            MODULE.cmd_next(args(run_dir=str(run)))
            MODULE.cmd_complete(args(run_dir=str(run), task="path-E-002"))
            paths = MODULE.P(str(run))

            self.assertEqual(len(MODULE.read_json(paths["candidateIndex"])["candidates"]), 2)
            self.assertEqual(
                len([row for row in MODULE.read_jsonl(paths["queue"]) if row["kind"] == "path_validation"]),
                2,
            )

    def test_incomplete_path_fails_candidate_admission(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            self.write_result(run, "E-001", admitted_candidate(end_to_end=False))

            MODULE.cmd_next(args(run_dir=str(run)))
            result = MODULE.cmd_complete(args(run_dir=str(run), task="path-E-001"))
            paths = MODULE.P(str(run))
            rejected = MODULE.read_jsonl(paths["rejected"])

            self.assertEqual(result["promoted_candidates"], [])
            self.assertEqual(MODULE.read_jsonl(paths["candidates"]), [])
            self.assertIn("end_to_end_sink", rejected[0]["reject_reason"])


if __name__ == "__main__":
    unittest.main()
