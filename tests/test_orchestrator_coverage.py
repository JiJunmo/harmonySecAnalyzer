import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EntryCandidateCoverageTests(unittest.TestCase):
    def make_run(self, run, unresolved=False, unit_status="completed", coverage_gap=False):
        paths = MODULE.P(str(run))
        MODULE.write_json(paths["projectModel"], {
            "schema_version": 1,
            "status": "complete",
            "diagnostics": [],
            "entry_candidates": [{"candidate_id": "PE-001"}, {"candidate_id": "PE-002"}],
        })
        entry_doc = {
            "entry_list": [{"entry_id": "E001", "project_candidate_ids": ["PE-001"]}],
            "excluded_candidates": [] if unresolved or coverage_gap else [{"project_candidate_id": "PE-002", "reason": "not externally reachable"}],
            "unresolved_candidates": [{"project_candidate_id": "PE-002", "evidence_gap": "symbol not found"}] if unresolved else [],
            "coverage_gaps": [{"project_candidate_id": "PE-002", "diagnostics": ["external reference unresolved"]}] if coverage_gap else [],
        }
        MODULE.write_json(paths["entryList"], entry_doc)
        MODULE.write_json(paths["discoveryPlan"], {
            "schema_version": 1,
            "units": [{"unit_id": "AU-001", "status": unit_status}],
        })
        MODULE.write_json(paths["normalizedSeeds"], {"schema_version": 1, "danger_seeds": []})
        MODULE.write_json(paths["attackMatrix"], {
            "schema_version": 1,
            "entries": [{"entry_id": "E001", "entry_key": "entry:test", "work_item_count": 0}],
            "seeds": [],
            "work_items": [],
            "routing_gaps": [],
        })
        MODULE.write_jsonl(paths["queue"], [{
            "task_id": "path-E001", "kind": "path_finding", "entry_id": "E001", "status": "done",
        }])
        MODULE.write_json(paths["candidateIndex"], MODULE.empty_candidate_index())

    def test_ready_when_all_project_candidates_have_resolved_disposition(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td))
            result = MODULE.cmd_validate_ready(SimpleNamespace(run_dir=td))
            self.assertTrue(result["ready"])
            self.assertEqual(result["entry_candidate_coverage"]["accounted"], 2)

    def test_unresolved_project_candidate_blocks_report(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td), unresolved=True)
            result = MODULE.cmd_validate_ready(SimpleNamespace(run_dir=td))
            self.assertFalse(result["ready"])
            self.assertEqual(result["entry_candidate_coverage"]["unresolved"], ["PE-002"])

    def test_planned_discovery_unit_blocks_report(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td), unit_status="planned")
            result = MODULE.cmd_validate_ready(SimpleNamespace(run_dir=td))
            self.assertFalse(result["ready"])
            self.assertEqual(result["discovery_plan_coverage"]["blocking_units"], ["AU-001"])

    def test_terminal_atlas_gap_allows_partial_coverage_report(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td), unit_status="atlas_gap", coverage_gap=True)
            result = MODULE.cmd_validate_ready(SimpleNamespace(run_dir=td))
            self.assertTrue(result["ready"])
            self.assertEqual(result["coverage_status"], "partial")
            self.assertEqual(result["entry_candidate_coverage"]["atlas_gaps"], ["PE-002"])

    def test_conflicting_candidate_dispositions_block_report(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td))
            path = MODULE.P(td)["entryList"]
            entry_doc = MODULE.read_json(path)
            entry_doc["excluded_candidates"].append({"project_candidate_id": "PE-001"})
            MODULE.write_json(path, entry_doc)

            result = MODULE.cmd_validate_ready(SimpleNamespace(run_dir=td))

            self.assertFalse(result["ready"])
            self.assertEqual(result["entry_candidate_coverage"]["conflicts"], ["PE-001"])

    def test_unknown_candidate_id_blocks_report(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td))
            path = MODULE.P(td)["entryList"]
            entry_doc = MODULE.read_json(path)
            entry_doc["excluded_candidates"].append({"project_candidate_id": "PE-999"})
            MODULE.write_json(path, entry_doc)

            result = MODULE.cmd_validate_ready(SimpleNamespace(run_dir=td))

            self.assertFalse(result["ready"])
            self.assertEqual(result["entry_candidate_coverage"]["unknown"], ["PE-999"])

    def test_finalize_marks_ready_run_completed_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td))
            paths = MODULE.P(td)
            MODULE.write_json(paths["session"], {"status": "running", "run_id": "test"})
            MODULE.write_json(paths["findings"], {"confirmed_vulnerabilities": []})
            MODULE.atomic_write_text(paths["report"], "# Report\n")

            first = MODULE.cmd_finalize(SimpleNamespace(run_dir=td))
            second = MODULE.cmd_finalize(SimpleNamespace(run_dir=td))
            session = MODULE.read_json(paths["session"])

            self.assertTrue(first["ok"])
            self.assertEqual(first["status"], "completed")
            self.assertEqual(session["status"], "completed")
            self.assertEqual(second["mode"], "already_finalized")

    def test_finalize_requires_report_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_run(Path(td))
            paths = MODULE.P(td)
            MODULE.write_json(paths["session"], {"status": "running", "run_id": "test"})

            result = MODULE.cmd_finalize(SimpleNamespace(run_dir=td))

            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "findings_missing_or_invalid")


if __name__ == "__main__":
    unittest.main()
