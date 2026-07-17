import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_contracts", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ResultContractTests(unittest.TestCase):
    def test_all_worker_schemas_are_valid_draft_2020_12(self):
        for schema_path in MODULE.SCHEMAS_DIR.glob("*.schema.json"):
            schema = MODULE.read_json(str(schema_path))
            MODULE.Draft202012Validator.check_schema(schema)

    def test_path_schema_reports_precise_missing_field_path(self):
        errors = MODULE.worker_result_schema_errors("path_finding", {
            "task_id": "path-AW-1",
            "work_item_id": "AW-1",
            "entry_id": "E-1",
            "conclusions": [{"pattern": "deeplink-injection", "classification": "no_path"}],
        })

        self.assertTrue(any("schema:$.conclusions[0]" in error and "seed_id" in error for error in errors))

    def test_candidate_path_requires_structured_root_cause(self):
        errors = MODULE.worker_result_schema_errors("path_finding", {
            "task_id": "path-AW-1",
            "work_item_id": "AW-1",
            "entry_id": "E-1",
            "conclusions": [{
                "seed_id": "D-1",
                "pattern": "exported-ability-file",
                "classification": "candidate",
                "admission": {
                    "external_entry_reachable": True,
                    "seed_reachable": True,
                    "attacker_influence": True,
                    "end_to_end_sink": True,
                    "attacker_control_preserved": True,
                },
                "path": [{"stage": "entrypoint"}, {"stage": "sink"}],
                "atlas_evidence": {"query_id": "q-1"},
            }],
        })

        self.assertTrue(any("root_cause" in error for error in errors))

    def test_confirmed_validation_requires_all_six_gates_and_exploit_artifacts(self):
        errors = MODULE.worker_result_schema_errors("path_validation", {
            "task_id": "val-CAND-001",
            "candidate_id": "CAND-001",
            "entry_ids": ["E-1"],
            "classification": "confirmed_vulnerability",
            "exploitability": {
                "externally_reachable": True,
                "attacker_controlled": True,
                "sink_reached": True,
                "guard_bypassed_or_absent": False,
                "boundary_violated": True,
                "concrete_impact": True,
            },
        })

        self.assertTrue(any("guard_bypassed_or_absent" in error for error in errors))
        self.assertTrue(any("poc" in error for error in errors))

    def test_protected_exposure_requires_effective_guard_semantics(self):
        result = {
            "classification": "protected_exposure",
            "exploitability": {
                "externally_reachable": True,
                "attacker_controlled": True,
                "sink_reached": True,
                "guard_bypassed_or_absent": False,
                "boundary_violated": False,
                "concrete_impact": False,
            },
            "guards": [{"effectiveness": "unknown"}],
        }

        self.assertEqual(
            MODULE.validation_business_errors(result),
            ["business:protected_exposure_requires_effective_guard"],
        )

    def test_discovery_query_references_must_resolve(self):
        unit = {"unit_id": "AU-1", "entry_candidate_ids": ["PE-1"]}
        result = {
            "unit_id": "AU-1", "status": "completed",
            "resolved_symbols": [], "atlas_query_ids": ["q-missing"], "gaps": [],
            "entry_list": [{
                "component_id": "CMP-1", "project_candidate_ids": ["PE-1"],
                "entry_function": "Entry.onCreate", "entry_function_file": "Entry.ets",
            }],
            "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
            "danger_seed_list": [], "query_evidence": [],
        }

        errors = MODULE.discovery_result_errors(unit, result)

        self.assertIn("unresolved_atlas_query_ids:q-missing", errors)

    def test_ipc_discovery_entry_requires_stable_transaction_identity(self):
        result = {
            "task_id": "discover-AU-IPC", "unit_id": "AU-IPC", "status": "completed",
            "resolved_symbols": ["AccountStub.onRemoteMessageRequest"], "atlas_query_ids": ["q-ipc"],
            "gaps": [], "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
            "entry_list": [{
                "component_id": "CMP-IPC", "project_candidate_ids": ["PE-IPC"],
                "type": "ipc_stub_transaction", "ability": "AccountStub",
                "entry_function": "AccountStub.onRemoteMessageRequest",
                "entry_function_file": "service/AccountStub.ets",
                "ipc_stub_class": "AccountStub", "ipc_descriptor": "ohos.demo.IAccount",
                "transaction_code": 7, "publication_point": "AccountService.onConnect",
                "publication_kind": "service_on_connect", "remote_reachable": True,
            }],
            "danger_seed_list": [{
                "category": "privacy", "sink_role": "terminal", "symbol": "AccountStore.read",
                "atlas_query_ids": ["q-ipc"],
            }],
            "query_evidence": [{"query_id": "q-ipc", "outcome": "matched"}],
        }

        self.assertEqual(MODULE.worker_result_schema_errors("attack_surface_discovery", result), [])
        del result["entry_list"][0]["transaction_code"]
        errors = MODULE.worker_result_schema_errors("attack_surface_discovery", result)
        self.assertTrue(any("transaction_code" in error for error in errors))

    def test_ready_is_blocked_when_aggregate_reference_is_corrupted(self):
        with tempfile.TemporaryDirectory() as td:
            MODULE.cmd_init(SimpleNamespace(run_dir=td, target_repo="/tmp/target", scope="full"))
            paths = MODULE.P(td)
            MODULE.write_json(paths["projectModel"], {
                "schema_version": 1, "status": "complete", "entry_candidates": [{"candidate_id": "PE-1"}],
            })
            MODULE.write_json(paths["discoveryPlan"], {
                "schema_version": 1, "units": [{"unit_id": "AU-1", "status": "completed"}],
            })
            MODULE.write_json(paths["entryList"], {
                "entry_list": [{
                    "entry_id": "E-1", "project_candidate_ids": ["PE-1"],
                    "atlas_query_ids": ["q-missing"],
                }],
                "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
            })
            MODULE.write_json(paths["normalizedSeeds"], {"schema_version": 1, "danger_seeds": []})
            MODULE.write_json(paths["attackMatrix"], {
                "schema_version": 1, "entries": [{"entry_id": "E-1"}],
                "seeds": [], "work_items": [], "routing_gaps": [],
            })

            ready = MODULE.cmd_validate_ready(SimpleNamespace(run_dir=td))

            self.assertFalse(ready["ready"])
            self.assertIn("entry:E-1:unknown_query_ids:q-missing", ready["reference_integrity"]["errors"])


if __name__ == "__main__":
    unittest.main()
