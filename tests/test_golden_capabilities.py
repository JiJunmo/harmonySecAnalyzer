import importlib.util
import json
import unittest
from collections import defaultdict
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".opencode" / "skills" / "audit-orchestration" / "config"
ORCHESTRATOR = CONFIG.parent / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_golden", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ADMISSION = {
    "external_entry_reachable", "seed_reachable", "attacker_influence",
    "end_to_end_sink", "attacker_control_preserved",
}
CASE_KINDS = {"vulnerability", "effective_guard", "benign_business", "insufficient_evidence"}
EXPECTED_CLASS = {
    "vulnerability": "confirmed_vulnerability",
    "effective_guard": "protected_exposure",
    "benign_business": "benign_business_flow",
    "insufficient_evidence": "insufficient_evidence",
}


class GoldenCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads((ROOT / "tests" / "golden" / "audit_capability_cases.json").read_text(encoding="utf-8"))
        cls.schema = json.loads((CONFIG / "schemas" / "golden-cases.schema.json").read_text(encoding="utf-8"))
        cls.registry = json.loads((CONFIG / "audit_capabilities.json").read_text(encoding="utf-8"))

    def test_corpus_schema_and_unique_case_ids(self):
        Draft202012Validator.check_schema(self.schema)
        Draft202012Validator(self.schema).validate(self.corpus)
        ids = [case["case_id"] for case in self.corpus["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(self.corpus["case_kinds"]), CASE_KINDS)

    def test_each_enabled_capability_has_four_semantic_oracles(self):
        by_capability = defaultdict(set)
        for case in self.corpus["cases"]:
            by_capability[case["capability_id"]].add(case["kind"])
        enabled_capabilities = {
            row["capability_id"] for row in self.registry["capabilities"]
            if row["implementation"]["route"]
        }
        self.assertEqual(set(by_capability), enabled_capabilities)
        for capability_id in enabled_capabilities:
            self.assertEqual(by_capability[capability_id], CASE_KINDS)

    def test_oracles_enforce_admission_and_validation_semantics(self):
        for case in self.corpus["cases"]:
            self.assertEqual(set(case["path"]["required_admission"]), ADMISSION, case["case_id"])
            validation = case["validation"]
            self.assertEqual(validation["classification"], EXPECTED_CLASS[case["kind"]], case["case_id"])
            gates = validation["gates"]
            if case["kind"] == "vulnerability":
                self.assertTrue(all(gates.values()), case["case_id"])
            elif case["kind"] == "effective_guard":
                self.assertFalse(gates["guard_bypassed_or_absent"], case["case_id"])
                self.assertFalse(gates["boundary_violated"], case["case_id"])
                self.assertFalse(gates["concrete_impact"], case["case_id"])
            elif case["kind"] == "benign_business":
                self.assertFalse(gates["boundary_violated"], case["case_id"])
                self.assertFalse(gates["concrete_impact"], case["case_id"])
            else:
                self.assertFalse(all(gates.values()), case["case_id"])

    def test_oracles_map_to_current_worker_contracts(self):
        for index, case in enumerate(self.corpus["cases"], start=1):
            work_id = f"AW-GOLDEN-{index:03d}"
            path_result = {
                "task_id": f"path-{work_id}", "work_item_id": work_id, "entry_id": "E-GOLDEN",
                "conclusions": [{
                    "seed_id": "D-GOLDEN", "pattern": case["pattern_id"], "classification": "candidate",
                    "root_cause": {
                        "boundary": "other", "mechanism": "missing_guard",
                        "file": "Golden.ets", "symbol": "Golden.execute",
                        "branch": f"case={case['case_id']}", "controlled_property": "external.input",
                    },
                    "admission": {**{name: True for name in ADMISSION}, "influence_mode": "data", "evidence": case["code_facts"]},
                    "path": [{"stage": "entrypoint"}, {"stage": "sink"}],
                    "atlas_evidence": {"query_id": f"q-golden-{index}"},
                }],
            }
            self.assertEqual(MODULE.worker_result_schema_errors("path_finding", path_result), [], case["case_id"])

            expected = case["validation"]
            validation_result = {
                "task_id": f"val-CAND-{index:03d}", "candidate_id": f"CAND-{index:03d}",
                "entry_ids": ["E-GOLDEN"], "classification": expected["classification"],
                "exploitability": expected["gates"],
            }
            if case["kind"] == "vulnerability":
                validation_result.update({
                    "security_boundary": {"violation": True}, "impact": "golden concrete impact",
                    "severity": "high", "cwe": "CWE-284", "poc": "golden poc",
                    "atlas_evidence": {"query_id": f"q-golden-{index}"},
                })
            else:
                validation_result["demotion_reason"] = expected["required_evidence"][0]
            if case["kind"] == "effective_guard":
                validation_result["guards"] = [{"effectiveness": "effective"}]
            elif case["kind"] == "benign_business":
                validation_result["business_intent"] = {"is_public_api": True}
            elif case["kind"] == "insufficient_evidence":
                validation_result["evidence_gap"] = expected["required_evidence"][0]
            self.assertEqual(MODULE.worker_result_schema_errors("path_validation", validation_result), [], case["case_id"])
            self.assertEqual(MODULE.validation_business_errors(validation_result), [], case["case_id"])


if __name__ == "__main__":
    unittest.main()
