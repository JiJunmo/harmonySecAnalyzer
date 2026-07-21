import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".opencode/skills/audit-orchestration/config"


class CapabilityRegistryTest(unittest.TestCase):
    def test_registry_contract_and_pattern_cards(self):
        registry = json.loads((CONFIG / "audit_capabilities.json").read_text(encoding="utf-8"))
        schema = json.loads((CONFIG / "schemas/audit-capabilities.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(registry)
        ids = [row["capability_id"] for row in registry["capabilities"]]
        self.assertEqual(len(ids), len(set(ids)))
        for row in registry["capabilities"]:
            if row["status"] not in {"partial", "implemented"}:
                continue
            self.assertTrue(row["entry_types"])
            self.assertTrue(row["pattern_ids"])
            for pattern in row["pattern_ids"]:
                self.assertTrue((ROOT / ".opencode/skills/attack-patterns/patterns" / f"{pattern}.md").is_file())

    def test_registry_has_no_task_routing_fields(self):
        registry = json.loads((CONFIG / "audit_capabilities.json").read_text(encoding="utf-8"))
        forbidden = {"routing", "seed_categories", "analysis_mode", "golden_corpus", "route"}
        for row in registry["capabilities"]:
            self.assertFalse(forbidden & set(row), row["capability_id"])
            self.assertFalse(forbidden & set(row.get("implementation", {})), row["capability_id"])


if __name__ == "__main__":
    unittest.main()
