import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".opencode/skills/audit-orchestration/config"


class CapabilityRegistryTest(unittest.TestCase):
    def test_registry_contract(self):
        registry = json.loads((CONFIG / "audit_capabilities.json").read_text(encoding="utf-8"))
        schema = json.loads((CONFIG / "schemas/audit-capabilities.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(registry)
        ids = [row["capability_id"] for row in registry["capabilities"]]
        self.assertEqual(len(ids), len(set(ids)))
        for row in registry["capabilities"]:
            self.assertEqual(
                set(row), {"capability_id", "title", "domain", "entry_types", "status"}
            )
            if row["status"] == "enabled":
                self.assertTrue(row["entry_types"])

if __name__ == "__main__":
    unittest.main()
