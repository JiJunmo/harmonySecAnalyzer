import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".opencode" / "skills" / "audit-orchestration" / "config"


class CapabilityRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((CONFIG / "audit_capabilities.json").read_text(encoding="utf-8"))
        cls.schema = json.loads((CONFIG / "schemas" / "audit-capabilities.schema.json").read_text(encoding="utf-8"))

    def routed_capabilities(self):
        return [
            capability
            for capability in self.registry["capabilities"]
            if capability["routing"] is not None
        ]

    def test_registry_matches_schema_and_has_unique_ids(self):
        Draft202012Validator.check_schema(self.schema)
        Draft202012Validator(self.schema).validate(self.registry)
        ids = [row["capability_id"] for row in self.registry["capabilities"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_score_totals_are_deterministic(self):
        dimensions = self.registry["scoring"]["dimensions"]
        for capability in self.registry["capabilities"]:
            score = capability["score"]
            self.assertEqual(score["total"], sum(score[name] for name in dimensions))

    def test_routed_capabilities_have_patterns_and_consistent_flags(self):
        for capability in self.routed_capabilities():
            self.assertTrue(capability["pattern_ids"], capability["capability_id"])
            routing_enabled = capability["routing"]["enabled"] is True
            self.assertEqual(capability["implementation"]["route"], routing_enabled)
            if not routing_enabled:
                self.assertTrue(capability["routing"].get("gap_reason"))

    def test_enabled_routes_have_partial_or_implemented_cards(self):
        for capability in self.routed_capabilities():
            if not capability["routing"]["enabled"]:
                continue
            self.assertIn(capability["status"], {"partial", "implemented"})
            self.assertTrue(capability["implementation"]["route"])
            self.assertTrue(capability["implementation"]["pattern_card"])
            for pattern_id in capability["pattern_ids"]:
                card = ROOT / ".opencode" / "skills" / "attack-patterns" / "patterns" / f"{pattern_id}.md"
                self.assertTrue(card.is_file(), pattern_id)

    def test_pattern_cards_are_thin_and_match_enabled_routes(self):
        pattern_dir = ROOT / ".opencode" / "skills" / "attack-patterns" / "patterns"
        enabled = {
            pattern_id
            for capability in self.routed_capabilities()
            if capability["routing"]["enabled"] is True
            for pattern_id in capability["pattern_ids"]
        }
        cards = {path.stem for path in pattern_dir.glob("*.md")}
        self.assertEqual(cards, enabled)
        required_sections = {
            "## 根因", "## 必须证明", "## 有效反证",
            "## 正常业务", "## 禁止推理", "## 证据要求",
        }
        for path in pattern_dir.glob("*.md"):
            content = path.read_text(encoding="utf-8")
            headings = {line.strip() for line in content.splitlines() if line.startswith("## ")}
            self.assertEqual(headings, required_sections, path.name)
            self.assertLessEqual(len(content.splitlines()), 32, path.name)

    def test_no_capability_claims_implemented_without_golden_corpus(self):
        for capability in self.registry["capabilities"]:
            if capability["status"] == "implemented":
                self.assertTrue(all(capability["implementation"].values()))

    def test_golden_flag_requires_four_case_kinds(self):
        corpus = json.loads((ROOT / "tests" / "golden" / "audit_capability_cases.json").read_text(encoding="utf-8"))
        by_capability = {}
        for case in corpus["cases"]:
            by_capability.setdefault(case["capability_id"], set()).add(case["kind"])
        expected = set(corpus["case_kinds"])
        for capability in self.registry["capabilities"]:
            if capability["implementation"]["golden_corpus"]:
                self.assertEqual(by_capability.get(capability["capability_id"]), expected)


if __name__ == "__main__":
    unittest.main()
