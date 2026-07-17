import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILER = ROOT / ".opencode" / "skills" / "project-modeling" / "scripts" / "project_profiler.py"
SPEC = importlib.util.spec_from_file_location("project_profiler", PROFILER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class JSON5LibraryTests(unittest.TestCase):
    def test_supports_harmony_json5_syntax(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "module.json5"
            path.write_text(
                """
                // project config
                {
                  module: {
                    name: 'entry',
                    exported: true,
                    values: [1, 0x10,],
                  },
                }
                """,
                encoding="utf-8",
            )
            value = MODULE.parse_json5(path)
            self.assertEqual(value["module"]["name"], "entry")
            self.assertEqual(value["module"]["values"], [1, 16])


class ProjectProfilerTests(unittest.TestCase):
    def test_builds_normalized_project_model(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AppScope").mkdir()
            (root / "entry" / "src" / "main" / "ets" / "pages").mkdir(parents=True)
            (root / "AppScope" / "app.json5").write_text(
                "{ app: { bundleName: 'com.example.demo', vendor: 'demo', versionCode: 1, }, }",
                encoding="utf-8",
            )
            (root / "entry" / "src" / "main" / "module.json5").write_text(
                """
                {
                  module: {
                    name: 'entry',
                    type: 'entry',
                    requestPermissions: [{ name: 'ohos.permission.INTERNET' }],
                    abilities: [{
                      name: 'EntryAbility',
                      srcEntry: './ets/entryability/EntryAbility.ets',
                      exported: true,
                      skills: [{
                        actions: ['ohos.want.action.viewData'],
                        uris: [{ scheme: 'demo', host: 'open' }],
                      }],
                    }],
                  },
                }
                """,
                encoding="utf-8",
            )
            (root / "oh-package.json5").write_text(
                "{ dependencies: { '@ohos/example': '^1.0.0', }, }",
                encoding="utf-8",
            )
            # Invalid UTF-8 proves the profiler never opens source contents.
            (root / "entry" / "src" / "main" / "ets" / "pages" / "Index.ets").write_bytes(b"\xff\xfe")

            model = MODULE.profile_project(root)
            plan = MODULE.build_discovery_plan(model)

            self.assertEqual(model["status"], "complete")
            self.assertEqual(model["application"]["bundle_name"], "com.example.demo")
            self.assertEqual(model["summary"]["modules"], 1)
            self.assertEqual(model["summary"]["components"], 1)
            self.assertEqual(model["dependencies"][0]["name"], "@ohos/example")
            entry_types = {row["type"] for row in model["entry_candidates"]}
            self.assertEqual(entry_types, {"exported_component", "deeplink", "implicit_want"})
            self.assertNotIn("code_signals", model)
            self.assertNotIn("source_inventory", model)
            self.assertFalse(plan["source_content_scanned"])
            self.assertEqual(plan["units"][0]["scope"], "entry/src/main")
            self.assertEqual(plan["units"][0]["entry_candidate_ids"], ["PE-001", "PE-002", "PE-003"])
            self.assertEqual(
                {anchor["query"] for anchor in plan["units"][0]["anchors"]},
                {"EntryAbility", "onCreate", "onNewWant"},
            )

    def test_records_parse_errors_without_silent_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "module.json5").write_text("{ module: { name: 'broken' ", encoding="utf-8")

            model = MODULE.profile_project(root)

            self.assertEqual(model["status"], "partial")
            self.assertEqual(model["summary"]["parse_errors"], 1)
            self.assertEqual(model["parsed_files"][0]["status"], "error")

    def test_service_extension_gets_ipc_discovery_candidate_even_when_not_exported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "service" / "src" / "main").mkdir(parents=True)
            (root / "service" / "src" / "main" / "module.json5").write_text(
                """
                {
                  module: {
                    name: 'service',
                    extensionAbilities: [{
                      name: 'AccountService',
                      srcEntry: './ets/AccountService.ets',
                      type: 'service',
                      exported: false,
                    }],
                  },
                }
                """,
                encoding="utf-8",
            )

            model = MODULE.profile_project(root)
            plan = MODULE.build_discovery_plan(model)

            candidates = model["entry_candidates"]
            self.assertEqual([row["type"] for row in candidates], ["ipc_service_candidate"])
            self.assertEqual(len(plan["units"]), 1)
            self.assertEqual(plan["units"][0]["analysis_kinds"], ["ipc_server"])
            self.assertEqual(plan["units"][0]["ipc_candidate_ids"], [candidates[0]["candidate_id"]])
            self.assertIn("onRemoteMessageRequest", {row["query"] for row in plan["units"][0]["anchors"]})


if __name__ == "__main__":
    unittest.main()
