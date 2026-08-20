import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "resources/skills/project-modeling/scripts/project_profiler.py"
SPEC = importlib.util.spec_from_file_location("project_profiler", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProjectProfilerTest(unittest.TestCase):
    def assertValidModel(self, model):
        schema_path = ROOT / "resources/skills/audit-orchestration/config/schemas/project-model.schema.json"
        Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))).validate(model)

    def test_profiles_json5_entry_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            main = root / "entry/src/main"
            main.mkdir(parents=True)
            (main / "module.json5").write_text("""{
              module: { name: 'entry', type: 'entry', abilities: [{
                name: 'EntryAbility', exported: true,
                skills: [{ actions: ['ohos.want.action.viewData'], uris: [{scheme: 'demo'}] }],
              }] }
            }""", encoding="utf-8")
            model = MODULE.profile_project(root)
            self.assertValidModel(model)
            types = {row["type"] for row in model["entry_candidates"]}
            self.assertEqual(model["status"], "complete")
            self.assertIn("deeplink", types)
            self.assertNotIn("common_event_candidate", types)

    def test_form_extension_is_analyzed_without_direct_exported_entry(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            main = root / "entry/src/main"
            main.mkdir(parents=True)
            (main / "module.json5").write_text("""{
              module: { name: 'entry', type: 'entry',
                abilities: [{name: 'EntryAbility', exported: true}],
                extensionAbilities: [{
                  name: 'EntryFormAbility', type: 'form', exported: true,
                  srcEntry: './ets/entryformability/EntryFormAbility.ets',
                  permissions: ['com.example.permission.USE_FORM']
                }]
              }
            }""", encoding="utf-8")

            model = MODULE.profile_project(root)
            self.assertValidModel(model)
            components = {row["name"]: row for row in model["components"]}
            candidates = {}
            for row in model["entry_candidates"]:
                candidates.setdefault(row["component_name"], []).append(row)

            form = components["EntryFormAbility"]
            self.assertEqual(form["lifecycle_candidates"], ["onAddForm", "onUpdateForm", "onFormEvent"])
            self.assertEqual(form["permissions"], ["com.example.permission.USE_FORM"])
            self.assertEqual(
                {row["type"] for row in candidates["EntryFormAbility"]},
                {"component_scope"},
            )
            self.assertTrue(
                candidates["EntryFormAbility"][0]["trigger_facts"][
                    "requires_upstream_reachability_evidence"
                ]
            )
            self.assertIn(
                "exported_component",
                {row["type"] for row in candidates["EntryAbility"]},
            )

    def test_models_declared_hap_hsp_and_local_dependency(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "build-profile.json5").write_text("""{
              app: {
                products: [{name: 'default'}, {name: 'enterprise'}],
                buildModeSet: [{name: 'debug'}, {name: 'release'}]
              },
              modules: [
                {name: 'entry', srcPath: './apps/entry', targets: [
                  {name: 'default', applyToProducts: ['default', 'enterprise']}
                ]},
                {name: 'shared', srcPath: './services/shared', targets: [
                  {name: 'default', applyToProducts: ['enterprise']}
                ]}
              ]
            }""", encoding="utf-8")
            entry = root / "apps/entry"
            shared = root / "services/shared"
            ignored = root / "unused"
            for module_root in (entry, shared, ignored):
                (module_root / "src/main").mkdir(parents=True)
            (entry / "src/ohosTest").mkdir(parents=True)
            (entry / "src/main/module.json5").write_text("""{
              module: {name: 'entry', type: 'entry', abilities: [
                {name: 'EntryAbility', srcEntry: './ets/EntryAbility.ets', exported: true}
              ]}
            }""", encoding="utf-8")
            (entry / "src/ohosTest/module.json5").write_text(
                "{module:{name:'entry_test',type:'feature',abilities:[{name:'TestAbility',exported:true}]}}",
                encoding="utf-8",
            )
            (shared / "src/main/module.json5").write_text("""{
              module: {name: 'shared', type: 'shared', extensionAbilities: [
                {name: 'SharedService', type: 'service', srcEntry: './ets/SharedService.ets', exported: true}
              ]}
            }""", encoding="utf-8")
            (ignored / "src/main/module.json5").write_text(
                "{module:{name:'unused',type:'feature',abilities:[{name:'UnusedAbility',exported:true}]}}",
                encoding="utf-8",
            )
            (entry / "oh-package.json5").write_text(
                "{name:'entry',dependencies:{shared:'file:../../services/shared'}}",
                encoding="utf-8",
            )
            (shared / "oh-package.json5").write_text("{name:'shared',dependencies:{}}", encoding="utf-8")

            model = MODULE.profile_project(root)
            self.assertValidModel(model)
            self.assertEqual(model["status"], "complete")
            self.assertEqual(model["summary"]["modules"], 2)
            self.assertEqual(model["summary"]["discovered_modules"], 3)
            self.assertEqual({row["output_kind"] for row in model["modules"] if row["included_in_build"]}, {"hap", "hsp"})
            self.assertEqual({row["name"] for row in model["components"]}, {"EntryAbility", "SharedService"})
            self.assertNotIn("TestAbility", {row["name"] for row in model["components"]})
            self.assertNotIn("UnusedAbility", {row["name"] for row in model["components"]})
            self.assertEqual(len(model["module_dependencies"]), 1)
            edge = model["module_dependencies"][0]
            modules = {row["name"]: row for row in model["modules"]}
            self.assertEqual(edge["source_module_id"], modules["entry"]["module_id"])
            self.assertEqual(edge["target_module_id"], modules["shared"]["module_id"])
            self.assertEqual(model["build"]["products"], ["default", "enterprise"])
            self.assertEqual(model["build"]["build_modes"], ["debug", "release"])
            self.assertEqual(model["build"]["product_scope"], "union")

            repeated = MODULE.profile_project(root)
            self.assertEqual(
                [row["module_id"] for row in model["modules"]],
                [row["module_id"] for row in repeated["modules"]],
            )


if __name__ == "__main__":
    unittest.main()
