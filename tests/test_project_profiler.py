import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / ".opencode/skills/project-modeling/scripts/project_profiler.py"
SPEC = importlib.util.spec_from_file_location("project_profiler", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProjectProfilerTest(unittest.TestCase):
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
            types = {row["type"] for row in model["entry_candidates"]}
            self.assertEqual(model["status"], "complete")
            self.assertIn("deeplink", types)
            self.assertIn("common_event_candidate", types)


if __name__ == "__main__":
    unittest.main()
