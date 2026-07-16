import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_run_isolation", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RunIsolationTests(unittest.TestCase):
    def test_repeated_audits_allocate_distinct_run_directories(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target app"
            target.mkdir()
            args = SimpleNamespace(
                reports_root=str(root / "reports"),
                target_repo=str(target),
                scope="full",
            )

            first = MODULE.cmd_new_run(args)
            second = MODULE.cmd_new_run(args)

            self.assertTrue(first["ok"])
            self.assertTrue(second["ok"])
            self.assertNotEqual(first["run_dir"], second["run_dir"])
            self.assertEqual(first["project_key"], second["project_key"])
            self.assertEqual(Path(first["run_dir"]).parent, Path(second["run_dir"]).parent)
            self.assertTrue((Path(first["run_dir"]) / "session.json").is_file())
            self.assertTrue((Path(second["run_dir"]) / "session.json").is_file())

    def test_init_rejects_existing_run_without_modifying_it(self):
        with tempfile.TemporaryDirectory() as td:
            run = Path(td) / "existing-run"
            args = SimpleNamespace(
                run_dir=str(run),
                target_repo="/tmp/example",
                scope="full",
            )
            first = MODULE.cmd_init(args)
            marker = run / "history-marker.txt"
            marker.write_text("preserve", encoding="utf-8")

            second = MODULE.cmd_init(args)

            self.assertTrue(first["ok"])
            self.assertFalse(second["ok"])
            self.assertEqual(second["error"], "run_dir_not_empty")
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
