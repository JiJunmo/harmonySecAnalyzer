import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import deploy


ROOT = Path(__file__).resolve().parents[1]


class DeployTest(unittest.TestCase):
    def test_atlas_smoke_uses_resolved_executable_instead_of_temporary_stub(self):
        atlas = Path("C:/Tools/atlas.exe")
        actions = iter(("index", "sync"))
        commands = []

        def completed(command, **kwargs):
            commands.append(command)
            action = next(actions)
            payload = {"ok": True, "action": action, "files_indexed": 1}
            output = Path(command[command.index("--output") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(deploy.json.dumps(payload), encoding="utf-8")
            noisy_stdout = "Atlas\xc2\xa0index\xc2\xa0complete\n"
            return deploy.subprocess.CompletedProcess(command, 0, stdout=noisy_stdout, stderr="")

        with patch.object(deploy.subprocess, "run", side_effect=completed):
            good, message = deploy.smoke_atlas_indexer(
                ROOT / deploy.ATLAS_INDEXER_REL, "python", atlas,
            )

        self.assertTrue(good, message)
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertEqual(command[command.index("--atlas") + 1], str(atlas))
            self.assertNotEqual(Path(command[command.index("--atlas") + 1]).parent, Path(tempfile.gettempdir()))

    def test_global_install_rewrites_runtime_paths(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "opencode"
            legacy = target / "agents/entry-planner.md"
            legacy_pattern = target / "agents/flow-pattern-evaluator.md"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("legacy", encoding="utf-8")
            legacy_pattern.write_text("legacy", encoding="utf-8")
            deploy.install_global(ROOT, Path("/bin/echo"), target)
            skill = (target / "skills/audit-orchestration/SKILL.md").read_text(encoding="utf-8")
            expected = target.resolve() / "skills/audit-orchestration/scripts/audit_orchestrator.py"
            self.assertIn(f"python3 {expected}", skill)
            self.assertNotIn("python3 .opencode/skills/audit-orchestration", skill)

            agent = (target / "agents/harmony-auditor.md").read_text(encoding="utf-8")
            self.assertIn('"*": deny', agent)
            self.assertIn("grep: allow", agent)
            self.assertIn("glob: allow", agent)
            self.assertTrue((target / "agents/entry-resolver.md").is_file())
            self.assertTrue((target / "agents/security-assessor.md").is_file())
            self.assertFalse(legacy.exists())
            self.assertFalse(legacy_pattern.exists())


if __name__ == "__main__":
    unittest.main()
