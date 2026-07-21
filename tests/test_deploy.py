import tempfile
import unittest
from pathlib import Path

import deploy


ROOT = Path(__file__).resolve().parents[1]


class DeployTest(unittest.TestCase):
    def test_global_install_rewrites_runtime_paths(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "opencode"
            deploy.install_global(ROOT, Path("/bin/echo"), target)
            skill = (target / "skills/audit-orchestration/SKILL.md").read_text(encoding="utf-8")
            expected = target.resolve() / "skills/audit-orchestration/scripts/audit_orchestrator.py"
            self.assertIn(f"python3 {expected}", skill)
            self.assertNotIn("python3 .opencode/skills/audit-orchestration", skill)

            agent = (target / "agents/harmony-auditor.md").read_text(encoding="utf-8")
            self.assertIn('"*": deny', agent)
            self.assertIn("grep: allow", agent)
            self.assertIn("glob: allow", agent)


if __name__ == "__main__":
    unittest.main()
