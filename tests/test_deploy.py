import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import deploy


ROOT = Path(__file__).resolve().parents[1]


class DeployRenderTest(unittest.TestCase):
    def test_opencode_subagents_can_write_dynamic_submission_paths(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            deploy.render_tree(ROOT, deploy.PROFILES["opencode"], Path("/bin/echo"), base=base)
            for name in ("component-semantic-analyzer.md", "exploitability-validator.md"):
                agent = base / ".opencode" / "agents" / name
                content = agent.read_text(encoding="utf-8")
                self.assertIn("  edit: allow", content, name)
                self.assertNotIn('    "*": deny', content, name)
                self.assertNotIn('    "**/reports/**": allow', content, name)

    def test_opencode_internal_skills_are_not_exposed_as_slash_commands(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            deploy.render_tree(ROOT, deploy.PROFILES["opencode"], Path("/bin/echo"), base=base)
            for name in deploy.OWNED_SKILLS:
                skill = base / ".opencode" / "skills" / name / "SKILL.md"
                content = skill.read_text(encoding="utf-8")
                self.assertIn("slash: false", content, name)

    def test_claude_render_produces_expected_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            deploy.render_tree(ROOT, deploy.PROFILES["claude"], Path("/bin/echo"), base=base)
            mcp = json.loads((base / ".mcp.json").read_text(encoding="utf-8"))
            self.assertEqual(mcp["mcpServers"]["atlas"]["command"], "/bin/echo")
            self.assertEqual(mcp["mcpServers"]["atlas"]["args"], ["mcp"])
            settings = json.loads((base / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertIn("mcp__atlas__*", settings["permissions"]["allow"])
            auditor = (base / ".claude" / "agents" / "harmony-auditor.md").read_text(encoding="utf-8")
            self.assertIn("mcp__atlas__project", auditor)
            self.assertIn("subagent_type", auditor)
            self.assertIn("run_in_background", auditor)
            semantic = (base / ".claude" / "agents" / "component-semantic-analyzer.md").read_text(encoding="utf-8")
            self.assertIn("tools: Read, Grep, Glob, Edit, Write", semantic)
            for name in deploy.OWNED_SKILLS:
                skill = (base / ".claude" / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
                self.assertNotIn("slash: false", skill, name)

    def test_render_is_idempotent_per_tool(self):
        with tempfile.TemporaryDirectory() as td:
            for tool in ("opencode", "claude"):
                a = Path(td) / tool / "a"
                b = Path(td) / tool / "b"
                deploy.render_tree(ROOT, deploy.PROFILES[tool], Path("/bin/echo"), base=a)
                deploy.render_tree(ROOT, deploy.PROFILES[tool], Path("/bin/echo"), base=b)
                files_a = {p.relative_to(a).as_posix(): p.read_bytes() for p in a.rglob("*") if p.is_file()}
                files_b = {p.relative_to(b).as_posix(): p.read_bytes() for p in b.rglob("*") if p.is_file()}
                self.assertEqual(files_a, files_b, tool)


class DeploySourceTest(unittest.TestCase):
    def test_runtime_smoke_uses_batch_scheduler_command(self):
        source = (ROOT / "deploy.py").read_text(encoding="utf-8")
        self.assertIn('invoke("claim-batch", first["run_dir"])', source)
        self.assertNotIn('invoke("next", first["run_dir"])', source)
        self.assertIn('status_payload["tasks"].get("running") != len(tasks)', source)

    def test_usage_hint_uses_current_audit_syntax(self):
        source = (ROOT / "deploy.py").read_text(encoding="utf-8")
        self.assertNotIn("/audit full <", source)
        self.assertIn("/audit <目标鸿蒙仓路径>", source)

    def test_tool_is_mandatory(self):
        source = (ROOT / "deploy.py").read_text(encoding="utf-8")
        self.assertIn("required=True", source)
        self.assertIn('choices=["opencode", "claude"]', source)

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
            legacy_entry_resolver = target / "agents/entry-resolver.md"
            legacy_component_analyzer = target / "agents/component-security-analyzer.md"
            legacy_pattern = target / "agents/flow-pattern-evaluator.md"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("legacy", encoding="utf-8")
            legacy_entry_resolver.write_text("legacy", encoding="utf-8")
            legacy_component_analyzer.write_text("legacy", encoding="utf-8")
            legacy_pattern.write_text("legacy", encoding="utf-8")
            # 渲染本地树(测试副作用,结束后清理;产物均被 gitignore)
            deploy.render_tree(ROOT, deploy.PROFILES["opencode"], Path("/bin/echo"))
            try:
                deploy.install_global(ROOT, deploy.PROFILES["opencode"], Path("/bin/echo"), target)
            finally:
                for p in (ROOT / ".opencode", ROOT / "AGENTS.md", ROOT / "opencode.json"):
                    if p.is_dir():
                        shutil.rmtree(p)
                    elif p.exists():
                        p.unlink()
            skill = (target / "skills/audit-orchestration/SKILL.md").read_text(encoding="utf-8")
            expected = target.resolve() / "skills/audit-orchestration/scripts/audit_orchestrator.py"
            self.assertIn(f"python3 {expected}", skill)
            self.assertNotIn("python3 resources/skills/audit-orchestration", skill)

            agent = (target / "agents/harmony-auditor.md").read_text(encoding="utf-8")
            self.assertIn('"*": deny', agent)
            self.assertIn("grep: allow", agent)
            self.assertIn("glob: allow", agent)
            self.assertIn("无论回复内容是什么，都只调用一次 `reconcile-batch", agent)
            self.assertTrue((target / "agents/component-semantic-analyzer.md").is_file())
            self.assertTrue((target / "agents/exploitability-validator.md").is_file())
            self.assertFalse((target / "agents/component-security-analyzer.md").exists())
            self.assertFalse((target / "agents/entry-resolver.md").exists())
            self.assertFalse(legacy.exists())
            self.assertFalse(legacy_entry_resolver.exists())
            self.assertFalse(legacy_component_analyzer.exists())
            self.assertFalse(legacy_pattern.exists())


if __name__ == "__main__":
    unittest.main()
