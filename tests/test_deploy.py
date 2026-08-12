import json
import shutil
import subprocess
import sys
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

            semantic = (base / ".opencode/agents/component-semantic-analyzer.md").read_text(encoding="utf-8")
            validator = (base / ".opencode/agents/exploitability-validator.md").read_text(encoding="utf-8")
            poc = (base / ".opencode/agents/poc-generator.md").read_text(encoding="utf-8")
            self.assertIn("confirmed > uncertain > excluded", semantic)
            self.assertIn("`external_entry_status`", semantic)
            self.assertIn("`invocation_control`", semantic)
            self.assertIn("不按源码目录、构建模块、依赖包、类名或类继承关系划分", semantic)
            self.assertIn("笛卡尔组合", semantic)
            self.assertIn("入口类型，不是组件排除条件", semantic)
            self.assertIn("不得把该限制解释为禁止读取当前组定性所需的链路源码", validator)
            self.assertIn("import、依赖包调用、继承、组合对象、普通函数调用和 `super` 调用都不是组件跳转", semantic)
            self.assertIn("`false` 表示存在反向证据", validator)
            self.assertIn("不得输出 `assurance_status`", poc)

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
            self.assertIn("Bash(python3 *audit_orchestrator.py*:*)", settings["permissions"]["allow"])
            auditor = (base / ".claude" / "agents" / "harmony-auditor.md").read_text(encoding="utf-8")
            self.assertIn("mcp__atlas__project", auditor)
            self.assertIn("subagent_type", auditor)
            self.assertIn("run_in_background", auditor)
            semantic = (base / ".claude" / "agents" / "component-semantic-analyzer.md").read_text(encoding="utf-8")
            self.assertIn("tools: Read, Grep, Glob, Edit, Write", semantic)
            for name in deploy.OWNED_SKILLS:
                skill = (base / ".claude" / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
                self.assertNotIn("slash: false", skill, name)

    def test_local_render_is_self_contained_and_cwd_independent(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as cwd:
            base = Path(td) / "vibe config with spaces"
            deploy.render_tree(ROOT, deploy.PROFILES["opencode"], Path("/bin/echo"), base=base)
            tree = base / ".opencode"
            orchestrator = tree / "skills/audit-orchestration/scripts/audit_orchestrator.py"
            self.assertTrue(orchestrator.is_file())
            self.assertTrue((tree / "skills/audit-orchestration/config/schemas/component-semantic-result.schema.json").is_file())
            self.assertTrue((tree / "skills/project-modeling/scripts/project_profiler.py").is_file())

            skill = (tree / "skills/audit-orchestration/SKILL.md").read_text(encoding="utf-8")
            self.assertIn(f'python3 "{orchestrator.resolve()}" prepare', skill)
            self.assertNotIn("{{audit_orchestrator_path}}", skill)
            self.assertNotIn("python3 resources/", skill)

            result = subprocess.run(
                [sys.executable, str(orchestrator), "--help"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

            for markdown in tree.rglob("*.md"):
                content = markdown.read_text(encoding="utf-8")
                self.assertNotIn("python3 resources/", content, markdown)
                self.assertNotRegex(content, r"\{\{[a-z_]+\}\}", markdown)

    def test_render_preserves_user_local_settings(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)
            deploy.render_tree(ROOT, deploy.PROFILES["claude"], Path("/bin/echo"), base=dest)
            local = dest / ".claude" / "settings.local.json"
            local.write_text('{"env": {"X": "1"}}', encoding="utf-8")
            deploy.render_tree(ROOT, deploy.PROFILES["claude"], Path("/bin/echo"), base=dest)
            self.assertTrue(local.exists(), "settings.local.json 不应被重新渲染删除")
            self.assertEqual(local.read_text(encoding="utf-8"), '{"env": {"X": "1"}}')

    def test_check_only_detects_drift(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td)
            deploy.render_tree(ROOT, deploy.PROFILES["claude"], Path("/bin/echo"), base=dest)
            good, problems = deploy.render_drift(ROOT, deploy.PROFILES["claude"], Path("/bin/echo"), dest=dest)
            self.assertTrue(good, problems)
            f = dest / ".claude" / "agents" / "harmony-auditor.md"
            f.write_text("tampered", encoding="utf-8")
            good, problems = deploy.render_drift(ROOT, deploy.PROFILES["claude"], Path("/bin/echo"), dest=dest)
            self.assertFalse(good)
            self.assertTrue(any("harmony-auditor.md" in p for p in problems), problems)
            f.unlink()
            good, problems = deploy.render_drift(ROOT, deploy.PROFILES["claude"], Path("/bin/echo"), dest=dest)
            self.assertFalse(good)
            self.assertTrue(any("缺失" in p for p in problems), problems)

    def test_render_is_idempotent_per_tool(self):
        with tempfile.TemporaryDirectory() as td:
            for tool in ("opencode", "claude"):
                dest = Path(td) / tool
                deploy.render_tree(ROOT, deploy.PROFILES[tool], Path("/bin/echo"), base=dest)
                before = {p.relative_to(dest).as_posix(): p.read_bytes() for p in dest.rglob("*") if p.is_file()}
                deploy.render_tree(ROOT, deploy.PROFILES[tool], Path("/bin/echo"), base=dest)
                after = {p.relative_to(dest).as_posix(): p.read_bytes() for p in dest.rglob("*") if p.is_file()}
                self.assertEqual(before, after, tool)


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

    def test_global_install_is_self_contained(self):
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
            deploy.install_global(ROOT, deploy.PROFILES["opencode"], Path("/bin/echo"), target)
            skill = (target / "skills/audit-orchestration/SKILL.md").read_text(encoding="utf-8")
            expected = target.resolve() / "skills/audit-orchestration/scripts/audit_orchestrator.py"
            self.assertIn(f'python3 "{expected}"', skill)
            self.assertNotIn("python3 resources/skills/audit-orchestration", skill)
            self.assertTrue(expected.is_file())
            self.assertTrue((target / "skills/audit-orchestration/config/schemas/exploitability-validation-result.schema.json").is_file())
            self.assertTrue((target / "AGENTS.md").is_file())

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
