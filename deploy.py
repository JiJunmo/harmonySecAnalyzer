#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harmonySecAnalyzer 部署脚本（OpenCode / Claude Code 双工具）

规范源位于 resources/（模板 + 运行时脚本），生成物不入库：
.opencode/、.claude/、opencode.json、.mcp.json、AGENTS.md、CLAUDE.md
均由本脚本按 --tool 渲染生成。

用法:
  python deploy.py --tool opencode             # 本地配置:本项目内用 opencode 审计
  python deploy.py --tool claude               # 本地配置:本项目内用 Claude Code 审计
  python deploy.py --tool opencode --global    # 全局安装到 ~/.config/opencode
  python deploy.py --tool claude --global      # 全局安装到 ~/.claude(并注册 atlas MCP)
  python deploy.py --tool claude --uninstall   # 卸载全局安装的资源
  python deploy.py --tool opencode --check-only  # 不写入,校验生成物与模板一致性(供 CI)
  python deploy.py --tool claude --atlas /path/to/atlas

跨平台: macOS / Windows / Linux。部署脚本使用标准库,运行时依赖见 requirements.txt。
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------- 常量(匹配 resources/ 规范源结构) ----------------

ORCH_REL = "resources/skills/audit-orchestration/scripts/audit_orchestrator.py"
PROFILER_REL = "resources/skills/project-modeling/scripts/project_profiler.py"
ATLAS_INDEXER_REL = "resources/skills/project-modeling/scripts/atlas_indexer.py"
ORCHESTRATION_RUNTIME_FILES = [
    f"resources/skills/audit-orchestration/scripts/audit_runtime/{name}"
    for name in (
        "__init__.py", "common.py", "store.py", "contracts.py", "evidence.py", "reporting.py",
        "commands.py", "initialization.py", "lifecycle.py", "correlation.py", "scheduler.py", "task_context.py", "cli.py",
    )
]

REQUIRED = [
    "deploy.py", "requirements.txt",
    ORCH_REL,
    PROFILER_REL,
    ATLAS_INDEXER_REL,
    *ORCHESTRATION_RUNTIME_FILES,
    "resources/agents/harmony-auditor.md",
    "resources/agents/component-semantic-analyzer.md",
    "resources/agents/exploitability-validator.md",
    "resources/agents/poc-generator.md",
    "resources/commands/audit.md",
    "resources/skills/audit-workflow/SKILL.md",
    "resources/skills/audit-orchestration/SKILL.md",
    "resources/skills/audit-orchestration/config/audit_capabilities.json",
    "resources/skills/audit-orchestration/config/schemas/audit-capabilities.schema.json",
    "resources/skills/audit-orchestration/config/schemas/project-model.schema.json",
    "resources/skills/audit-orchestration/config/schemas/component-semantic-result.schema.json",
    "resources/skills/audit-orchestration/config/schemas/exploitability-validation-result.schema.json",
    "resources/skills/audit-orchestration/config/schemas/poc-result.schema.json",
    "resources/skills/project-modeling/SKILL.md",
    "resources/docs/shared-conventions.md",
]

AGENTS = ["harmony-auditor.md", "component-semantic-analyzer.md", "exploitability-validator.md", "poc-generator.md"]
SKILLS = ["audit-workflow", "audit-orchestration", "project-modeling"]
OWNED_AGENTS = AGENTS
LEGACY_AGENTS = ["entry-planner.md", "entry-resolver.md", "component-security-analyzer.md", "flow-pattern-evaluator.md", "flow-validator.md", "flow-analyzer.md", "security-assessor.md"]
OWNED_COMMANDS = ["audit.md"]
OWNED_SKILLS = SKILLS
LEGACY_SKILLS = ["attack-patterns"]

# ---------------- 描述与工具集合(两工具共享的语义数据) ----------------

AGENT_DESCRIPTIONS = {
    "harmony-auditor.md": "鸿蒙 ArkTS 白盒安全审计编排者。负责确定性初始化、任务调度和报告准入，不直接分析源码。",
    "component-semantic-analyzer.md": "以单个组件为单位提取输入、安全相关操作和跨组件调用控制事实。只处理 component_semantic_analysis 任务。",
    "exploitability-validator.md": "根据已落盘语义事实执行有界的六维漏洞有效性验证。只处理 exploitability_validation 任务。",
    "poc-generator.md": "为已确认漏洞生成结构化、可人工复现的 PoC 触发套件，产出 ArkTS/Shell 等可执行片段。只处理 poc_generation 任务。",
}

ATLAS_TOOLS = ["project", "search", "symbol", "explore", "calls", "path", "trace", "impact", "file_dependencies"]
ATLAS_TOOL_SETS = {
    "harmony-auditor.md": ["project"],
    "component-semantic-analyzer.md": ATLAS_TOOLS,
    "exploitability-validator.md": ["project", "symbol", "explore", "calls", "path", "trace"],
    "poc-generator.md": ["project", "symbol", "explore", "path", "trace"],
}

COMMAND_DESCRIPTION = "对 HarmonyOS ArkTS 项目执行组件驱动的白盒安全审计"
ARGUMENT_HINT = "<repo-path> [--incremental] [--resume <run-dir>] [--capability <CAP-ID>] [--component <Name>]"

SKILL_DESCRIPTIONS = {
    "audit-orchestration": "基于 SQLite 的组件级安全分析运行时调用协议。当需要执行审计运行时的 prepare/claim-batch/reconcile-batch/finalize/resume/status 命令，或确认 run 状态机、准入条件、增量/能力/组件模式行为与 run 目录结构时使用。",
    "audit-workflow": "以组件为任务单位、以实际敏感操作组为判断单位的审计语义。当需要确认组件语义分析、跨组件连接、六维验证、根因归并与 Atlas 有界追踪的执行边界时使用。",
    "project-modeling": "确定性解析 HarmonyOS JSON5 工程配置，为组件任务生成提供项目事实与入口候选。当需要了解项目模型生成过程、Profiler 输出边界或 Atlas 索引准入条件时使用。",
}

# ---------------- 每工具 profile ----------------

def _opencode_permission(agent, tools):
    atlas = {f"atlas_{t}": "allow" for t in tools}
    if agent == "harmony-auditor.md":
        return {
            "external_directory": "allow",
            "read": {"*": "allow", "**/reports/**/tasks/**": "deny"},
            "grep": "allow",
            "glob": "allow",
            "task": {"*": "deny", "component-semantic-analyzer": "allow", "exploitability-validator": "allow", "poc-generator": "allow"},
            "skill": "allow",
            **atlas,
            "bash": {"*": "deny", "python3 *audit_orchestrator.py*": "allow"},
            "edit": "deny",
        }
    return {"external_directory": "allow", "read": "allow", "edit": "allow", **atlas}


def _claude_tools(agent):
    base = "Read, Grep, Glob"
    tools = ATLAS_TOOL_SETS[agent]
    mcp = ", ".join(f"mcp__atlas__{t}" for t in tools)
    if agent == "harmony-auditor.md":
        return f"{base}, Skill, Agent, Bash, {mcp}"
    return f"{base}, Edit, Write, {mcp}"


OPENCODE_PROFILE = {
    "tool": "opencode",
    "executable": "opencode",
    "dir": ".opencode",
    "docs_file": "AGENTS.md",
    "global_dir": "~/.config/opencode",
    "atlas_prefix": "atlas_",
    "config_file": "opencode.json",
    "snippets": {
        "skill_load": "先加载 `project-modeling`、`audit-orchestration` 和 `audit-workflow`。",
        "atlas_project_call": "调用 `atlas_project(open)` 打开目标项目索引。",
        "dispatch_call": "TaskTool 调用，一次全部派发；每个调用使用句柄的 `assigned_agent`，并将 `worker_prompt` 原样作为 prompt",
        "batch_wait": "TaskTool",
        "file_tools": "文件查看与查找使用 `read`、`glob`、`grep`。",
    },
    "command_dispatch": "",
    "doc": {
        "intro": "本项目同时适配 OpenCode 与 Claude Code 的 HarmonyOS ArkTS 白盒安全审计多智能体系统。本文件面向 OpenCode，由 `python3 deploy.py --tool opencode` 生成；Claude Code 侧见 `CLAUDE.md`（由 `--tool claude` 生成）。",
        "entry": "- 命令：`/audit [--incremental] [--capability CAP-ID] [--component Component] <repo-path>`\n- 编排者：工具配置目录中的 `agents/harmony-auditor.md`",
        "extra": "## 资源与部署\n\n- `.opencode/` 是 OpenCode 资源目录（agents/commands/skills），由 `python3 deploy.py --tool opencode` 生成，不入库。\n- Atlas MCP 配置在 `opencode.json`，部署时写入本机 atlas 路径。\n- 全局安装后任意目录启动 opencode 即可用 `/audit`：`python3 deploy.py --tool opencode --global`；卸载：`python3 deploy.py --tool opencode --uninstall`。",
    },
}

CLAUDE_PROFILE = {
    "tool": "claude",
    "executable": "claude",
    "dir": ".claude",
    "docs_file": "CLAUDE.md",
    "global_dir": "~/.claude",
    "atlas_prefix": "mcp__atlas__",
    "config_file": ".mcp.json",
    "snippets": {
        "skill_load": "先使用 Skill 工具依次加载 `audit-orchestration`、`audit-workflow` 和 `project-modeling` 三个技能，按其中协议执行。",
        "atlas_project_call": "调用 `mcp__atlas__project` 打开目标项目索引：`action=\"open\"`，`project_path` 为目标仓库绝对路径。",
        "dispatch_call": "Agent 工具调用，一次全部并行派发；每个调用的 `subagent_type` 使用句柄的 `assigned_agent`，`prompt` 原样使用句柄的 `worker_prompt`，`description` 填简短任务说明，并设置 `run_in_background: false` 等待整批返回",
        "batch_wait": "Agent 工具",
        "file_tools": "文件查看与查找使用 Read、Glob、Grep 工具。子代理回复只用于批次同步，不引用其内容，也不据其判断任务成败。",
    },
    "command_dispatch": "执行方式：使用 Agent 工具派发编排者，`subagent_type: harmony-auditor`，`description: \"运行 /audit 审计编排\"`，`prompt` 原样传入完整参数 `$ARGUMENTS`（例如 `<repo-path>` 或 `--incremental <repo-path>`，保留所有标志与位置参数），等待其完成并向用户汇报结果。",
    "doc": {
        "intro": "本项目同时适配 Claude Code 与 OpenCode 的 HarmonyOS ArkTS 白盒安全审计多智能体系统。本文件面向 Claude Code，由 `python3 deploy.py --tool claude` 生成；OpenCode 侧见 `AGENTS.md`（由 `--tool opencode` 生成）。",
        "entry": "- 命令：`/audit [--incremental] [--capability CAP-ID] [--component Component] <repo-path>`（命令正文用 Agent 工具派发，`subagent_type: harmony-auditor`）\n- 编排者：工具配置目录中的 `agents/harmony-auditor.md`",
        "extra": "## 权限说明\n\n- `.claude/settings.json` 放行当前部署包中的编排脚本命令与全部 Atlas MCP 工具；其他 Bash 命令沿用用户配置。\n- 审计的目标仓库在工作目录之外时，需要把目标仓绝对路径加入 `.claude/settings.json` 的 `additionalDirectories`，或在首次访问时批准。\n- 任务文件（`**/reports/**/tasks/**`）与 `run.db` 由编排者指令约束为不可读取；编排者只通过 `claim-batch`/`reconcile-batch` 推进任务状态。\n- Atlas MCP 由项目级 `.mcp.json` 提供（stdio 启动 `atlas mcp`）；Claude Code 中工具名为 `mcp__atlas__*`。\n- 全局安装后任意目录启动 Claude Code 即可用 `/audit`：`python3 deploy.py --tool claude --global`；卸载：`python3 deploy.py --tool claude --uninstall`。",
    },
}

PROFILES = {"opencode": OPENCODE_PROFILE, "claude": CLAUDE_PROFILE}


def frontmatter_for(profile, kind, name):
    """每工具 frontmatter 数据(渲染时生成 YAML)。"""
    if kind == "agents":
        desc = AGENT_DESCRIPTIONS[name]
        if profile["tool"] == "opencode":
            mode = "primary" if name == "harmony-auditor.md" else "subagent"
            return {"description": desc, "mode": mode,
                    "permission": _opencode_permission(name, ATLAS_TOOL_SETS[name])}
        return {"name": name[:-3], "description": desc, "tools": _claude_tools(name)}
    if kind == "commands":
        if profile["tool"] == "opencode":
            return {"description": COMMAND_DESCRIPTION, "agent": "harmony-auditor"}
        return {"description": COMMAND_DESCRIPTION, "argument-hint": ARGUMENT_HINT}
    # skills
    desc = SKILL_DESCRIPTIONS[name]
    fm = {"name": name, "description": desc}
    if profile["tool"] == "opencode":
        fm["slash"] = False
    return fm


# ---------------- 渲染 ----------------

_SAFE_SCALAR = re.compile(r"^[\w./\-,一-鿿 ]+$")


def yaml_scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    return s if _SAFE_SCALAR.match(s) else json.dumps(s, ensure_ascii=False)


def yaml_dump(obj, indent=0):
    pad = " " * indent
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            if isinstance(v, dict):
                out.append(f"{pad}{yaml_scalar(k)}:")
                out.append(yaml_dump(v, indent + 2))
            elif isinstance(v, list):
                out.append(f"{pad}{yaml_scalar(k)}:")
                out.extend(f"{pad}  - {yaml_scalar(it)}" for it in v)
            else:
                out.append(f"{pad}{yaml_scalar(k)}: {yaml_scalar(v)}")
        return "\n".join(out)
    raise TypeError(f"yaml_dump 不支持: {type(obj)}")


def deployment_paths(tree):
    """Return paths inside the installed Vibe Coding resource directory."""
    skills = Path(tree).resolve() / "skills"
    return {
        "audit_orchestrator_path": (
            skills / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
        ).as_posix(),
        "project_profiler_path": (
            skills / "project-modeling" / "scripts" / "project_profiler.py"
        ).as_posix(),
        "atlas_indexer_path": (
            skills / "project-modeling" / "scripts" / "atlas_indexer.py"
        ).as_posix(),
    }


def substitute(text, profile, paths=None):
    for key, val in profile["snippets"].items():
        text = text.replace("{{" + key + "}}", val)
    text = text.replace("{{atlas_prefix}}", profile["atlas_prefix"])
    for key, val in (paths or {}).items():
        text = text.replace("{{" + key + "}}", val)
    return text


def render_doc(root, profile):
    conventions = (root / "resources/docs/shared-conventions.md").read_text(encoding="utf-8").rstrip()
    return "\n".join([
        "# harmonySecAnalyzer-v3.1", "",
        profile["doc"]["intro"], "",
        "## 入口", "",
        profile["doc"]["entry"], "",
        "## 约定", "",
        conventions, "",
        profile["doc"]["extra"].rstrip(), "",
    ])


def opencode_config(atlas):
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {"atlas": {"type": "local", "command": [str(atlas), "mcp"], "enabled": True, "timeout": 30000}},
        "permission": {"read": "allow", "grep": "allow", "glob": "allow",
                       "edit": "ask", "bash": "ask", "webfetch": "ask", "websearch": "ask"},
    }


def claude_mcp_config(atlas):
    return {"mcpServers": {"atlas": {"type": "stdio", "command": str(atlas), "args": ["mcp"]}}}


def claude_settings_config():
    return {"permissions": {"allow": [
        "Bash(python3 *audit_orchestrator.py*:*)",
        "mcp__atlas__*",
    ]}}


def render_resources(root, profile, tree, runtime_tree=None):
    """Install a self-contained Agent/Command/Skill bundle into a tool config tree."""
    paths = deployment_paths(runtime_tree or tree)
    for agent in AGENTS:
        fm = frontmatter_for(profile, "agents", agent)
        body = substitute(
            (root / "resources" / "agents" / agent).read_text(encoding="utf-8"),
            profile,
            paths,
        ).rstrip() + "\n"
        out = tree / "agents" / agent
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("---\n" + yaml_dump(fm) + "\n---\n" + body, encoding="utf-8")

    fm = frontmatter_for(profile, "commands", "audit.md")
    body = substitute(
        (root / "resources" / "commands" / "audit.md").read_text(encoding="utf-8"),
        profile,
        paths,
    )
    body = body.replace("{{command_dispatch}}", profile["command_dispatch"]).rstrip() + "\n"
    out = tree / "commands" / "audit.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("---\n" + yaml_dump(fm) + "\n---\n" + body, encoding="utf-8")

    for skill in SKILLS:
        source = root / "resources" / "skills" / skill
        dst = tree / "skills" / skill
        if dst.exists():
            shutil.rmtree(dst)
        dst.mkdir(parents=True)
        for sub in ("scripts", "config"):
            if (source / sub).exists():
                shutil.copytree(
                    source / sub,
                    dst / sub,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
        fm = frontmatter_for(profile, "skills", skill)
        body = substitute(
            (source / "SKILL.md").read_text(encoding="utf-8"), profile, paths,
        ).rstrip() + "\n"
        (dst / "SKILL.md").write_text(
            "---\n" + yaml_dump(fm) + "\n---\n" + body,
            encoding="utf-8",
        )


def render_tree(root, profile, atlas, base=None, runtime_base=None):
    """按 profile 渲染自包含资源目录、根级配置和工具文档。

    base 供测试重定向；runtime_base 指定最终运行位置，以便临时渲染时仍能注入
    正确路径。仅重建本项目拥有的子目录，保留用户个人文件。
    """
    dest = base or root
    tree = dest / profile["dir"]
    runtime_tree = (runtime_base or dest) / profile["dir"]
    tree.mkdir(parents=True, exist_ok=True)
    for sub in ("agents", "commands", "skills"):
        p = tree / sub
        if p.exists():
            shutil.rmtree(p)
    if profile["tool"] == "claude":
        p = tree / "settings.json"
        if p.exists():
            p.unlink()

    render_resources(root, profile, tree, runtime_tree=runtime_tree)

    if profile["tool"] == "opencode":
        (dest / "opencode.json").write_text(json.dumps(opencode_config(atlas), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        (dest / ".mcp.json").write_text(json.dumps(claude_mcp_config(atlas), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (tree / "settings.json").write_text(json.dumps(claude_settings_config(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    (dest / profile["docs_file"]).write_text(render_doc(root, profile), encoding="utf-8")


def render_drift(root, profile, atlas, dest=None):
    """渲染到临时目录,与 dest(默认项目根)下现有生成物字节比对。

    返回 (ok, problems); 用于 --check-only 与 CI 漂移校验,不写任何文件。
    """
    dest = dest or root
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        render_tree(root, profile, atlas, base=base, runtime_base=dest)
        generated = {p.relative_to(base).as_posix(): p.read_bytes()
                     for p in base.rglob("*") if p.is_file()}
    problems = []
    for rel, content in sorted(generated.items()):
        cur = dest / rel
        if not cur.exists():
            problems.append(f"缺失: {rel}")
        elif cur.read_bytes() != content:
            problems.append(f"不一致: {rel}")
    return (not problems), problems


# ---------------- 输出 ----------------

def ok(msg): print(f"  [OK]   {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def fail(msg): print(f"  [FAIL] {msg}")
def info(msg): print(f"  {msg}")


# ---------------- 路径 ----------------

def global_dir(target, profile):
    if target:
        return Path(target).expanduser().resolve()
    return Path(profile["global_dir"]).expanduser().resolve()


def harmony_sec_home(gdir):
    return gdir / "harmony-sec"


# ---------------- 依赖检查 ----------------

def find_python3():
    for name in ("python3", "python"):
        p = shutil.which(name)
        if not p:
            continue
        try:
            r = subprocess.run([p, "-c", "import sys; print(sys.version_info[:2])"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                major, minor = eval(r.stdout.strip())
                if (major, minor) >= (3, 8):
                    return p
        except Exception:
            continue
    return None


def python_module_version(python, module):
    try:
        result = subprocess.run(
            [python, "-c", f"import {module}; print(getattr({module}, '__version__', 'installed'))"],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def find_tool(profile):
    p = shutil.which(profile["executable"])
    if not p:
        return None
    try:
        r = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=20)
        return p if r.returncode == 0 else None
    except Exception:
        return None


def verify_atlas(path):
    if not path or not Path(path).is_file():
        return False
    try:
        r = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=20)
        # 要求版本输出含 "atlas",避免任意可执行文件(如 /bin/echo)通过探测
        return r.returncode == 0 and "atlas" in (r.stdout + r.stderr).lower()
    except Exception:
        return False


def resolve_atlas(explicit, profile, root):
    if explicit:
        p = Path(explicit).expanduser()
        if verify_atlas(p):
            return p.resolve(), "用户指定"
        return None, f"用户指定的 atlas 不可执行: {explicit}"
    cfg = root / profile["config_file"]
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            if profile["tool"] == "opencode":
                cmd = data.get("mcp", {}).get("atlas", {}).get("command", [])
            else:
                cmd = data.get("mcpServers", {}).get("atlas", {}).get("command")
            if isinstance(cmd, list):
                cmd = cmd[0] if cmd else None
            if cmd and verify_atlas(cmd):
                return Path(cmd).resolve(), f"{profile['config_file']} 现有配置"
        except Exception:
            pass
    p = shutil.which("atlas")
    if p and verify_atlas(p):
        return Path(p).resolve(), "PATH"
    return None, "未找到可执行的 atlas"


# ---------------- 结构校验 ----------------

def validate_structure(root):
    all_ok = True
    for rel in REQUIRED:
        if (root / rel).exists():
            ok(rel)
        else:
            fail(f"缺失: {rel}")
            all_ok = False
    return all_ok


# ---------------- 状态机 smoke ----------------

def smoke_atlas_indexer(indexer, python, atlas):
    """Verify first-run index, repeat sync, status validation and output persistence."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "target"
        target.mkdir()
        (target / "Smoke.ets").write_text(
            "export function atlasSmoke(): boolean { return true; }\n",
            encoding="utf-8",
        )
        output = root / "run" / "atlas" / "index_status.json"

        actions = []
        for _ in range(2):
            result = subprocess.run(
                [
                    python, str(indexer), str(target), "--output", str(output),
                    "--atlas", str(atlas),
                ],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode != 0:
                return False, f"Atlas indexer 失败: {result.stderr.strip() or result.stdout.strip()}"
            try:
                payload = json.loads(output.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                return False, f"Atlas index result 文件无效: {exc}"
            actions.append(payload.get("action"))
            files_indexed = payload.get("files_indexed")
            if not payload.get("ok") or not isinstance(files_indexed, int) or files_indexed <= 0:
                return False, f"Atlas index status 无效: {payload}"
        if actions != ["index", "sync"]:
            return False, f"Atlas index/sync 选择错误: {actions}"
        return True, "首次 full-analysis index + 后续 incremental sync 通过"


def smoke_flow_runtime(orch, python, atlas):
    """Exercise deterministic preparation, isolated allocation and batch claiming."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "target"
        module = target / "entry/src/main"
        module.mkdir(parents=True)
        (module / "module.json5").write_text(
            "{module:{name:'entry',abilities:[{name:'EntryAbility',exported:true,srcEntry:'./ets/EntryAbility.ets'}]}}",
            encoding="utf-8",
        )
        source = module / "ets" / "EntryAbility.ets"
        source.parent.mkdir()
        source.write_text(
            "export default class EntryAbility { onCreate(): void {} }\n",
            encoding="utf-8",
        )

        def invoke(*args):
            result = subprocess.run([python, str(orch), *map(str, args)], capture_output=True, text=True, timeout=20)
            try:
                payload = json.loads(result.stdout)
            except Exception as exc:
                raise RuntimeError(
                    f"{args[0]} 非 JSON: {exc}: stdout={result.stdout!r}, stderr={result.stderr!r}"
                )
            if result.returncode != 0 or not payload.get("ok"):
                raise RuntimeError(f"{args[0]} 失败: {result.stderr or result.stdout}")
            return payload

        try:
            first = invoke("prepare", "--target-repo", target, "--mode", "full", "--atlas", atlas)
            second = invoke("prepare", "--target-repo", target, "--mode", "full", "--atlas", atlas)
            if first["run_dir"] == second["run_dir"]:
                return False, "prepare 未隔离重复审计"
            claimed = invoke("claim-batch", first["run_dir"])
            tasks = claimed.get("tasks") or []
            if not tasks or any(task.get("kind") != "component_semantic_analysis" for task in tasks):
                return False, "组件语义任务未正确生成"
            if any(not task.get("worker_prompt") for task in tasks):
                return False, "任务句柄缺少并发派发 prompt"
            status_payload = invoke("status", first["run_dir"])
            if (status_payload["tasks"].get("running") != len(tasks)
                    or not (Path(first["run_dir"]) / "run.db").is_file()):
                return False, "SQLite 任务状态不正确"
        except Exception as exc:
            return False, str(exc)
        return True, "确定性 prepare + 隔离 run + Component Semantics 批量领取通过"


def smoke_project_model(profiler, python):
    """Verify JSON5 profiling without producing an audit plan."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "target"
        module = root / "entry" / "src" / "main"
        module.mkdir(parents=True)
        (module / "module.json5").write_text("{module:{name:'entry',type:'entry',abilities:[{name:'EntryAbility',exported:true}]}}", encoding="utf-8")
        output = Path(td) / "project_model.json"
        result = subprocess.run([python, str(profiler), str(root), "--output", str(output)], capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            return False, result.stderr or result.stdout
        payload = json.loads(result.stdout)
        model = json.loads(output.read_text(encoding="utf-8"))
        modules = model.get("modules", [])
        if (not payload.get("ok") or model.get("schema_version") != 2
                or not model.get("entry_candidates") or len(modules) != 1
                or not modules[0].get("module_id") or modules[0].get("output_kind") != "hap"):
            return False, "project model 未生成入口候选"
        return True, "JSON5 project model 生成通过"


# ---------------- 全局安装 ----------------

def claude_mcp_register(atlas):
    claude = shutil.which("claude")
    if not claude:
        warn("claude 不在 PATH,跳过用户级 MCP 注册(可手动: claude mcp add atlas -- /path/atlas mcp)")
        return
    try:
        r = subprocess.run([claude, "mcp", "list"], capture_output=True, text=True, timeout=60)
        if r.returncode == 0 and "atlas" in r.stdout:
            ok("用户级 atlas MCP 已注册")
            return
    except Exception:
        pass
    try:
        r = subprocess.run([claude, "mcp", "add", "atlas", "--scope", "user", "--", str(atlas), "mcp"],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            ok(f"已注册用户级 atlas MCP: {atlas} mcp")
        else:
            warn(f"claude mcp add 失败: {r.stderr.strip() or r.stdout.strip()}")
    except Exception as exc:
        warn(f"claude mcp add 异常: {exc}")


def install_global(root, profile, atlas, target):
    g = global_dir(target, profile)
    info(f"全局目录: {g}")
    g.mkdir(parents=True, exist_ok=True)
    for name in LEGACY_AGENTS:
        legacy = g / "agents" / name
        if legacy.exists():
            legacy.unlink()
            ok(f"清理旧 agents/{name}")
    for name in LEGACY_SKILLS:
        legacy = g / "skills" / name
        if legacy.exists():
            shutil.rmtree(legacy)
            ok(f"清理旧 skills/{name}")

    # 1-3. 直接在目标配置目录生成自包含资源包，不依赖源码仓的中间生成物。
    render_resources(root, profile, g, runtime_tree=g)
    for name in OWNED_AGENTS:
        ok(f"agents/{name}")
    for name in OWNED_COMMANDS:
        ok(f"commands/{name}")
    for name in OWNED_SKILLS:
        ok(f"skills/{name}")
    # 4. 工具文档(备份已有)
    doc_dst = g / profile["docs_file"]
    doc_content = render_doc(root, profile)
    if doc_dst.exists() and doc_dst.read_text(encoding="utf-8") != doc_content:
        shutil.copy2(doc_dst, g / f"{profile['docs_file']}.bak")
        warn(f"全局 {profile['docs_file']} 已备份为 .bak")
    doc_dst.write_text(doc_content, encoding="utf-8")
    ok(profile["docs_file"])
    # 5. MCP/配置
    if profile["tool"] == "opencode":
        gj = g / "opencode.json"
        gd = {}
        if gj.exists():
            try:
                gd = json.loads(gj.read_text(encoding="utf-8"))
            except Exception:
                shutil.copy2(gj, g / "opencode.json.bak")
                warn("全局 opencode.json 解析失败,备份后覆盖")
        gd.setdefault("mcp", {})["atlas"] = {"type": "local", "command": [str(atlas), "mcp"], "enabled": True}
        gj.write_text(json.dumps(gd, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        ok(f"合并 mcp.atlas → {gj}")
    else:
        claude_mcp_register(atlas)


# ---------------- 卸载 ----------------

def uninstall_global(profile, target):
    g = global_dir(target, profile)
    h = harmony_sec_home(g)
    removed = []
    for name in OWNED_AGENTS + LEGACY_AGENTS:
        f = g / "agents" / name
        if f.exists():
            f.unlink()
            removed.append(str(f))
    for name in OWNED_COMMANDS:
        f = g / "commands" / name
        if f.exists():
            f.unlink()
            removed.append(str(f))
    for name in OWNED_SKILLS + LEGACY_SKILLS:
        d = g / "skills" / name
        if d.exists():
            shutil.rmtree(d)
            removed.append(str(d))
    if h.exists():
        shutil.rmtree(h)
        removed.append(str(h))
    doc = g / profile["docs_file"]
    if doc.exists():
        doc.unlink()
        removed.append(str(doc))
    if removed:
        for r in removed:
            ok(f"删除 {r}")
        if profile["tool"] == "opencode":
            info("全局 opencode.json 的 mcp.atlas 需手动移除(若不再用)。")
        else:
            info("用户级 atlas MCP 需手动移除: claude mcp remove atlas --scope user")
    else:
        info("全局无本项目资源可卸载。")


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="部署 harmonySecAnalyzer 到 opencode / Claude Code")
    ap.add_argument("--tool", required=True, choices=["opencode", "claude"],
                    help="目标工具(必填): opencode | claude")
    ap.add_argument("--atlas", help="atlas 可执行文件路径(默认自动检测)")
    ap.add_argument("--global", dest="global_install", action="store_true",
                    help="全局安装(opencode → ~/.config/opencode; claude → ~/.claude)")
    ap.add_argument("--target", help="全局目录(默认随工具)")
    ap.add_argument("--check-only", action="store_true", help="仅检查不修改")
    ap.add_argument("--uninstall", action="store_true", help="卸载全局安装的资源")
    args = ap.parse_args()

    profile = PROFILES[args.tool]
    root = Path(__file__).resolve().parent
    print("=" * 60)
    print(f"harmonySecAnalyzer → {profile['tool']} 部署")
    print("=" * 60)
    info(f"项目根: {root}")

    if args.uninstall:
        uninstall_global(profile, args.target)
        return

    info(f"模式: {'全局安装' if args.global_install else '本地配置'}"
         + (" (仅检查)" if args.check_only else ""))
    print()

    # [1/5] python3
    info("[1/5] 检查 python3")
    py = find_python3()
    if py:
        ok(f"python3: {py}")
    else:
        fail("python3 未找到(需 ≥3.8)")
        sys.exit(2)
    json5_version = python_module_version(py, "json5")
    if json5_version:
        ok(f"Python json5: {json5_version}")
    else:
        fail("缺少 Python json5 依赖")
        info(f"安装: {py} -m pip install -r {root / 'requirements.txt'}")
        sys.exit(2)
    jsonschema_version = python_module_version(py, "jsonschema")
    if jsonschema_version:
        ok(f"Python jsonschema: {jsonschema_version}")
    else:
        fail("缺少 Python jsonschema 依赖")
        info(f"安装: {py} -m pip install -r {root / 'requirements.txt'}")
        sys.exit(2)
    print()

    # [2/5] 目标工具
    info(f"[2/5] 检查 {profile['executable']}")
    tool = find_tool(profile)
    if tool:
        ok(f"{profile['executable']}: {tool}")
    else:
        fail(f"{profile['executable']} 未安装或不在 PATH")
        if not args.global_install and not args.check_only:
            sys.exit(1)
        warn("继续检查其余项")
    print()

    # [3/5] atlas
    info("[3/5] 检查 atlas")
    atlas, src = resolve_atlas(args.atlas, profile, root)
    if atlas:
        ok(f"atlas: {atlas} (来源: {src})")
        warn("若工具启动后 atlas mcp 报错,确认 atlas 编译时带 --features mcp")
    else:
        fail(f"atlas 不可用: {src}")
        warn("请用 --atlas <path> 指定,或把 atlas 加入 PATH")
        sys.exit(3)
    print()

    # [4/5] 配置/安装
    info(f"[4/5] {'全局安装' if args.global_install else '本地配置'}")
    drift_found = False
    if args.check_only:
        warn("--check-only: 不写入,校验渲染产物与模板一致性")
        try:
            drift_ok, problems = render_drift(root, profile, atlas)
        except Exception as exc:
            drift_ok, problems = False, [f"渲染校验异常: {exc}"]
        if drift_ok:
            ok("生成物与当前模板一致")
        else:
            drift_found = True
            fail(f"生成物与模板不一致({len(problems)} 处):")
            for p in problems:
                fail(f"  {p}")
            fail(f"请重新部署: python deploy.py --tool {profile['tool']}")
    elif args.global_install:
        install_global(root, profile, atlas, args.target)
    else:
        render_tree(root, profile, atlas)
    print()

    # [5/5] 结构校验 + smoke
    info("[5/5] 校验规范源结构 + 状态机 smoke")
    validation_ok = True
    if not validate_structure(root):
        fail("结构校验未通过")
        validation_ok = False
    else:
        ok(f"结构校验通过({len(REQUIRED)} 文件)")
        good, msg = smoke_project_model(root / PROFILER_REL, py)
        if good:
            ok(f"项目建模 smoke: {msg}")
        else:
            fail(f"项目建模 smoke 失败: {msg}")
            validation_ok = False
        good, msg = smoke_atlas_indexer(root / ATLAS_INDEXER_REL, py, atlas)
        if good:
            ok(f"Atlas 索引 smoke: {msg}")
        else:
            fail(f"Atlas 索引 smoke 失败: {msg}")
            validation_ok = False
        good, msg = smoke_flow_runtime(root / ORCH_REL, py, atlas)
        if good:
            ok(f"状态机 smoke: {msg}")
        else:
            fail(f"状态机 smoke 失败: {msg}")
            validation_ok = False
    print()

    print("=" * 60)
    if not validation_ok or drift_found:
        print("✗ 部署校验失败，请修复上方错误后重试。")
    elif args.global_install:
        print(f"✓ 全局安装完成。任意目录启动 {profile['tool']} 即可用 /audit。")
        print(f"    cd <某鸿蒙仓> && {profile['tool']} && /audit <该仓路径>")
        print(f"    失败任务恢复: /audit --resume <run目录>")
        print(f"  卸载: python deploy.py --tool {profile['tool']} --uninstall")
    else:
        print(f"✓ 本地配置完成。在本项目目录启动 {profile['tool']}:")
        print(f"    cd {root} && {profile['tool']} && /audit <目标鸿蒙仓路径>")
        print(f"    失败任务恢复: /audit --resume <run目录>")
    print("=" * 60)
    if not validation_ok or drift_found:
        sys.exit(4)


if __name__ == "__main__":
    main()
