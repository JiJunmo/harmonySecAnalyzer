#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harmonySecAnalyzer 部署脚本

把本项目部署到 opencode:
  1. 校验 opencode / atlas / python3 依赖
  2. 把本机 atlas 路径写入 opencode.json 的 mcp.atlas
  3. 校验项目结构 + 状态机脚本 smoke 测试
  4. (可选 --global) 同步资源到 opencode 全局目录,任意位置可用 /audit

跨平台: macOS / Windows / Linux。部署脚本使用标准库,运行时依赖见 requirements.txt。

用法:
  python deploy.py                 # 本地配置(默认):在项目目录启动 opencode 审计外部仓
  python deploy.py --global        # 全局安装:复制资源到 ~/.config/opencode
  python deploy.py --check-only    # 仅检查不修改
  python deploy.py --uninstall     # 卸载全局安装的资源
  python deploy.py --atlas /path/to/atlas
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------- 常量(匹配实际文件结构) ----------------

ORCH_REL = ".opencode/skills/audit-orchestration/scripts/audit_orchestrator.py"
PROFILER_REL = ".opencode/skills/project-modeling/scripts/project_profiler.py"

REQUIRED = [
    "opencode.json", "AGENTS.md", "deploy.py", "requirements.txt",
    ORCH_REL,
    PROFILER_REL,
    ".opencode/agents/harmony-auditor.md",
    ".opencode/agents/attack-surface-mapper.md",
    ".opencode/agents/path-finder.md",
    ".opencode/agents/path-validator.md",
    ".opencode/agents/report-composer.md",
    ".opencode/commands/audit.md",
    ".opencode/skills/audit-workflow/SKILL.md",
    ".opencode/skills/attack-patterns/SKILL.md",
    ".opencode/skills/audit-orchestration/SKILL.md",
    ".opencode/skills/audit-orchestration/config/audit_capabilities.json",
    ".opencode/skills/audit-orchestration/config/schemas/audit-capabilities.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/golden-cases.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/discovery-result.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/path-result.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/validation-result.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/project-model.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/discovery-plan.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/entry-list.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/danger-seeds.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/attack-matrix.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/findings.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/report-snapshot.schema.json",
    ".opencode/skills/project-modeling/SKILL.md",
    "tests/golden/audit_capability_cases.json",
]

_capabilities_path = Path(__file__).resolve().parent / ".opencode/skills/audit-orchestration/config/audit_capabilities.json"
if _capabilities_path.is_file():
    _capabilities = json.loads(_capabilities_path.read_text(encoding="utf-8"))
    REQUIRED.extend(
        f".opencode/skills/attack-patterns/patterns/{pattern_id}.md"
        for capability in _capabilities.get("capabilities", [])
        if isinstance(capability.get("routing"), dict) and capability["routing"].get("enabled") is True
        for pattern_id in capability.get("pattern_ids", [])
    )

# 全局安装/卸载的项目资源白名单(不动第三方)
OWNED_AGENTS = ["harmony-auditor.md", "attack-surface-mapper.md", "path-finder.md",
                "path-validator.md", "report-composer.md"]
OWNED_COMMANDS = ["audit.md"]
OWNED_SKILLS = ["audit-workflow", "attack-patterns", "audit-orchestration", "project-modeling"]


# ---------------- 输出 ----------------

def ok(msg): print(f"  [OK]   {msg}")
def warn(msg): print(f"  [WARN] {msg}")
def fail(msg): print(f"  [FAIL] {msg}")
def info(msg): print(f"  {msg}")


# ---------------- 路径 ----------------

def global_dir(target):
    if target:
        return Path(target).expanduser().resolve()
    return (Path.home() / ".config" / "opencode").resolve()

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

def find_opencode():
    p = shutil.which("opencode")
    if not p:
        return None
    try:
        r = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=20)
        return p if r.returncode == 0 else None
    except Exception:
        return None

def verify_atlas(path):
    if not path or not Path(path).exists():
        return False
    try:
        r = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False

def resolve_atlas(explicit, ojson):
    if explicit:
        p = Path(explicit).expanduser()
        if verify_atlas(p):
            return p.resolve(), "用户指定"
        return None, f"用户指定的 atlas 不可执行: {explicit}"
    if ojson.exists():
        try:
            cmd = json.loads(ojson.read_text(encoding="utf-8")).get("mcp", {}).get("atlas", {}).get("command", [])
            if cmd and cmd[0] and verify_atlas(cmd[0]):
                return Path(cmd[0]).resolve(), "opencode.json 现有配置"
        except Exception:
            pass
    p = shutil.which("atlas")
    if p and verify_atlas(p):
        return Path(p).resolve(), "PATH"
    return None, "未找到可执行的 atlas"


# ---------------- 本地配置 ----------------

def configure_local(ojson, atlas):
    data = {}
    if ojson.exists():
        try:
            data = json.loads(ojson.read_text(encoding="utf-8"))
        except Exception as e:
            warn(f"opencode.json 解析失败,将重建: {e}")
    data.setdefault("mcp", {})
    cmd = [str(atlas), "mcp"]
    if data["mcp"].get("atlas", {}).get("command") == cmd:
        ok(f"opencode.json mcp.atlas 已正确配置: {cmd}")
        return
    data["mcp"]["atlas"] = {"type": "local", "command": cmd, "enabled": True}
    ojson.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ok(f"已写入 opencode.json mcp.atlas.command = {cmd}")


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

def smoke_orchestrator(orch, python):
    """Allocate isolated runs and exercise the state-machine commands."""
    with tempfile.TemporaryDirectory() as td:
        reports_root = os.path.join(td, "reports")
        allocate = [python, orch, "new-run", reports_root, "--target-repo", td, "--scope", "smoke"]
        allocated = []
        for _ in range(3):
            try:
                result = subprocess.run(allocate, capture_output=True, text=True, timeout=20)
                payload = json.loads(result.stdout)
            except Exception as exc:
                return False, f"new-run 异常: {exc}"
            if result.returncode != 0 or not payload.get("ok"):
                return False, f"new-run 失败: {result.stderr.strip() or result.stdout.strip()}"
            allocated.append(payload["run_dir"])
        if allocated[0] == allocated[1]:
            return False, "new-run 未隔离重复审计目录"

        run = allocated[0]
        atlas_dir = Path(run) / "atlas"
        (atlas_dir / "entry_list.json").write_text(json.dumps({
            "entry_list": [
                {
                    "entry_id": "E001", "analysis_unit_id": "AU001", "ability": "EntryAbility",
                    "entry_function": "EntryAbility.onCreate", "entry_function_file": "EntryAbility.ets",
                    "type": "exported_ability", "project_candidate_ids": ["PE001"],
                },
                {
                    "entry_id": "E002", "analysis_unit_id": "AU001", "ability": "EntryAbility",
                    "entry_function": "EntryAbility.onCreate", "entry_function_file": "EntryAbility.ets",
                    "type": "implicit_want", "project_candidate_ids": ["PE002"],
                },
            ],
            "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
        }), encoding="utf-8")
        (atlas_dir / "danger_seed_list.json").write_text(json.dumps({
            "danger_seed_list": [{
                "seed_id": "D001", "category": "fs", "operation": "bridge file read",
                "symbol": "WebBridge.openFile", "symbol_file": "WebBridge.ets", "location": "WebBridge.ets:42",
                "sink_role": "terminal", "sink_parameter": "path", "tags": ["web", "jsbridge"],
            }],
        }), encoding="utf-8")
        cmds = [
            [python, orch, "compile-matrix", run],
            [python, orch, "next", run],
            [python, orch, "validate-coverage", run],
            [python, orch, "status", run],
        ]
        for c in cmds:
            try:
                r = subprocess.run(c, capture_output=True, text=True, timeout=20)
            except Exception as e:
                return False, f"{c[2]} 异常: {e}"
            if r.returncode != 0:
                return False, f"{c[2]} 退出码非0: {r.stderr.strip()}"
            try:
                if not json.loads(r.stdout).get("ok"):
                    return False, f"{c[2]} 返回 ok=false: {r.stdout.strip()}"
            except Exception:
                return False, f"{c[2]} 非 JSON: {r.stdout.strip()}"

        running_tasks = [
            json.loads(line) for line in (Path(run) / "queue.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip() and json.loads(line).get("status") == "running"
        ]
        if len(running_tasks) != 1:
            return False, "retry smoke 未找到唯一 running task"
        retry_cmd = [python, orch, "complete", run, "--task", running_tasks[0]["task_id"]]
        retry_result = subprocess.run(retry_cmd, capture_output=True, text=True, timeout=20)
        try:
            retry_payload = json.loads(retry_result.stdout)
        except Exception:
            return False, f"retry smoke complete 非 JSON: {retry_result.stdout.strip()}"
        if retry_result.returncode != 0 or not retry_payload.get("retry_scheduled"):
            return False, f"缺失结果未自动重排: {retry_result.stderr.strip() or retry_result.stdout.strip()}"
        next_retry = subprocess.run(
            [python, orch, "next", run], capture_output=True, text=True, timeout=20,
        )
        try:
            retry_task = json.loads(next_retry.stdout).get("task") or {}
        except Exception:
            return False, f"retry smoke next 非 JSON: {next_retry.stdout.strip()}"
        if next_retry.returncode != 0 or retry_task.get("attempts") != 2:
            return False, f"自动重排 attempt 未递增: {next_retry.stderr.strip() or next_retry.stdout.strip()}"
        if not Path(retry_task.get("result_path", "relative")).is_absolute():
            return False, "next 未返回绝对 result_path"

        discovery_run = Path(allocated[2])
        (discovery_run / "project" / "project_model.json").write_text(json.dumps({
            "schema_version": 1, "status": "complete",
            "entry_candidates": [{"candidate_id": "PE-SMOKE"}],
        }), encoding="utf-8")
        (discovery_run / "atlas" / "discovery_plan.json").write_text(json.dumps({
            "schema_version": 1, "project_model_schema_version": 1,
            "units": [{
                "unit_id": "AU-SMOKE", "component_id": "CMP-SMOKE",
                "entry_candidate_ids": ["PE-SMOKE"], "status": "planned",
                "resolved_symbols": [], "atlas_query_ids": [], "gaps": [],
            }],
        }), encoding="utf-8")
        enqueue_discovery = subprocess.run(
            [python, orch, "enqueue-discovery", str(discovery_run)],
            capture_output=True, text=True, timeout=20,
        )
        claim_discovery = subprocess.run(
            [python, orch, "next", str(discovery_run)],
            capture_output=True, text=True, timeout=20,
        )
        try:
            enqueue_payload = json.loads(enqueue_discovery.stdout)
            discovery_task = json.loads(claim_discovery.stdout).get("task") or {}
        except Exception as exc:
            return False, f"discovery smoke 输出无效: {exc}"
        if not enqueue_payload.get("ok") or discovery_task.get("kind") != "attack_surface_discovery":
            return False, "discovery unit 未正确入队/领取"
        Path(discovery_task["result_path"]).write_text(json.dumps({
            "task_id": discovery_task["task_id"], "unit_id": "AU-SMOKE", "status": "completed",
            "resolved_symbols": ["EntryAbility.onNewWant"], "atlas_query_ids": ["q-smoke"], "gaps": [],
            "entry_list": [{
                "component_id": "CMP-SMOKE", "project_candidate_ids": ["PE-SMOKE"],
                "type": "deeplink", "ability": "EntryAbility",
                "entry_function": "EntryAbility.onNewWant", "entry_function_file": "entry/EntryAbility.ets",
            }],
            "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
            "danger_seed_list": [{
                "category": "sql", "operation": "query", "symbol": "Db.query",
                "symbol_file": "entry/Db.ets", "location": "entry/Db.ets:20",
                "sink_role": "terminal", "sink_parameter": "sql",
            }],
            "query_evidence": [{"unit_id": "AU-SMOKE", "query_id": "q-smoke", "outcome": "matched"}],
        }), encoding="utf-8")
        complete_discovery = subprocess.run(
            [python, orch, "complete", str(discovery_run), "--task", discovery_task["task_id"]],
            capture_output=True, text=True, timeout=20,
        )
        try:
            discovery_complete_payload = json.loads(complete_discovery.stdout)
        except Exception:
            return False, f"discovery complete 非 JSON: {complete_discovery.stdout.strip()}"
        if complete_discovery.returncode != 0 or discovery_complete_payload.get("added_path_tasks") != 1:
            return False, f"discovery 未流式生成 path task: {complete_discovery.stderr.strip() or complete_discovery.stdout.strip()}"

        final_run = Path(allocated[1])
        (final_run / "project" / "project_model.json").write_text(json.dumps({
            "schema_version": 1, "status": "complete", "entry_candidates": [],
        }), encoding="utf-8")
        (final_run / "atlas" / "discovery_plan.json").write_text(json.dumps({
            "schema_version": 1, "units": [],
        }), encoding="utf-8")
        (final_run / "atlas" / "entry_list.json").write_text(json.dumps({
            "entry_list": [], "excluded_candidates": [], "unresolved_candidates": [],
            "coverage_gaps": [],
        }), encoding="utf-8")
        (final_run / "atlas" / "danger_seed_list.json").write_text(json.dumps({
            "danger_seed_list": [],
        }), encoding="utf-8")
        (final_run / "findings.json").write_text(json.dumps({
            "confirmed_vulnerabilities": [], "protected_exposures": [],
            "residual_risks": [], "benign_business_flows": [],
            "insufficient_evidence": [], "isolated_findings": [], "summary": {},
        }) + "\n", encoding="utf-8")
        (final_run / "report.md").write_text("# Smoke report\n", encoding="utf-8")
        for c in (
            [python, orch, "compile-matrix", str(final_run)],
            [python, orch, "validate-ready", str(final_run)],
            [python, orch, "finalize", str(final_run)],
        ):
            try:
                r = subprocess.run(c, capture_output=True, text=True, timeout=20)
                payload = json.loads(r.stdout)
            except Exception as exc:
                return False, f"{c[2]} 异常: {exc}"
            if r.returncode != 0 or not payload.get("ok"):
                return False, f"{c[2]} 失败: {r.stderr.strip() or r.stdout.strip()}"
            if c[2] == "validate-ready" and not payload.get("ready"):
                return False, f"validate-ready 未闭合: {r.stdout.strip()}"
            if c[2] == "finalize" and payload.get("status") != "completed":
                return False, f"finalize 未完成 session: {r.stdout.strip()}"
        snapshot = final_run / "report_snapshot.json"
        if not snapshot.is_file() or len(json.loads(snapshot.read_text(encoding="utf-8")).get("artifacts", {})) < 10:
            return False, "finalize 未生成完整 report snapshot/hash"
        return True, "new-run 隔离 + per-unit discovery 流式下发 + Schema/引用校验 + 自动重试/coverage/finalize snapshot 全通过"


def smoke_project_profiler(profiler, python):
    """Parse representative Harmony JSON5 and verify the normalized model."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "target"
        run = Path(td) / "run"
        (root / "AppScope").mkdir(parents=True)
        (root / "entry" / "src" / "main").mkdir(parents=True)
        (root / "AppScope" / "app.json5").write_text(
            "{ app: { bundleName: 'com.example.smoke', versionCode: 1, }, }",
            encoding="utf-8",
        )
        (root / "entry" / "src" / "main" / "module.json5").write_text(
            """{
              module: {
                name: 'entry',
                abilities: [{
                  name: 'EntryAbility', exported: true,
                  skills: [{ actions: ['ohos.want.action.viewData'], uris: [{ scheme: 'demo' }], }],
                }],
              },
            }""",
            encoding="utf-8",
        )
        output = run / "project" / "project_model.json"
        plan_output = run / "atlas" / "discovery_plan.json"
        try:
            result = subprocess.run(
                [python, str(profiler), str(root), "--output", str(output), "--plan-output", str(plan_output)],
                capture_output=True, text=True, timeout=20,
            )
        except Exception as exc:
            return False, f"project profiler 异常: {exc}"
        if result.returncode != 0:
            return False, f"project profiler 退出码非0: {result.stderr.strip() or result.stdout.strip()}"
        try:
            summary = json.loads(result.stdout)
            model = json.loads(output.read_text(encoding="utf-8"))
            plan = json.loads(plan_output.read_text(encoding="utf-8"))
        except Exception as exc:
            return False, f"project profiler 输出无效: {exc}"
        entry_types = {row.get("type") for row in model.get("entry_candidates", [])}
        expected = {"exported_component", "deeplink", "implicit_want"}
        if not summary.get("ok") or model.get("status") != "complete" or not expected.issubset(entry_types):
            return False, f"project model 内容不完整: status={model.get('status')} entries={sorted(entry_types)}"
        if plan.get("source_content_scanned") is not False or len(plan.get("units", [])) != 1:
            return False, f"Atlas discovery plan 无效: {plan}"
        return True, "JSON5/组件/入口候选/Atlas discovery plan 生成通过"


# ---------------- 全局安装 ----------------

def install_global(root, atlas, target):
    g = global_dir(target)
    h = harmony_sec_home(g)
    info(f"全局目录: {g}")
    g.mkdir(parents=True, exist_ok=True)
    orch_abs = (g / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py").as_posix()
    profiler_abs = (g / "skills" / "project-modeling" / "scripts" / "project_profiler.py").as_posix()

    # 1. agents(路径改写: skill 内脚本 → 绝对,使全局 /audit 不依赖 CWD)
    for name in OWNED_AGENTS:
        src = root / ".opencode" / "agents" / name
        if not src.exists():
            continue
        dst = g / "agents" / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        content = src.read_text(encoding="utf-8")
        content = content.replace(f"python3 {ORCH_REL}", f"python3 {orch_abs}")
        content = content.replace(ORCH_REL, orch_abs)
        content = content.replace(f"python3 {PROFILER_REL}", f"python3 {profiler_abs}")
        content = content.replace(PROFILER_REL, profiler_abs)
        dst.write_text(content, encoding="utf-8")
        ok(f"agents/{name}")
    # 2. commands
    for name in OWNED_COMMANDS:
        src = root / ".opencode" / "commands" / name
        if not src.exists():
            continue
        dst = g / "commands" / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        ok(f"commands/{name}")
    # 3. skills(路径改写)
    for name in OWNED_SKILLS:
        src = root / ".opencode" / "skills" / name
        if not src.exists():
            continue
        dst = g / "skills" / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        sk = dst / "SKILL.md"
        if sk.exists():
            content = sk.read_text(encoding="utf-8")
            content = content.replace(f"python3 {ORCH_REL}", f"python3 {orch_abs}")
            content = content.replace(ORCH_REL, orch_abs)
            content = content.replace(f"python3 {PROFILER_REL}", f"python3 {profiler_abs}")
            content = content.replace(PROFILER_REL, profiler_abs)
            sk.write_text(content, encoding="utf-8")
        ok(f"skills/{name}")
    # 4. 运行时资产 → harmony-sec/
    if (root / "knowledge").exists():
        kdst = h / "knowledge"
        if kdst.exists():
            shutil.rmtree(kdst)
        shutil.copytree(root / "knowledge", kdst)
        ok(f"knowledge → {kdst}")
    # 5. AGENTS.md(备份已有)
    ag_src = root / "AGENTS.md"
    ag_dst = g / "AGENTS.md"
    if ag_src.exists():
        if ag_dst.exists() and ag_dst.read_text(encoding="utf-8") != ag_src.read_text(encoding="utf-8"):
            shutil.copy2(ag_dst, g / "AGENTS.md.bak")
            warn("全局 AGENTS.md 已备份为 .bak")
        shutil.copy2(ag_src, ag_dst)
        ok("AGENTS.md")
    # 6. 合并 opencode.json(只注入 mcp.atlas)
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


# ---------------- 卸载 ----------------

def uninstall_global(target):
    g = global_dir(target)
    h = harmony_sec_home(g)
    removed = []
    for name in OWNED_AGENTS:
        f = g / "agents" / name
        if f.exists():
            f.unlink()
            removed.append(str(f))
    for name in OWNED_COMMANDS:
        f = g / "commands" / name
        if f.exists():
            f.unlink()
            removed.append(str(f))
    for name in OWNED_SKILLS:
        d = g / "skills" / name
        if d.exists():
            shutil.rmtree(d)
            removed.append(str(d))
    if h.exists():
        shutil.rmtree(h)
        removed.append(str(h))
    if removed:
        for r in removed:
            ok(f"删除 {r}")
        info(f"卸载完成,共 {len(removed)} 项。全局 opencode.json 的 mcp.atlas 需手动移除(若不再用)。")
    else:
        info("全局无本项目资源可卸载。")


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="部署 harmonySecAnalyzer 到 opencode")
    ap.add_argument("--atlas", help="atlas 可执行文件路径(默认自动检测)")
    ap.add_argument("--global", dest="global_install", action="store_true",
                    help="全局安装到 ~/.config/opencode")
    ap.add_argument("--target", help="全局目录(默认 ~/.config/opencode)")
    ap.add_argument("--check-only", action="store_true", help="仅检查不修改")
    ap.add_argument("--uninstall", action="store_true", help="卸载全局安装的资源")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent
    print("=" * 60)
    print("harmonySecAnalyzer → opencode 部署")
    print("=" * 60)
    info(f"项目根: {root}")

    if args.uninstall:
        uninstall_global(args.target)
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

    # [2/5] opencode
    info("[2/5] 检查 opencode")
    oc = find_opencode()
    if oc:
        ok(f"opencode: {oc}")
    else:
        fail("opencode 未安装或不在 PATH。安装: https://opencode.ai")
        if not args.global_install and not args.check_only:
            sys.exit(1)
        warn("继续检查其余项")
    print()

    # [3/5] atlas
    info("[3/5] 检查 atlas")
    ojson = root / "opencode.json"
    atlas, src = resolve_atlas(args.atlas, ojson)
    if atlas:
        ok(f"atlas: {atlas} (来源: {src})")
        warn("若 opencode 启动后 atlas mcp 报错,确认 atlas 编译时带 --features mcp")
    else:
        fail(f"atlas 不可用: {src}")
        warn("请用 --atlas <path> 指定,或把 atlas 加入 PATH")
        sys.exit(3)
    print()

    # [4/5] 配置/安装
    info("[4/5] " + ("全局安装" if args.global_install else "本地配置"))
    if args.check_only:
        warn("--check-only: 跳过写入")
    elif args.global_install:
        install_global(root, atlas, args.target)
    else:
        configure_local(ojson, atlas)
    print()

    # [5/5] 结构校验 + smoke
    info("[5/5] 校验项目结构 + 状态机 smoke")
    if not validate_structure(root):
        fail("结构校验未通过")
    else:
        ok(f"结构校验通过({len(REQUIRED)} 文件)")
        good, msg = smoke_project_profiler(root / PROFILER_REL, py)
        if good:
            ok(f"项目建模 smoke: {msg}")
        else:
            fail(f"项目建模 smoke 失败: {msg}")
        good, msg = smoke_orchestrator(root / ORCH_REL, py)
        if good:
            ok(f"状态机 smoke: {msg}")
        else:
            fail(f"状态机 smoke 失败: {msg}")
    print()

    print("=" * 60)
    if args.global_install:
        print("✓ 全局安装完成。任何目录启动 opencode 即可用 /audit。")
        print(f"    cd <某鸿蒙仓> && opencode && /audit full <该仓路径>")
        print(f"  卸载: python deploy.py --uninstall")
    else:
        print("✓ 本地配置完成。在本项目目录启动 opencode:")
        print(f"    cd {root} && opencode && /audit full <目标鸿蒙仓路径>")
    print("=" * 60)


if __name__ == "__main__":
    main()
