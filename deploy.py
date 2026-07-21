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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------- 常量(匹配实际文件结构) ----------------

ORCH_REL = ".opencode/skills/audit-orchestration/scripts/audit_orchestrator.py"
PROFILER_REL = ".opencode/skills/project-modeling/scripts/project_profiler.py"
ATLAS_INDEXER_REL = ".opencode/skills/project-modeling/scripts/atlas_indexer.py"
ORCHESTRATION_RUNTIME_FILES = [
    f".opencode/skills/audit-orchestration/scripts/audit_runtime/{name}"
    for name in (
        "__init__.py", "common.py", "store.py", "contracts.py", "reporting.py", "commands.py", "cli.py",
    )
]

REQUIRED = [
    "opencode.json", "AGENTS.md", "deploy.py", "requirements.txt",
    ORCH_REL,
    PROFILER_REL,
    ATLAS_INDEXER_REL,
    *ORCHESTRATION_RUNTIME_FILES,
    ".opencode/agents/harmony-auditor.md",
    ".opencode/agents/entry-planner.md",
    ".opencode/agents/flow-analyzer.md",
    ".opencode/agents/flow-pattern-evaluator.md",
    ".opencode/agents/flow-validator.md",
    ".opencode/commands/audit.md",
    ".opencode/skills/audit-workflow/SKILL.md",
    ".opencode/skills/attack-patterns/SKILL.md",
    ".opencode/skills/audit-orchestration/SKILL.md",
    ".opencode/skills/audit-orchestration/config/audit_capabilities.json",
    ".opencode/skills/audit-orchestration/config/schemas/audit-capabilities.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/project-model.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/entry-plan-result.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/flow-task-result.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/pattern-evaluation-result.schema.json",
    ".opencode/skills/audit-orchestration/config/schemas/flow-validation-result.schema.json",
    ".opencode/skills/project-modeling/SKILL.md",
]

_capabilities_path = Path(__file__).resolve().parent / ".opencode/skills/audit-orchestration/config/audit_capabilities.json"
if _capabilities_path.is_file():
    _capabilities = json.loads(_capabilities_path.read_text(encoding="utf-8"))
    REQUIRED.extend(
        f".opencode/skills/attack-patterns/patterns/{pattern_id}.md"
        for capability in _capabilities.get("capabilities", [])
        if capability.get("status") in {"partial", "implemented"}
        for pattern_id in capability.get("pattern_ids", [])
    )

# 全局安装/卸载的项目资源白名单(不动第三方)
OWNED_AGENTS = ["harmony-auditor.md", "entry-planner.md", "flow-analyzer.md",
                "flow-pattern-evaluator.md", "flow-validator.md"]
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

def smoke_atlas_indexer(indexer, python):
    """Verify first-run index, repeat sync, status validation and output persistence."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "target"
        target.mkdir()
        fake_atlas = root / "atlas"
        fake_atlas.write_text(
            """#!/usr/bin/env python3
import sys
from pathlib import Path
command = sys.argv[1]
project = Path(sys.argv[sys.argv.index('--project') + 1])
database = project / '.atlas' / 'atlas.db'
if command in ('index', 'sync'):
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_bytes(b'smoke')
    print(command + ' complete')
elif command == 'status':
    print('Files indexed:   3')
else:
    sys.exit(2)
""",
            encoding="utf-8",
        )
        fake_atlas.chmod(0o755)
        output = root / "run" / "atlas" / "index_status.json"

        actions = []
        for _ in range(2):
            result = subprocess.run(
                [
                    python, str(indexer), str(target), "--output", str(output),
                    "--atlas", str(fake_atlas),
                ],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode != 0:
                return False, f"Atlas indexer 失败: {result.stderr.strip() or result.stdout.strip()}"
            payload = json.loads(result.stdout)
            actions.append(payload.get("action"))
            if not payload.get("ok") or payload.get("files_indexed") != 3:
                return False, f"Atlas index status 无效: {payload}"
        if actions != ["index", "sync"]:
            return False, f"Atlas index/sync 选择错误: {actions}"
        return True, "首次 full-analysis index + 后续 incremental sync 通过"


def smoke_flow_runtime(orch, python):
    """Exercise isolated allocation, SQLite initialization and entry planning."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        target = root / "target"
        target.mkdir()
        model = root / "model.json"
        model.write_text(json.dumps({
            "schema_version": 1, "status": "complete", "target_repo": str(target),
            "entry_candidates": [{"candidate_id": "PE-SMOKE", "type": "exported_component"}],
        }), encoding="utf-8")

        def invoke(*args):
            result = subprocess.run([python, str(orch), *map(str, args)], capture_output=True, text=True, timeout=20)
            try:
                payload = json.loads(result.stdout)
            except Exception as exc:
                raise RuntimeError(f"{args[0]} 非 JSON: {exc}: {result.stdout}")
            if result.returncode != 0 or not payload.get("ok"):
                raise RuntimeError(f"{args[0]} 失败: {result.stderr or result.stdout}")
            return payload

        try:
            first = invoke("new-run", root / "reports", "--target-repo", target, "--mode", "full")
            second = invoke("new-run", root / "reports", "--target-repo", target, "--mode", "full")
            if first["run_dir"] == second["run_dir"]:
                return False, "new-run 未隔离重复审计"
            invoke("init", first["run_dir"], "--project-model", model)
            claim = invoke("claim", first["run_dir"], "--limit", "5")
            if claim.get("count") != 1 or claim["tasks"][0].get("kind") != "entry_planning":
                return False, "入口规划任务未正确生成"
            status_payload = invoke("status", first["run_dir"])
            if status_payload["tasks"].get("running") != 1 or not (Path(first["run_dir"]) / "run.db").is_file():
                return False, "SQLite 任务状态不正确"
        except Exception as exc:
            return False, str(exc)
        return True, "隔离 run + SQLite 初始化 + Entry Planner claim 通过"


def smoke_project_model(profiler, python):
    """Verify JSON5 profiling without producing an audit plan."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "target"
        module = root / "entry" / "src" / "main"
        module.mkdir(parents=True)
        (module / "module.json5").write_text("{module:{name:'entry',abilities:[{name:'EntryAbility',exported:true}]}}", encoding="utf-8")
        output = Path(td) / "project_model.json"
        result = subprocess.run([python, str(profiler), str(root), "--output", str(output)], capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            return False, result.stderr or result.stdout
        payload = json.loads(result.stdout)
        model = json.loads(output.read_text(encoding="utf-8"))
        if not payload.get("ok") or not model.get("entry_candidates"):
            return False, "project model 未生成入口候选"
        return True, "JSON5 project model 生成通过"


# ---------------- 全局安装 ----------------

def install_global(root, atlas, target):
    g = global_dir(target)
    h = harmony_sec_home(g)
    info(f"全局目录: {g}")
    g.mkdir(parents=True, exist_ok=True)
    orch_abs = (g / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py").as_posix()
    profiler_abs = (g / "skills" / "project-modeling" / "scripts" / "project_profiler.py").as_posix()
    indexer_abs = (g / "skills" / "project-modeling" / "scripts" / "atlas_indexer.py").as_posix()

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
        content = content.replace(f"python3 {ATLAS_INDEXER_REL}", f"python3 {indexer_abs}")
        content = content.replace(ATLAS_INDEXER_REL, indexer_abs)
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
            content = content.replace(f"python3 {ATLAS_INDEXER_REL}", f"python3 {indexer_abs}")
            content = content.replace(ATLAS_INDEXER_REL, indexer_abs)
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
        good, msg = smoke_atlas_indexer(root / ATLAS_INDEXER_REL, py)
        if good:
            ok(f"Atlas 索引 smoke: {msg}")
        else:
            fail(f"Atlas 索引 smoke 失败: {msg}")
            validation_ok = False
        good, msg = smoke_flow_runtime(root / ORCH_REL, py)
        if good:
            ok(f"状态机 smoke: {msg}")
        else:
            fail(f"状态机 smoke 失败: {msg}")
            validation_ok = False
    print()

    print("=" * 60)
    if not validation_ok:
        print("✗ 部署校验失败，请修复上方错误后重试。")
    elif args.global_install:
        print("✓ 全局安装完成。任何目录启动 opencode 即可用 /audit。")
        print(f"    cd <某鸿蒙仓> && opencode && /audit full <该仓路径>")
        print(f"  卸载: python deploy.py --uninstall")
    else:
        print("✓ 本地配置完成。在本项目目录启动 opencode:")
        print(f"    cd {root} && opencode && /audit full <目标鸿蒙仓路径>")
    print("=" * 60)
    if not validation_ok:
        sys.exit(4)


if __name__ == "__main__":
    main()
