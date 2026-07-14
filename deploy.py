#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harmonySecAnalyzer 部署脚本

把本项目部署到 opencode:
  1. 校验 opencode / atlas / python3 依赖
  2. 把本机 atlas 路径写入 opencode.json 的 mcp.atlas
  3. 校验项目结构 + 状态机脚本 smoke 测试
  4. (可选 --global) 同步资源到 opencode 全局目录,任意位置可用 /audit

跨平台: macOS / Windows / Linux。纯标准库,Python 3.8+。

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

REQUIRED = [
    "opencode.json", "AGENTS.md", "deploy.py",
    "tools/audit_orchestrator.py",
    ".opencode/agents/harmony-auditor.md",
    ".opencode/agents/attack-surface-mapper.md",
    ".opencode/agents/path-finder.md",
    ".opencode/agents/path-validator.md",
    ".opencode/agents/report-composer.md",
    ".opencode/commands/audit.md",
    ".opencode/skills/audit-workflow/SKILL.md",
    ".opencode/skills/attack-patterns/SKILL.md",
    ".opencode/skills/audit-orchestration/SKILL.md",
    "knowledge/patterns/index.md",
    "knowledge/patterns/deeplink-injection.md",
    "knowledge/patterns/exported-ability-file.md",
    "knowledge/patterns/web-jsbridge.md",
]

# 全局安装/卸载的项目资源白名单(不动第三方)
OWNED_AGENTS = ["harmony-auditor.md", "attack-surface-mapper.md", "path-finder.md",
                "path-validator.md", "report-composer.md"]
OWNED_COMMANDS = ["audit.md"]
OWNED_SKILLS = ["audit-workflow", "attack-patterns", "audit-orchestration"]


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
    """用临时 run_dir 跑 init/enqueue/next/validate-coverage/status,验证脚本各命令工作。"""
    with tempfile.TemporaryDirectory() as td:
        run = os.path.join(td, "smoke")
        cmds = [
            [python, orch, "init", run, "--target-repo", td, "--scope", "smoke"],
            [python, orch, "enqueue", run, "--tasks", '[{"kind":"path_finding","entry_id":"E001"}]'],
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
        return True, "init/enqueue/next/validate-coverage/status 全通过"


# ---------------- 全局安装 ----------------

def install_global(root, atlas, target):
    g = global_dir(target)
    h = harmony_sec_home(g)
    info(f"全局目录: {g}")
    g.mkdir(parents=True, exist_ok=True)
    orch_abs = (h / "tools" / "audit_orchestrator.py").as_posix()

    # 1. agents(路径改写: tools/audit_orchestrator.py → 绝对,使全局 /audit 不依赖 CWD)
    for name in OWNED_AGENTS:
        src = root / ".opencode" / "agents" / name
        if not src.exists():
            continue
        dst = g / "agents" / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        content = src.read_text(encoding="utf-8")
        content = content.replace("python3 tools/audit_orchestrator.py", f"python3 {orch_abs}")
        content = content.replace("tools/audit_orchestrator.py", orch_abs)
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
    # 3. skills(audit-orchestration 路径改写)
    for name in OWNED_SKILLS:
        src = root / ".opencode" / "skills" / name
        if not src.exists():
            continue
        dst = g / "skills" / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        if name == "audit-orchestration":
            sk = dst / "SKILL.md"
            content = sk.read_text(encoding="utf-8")
            content = content.replace("python3 tools/audit_orchestrator.py", f"python3 {orch_abs}")
            content = content.replace("tools/audit_orchestrator.py", orch_abs)
            sk.write_text(content, encoding="utf-8")
        ok(f"skills/{name}")
    # 4. 运行时资产 → harmony-sec/
    (h / "tools").mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "tools" / "audit_orchestrator.py", h / "tools" / "audit_orchestrator.py")
    ok(f"tools/audit_orchestrator.py → {h}/tools/")
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
        ok("结构校验通过(17 文件)")
        good, msg = smoke_orchestrator(root / "tools" / "audit_orchestrator.py", py)
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
