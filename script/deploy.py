#!/usr/bin/env python3
import os
import shutil
import sys
from pathlib import Path

def main():
    print("====================================================")
    print("   harmonySecAnalyzer - Cross-Platform Deployment")
    print("====================================================")
    print()

    # 1. 验证运行路径是否在项目根目录
    project_root = Path.cwd()
    agent_src = project_root / "agent"
    skills_src = project_root / "skills_v2"

    if not agent_src.is_dir() or not skills_src.is_dir():
        print("[ERROR] 'agent' or 'skills_v2' directory not found. Please run this script from the project root.", file=sys.stderr)
        sys.exit(1)

    # 2. 定位 OpenCode 全局配置目录
    # On Windows: C:\Users\<Username>\.config\opencode
    # On macOS/Linux: ~/.config/opencode
    opencode_dir = Path.home() / ".config" / "opencode"
    agent_dst = opencode_dir / "agent"
    skills_dst = opencode_dir / "skills"

    print(f"[*] OpenCode Config Directory: {opencode_dir}")
    print(f"[*] Target Agent Directory:  {agent_dst}")
    print(f"[*] Target Skills Directory: {skills_dst}")
    print()

    # 3. 清理旧版本文件以防止覆盖冲突
    print("[*] Cleaning up old installations...")
    
    old_agents = [
        "harmony_analyzer.md",
        "project_parser.md",
        "vulnerability_auditor.md",
        "report_generator.md"
    ]
    for agent_name in old_agents:
        old_file = agent_dst / agent_name
        if old_file.is_file():
            print(f"  - Removing old agent: {agent_name}")
            try:
                old_file.unlink()
            except Exception as e:
                print(f"  [WARN] Failed to remove {old_file}: {e}")

    old_skills = [
        "atlas-indexer",
        "harmony-code-verifier",
        "harmony-project-parser",
        "harmony-report-generator"
    ]
    for skill_name in old_skills:
        old_dir = skills_dst / skill_name
        if old_dir.is_dir():
            print(f"  - Removing old skill: {skill_name}")
            try:
                shutil.rmtree(old_dir)
            except Exception as e:
                print(f"  [WARN] Failed to remove {old_dir}: {e}")
                
    print("[DONE] Cleanup completed.\n")

    # 4. 创建目标目录（如果不存在）
    try:
        agent_dst.mkdir(parents=True, exist_ok=True)
        skills_dst.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[ERROR] Failed to create directories: {e}", file=sys.stderr)
        sys.exit(1)

    # 5. 复制新版本 Agent 和 Skills
    print("[*] Deploying agents and skills...")
    try:
        # 复制 agents md 文件
        for md_file in agent_src.glob("*.md"):
            shutil.copy2(md_file, agent_dst / md_file.name)
            
        # 复制 skills_v2 下的各个子目录
        for skill_dir in skills_src.iterdir():
            if skill_dir.is_dir():
                shutil.copytree(skill_dir, skills_dst / skill_dir.name)
        
        print("[SUCCESS] Installation completed successfully!\n")
    except Exception as e:
        print(f"[ERROR] Failed to copy files: {e}", file=sys.stderr)
        sys.exit(1)

    # 6. 输出花体控制台日志提醒用户重启 OpenCode
    message_path = project_root / "script" / "restart_message.txt"
    if message_path.is_file():
        try:
            with open(message_path, "r", encoding="utf-8") as f:
                print(f.read())
        except Exception as e:
            print(f"[WARN] Failed to read restart message: {e}")
    else:
        print("***************************************************************")
        print("* PLEASE RESTART OPENCODE                                     *")
        print("***************************************************************")

if __name__ == "__main__":
    main()
