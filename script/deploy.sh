#!/bin/bash

echo "===================================================="
echo "   harmonySecAnalyzer - macOS/Linux Deployment Script"
echo "===================================================="
echo ""

# 1. 验证运行路径是否在项目根目录
if [ ! -d "agent" ]; then
    echo "[ERROR] 'agent' directory not found. Please run this script from the project root."
    exit 1
fi
if [ ! -d "skills_v2" ]; then
    echo "[ERROR] 'skills_v2' directory not found. Please run this script from the project root."
    exit 1
fi

# 2. 定位 OpenCode 全局配置目录
OPENCODE_DIR="$HOME/.config/opencode"
AGENT_DIR="$OPENCODE_DIR/agent"
SKILLS_DIR="$OPENCODE_DIR/skills"

echo "[*] OpenCode Config Directory: $OPENCODE_DIR"
echo "[*] Target Agent Directory:  $AGENT_DIR"
echo "[*] Target Skills Directory: $SKILLS_DIR"
echo ""

# 3. 清理旧版本文件以防止覆盖冲突
echo "[*] Cleaning up old installations..."
if [ -f "$AGENT_DIR/harmony_analyzer.md" ]; then
    echo "  - Removing old agent: harmony_analyzer.md"
    rm -f "$AGENT_DIR/harmony_analyzer.md"
fi
if [ -f "$AGENT_DIR/project_parser.md" ]; then
    echo "  - Removing old agent: project_parser.md"
    rm -f "$AGENT_DIR/project_parser.md"
fi
if [ -f "$AGENT_DIR/vulnerability_auditor.md" ]; then
    echo "  - Removing old agent: vulnerability_auditor.md"
    rm -f "$AGENT_DIR/vulnerability_auditor.md"
fi
if [ -f "$AGENT_DIR/report_generator.md" ]; then
    echo "  - Removing old agent: report_generator.md"
    rm -f "$AGENT_DIR/report_generator.md"
fi

if [ -d "$SKILLS_DIR/atlas-indexer" ]; then
    echo "  - Removing old skill: atlas-indexer"
    rm -rf "$SKILLS_DIR/atlas-indexer"
fi
if [ -d "$SKILLS_DIR/harmony-code-verifier" ]; then
    echo "  - Removing old skill: harmony-code-verifier"
    rm -rf "$SKILLS_DIR/harmony-code-verifier"
fi
if [ -d "$SKILLS_DIR/harmony-project-parser" ]; then
    echo "  - Removing old skill: harmony-project-parser"
    rm -rf "$SKILLS_DIR/harmony-project-parser"
fi
if [ -d "$SKILLS_DIR/harmony-report-generator" ]; then
    echo "  - Removing old skill: harmony-report-generator"
    rm -rf "$SKILLS_DIR/harmony-report-generator"
fi
echo "[DONE] Cleanup completed."
echo ""

# 4. 创建目标目录（如果不存在）
mkdir -p "$AGENT_DIR"
mkdir -p "$SKILLS_DIR"

# 5. 复制新版本 Agent 和 Skills 
echo "[*] Deploying agents and skills..."
cp -f agent/*.md "$AGENT_DIR/"

cp -rf skills_v2/atlas-indexer "$SKILLS_DIR/"
cp -rf skills_v2/harmony-code-verifier "$SKILLS_DIR/"
cp -rf skills_v2/harmony-project-parser "$SKILLS_DIR/"
cp -rf skills_v2/harmony-report-generator "$SKILLS_DIR/"

echo "[SUCCESS] Installation completed successfully!"
echo ""

# 6. 输出花体控制台日志提醒用户重启 OpenCode
echo "***************************************************************"
echo "*                                                             *"
echo "*    ____  _      _____    _    ____  _____                   *"
echo "*   |  _ \| |    |  ___|  / \  / ___|| ____|                  *"
echo "*   | |_) | |    | |_    / _ \ \___ \|  _|                    *"
echo "*   |  __/| |___ |  _|  / ___ \ ___) | |___                   *"
echo "*   |_|   |_____|_____|/_/   \_\____/|_____|                  *"
echo "*                                                             *"
echo "*    ____  _____ ____ _____  _    ____ _____                  *"
echo "*   |  _ \| ____/ ___|_   _|/ \  |  _ \_   _|                 *"
echo "*   | |_) |  _| \___ \ | | / _ \ | |_) || |                   *"
echo "*   |  _ <| |___ ___) || |/ ___ \|  _ < | |                   *"
echo "*   |_| \_\_____|____/ |_/_/   \_\_| \_\|_|                   *"
echo "*                                                             *"
echo "*     ___  ____  _____ _   _  ____  ___  ____  _____          *"
echo "*    / _ \|  _ \| ____| \ | |/ ___|/ _ \|  _ \| ____|         *"
echo "*   | | | | |_) |  _| |  \| | |   | | | | | | |  _|           *"
echo "*   | |_| |  __/| |___| |\  | |___| |_| |  _ <| |___          *"
echo "*    \___/|_|   |_____|_| \_\____/\___/|_| \_\|_____|         *"
echo "*                                                             *"
echo "***************************************************************"
echo ""
