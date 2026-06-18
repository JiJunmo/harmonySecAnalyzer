@echo off
setlocal enabledelayedexpansion

echo ====================================================
echo   harmonySecAnalyzer - Windows Deployment Script
echo ====================================================
echo.

:: 1. 验证运行路径是否在项目根目录
if not exist "agent" (
    echo [ERROR] "agent" directory not found. Please run this script from the project root.
    pause
    exit /b 1
)
if not exist "skills_v2" (
    echo [ERROR] "skills_v2" directory not found. Please run this script from the project root.
    pause
    exit /b 1
)

:: 2. 定位 OpenCode 全局配置目录
set "OPENCODE_DIR=%USERPROFILE%\.config\opencode"
set "AGENT_DIR=%OPENCODE_DIR%\agent"
set "SKILLS_DIR=%OPENCODE_DIR%\skills"

echo [*] OpenCode Config Directory: %OPENCODE_DIR%
echo [*] Target Agent Directory:  %AGENT_DIR%
echo [*] Target Skills Directory: %SKILLS_DIR%
echo.

:: 3. 清理旧版本文件以防止覆盖冲突
echo [*] Cleaning up old installations...
if exist "%AGENT_DIR%\harmony_analyzer.md" (
    echo   - Removing old agent: harmony_analyzer.md
    del /q "%AGENT_DIR%\harmony_analyzer.md"
)
if exist "%AGENT_DIR%\project_parser.md" (
    echo   - Removing old agent: project_parser.md
    del /q "%AGENT_DIR%\project_parser.md"
)
if exist "%AGENT_DIR%\vulnerability_auditor.md" (
    echo   - Removing old agent: vulnerability_auditor.md
    del /q "%AGENT_DIR%\vulnerability_auditor.md"
)
if exist "%AGENT_DIR%\report_generator.md" (
    echo   - Removing old agent: report_generator.md
    del /q "%AGENT_DIR%\report_generator.md"
)

if exist "%SKILLS_DIR%\atlas-indexer" (
    echo   - Removing old skill: atlas-indexer
    rd /s /q "%SKILLS_DIR%\atlas-indexer"
)
if exist "%SKILLS_DIR%\harmony-code-verifier" (
    echo   - Removing old skill: harmony-code-verifier
    rd /s /q "%SKILLS_DIR%\harmony-code-verifier"
)
if exist "%SKILLS_DIR%\harmony-project-parser" (
    echo   - Removing old skill: harmony-project-parser
    rd /s /q "%SKILLS_DIR%\harmony-project-parser"
)
if exist "%SKILLS_DIR%\harmony-report-generator" (
    echo   - Removing old skill: harmony-report-generator
    rd /s /q "%SKILLS_DIR%\harmony-report-generator"
)
echo [DONE] Cleanup completed.
echo.

:: 4. 创建目标目录（如果不存在）
if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
if not exist "%SKILLS_DIR%" mkdir "%SKILLS_DIR%"

:: 5. 复制新版本 Agent 和 Skills 
echo [*] Deploying agents and skills...
copy /y "agent\*.md" "%AGENT_DIR%\" > nul

xcopy /e /i /y "skills_v2\atlas-indexer" "%SKILLS_DIR%\atlas-indexer" > nul
xcopy /e /i /y "skills_v2\harmony-code-verifier" "%SKILLS_DIR%\harmony-code-verifier" > nul
xcopy /e /i /y "skills_v2\harmony-project-parser" "%SKILLS_DIR%\harmony-project-parser" > nul
xcopy /e /i /y "skills_v2\harmony-report-generator" "%SKILLS_DIR%\harmony-report-generator" > nul

echo [SUCCESS] Installation completed successfully!
echo.

:: 6. 输出花体控制台日志提醒用户重启 OpenCode
echo ***************************************************************
echo *                                                             *
echo *    ____  _      _____    _    ____  _____                   *
echo *   ^|  _ \^| ^|    ^|  ___^|  / \  / ___^|^| ____^|                  *
echo *   ^| ^|_) ^| ^|    ^| ^|_    / _ \ \___ \^|  _^|                    *
echo *   ^|  __/^| ^|___ ^|  _^|  / ___ \ ___) ^| ^|___                   *
echo *   ^|_^|   ^|_____^|_____^|/_/   \_\____/^|_____^|                  *
echo *                                                             *
echo *    ____  _____ ____ _____  _    ____ _____                  *
echo *   ^|  _ \^| ____/ ___^|_   _^|/ \  ^|  _ \_   _^|                 *
echo *   ^| ^|_) ^|  _^| \___ \ ^| ^| / _ \ ^| ^|_) ^|^| ^|                   *
echo *   ^|  _ <^| ^|___ ___) ^|^| ^|/ ___ \^|  _ < ^| ^|                   *
echo *   ^|_^| \_\_____^|____/ ^|_/_/   \_\_^| \_\^|_^|                   *
echo *                                                             *
echo *     ___  ____  _____ _   _  ____  ___  ____  _____          *
echo *    / _ \^|  _ \^| ____^| \ ^| ^|/ ___^|/ _ \^|  _ \^| ____^|         *
echo *   ^| ^| ^| ^| ^|_) ^|  _^| ^|  \^| ^| ^|   ^| ^| ^| ^| ^|_) ^|^|  _^|          *
echo *   ^| |_^| ^|  __/^| ^|___^| ^|\  ^| ^|___^| |_^| ^|  _ < ^| ^|___          *
echo *    \___/^|_^|   ^|_____^|_^| \_\____/\___/^|_^| \_\^|_____^|         *
echo *                                                             *
echo ***************************************************************
echo.

pause
