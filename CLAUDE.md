# harmonySecAnalyzer-v3.1

本项目同时适配 Claude Code 与 OpenCode 的 HarmonyOS ArkTS 白盒安全审计多智能体系统。本文件面向 Claude Code；OpenCode 侧见 `AGENTS.md`。

## 入口

- 命令：`/audit [--incremental] [--capability CAP-ID] [--component Component] <repo-path>`
- 编排者：`.claude/agents/harmony-auditor.md`（命令正文用 Agent 工具派发，`subagent_type: harmony-auditor`）
- 设计事实基线：`DESIGN.md`

## 约定

- `.claude/` 是 Claude Code 资源目录（`agents/`、`commands/`、`skills/`、`settings.json`）；`.opencode/` 是 OpenCode 资源目录，两者并存、语义保持一致。
- 运行时脚本（`audit_orchestrator.py`、`audit_runtime/`、`project_profiler.py`、`atlas_indexer.py`、config/schemas）的唯一事实源位于 `.opencode/skills/` 下；两个工具的 SKILL.md 都引用同一路径，不复制运行时。
- Atlas MCP 由项目级 `.mcp.json` 提供（stdio 启动 `atlas mcp`）；Claude Code 中工具名为 `mcp__atlas__*`（如 `mcp__atlas__project`、`mcp__atlas__search`）。
- `run.db` 是可变状态唯一事实源；Agent 不直接修改中央状态或报告。
- 源码事实查询使用 Atlas MCP；项目配置由 `project_profiler.py` 确定性解析。
- 能力注册表只定义审计范围；安全判定统一由六维验证契约完成。
- `exports/attack_matrix.json` 是 Entry、Operation Group 和 Finding 的确定性覆盖视图。
- 审计目标源码只读；运行时只允许生成 `.atlas/` 和 `reports/`。
- 增量基线位于 `reports/incremental-baseline/`；Git 与非 Git 项目统一使用内容哈希判定变化，只在无缺口的成功运行后推进。
- ArkTS 使用 Atlas `search/symbol/explore/calls/path/trace/impact/file_dependencies`；Native/NAPI 当前不接入。

## 权限说明

- `.claude/settings.json` 只放行了编排脚本命令（`python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py:*`）与全部 Atlas MCP 工具；其他 Bash 命令默认询问。
- 审计的目标仓库在工作目录之外时，需要把目标仓绝对路径加入 `.claude/settings.json` 的 `additionalDirectories`，或在首次访问时批准。
- 任务文件（`**/reports/**/tasks/**`）与 `run.db` 由编排者指令约束为不可读取；编排者只通过 `claim-batch`/`reconcile-batch` 推进任务状态。
