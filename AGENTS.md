# harmonySecAnalyzer-v3.1

本项目同时适配 OpenCode 与 Claude Code 的 HarmonyOS ArkTS 白盒安全审计多智能体系统。本文件面向 OpenCode；Claude Code 侧见 `CLAUDE.md`，其资源位于 `.claude/`，运行时与本文约定共用 `.opencode/skills/` 下的同一份脚本。

## 入口

- 命令：`/audit [--incremental] [--capability CAP-ID] [--component Component] <repo-path>`
- 编排者：`.opencode/agents/harmony-auditor.md`
- 设计事实基线：`DESIGN.md`

## 约定

- `.opencode/` 是 OpenCode 强制资源目录，不改名。
- Agent 定义位于 `.opencode/agents/`；流程和知识位于 `.opencode/skills/`。
- `audit-orchestration/scripts/audit_runtime/` 是 SQLite 证据流运行时。
- `run.db` 是可变状态唯一事实源；Agent 不直接修改中央状态或报告。
- 源码事实查询使用 Atlas MCP；项目配置由 `project_profiler.py` 确定性解析。
- 能力注册表只定义审计范围；安全判定统一由六维验证契约完成。
- `exports/attack_matrix.json` 是 Entry、Operation Group 和 Finding 的确定性覆盖视图。
- 审计目标源码只读；运行时只允许生成 `.atlas/` 和 `reports/`。
- 增量基线位于 `reports/incremental-baseline/`；Git 与非 Git 项目统一使用内容哈希判定变化，只在无缺口的成功运行后推进。
- ArkTS 使用 Atlas `search/symbol/explore/calls/path/trace/impact/file_dependencies`；Native/NAPI 当前不接入。
