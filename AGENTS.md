# harmonySecAnalyzer-v3.1

本项目是适配 OpenCode 的 HarmonyOS ArkTS 白盒安全审计多智能体系统。

## 入口

- 命令：`/audit [--capability CAP-ID] <repo-path>`
- 编排者：`.opencode/agents/harmony-auditor.md`
- 设计事实基线：`DESIGN.md`

## 约定

- `.opencode/` 是 OpenCode 强制资源目录，不改名。
- Agent 定义位于 `.opencode/agents/`；流程和知识位于 `.opencode/skills/`。
- `audit-orchestration/scripts/audit_runtime/` 是 SQLite 证据流运行时。
- `run.db` 是可变状态唯一事实源；Agent 不直接修改中央状态或报告。
- 源码事实查询使用 Atlas MCP；项目配置由 `project_profiler.py` 确定性解析。
- 模式卡属于 `attack-patterns` Skill，能力画像属于 `audit-orchestration` Skill。
- `exports/attack_matrix.json` 是 Flow、Hypothesis 和 Finding 的确定性覆盖视图。
- 审计目标仓只读；Atlas 生成 `.atlas/` 可接受。
- ArkTS 使用 Atlas `search/symbol/explore/calls/path/trace/impact/file_dependencies`；Native/NAPI 当前不接入。
