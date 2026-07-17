# harmonySecAnalyzer-v3.1

本项目是适配 opencode 的鸿蒙 ArkTS 白盒安全审计多智能体系统。

## 快速上手

- 入口命令：`/audit [scope] [repo-path]`（见 `.opencode/commands/audit.md`）
- 编排者：`harmony-auditor`（`.opencode/agents/harmony-auditor.md`）
- 完整设计：`DESIGN.md`

## 目录

- `.opencode/`：opencode 资源（agents/commands/skills）—— opencode 强制约定目录，不可改名
- `.opencode/skills/audit-orchestration/config/schemas/`：跨组件交换数据的 JSON Schema
- `tests/`：编排器、建模器、能力注册表与回归样本测试
- `docs/`：辅助设计与测试文档
- `reports/`：审计产出（gitignore）

## 开发约定

- agent 定义放 `.opencode/agents/*.md`（frontmatter 配置 + body 作为 prompt）
- 知识/流程放 `.opencode/skills/<name>/SKILL.md`（按需加载，不进系统提示）
- 攻击模式卡归属 `attack-patterns` Skill；能力注册表归属 `audit-orchestration` Skill
- 源码事实查询使用 atlas MCP 工具（`atlas_*`）；确定性转换脚本归属对应 Skill
- finding 统一契约见 `audit-orchestration/config/schemas/findings.schema.json`
- atlas 在目标仓生成 `.atlas/`（可接受）；审计过程只读目标仓，不修改其代码
- opencode 中 MCP 工具名以 server 名为前缀：atlas 工具即 `atlas_search` / `atlas_path` / `atlas_trace` 等，permission 用 `atlas_*` glob 控制

## atlas 能力边界（重要）

- **ArkTS**（.ets/.sts）：`search` / `symbol` / `explore` / `calls` / `path` / `trace(variable/forward/callers)` / `impact` / `file_dependencies` ✅ —— 污点可达性用 `path` + `trace`
- **C/C++**：Atlas 提供 `lifecycle` / `branch_diff` / `fp_dispatches` / `domain_rules`，但当前流程不接入 native 审计
- ArkTS **无 CFG**，故 `lifecycle` / `branch_diff` / `fp_dispatches` 不适用于 ArkTS 符号

## 四阶段流水线

`项目解析 → 逻辑审计与漏洞发现 → 漏洞验证 → 报告生成`

详见 `DESIGN.md` 与 `.opencode/skills/audit-workflow/SKILL.md`。
