# harmonySecAnalyzer-v3.1

本项目是适配 opencode 的鸿蒙 ArkTS 白盒安全审计多智能体系统。

## 快速上手

- 入口命令：`/audit [scope] [repo-path]`（见 `.opencode/commands/audit.md`）
- 编排者：`harmony-auditor`（`.opencode/agents/harmony-auditor.md`）
- 完整设计：`DESIGN.md`

## 目录

- `.opencode/`：opencode 资源（agents/commands/skills/tools/plugins）—— opencode 强制约定目录，不可改名
- `rules/`：semgrep 规则库（与运行时解耦，可单测）
- `knowledge/`：漏洞知识库、权限映射、CWE 表
- `examples/` `tests/`：规则回归（正例/反例）
- `reports/`：审计产出（gitignore）
- `tools/`：独立 CLI 工具（P4）

## 开发约定

- agent 定义放 `.opencode/agents/*.md`（frontmatter 配置 + body 作为 prompt）
- 知识/流程放 `.opencode/skills/<name>/SKILL.md`（按需加载，不进系统提示）
- 确定性分析动作用 atlas MCP 工具（`atlas_*`）或 `.opencode/tools/*.ts` custom tool
- finding 统一 schema 见 `harmony-auditor` 的 prompt
- atlas 在目标仓生成 `.atlas/`（可接受）；审计过程只读目标仓，不修改其代码
- opencode 中 MCP 工具名以 server 名为前缀：atlas 工具即 `atlas_search` / `atlas_path` / `atlas_trace` 等，permission 用 `atlas_*` glob 控制

## atlas 能力边界（重要）

- **ArkTS**（.ets/.sts）：`search` / `symbol` / `explore` / `calls` / `path` / `trace(variable/forward/callers)` / `impact` / `file_dependencies` ✅ —— 污点可达性用 `path` + `trace`
- **C/C++**（NAPI native 层）：`lifecycle` / `branch_diff` / `fp_dispatches` / `domain_rules` ✅ —— 用于 native 内存安全（UAF / 双 free / 漏 free / 分支泄漏）
- ArkTS **无 CFG**，故 `lifecycle` / `branch_diff` / `fp_dispatches` 不适用于 ArkTS 符号
- 装饰器（@Component/@State/@Builder）语义 atlas 文档未明确 → P4 用 ts-morph 补充

## 四阶段流水线

`项目解析 → 逻辑审计与漏洞发现 → 漏洞验证 → 报告生成`

详见 `DESIGN.md` §3 与 `.opencode/skills/audit-workflow/SKILL.md`。
