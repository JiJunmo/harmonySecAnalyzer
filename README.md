# harmonySecAnalyzer-v3.1

面向 HarmonyOS ArkTS 项目的 OpenCode 多智能体白盒安全审计系统。系统从外部入口构建证据 Flow，并在 Flow 闭合后执行模式评估和可利用性验证。

## 使用

```text
/audit <repo-path>
/audit --capability <CAP-ID> <repo-path>
/audit --component <AbilityName> <repo-path>
/audit --component <module/ExtensionAbilityName> --capability <CAP-ID> <repo-path>
```

`--component` 可重复使用，支持组件简单名、`module/Component` 和 `module:Component`。它在入口规划前裁剪项目候选，适合定点验证某个 Ability 或 ExtensionAbility。

部署：

```bash
python3 -m pip install -r requirements.txt
python3 deploy.py
python3 deploy.py --global
```

## 架构

| 阶段 | 组件 | 产出 |
|---|---|---|
| 项目建模 | `project-modeling` Skill | Manifest/JSON5 项目事实与入口候选 |
| 入口归一化 | `entry-planner` Agent | 带 dispatcher 判别符的 Canonical Entry |
| 证据流分析 | `flow-analyzer` Agent + Atlas MCP | Flow、Fact、Edge、Continuation |
| 模式评估 | `flow-pattern-evaluator` Agent + `attack-patterns` Skill | 按能力画像产生 Hypothesis |
| 可利用性验证 | `flow-validator` Agent | 六门槛分类与结构化根因 |
| 状态与报告 | `audit-orchestration` Skill | SQLite 状态、根因聚合、JSON/Markdown/HTML |

`run.db` 是运行状态唯一事实源。`exports/attack_matrix.json` 提供 Flow、Hypothesis 和 Finding 的覆盖视图。

完整设计见 [DESIGN.md](DESIGN.md)。
