# harmonySecAnalyzer-v3.1

面向 HarmonyOS ArkTS 项目的 OpenCode 多智能体白盒安全审计系统。系统从外部入口构建局部证据 Flow，并沿 continuation 组装完整 Path；每条闭合 Path 通过一次安全判定完成模式识别和六维漏洞有效性验证。

## 使用

```text
/audit <repo-path>
/audit --capability <CAP-ID> <repo-path>
/audit --component <AbilityName> <repo-path>
/audit --component <module/ExtensionAbilityName> --capability <CAP-ID> <repo-path>
```

`--component` 与 `--capability` 均可重复并可组合。组件过滤在入口确认前裁剪项目候选；能力过滤在入口类型确认后只为适用入口创建路径任务，适合定点验证某个 Ability、ExtensionAbility 或单项审计能力。

部署：

```bash
python3 -m pip install -r requirements.txt
python3 deploy.py
python3 deploy.py --global
```

## 架构

| 阶段 | 组件 | 产出 |
|---|---|---|
| 审计准备与入口建模 | `project-modeling` Skill、Atlas Indexer、`entry-resolver` Agent | 项目事实、可用索引、Canonical Entry、排除项与入口缺口 |
| 证据路径发现 | `flow-analyzer` Agent + Atlas MCP | 局部 Flow、Fact、Edge、Continuation、完整 Path |
| 安全判定 | `security-assessor` Agent + `attack-patterns` Skill | 模式识别、六维有效性验证与 Assessment |
| 状态与报告 | `audit-orchestration` Skill | SQLite 状态、根因聚合、JSON/Markdown/HTML |

`run.db` 是运行状态唯一事实源。`exports/attack_matrix.json` 提供 Path、Assessment 和 Finding 的覆盖视图。

完整设计见 [DESIGN.md](DESIGN.md)。
