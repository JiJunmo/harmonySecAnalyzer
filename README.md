# harmonySecAnalyzer-v3.1

面向 HarmonyOS ArkTS 项目的 OpenCode 多智能体白盒安全审计系统。脚本完成项目建模、Atlas 索引和组件任务生成；组件语义 Agent 负责源码事实，独立验证 Agent 只根据落盘语义结果完成六维漏洞有效性判断。

## 使用

```text
/audit <repo-path>
/audit --incremental <repo-path>
/audit --resume <run-dir>
/audit --capability <CAP-ID> <repo-path>
/audit --component <AbilityName> <repo-path>
/audit --component <module/ExtensionAbilityName> --capability <CAP-ID> <repo-path>
```

`--incremental` 使用上次成功的无过滤审计作为基线。Git 项目记录两个审计提交之间的累计变化并纳入工作区，非 Git 项目使用内容哈希快照。受影响组件重新执行语义分析，未受影响组件复用已校验的语义结果；组件连接始终使用当前完整状态重新计算，操作组集合和安全语义均未变化时同时复用六维验证结论。报告按稳定 Finding ID 展示新增、结论变化、已消失和未变的风险路径。

`--resume` 用于最终报告存在 exhausted 任务的运行。参数是具体 run 目录；已完成结果保持不变，只重试失败任务，成功后覆盖生成该 run 的报告并推进合格基线。

`--component` 与 `--capability` 均可重复并可组合。组件过滤用于定点审计 Ability/ExtensionAbility，能力过滤用于只验证指定能力。

```bash
python3 -m pip install -r requirements.txt
python3 deploy.py
python3 deploy.py --global
```

## 架构

| 阶段 | 组件 | 产出 |
|---|---|---|
| 审计准备与任务生成 | `project-modeling` Skill、Atlas Indexer、Python Runtime | 项目事实、完整索引、组件分析单元与任务 |
| 组件语义分析 | `component-semantic-analyzer` Agent、Atlas MCP | 真实入口、数据传播、实际操作组、组件间身份权限变化和防护事实 |
| 组件关联与六维验证 | Python Correlator、`exploitability-validator` Agent | 跨组件参数与身份链、每个操作组的六维结论、反证和漏洞分类 |
| 状态与报告 | `audit-orchestration` Skill | SQLite 状态、根因聚合、漏洞证据路径、JSON/Markdown/HTML |

CAP-DOS-001 用于 ArkTS 可用性安全审计，覆盖外部可触发的崩溃、无界或可放大的 CPU/内存/线程/队列/存储消耗，以及可重复的 IPC 和 CommonEvent 资源耗尽。Native/NAPI 层 DoS 不在当前范围内。

`run.db` 是运行状态唯一事实源。`exports/attack_matrix.json` 是入口、实际操作组和 Finding 的确定性覆盖视图。

完整设计见 [DESIGN.md](DESIGN.md)。
