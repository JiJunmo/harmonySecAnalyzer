---
name: audit-orchestration
description: 基于 SQLite 的组件级安全分析运行时调用协议。
---

`.opencode/skills/audit-orchestration/scripts/audit_orchestrator.py` 是唯一控制面。`run.db` 是可变状态唯一事实源；Agent 结果先通过 Schema 和业务不变量校验，再在一个事务中落库。JSON、Markdown 和 HTML 都是可重建导出。

```bash
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode full
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode capability --capability CAP-XXX
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode full --component <AbilityName>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode capability --capability CAP-XXX --component <module/ExtensionAbilityName>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py claim-batch <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py reconcile-batch <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py export <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py build-report <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py finalize <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py status <run_dir>
```

`prepare` 依次完成 JSON5 配置解析、Atlas 全量索引、隔离 run 创建、分析单元归组和组件任务初始化。Manifest 候选按 `component_id` 归组；无组件 ID 的动态入口候选按 module 和候选类型归组。上述工作全部由脚本完成，不调用 AI。

AI 任务严格分成 `component_semantic_analysis` 和 `exploitability_validation`。语义任务使用 Atlas 完成入口确认、数据追踪和实际操作归并，不输出安全结论。语义结果原子落库后，有操作组才创建同组件验证任务；验证任务只能在语义结果限定的源码范围内读取实现和定点使用 Atlas，不得重新执行路径发现。

Operation Group 只按操作源码位置和关键受控参数集合拆分，普通分支、防护代码和业务上下文作为组内事实。运行时验证语义证据后再要求每个组有且只有一个六维结论；验证结果不能引用语义阶段不存在的证据。只有 confirmed vulnerability 和 residual risk 生成 Finding 及报告证据路径。

编排者调用一次 `claim-batch` 领取最多 5 个任务，并在同一条 assistant 消息中一次派发全部句柄。整批返回后只调用一次 `reconcile-batch`；脚本检查每个任务约定的 submission 文件，接收有效结果，并将缺失或无效结果重新排队。第三次仍没有有效结果时只将该任务标记为 `exhausted`，不终止其他组件。会话中断后也使用同一个收敛命令，不存在独立恢复分支。

`--component` 可重复，接受组件简单名、`module/Component` 或 `module:Component`；它与 `--capability` 正交。组件过滤在任务生成前裁剪候选，能力过滤根据候选入口类型只创建适用的组件任务。

报告准入要求：run 仍为 running，且没有 queued/running 任务。`exhausted` 任务和缺少语义分析或六维验证的对象作为覆盖缺口进入报告，不阻止已有审计结果输出。`build-report` 与 `finalize` 使用同一准入。

run 目录：

```text
run.db
session.json
project/project_model.json
tasks/*.json + *.result.json
exports/entries.json + semantic_analyses.json + operation_groups.json + validation_results.json
exports/evidence_paths.json + attack_matrix.json + tasks.json
findings.json + report_model.json + report.md + report.html + report_snapshot.json
```
