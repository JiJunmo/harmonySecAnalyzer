---
name: audit-orchestration
description: 基于 SQLite 的入口驱动证据流运行时调用协议。
---

`.opencode/skills/audit-orchestration/scripts/audit_orchestrator.py` 是唯一控制面。`run.db` 是可变状态唯一事实源；Agent 结果先做 Schema 与业务不变量校验，再在一个事务中合并并派生后续任务。JSON、Markdown 和 HTML 都是可重建导出。

```bash
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py new-run reports --target-repo <repo> --mode full
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py new-run reports --target-repo <repo> --mode capability --capability CAP-XXX
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py new-run reports --target-repo <repo> --mode full --component <AbilityName>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py new-run reports --target-repo <repo> --mode capability --capability CAP-XXX --component <module/ExtensionAbilityName>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py init <run_dir> --project-model <project_model.json>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py claim <run_dir> --limit 5
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py submit <run_dir> --task <task_id> --input <worker-result.json>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py fail <run_dir> --task <task_id> --error <message> [--retryable]
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py validate-ready <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py export <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py build-report <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py finalize <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py status <run_dir>
```

一次 bash 调用对应上述一条命令，并直接使用 `new-run`、`claim` 返回的绝对路径值。

任务演进固定为：`entry_planning -> entry_exploration/continuation -> pattern_evaluation -> flow_validation`。`claim` 在全局 5 worker 上限内返回轻量任务句柄，完整上下文与结果 Schema 位于句柄指定的 `task_file`。只有 `claim` 能派发任务；`submit` 不返回可直接派发的下游任务 ID。worker 只写私有结果；`submit` 成功才算任务完成。

`--component` 可重复，接受组件简单名、`module/Component` 或 `module:Component`；它与 `--capability` 正交，并在 `init` 时确定性裁剪 Entry Planning 候选。

报告准入要求：所有项目候选有唯一 disposition、无 queued/running/failed task、无 open continuation。`exports/attack_matrix.json` 从 Flow、Hypothesis 和 Finding 确定性生成覆盖视图。

run 目录：

```text
run.db
session.json
project/project_model.json
tasks/*.json + *.result.json
exports/entries.json + flows.json + attack_matrix.json + tasks.json
findings.json + report_model.json + report.md + report.html + report_snapshot.json
```
