---
name: audit-orchestration
description: 基于 SQLite 的入口驱动证据流运行时调用协议。
---

`.opencode/skills/audit-orchestration/scripts/audit_orchestrator.py` 是唯一控制面。`run.db` 是可变状态唯一事实源；Agent 结果先做 Schema 与业务不变量校验，再在一个事务中合并并派生后续任务。JSON、Markdown 和 HTML 都是可重建导出。

```bash
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode full
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode capability --capability CAP-XXX
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode full --component <AbilityName>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py prepare --target-repo <repo> --mode capability --capability CAP-XXX --component <module/ExtensionAbilityName>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py next <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py submit <run_dir> --task <task_id> --attempt <attempt> --input <worker-result.json>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py fail <run_dir> --task <task_id> --attempt <attempt> --error <message> [--retryable]
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py recover <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py validate-ready <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py export <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py build-report <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py finalize <run_dir>
python3 .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py status <run_dir>
```

一次 bash 调用对应上述一条命令，并直接使用 `prepare`、`next` 返回的绝对路径值。`prepare` 是“审计准备与入口建模”的确定性入口，依次完成配置解析、Atlas 索引、run 创建和 Entry Resolution 任务初始化；失败时不产生可继续调度的半成品 run。Entry Resolution 提交完成且每个候选都有唯一 disposition 后，这个大流程才算完成。

任务演进固定为：`entry_resolution -> entry_path_discovery/continuation_resolution -> security_assessment`。前两类分析产生局部 Flow 段，运行时沿 continuation 将它们组装为完整 Path；每条闭合 Path 只创建一个安全判定任务。`next` 每次只返回一个轻量任务句柄，完整上下文与结果 Schema 位于句柄指定的 `task_file`，句柄中的 `worker_prompt` 可原样交给对应 subagent。只有 `next` 能派发任务；`submit` 不返回可直接派发的下游任务 ID。worker 只写私有结果；`submit` 成功才算任务完成。

continuation 按规范化 handler identity 归并，调用标签等展示差异不产生新的 handler 分析。一个 `continuation_resolution` task 可以承载多个父 Flow；若同一 handler 已分析，task input 提供规范化的 `reusable_handler_flows`，worker 只补充当前安全上下文映射。不同父 Flow 的 root entry、branch、controlled property 与边界仍分别建 Flow，运行时记录父 continuation 到子 Flow 的显式关系。

编排者连续调用 `next`，只收集句柄而不读取或派发，直到 `worker_pool_full` 或 `no_queued`，再在同一条 assistant 消息中一次发出全部 TaskTool 调用。一个句柄严格对应一次独立 subagent 调用；整批完成并逐个 `submit` 后才开始下一轮填槽。运行时不声称能控制动态补位。每次尝试有独立 submission 文件，过期结果只会被忽略。提交时尽可能一次返回 Schema 和业务不变量的全部错误；前两次失败重新排队。安全判定第三次仍不合法时只把当前 Path 记为 `insufficient_evidence`，其余任务继续；前置建模或路径结构任务耗尽重试仍会终止 run。中断已有 run 时显式使用一次 `recover`，正常流程不依赖超时 lease。

Security Assessment 的 task input 包含完整 Path、Canonical Entry、该入口适用的能力画像和对应 `pattern_cards`。Agent 根据 Path 实际语义直接识别相关模式，不逐张输出适用性；已有模式之外的安全场景允许以空 pattern ID 提交。只有关键维度缺证据时才能使用 Atlas 做有界复核。

`--component` 可重复，接受组件简单名、`module/Component` 或 `module:Component`；它与 `--capability` 正交，并在 Atlas 索引和 Entry Resolution 前确定性裁剪候选。能力模式在 Entry Resolution 确认入口类型后，不再为不适用目标能力的入口创建路径任务。

Flow Analyzer 只产生结构状态 `open/reached/stopped/gap`，不得判断 Guard 有效性、业务合理性或漏洞。Security Assessor 对完整 Path 先执行反证审查，再完成六维有效性验证；确认漏洞必须六项全部为 true、没有有效反证，且 Path 中存在 operation 与 effect。分类不会反向修改 Flow 或 Path 的结构状态。

报告准入要求：run 仍为 running、所有项目候选有唯一 disposition、无 queued/running/failed/cancelled task、无 open continuation、无未组装为 Path 的终止 Flow、无缺少子 Flow 的已解析 continuation，且每条 Path 都有对应的安全判定任务。失败 run 不允许生成正式报告。`build-report` 与 `finalize` 使用相同准入。报告主指标只把 `confirmed_vulnerability` 与 `residual_risk` 的根因 Finding 计为安全问题。`exports/attack_matrix.json` 从 Path、Assessment 和 Finding 确定性生成覆盖视图。

run 目录：

```text
run.db
session.json
project/project_model.json
tasks/*.json + *.result.json
exports/entries.json + flows.json + paths.json + assessments.json + attack_matrix.json + tasks.json
findings.json + report_model.json + report.md + report.html + report_snapshot.json
```
