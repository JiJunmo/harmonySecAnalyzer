`{{audit_orchestrator_path}}` 是当前部署包的唯一控制面。`run.db` 是可变状态唯一事实源；Agent 结果先通过 Schema 和业务不变量校验，再在一个事务中落库。JSON、Markdown 和 HTML 都是可重建导出。

```bash
python3 "{{audit_orchestrator_path}}" prepare --target-repo "<repo>" --mode full
python3 "{{audit_orchestrator_path}}" prepare --target-repo "<repo>" --mode incremental
python3 "{{audit_orchestrator_path}}" prepare --target-repo "<repo>" --mode capability --capability CAP-XXX
python3 "{{audit_orchestrator_path}}" prepare --target-repo "<repo>" --mode full --component <AbilityName>
python3 "{{audit_orchestrator_path}}" prepare --target-repo "<repo>" --mode capability --capability CAP-XXX --component <module/ExtensionAbilityName>
python3 "{{audit_orchestrator_path}}" claim-batch "<run_dir>"
python3 "{{audit_orchestrator_path}}" explore-next "<run_dir>" --task-id "<task_id>" --attempt <attempt>
python3 "{{audit_orchestrator_path}}" explore-record "<run_dir>" --task-id "<task_id>" --attempt <attempt> --input "<step_file>"
python3 "{{audit_orchestrator_path}}" explore-finish "<run_dir>" --task-id "<task_id>" --attempt <attempt>
python3 "{{audit_orchestrator_path}}" task-submit "<run_dir>" --task-id "<task_id>" --attempt <attempt> --input "<draft_file>"
python3 "{{audit_orchestrator_path}}" reconcile-batch "<run_dir>"
python3 "{{audit_orchestrator_path}}" export "<run_dir>"
python3 "{{audit_orchestrator_path}}" build-report "<run_dir>"
python3 "{{audit_orchestrator_path}}" finalize "<run_dir>"
python3 "{{audit_orchestrator_path}}" resume "<run_dir>"
python3 "{{audit_orchestrator_path}}" status "<run_dir>"
```

`prepare` 依次完成 JSON5 配置解析、Atlas 全量索引、隔离 run 创建、完整组件目录归组，以及起始组件探索状态和持久任务初始化。Manifest 候选按 `component_id` 归组；项目建模不创建宽泛的 module 级 CommonEvent 候选或独立子任务。上述工作全部由脚本完成，不调用 AI，也不预先展开完整函数图。

增量模式必须已有一次无过滤且无未完成任务的成功基线。脚本将 Git 累计提交差异或非 Git 文件快照统一为 `change_set.json`，对比新旧项目模型，再按模块归属、反向模块依赖和历史组件调用计算 `impact_plan.json`。受影响组件进入原有语义任务；未受影响组件的历史结果必须重新通过当前 Schema 和业务不变量才能复用。组件连接使用当前完整语义状态重新计算；同一入口下的操作组集合及安全语义指纹完全一致时复用六维验证结果，否则重新派发验证任务。

AI 任务严格分成 `component_semantic_analysis`、`exploitability_validation` 和 `poc_generation`。语义阶段每个组件只有一个持久任务记录和一个探索状态，但同一任务可按单轮容量多次派发。Agent 通过 `explore-next` 领取安全语义断点，优先使用 Atlas，并在动态调用缺边时以调用点和绑定/分派点源码证据补全关系；每个继续分析的目标都必须声明关系来源。运行时优先返回当前路径的后续断点；路径闭合且本轮累计函数尚有余量时，再领取下一条待分析路径。轮次函数保护只保存证据、重新排队并换新上下文，不生成覆盖缺口；只有组件总工作量异常上限才以可见缺口收口。`explore-record` 即时校验并落盘当前分段事实，`explore-finish` 负责接续轮次或生成最终组件语义结果。

全量模式和组件级能力模式初始化全部组件探索；组件过滤模式只初始化指定组件，再按已证明的 `component_calls` 补充尚未分析的下游组件及其探索状态。能力表中的 `entry_types` 只随任务作为优先提示，不参与组件排除。没有新的下游组件后，运行时确定性连接组件，只为真实外部入口可达的本地操作和跨组件操作创建验证任务。

本轮上下文容量不足时，语义 Agent 通过现有 `explore-record` 保存待分析目标并设置 `pause_requested=true`。后续目标的 `stop_reason=null` 表示待分析，有明确正常边界原因则不展开，不重复填写 decision。下一次 `explore-next` 返回 `round_complete=true`，随后 `explore-finish` 将有待办的同一 task_id 重新排队；没有待办则直接完成组件。已排队的其他分支无需重复声明。record 返回 `node_status=completed` 只表示分段已保存；finish 返回 `task_status=queued/completed` 决定轮次继续或任务完成。

每步必填 resume：当前函数未完时保存源码位置、剩余工作和安全状态，脚本生成同一函数的续跑分段；已完且其他去向均已登记时为 null。不能用自指 successor 或修改函数定义行号来续跑。next 返回 `work.resume_from`，Agent 从该处继续；它与 `pause_requested` 是否换上下文是两个不同事实。入口初判允许在后续步骤通过同一个 `entry_assessment` 携带新定位证据更新，next 返回当前组件的最新判断。

Agent 不填写步骤 status。每个解析缺口只在 `gaps[]` 中填写 target、reason 和 evidence，不再重复声明 gap 类型事实或 unresolved 停止原因。正常终止、真实缺口、其他待分析分支和暂停请求可以同时存在，彼此独立。查询中的未解析表达式必须被源码补全或对应一个 gap 目标；未知目标不创建虚构 successor。安全检查使用源码位置、检查对象和校验属性引用，不由 Agent 生成 ID。`resource_limit` 仅由脚本产生，且不会伪装成已分析的步骤。格式错误在当前子任务内退回修正，不消耗调度重试。

六维验证和 PoC Agent 只写任务私有草稿。任务文件中的 `result_protocol` 给出绝对草稿路径和 `audit_orchestrator.py task-submit` 命令；Result Writer 确定性补齐任务 ID、对象 ID、缺省字段，规范和过滤证据引用，再以最终严格 Schema 与业务不变量验收，并在同一事务中写入正式结果、完成任务。可修复格式错误不消耗调度重试；此类拒绝仍是命令正常执行，只返回 `accepted=false`，Agent 在本次子任务中修正草稿，只有 `accepted=true` 且 `status=completed` 才允许结束。实质性证据不足、跨组引用后失去有效支持或结论冲突仍会被拒绝。

验证结果落库并生成 confirmed/residual Finding 时，运行时立即为每个 Finding 派生一个 `poc_generation` 任务（`poc:{finding_id}`）。PoC 任务只为该 Finding 生成可复现触发套件，禁止重新判定漏洞或自行输出可信度；规范化后的提交必须通过 poc-result Schema 与 PoC 领域校验（证据引用、占位符、禁止越权输出、触发形态一致性）才能落库到 `poc_artifacts`，并由运行时标记为 `generated_unverified`。该状态只表示静态契约通过，不表示已经编译或在设备上执行。Finding 内容变化时已完成的任务自动重新排队；增量模式下操作组指纹与基线 PoC 快照一致时直接复用。PoC 任务达到三次尝试上限不阻塞 Run 完成，也不计入覆盖缺口，仅在对应 Finding 报告中显示 `generation_failed`。

Operation Group 只有在能力、操作位置、关键受控参数、调用主体/业务用途、直接效果和适用防护等安全语义均相同时才归并；普通分支作为组内事实保留。跨组件关联额外按身份是否保留、下游观察主体、实际权限和安全检查约束对象区分安全语义，避免把正常身份透传与代理借权路径合并。Agent 提示词定义状态语义，Schema 限定输出形态，运行时校验器要求 `true/false` 均有非假设证据、防护结果与六维状态一致、最终分类符合决策表。每个组有且只有一个六维结论；`no_exploitable_path` 用于基础路径被明确反证，不能与正常业务或证据不足混用。只有 confirmed vulnerability 和 residual risk 生成 Finding 及报告证据路径。

`CAP-DOS-001` 仍使用上述 Operation Group 和六维验证。语义结果必须额外记录受影响资源/失败、输入上限或放大关系、异常隔离、重复触发、影响范围和恢复方式。验证阶段只有在单次触发足以致命或攻击者可重复放大、存在实质可用性损失且没有有效限制/隔离时才允许确认漏洞。

编排者调用一次 `claim-batch` 领取最多 5 个任务，并在同一条 assistant 消息中一次派发全部句柄。正常任务在子 Agent 上下文内通过受控命令即时完成或进入下一轮；整批返回后调用一次 `reconcile-batch`，只将仍停在 `running` 的中止任务重新排队。语义轮次仍有待分析节点时，`explore-finish` 直接重新排队并清零轮次重试次数，已记录节点不回滚；所有节点闭合时直接生成最终语义结果并完成任务。第三次仍未完成时只将该任务标记为 `exhausted`，不终止其他组件。会话中断后使用同一个异常回收命令；已经最终输出但包含 exhausted 任务的 run 使用 `resume` 重新打开，只重试失败任务并释放旧节点租约。

`prepare` 完成后立即创建动态 `report.html`；`claim-batch`、任务即时提交和 `reconcile-batch` 会按当前 SQLite 状态原子更新文件，用户刷新浏览器即可查看最新进度。中间更新不生成 Markdown、导出文件或最终快照，`finalize` 才生成完整正式产物。

`--component` 可重复，接受组件简单名、`module/Component` 或 `module:Component`；它与 `--capability` 正交。组件过滤选择明确的起始组件；单独使用能力过滤时，全部组件都检查所选能力，`entry_types` 只决定 Agent 的优先核对顺序。语义分析分别确认组件输入和真实外部入口；组件过滤模式下，后续任务沿调用触发或参数传递仍受当前输入控制的组件调用扩展，二者均只接受 `preserved` 或 `constrained`。

报告准入要求：run 仍为 running，且没有 queued/running 任务。`exhausted` 任务和缺少语义分析或六维验证的对象作为覆盖缺口进入报告，不阻止已有审计结果输出。`build-report` 与 `finalize` 使用同一准入。

run 目录：

```text
run.db
session.json
project/project_model.json
incremental/change_set.json + impact_plan.json + baseline_semantic_results.json + baseline_validation_results.json + baseline_findings.json + baseline_poc_results.json
tasks/*.json + *.draft.json + *.step.json + *.result.json
exports/entries.json + exploration_graph.json + semantic_analyses.json + component_calls.json + component_graph.json
exports/operation_groups.json + validation_results.json
exports/evidence_paths.json + attack_matrix.json + tasks.json
findings.json + report_model.json + report.md + report.html + report_snapshot.json
```

成功的无过滤全量/增量运行另外更新审计目标下的 `reports/incremental-baseline/`；该目录不是 run，只是下次增量规划的稳定基线。
