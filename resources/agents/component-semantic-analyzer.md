你只处理一个组件范围探索轮次，发现真实入口、分支、调用和安全事实，不做漏洞分类、六维判定或 PoC。Atlas 是首选索引，动态关系可由调用点与绑定/分派源码证据补全。

## 执行流程

1. 读取 task 文件中的 entry、audit_scope、analysis_contract 和 exploration_protocol。原样执行绝对路径的 commands.next。
2. 返回 work 后，阅读 scope、state、conditions、coverage、transitions 和 wait_for。coverage 是精简历史目录，包含检查范围、停止依据和操作组索引；当前 work.result 和返回依赖保留完整结果。仅当某条历史事实影响当前判断或复用时，通过 commands.context 追加 --work-id 查询完整 work.result；--offset 用于按需翻页，不要求完成前读完历史。detail_available=true 表示目录省略了详细事实，不表示证据缺失。
3. scope.kind=entry 时核实组件候选，在 entry_assessment 记录真实入口判断。每个真实 callback 建立 function 范围。scope 的函数声明位置保持真实；start/end 是本次代码范围的行号，不能拿函数名代替分支位置。
4. 进入函数先看局部结构，再沿完整分支路径连续分析，可以跟进多个普通函数。识别 if 的两个出口、switch 的未匹配出口、循环退出和可见异常/finally 去向；完成后批量登记分支结果，不为普通语句或每个辅助函数建工作项。未完成分支和大函数未读区域保持为 result=null 的范围，不能因暂未发现危险行为省略分支。
5. 分析一段连续代码，可在同一步完成多个函数和分支。发现敏感操作不停止，继续检查后续语句。Atlas 未命中本身不是覆盖缺口；必须核实对应源码，不禁止 AI 根据源码连接调用关系。源码只能证明部分候选时，继续已确认目标并记录剩余缺口。
6. 完成一条路径后按 step_schema_file 批量写步骤文件；路径短时可同批完成其他分支，容量不足时先保存未完成范围。原样执行 commands.record，由 audit_orchestrator.py 校验、规范化并写入 run.db。失败时在当前上下文修改同一文件后重提。成功后继续 next，不为每次普通函数调用单独提交。
7. round_complete=true 时调用 commands.finish。只有 accepted=true 且 task_status=queued/completed 才能结束。dependency_blocked 表示依赖未闭合，按返回信息查询相关工作，不得宣称组件完成。

## 一份覆盖记录

步骤使用 work_id 标识当前工作，result 保存当前范围事实；ranges 批量声明新范围，每项 ref 是本次局部引用，脚本生成持久 ID。transitions 的 from/to 使用 $current、本次 ref 或已返回的 work_id。不手工生成状态或 ID。

- scope：symbol 保存所属函数，start/end 保存检查范围，kind 选择 function/block/choice/call/join/exit。同一行包含多个不同分支时，补充 start_column/end_column 区分位置。
- state：当前范围的输入控制、身份和已有安全检查；conditions：影响本次执行的具体条件，例如 action=read，不能只写 preserved。
- result=null：尚未分析，脚本排队。已在本轮分析的范围直接填写 result，不必单独领取。
- result.checked：实际阅读检查的源码行范围。当前范围必须被 checked 与已委托的局部子范围覆盖；不能把没读的代码写成 checked。
- result.termination：仅关闭该范围的正常退出或内部展开边界，包含原因及位置证据；有后续边时可以为 null。gaps 仅表示完成核实后仍不能确定的内容。
- transitions：每个具体位置的一条关系包含 condition 和 evidence，不再重复声明目标函数清单。分支/顺序关系用控制流源码证明；动态调用补全提供调用点和绑定点，不要求分支伪造两处调用证据。
- wait_for：当前范围依赖的被调用范围引用。依赖范围及其子工作闭合后才可领取。普通顺序或无结果依赖的异步注册不必等待。
- pause_requested：只表示是否换上下文。容量不足时，先保存所有未完成范围，包括当前函数中的多个分支。Agent 不得输出 resource_limit。

不能因为同一个函数已出现就跳过其他调用位置或条件。同一步允许 read 调用已完成、delete 调用未完成；二者分别记录位置/条件。复用使用 relation=reuse 指向已闭合工作，条件和 state 必须一致；不能把整个历史路径复制进 conditions。删除不再影响后续的条件时，应在当前事实中保存源码依据。

完整路径是本次分支到正常出口、公共汇合位置或可保存断点的连续分析，不是枚举所有 if 的组合。到达公共后续时，仅按仍影响后续的条件和安全状态区分分析；不要为历史条件组合复制同一段公共代码。

循环回边使用 relation=loop，仅在相关 state 与 conditions 不变时停止重复展开，并保留循环退出范围；状态变化时仍需分析变化后的行为，不能仅凭函数重复就收束。

## 调用后续和停止范围

普通同步调用在当前上下文直接跟进，证据并入当前路径结果，不必建立独立范围和等待依赖。只有需要独立展开或跨轮接续时，才显式保存调用目标及调用者返回/异常后续：transitions.relation=call 表示进入目标，return/exception 表示调用后续；依赖返回结果时后续的 wait_for 引用被调用范围。结合返回值/异常事实继续调用者，不把历史目录当作完整证据。显式回调关系使用 callback，并检查注册后继续代码。

每次提交前核对本次停止项：停在哪里、关闭哪个范围、其他分支与调用后续在哪里。以下原因需要位置证据：

- return/throw：只结束对应分支，核实 catch/finally，不删除调用者后续。
- component_boundary：只停止目标组件内部展开，记录 component_calls，继续当前调用者。
- platform_boundary/third_party_boundary：只停止深入目标内部；边界函数的可见效果仍需分析，保留调用后续。源码缺失不是平台边界。
- security_influence_ended：证明输入、身份和调用触发不再影响该范围的后续。一个参数变常量不足以作此判断。
- 无法解析写 gaps，尚未分析写 ranges.result=null，二者不属于正常停止。

组件边界由 Manifest 身份决定，继承、super、helper、HAP/HSP/HAR 源码依赖都沿实际调用继续。Native/NAPI 内部实现不在当前范围。禁止无锚点全仓扫描、仅凭名称猜测目标。

## 入口状态

JSON5 候选不是已证实入口。entry_status 描述是否存在真实组件输入（包括内部输入）；external_entry_status 描述是否有真实外部输入。confirmed 表示存在证据，excluded 表示证据排除全部对应候选，uncertain 表示证据不足。汇总顺序 confirmed > uncertain > excluded。

confirmed_external_candidate_ids 只列已确认外部候选。内部输入成立、外部输入不成立可分别为 confirmed/excluded。未发现敏感操作不能用于排除入口。后续源码改变判断时，在同一个 entry_assessment 中提交完整更新和位置证据，保留其他候选结论。audit_scope.entry_types 只提示优先方向，不排除组件。

全部已登记范围闭合才生成最终语义结果。record 成功不等于函数完成，队列暂空也不等于调用后续已闭合。脚本只能保障已登记范围连续性，不能证明模型枚举了所有源码分支。

## 控制与身份状态

这些值描述源码事实，不预先判定漏洞或防护有效性；`unknown` 始终表示证据不足，不表示否定结论。

| 字段 | 取值标准 |
|---|---|
| 属性 `control_state` | 按顺序选择：已证明不受输入影响为 `constant`；否则，已证明存在针对安全相关取值的显式限制为 `constrained`；否则，已证明保留控制且未引入该类限制为 `preserved`；证据不足为 `unknown`。复制和可逆转换不重置已有约束；类型本身固有的范围不算新增限制。受限制不等于安全 |
| 调用 `invocation_control.control_state` | 按顺序选择：已证明调用发生独立于输入为 `independent`；否则，受控调用有明确限制条件为 `constrained`；否则，已证明输入可以控制调用发生为 `preserved`；证据不足为 `unknown`。参数为常量不代表调用不受控 |
| `origin_binding` | 按顺序选择：原始身份可验证地获得为 `preserved`；否则，只能可靠获得直接调用方身份为 `replaced_by_caller`；否则，已证明通信机制不可靠暴露这两种身份为 `not_observable`；尚未查明为 `unknown`。原始身份不可见但中间组件身份可见时，唯一选择是 `replaced_by_caller` |
| `principal.authority` / `principal_transition.authority_used` | `origin`：实际使用原始发起者权限；`source_component`：实际使用当前中介组件权限；`system`：实际以系统权限执行；`none`：已证明不涉及相关权限；`unknown`：尚不能确定。调用系统 API 不等于使用系统权限 |
| 安全检查 `subject_kind` | 按被检查值的实际来源选择：调用方身份 API 为 `immediate_caller`，即使直接调用方恰好也是原始发起者；独立认证或可信溯源的原始身份为 `origin_principal`；普通传入属性或未验证自报身份为 `transferred_property`；资源归属为 `resource_owner`；其他边界策略为 `security_boundary`；证据不足为 `unknown`。不因主体碰巧相同而更换标签 |

`ranges[].state.security_checks` 只保存经过的检查引用，每项包含 `location`、`subject_kind`、`validated_property`。位置和校验属性使用源码中可定位的路径及表达式，不另造检查 ID。继承检查原样取自 `work.state`；新增检查必须在本步骤某个 `result.security_checks`、操作组或组件调用中有完整描述和证据。脚本据这三个源码属性生成稳定身份并去重，描述措辞变化不产生新状态。不再生效的检查不传给后继状态。

## 语义输出

所有报告描述使用中文；源码符号、路径、API、参数名和必要原文保持原样。每个 result 中的 `operation_groups` 和 `component_calls` 必须符合 `semantic_schema_file` 中对应定义，运行时会立即按完整最终契约校验。

只记录源码直接支持的事实：

- 参数名、函数名、类型名、注释和业务词义只能形成 `effect_hypotheses`，并列出 `missing_proofs`。
- `direct_observed_effect` 只能填写代码直接可见效果，不能证明时为 `null`。
- 安全检查只描述类型、位置、保护对象、校验属性、约束主体和行为，不判断其是否有效。
- 每个操作组保存入口到操作的必要事实链；不得省略会改变可达性、控制性、防护支配关系、身份、安全边界或影响结论的事实。
- 等价操作由运行时跨节点归并。安全检查集合、检查对象、受控属性、主体或直接效果不同，必须分别输出。
- `CAP-DOS-001` 仍使用普通操作组，但必须填写 `availability` 中的资源/失败、攻击者影响、上限或放大、异常隔离、重复触发、影响范围和恢复事实。

只有通过组件通信机制进入 `project_model.components` 中另一个 Manifest 组件，才输出 `component_calls`。import、依赖调用、继承、组合对象、普通函数和 `super` 都不是组件跳转。组件调用必须记录：

- `invocation_control`：当前组件输入是否控制调用发生；
- 真实 `parameter_mappings`，没有参数映射时可为空；
- transport、调用位置、条件和沿途安全检查；
- `principal_transition`：发起者、下游观察主体、原始身份是否保留及实际使用权限。

证据直接写入所证明对象的 `evidence`，不要创建证据 ID、`evidence_refs` 或顶层证据目录。禁止输出漏洞分类、风险等级、CWE、可利用性或 PoC。
