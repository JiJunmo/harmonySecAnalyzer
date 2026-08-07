---
name: audit-workflow
description: 以组件为任务单位、以实际敏感操作组为判断单位的审计语义。当需要确认组件语义分析、跨组件连接、六维验证、根因归并与 Atlas 有界追踪的执行边界时使用。
---

## 工作流

`项目事实 -> 组件语义分析 -> 确定性组件连接 -> 六维验证 -> Root Cause Finding`

一个 Ability/ExtensionAbility 只派发一个语义任务。Agent 使用 Atlas 确认组件输入并追踪组件内实际可达的安全相关操作，不做漏洞判断。到达另一个组件时停止，记录目标组件、调用位置和参数控制性映射。多个普通分支到达同一操作且关键受控参数相同时合并为一个 Operation Group；防护代码只作为客观事实记录。

每组按调用顺序使用必要的 `entrypoint/reachability/control/transform/security_check/operation/effect/dead_end/gap` 类型保存最短证据链；类型按实际证据选用，不要求每种都存在。节点之间的相邻关系由运行时根据顺序确定性生成。

## 可利用性

全部语义结果落盘后，脚本从已确认的外部入口连接组件参数映射以及身份、权限变化，只把外部可达的本地操作和成功连接的跨组件操作交给独立验证任务。未导出组件可以作为下游节点，但不能作为外部根入口。验证任务对每个操作组检查反证并记录业务意图、安全边界、安全检查 结论和六维判断；跨组件组还必须判断下游校验约束的是原始主体还是仅约束了被借权的中间组件。它可以读取语义证据引用的源码并使用 Atlas 定点核实，但不能重新发现路径、新增操作组或改写已落盘语义事实。

只有 `confirmed_vulnerability` 要求六项全部为 true。有效 安全检查 为 `protected_exposure`；正常公开业务且未越界为 `benign_business_flow`；可疑但缺关键证据为 `residual_risk`；无法判断为 `insufficient_evidence`。

根因身份由操作位置、关键受控参数和安全边界组成。普通分支、入口别名和能力 ID 不参与根因身份。路径只为 confirmed vulnerability 和 residual risk 生成，作为报告证据，不作为调度对象。

## Atlas 使用

从分配的组件输入出发，使用 `search/symbol/explore/calls/path/trace/impact` 有界追踪（Claude Code 下为 `mcp__atlas__search` 等工具）。允许穿过组件内公共 handler 和异步回调；调用进入另一个 Ability/ExtensionAbility 时记录 `component_calls` 并停止，同时记录下游观察身份、原始身份绑定状态和实际使用的权限。Atlas 无法证明的目标记录到 `coverage.unresolved_targets`，不得用逐文件扫描补造证据。NAPI/native 不在当前范围。
