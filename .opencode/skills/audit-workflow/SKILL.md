---
name: audit-workflow
description: 以外部组件为任务单位、以实际敏感操作组为判断单位的审计语义。
---

## 工作流

`项目事实 -> 组件语义分析 -> 语义事实落盘 -> 六维验证 -> Root Cause Finding`

一个 Ability/ExtensionAbility 先派发一个语义任务。Agent 使用 Atlas 确认真实入口并追踪实际可达的安全相关操作，不做漏洞判断。多个普通分支到达同一操作且关键受控参数相同时合并为一个 Operation Group；防护代码只作为客观事实记录。

每组按调用顺序使用必要的 `entrypoint/reachability/control/transform/guard/operation/effect/dead_end/gap` Fact 保存最短证据链；类型按实际证据选用，不要求每种都存在。Edge 由运行时根据 Fact 顺序确定性生成。

## 可利用性

语义结果落盘后，一个独立验证任务以这些结果为范围，对每个操作组检查反证并记录业务意图、安全边界、Guard 结论和六维判断。它可以读取语义证据引用的源码并使用 Atlas 定点核实，但不能全仓搜索、新增操作组或改写已落盘语义事实。

只有 `confirmed_vulnerability` 要求六项全部为 true。有效 Guard 为 `protected_exposure`；正常公开业务且未越界为 `benign_business_flow`；可疑但缺关键证据为 `residual_risk`；无法判断为 `insufficient_evidence`。

根因身份由操作位置、关键受控参数和安全边界组成。普通分支、入口别名、能力 ID、模式 ID 不参与根因身份。路径只为 confirmed vulnerability 和 residual risk 生成，作为报告证据，不作为调度对象。

## Atlas 使用

从分配的 Entry 出发，使用 `search/symbol/explore/calls/path/trace/impact` 有界追踪。允许在同一任务内穿过公共 handler、异步回调和跨组件调用。Atlas 无法证明的目标记录到 `coverage.unresolved_targets`，不得用逐文件扫描补造证据。NAPI/native 不在当前范围。
