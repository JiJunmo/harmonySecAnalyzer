---
name: audit-workflow
description: 入口驱动证据 Path 的分析语义、闭合与验证规则。
---

## 工作流

`项目事实 -> Canonical Entry -> 局部 Flow/Continuation -> 完整 Path -> Security Assessment -> Root Cause Finding`

Canonical Entry 包含会改变安全语义的 dispatcher discriminator。Flow 是单次分析产生的局部证据段，使用带 Evidence 的 Fact 和 Edge 证明可达性、控制传播、Guard、目标操作和影响。运行时沿 continuation 连接 Flow 并组装完整 Path；Security Assessment 只消费闭合 Path 中已经建立的事实，模式卡是知识和判断尺度，不是逐张填写的检查表。

Fact 类型：`entrypoint/reachability/control/transform/guard/operation/effect/dead_end/gap`。

Continuation 类型：`component_dispatch/callback_dispatch/shared_handler/async_resume/unknown_target`。它是必须闭合的结构化边，不是备注。

Flow 结构状态：

- `reached`：本段到达 operation 或 effect。
- `stopped`：代码路径在本段明确终止。
- `gap`：完成有界查询后仍缺关键证据。
- `open`：存在后续 continuation，必须继续追踪。

探索层不能判断 Guard 是否有效、业务是否正常或是否存在漏洞。`reached/stopped/gap` Flow 会被运行时组装为 Path，安全判定和报告只处理 Path。

## 可利用性

每个安全场景先执行反证审查，结构化记录业务意图、安全边界、Guard 和反证，再逐一验证六维：外部可达、关键参数可控、到达敏感操作、Guard 缺失或可绕过、安全边界违反、具体安全影响。`confirmed_vulnerability` 要求六项全部为 true 且没有有效反证；有效 Guard 为 `protected_exposure`；正常公开业务且未越界为 `benign_business_flow`；可疑但缺少关键成立证据为 `residual_risk`，无法判断为 `insufficient_evidence`。

根因身份只由归一化 operation location、branch、boundary、controlled property 组成。入口别名、能力 ID、模式 ID 和相邻调用点不参与根因身份。

## Atlas 使用

从分配的 Entry 或 continuation 出发，优先 `search/symbol/explore/calls/path/trace`。查询应围绕具体符号和受控属性有界扩展。Atlas 无法证明的框架边界应记录 gap，不得用逐文件扫描补造证据。NAPI/native 不在当前范围。
