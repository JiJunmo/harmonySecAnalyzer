---
name: audit-workflow
description: 入口驱动证据 Flow 的分析语义、终态与验证规则。
---

## 工作流

`项目事实 -> Canonical Entry -> Flow/Continuation -> Pattern Hypothesis -> Exploitability Validation -> Root Cause Finding`

Canonical Entry 包含会改变安全语义的 dispatcher discriminator。Flow 使用带 Evidence 的 Fact 和 Edge 证明可达性、控制传播、Guard、目标操作和影响；模式评估只消费 Flow 中已经建立的事实。

Fact 类型：`entrypoint/reachability/control/transform/guard/operation/effect/dead_end/gap`。

Continuation 类型：`component_dispatch/callback_dispatch/shared_handler/async_resume/unknown_target`。它是必须闭合的结构化边，不是备注。

Flow 终态：

- `connected`：受控值到达操作并产生可观察 effect。
- `blocked`：相关 Guard 在操作前有效阻断。
- `benign`：公开业务行为被限制在允许对象和边界内。
- `gap`：完成有界查询后仍缺关键证据。
- `open`：存在后续 continuation，不是报告终态。

## 可利用性

`confirmed_vulnerability` 必须同时证明：外部可达、关键属性可控、操作到达、Guard 缺失或可绕过、安全边界违反、可观察影响。有效 Guard 为 `protected_exposure`；正常公开业务为 `benign_business_flow`；缺证据为 `insufficient_evidence` 或 `residual_risk`。

根因身份只由归一化 operation location、branch、boundary、controlled property 组成。入口别名、能力 ID、模式 ID 和相邻调用点不参与根因身份。

## Atlas 使用

从分配的 Entry 或 continuation 出发，优先 `search/symbol/explore/calls/path/trace`。查询应围绕具体符号和受控属性有界扩展。Atlas 无法证明的框架边界应记录 gap，不得用逐文件扫描补造证据。NAPI/native 不在当前范围。
