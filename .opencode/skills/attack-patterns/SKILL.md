---
name: attack-patterns
description: 在闭合证据 Flow 上评估漏洞假设与有效反证的领域模式卡。
---

模式卡只由 Flow Pattern Evaluator 和 Flow Validator 按 capability profile 加载。它描述该类问题需要的 source/control/operation/effect、相关安全边界、有效 Guard、正常业务反证和证据缺口。

模式卡不能生成任务，不能把 API 命中视为路径，不能覆盖 Flow 中不存在的事实。Evaluator 先对每个能力给出 `supported/refuted/not_applicable/evidence_gap`；Validator 再基于六门槛给出最终分类。

新增模式应保持差异化，只写平台或漏洞类型特有语义。通用 Flow、六门槛、根因聚合和结果 Schema 属于 `audit-workflow` 与 `audit-orchestration`，不得在每张卡重复实现。
