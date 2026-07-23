---
name: attack-patterns
description: 为闭合证据 Path 的安全判定提供 HarmonyOS 专有漏洞语义与有效反证。
---

模式卡由 Security Assessor 按当前审计能力范围加载。它描述该类问题需要的 source/control/operation/effect、相关安全边界、有效 Guard、正常业务反证和证据缺口。

模式卡不能生成任务，不能把 API 命中视为路径，也不能覆盖 Path 中不存在的事实。Security Assessor 先理解完整 Path 的实际行为，只识别真正适用的安全场景，再对每个场景执行六维漏洞有效性验证；无关模式不需要逐张输出。

新增模式应保持差异化，只写平台或漏洞类型特有语义。通用 Path 结构、六维验证、根因聚合和结果 Schema 属于 `audit-workflow` 与 `audit-orchestration`，不得在每张卡重复实现。
