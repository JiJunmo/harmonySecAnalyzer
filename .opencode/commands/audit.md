---
description: 启动鸿蒙 ArkTS 白盒安全审计
agent: harmony-auditor
subtask: false
---
对 $2 执行「$1」范围的安全审计。

scope 用作本次运行的审计焦点和目录标签；省略时为 `full`。实际启用的漏洞能力与路由以
`audit-orchestration` Skill 的能力注册表为准，不得因 scope 名称假定尚未注册的能力。

若 $2 未提供，询问用户目标仓绝对路径。若 $1 未提供，默认 full。

按 audit-workflow skill 执行：先确定性项目建模，再 `atlas_project open`，然后攻击面测绘 → 流式路径发现与验证 → 报告准入 → 分层报告，最终写入 `reports/` 目录。
