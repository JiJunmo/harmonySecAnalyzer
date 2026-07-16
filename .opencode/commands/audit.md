---
description: 启动鸿蒙 ArkTS 白盒安全审计
agent: harmony-auditor
subtask: false
---
对 $2 执行「$1」范围的安全审计。

scope 取值：
- full：全量（默认）
- quick：仅 manifest + 硬编码 + 网络明文（快速过一遍）
- manifest：仅 module.json5/app.json5 配置审计
- injection / crypto / network / icc / web / napi / dep：单领域深审（P2/P3 起支持）

若 $2 未提供，询问用户目标仓绝对路径。若 $1 未提供，默认 full。

按 audit-workflow skill 执行：先确定性项目建模，再 `atlas_project open`，然后攻击面测绘 → 流式路径发现与验证 → 报告准入 → 分层报告，最终写入 `reports/` 目录。
