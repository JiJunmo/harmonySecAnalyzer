---
description: 对 HarmonyOS ArkTS 项目执行入口驱动的白盒安全审计
agent: harmony-auditor
---

审计参数：`$ARGUMENTS`

语法：

- `/audit <repo-path>`：全量审计。
- `/audit --capability <CAP-ID> <repo-path>`：只分析适用指定能力的入口，仍使用同一证据流架构。
- `/audit --component <AbilityName> <repo-path>`：只审计指定 Ability 或 ExtensionAbility。
- `/audit --component <module/AbilityName> <repo-path>`：使用模块限定名消除同名组件歧义。

`--component` 与 `--capability` 均可重复并可组合。组件过滤在 Entry Resolution 前确定性执行；能力过滤在 Entry Resolution 确认入口类型后执行。不在目标范围内的入口不创建路径发现任务。

为本次审计创建隔离 run，先完成“审计准备与入口建模”：解析项目配置、建立 Atlas 索引并执行 Entry Resolution；随后发现局部 Flow、组装完整 Path，并对每条 Path 执行一次包含强制六维有效性验证的 Security Assessment，确定性根因归并和准入通过后生成 Markdown 与 HTML 报告。
