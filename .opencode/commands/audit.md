---
description: 对 HarmonyOS ArkTS 项目执行入口驱动的白盒安全审计
agent: harmony-auditor
---

审计参数：`$ARGUMENTS`

语法：

- `/audit <repo-path>`：全量审计。
- `/audit --capability <CAP-ID> <repo-path>`：只启用指定能力画像，仍使用同一证据流架构。
- `/audit --component <AbilityName> <repo-path>`：只审计指定 Ability 或 ExtensionAbility。
- `/audit --component <module/AbilityName> <repo-path>`：使用模块限定名消除同名组件歧义。

`--component` 与 `--capability` 均可重复并可组合。组件过滤在 Entry Planning 前确定性执行，不匹配的组件不创建审计任务。

为本次审计创建隔离 run，完成项目建模与 Atlas 索引，依次推进 Entry Planning、Flow Analysis、Pattern Evaluation 和 Flow Validation；确定性准入通过后生成 Markdown 与 HTML 报告。
