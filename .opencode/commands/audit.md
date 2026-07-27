---
description: 对 HarmonyOS ArkTS 项目执行组件驱动的白盒安全审计
agent: harmony-auditor
---

审计参数：`$ARGUMENTS`

语法：

- `/audit <repo-path>`：全量审计。
- `/audit --capability <CAP-ID> <repo-path>`：只分析适用指定能力的入口，仍使用同一证据流架构。
- `/audit --component <AbilityName> <repo-path>`：只审计指定 Ability 或 ExtensionAbility。
- `/audit --component <module/AbilityName> <repo-path>`：使用模块限定名消除同名组件歧义。
- `/audit --component <MOD-id/AbilityName> <repo-path>`：模块同名时使用稳定模块 ID 精确选择。

`--component` 与 `--capability` 均可重复并可组合。过滤条件决定审计的起始组件；起始组件语义结果证明可控参数进入下游组件时，运行时会为该下游组件补充一个语义任务，但不会把它当成新的外部根入口。简称匹配到多个组件时会明确报错并返回可选的 `MOD-id/组件名`，不会默认审计多个同名组件。

为本次审计创建隔离 run，解析项目配置、建立 Atlas 索引并确定性生成组件分析单元。每个组件只执行一次语义分析，落盘组件内操作和跨组件参数传递；全部组件结束后由脚本连接外部入口与敏感操作，再创建六维验证任务。确定性根因归并和准入通过后生成 Markdown 与 HTML 报告。
