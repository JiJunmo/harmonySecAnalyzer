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

`--component` 与 `--capability` 均可重复并可组合。组件和能力过滤都在脚本生成分析单元时确定性执行。不在目标范围内的组件不创建语义分析任务。

为本次审计创建隔离 run，解析项目配置、建立 Atlas 索引并确定性生成组件分析单元。每个组件先执行语义分析并落盘源码事实；存在安全相关操作时，再创建只读取语义结果的六维验证任务。确定性根因归并和准入通过后生成 Markdown 与 HTML 报告。
