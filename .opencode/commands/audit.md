---
description: 对 HarmonyOS ArkTS 项目执行组件驱动的白盒安全审计
agent: harmony-auditor
---

审计参数：`$ARGUMENTS`

语法：

- `/audit <repo-path>`：全量审计。
- `/audit --incremental <repo-path>`：以上次成功全量或增量审计为基线，只重新分析受影响组件。
- `/audit --resume <run-dir>`：重新打开存在 exhausted 任务的已完成运行，只重试失败任务并重建报告。
- `/audit --capability <CAP-ID> <repo-path>`：只分析适用指定能力的入口，仍使用同一证据流架构。
- `/audit --component <AbilityName> <repo-path>`：只审计指定 Ability 或 ExtensionAbility。
- `/audit --component <module/AbilityName> <repo-path>`：使用模块限定名消除同名组件歧义。
- `/audit --component <MOD-id/AbilityName> <repo-path>`：模块同名时使用稳定模块 ID 精确选择。

`--component` 与 `--capability` 均可重复并可组合。过滤条件决定审计的起始组件；起始组件语义结果证明可控参数进入下游组件时，运行时会为该下游组件补充一个语义任务，但不会把它当成新的外部根入口。简称匹配到多个组件时会明确报错并返回可选的 `MOD-id/组件名`，不会默认审计多个同名组件。

`--incremental` 不与 `--component` 或 `--capability` 组合。首次必须先成功执行一次无过滤的全量审计以建立基线。Git 项目记录上次成功审计提交到当前提交的累计变化，并纳入当前工作区内容；非 Git 项目使用文件内容哈希快照。基线不是当前 Git 分支祖先时要求重新全量审计。

`--resume` 的参数是具体 run 目录，不是项目目录，且不与其他模式组合。恢复时保留所有已完成结果，只重新排队 exhausted 任务；全部补齐后覆盖生成该 run 的最终报告并按原审计模式更新基线。

为本次审计创建隔离 run，解析项目配置、建立 Atlas 索引并确定性生成组件分析单元。每个组件只执行一次语义分析，落盘组件内操作和跨组件参数传递；全部组件结束后由脚本连接外部入口与敏感操作，再创建六维验证任务。确定性根因归并和准入通过后生成 Markdown 与 HTML 报告。
