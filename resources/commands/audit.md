审计参数：`$ARGUMENTS`

语法：

- `/audit <repo-path>`：全量审计。
- `/audit --incremental <repo-path>`：以上次成功全量或增量审计为基线，只重新分析受影响组件。
- `/audit --resume <run-dir>`：重新打开存在 exhausted 任务的已完成运行，只重试失败任务并重建报告。
- `/audit --capability <CAP-ID> <repo-path>`：在全部组件中定点分析指定能力，仍使用同一证据流架构。
- `/audit --component <AbilityName> <repo-path>`：只审计指定 Ability 或 ExtensionAbility。
- `/audit --component <module/AbilityName> <repo-path>`：使用模块限定名消除同名组件歧义。
- `/audit --component <MOD-id/AbilityName> <repo-path>`：模块同名时使用稳定模块 ID 精确选择。

`--component` 与 `--capability` 均可重复并可组合。`--component` 决定起始组件；单独使用 `--capability` 时，组件级能力会初始化全部 Manifest 组件，能力表的 `entry_types` 仅提示常见入口，不排除其他组件。组件过滤下，语义结果证明调用触发或参数控制进入下游组件时，运行时会补充该下游组件任务，但不会把它当成新的外部根入口。简称匹配到多个组件时会明确报错并返回可选的 `MOD-id/组件名`，不会默认审计多个同名组件。

项目建模不创建独立的 CommonEvent 子任务。全量模式继续分析全部 Ability/ExtensionAbility；指定组件使用现有 `--component` 参数，不增加 CommonEvent 专属调度分支。

`--incremental` 不与 `--component` 或 `--capability` 组合。首次必须先成功执行一次无过滤的全量审计以建立基线。Git 项目记录上次成功审计提交到当前提交的累计变化，并纳入当前工作区内容；非 Git 项目使用文件内容哈希快照。基线不是当前 Git 分支祖先时要求重新全量审计。

`--resume` 的参数是具体 run 目录，不是项目目录，且不与其他模式组合。恢复时保留所有已完成结果，只重新排队 exhausted 任务；全部补齐后覆盖生成该 run 的最终报告并按原审计模式更新基线。

为本次审计创建隔离 run，解析项目配置、建立 Atlas 索引并确定性生成组件探索单元。每个组件只有一个持久语义任务记录，但可按上下文容量连续派发多轮短任务；Agent 使用 Atlas 按安全语义断点分段探索，优先走完当前路径，短路径闭合后可在同一轮继续下一条。长路径或多条短路径累计达到函数保护值时，运行时保存已有证据和后续断点，下一轮换新上下文续跑。全部分支闭合或形成明确覆盖缺口后，脚本生成最终组件语义结果，再进行组件连接、六维验证、根因归并和 Markdown/HTML 报告生成。

{{command_dispatch}}
