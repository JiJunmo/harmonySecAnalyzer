# 通用助手子 Agent

状态：已实现  
完成日期：2026-08-03

## 上游复用边界

Pi Coding Agent 明确不内置 SubAgent，但提供 SDK Session 和 Extension 扩展点。本项目不实现新的 Agent 循环：每个子 Agent 都是通过 `PiSessionFactory` 创建的 `workflow-worker` 内存 Session，复用 Pi 的模型、消息循环、工具调用、事件和 Abort。

平台只增加领域无关的生命周期外壳：

- 主助手通过 `delegate_task` 委派一个完整、独立的任务；
- 子 Agent 使用隔离上下文，不写入普通助手的 Pi JSONL 会话历史；
- 状态为 `queued / running / succeeded / failed / aborted`；
- `maxConcurrent` 控制通用并发容量，默认 4；
- 已完成记录只保留在当前进程内，默认最多 100 条；
- Web 可以查看状态、结果和取消排队或运行中的任务。

## 能力继承

子 Agent 默认获得 `read`、`bash`，可在 `agent-platform.json` 的 `subagents.tools` 中调整。它在开始执行时继承当时启用的全局 MCP 工具和 Pi Skills，并可通过 `subagents.model` 选择一个已经在 Pi `models.json` 中声明的模型别名。Provider、Base URL 和密钥不会在子 Agent 配置中重复声明。

## 过程可观测性

通用 `SubagentRuntime` 订阅每个隔离 Pi Session 的事件，记录排队/启动/终止状态、provider 可见的 assistant 文本与 thinking 内容，以及工具调用的名称、参数、结果和错误。Trace 在进入内存前统一脱敏并限制字符串、数组、嵌套深度和单任务事件数；它不尝试读取或展示模型不可见的内部推理状态。

运行列表接口只返回轻量摘要，单任务详情接口返回完整 Trace。Web 的“子 Agent”工作区采用任务列表与过程时间线双栏展示，运行中任务通过轮询持续更新，且可从列表或详情中观察其执行进度。

能力与普通会话一样采用创建时快照。任务开始后切换 MCP、Skill 或模型配置，不会改变正在运行的子 Agent。

## 与多 Agent 插件的边界

`delegate_task` 是普通助手的一次性通用委派，不是领域工作流引擎。LangGraph 插件继续完整拥有自己的图拓扑、Agent 分工、checkpoint、interrupt/resume、重试和领域状态机。Harmony 插件的五槽池也不使用这里的默认并发值。

当前版本不持久化通用子 Agent 队列；服务重启会终止未完成任务。需要跨进程恢复的长期工作应实现为版本化 LangGraph 插件 Run。
