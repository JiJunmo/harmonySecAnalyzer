# 通用 Agent Execution Trace

状态：已实现  
实现日期：2026-08-03

## 边界

Agent Trace 是通用助手骨架能力。Core 只记录可观察的执行事实，不理解 HarmonyOS、路径发现、六维验证、Finding 或 Atlas。插件把自己的领域任务映射为 `Execution Unit`，并自行选择持久化方式。

```text
Plugin Run
  └─ Execution Unit
       └─ Attempt
            └─ Trace Event
```

Core 标准事件包括 Agent 开始/完成/失败、Provider 实际返回的文本或 thinking 摘要、工具调用开始/完成，以及结构化提交开始/接受/拒绝。它不生成、推断或暴露模型不可见的隐藏思维链。

工具参数、工具结果和模型消息在进入 Trace Sink 前执行递归脱敏、字符串截断、数组限长、深度限制和循环引用保护。API Key、Authorization、Token、Password、Secret 和 Credential 字段不会写入轨迹。

## Plugin Contract

插件可以选择实现：

- `executions(run)`：列出 Run 下的执行单元；
- `execution(run, executionId)`：返回输入、结果、尝试和事件时间线。

这是可选合同。未接入 Trace 的旧插件仍然合法，Host 对其返回空执行列表。

通用 HTTP API：

- `GET /api/runs/:id/executions`
- `GET /api/runs/:id/executions/:executionId`

## Harmony 首个适配

Harmony 插件把 `component_semantic_analysis` 和 `exploitability_validation` 任务映射为执行单元。Trace 直接写入该 Run 的 `run.db.events`，因此与 Run 一起归档、恢复，不引入平台数据库，也不改变 `run.db v2` Schema。

Harmony 工作台提供完整任务列表、五槽任务快捷入口和任务详情时间线。旧 Run 可以查看任务输入、状态和最终错误；完整工具与模型轨迹只对升级后执行的新 Attempt 可用。
