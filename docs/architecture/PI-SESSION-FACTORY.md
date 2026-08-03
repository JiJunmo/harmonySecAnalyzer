# 通用 Pi Session Factory

状态：已实现  
完成日期：2026-08-03  
实现位置：[`packages/core/src/pi-session.ts`](../../packages/core/src/pi-session.ts)

## 1. 目标

`PiSessionFactory` 是通用 AI 助手和 LangGraph 插件 Worker 共用的 Pi Coding Agent 生产适配层。平台不再维护自己的模型—工具消息循环。

它提供两种配置档：

| 配置档 | 用途 | 默认行为 |
|---|---|---|
| `interactive` | 通用助手对话 | Pi 默认 coding tools、Compaction、Retry、Steering、Follow-up；调用方可加入全局 MCP/Tool/Skill |
| `workflow-worker` | LangGraph 节点中的 Agent | 内存 Session、关闭 Compaction、不隐式启用内置工具；插件传入的 MCP/Tool 可以全部启用或显式缩小 |

Atlas、HarmonyOS 任务类型和五槽策略没有进入 Factory。

## 2. ModelRuntime

生产路径直接通过 Pi `ModelRuntime` 和 `SettingsManager` 读取官方配置：

- `models.json` 声明 Provider、模型和 `$ENV_VAR` 凭据引用；
- `settings.json` 声明默认 Provider/Model、Session、Retry、Compaction 与 Skills；
- `auth.json` 由 Pi 官方凭据存储读取；
- 模型选择使用 Pi 的 `provider/model-id` 引用；
- 远程模型目录刷新默认关闭。

旧里程碑配置仅保留在内部兼容测试路径，Server、CLI 和 Harmony 生产路径均不再读取它。

## 3. Session 合同

平台公开领域无关的 `PlatformAgentSession`：

```text
prompt / steer / followUp / abort / subscribe / dispose
```

并提供 Session ID、消息、流式状态、激活工具和可选 Session 文件。交互 Session 只有在调用方传入平台拥有的 `sessionDirectory` 时才持久化；插件 Worker 始终使用内存 Session，领域恢复继续由插件数据库和 LangGraph checkpoint 负责。

## 4. 结构化 Worker

`runStructured()` 在 `workflow-worker` 上增加一个 terminating submission tool，并用 Ajv 校验提交 Schema。插件提供：

- System Prompt；
- Task 文档；
- Task Kind/模型别名；
- 当前 Worker 使用的 MCP/Tool；
- 输出 Schema 和提交工具名。

Factory 不决定插件允许哪些 MCP。Harmony 插件当前传入 Atlas MCP 工具；其他插件可以传入完全不同的工具，通用助手可以传入全局启用的全部 MCP。

## 5. 当前接入状态

- 独立通用交互 Session 已运行通过；
- Harmony LangGraph Worker 已从旧 `PiAgentRuntime` 切换到 `PiSessionFactory.runStructured()`；
- 旧的自研 Agent 循环已删除；
- 下一步是建立 Assistant Session Service/API/Web 对话，而不是继续修改 Harmony 审计编排。
