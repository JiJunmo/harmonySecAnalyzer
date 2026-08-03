# Web API v1

Server 同时承载两类彼此独立的资源：普通助手 Session 与插件 Run。所有 API 响应均为 JSON，SSE 和 Artifact 内容除外。配置 `AGENT_PLATFORM_WEB_TOKEN` 后，`/api/*` 使用 `Authorization: Bearer <token>`；EventSource 可使用同源 `?token=`。

## 通用助手

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/assistant` | 可选模型、默认模型和全局 MCP 能力 |
| GET | `/api/assistant/capabilities` | Skills、Extensions、Packages 和 MCP 的加载状态 |
| POST | `/api/assistant/capabilities` | 启用或停用一个已配置能力 |
| GET | `/api/assistant/subagents` | 子 Agent 轻量运行列表，可按 `parentSessionId` 过滤，不返回过程 Trace |
| GET | `/api/assistant/subagents/:id` | 子 Agent 状态、结果和完整可见过程 Trace（模型消息、工具调用及生命周期） |
| POST | `/api/assistant/subagents/:id/actions/abort` | 取消排队或运行中的子 Agent |
| GET | `/api/reliability` | 本地网关状态库、日志、记录数量和保留策略诊断 |
| POST | `/api/reliability/actions/prune` | 立即按保留期和数量上限清理终态平台索引/Trace；不删除插件报告 |
| GET | `/api/assistant/sessions` | 当前进程的对话列表 |
| POST | `/api/assistant/sessions` | 创建对话，可指定模型别名 |
| GET | `/api/assistant/sessions/:id` | 对话快照和消息 |
| DELETE | `/api/assistant/sessions/:id` | 中止并删除对话 |
| POST | `/api/assistant/sessions/:id/messages` | 异步发送用户消息，返回 `202` |
| POST | `/api/assistant/sessions/:id/actions/abort` | 中止当前生成 |
| POST | `/api/assistant/sessions/:id/actions/rename` | 写入 Pi `session_info` 并重命名对话 |
| GET | `/api/assistant/sessions/:id/events` | SSE 会话快照和增量更新 |

## 插件宿主

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/plugins` | 已安装插件 Manifest |
| GET | `/api/web-contributions` | 插件 Web 页面贡献 |
| POST | `/api/plugins/:id/operations/:name` | 调用插件 Operation |
| GET/POST | `/api/runs` | 列出或创建插件 Run |
| POST | `/api/runs/adopt` | 导入插件已有 Run |
| GET | `/api/runs/:id` | Run 快照 |
| GET | `/api/runs/:id/executions` | 插件 Run 的 Agent 执行单元；未贡献时为空 |
| GET | `/api/runs/:id/executions/:executionId` | 单个执行单元的输入、尝试和 Trace 时间线 |
| GET | `/api/runs/:id/events` | Host 与 Plugin SSE 事件 |
| POST | `/api/runs/:id/actions/:name` | 调用插件 Run Action |
| GET | `/api/runs/:id/artifacts` | Artifact 描述符 |
| GET | `/api/runs/:id/artifacts/:artifactId` | Artifact 内容 |

## 安全边界

- 请求体最大 1 MiB；
- 服务默认只监听 `127.0.0.1`；
- Assistant 工作目录由服务配置固定，Web 请求不能任意指定文件系统路径；
- API Key 只从 Provider 声明的环境变量读取；
- Web 层不直接调用模型、MCP、Atlas 或插件数据库；
- 子 Agent 的工作目录由服务固定，API 不接受任意目录或直接创建任务；任务只能由助手的 `delegate_task` 工具产生；
- 插件自己校验其 Run Payload、允许路径和 Artifact 权限。
- Agent Trace 只保存 Provider 实际返回的可见消息和工具活动；通用层在持久化前执行敏感字段脱敏与有界截断。
