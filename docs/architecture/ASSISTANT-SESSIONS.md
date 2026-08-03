# 通用助手会话服务

状态：主链路已实现  
完成日期：2026-08-03

## 定位

`AssistantSessionService` 是通用助手的 Application Service。它直接使用 `PiSessionFactory` 的 `interactive` 配置档，与 `PluginHostService` 并列，不把普通对话建模为插件 Run。

```text
Web Chat
  -> /api/assistant/sessions
  -> AssistantSessionService
  -> PiSessionFactory(interactive)
  -> Pi AgentSession
       + Pi built-in tools
       + global MCP tools
       + configured Skills
       + selected model

Plugin Workspace
  -> /api/runs
  -> PluginHostService
  -> installed LangGraph plugin
```

## 已实现合同

- 创建、列出、读取和删除会话；
- 启动时通过 Pi `SessionManager.list/open` 恢复 `sessionDir` 中的历史 JSONL；
- 恢复原会话模型、消息树和上下文，并可继续对话；
- 使用 Pi `session_info` 持久化会话名称；删除时同步删除对应 JSONL；
- 异步发送 Prompt，使用 SSE 接收消息和工具执行期间的会话快照；
- 中止正在运行的模型调用；
- 默认模型与会话级模型选择；
- Pi 默认 coding tools；
- 启动时连接全局配置的 MCP Server，并把所有不重名工具注入普通助手；
- 将全局 Skill 根目录传给 Pi Resource Loader；
- Server 可以在没有任何领域插件时启动。

会话 API 和插件 Run API 是两套并列资源。插件可以使用同一个 `PiSessionFactory` 创建隔离 Worker，但无权改变普通助手的全局工具策略。

## 配置

普通助手直接读取 Pi 官方配置目录：`settings.json` 负责默认模型、Session、Retry、Compaction、Skills、Extensions 和 Packages，`models.json` 负责 Provider 与模型，`auth.json` 负责可选持久凭据。平台通过 `AGENT_PLATFORM_PI_DIR` 指向该目录。Pi 本身没有 MCP 和 SubAgent，因此 MCP Server 与领域无关的子 Agent 并发/工具策略放在独立的 `agent-platform.json` 中；子 Agent 模型仍只引用 Pi 模型别名。

Web 历史列表以 Pi Session JSONL 为唯一事实源，不维护平行数据库。后续还包括会话归档、附件输入、MCP/Skill 管理页面及通用子 Agent 入口。
