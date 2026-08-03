# 统一模型配置

状态：已实现  
完成日期：2026-07-31

模型配置已改为直接使用 Pi 官方文件：

1. `pi-agent/models.json`：Provider、模型目录和 `$ENV_VAR` 凭据引用；
2. `pi-agent/settings.json`：`defaultProvider`、`defaultModel`、`enabledModels` 及 Session/Retry/Skill 设置；
3. `pi-agent/auth.json`：可选的 Pi 官方持久凭据文件，不提交到代码仓。

CLI 和 Server 将全局 `models/mcp/skills` 作为 `PluginActivationContext.sharedConfig` 注入插件。Harmony 插件不再要求复制这些配置，只保留 Atlas、允许路径、容量等领域参数。

新配置见 [`docs/examples/pi-agent/settings.json`](../examples/pi-agent/settings.json) 与 [`docs/examples/pi-agent/models.json`](../examples/pi-agent/models.json)。`agent-platform.json` 只保存 Pi 不具备的 MCP Server、通用子 Agent 策略与自定义 LangGraph 插件配置；子 Agent 只引用 Pi 中已经声明的模型别名。
