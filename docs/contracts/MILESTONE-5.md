# 里程碑 5：运行时基础设施与可扩展装配

状态：已完成  
完成日期：2026-07-31  
依赖：里程碑 4

## 已交付

### MCP 会话治理

- `McpManager` 以 FIFO 等待队列限制活动会话数量。
- 连接支持健康检查、有限次数退避重试和稳定的 exhausted 错误。
- Session close 幂等；Manager close 关闭所有活动会话并拒绝新连接。
- 状态快照不暴露环境变量或凭据。

### 模型配置

- TOML 可声明多个 OpenAI-compatible Provider/Model、默认别名和 Task Kind 映射。
- 选择顺序为 CLI `--model`、Task Kind 映射、默认模型。
- API Key 使用 Pi 官方 `models.json` 的 `$ENV_VAR`、`auth.json` 或 Provider 标准环境变量解析。

### Skill 与插件

- `SkillManager` 统一负责发现、注册、任务映射、激活及 required tools 校验。
- Harmony Worker 只消费已激活 Skill，不感知文件布局。
- 插件由 `[plugins].modules` 动态发现，清单可提供一个或多个 Orchestrator。
- CLI `run` 可调用配置插件，Core 和 CLI 不包含插件领域名称分支。

### CLI

- 新增 `capabilities`、`components` 和通用 `run`。
- `audit/resume` 支持 `--config`、`--model`、`--atlas` 和 `--capacity`。
- Component selector 支持稳定 ID或名称；无匹配和同名多匹配返回稳定诊断码。

配置示例见 [`../examples/pi-agent/settings.json`](../examples/pi-agent/settings.json)、[`../examples/pi-agent/models.json`](../examples/pi-agent/models.json) 和 [`../examples/agent-platform.json`](../examples/agent-platform.json)。

## 验收门槛

- 多模型默认选择、任务映射和显式覆盖可确定性测试。
- Skill 缺少 required tool 时必须在模型执行前拒绝。
- MCP 会话上限和策略参数必须经过边界校验。
- 新插件仅通过模块和 TOML 即可发现，不修改通用注册源码。
- CLI 查询输出为稳定 JSON 数据。
- TypeScript 检查、全部单元测试和 workspace build 通过。

## 后续边界

HTTP API、身份认证、Web 控制台、跨进程分布式 MCP 池、指标/Trace 后端和上下文压缩治理不属于本里程碑。
