# Pi Coding Agent 兼容性验证与复用决策

状态：已验证并接入生产 Session  
验证日期：2026-07-31  
验证版本：`@earendil-works/pi-coding-agent@0.82.1`  
判断基线：[`platform-plugin-boundary-v2`](PLATFORM-PLUGIN-BOUNDARY.md)

## 1. 结论

采用 **SDK 级选择性复用**，由 Pi Coding Agent 提供通用 AI 助手的 Session 核心，但不直接复用其 TUI。

Pi Coding Agent 适合接管通用的模型目录与认证、Agent Session、事件、取消、会话机制、工具注册和基础 Skill 解析。平台仍需保留一层很薄的安全适配器，用于强制工具白名单、资源隔离、结构化结果校验和平台事件转换。

鸿蒙白盒安全审计插件的项目解析、Atlas、路径发现、六维验证、编排器、状态机、5 槽策略、`run.db` 和报告均不交给 Pi，也不因本决策改变。

```text
Web / CLI / API
    |
通用 AI 助手（Pi AgentSession）
    |-- 全局启用的 Model / Tool / MCP / Skill / SubAgent
    `-- Plugin Host
            |
       LangGraph 多 Agent 插件
            |
       HarmonyAuditPlugin（当前首个插件）
```

## 2. 可执行验证

兼容性测试位于 [`packages/core/test/pi-coding-agent-compat.test.ts`](../../packages/core/test/pi-coding-agent-compat.test.ts)，全程使用 Faux Provider，不访问真实模型或网络，不写入用户 Pi 配置。

已验证：

1. `ModelRuntime` 可以使用 `InMemoryCredentialStore` 和仅运行期 API Key；密钥不会进入 Provider 的可序列化信息，也不会写入 Credential Store。
2. `SessionManager.inMemory()` 不创建 Session 文件。
3. `SettingsManager.inMemory()` 可以关闭自动 Compaction。
4. `createAgentSession()` 可以通过 `tools` 只暴露一个自定义 `submit_result` 工具，默认 `read/bash/edit/write` 均不进入 Agent。
5. 自定义工具支持 `terminate: true`，一次工具调用即可结束，并产生完整工具执行事件。
6. `AgentSession.subscribe()` 能提供 Agent、Message、Tool 和 Settled 事件；`abort()` 与 `dispose()` 可由 Host 管理生命周期。
7. Pi 能解析显式 `SKILL.md`，但仅配置 `additionalSkillPaths` **不会关闭全局 Skill 扫描**；安全隔离必须使用 `skillsOverride` 白名单或自定义 `ResourceLoader`。
8. `noExtensions`、`noContextFiles`、`noPromptTemplates` 和 `noThemes` 可以阻断项目/用户资源的隐式注入。

## 3. 复用矩阵

| 能力 | 决策 | 原因与约束 |
|---|---|---|
| Model catalog/provider | 直接复用 `ModelRuntime` | 已覆盖 Provider 注册、模型目录、可用性和调用入口；不应继续维护平行 `ModelManager` |
| API Key/OAuth | 直接复用并注入存储 | Web Host 注入自己的 Credential Store 或配置解析结果；审计 Worker 使用运行期凭据，不能默认读 `~/.pi/agent/auth.json` |
| Agent Session | 包装复用 `AgentSession` | 复用消息、事件、排队、模型切换和生命周期；外部只暴露平台合同 |
| Event/Abort | 直接复用并转换事件 | 映射为 Host 通用事件；外部 `AbortSignal` 转为 `session.abort()` |
| Session persistence | 按场景复用 | 助手对话可持久化；审计 Worker 使用内存 Session，领域恢复仍以插件 `run.db` 为准 |
| Compaction/Retry | 按场景配置 | 普通助手可开启；结构化审计任务默认关闭 Compaction，由插件决定任务重试 |
| Tool registry | 包装复用 | 通用助手默认使用全局启用工具；插件可继承或按任务缩小范围 |
| Structured output | 保留薄适配器 | 用 Pi 自定义 terminating tool 执行提交，但继续使用 Ajv/领域校验器保证 Schema、一次提交和错误语义 |
| Skill discovery/parser | 部分复用 | 复用标准 `SKILL.md` 解析；插件继续拥有任务到 Skill、所需工具和完整正文注入策略 |
| Pi extensions/packages | 仅作内部扩展候选 | 不能替代本项目的版本化领域插件合同；Pi Extension 与审计插件不是同一抽象层 |
| MCP | 保留当前薄治理层 | Pi Session 可消费转换后的工具，但 MCP 连接、池化、重试和授权仍由平台管理 |
| TUI | 不集成到产品交互 | 本产品以 Web 和 HTML Artifact 为主；TUI 可作为上游参考或开发调试入口 |
| Web | 自行实现通用 Shell | Pi SDK 是 Headless 能力来源，Web 通过 Host API/SSE 消费事件，不复制 TUI 组件 |

## 4. Session 策略

`PiSessionFactory` 必须支持至少两种配置档，而不是把受限策略施加给整个助手：

| 配置档 | 默认能力 |
|---|---|
| `interactive` | 用户全局启用的 Tool、MCP、Skill、上下文和 Session 能力 |
| `workflow-worker` | 继承插件声明的能力；插件可针对敏感任务进一步缩小范围 |

鸿蒙审计 Worker 可以显式设置：

```ts
createAgentSession({
  modelRuntime,
  model,
  sessionManager: SessionManager.inMemory(cwd),
  settingsManager: SettingsManager.inMemory({ compaction: { enabled: false } }),
  resourceLoader: isolatedResourceLoader,
  tools: allowedToolNames,
  customTools,
});
```

只有选择隔离执行的插件 Worker 才要求 `isolatedResourceLoader` 满足：

- `noExtensions: true`：不执行用户或项目 Extension；
- `noContextFiles: true`：不隐式加载 `AGENTS.md` 等上下文；
- `noPromptTemplates: true`、`noThemes: true`：审计 Worker 不加载交互资源；
- Skill 经过 `skillsOverride` 精确白名单，不能只设置 `additionalSkillPaths`；
- System Prompt 由插件任务装配器提供；
- 不使用 Pi 默认 `agentDir`、认证文件或会话目录；
- `tools` 必须是精确 allowlist，且包含结构化提交工具。

通用助手不得默认套用该白名单。其他 MCP 可以由全局配置启用并被交互助手使用，也可以由插件继承；Atlas 只属于 Harmony 插件，不能写死在 Factory 中。

## 5. 对当前代码的处理决定

| 当前文件 | 决定 |
|---|---|
| `packages/core/src/models.ts` | 后续由 `ModelRuntime` Adapter 替换；只保留平台配置到 Pi Provider/Auth 的映射，不再自建模型调用体系 |
| `packages/core/src/pi-session.ts` | 已实现双配置档 `PiSessionFactory`；保留 Ajv 提交验证和平台错误语义，旧自研循环已删除 |
| `packages/core/src/skills.ts` | 用 Pi 的 Skill 解析替换手写 Frontmatter；保留插件侧任务映射、required-tools 校验和确定性正文装配 |
| `packages/core/src/plugins.ts` | 继续扩展为本项目的版本化 Plugin Host，不能替换为 Pi Extension |
| `packages/core/src/mcp.ts` | 保留 MCP 生命周期与治理层，将工具转换给 Pi Session |
| `packages/core/src/tools.ts` | 作为可选工具包保留，默认不进入审计 Agent |

生产执行路径已经切换：通用交互 Session 与 Harmony LangGraph Worker 均使用 Pi `AgentSession`；模型配置通过 `ModelRuntime` 注册，旧自研 Agent 循环已经删除。

## 6. 实施状态与后续顺序

插件合同、平台边界反转和 Pi Session 迁移现已完成。原实施项状态如下：

1. **已完成**：版本化 Plugin Contract、Dummy Plugin、Harmony Adapter。
2. **已完成**：CLI、Server、Web Shell 反转为通用 Plugin Host 合同。
3. **已完成**：`interactive` / `workflow-worker` 双配置档 `PiSessionFactory`。
4. **已完成**：生产会话使用 Pi `ModelRuntime`、凭据存储和 `AgentSession`，旧 Agent 循环已删除。
5. **下一步候选**：复用 Pi Skill parser，同时保留插件确定性 Skill 选择策略。
6. **持续约束**：通过 import-boundary 检查防止领域逻辑回流平台骨架。

## 7. 上游依据

- [Pi Coding Agent SDK 文档](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/sdk.md)
- [Pi Coding Agent Extensions 文档](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md)
- [Pi Coding Agent Skills 文档](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/skills.md)
- [Pi Coding Agent package manifest](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/package.json)
