# 第二阶段：Harmony 审计插件接入基线

状态：接入主链路已贯通  
完成日期：2026-08-03

## 接入结论

Harmony 白盒安全审计已经作为独立 `@agent-platform/harmony-audit` 插件接入通用助手。平台只通过 Plugin Contract 发现、激活和调用它，不解析项目、任务、Finding 或报告字段。

| 链路 | 当前状态 | 所有者 |
|---|---|---|
| 配置驱动发现与 Manifest 校验 | 已接通 | Platform Plugin Host |
| Atlas、允许目录、模型别名配置 | 已接通 | Harmony 插件配置 |
| Project Model 与范围选择 | 已接通 | Harmony 插件 |
| Atlas CLI 索引与私有 MCP 会话 | 已接通 | Harmony 插件 |
| LangGraph 状态机 | 已接通 | Harmony 插件 |
| 最大五槽滚动 Worker | 已接通 | Harmony 插件 |
| 路径发现与六维验证 | 已接通 | Harmony 插件 |
| `run.db`、恢复和确定性报告 | 已接通 | Harmony 插件 |
| Web Contribution、SSE、Action、Artifact | 已接通 | Plugin Contract + Harmony 页面 |

## 本轮补齐

- 新增 `readiness` 插件 Operation，在创建 Run 前检查 Atlas、Pi 模型目录和两类内置审计 Skill；
- Orchestrator 在项目解析和 Atlas 索引前解析模型并验证 Skill/工具映射，让配置错误尽早失败；
- Atlas 命令探测增加 10 秒超时；
- Harmony 工作台只显示 `pluginId=harmony-audit` 的 Platform Job，不混入其他插件；
- 模型输入使用通用助手公布的 Pi 模型别名；
- 只有 `report-html` Artifact 确实存在时才装载报告，失败或取消 Run 不再产生无意义的 404 iframe；
- Web 在启动审计前显示插件就绪状态，未就绪时禁用提交。

## 配置和运行边界

Provider、Base URL、认证和模型目录继续只写在 Pi 官方 `models.json/settings.json/auth.json` 中。Harmony 插件配置只保存模型别名、Atlas、允许目录和领域运行策略。Atlas MCP 不进入普通助手的全局 MCP 列表。

`readiness=true` 证明静态接入条件满足，但不会创建 `.atlas` 索引或调用模型。真实端到端验收仍需要用户提供：

1. 可执行的 Atlas；
2. 位于 `allowedRoots` 下的 HarmonyOS 项目；
3. 可调用的 Pi 模型凭据。

下一验收门槛是在真实项目上完成一次 `项目解析 → Atlas 索引 → 五槽分析 → 六维验证 → report.html`，并保留 Run Directory 供恢复测试。
