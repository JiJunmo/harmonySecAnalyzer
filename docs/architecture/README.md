# 架构与设计文档索引

## 当前权威文档

- [当前总体设计](../../DESIGN.md)：产品边界、分层、运行链路、状态与部署模型。
- [已实现系统架构图](../架构图-已实现.md)：当前模块与运行数据流。
- [功能骨架与领域插件边界契约](PLATFORM-PLUGIN-BOUNDARY.md)：不可违反的所有权和依赖规则。
- [当前架构边界审计](CURRENT-BOUNDARY-AUDIT.md)：按当前源码完成的最终边界检查和纠偏记录。
- [Plugin Contract v1](PLUGIN-CONTRACT-V1.md)：Manifest、激活、Run、事件、动作、执行过程和 Artifact 合同。
- [本地网关可靠性](LOCAL-GATEWAY-RELIABILITY.md)：SQLite 状态、重启恢复、保留清理、日志和诊断。
- [Web API v1](../contracts/WEB-API-V1.md)：助手与插件的 HTTP/SSE 接口。

## 通用助手与平台机制

- [Pi Coding Agent 复用决策](PI-CODING-AGENT-COMPATIBILITY.md)
- [Pi Session Factory](PI-SESSION-FACTORY.md)
- [助手 Session](ASSISTANT-SESSIONS.md)
- [助手能力管理](ASSISTANT-CAPABILITY-MANAGEMENT.md)
- [通用助手子 Agent](ASSISTANT-SUBAGENTS.md)
- [Agent Execution Trace](AGENT-EXECUTION-TRACE.md)
- [Plugin Host Service](PLUGIN-HOST-SERVICE.md)
- [通用 Plugin Server](GENERIC-PLUGIN-SERVER.md)
- [通用 Plugin CLI](GENERIC-PLUGIN-CLI.md)
- [Web Shell 与插件贡献](WEB-SHELL-CONTRIBUTIONS.md)

## Harmony 插件设计

- [Harmony 插件适配](HARMONY-PLUGIN-ADAPTER.md)
- [第二阶段接入基线](SECOND-PHASE-HARMONY-INTEGRATION.md)
- [五槽并发策略](HARMONY-POOL-POLICY.md)
- [增量审计](HARMONY-INCREMENTAL-AUDIT.md)
- [run.db v2](../contracts/RUN-DB-V2.md)
- [领域不变量](../contracts/INVARIANTS.md)
- [v3.1 行为等价清单](../../packages/harmony-audit/V31-PARITY.md)

## 历史决策与验收档案

以下文档保留用于追溯迁移过程，不代表当前仍有对应缺口：

- `docs/contracts/MILESTONE-0.md` 至 `MILESTONE-6.md`
- [v3.1 等价矩阵](../contracts/V31-EQUIVALENCE.md)
- [统一模型配置迁移](SHARED-MODEL-CONFIG.md)
- [旧边界迁移阶段记录](PLATFORM-PLUGIN-BOUNDARY.md)中的完成日志

发生表述冲突时，以 `DESIGN.md`、边界契约和当前边界审计为准。
