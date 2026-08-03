# HarmonyAuditPlugin Adapter

状态：已实现  
插件 ID：`harmony-audit`  
插件版本：`3.2.0`  
Plugin API：`1`  
实现位置：[`packages/harmony-audit/src/plugin.ts`](../../packages/harmony-audit/src/plugin.ts)

## 1. 职责

`HarmonyAuditPlugin` 是鸿蒙白盒安全审计插件与通用 Plugin Contract v1 之间的窄适配层。它只负责协议映射，不重新实现或搬运领域逻辑。

仍由原有鸿蒙模块完整负责：

- Project Model 和项目解析；
- Atlas 校验、索引及工具白名单；
- 路径发现、跨组件关联和六维验证；
- LangGraph 编排、状态机和固定 5 槽策略；
- `run.db`、领域事件、不变量和恢复；
- Finding、Attack Matrix 与 JSON/Markdown/HTML 报告。

Adapter 新增的职责只有：

- 校验插件配置和 Run payload；
- 执行插件自己的路径授权；
- 调用 `HarmonyAuditOrchestrator.run/resume`；
- 把领域状态映射为通用 Run 状态；
- 从 `run.db.events` 转换 Plugin Event；
- 把领域动作和报告映射为 Plugin Action/Artifact；
- 管理激活与释放期间的后台执行引用。
- 提供 `profile`、`capabilities` 两个创建 Run 前的插件级 Operation。
- 提供 `readiness` Operation，在创建 Run 前检查 Atlas、Pi 模型目录和审计 Skills。

## 2. Run 引用

Plugin Contract 中的 `PluginRunReference.id` 对平台是不透明字符串。Harmony Adapter 使用规范化后的 Run Directory 作为该字符串：

```text
PluginRunReference.id
  = /authorized/project/reports/harmony-audit-<run-id>
```

这样无需引入第二套插件映射数据库，Host 重启后仍可把保存的引用交回插件完成 `adoptRun()`。平台不得解析该字符串、拼接内部文件名或假设其他插件也使用目录。

`createRun()` 会等待原 Orchestrator 完成 Project Model、Atlas 准备和 `AuditStore.create()`，在 `onRunCreated` 获得稳定 Run Directory 后返回；后续审计图继续在后台运行。

## 3. 状态映射

| Harmony `run.db` 状态 | Plugin Contract 状态 |
|---|---|
| `created` | `accepted` |
| Atlas/恢复准备阶段 | `preparing` |
| `running` | `running` |
| `complete` | `succeeded` |
| `complete_with_gaps` | `succeeded`，覆盖缺口保留在 opaque `details` |
| `failed` | `failed` |
| `cancelled` | `cancelled` |

Task 计数只映射为通用 `progress.completed/total`。完整 task、finding、coverage gap 和路径信息保留在 `details`，平台只传输、不解释。

## 4. 事件与动作

`AuditStore.eventsAfter()` 是此次增加的唯一领域存储读取接口，按自增 `event_id` 返回持久化事件。Adapter 将游标编码为 `<run-id>:<event-id>`，通过 `AsyncIterable<PluginEvent>` 支持重放和持续轮询。

支持的动作：

| Action | 委托目标 |
|---|---|
| `cancel` | `AuditStore.cancel()` |
| `resume` | `HarmonyAuditOrchestrator.resume()` |
| `rebuild-report` | `AuditStore.rebuildReport()` |

固定容量范围 `1..5` 仍由鸿蒙插件校验，不进入 Core。

## 5. Artifact

Adapter 只允许下列固定 Artifact ID：

| ID | 领域文件 | Media Type |
|---|---|---|
| `report-json` | `report.json` | `application/json` |
| `report-markdown` | `report.md` | `text/markdown` |
| `report-html` | `report.html` | `text/html` |
| `attack-matrix` | `attack-matrix.json` | `application/json` |

调用方不能把文件路径作为 Artifact ID，因此不能通过 `../` 读取 `run.db`、Project Model 或其他内部文件。不存在的报告只是不出现在 `artifacts()` 中。

## 6. 插件配置

Adapter 激活配置由插件自己的 JSON Schema 校验：

```json
{
  "plugins": {
    "modules": ["@agent-platform/harmony-audit"],
    "configs": {
      "harmony-audit": {
        "atlasExecutable": "/absolute/path/to/atlas",
        "allowedRoots": ["/absolute/path/to/projects"],
        "capacity": 5,
        "model": "local/gemini-3.6-flash-high",
        "eventPollIntervalMs": 500
      }
    }
  }
}
```

`allowedRoots` 至少包含一个已存在的绝对目录。create/adopt/status/events/action/artifact 的所有路径都会经过真实路径解析和子路径检查。

Provider、认证和模型目录在 Pi 官方配置中只声明一次，由 Host 通过 `sharedConfig` 注入 Pi 目录；Harmony 配置只选择模型别名。Atlas MCP 和任务 Skill 归插件所有，不进入普通助手的全局能力列表。

## 7. 验收

测试位于 [`packages/harmony-audit/test/plugin.test.ts`](../../packages/harmony-audit/test/plugin.test.ts)，覆盖：

- create 后返回稳定 opaque 引用；
- 状态和进度映射；
- cancel 与持久化事件转换；
- 报告重建和四类 Artifact；
- Runtime 重启后的 adopt；
- allowed-root 路径授权；
- Artifact 路径穿越拒绝。

Interface、CLI 和 Server 均已通过通用 Plugin Contract 使用 Adapter，不再静态依赖 Harmony 实现。Harmony Web 控制台以 `console` contribution 声明，静态资源归属插件自身。
