# PluginHostService

状态：已实现  
实现位置：[`packages/interface/src/service.ts`](../../packages/interface/src/service.ts)  
依赖：`@agent-platform/core`  
禁止依赖：任意具体领域插件

## 1. 结果

`packages/interface` 已从 Harmony 专用 `AuditApplicationService` 转换为领域无关的 `PluginHostService`。Interface 的 package manifest、TypeScript reference、源代码和测试均不再依赖 `@agent-platform/harmony-audit`。

Host Service 只认识 Plugin Contract v1：

```text
PluginDefinition / Manifest
PluginRuntime
PluginRunReference / Snapshot
PluginEvent / Action
PluginArtifact
```

它不认识项目路径、Component、Capability、Finding、报告类型或固定并发槽数。

## 2. 激活与配置

```ts
const host = await PluginHostService.create({
  plugins: [pluginA, pluginB],
  configs: {
    "plugin-a": opaqueConfigA,
    "plugin-b": opaqueConfigB,
  },
});
```

创建过程：

1. 使用 `PluginRegistry` 校验 ID、Manifest 和 API 版本；
2. 按插件 ID 选择配置，未提供时使用插件 `defaultConfig`；
3. 通过 `activatePlugin()` 执行插件自己的 JSON Schema 校验；
4. 注入 Host AbortSignal 和通用 Logger；
5. 任一插件激活失败时，释放此前已经激活的 Runtime。

Host 不解析、合并或补写插件配置字段。

## 3. 平台 Job 索引

Host 为每次调用生成独立 `JOB-<uuid>`，保存最小通用索引：

```text
platform job id
plugin id
opaque plugin run reference
generic status/snapshot/error
created/updated timestamp
```

`createRun()` 立即返回 `accepted`，插件初始化在后台继续。插件产生稳定 Run 引用后，Job 更新为插件 Snapshot；因此较慢的 Project Model 或 Atlas 准备不会阻塞 HTTP 接收阶段。

当前 Job 索引位于内存中。插件自己的 Run 仍可在 Host 重启后通过 `adoptRun(pluginId, reference)` 恢复；平台 Job 索引持久化属于后续通用运维增强，不影响领域 `run.db` 的事实源地位。

## 4. 通用操作

| Host 方法 | 行为 |
|---|---|
| `listPlugins()` | 返回已激活 Manifest |
| `operation()` | 委托不依赖既有 Run 的插件级操作 |
| `createRun()` | 创建通用 Job，异步委托插件 |
| `adoptRun()` | 用 opaque 引用接管已有插件 Run |
| `listRuns()/getRun()` | 返回通用 Job 外壳，查询时刷新插件 Snapshot |
| `action()` | 原样委托 Action name/payload/subject |
| `events()` | 原样转发插件 `AsyncIterable<PluginEvent>` |
| `artifacts()/openArtifact()` | 委托插件列举和打开 Artifact |
| `subscribe()` | 提供 Host Job 生命周期事件 |
| `dispose()` | Abort Host 并释放全部 Runtime |

Host 不基于 Action 名称、事件类型、payload、details 或 Artifact 媒体类型执行领域分支。

## 5. Server 迁移结果

BL-003 已完成：Server 现直接使用 `PluginHostService`，此前临时移动到 Server 的 `AuditApplicationService` 已删除。通用 HTTP 协议见 [`Generic Plugin Server`](GENERIC-PLUGIN-SERVER.md)。

## 6. 验收

[`packages/interface/test/service.test.ts`](../../packages/interface/test/service.test.ts) 只使用独立 Dummy Plugin，验证：

- 插件激活和配置校验；
- accepted 到 initialized 的异步 Job 生命周期；
- Action、Event 和 Artifact 委托；
- Host 生命周期事件；
- 未知插件拒绝；
- dispose 后禁止继续使用。

现有 Server 测试继续通过，证明本步骤没有提前改变 Web API。
