# Plugin Contract v1

状态：已实现  
协议版本：`1`  
实现位置：[`packages/core/src/plugins.ts`](../../packages/core/src/plugins.ts)  
参考插件：[`packages/dummy-plugin`](../../packages/dummy-plugin)

## 1. 目标

Plugin Contract v1 是功能骨架与任意领域插件之间唯一的运行期协议。协议只描述插件身份、生命周期、通用 Run 外壳、事件、动作和 Artifact，不包含任何具体审计概念。

Host 通过配置发现 `PluginDefinition`，校验 Manifest/API 版本和插件配置，随后激活 `PluginRuntime`。插件内部存储、状态机、业务 payload 和 Artifact 内容对 Host 保持不透明。

## 2. Manifest

```ts
interface PluginManifest {
  apiVersion: "1";
  id: string;
  version: string;
  displayName: string;
  description?: string;
  entry?: string;
  contributes: ("runs" | "cli" | "web")[];
}
```

规则：

- `id` 是 Host 中的稳定唯一标识，只允许小写字母、数字、点和连字符；
- `version` 使用 SemVer；
- `apiVersion` 必须与 `PLUGIN_API_VERSION` 完全一致；
- v1 插件必须声明 `runs`；
- 同一个 `id` 不能注册两次；
- `cli` 和 `web` 表示对应贡献类型；声明后必须分别提供有效的 `PluginDefinition.cli` 或 `PluginDefinition.web`。

## 3. Definition 与激活

`PluginDefinition` 提供：

- `manifest`；
- 可选 JSON Schema `configSchema`；
- 可选 `defaultConfig`；
- `activate(context)` 生命周期入口。

`activatePlugin()` 在调用插件代码前完成 Manifest/API 和配置 Schema 校验，在返回后检查 Runtime 是否实现全部 v1 方法。激活上下文目前只提供：

- 已解析但对平台无业务语义的 `config`；
- 全局且领域无关的 `sharedConfig`（当前包含统一的 models、MCP 和 Skill 配置，插件可以显式覆盖）；
- Host 生命周期 `AbortSignal`；
- 通用结构化 Logger。

模型、Agent、MCP、Skill 和 LangGraph Workflow 端口会在通用 `PiSessionFactory` 与 Host 服务实现时加入，不允许在合同中加入某一插件专用服务。通用助手默认继承全局启用能力，插件 Worker 可继承或缩小范围。

## 4. Runtime

```text
createRun  -> 创建插件 Run，返回通用 Snapshot
operation  -> 执行不依赖既有 Run 的插件级操作
adoptRun   -> 由插件重新接管自己的不透明 Run 引用
getRun     -> 查询通用状态外壳
events     -> 以 AsyncIterable 转发事件
action     -> 委托 cancel/resume 或插件扩展动作
artifacts  -> 列举产物描述
openArtifact -> 打开字节内容或异步字节流
executions? -> 可选列出插件 Run 的 Agent 执行单元
execution?  -> 可选读取单个执行单元的 Attempt 与 Trace
dispose    -> 释放插件级资源
```

`PluginRunReference.id` 由插件产生并解释。Host 只能保存和回传，不能假设它是目录、数据库主键或 UUID。

通用状态固定为：

```text
accepted | preparing | running | succeeded | failed | cancelled
```

插件负责把自己的领域状态映射到这些状态。`details`、事件 `payload` 和动作 `payload` 均为 `unknown`，Host 不得基于其字段分支。

Artifact v1 支持 `Uint8Array` 或 `AsyncIterable<Uint8Array>`，因此既能传输小型 JSON，也能流式传输 HTML 报告或其他大文件。

`executions` 与 `execution` 是领域无关的可选可观察性贡献。Host 只传输执行单元、Attempt 和 Trace Event，不理解任务输入与结果；未实现这两个方法的旧插件继续兼容 Contract v1。

## 5. Dummy Plugin 验收

`@agent-platform/dummy-plugin` 是独立 workspace package，只依赖 `@agent-platform/core`，不依赖 Harmony 包。它验证：

1. v1 Manifest 注册和 API 兼容校验；
2. JSON Schema 配置校验发生在激活前；
3. create/adopt/get/events/action/artifacts/open/dispose 全生命周期可运行；
4. 任意嵌套 payload 能原样穿过合同；
5. Artifact 可以从插件返回给 Host；
6. dispose 后运行时不再接受调用。

对应测试为 [`packages/dummy-plugin/test/contract.test.ts`](../../packages/dummy-plugin/test/contract.test.ts)。动态模块发现、重复 ID 和不兼容 API 版本测试位于 [`packages/core/test/config-plugins.test.ts`](../../packages/core/test/config-plugins.test.ts)。

## 6. CLI Contribution

`PluginDefinition.cli` 提供插件自己的命令名、说明、usage 和参数解析器。参数解析器只返回声明式 `PluginCliInvocation`，通用 CLI 根据 invocation 调用 Plugin Host。

当前支持的 invocation：

- `operation`；
- `run`；
- `inspect`；
- `action`；
- `artifacts`。

旧 `PluginDefinition.orchestrators` 过渡字段已经删除。

## 7. Web Contribution

`PluginDefinition.web` 声明插件拥有的静态页面：

```ts
interface PluginWebContribution {
  id: string;
  title: string;
  entry: string;
  assetsRoot: string;
}
```

Host 对 Shell 只公开 `pluginId/id/title/entry`，不会暴露服务端 `assetsRoot`。资源读取由 Host 完成 realpath 边界检查，禁止绝对路径、空路径、`..` 和通过符号链接逃逸资源根目录。页面通过 `/plugins/:pluginId/:contributionId/*` 装载，领域页面仍使用同一套通用 Plugin/Run/Action/Artifact API。

平台不读取页面内容，也不解释插件 `snapshot.details`；插件页面、样式、状态展示和 Artifact 视图全部由插件拥有。
