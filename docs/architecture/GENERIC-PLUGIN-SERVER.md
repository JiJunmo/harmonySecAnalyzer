# Generic Plugin Server

状态：已实现  
实现位置：[`apps/server/src/server.ts`](../../apps/server/src/server.ts)  
组合入口：[`apps/server/src/main.ts`](../../apps/server/src/main.ts)

## 1. 结果

Server 已改为只依赖 Core Plugin Contract 和 `PluginHostService`。Server package manifest、TypeScript reference、路由、请求类型和测试均不再依赖具体领域插件。

具体插件由组合根安装，并从 `agent-platform.json` 的 `plugins.modules` 动态发现：

```json
{
  "plugins": {
    "modules": ["@agent-platform/harmony-audit"],
    "configs": {
      "harmony-audit": {
        "atlasExecutable": "/absolute/path/to/atlas",
        "allowedRoots": ["/absolute/path/to/projects"],
        "capacity": 5
      }
    }
  }
}
```

Server 不读取 `harmony-audit` 配置字段；整个 `configs[pluginId]` 对它是不透明值，由插件激活时用自己的 JSON Schema 校验。

## 2. 通用 HTTP API

| Method | Path | 语义 |
|---|---|---|
| `GET` | `/api/health` | Host 健康状态和插件数量 |
| `GET` | `/api/plugins` | 已激活 Plugin Manifest |
| `POST` | `/api/plugins/:pluginId/operations/:name` | 插件级无 Run 操作 |
| `GET` | `/api/runs` | Platform Job 列表 |
| `POST` | `/api/runs` | `{ pluginId, payload }` 创建 Run |
| `POST` | `/api/runs/adopt` | `{ pluginId, pluginRun }` 接管已有 Run |
| `GET` | `/api/runs/:jobId` | 查询并刷新通用 Run |
| `POST` | `/api/runs/:jobId/actions/:name` | 委托 Run Action |
| `GET` | `/api/runs/:jobId/events` | SSE Host/Plugin 事件流 |
| `GET` | `/api/runs/:jobId/artifacts` | Artifact 列表 |
| `GET` | `/api/runs/:jobId/artifacts/:artifactId` | 字节或异步字节流传输 |

`payload`、Operation name、Action name、Plugin Event type 和 Artifact ID 都只透传，Server 不包含具体插件分支。

## 3. Plugin Operation

为支持创建 Run 前的插件交互，Plugin Contract v1 增加了领域无关的 `operation()`：

```ts
interface PluginOperation {
  name: string;
  payload?: unknown;
  subject?: PluginSubject;
}
```

Harmony Adapter 当前贡献：

- `capabilities`：返回插件自己的能力目录；
- `profile`：解析授权范围内的 HarmonyOS 项目。
- `readiness`：检查 Atlas、Pi 模型和插件内置审计 Skill 是否可用。

Dummy Plugin 贡献 `echo` 用于验证 payload 不被 HTTP/Host 改写。新增其他插件级操作不需要修改 Server。

## 4. SSE

事件流包含三种通用事件：

- `snapshot`：连接时的 Host Run 快照；
- `host_event`：accepted、initialized、updated、failed 等 Platform Job 变化；
- `plugin_event`：插件持久化或实时事件原样转发。

客户端断开时 Server 会取消插件事件迭代、移除 Host listener 并停止 heartbeat。

## 5. Artifact 安全

Server 只能用 `artifactId` 调用插件 `openArtifact()`，不接受文件路径。响应统一包含：

- 插件声明的 Media Type；
- `Content-Disposition` 安全文件名；
- `X-Content-Type-Options: nosniff`；
- `Cache-Control: no-store`；
- HTML Artifact 的限制性 CSP。

具体插件继续负责 Artifact ID 白名单和底层内容授权。

## 6. 组合根与环境变量

Server 使用通用环境变量：

```text
AGENT_PLATFORM_CONFIG
AGENT_PLATFORM_WEB_HOST
AGENT_PLATFORM_WEB_PORT
AGENT_PLATFORM_WEB_TOKEN
```

模型和认证使用 Pi 官方配置；API Key 不写入 `agent-platform.json`。仓库 `.env.example` 只保留空密钥字段。

`@agent-platform/harmony-audit` 现在安装在 workspace 根 package，作为当前发行组合的一部分；`apps/server/package.json` 不依赖它。未来增加或移除插件只修改组合配置/安装项，不修改 Server 源码。

## 7. Web Shell 与页面贡献

Server 额外提供两个领域无关的 Web 装载入口：

- `GET /api/web-contributions`：返回插件页面的公开元数据；
- `GET /plugins/:pluginId/:contributionId/*`：经 Host 路径授权后读取插件静态资源。

`apps/web/public` 只包含通用 Shell，负责 Token、健康状态、插件页面导航和 iframe 装载。Harmony 页面已迁入 `packages/harmony-audit/resources/web`，并继续使用通用 API：

- profile/capabilities 使用 Plugin Operation；
- 创建请求使用 `{ pluginId, payload }`；
- cancel/resume/report 使用通用 Action；
- HTML 报告使用 `report-html` Artifact；
- Run 详情从 `snapshot.details` 读取插件数据。

这些字段只在 Harmony 插件页面中解释；Shell 和 Server 不读取其领域结构。
