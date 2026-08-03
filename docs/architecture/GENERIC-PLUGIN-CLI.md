# Generic Plugin CLI

状态：已实现  
实现位置：[`apps/cli/src/main.ts`](../../apps/cli/src/main.ts)

## 1. 结果

CLI 已改为只依赖 Core Plugin Contract 与 `PluginHostService`。CLI package manifest、TypeScript reference、源码和测试均不再静态依赖 Harmony 插件，也不包含审计命令、Component、Capability、Atlas 或固定 5 槽参数解释。

CLI 从 `plugins.modules` 动态发现插件，并执行插件声明的 `PluginCliCommand`：

```ts
interface PluginCliCommand {
  name: string;
  description: string;
  usage: string;
  invoke(args: string[]): PluginCliInvocation;
}
```

`PluginCliInvocation` 是声明式结果，只能要求通用 CLI 执行：

- plugin-level operation；
- create run；
- inspect/adopt run；
- run action；
- list artifacts。

插件 contribution 不能直接访问 CLI 的 Host 内部状态。

## 2. 命令发现

```bash
pnpm agent -- plugins --config agent-platform.json
pnpm agent -- <command> ... --config agent-platform.json
pnpm agent -- <plugin-id>:<command> ... --config agent-platform.json
```

无冲突时可以使用短命令名。多个插件声明同名命令时，短名称不会注册，用户必须使用 `<plugin-id>:<command>`，因此增加插件不需要在 CLI 中添加领域分支。

配置也可以统一通过环境变量指定：

```bash
export AGENT_PLATFORM_CONFIG=/absolute/path/to/agent-platform.json
```

## 3. Harmony CLI Contribution

Harmony Adapter 当前贡献：

| 命令 | 通用 Invocation |
|---|---|
| `audit` | `run` |
| `status` | `inspect` |
| `resume` | `action: resume`，等待终态 |
| `cancel` | `action: cancel` |
| `report` | `action: rebuild-report` |
| `capabilities` | `operation: capabilities` |
| `components` | `operation: profile` |

因此原有命令名称保持不变，但参数、容量范围、组件和能力选择均由 Harmony 插件解释。

`harmony-agent` bin 暂时作为兼容别名保留；新的通用 bin 名称为 `agent-platform`。

## 4. 生命周期

CLI 运行在单进程、一次性调用模式中：

- `run` 默认等待插件达到通用终态，再释放 Host；
- `resume` contribution 声明 `wait: true`，避免后台审计随 CLI 进程退出；
- inspect、cancel、report 和 operation 完成委托后即可释放 Runtime；
- CLI 显式等待 invocation Promise 后才执行 `dispose()`。

最后一条由回归测试覆盖，防止异步命令尚未完成时提前卸载插件。

## 5. 验收

[`apps/cli/test/cli.test.ts`](../../apps/cli/test/cli.test.ts) 使用运行时生成的领域无关插件，验证：

- 动态发现 Manifest 和 CLI contribution；
- 短命令和 qualified command；
- operation payload 不透明传递；
- Run 等待终态；
- 未知命令稳定报错；
- CLI 测试不导入 Harmony 包。

Harmony 命令参数映射由 [`packages/harmony-audit/test/plugin.test.ts`](../../packages/harmony-audit/test/plugin.test.ts) 在插件包内验证。
