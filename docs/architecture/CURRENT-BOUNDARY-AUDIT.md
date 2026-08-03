# 当前架构边界审计

状态：通过  
审计日期：2026-08-03  
基线：`platform-plugin-boundary-v2`

## 结论

当前实现已经达到“通用 AI 助手 + 可插拔 LangGraph 多 Agent 插件”的目标边界。Harmony 插件可以从平台装配中移除，而不破坏 Core、Interface、Server、CLI 或内置对话助手的构建。

```text
apps/web + apps/cli
        -> apps/server / packages/interface
                -> packages/core
                -> Plugin Contract <- packages/harmony-audit
```

## 包级检查

| 范围 | 结论 | 说明 |
|---|---|---|
| `packages/core` | 通过 | 只包含 Pi 适配、Plugin Contract、MCP、通用子 Agent、滚动池、Skill 与 Graph 薄机制 |
| `packages/interface` | 通过 | 只处理通用助手、Plugin Host 和本地状态，不 import Harmony 类型 |
| `apps/server` | 通过 | 只提供通用 HTTP/SSE/Artifact/Web contribution 传输 |
| `apps/cli` | 通过 | 动态装载插件 CLI contribution，不静态注册审计命令 |
| `apps/web` | 通过 | 通用 Shell 不解释 Component、Capability、Finding 或审计状态 |
| `packages/harmony-audit` | 通过 | 项目解析、Atlas、五槽调度、审计状态机、事实与报告均封装在插件内 |
| `packages/dummy-plugin` | 通过 | 独立验证插件合同，不依赖审计实现 |

## 本次纠偏

- 删除未进入运行链路的旧 `ModelManager`，模型与认证统一由 Pi 官方配置管理；
- 删除重复的基础 Tool Registry，通用助手直接使用 Pi 工具体系；
- 删除已被 Plugin Host 替代的 `AgentKernel`/Registry 路由实现；
- 根 workspace 作为部署组合根声明当前安装的领域插件；各包的其他运行依赖仍由所有者 package 自行声明；
- 保留 Harmony 实际复用的领域无关 `McpManager`、`SkillManager`、`RollingAgentPool` 和 `GraphApplication`；
- 正式配置、Pi 会话、构建缓存和本地 pnpm store 均与可提交源码分离。

## 不构成边界泄漏的组合点

- 配置中的 `plugins.modules=["@agent-platform/harmony-audit"]` 是组合根的运行期选择，不是平台源码依赖；
- 根 `package.json` 安装 Harmony 插件是部署装配，不代表 Core、Interface 或应用服务静态依赖该插件；
- Harmony 调用 `PiSessionFactory`、`RollingAgentPool` 和 `GraphApplication` 是插件依赖通用机制，方向正确；
- Harmony Web 资源经 Plugin Web Contribution 暴露，Server 仅做受控静态传输；
- Host 的 `discoverRuns()` 是通用可选合同，目录扫描和重启修复规则仍由 Harmony Runtime 实现。

## 后续守护规则

1. 新领域能力必须建立独立 package 并实现 Plugin Contract；
2. 平台源码不得新增具体插件 ID 或领域数据结构判断；
3. Core 新增模型、认证、Session、基础工具能力前先验证 Pi 是否已提供；
4. 插件自己的图节点、并发上限、重试、状态库和报告不得提升到平台；
5. 合并前持续运行类型检查、合同测试和无领域 import 检查。
