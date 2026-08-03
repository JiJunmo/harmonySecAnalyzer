# 通用助手能力管理

状态：已实现  
完成日期：2026-08-03

## 边界

能力管理分为两种事实源：

- Skills、Extensions、Pi Packages：Pi 官方 `settings.json`；
- MCP Server：`agent-platform.json`，因为 Pi 官方不提供 MCP。

平台不复制 Skill 或 Extension 元数据。查询时通过 Pi `DefaultResourceLoader` 获取实际加载结果、来源和诊断，通过 `DefaultPackageManager` 获取 Package 安装状态。

## 行为

- 展示 Skill、Extension、Package 和 MCP Server；
- 区分已启用、已加载和加载错误；
- Skill/Extension 停用使用 Pi 官方资源排除项并写回 `settings.json`；
- Package 停用使用 Pi 官方 `autoload: false`，不会卸载文件；
- MCP 启停写回 Server 条目的 `enabled` 字段；
- 启用 MCP 时立即连接并检查工具名冲突；
- 配置变化从新建会话开始生效，既有会话保留创建时的能力快照。

管理接口不提供任意路径或任意 Package 安装。它只能切换 Pi 已发现或已配置的资源，避免 Web 请求变成不受约束的软件安装入口。
