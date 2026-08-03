# 本地网关可靠性

## 定位

Agent Platform 按仅监听本机的单机网关设计。本能力不引入账号、租户、HTTPS 终止、远程队列或分布式 Worker，只保证本机进程重启后的记录连续性、状态诚实性和可诊断性。

## 状态分层

| 数据 | 持久化位置 | 重启行为 |
|---|---|---|
| 普通助手对话 | Pi 官方 Session 文件 | 由 `PiSessionFactory` 恢复 |
| 平台 Plugin Job 索引 | `<dataDirectory>/gateway.db` | 保留原 Job ID、插件引用和最后快照 |
| 通用子 Agent 与 Trace | `<dataDirectory>/gateway.db` | 历史保留；queued/running 转为 `aborted / gateway_restarted` |
| Harmony 审计事实 | 项目 `reports/harmony-audit-*/run.db` | 插件扫描 `allowedRoots` 自动发现；孤儿 running Run 转为 failed/recoverable，running task 回到 queued |
| Harmony 报告 | 对应审计 Run 目录 | 平台清理永不自动删除 |
| 本地结构化日志 | `<dataDirectory>/gateway.log` | JSON Lines；启动时超过上限轮换为 `.1` |

平台数据库只保存索引和通用 Trace，不复制插件领域事实。Harmony 历史发现由 Harmony 插件实现，平台不理解 `reports` 或 `run.db` 布局。

## 配置

```json
{
  "reliability": {
    "dataDirectory": ".agent-platform",
    "retentionDays": 90,
    "maxHostRuns": 500,
    "maxSubagentRuns": 500,
    "logMaxBytes": 10485760
  }
}
```

相对目录以 `agent-platform.json` 所在目录解析。启动时和调用 `POST /api/reliability/actions/prune` 时，只删除超过保留期或数量上限的终态 Job/子 Agent 记录；运行态记录和插件报告不被删除。

Harmony 插件默认开启历史发现，可使用 `discoverHistory=false` 关闭，并以 `historyMaxRuns` 限制单次采用的最大历史 Run 数量。

## 中断恢复语义

网关无法安全恢复模型生成中的内存上下文，因此通用子 Agent 被诚实地关闭为 aborted。Harmony 审计的任务事实和输入位于 `run.db`，启动发现时会把孤儿运行标记为 failed/recoverable，并将已领取但未提交的任务退回 queued；用户执行 Resume 后由现有恢复不变量继续运行。

## 本地诊断

`GET /api/reliability` 返回状态库与日志路径、文件大小、平台 Job/子 Agent 数量、保留策略、最近启动和清理时间。`GET /api/health` 只返回精简的可靠性状态与计数。HTTP 错误和插件生命周期事件写入脱敏 JSONL 日志，日志失败不会导致网关退出。
