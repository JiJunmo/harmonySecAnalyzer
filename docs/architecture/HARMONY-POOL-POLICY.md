# Harmony 五槽并发策略归属

状态：已完成  
通用调度器：[`packages/core/src/agent-pool.ts`](../../packages/core/src/agent-pool.ts)  
领域策略：[`packages/harmony-audit/src/pool-policy.ts`](../../packages/harmony-audit/src/pool-policy.ts)

## 1. 结果

Core `RollingAgentPool` 现在只实现领域无关的滚动补槽算法：

- capacity 必须由调用方显式提供；
- 只校验为正整数；
- 不设置默认容量；
- 不设置平台级最大容量；
- 继续保证 claim 不得超过空闲槽位、完成一个立即补一个和 stall 检测。

Core 可以运行容量 1、3、32 或其他由上层资源策略允许的值，不知道 Harmony 使用 5 槽。

## 2. Harmony 策略

鸿蒙插件集中定义：

```ts
HARMONY_DEFAULT_AGENT_CAPACITY = 5
HARMONY_MAX_AGENT_CAPACITY = 5
harmonyAgentCapacity(value)
```

该策略被以下领域入口共同使用：

| 位置 | 用途 |
|---|---|
| `HarmonyAuditPlugin` | 配置、Web/CLI payload 和 resume action 校验 |
| `HarmonyAuditOrchestrator` | Graph 与 MCP Session 容量装配 |
| `HarmonyAuditGraphPlugin` | 创建通用 Rolling Pool 前校验 |
| `AuditStore.claim()` | 即使调用者请求更多任务，也最多维持 5 个领域 running task |
| Harmony CLI contribution | 保持 `--capacity 1..5` 用户合同 |

因此 5 槽仍是端到端领域不变量，而不再是通用基础设施默认值。

## 3. 验收

Core 测试使用容量 3 验证滚动补槽，并单独验证容量 32 合法、0 和小数非法。测试中不再把 5 描述为平台 ceiling。

Harmony 测试验证默认值和最大值均为 5，容量 6 被领域策略拒绝。Graph、Store、Plugin 和现有审计回归测试继续通过。

