# 里程碑 1：规范化存储与确定性校验

状态：已完成  
完成日期：2026-07-31  
依赖契约：`audit-contract-v1`

## 已交付

- 新运行直接创建 `run.db schema v2`，打开数据库时强制检查版本。
- 建立 Entry/Facet、Semantic、Evidence、Component Call、Parameter、Operation Group、Fact、Edge、Security Check、Validation、Counter Evidence、Finding Cause 等规范化表。
- Semantic 与 Validation 提交在单个 SQLite 事务中完成校验、事实写入、派生任务和任务完成迁移。
- Store 边界再次执行 Draft 2020-12 Schema 校验，不依赖调用方一定经过 Pi Runtime。
- 实现任务/入口一致性、Evidence 引用、Fact Edge、Capability 范围与分类、目标组件、Validation 双射、confirmed、降级和 DoS 不变量。
- 使用稳定错误码拒绝非法提交；拒绝时事实表保持不变，任务进入有限重试。
- Evidence 使用内容哈希和确定性 ID；冲突内容以 `IDENTITY_COLLISION` 拒绝。
- exhausted 任务使 Run 最终进入 `complete_with_gaps`，并进入报告缺口列表。
- 多来源调用到尚未执行的下游任务时合并 `upstream_calls`，不再由 `INSERT OR IGNORE` 丢失 queued 任务上下文。

## 明确保留到后续里程碑

- 多跳 Control State、Principal、Permission 和 Confused Deputy 的全局收敛：里程碑 2。
- 完整确定性报告与 Attack Matrix：里程碑 3。
- v1 数据库离线迁移命令和 CLI resume：里程碑 4；本里程碑冻结迁移契约但不提供旧 Run 原地升级入口。
- Project Model v2 的完整 Profiler：里程碑 4。

## 验证门槛

```text
pnpm check
pnpm test
```

必须覆盖：合法规范化写入、外键检查、Schema 拒绝、上下文拒绝、Evidence/Edge 拒绝、Capability 拒绝、Validation 双射、confirmed/降级/DoS、事务回滚和 exhausted 状态。
