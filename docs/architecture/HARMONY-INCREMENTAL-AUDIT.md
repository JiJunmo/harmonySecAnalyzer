# Harmony 增量审计

状态：已实现  
完成日期：2026-08-03

## 设计边界

增量审计完全属于 Harmony 白盒安全审计插件，不进入通用助手、Plugin Host 或平台 Run 数据模型。它复用原有 Project Model、路径发现、确定性关联、六维验证、`run.db` 和报告链路，不创建第二套审计流程。

## 执行流程

```text
完整无过滤审计成功
  -> reports/incremental-baseline/
       baseline.json
       project-model.json
       semantic-results.json
       validation-results.json
       findings.json

后续 --incremental
  -> 重新生成 Project Model 与文件内容哈希
  -> 比较 Git 提交范围和工作区变化（非 Git 项目使用同一内容哈希）
  -> 入口定义、模块反向依赖、组件源码和历史调用方失效分析
  -> 受影响入口进入原语义 Agent 队列
  -> 未受影响语义结果经当前 Schema/领域不变量重新验收后导入 run.db
  -> 重新执行确定性跨组件关联
  -> 操作组安全指纹一致时复用六维验证，否则进入原验证 Agent 队列
  -> 生成完整报告和风险新增/变化/消失/未变化对比
  -> 仅在 complete 且无过滤时推进下一版基线
```

## 基线有效性

基线记录所有可追踪源码和配置文件的 SHA-256、Project Model、语义提交、验证提交、风险快照、Git 根与提交以及审计契约哈希。审计契约哈希覆盖 Capability Registry、两份提交 Schema 和两份内置 Skill。

以下情况拒绝增量执行并要求重新全量审计：

- 基线不存在或结构不完整；
- 审计契约发生变化；
- 项目从 Git 切换为非 Git，或反向切换；
- Git 仓库发生变化；
- 基线提交不再是当前提交的祖先；
- 请求同时包含 Component 或 Capability 过滤。

## 复用约束

历史结果不会绕过当前运行时直接复制事实表。语义提交会重写当前 `task_id/entry_id`，再经过当前 Schema、Capability、Evidence、Component Call 和领域不变量校验，通过原子事务写入规范事实表。

六维验证复用要求当前入口语义来自已验收的基线，并且本次所有待验证 Operation Group 的安全相关指纹与基线完全一致。复用提交同样重写当前 Group ID，再经过六维双射、证据、边界、主体、DoS 和 Finding 规则校验。

复用任务使用 `attempts=0` 并产生 `semantic_result_reused` 或 `validation_result_reused` 事件。验收失败会产生 `*_reuse_rejected` 事件并自动回退到正常 Agent 队列，不会静默丢失覆盖。

## 报告与恢复

每个增量 Run 的 `incremental/` 目录保存冻结的 `change-set.json`、`impact-plan.json` 和本次使用的三类基线快照，恢复时不重新计算变化范围。Report Model、Markdown 和 HTML 同步展示变化文件数量、受影响/复用入口和风险路径变化。

`run.db` 仍是本次 Run 的唯一事实源；全局增量基线只是下一次 Run 的只读输入。失败、取消、范围过滤或 `complete_with_gaps` 不推进基线。
