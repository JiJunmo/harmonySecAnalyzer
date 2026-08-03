# 里程碑 0：审计契约基线

状态：已冻结  
契约版本：`audit-contract-v1`  
目标数据库版本：`run.db schema v2`  
冻结日期：2026-07-31

## 1. 范围

本里程碑只冻结后续 P0 实现必须遵守的事实、状态、标识符、校验和迁移契约，不在本阶段迁移运行时代码。

配套文档：

- [RUN-DB-V2.md](RUN-DB-V2.md)：规范化事实模型、数据来源和迁移规则。
- [INVARIANTS.md](INVARIANTS.md)：状态机、业务不变量、稳定错误码和测试目录。
- [V31-EQUIVALENCE.md](V31-EQUIVALENCE.md)：v3.1 固定场景及等价判定。

## 2. 权威数据来源

| 数据 | 权威来源 | Agent 是否可声明 | 确定性代码职责 |
|---|---|---:|---|
| 模块、组件、Manifest 入口 | Project Profiler | 否 | 解析、稳定编号、诊断 |
| 源码位置、符号、调用关系 | Atlas | 可引用 | 校验引用、保存证据摘要/哈希 |
| 局部语义事实 | Semantic Agent | 是 | 校验任务上下文并规范化入库 |
| 跨组件传播链 | 关联引擎 | 否 | 参数、控制状态、主体与权限传播 |
| 六维验证候选 | Validation Agent | 是 | 一一对应和领域不变量校验 |
| Finding | Finding Builder | 否 | 仅从已接受 Validation 确定性生成 |
| Run/Task 状态 | Audit Runtime | 否 | 事务迁移、租约、重试、恢复 |
| 报告与 Attack Matrix | Report Builder | 否 | 只从规范化事实表重建 |
| LangGraph 游标 | graph.db | 否 | 仅控制恢复，不作为审计事实 |

冲突裁决顺序：确定性配置事实 > 已持久化 Atlas 证据 > Agent 候选描述。Agent 不得覆盖 Project Model、任务上下文或确定性关联结果。

## 3. 版本边界

当前实现属于 `run.db schema v1`，只包含基础 `runs/tasks/analysis_units/findings/events` 表。P0 实现目标为 schema v2。

`project-model.schema.json` 已描述目标 Project Model v2，但当前 Profiler 仍输出精简模型，且状态使用 `complete/incomplete`。在 P1 项目建模完成前：

1. schema v2 数据库不得假定目标 Project Model 的可选字段已经存在。
2. 初始化器必须记录实际 Project Model 版本；无法识别时拒绝初始化。
3. 不允许把当前精简对象标记为 Project Model schema v2。
4. Project Model 升级独立于 run.db 迁移，但迁移结果必须记录两者版本。

## 4. 确定性 ID

统一算法：

```text
ID = PREFIX + "-" + first16hex(SHA-256(canonical-json(identity tuple)))
```

`canonical-json` 要求对象键按 Unicode 码点升序、数组保持业务顺序、路径转为仓库相对 POSIX 路径、禁止时间戳和绝对报告目录进入 identity tuple。

| 实体 | 前缀 | identity tuple |
|---|---|---|
| Module | `MOD` | `[module_file, module_name]` |
| Component | `CMP` | `[module_id, kind, name, src_entry, declaration_index]` |
| Entry | `PE` | `[component_id, entry_type, normalized_location]` |
| Entry Facet | `FACET` | `[entry_id, facet_type, canonical_payload]` |
| Task | `TASK` | `[run_id, semantic_key]` |
| Semantic Analysis | `SEM` | `[run_id, task_id, accepted_attempt]` |
| Evidence | `EV` | `[run_id, source, kind, normalized_location, content_sha256]` |
| Component Call | `CALL` | `[semantic_analysis_id, call_key]` |
| Operation Group | `GRP` | `[semantic_analysis_id, group_key]` |
| Validation | `VAL` | `[validation_task_id, group_id]` |
| Finding | `FIND` | `[run_id, root_cause_key]` |
| Event | 自增整数 | 不作为跨运行稳定引用 |

同一 run 内 identity tuple 冲突但内容不同必须拒绝为 `IDENTITY_COLLISION`，不得用 `INSERT OR REPLACE` 静默覆盖。

## 5. 完成定义

里程碑 0 的文档验收条件：

- 每个目标事实实体均有主键、外键、唯一约束和数据来源。
- Run/Task 的所有合法迁移均已列出，未列出的迁移默认非法。
- 每条 P0 不变量均有稳定错误码、正例测试和反例测试描述。
- v3.1 等价场景覆盖单组件、跨组件、DoS、降级、重试、范围过滤和报告映射。
- schema v1 到 v2 的迁移与失败回滚规则已冻结。

以上条件由三份配套文档满足。对契约的破坏性修改必须提升 `audit-contract` 版本，并记录迁移影响。
