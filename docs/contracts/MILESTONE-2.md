# 里程碑 2：跨组件确定性关联

状态：已完成  
完成日期：2026-07-31  
依赖：里程碑 1、`audit-contract-v1`

## 已交付

- `component_paths` 将跨组件路径保存为 run.db 事实，使用稳定 fingerprint 去重。
- `cross_component_groups` 记录确定性路径与局部 Operation Group 的派生关系。
- 参数链按 `source_property → target_property` 逐跳合成，只连接属性连续的映射。
- Control State 确定性收敛：`unknown` 保留不确定性，`constant` 切断控制，`constrained` 保留约束，全部 preserved 才保持 preserved。
- 传播并区分 Origin Principal、Immediate Caller、Target Observed Principal、Origin Binding 和 Authority Used。
- 调用路径上的安全及权限检查记录来源组件与 hop，并确定其是否约束原始主体。
- 从路径和下游局部 Group 确定性生成跨组件 Group，受控属性回映射到根入口属性。
- 多来源调用同一目标时只保留一个语义任务，同时合并多条独立路径。
- 目标组件已完成后出现新来源时，无需重新执行语义 Agent，直接从既有局部事实生成跨组件 Group 和增量验证任务。
- 路径遇到已访问组件时标记 cycle、保存事实，但不再创建语义任务，保证有界收敛。
- 跨组件 Validation 必须提交与确定性 principal state 一致的 `principal_analysis`。

## 路径状态示例

```json
{
  "component_ids": ["CMP-A", "CMP-B", "CMP-C"],
  "parameter_chains": [{
    "origin_property": "want.input",
    "current_property": "query",
    "control_state": "constrained",
    "transforms": ["none", "allowlist"]
  }],
  "principal_state": {
    "origin_principal": "external",
    "immediate_caller": "CMP-B",
    "target_observed_principal": "component-B",
    "origin_binding": "replaced_by_caller",
    "authority_used": "source_component"
  },
  "cycle": false
}
```

## 验证覆盖

- 单跳与多跳属性映射。
- constrained Control State 收敛。
- 身份替换和委托风险。
- 权限检查是否约束 origin。
- 两个来源汇聚到一个目标组件。
- A → B → A 循环截断。
- 跨组件 Group 持久化和外键完整性。
- principal analysis 正反校验。

## 后续边界

- 根因级 Finding 归并、Attack Matrix 和完整证据链展示属于里程碑 3。
- 恢复后重新调度路径关联和旧数据库迁移属于恢复里程碑。
