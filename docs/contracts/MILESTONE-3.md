# 里程碑 3：严格终态与确定性报告

状态：已完成  
完成日期：2026-07-31  
依赖：里程碑 1、里程碑 2、`audit-contract-v1`

## Run 终态

| 条件 | 状态 |
|---|---|
| 所有已派生任务完成，且无覆盖缺口 | `complete` |
| 存在 exhausted、uncertain entry、unresolved target 或未验证 Group | `complete_with_gaps` |
| Pool、Graph、Store 或报告构建发生不可恢复错误 | `failed` |

Graph 的 fail 节点和 finalize 异常均写回 `runs.status/error`。报告文件全部成功写入后才提交完成状态；报告失败不会产生虚假的 complete。

## 根因 Finding 归并

- local Operation Group 的根因键为其稳定 `group_id`。
- cross-component Group 的根因键为 `cross_component_groups.local_group_id`。
- 同一局部安全操作经多条入口或组件路径确认时只生成一个 Finding。
- `finding_causes` 保存全部 confirmed Validation。
- 严重性取全部 cause 中的最高等级；同级按稳定 Validation ID 选择代表详情。
- Finding 标题取局部根因 Group，不受模型对跨组件标题的措辞变化影响。

## Report Model

统一模型只读取规范化表，包含：

- Run、范围和任务状态统计。
- Entry 及覆盖状态。
- 跨组件 Path。
- local/cross Operation Group。
- Validation、反证和六维结论。
- 根因 Finding 及全部 cause。
- Evidence 与内容哈希。
- Coverage Gap。
- Entry → Group → Validation → Finding Attack Matrix。

明确禁止把 `tasks.result_json`、LangGraph checkpoint 或模型普通文本作为报告来源。

## 输出

```text
report.json
report.md
report.html
attack-matrix.json
```

所有数组按稳定 ID 排序；Report Model 不包含报告生成时间和可变 `updated_at/finalized_at`。相同 `run.db` 重复生成的文件必须完全一致。

每个文件先写入同目录临时文件，再用 rename 原子替换。全部临时文件写入成功后才开始替换，任何异常均清理尚存临时文件并保持 Run 可恢复。

## 验证覆盖

- 无缺口 Run 为 complete。
- exhausted、uncertain、unresolved 和 unvalidated 进入 complete_with_gaps。
- Pool 失败进入 failed 并保存错误。
- local/cross 两个确认结果归并为一个 Finding 和两个 cause。
- 根因采用最高严重性。
- Attack Matrix 覆盖 Entry、Group、Validation、Finding。
- JSON、Markdown、HTML 和 Attack Matrix 全部生成。
- 修改 `tasks.result_json` 后重建报告保持字节一致。
- 重复 finalize 输出保持字节一致。
