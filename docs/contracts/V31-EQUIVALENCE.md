# v3.1 等价样本与预期输出

## 1. 基线来源

对照基线来自相邻 `harmonySecAnalyzer-v3.1/tests` 中的确定性运行时和 Project Profiler 测试。v3.2 不复制 Python 实现，只冻结可观察语义。

比较时忽略：run ID、时间戳、绝对临时目录、数据库内部行号和报告排版。必须比较：实体数量、稳定关系、分类、状态、覆盖缺口和根因集合。

## 2. 固定场景矩阵

| 场景 ID | 输入 | 必须产生的事实 | 最终状态 |
|---|---|---|---|
| `EQ-SCOPE-001` | 两个组件，仅选择一个组件 | 只创建选中入口的初始 semantic task | `complete` |
| `EQ-SEM-001` | 单 deeplink 到数据库操作 | 1 Semantic、1 Group、完整 Fact/Edge/Evidence | `complete` |
| `EQ-VAL-001` | 六维全真且无有效防护 | 每 Group 1 Validation、1 confirmed Finding | `complete` |
| `EQ-VAL-002` | 有效安全检查 | `protected_exposure`，无 Finding，保留反证 | `complete` |
| `EQ-VAL-003` | 缺外部可达证据 | `insufficient_evidence` 或 `residual_risk`，含 gap | `complete` |
| `EQ-DOS-001` | 外部 count 驱动无界任务创建 | availability group、DoS 专项分析、confirmed Finding | `complete` |
| `EQ-DOS-002` | 仅存在 SQL/文件/Web 风险，无不可用影响 | DoS 不得 confirmed，记录语义不匹配 | `complete` |
| `EQ-CALL-001` | A 调 B，参数控制性保持 | B task 携带确定性 upstream context，构造跨组件链 | `complete` |
| `EQ-CALL-002` | A/C 同时调 B | B 合并两条来源路径，不漏失、不重复任务 | `complete` |
| `EQ-CALL-003` | A → B → A | 有界收敛，不无限创建任务或 Group | `complete` |
| `EQ-PRINCIPAL-001` | A 以自身身份调用 B | origin 与 observed principal 分离，可识别委托风险 | `complete` |
| `EQ-RETRY-001` | 前两次执行失败，第三次成功 | attempts=3，只有一次规范事实提交 | `complete` |
| `EQ-RETRY-002` | 三次均失败 | task exhausted，报告列出影响范围 | `complete_with_gaps` |
| `EQ-IDEM-001` | 重放同一 accepted submission | 实体数和 Finding 数不变 | `complete` |
| `EQ-REPORT-001` | 删除 graph.db 后重建报告 | Attack Matrix 和 Finding 根因集合不变 | 原状态不变 |

## 3. 每个场景的比较快照

快照统一使用下列结构，按 ID 排序：

```json
{
  "run_status": "complete",
  "counts": {
    "entries": 0,
    "semantic_analyses": 0,
    "component_calls": 0,
    "operation_groups": 0,
    "validation_results": 0,
    "findings": 0,
    "exhausted_tasks": 0
  },
  "entry_group_validation_finding": [],
  "cross_component_paths": [],
  "coverage_gaps": [],
  "root_causes": []
}
```

禁止直接比较 v3.1 与 v3.2 的随机 run ID。若旧版 ID 算法不同，通过业务键映射后比较实体关系。

## 4. 固定输入资产计划

后续实现测试时在 `packages/harmony-audit/test/fixtures/equivalence/` 建立最小 ArkTS 工程：

```text
single-deeplink/
protected-operation/
dos-unbounded-allocation/
dos-semantic-mismatch/
multi-source-component-call/
component-cycle/
confused-deputy/
```

每个 fixture 必须包含：

- 最小 `module.json5` 和相关 ArkTS 源码。
- 固定 Project Model 快照。
- 固定 Semantic submission。
- 固定 Validation submission。
- 期望的规范化事实快照。

Atlas/模型端到端测试可使用同一工程，但契约测试必须使用固定 submission，确保不受模型随机性影响。

## 5. 等价验收

P0 合并门槛：

1. 上表全部场景具有固定 fixture 和快照。
2. v3.2 的实体关系、分类、状态和覆盖缺口符合本文件预期。
3. 与 v3.1 基线存在差异时，必须记录为已批准的契约变更，而不是更新快照掩盖差异。
4. 真实 Atlas/模型回归仅作为补充，不替代确定性契约测试。
