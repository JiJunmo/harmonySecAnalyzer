# HarmonyOS 白盒安全审计插件

`@agent-platform/harmony-audit` 是独立领域插件。通用助手只负责发现、激活和承载插件；HarmonyOS 项目解析、Atlas、任务契约、编排状态、五槽并发、路径关联、六维验证、事实库和报告全部由本包拥有。

## 逻辑基线

领域行为以 `harmonySecAnalyzer-v3.1` 为兼容基线：

```text
Project Profiler + Atlas Index
  -> component_semantic_analysis（一个组件一个任务）
  -> deterministic_component_correlation
  -> exploitability_validation（六维判断）
  -> root-cause findings
  -> deterministic reports
```

约束：

- `run.db` 是审计状态与事实的唯一可变事实源；`graph.db` 只保存控制游标。
- 语义 Agent 只提取事实，到组件边界停止，不进行漏洞判断。
- 运行时根据操作位置和受控属性归并 Operation Group，并确定性生成 Fact Edge。
- 所有语义任务及组件关联收敛后，才允许规划六维验证任务。
- 只有外部根入口可达的本地组和确定性连接的跨组件组进入六维验证。
- 最大并发固定为 5；单任务最多尝试 3 次，失败只耗尽该任务。
- Agent 只提交候选结果；Schema、领域不变量、规范化、落库和报告均由运行时完成。

## 包内边界

| 模块 | 所有权 |
|---|---|
| `project/` | JSON5/Manifest 确定性建模 |
| `atlas.ts` | Atlas 索引与任务私有 MCP Profile |
| `resources/skills/` | 两类领域 Agent 契约 |
| `runtime/task-context.ts` | 从规范状态构造不可变 Agent 任务文档 |
| `validation/` | Schema、规范化和领域不变量 |
| `correlation/` | 跨组件参数、主体、权限和路径组合 |
| `runtime/store.ts` | SQLite 状态机、事务、调度与恢复 |
| `reporting/` | 只读事实到报告模型和产物 |
| `plugin.ts` | 通用 Plugin Contract 适配，不承载审计规则 |

## v3.1 等价状态

全量与增量主链路已经完成迁移并可用。详见 [V31-PARITY.md](V31-PARITY.md)；剩余同名细粒度导出和固定快照 harness 属于兼容性验收增强，不阻塞当前插件使用。
