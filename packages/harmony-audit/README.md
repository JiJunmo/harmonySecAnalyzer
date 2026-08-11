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
- 语义 Agent 只提取源码事实，到真实的 Manifest 组件调用边界停止，不进行漏洞判断；继承、`super`、helper 和有源码的依赖实现仍属于当前组件调用链，名称或注释产生的效果推断必须进入 `effect_hypotheses`，不能冒充事实。
- 运行时只归并能力、操作位置、受控对象、主体/业务语义、直接效果和适用防护均一致的 Operation Group，并确定性生成 Fact Edge。
- 所有语义任务及组件关联收敛后，才允许规划六维验证任务。
- 语义阶段分别确认组件输入和真实外部入口；只有确认过候选 ID 的外部入口可作为路径起点。
- 能力模式按 `analysis_scope` 选择组件级或项目级分析单元；`entry_types` 只是常见入口优先提示，不排除组件。
- 跨组件连接分别传播调用触发控制和真实参数映射；无参数但调用受控的链路可进入验证，常量、独立或未知控制不会扩展。
- 最大并发固定为 5；六维验证按 Operation Group 一组一任务调度。单任务最多尝试 3 次，失败只影响该组。
- 排队或执行中的验证组属于待处理进度，不计入 Coverage Gap；只有终态任务中缺少验证结果的组才形成缺口。
- 六维每一项使用 `true/false/unknown` 三态并绑定理由、证据等级和证据引用；`true` 和 `false` 均须有对应证据，缺少证明使用 `unknown`。基础路径被明确反证时使用 `no_exploitable_path`，确认漏洞还必须由本轮验证证据证明“受控值使用 → 安全行为变化 → 受保护操作 → 具体影响”。
- 六维验证可以读取当前操作组定性所需的全部调用链源码；限制的是发现新的独立操作和另建路径，不是源码读取范围。
- PoC 可信状态由运行时管理：当前通过静态契约的产物标记为 `generated_unverified`，不能由 Agent 自行声明已经编译或真机验证；PoC 失败不计作审计覆盖缺口。
- Agent 只提交候选结果；Schema、领域不变量、规范化、落库和报告均由运行时完成。

## 包内边界

| 模块 | 所有权 |
|---|---|
| `project/` | JSON5/Manifest 确定性建模 |
| `atlas.ts` | Atlas 索引与任务私有 MCP Profile |
| `resources/skills/` | 两类领域 Agent 契约 |
| `runtime/task-context.ts` | 从规范状态构造不可变 Agent 任务文档 |
| `validation/` | Schema、规范化和领域不变量 |
| `correlation/` | 跨组件调用触发、参数、主体、权限和路径组合 |
| `runtime/store.ts` | SQLite 状态机、事务、调度与恢复 |
| `reporting/` | 只读事实到报告模型和产物 |
| `plugin.ts` | 通用 Plugin Contract 适配，不承载审计规则 |

## v3.1 等价状态

全量与增量主链路已经完成迁移并可用。详见 [V31-PARITY.md](V31-PARITY.md)；剩余同名细粒度导出和固定快照 harness 属于兼容性验收增强，不阻塞当前插件使用。
