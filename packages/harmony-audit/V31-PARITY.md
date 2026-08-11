# v3.1 行为等价清单

基线目录：`/Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer-v3.1`。

比较外部行为和安全事实，不要求 Python 与 TypeScript 文件一一对应。忽略 run ID、时间戳、数据库内部行号和排版；必须比较范围、任务、关系、分类、覆盖缺口、根因和恢复结果。

## 已对齐

| 领域 | 状态 | 说明 |
|---|---|---|
| Capability Registry | 已对齐并扩展 | 保留 v3.1 的 21 项能力标识与领域语义；v3.2 已实现原 6 项 planned 和 2 项 deferred，并增加项目级分析单元、能力专用指导与组件/项目分流。空过滤展开全部 enabled，显式过滤拒绝 unknown。 |
| Semantic/Validation/PoC Schema | 已对齐 | 三份 Agent submission Schema 与 v3.1 文件内容一致（内联证据模型）。 |
| 证据契约 | 已对齐 | 三阶段统一为内联证据：模型不创建证据 ID、不输出顶层 `evidence` 目录；运行时按内容哈希编号去重并落 `evidence_refs` 连接表；验证阶段 `semantic_refs` 只能引用本组 `evidence_scope.admissible`，hypothesis-only 证据不可支撑结论；PoC `evidence_refs` 只能引用继承证据，每个 `symbol_ref` 必须携带内联证据。作用域 ID 使用 local id（v3.2 有意分叉，全局 id 仍由 local→global 映射，行为等价）。错误码统一为大写枚举。 |
| Project Profiler 主模型 | 已对齐并扩展 | JSON5、构建模块、组件、入口和依赖语义保持一致；v3.2 增加生成元数据和权限投影。 |
| 初始范围 | 已对齐并扩展 | Component 过滤优先；Capability 模式按 `analysis_scope` 分流，组件能力分析全部 Manifest 组件，项目能力进入唯一项目级分析单元。`entry_types` 只作为 Agent 的常见入口优先提示，不排除组件。 |
| 组件任务单位 | 已对齐 | 同一组件的 Manifest 候选归为一个语义任务；下游组件按已证明调用扩展。 |
| Agent 任务文档 | 已对齐 | 注入 entry facets/project candidates、`capability_id/title/domain`、analysis contract、组件目录、upstream context 和 previous error。 |
| Runtime Normalization | 已对齐 | 修正 entry、能力 domain、受控属性、等价 Group/Call、参数映射和空白验证字段；Operation Fact 携带组证据，edges 由运行时在落库物化时从有序 facts 确定性重建。 |
| 阶段顺序 | 已对齐 | 全部语义任务与确定性关联收敛后才规划六维验证。 |
| 验证准入 | 已对齐 | 非根组件局部 Group 不单独验证；外部根本地 Group 和跨组件 Group 才验证。 |
| 五槽并发/三次尝试 | 已对齐 | 插件拥有 1–5 容量策略，默认/上限为 5；单任务最多三次。 |
| 跨组件事实 | 已对齐 | 参数控制状态、主体绑定、权限、检查、循环和多来源路径确定性组合。 |
| 六维/Finding | 已对齐 | 双射、六维、反证、边界、主体、DoS 和根因归并由运行时校验。 |
| 恢复事实源 | 已对齐 | `run.db` 可独立恢复、重建报告；LangGraph checkpoint 不承载结论。 |
| 增量审计 | 已对齐 | 内容哈希、Git 范围、模块反向依赖、入口/调用方失效、语义重新验收、验证指纹复用、风险变化与无缺口基线推进均已迁移。 |
| 详细 HTML/Markdown 报告 | 已对齐并扩展 | 已提供概览、Finding、组件、路径、项目和覆盖视图；增量运行同步展示变化范围与风险变化。 |

## 尚未完全对齐

| 缺口 | 影响 | 后续实现 |
|---|---|---|
| 完整运行导出集合 | 当前核心事实存在于 `run.db` 和精简 Report Model，但缺少 v3.1 的 `exports/*.json`、`findings.json`、`report_snapshot.json` 等同名产物 | 从规范表构建同结构只读导出，不读取 `tasks.result_json`。 |
| 固定 v3.1 快照夹具 | 现有 40 个插件测试覆盖主要不变量，但还没有逐场景同时运行 Python/TS 并比较规范快照 | 建立最小 ArkTS fixtures 和跨版本 snapshot harness。 |

## 当前结论

全量与增量主链路已经按 v3.1 的领域契约重新收敛。当前剩余等价工作是同名细粒度导出兼容和跨版本固定快照验收；五槽滚动补槽是 v3.2 已确认的调度策略，不再作为待迁移缺口。新增平台 Trace、Web Contribution 和 Pi Session 接入属于承载层扩展，不应改变本表中的审计事实。

证据契约迁移的行为说明：契约哈希随 schema/SKILL 变更自动失效旧增量基线（全量重审）；运行中被 resume 的旧契约验证任务输入（无 `evidence_scope`）会因空 admissible 作用域被拒，三次耗尽后以 coverage gap 呈现，属预期迁移行为。
