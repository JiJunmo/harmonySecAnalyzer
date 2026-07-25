# harmonySecAnalyzer 设计

## 1. 工作流

```text
JSON5 项目事实 + Atlas 全量索引
  -> 脚本生成组件分析单元与任务
  -> 组件语义分析并落盘实际操作组
  -> 六维验证只读取语义结果
  -> 根因 Finding + 漏洞证据路径
  -> 确定性报告
```

系统覆盖外部入口和实际可达的安全相关操作，不枚举所有代码路径，也不预先构造入口与敏感 API 的笛卡尔积。

## 2. 组件边界

| 组件 | 负责 | 不负责 |
|---|---|---|
| Project Profiler | 确定性解析 JSON5/Manifest，输出组件和入口候选 | 源码语义、漏洞判断 |
| Atlas Indexer | 审计前建立完整源码索引 | 项目配置解析、漏洞判断 |
| Analysis Unit Builder（Python） | 按 `component_id` 归并 Manifest 候选，按 module 归并动态入口候选，并直接创建组件任务 | 判断候选是否形成真实源码入口 |
| Component Semantic Analyzer | 使用 Atlas 确认入口、追踪外部数据、归并实际操作并记录防护事实 | 漏洞分类、六维判断、生成报告 |
| Exploitability Validator | 只根据已落盘语义结果执行六维判断和反证分析 | 查询 Atlas、读取项目源码、补写语义事实 |
| Audit Runtime | 任务、事务、协议校验、确定性 ID、根因归并、报告准入 | 理解源码语义 |
| Atlas MCP | 符号、调用、变量传播和影响证据 | 审计状态管理 |

## 3. 分析单位

分析单元代表一个待检查的 Ability/ExtensionAbility 组件，或一个 module 级动态入口调查范围。JSON5 中的不同触发渠道作为候选 facets 输入，同一组件只生成一个组件分析任务。facet 是脚本事实，不表示入口已经得到 AI 确认。

每个分析单元先创建一个语义任务，完成入口确认、实际操作收集、等价操作归并和覆盖记录。语义结果存在操作组时，再创建一个六维验证任务。普通代码分支不会生成额外任务。

Operation Group 是语义分析的核心单位。只有以下任一项真实不同才拆组：

1. 敏感操作源码位置。
2. 进入操作的关键受控参数集合。
其余代码分支合并到同一组的 `branches` 中。观察到的防护代码和业务上下文作为事实保存，不在语义阶段判断其有效性或是否越界。每组保存一条从入口到操作和影响的最短证据链。

## 4. 安全判断

每个操作组先检查业务意图、有效防护和其他反证，再逐项记录六维结论：外部可达、关键参数可控、到达敏感操作、防护缺失或可绕过、安全边界被突破、存在具体影响。

六维是统一判断框架，不要求每个操作组六项都满足。只有 `confirmed_vulnerability` 必须六项全真、没有有效反证，并包含 operation 和 effect 事实。有效防护为 `protected_exposure`；公开业务且未越界为 `benign_business_flow`；现实风险缺关键证据为 `residual_risk`；证据不足为 `insufficient_evidence`。

模式卡保留为审计能力设计和人工维护知识，不自动注入语义或验证 Task。运行时六维判断只依赖已落盘语义事实和固定验证契约。

Finding 根因只使用操作位置、关键受控参数和安全边界。入口别名、普通分支、能力 ID 和模式 ID 不制造新根因。只有已确认漏洞和残余风险生成报告中的攻击路径；有效防护和正常业务保留为覆盖证明。

## 5. 调度与状态

任务流水线为：

```text
component_semantic_analysis -> exploitability_validation
```

Python 初始化时为每个分析单元创建语义任务。语义提交通过后先原子落库；有操作组时立即创建同组件的验证任务。验证输入由已落盘语义结果和脚本据此生成的限定源码范围组成，不加载项目模型或模式卡。验证 Agent 可以定点读取相关实现并使用 Atlas 核实调用链，但禁止全仓搜索和新增操作组。空操作组不创建验证任务。

`run.db` 是唯一可变事实源。Agent 只写私有 submission；运行时在每批任务返回后统一检查文件，校验 JSON Schema、证据引用、操作事实、组身份和六维一致性，并在事务中落库。编排 Agent 不解析 worker 回复，也不逐项决定提交或失败。缺失或无效结果最多尝试三次，耗尽后只记录当前任务缺口；固定的模型服务或 MCP 故障不由项目增加复杂兜底。

报告准入要求：没有 queued/running 任务。未完成任务、缺少语义分析的入口和缺少六维验证的操作组进入覆盖缺口，但不阻止报告生成。入口确认状态保存在组件任务的 coverage 中。旧版数据库不迁移，Schema 版本不一致时明确拒绝恢复。

## 6. 运行产物

```text
<run_dir>/
  run.db
  session.json
  project/project_model.json
  tasks/<task>.json
  tasks/<task>.result.json
  exports/entries.json
  exports/semantic_analyses.json
  exports/operation_groups.json
  exports/validation_results.json
  exports/evidence_paths.json
  exports/attack_matrix.json
  exports/tasks.json
  findings.json
  report_model.json
  report.md
  report.html
  report_snapshot.json
```

JSON、Markdown 和 HTML 全部从 SQLite 重建。HTML 仍提供概览、攻击路径、项目结构、覆盖与缺口四个中文视图；其中攻击路径只展示 actionable Finding 的证据链。

## 7. 扩展原则

新增审计能力优先扩展 capability profile；模式卡用于维护该能力的设计知识。只有语义事实或六维契约发生变化时才修改运行时。Native/NAPI 当前不在范围内。
