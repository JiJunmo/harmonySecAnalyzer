# harmonySecAnalyzer 设计

## 1. 核心模型

系统采用入口驱动的证据流：

```text
Audit Preparation & Entry Modeling
  -> Project Model + Atlas Index + Canonical Entry Ledger
  -> Local Flow Segment / Continuation
  -> Closed Evidence Path
  -> Security Assessment (Pattern Recognition + Six-Dimensional Validation)
  -> Root Cause Finding
  -> Deterministic Report
```

模式不能制造执行路径；危险 API 文本命中不能代替可达性；外部可达不能代替攻击者控制；敏感调用不能代替安全影响。

第一个大流程“审计准备与入口建模”包含三个内部组件：Project Profiler 确定性解析 JSON5，Atlas Indexer 准备完整索引，Entry Resolver 使用 Atlas 将配置候选确认为 Canonical Entry、排除项或缺口。三者共同输出可直接供路径发现使用的入口账本；任一候选尚无唯一 disposition 时，该流程未完成。它们属于同一前置流程，但实现和测试保持独立。

## 2. 组件边界

| 组件 | 负责 | 不负责 |
|---|---|---|
| Project Profiler | JSON5/Manifest 的确定性事实和候选账本 | 源码扫描、入口实现、漏洞判断 |
| Entry Resolver | 将配置候选确认为入口、排除项或缺口；归一化外部触达和 dispatcher 分支 | 下游漏洞路径 |
| Flow Analyzer | 从指定入口或 continuation 构建局部 Flow 段和结构化 continuation | Guard 有效性、业务合理性、漏洞判断 |
| Security Assessor | 基于完整 Path 识别真实安全场景，并执行六维有效性验证 | 路径发现、状态管理、根因归并 |
| Flow Runtime | 事务、去重、依赖、准入、导出和报告 | 源码语义判断 |
| Atlas MCP | 项目符号、调用与变量路径证据 | 审计状态管理 |

Agent 只提交当前任务的 JSON。中央状态、ID、任务派生、根因聚合和报告全部由确定性 Python 运行时负责。

## 3. 数据语义

Canonical Entry 的身份包含入口符号与安全相关判别符，例如 IPC transaction code、CommonEvent event name、URI route、Want flow 或 Provider operation。Manifest 别名若共享同一执行入口和安全分支则归并。

Flow 是单次入口或 continuation 分析产生的局部证据段，由 Fact 和 Edge 构成。Fact 类型为：

```text
entrypoint reachability control transform guard operation effect dead_end gap
```

Continuation 是必须闭合的结构化边：

```text
component_dispatch callback_dispatch shared_handler async_resume unknown_target
```

Flow 状态只描述结构：`open` 表示需要沿 continuation 继续追踪，`reached` 表示本段到达 operation/effect，`stopped` 表示代码路径明确终止，`gap` 表示证据不足。探索层不判断 Guard 是否有效、业务是否正常或是否存在漏洞。

Path 是从 Canonical Entry 到 `reached/stopped/gap` 终点的完整证据路径，按顺序引用一个或多个 Flow。Security Assessor、攻击矩阵和报告都以 Path 为审计对象；Flow 只作为内部可复用的局部证据段。

## 4. 验证与聚合

每个 Assessment 必须逐一验证六个维度：

1. 外部可达。
2. 关键属性受攻击者控制。
3. 受控值到达目标操作。
4. Guard 缺失或可绕过。
5. 安全边界被违反。
6. 存在具体安全影响。

Security Assessor 先检查正常业务意图、有效 Guard、安全边界和其他反证，再填写六项布尔结论。确认漏洞要求六项全部为 true、没有有效反证，并且 Path 中存在对应 operation 与 effect；有效 Guard 分类为 `protected_exposure`；正常公开业务且未越界分类为 `benign_business_flow`；可疑但缺少关键成立证据时分类为 `residual_risk`，无法判断时分类为 `insufficient_evidence`。非确认结果必须记录降级原因，后两类还必须记录证据缺口。

Security Assessor 是唯一安全裁决层。它一次完成模式识别和六维验证；模式卡是知识与统一尺度，不要求对无关模式逐张输出不适用。已有模式之外的安全问题也可产生 Assessment。分类不反向修改 Flow 或 Path 的结构状态。

根因键只包含归一化 operation location、branch、boundary 和 controlled property。入口别名、能力 ID、模式 ID 不参与根因身份，因此同一修复点只产生一个 Finding。

## 5. 控制面

SQLite `run.db` 是可变状态唯一事实源，包含 run、entry disposition、entry、task/dependency、evidence、flow、fact/edge、continuation、path、security assessment、finding 和 event。

`prepare` 是“审计准备与入口建模”的唯一初始化入口，先校验模式、能力和组件过滤，再确定性完成 JSON5 项目建模、Atlas 索引、隔离 run 创建和 Entry Resolution 任务初始化。Entry Resolver 提交覆盖全部候选的结果后，这个前置流程才完成。索引前失败不创建 run；已创建 run 的终止状态必须明确为 `failed`，不能继续调度。Agent 不参与目录选择或初始化步骤编排。

任务状态为 `queued/running/completed/failed/cancelled`，run 状态为 `created/running/complete/failed`。`next` 在事务内领取一个依赖已完成的任务；`submit` 同时校验 Schema 与可执行的业务不变量，再在同一事务中合并结果、完成任务并派生后续任务。无效提交会携带完整错误重新排队；安全判定第三次仍无效时确定性降级为 `insufficient_evidence`，保留覆盖缺口并继续其他路径，前置建模或路径结构任务耗尽重试以及不可恢复失败才终止 run。数据库提交不触发报告导出，避免任务状态与文件写出形成半提交。

continuation 统一由 `continuation_resolution` 处理。公共 handler 以规范化 symbol/target 作为缓存身份，同一实现的局部 Flow 证据可被复用；每个父 Flow 仍产生独立子段，运行时通过显式 `child_flow_ids` 连接父子段并组装完整 Path。

运行时采用最多 5 个任务的并发批次。编排者连续调用单任务 `next` 填满可用槽位，期间只积累句柄；收到 `worker_pool_full` 或 `no_queued` 后，在同一轮发出本批全部 subagent 调用，并在全部返回后逐个提交。该协议恢复大重构前稳定工作的“先填槽、后整批派发”行为。动态补位不属于当前 OpenCode Agent 协议能够确定性保证的能力；会话中断后的已有 run 通过显式 `recover` 恢复。

Flow 身份由 root entry、parent Flow、规范化 branch、controlled property、目标 operation 与 continuation 确定性生成，模型提供的展示标签不参与身份。Fact 优先按类型与规范化源码位置归一化。Security Assessment 的任务上下文由运行时注入完整 Path、审计范围内的能力画像和全部可用模式卡；已有事实之外只允许通过 Atlas 做有界补证。

每条完整 Path 只派生一个 `security_assessment` 任务，无论 Path 是否命中现有模式。任务只携带根入口适用的能力画像和模式卡，模型仍可直接识别模式之外的问题。结果可包含零个或多个 Assessment。Python 校验六维结论和 evidence 范围，并仅将 `confirmed_vulnerability` 与 `residual_risk` 按规范化根因键聚合为 Finding；安全对照保留在 Assessment 中。

报告准入要求：

- 每个项目候选恰有一个 disposition；
- run 未失败，且无 queued、running、failed 或 cancelled task；
- 无 open continuation；
- 每个终止 Flow 已组装为 Path，且每个已解析 continuation 都显式关联子 Flow；
- 每个闭合 Path 都有且仅有一个完成的安全判定任务。

`build-report` 和 `finalize` 都必须通过上述准入。报告区分 actionable findings（confirmed vulnerability 与 residual risk）、protected exposure、benign business flow 和 insufficient evidence；后几类用于覆盖证明，不计入安全问题总数。

## 6. 运行产物

```text
<run_dir>/
  run.db
  session.json
  project/project_model.json
  tasks/<task>.json
  tasks/<task>.result.json
  exports/entries.json
  exports/flows.json
  exports/paths.json
  exports/assessments.json
  exports/attack_matrix.json
  exports/tasks.json
  findings.json
  report_model.json
  report.md
  report.html
  report_snapshot.json
```

JSON 导出、Path 覆盖视图、Markdown 和 HTML 均从数据库重建。`exports/flows.json` 保留内部证据段，`exports/paths.json` 输出完整路径，`exports/assessments.json` 输出安全判定，`exports/attack_matrix.json` 汇总 Entry、Path、Assessment 与 Finding 的对应关系。

HTML 报告固定提供四个中文视图：

- 概览：结果分类、外部入口、路径数量和重点安全结论；
- 攻击路径：支持筛选，并展示入口、分支、受控参数、敏感操作、事实链、安全判定和六维验证；
- 项目结构：展示应用、模块、组件、权限和依赖；
- 覆盖与缺口：展示入口处理、任务、规则判断、跨边界追踪以及未闭合证据。

页面只嵌入展示所需字段，完整事实仍以 `run.db` 和 JSON 导出为准。

## 7. 扩展原则

新增审计能力时扩展 capability profile 与模式卡；只有出现新的事实、边或 continuation 语义时才修改运行时。全量、单能力和定点组件审计使用同一架构：组件过滤在 Entry Resolution 前按 project model 中的 Ability/ExtensionAbility 身份裁剪候选；能力过滤在 Entry Resolution 后按已确认的 Entry 类型裁剪路径任务和知识上下文。Native/NAPI 当前不在范围内。
