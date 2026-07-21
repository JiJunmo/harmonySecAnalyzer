# harmonySecAnalyzer 设计

## 1. 核心模型

系统采用入口驱动的证据流：

```text
Project Model
  -> Canonical Entry
  -> Entry Flow / Continuation
  -> Closed Evidence Flow
  -> Pattern Hypothesis
  -> Exploitability Validation
  -> Root Cause Finding
  -> Deterministic Report
```

模式不能制造执行路径；危险 API 文本命中不能代替可达性；外部可达不能代替攻击者控制；敏感调用不能代替安全影响。

## 2. 组件边界

| 组件 | 负责 | 不负责 |
|---|---|---|
| Project Profiler | JSON5/Manifest 的确定性事实和候选账本 | 源码扫描、入口实现、漏洞判断 |
| Entry Planner | 入口符号、外部触达、dispatcher 分支归一化 | 下游漏洞路径 |
| Flow Analyzer | 从指定入口或 continuation 构建 Fact/Edge | 当前任务边界内的源码语义分析 |
| Pattern Evaluator | 用模式卡解释闭合 Flow | 反向补造路径 |
| Flow Validator | 六门槛、Guard、边界、影响和根因 | 修改任务或报告 |
| Flow Runtime | 事务、去重、依赖、准入、导出和报告 | 源码语义判断 |
| Atlas MCP | 项目符号、调用与变量路径证据 | 审计状态管理 |

Agent 只提交当前任务的 JSON。中央状态、ID、任务派生、根因聚合和报告全部由确定性 Python 运行时负责。

## 3. 数据语义

Canonical Entry 的身份包含入口符号与安全相关判别符，例如 IPC transaction code、CommonEvent event name、URI route、Want flow 或 Provider operation。Manifest 别名若共享同一执行入口和安全分支则归并。

Flow 由 Fact 和 Edge 构成。Fact 类型为：

```text
entrypoint reachability control transform guard operation effect dead_end gap
```

Continuation 是必须闭合的结构化边：

```text
component_dispatch callback_dispatch shared_handler async_resume unknown_target
```

Flow 终态为 `connected/blocked/benign/gap`；`open` 必须带 continuation。公共 handler 任务按目标符号去重，但每个父 Flow 保留独立 continuation 和受控属性。

## 4. 验证与聚合

确认漏洞必须同时证明：

1. 外部可达。
2. 关键属性受攻击者控制。
3. 受控值到达目标操作。
4. Guard 缺失或可绕过。
5. 安全边界被违反。
6. 存在可观察影响。

有效 Guard 分类为 `protected_exposure`；正常公开业务分类为 `benign_business_flow`；缺证据分类为 `insufficient_evidence` 或 `residual_risk`。

根因键只包含归一化 operation location、branch、boundary 和 controlled property。入口别名、能力 ID、模式 ID 不参与根因身份，因此同一修复点只产生一个 Finding。

## 5. 控制面

SQLite `run.db` 是可变状态唯一事实源，包含 run、entry disposition、entry、task/dependency、evidence、flow、fact/edge、continuation、hypothesis、finding 和 event。

任务状态只有 `queued/running/completed/failed`。`claim` 在事务内领取依赖已完成的任务；`submit` 先校验 Schema 与业务不变量，再在同一事务中合并结果、完成任务并派生后续任务。无效提交不改变中央状态。

报告准入要求：

- 每个项目候选恰有一个 disposition；
- 无 queued、running 或 failed task；
- 无 open continuation；
- 每个闭合 Flow 完成模式评估和验证。

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
  exports/attack_matrix.json
  exports/tasks.json
  findings.json
  report_model.json
  report.md
  report.html
  report_snapshot.json
```

JSON 导出、Flow 覆盖视图、Markdown 和 HTML 均从数据库重建。`exports/attack_matrix.json` 汇总 Entry、Flow、Hypothesis 与 Finding 的对应关系。

## 7. 扩展原则

新增审计能力时扩展 capability profile 与模式卡；只有出现新的事实、边或 continuation 语义时才修改运行时。全量、单能力和定点组件审计使用同一架构：能力过滤只裁剪 Entry 的能力画像，组件过滤在 Entry Planning 前按 project model 中的 Ability/ExtensionAbility 身份裁剪候选。Native/NAPI 当前不在范围内。
