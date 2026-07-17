# harmonySecAnalyzer 设计

本文档描述当前可运行系统的架构边界。操作命令归属各 Skill，能力开关归属机器配置，
漏洞语义归属模式卡；本文不复制这些内容，也不维护未来功能清单。

## 1. 设计原则

1. **确定性事实优先**：工程配置、任务状态、身份分配、覆盖校验和结果准入由脚本完成。
2. **Agent 负责语义判断**：Agent 使用 Atlas 获取代码证据，不直接维护共享状态。
3. **私有写入，集中合并**：worker 只写自己的结果文件，状态机校验后更新共享产物。
4. **路径不是漏洞**：路径发现与漏洞确认分离，验证阶段优先寻找反证。
5. **配置与语义分离**：能力注册表负责路由，模式卡负责领域判断，不互相复制。
6. **报告不创造事实**：报告器只能聚合已经通过准入的验证结果。

## 2. 组件边界

### 2.1 Command

`.opencode/commands/audit.md` 是唯一用户入口，只负责解析审计范围和目标仓路径，并将任务
交给 `harmony-auditor`。它不包含状态机命令和漏洞规则。

### 2.2 Primary Agent

`harmony-auditor` 是流程控制者，职责限于：

- 加载工作流和相关 Skill；
- 创建独立 run；
- 调用项目建模；
- 从状态机领取任务并派发给对应 worker；
- 提交 worker 结果；
- 在准入通过后调用报告器和完成运行。

它不解析 Manifest、不手写中间文件、不自行判断漏洞，也不复制 Skill 内的脚本调用细节。

### 2.3 Worker Agents

| Agent | 输入 | 输出 | 不负责 |
|---|---|---|---|
| `attack-surface-mapper` | 单个 discovery task | 私有 discovery result | 合并共享入口、编译矩阵 |
| `path-finder` | 单个 attack-matrix work item | 私有 path result | 分配 candidate ID、确认漏洞 |
| `path-validator` | 单个 candidate | 私有 validation result | 聚合报告、修改候选身份 |
| `report-composer` | 已闭合的结构化结果 | `findings.json`、`report.md` | 新增路径或改变验证结论 |

所有 worker 只能写任务信封给出的绝对 `result_path`。共享文件由状态机独占写入。

### 2.4 Skills

| Skill | 所有权 |
|---|---|
| `project-modeling` | JSON5/Manifest 解析规则、项目模型和 discovery plan |
| `audit-orchestration` | run 生命周期、队列、归一化、攻击矩阵、准入与数据 Schema |
| `attack-patterns` | 漏洞模式的 source/sink/guard/reject/impact 语义 |
| `audit-workflow` | 跨组件顺序、调度约束和漏洞确认门槛 |

Skill 之间通过文件契约协作，不通过复制提示词或调用彼此内部函数耦合。

### 2.5 Atlas MCP

Atlas 是源码事实查询层：

- ArkTS 使用 `search`、`symbol`、`explore`、`calls`、`path`、`trace` 和依赖查询；
- C/C++ 的生命周期与分支能力不套用于 ArkTS；
- Atlas 返回的符号、位置和路径必须记录为证据，Agent 不用逐文件文本扫描替代索引查询；
- Atlas 失败必须形成覆盖缺口，不能被默认为“未发现问题”。

## 3. 依赖方向

```text
/audit
  -> harmony-auditor
      -> project-modeling
      -> audit-orchestration
          -> attack-surface-mapper -> Atlas
          -> path-finder           -> Atlas + attack-patterns
          -> path-validator        -> Atlas + attack-patterns
      -> report-composer
```

稳定数据依赖：

```text
project model
  -> discovery plan
  -> per-unit discovery results
  -> normalized entries and danger seeds
  -> sparse attack matrix
  -> path results
  -> root-cause candidates
  -> validation results
  -> findings and report
```

禁止反向依赖。例如，项目建模不得读取验证结果，报告器不得修改攻击矩阵，模式卡不得保存
某次运行的状态。

## 4. 流水线

### 4.1 建模

`project_profiler.py` 使用第三方 `json5` 库解析 HarmonyOS 工程配置，生成：

- `project/project_model.json`：模块、组件、权限、依赖和入口候选；
- `atlas/discovery_plan.json`：可独立执行的 Atlas 分析单元。

这一阶段不扫描源码。解析失败进入 diagnostics，`status` 未完成时流程不能继续。

### 4.2 攻击面测绘

状态机将 discovery plan 的每个 unit 转换为独立任务。mapper 在限定 scope 内查询 Atlas，
并将每个项目入口候选唯一归类为：

- 接收为执行入口；
- 明确排除；
- 终态覆盖缺口。

状态机对结果执行 Schema、身份和引用校验，再确定性重建共享入口、危险种子和查询证据。
worker 之间不读写彼此结果。

### 4.3 攻击矩阵与路径

状态机对入口和危险种子做归一化，根据能力注册表编译稀疏
`Entry x Sink x Pattern` 工作项。矩阵只表达“值得验证的攻击假设”，不表达漏洞结论。

每个工作项由一个 path-finder 处理。path result 必须给出唯一结论：

- 找到符合准入条件的候选路径；
- 无路径；
- 分析缺口；
- 被规则明确拒绝。

状态机只接纳结构完整、引用可解析、拥有稳定 root cause 的候选。

### 4.4 根因身份与去重

候选身份由状态机根据结构化 root cause 与 pattern 确定。入口别名、Manifest 别名和重复
危险点证据合并为同一根因的触发或证据变体，不产生多个 candidate。

`candidate_index.json` 是 candidate ID 和根因聚合的唯一事实源。Agent 不自行创建或复用
`CAND-*` 标识。

### 4.5 验证

每个独立 candidate 只派发一个 path-validator。确认漏洞必须同时通过六门槛：

1. 外部可达；
2. 关键参数受攻击者控制；
3. 可控值到达敏感操作；
4. 防护缺失或可绕过；
5. 越过安全边界；
6. 存在具体安全影响。

验证器必须检查白名单、权限、身份、来源、对象所有权和业务意图等反证。无法满足全部
门槛时，只能输出受保护暴露、正常业务、残余风险或证据不足。

### 4.6 报告

`validate-ready` 检查：

- 项目模型与 discovery 覆盖闭合；
- 队列没有未终态任务；
- 矩阵工作项均有终态；
- candidate、path、validation 和 query 引用完整；
- 所有共享产物符合 Schema。

终态 Atlas/routing/analysis gap 允许生成 `partial` 报告，但必须披露。报告生成后，
`finalize` 再校验报告契约，并用 SHA-256 快照冻结事实输入。

## 5. 状态与产物

每次运行拥有独立目录：

```text
reports/<project>-<path-hash>/<timestamp>-<scope>-<run-id>/
  session.json
  queue.jsonl
  task_events.jsonl
  candidate_index.json
  project/project_model.json
  atlas/discovery_plan.json
  atlas/entry_list.json
  atlas/danger_seed_list.json
  atlas/query_evidence.jsonl
  analysis/danger_seeds.json
  analysis/attack_matrix.json
  tasks/<task-id>.result.json
  paths/*.jsonl
  validation/*.jsonl
  findings.json
  report.md
  report_snapshot.json
```

`session.json` 表示运行生命周期，`queue.jsonl` 表示任务当前状态，
`task_events.jsonl` 记录追加式事件。运行目录不得复用；完成后的事实输入被改写时，快照
校验应失败。

任务失败、结果缺失、JSON 无效或身份不匹配时统一进入状态机重试，最多三次。无效结果
按 attempt 留档，不能覆盖成功结果。

## 6. 配置与知识

### 6.1 能力注册表

`.opencode/skills/audit-orchestration/config/audit_capabilities.json` 是机器可读的唯一配置源，
保存能力 ID、启用状态、entry/seed 条件、分析模式和 pattern 绑定。

增加或调整能力路由时只修改该注册表，并通过对应 Schema 和注册表测试。

### 6.2 模式卡

`.opencode/skills/attack-patterns/patterns/*.md` 保存模型需要的领域判断信息：

- source/sink 的语义边界；
- 有效和无效 guard；
- 正常业务与漏洞的区分；
- 必需证据和拒绝条件。

模式卡不保存启用开关、任务状态或重复的路由表达式。通用六门槛保留在工作流，领域差异
保留在模式卡。

### 6.3 Schema

`.opencode/skills/audit-orchestration/config/schemas/` 是跨组件 JSON 契约的唯一来源。
准入顺序固定为：

```text
JSON Schema -> 业务不变量 -> 跨产物引用完整性
```

提示词中的字段说明只能引用 Schema，不应另建一套不一致的数据定义。

## 7. 扩展规则

新增审计能力时：

1. 在能力注册表增加路由项；
2. 仅在存在领域差异时增加或修改模式卡；
3. 复用现有 discovery、path、validation 契约；
4. 增加注册表、路由和语义回归；
5. 不为单一规则创建新的 Agent。

新增流程组件只在它拥有独立输入、输出和失败边界时成立。确定性转换优先放入对应 Skill
脚本；需要代码语义推理的工作才交给 Agent。

当前边界明确不包含 Semgrep、NAPI/native 审计和异步滑动 subagent 池。实现这些能力时
应作为独立扩展接入，而不是在现有 worker 中留下空目录或兼容占位。

## 8. 一致性验证

本地完整性检查：

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 deploy.py --check-only
```

测试覆盖项目建模、流式发现、攻击矩阵、归一化、重试、run 隔离、结果契约、能力注册表
和语义回归。部署检查只验证当前运行必需组件，不为未来目录保留占位。
