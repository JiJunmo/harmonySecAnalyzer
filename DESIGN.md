# 鸿蒙 ArkTS 白盒安全审计多智能体方案（适配 opencode）

> 项目：harmonySecAnalyzer-v3.1
> 目标：面向 HarmonyOS / OpenHarmony ArkTS 代码仓的白盒安全审计与漏洞挖掘多智能体系统
> 运行平台：[opencode](https://opencode.ai)（SST 团队开源终端 AI 编程代理）
> 代码理解引擎：[atlas MCP](https://github.com/LordCasser/atlas)（适配 ArkTS 语法的代码索引/调用图/数据流工具）
> 日期：2026-07-12

---

## 0. 方案定位

一个**面向 HarmonyOS / OpenHarmony ArkTS 代码仓的白盒安全审计多智能体系统**，用 opencode 原生的 `agent + subagent + skill + command + custom tool + plugin` 机制编排，以"**编排者 + 专项 subagent + 确定性状态机**"模式运行，借助 **atlas MCP** 提供确定性的符号/调用图/数据流/路径查询能力，输出可复核的分层结构化报告（含 CWE 映射、污点链、guard 证据、降级原因与修复建议）。

### 核心设计原则

1. **知识与分析分离**：漏洞模式、权限映射、CWE 表 → 做成按需加载的 `skill`；项目配置事实由 profiler 提取，源码结构/调用/数据流统一走 atlas MCP。
2. **专家分工 + 编排收敛**：每个 subagent 只管一个领域（manifest / 注入 / 加密 / 网络 / ICC / Web / 依赖），编排者负责切片、派发、去重、定级；NAPI/native 留作后续独立扩展。
3. **LLM 判断 + Atlas 确定性事实**：符号定位、调用图、依赖、污点可达性走 Atlas；LLM 只对 Atlas 返回的有界源码上下文做能力识别、业务语义和误报过滤，不遍历源码。
4. **审计可追溯**：plugin 记录每条 finding 的产生链路（哪个 agent、哪条规则/查询、哪个文件行），便于复核。
5. **漏洞确认反证优先**：外部可达、敏感 API、调用链存在只说明 exposure/capability/path；只有满足"外部可达、攻击者可控关键参数、到达敏感 sink、guard 缺失或可绕过、违反安全边界、有具体 impact"六门槛,才进入 `confirmed_vulnerability`。

### 能力栈总览

| 层 | 机制 | 来源 | 本方案用途 |
|---|---|---|---|
| 配置 | `opencode.json` + `.opencode/` | opencode 原生 | 主配置 |
| Agent / Subagent | `.opencode/agents/*.md`（`task` 工具调用，`permission.task` glob 控制） | opencode 原生 | 主 agent + 领域专家 |
| Skill | `.opencode/skills/<name>/SKILL.md`（`skill` 工具按需加载） | opencode 原生 | 知识库/流程 |
| Command | `.opencode/commands/*.md`（frontmatter + 模板） | opencode 原生 | 用户入口 |
| Custom Tool | `.opencode/tools/*.ts`（`tool()` + Zod） | opencode 原生 | 复合分析流程 |
| Plugin | `.opencode/plugins/*.ts`（事件 hooks） | opencode 原生 | 审计轨迹 |
| **代码理解引擎** | **atlas MCP**（stdio，Rust 二进制 `atlas mcp`） | **外部接入** | **符号/调用图/数据流/路径查询，污点可达性** |
| 静态规则扫描 | 暂不接入 | 预留 | 当前版本采用 Manifest 锚点 + Atlas scoped discovery |
| 工具集 | `read/grep/glob/edit/bash/skill/task/todowrite/...` | opencode 原生 | agent 能力底座 |

### opencode 扩展能力要点（方案依据）

- **Subagent**：`mode: subagent`，经 `task` 工具调用，`permission.task` 用 glob 控制调用关系（`allow`/`ask`/`deny`，最后匹配规则胜出）。
- **Skill**：经 `skill` 工具按需加载，不自动注入；frontmatter 仅识别 `name/description/license/compatibility/metadata`（无 `allowed-tools`，工具控制在 agent 的 `permission`）。
- **Command**：markdown frontmatter + 模板，支持 `$ARGUMENTS`/`$1`/`!cmd`/`@file`，可指定 `agent` 与 `subtask`。
- **MCP**：`opencode.json` 的 `mcp` 对象，`type: "local"` 时 `command` 为数组（含可执行文件与参数）；可按 agent 启用/禁用（`permission` 里用 `<server>_*` glob）。opencode 中 MCP 工具名以 server 名为前缀，atlas 工具即 `atlas_search`/`atlas_path`/`atlas_trace` 等，glob 写 `atlas_*`。
- **权限模型**：统一 `permission` 字段 + glob（`allow`/`ask`/`deny`），`tools: {name: bool}` 已废弃。
- **指令**：`AGENTS.md`（兼容 `CLAUDE.md`）。

---

## 1. 编程语言选型

| 层 | 选型 | 理由 |
|---|---|---|
| Agent / Skill / Command 定义 | **Markdown + JSONC** | opencode 原生格式，零运行时成本 |
| Custom Tool / Plugin | **TypeScript (Bun)** | opencode plugin 原生语言；`@opencode-ai/plugin` 的 `tool()` + Zod；与 ArkTS（TS 超集）生态一致 |
| **代码理解引擎** | **atlas（Rust 二进制，外部接入）** | 适配 ArkTS 语法，提供符号/调用图/数据流/路径查询；open-first + focus lazy extraction，大仓友好；无需自研 AST/调用图/污点引擎 |
| 静态分析规则 | **本轮不接入 Semgrep** | 先验证 Manifest 锚点 + Atlas scoped discovery 的覆盖与性能；规则引擎保留为后续可选项 |
| 知识库 / 规则库 | **Markdown + YAML** | 被 skill 加载、可独立 diff、可版本化 |
| 装饰器专项分析（补充） | **TypeScript（ts-morph）** | atlas 文档未明确声明式 UI 装饰器（@Component/@State/@Builder）语义；用 ts-morph 做 ArkTS 状态数据流补充 |
| MCP server（可选进阶） | **TypeScript** | P4 视情况抽知识检索/CVE 查询 MCP |

**结论**：主语言 **TypeScript**，代码理解用 **atlas**（外部 Rust 二进制，非自研），配置/知识层 **Markdown + JSONC + YAML**。**不引入自研污点引擎**（atlas 的 `path`/`trace` 已覆盖核心需求），仅在 P4 对 atlas 不支持的异步/装饰器场景做 ts-morph 补充。

---

## 2. 项目目录结构

```
harmonySecAnalyzer-v3.1/
├── opencode.json                 # 主配置：provider/model/agent 权限/mcp(atlas)/permission
├── AGENTS.md                     # 项目级指令（opencode 原生，/init 生成；兼容 CLAUDE.md）
├── README.md
├── requirements.txt              # Python 运行时依赖（json5）
├── .opencode/                    # opencode 项目级资源目录（复数子目录，官方约定）
│   ├── agents/                   # 主 agent + 所有 subagent（一个 .md 一个 agent）
│   │   ├── harmony-auditor.md        # primary｜编排者：切片/派发/去重/定级
│   │   ├── attack-surface-mapper.md  # subagent｜枚举外部可达入口 + 危险能力种子
│   │   ├── path-finder.md            # subagent｜per-attack-matrix-work-item 验证 entry → sink,只产一个路径结论
│   │   ├── path-validator.md         # subagent｜per-candidate 反证优先六门槛验证
│   │   └── report-composer.md        # subagent｜汇总成分层结构化报告
│   ├── commands/                 # 斜杠命令（用户入口）
│   │   ├── audit.md                  # /audit [full|quick|manifest|<domain>] [path]
│   │   ├── triage.md                 # /triage 对 findings 去重/分级
│   │   └── report.md                 # /report 生成/导出报告
│   ├── skills/                   # 按需加载的知识/流程（SKILL.md）
│   │   ├── audit-workflow/SKILL.md       # 端到端审计 SOP（编排者必读）
│   │   ├── audit-orchestration/          # 状态机协议 + 私有 Python 脚本
│   │   │   ├── SKILL.md
│   │   │   └── scripts/audit_orchestrator.py
│   │   ├── project-modeling/              # 确定性项目建模协议 + JSON5 解析脚本
│   │   │   ├── SKILL.md
│   │   │   └── scripts/project_profiler.py
│   │   ├── attack-patterns/SKILL.md      # 攻击链模式卡 + 正常业务/guard/降级规则
│   │   ├── atlas-query-patterns/SKILL.md # 如何用 atlas 查污点/调用链/影响面（规划）
│   │   ├── arkts-vuln-kb/SKILL.md        # ArkTS 漏洞模式知识库（规划）
│   │   ├── harmony-permission-map/SKILL.md
│   │   ├── harmony-icc-model/SKILL.md
│   │   ├── napi-boundary-rules/SKILL.md  # 后续 NAPI 扩展预留
│   │   ├── crypto-storage-guide/SKILL.md
│   │   ├── cwe-mapping/SKILL.md
│   │   ├── report-template/SKILL.md
│   │   └── semgrep-rule-authoring/SKILL.md # 后续规则引擎预留
│   ├── tools/                    # opencode custom tool（TS，复合分析流程）
│   │   ├── taint_via_atlas.ts        # 封装 atlas search→path→trace 的污点可达查询
│   │   ├── arkts_decoration_parse.ts # ts-morph 做装饰器/@State 数据流（atlas 未覆盖）
│   │   ├── semgrep_run.ts            # 规划项，本轮不实现/调用
│   │   ├── cve_lookup.ts             # ohpm 依赖→CVE 查询
│   │   └── finding_dedupe.ts         # 基于位置+模式指纹去重
│   ├── plugins/
│   │   └── harmony-audit-plugin.ts    # 事件 hooks：记录审计轨迹/初始化 run 目录
│   ├── prompts/                  # agent 长 prompt 片段，被 {file:./} 引用
│   │   ├── orchestrator.txt
│   │   ├── verifier.txt
│   │   └── shared-guidelines.txt
│   └── package.json              # plugin/tool 依赖：@opencode-ai/plugin, zod, ts-morph, json5
├── rules/                        # 后续静态规则引擎预留，本轮运行时不消费
│   └── semgrep/.gitkeep
├── knowledge/                    # 知识库（被 skill 内容引用，不直接进上下文）
│   ├── vuln-patterns/
│   ├── permission-catalog/
│   ├── cwe-map.yml
│   └── checklist/
│       └── harmony-audit-checklist.md
├── tools/                        # 独立 CLI 工具（经 bash 调用）
│   └── arkts-decoration-flow/    # 可选：装饰器状态数据流分析（ts-morph，P4）
│       ├── src/ └── package.json
├── examples/                     # 漏洞样例仓（规则回归用）
│   ├── vulnerable-samples/
│   └── safe-samples/
├── tests/                        # 规则与工具回归测试
│   ├── test_project_profiler.py      # JSON5/project model/discovery plan 回归
│   ├── test_orchestrator_coverage.py # 候选与 Atlas unit 覆盖准入回归
│   └── semgrep-spec/.gitkeep         # 后续规则引擎预留
├── reports/                      # 审计产出（gitignore）
│   └── .gitkeep
└── .gitignore
```

### 目录分层逻辑

- `.opencode/` —— opencode 运行时直接消费的资源（agents/skills/commands/tools/plugins）
- `rules/` + `knowledge/` —— 与运行时解耦的**可复用资产**，单独 diff、单测、版本化
- `tools/` —— 重型独立分析器（如装饰器数据流，P4），经 `bash` 调用
- `examples/` + `tests/` —— 规则回归（正例/反例）与误报监控

---

## 3. 核心架构设计

### 3.1 分层

```
┌─────────────────────────────────────────────────────────────┐
│  入口层   commands:  /audit  /triage  /report                │
├─────────────────────────────────────────────────────────────┤
│  编排层   harmony-auditor (primary)                          │
│           open atlas → 切片 → 派发 → 收敛 → 去重 → 定级 → 报告│
├─────────────────────────────────────────────────────────────┤
│  专家层   subagents (via task 工具, 并行/串行)                │
│   mapper ─ path-finder ─ path-validator ─ composer            │
│   network ─ icc ─ web ─ dependency ─ verifier ─ composer     │
├─────────────────────────────────────────────────────────────┤
│  能力层   project profiler(确定性 JSON5/工程建模) +           │
│           atlas MCP(符号/调用图/数据流/路径) +                │
│           skills(按需知识) + custom tools(复合流程)           │
│           + project model/discovery plan + plugin(轨迹/事件) │
├─────────────────────────────────────────────────────────────┤
│  资产层   knowledge/  attack-patterns  examples/             │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 编排流程（端到端）

1. **`/audit full <repo-path>`** → 触发 `harmony-auditor`（primary）。
2. **初始化 run**：编排者按 audit-orchestration skill 执行 `new-run`。状态机以目标仓规范路径生成 project key，并原子创建 `reports/<project-key>/<run-id>/`、`session.json`、`queue.jsonl` 与 validation/paths 目录；重复和并发审计不会复用目录。
3. **确定性项目建模**：`project_profiler.py` 只读取 app/module/build-profile/oh-package JSON5，枚举组件、权限、依赖、Manifest 入口候选，并生成带 module scope/component/lifecycle anchors 的 `atlas/discovery_plan.json`。不读取源码内容；NAPI 本轮不实现。
4. **激活 atlas**：编排者调 `atlas_project action=open project_path=<repo-path>`，打开/创建 `<repo>/.atlas/atlas.db`。后续 subagent 共享该 atlas 会话。
5. **Atlas 攻击面测绘**：mapper 按 discovery unit 执行 scoped `search → symbol/explore → calls/file_dependencies`，只从 Atlas 返回的可达上下文发现 Web/JSBridge 与危险能力；更新 plan 并写 query_evidence/entry/seed。每个 candidate 进入 entry/excluded/unresolved/coverage_gaps。
6. **分析计划编译与候选准入**：状态机 `compile-matrix` 分别归一化 execution entry 与 danger seed,先按 discovery unit 关联做保守剪枝,再按数据驱动路由编译稀疏 `Entry × Sink × Pattern` 攻击矩阵。`intermediate` seed 作为路径过渡证据排除出矩阵;每个有效终态 work item 分配一个 path task,未实现模式才进入 routing gap。path-finder 必须证明外部可达、正向 sink 可达、攻击者影响、终态 sink 与控制连续性,否则不得晋级。
7. **5 槽任务池 + 可靠提交 + 流式晋级**：状态机 `next` 最多允许 5 个 running task,向 worker 下发唯一绝对 `result_path` 和 attempt。worker 写后回读;`complete` 对 provider 中断导致的结果缺失、无效 JSON 和身份错误自动重新入队,默认 3 次后才终态失败,并在 `complete(path_finding)` 成功时立即生成验证任务。当前 OpenCode TaskTool 同步阻塞父 agent,执行层实际按最多 5 个一批推进;真正的单任务完成即补位列为低优先级技术债。
8. **根因级 promote**：`complete(path_finding)` 校验 work item 身份与 admission,按稳定的 `seed_key + pattern` fingerprint 合并多入口触发方式,写 `candidate_index.json`、为每个独立根因分配一个 `CAND-xxx`,并 enqueue 一个 `path_validation` task。
9. **反证优先验证**：`path-validator` 对每条候选做六门槛验证。结果分层为 `confirmed_vulnerability`、`protected_exposure`、`residual_risk`、`benign_business_flow`、`insufficient_evidence`。
10. **报告准入**：`validate-ready` 检查 project model、discovery units、entry candidate 去向、attack matrix work item、candidate 验证和队列闭合。planned/queued/running/failed/unresolved 阻断；terminal atlas_gap/routing gap/analysis_gap 可报告但 coverage_status=partial。
11. **分层报告与收尾**：`report-composer` 只把 `confirmed_vulnerability` 放入主报告，其余进入受保护暴露、残余风险、正常业务流、证据不足和攻击面附录。报告生成后执行 `finalize`,复核 ready 状态与两份报告产物后将 session 标记为 `completed`。

### 3.2.1 状态存储与流式调度

当前阶段保留 JSON/JSONL 文件存储,不引入 SQLite。原因是状态由主编排者统一推进,subagent 只写自己的 `tasks/<task_id>.result.json`;JSONL 更便于复核、手工恢复和报告生成。

run 目录新增/使用:

```
reports/<project-name>-<target-path-hash>/
  <YYYYMMDD-HHMMSS>-<scope>-<run-id>/
    session.json
    queue.jsonl
    task_events.jsonl
    candidate_index.json
    .lock
    project/project_model.json
    atlas/{discovery_plan, entry_list, danger_seed_list}.json
    atlas/query_evidence.jsonl
    analysis/{danger_seeds, attack_matrix}.json
    tasks/<task_id>.result.json
    paths/{candidates, rejected, no_path, analysis_gaps}.jsonl
    validation/{confirmed, protected_exposure, residual, benign_business_flow, insufficient_evidence}.jsonl
```

关键约束:

- `queue.jsonl` 记录任务当前状态、attempts、last_error 与 retry_history。
- `task_events.jsonl` 记录 enqueue/start/retry_scheduled/complete/promote/fail 等事件。
- `candidate_index.json` 维护 `next_candidate_no`、root-cause fingerprint → candidate_id、entry_ids 与 source_task_ids,避免同一根因因 Manifest action/显式启动差异重复验证和报告。
- `analysis/attack_matrix.json` 维护稀疏 `Entry × Sink × Pattern` 工作项及唯一终态;`excluded_intermediate` 记录不独立立项的过渡节点,`routing_gaps` 只记录未实现或无兼容模式的终态 seed。
- `project_model.json` 是配置事实源;`discovery_plan.json` 是 Atlas 源码分析覆盖契约。profiler 固定 `source_content_scanned=false`。
- 状态机命令持有 `.lock`,重要 JSON/JSONL 重写使用临时文件 + rename 原子写。
- `new-run` 使用目标仓规范路径哈希区分同名项目,并以时间 + 随机短 ID 原子分配运行目录;`init` 拒绝非空目录,防止历史产物叠加。

### 3.2.2 Finding 生命周期与六门槛

审计结论必须按生命周期分层:

1. `exposure`:外部可达入口、导出组件、WebView/JSBridge 暴露面。
2. `capability`:文件、SQL、网络、隐私、Ability 拉起等敏感能力。
3. `abuse_path`:外部输入可能控制敏感能力关键参数的可疑路径。
4. `vulnerability`:外部输入绕过有效防护与预期安全边界,造成具体安全影响。

`confirmed_vulnerability` 必须同时满足:

- `externally_reachable`:入口可被外部触达。
- `attacker_controlled`:攻击者能控制进入 sink 的关键参数。
- `sink_reached`:可控值到达敏感 sink。
- `guard_bypassed_or_absent`:防护缺失、无关、在 sink 后、未覆盖危险属性,或有明确绕过证据。
- `boundary_violated`:越过身份/权限/来源/域名/路径/组件/数据所有权/业务授权边界。
- `concrete_impact`:存在具体安全影响,不是仅"可调用敏感函数"。

降级分类:

- `protected_exposure`:外部可达且有敏感能力,但有效 guard 将行为约束在安全范围。
- `benign_business_flow`:属于预期公开业务能力,输入只影响允许的业务对象或路由,未越界。
- `residual_risk`:路径可疑或 guard 弱,但缺少确认漏洞的关键证据。
- `insufficient_evidence`:证据不足,不能臆造。

### 3.3 关键机制利用

- **subagent 调用与权限收窄**：编排者 `permission.task` glob 只放行审计相关 subagent：

  ```json
  "permission": {
    "task": {
      "*": "deny",
      "attack-surface-mapper": "allow",
      "path-finder": "allow",
      "path-validator": "allow",
      "report-composer": "allow"
    }
  }
  ```

  专家 subagent 默认 `task: deny`（不再级联）。

- **atlas 工具按 agent 启用**：opencode 中 atlas 工具名为 `atlas_*`。全局启用 atlas，再按 agent 用 `permission` 的 `atlas_*` glob 收窄（如 `report-composer` 设 `"atlas_*": "deny"`，`taint-analyst` 设 `"atlas_*": "allow"`）。

- **skill 按需加载**：知识库不进系统提示，subagent 需要时 `skill({name:"..."})` 拉取。

- **Atlas 查询可追溯**：mapper 把关键 `atlas_*` 输入、query_id、命中符号和 diagnostics 落盘到 `atlas/query_evidence.jsonl`；后续 plugin 可统一采集工具事件。

### 3.4 atlas MCP 整合与能力边界

atlas 是 open-first 的 stdio MCP server：`project open` 打开 `<repo>/.atlas/atlas.db`，按需 focus extraction（不全仓预扫），大仓局部体验接近已索引邻域。opencode 接入：

```jsonc
// opencode.json
"mcp": {
  "atlas": {
    "type": "local",
    "command": ["/path/to/atlas", "mcp"],
    "enabled": true
  }
}
```

> atlas 是 Rust 二进制（非 npm 包），需 `cargo build --release -p atlas-cli --features mcp` 或下载 release；支持 macOS arm64 / Linux / Windows。`command` 数组里第一个元素是 atlas 可执行文件绝对路径，由用户按实际安装位置填。

**能力边界（关键，避免过度承诺）**：

| atlas 能力 | ArkTS | C/C++（NAPI native） | 本方案用途 |
|---|---|---|---|
| `search` / `symbol` / `explore` | ✅ | ✅ | 符号定位、上下文、调用证据 |
| `calls`（incoming/outgoing，多跳） | ✅（ArgToParam+ReturnToCall，仅项目内符号） | ✅ | 调用图、调用链审计 |
| `path`（两符号间最短路径 BFS） | ✅ | ✅ | **污点可达性 source→sink** |
| `trace` variable（反向数据流） | ✅ | ✅ | **污点回溯** |
| `trace` forward（前向调用链） | ✅ | ✅ | 影响面下行 |
| `trace` callers（反向调用链） | ✅ | ✅ | 谁能触达 sink |
| `impact`（上下游可达） | ✅ | ✅ | 漏洞影响半径 |
| `file_dependencies` | ✅ | ✅ | 模块依赖、import 关系 |
| `lifecycle`（allocate→use→free） | ❌ | ✅ | **NAPI native UAF/双 free/漏 free** |
| `branch_diff`（分支副作用不对称） | ❌ | ✅（主要） | NAPI native 分支资源泄漏 |
| `fp_dispatches`（函数指针分派注解） | ❌ | ✅ | NAPI 回调/间接调用 |
| `domain_rules`（alloc/free/cleanup 规则） | ❌ | ✅ | lifecycle 辅助 |

> 上表中的 C/C++ 能力仅记录 Atlas 的扩展边界，本轮不调用。ArkTS 无 CFG，不能对 ArkTS 符号使用 `lifecycle`/`branch_diff`/`fp_dispatches`。装饰器（@Component/@State/@Builder）的专项语义留到 P4 评估。

**注意事项**：
- atlas 在被审计仓写 `.atlas/atlas.db`。若需只读审计，先 copy 目标仓或用 git worktree，避免污染原仓。
- atlas MCP 用客户端 cwd，但 `project open` 接受 `project_path` 绝对参数，故可审计任意路径的仓。
- 跨 Worker/TaskPool 的异步污点、装饰器状态流转是 atlas 当前未覆盖的场景，由 ts-morph 补充（P4）。

---

## 4. Agent 详细设计

### 4.1 Agent 一览

| Agent | mode | 模型建议 | 工具 | 职责 |
|---|---|---|---|---|
| `project_profiler.py` | deterministic script | — | Python `json5` + 配置文件发现 | 只生成 Manifest project model 与 Atlas discovery plan；不读取源码、不处理 NAPI |
| `harmony-auditor` | primary | 强(opus/sonnet) | read/grep/glob + task + skill + todowrite + `atlas_project` + 两个确定性脚本 | 编排：init→project model→open atlas→测绘→worker pool→validate-ready→分层报告→finalize |
| `attack-surface-mapper` | subagent | 中 | read + `atlas_search`/`atlas_symbol`/`atlas_explore`/`atlas_calls`/`atlas_file_dependencies` | 按 Manifest scope/anchor 做 Atlas 有界扩展，从可达上下文发现 Web/JSBridge 与危险能力 |
| `path-finder` | subagent | 中/强 | read/grep/glob + `atlas_path`/`atlas_trace`/`atlas_calls` + skill | per-attack-matrix-work-item 验证指定 entry → sink → pattern,只产一个终态结论 |
| `path-validator` | subagent | 强(opus) | read/grep + `atlas_path`/`atlas_trace`/`atlas_calls`/`atlas_impact` + skill | per-candidate 反证优先六门槛验证,输出分层结论 |
| `report-composer` | subagent | 中 | read/write + skill（`atlas_*` deny） | 汇总→分层结构化报告（写 reports/） |
| crypto / network / icc / web / dependency | subagent（规划） | 视领域而定 | atlas + domain skill | P2/P3 领域专家扩展；NAPI 延后单独设计 |

> 模型字段以 `provider/model-id` 形式在 `opencode.json` 配置，按自己 provider 填；上表是"难度→档位"建议。

### 4.2 主编排 agent 配置示例（`.opencode/agents/harmony-auditor.md`）

```markdown
---
description: 鸿蒙 ArkTS 代码仓白盒安全审计编排者。用户请求审计时使用。
mode: primary
model: anthropic/claude-sonnet-4-20250514
prompt: "{file:./prompts/orchestrator.txt}"
permission:
  read: allow
  grep: allow
  glob: allow
  task:
    "*": deny
    attack-surface-mapper: allow
    path-finder: allow
    path-validator: allow
    report-composer: allow
  skill: allow
  todowrite: allow
  "atlas_project": allow        # 仅允许 open/status，分析查询下放给 subagent
  "atlas_*": deny
  edit: deny
  bash: deny
---
```

### 4.3 专家 subagent 配置示例（`.opencode/agents/taint-analyst.md`）

```markdown
---
description: ArkTS 跨过程污点追踪。用 atlas path/trace 判定 source→sink 可达性。被编排者调用。
mode: subagent
model: anthropic/claude-sonnet-4-20250514
prompt: "{file:./prompts/taint-analyst.txt}"
permission:
  read: allow
  grep: allow
  glob: allow
  skill: allow
  "atlas_path": allow
  "atlas_trace": allow
  "atlas_calls": allow
  "atlas_search": allow
  "atlas_symbol": allow
  edit: deny
  bash: deny
  task: deny
---
```

### 4.4 finding 统一 schema（所有 subagent 必须输出）

```jsonc
{
  "id": "ARKTS-INJ-001",
  "domain": "injection",
  "cwe": "CWE-94",
  "severity": "high",            // critical|high|medium|low|info
  "confidence": 0.8,             // 0-1，verifier 复核后更新
  "title": "eval() 执行不可信输入",
  "file": "src/pages/xx.ets",
  "loc": "42:9-42:40",
  "source": { "type": "user_input", "where": "TextInput.onChange" },
  "sink":   { "type": "eval", "call": "globalThis.eval(input)" },
  "taint_chain": ["TextInput.onChange", "-> eval(input)"],
  "evidence": "globalThis.eval(this.inputValue)",
  "reachable": true,             // 由 atlas path/trace 验证
  "atlas_query": {               // 可追溯：复现查询
    "path": "TextInput.onChange -> globalThis.eval",
    "trace_kind": "variable",
    "query_id": "q_abc123"
  },
  "fix": "移除 eval；改用白名单映射或 JSON.parse"
}
```

---

## 5. Skills 设计（按需加载的知识）

每个 skill 一个目录 + `SKILL.md`，frontmatter 仅 `name/description`。

| Skill | 何时加载 | 内容 |
|---|---|---|
| `audit-workflow` | 编排者启动时 | 端到端 SOP：init→project model→open atlas→攻击面测绘→worker pool→validate-ready→分层报告→finalize |
| `audit-orchestration` | 编排者调度状态机时 | 队列/事件日志/candidate_index/validate-ready 协议；内含 `scripts/audit_orchestrator.py` |
| `project-modeling` | 编排者项目解析时 | project_model 契约；内含使用成熟 `json5` 库的 `scripts/project_profiler.py` |
| `attack-patterns` | path-finder/path-validator 工作时 | 攻击链模式卡；每类模式包含 source/sink、正常业务形态、漏洞成立条件、有效 guard、降级条件、反证重点 |
| `atlas-query-patterns` | taint/icc/verifier 工作时 | 如何用 atlas 查污点/调用链/影响面：source/sink 如何定位、`path` vs `trace(variable/forward/callers)` 选择、`query_id`+`resume_query` 处理 lazy 未决 |
| `arkts-vuln-kb` | arkts-sast/taint 工作时 | ArkTS 漏洞模式库（注入/硬编码/eval/状态管理/UI 注入），每条含模式+示例+修复+CWE |
| `harmony-permission-map` | manifest/icc 工作时 | 鸿蒙权限等级（normal/system/user_grant）↔ 敏感资源↔ 风险矩阵 |
| `harmony-icc-model` | icc-auditor 工作时 | Stage/FA 模型 Ability/Want/公共事件/ExtensionAbility 数据流与攻击面 |
| `napi-boundary-rules` | 后续 NAPI 扩展 | 本轮不加载；未来提供 NAPI 边界清单与 Atlas C/C++ 查询模式 |
| `crypto-storage-guide` | crypto-secrets 工作时 | huks 正确用法/算法白名单/存储加密规范 |
| `cwe-mapping` | 所有 subagent 产出时 | 漏洞类型→CWE/OWASP Mobile Top10 映射 |
| `report-template` | report-composer 工作时 | 报告 schema、章节结构、severity 计数、修复优先级 |
| `semgrep-rule-authoring` | 后续可选 | 当前主流程不加载；未来引入规则引擎时再启用 |

### Skill 文件示例（`.opencode/skills/atlas-query-patterns/SKILL.md`）

```markdown
---
name: atlas-query-patterns
description: 用 atlas MCP 做污点/调用链/影响面查询的模式手册。当需要判定 source→sink 可达性、回溯数据来源、追踪调用链或评估影响半径时加载。
---

## 先决条件
- 编排者已 `atlas_project action=open`。若返回 not_open，先 open。

## 污点可达性（source→sink）
1. 用 `atlas_search` 定位 source 符号（如 TextInput.onChange）与 sink 符号（如 eval/executeSql/loadUrl）
2. `atlas_path from=<source> to=<sink>` 取最短路径；返回 breakpoints 说明间接跳转
3. 若 path 不直达，用 `atlas_trace kind=variable` 在 sink 处反向回溯数据来源
4. lazy 未决时记录 `query_id`，用 `atlas_resume_query` 或 `atlas_tasks` 轮询

## 调用链
- 下行（谁被调用）：`atlas_trace kind=forward from=<entry>`
- 上行（谁能触达）：`atlas_trace kind=callers symbol=<sink>`

## 影响半径
- `atlas_impact symbol=<vuln_fn> direction=both depth=3`

## 边界
- ArkTS 无 CFG：不要对 ArkTS 符号调 `atlas_lifecycle`/`atlas_branch_diff`（仅 C/C++）
- 跨 Worker/TaskPool 异步流：atlas 当前不覆盖，转 ts-morph 补充
```

---

## 6. Commands 设计（用户入口）

| 命令 | 模板变量 | 行为 |
|---|---|---|
| `/audit [scope] [path]` | `$1=scope` `$2=path` | 主入口。scope ∈ `full\|quick\|manifest\|injection\|crypto\|network\|icc\|web\|napi\|dep`；调用 harmony-auditor |
| `/triage` | — | 规划项：对 `reports/<run>/findings.json` 做复核、去重和重定级 |
| `/report [run]` | `$1=run` | 重新生成/导出报告（调 report-composer） |

### `/audit` 命令文件示例（`.opencode/commands/audit.md`）

```markdown
---
description: 启动鸿蒙 ArkTS 白盒安全审计
agent: harmony-auditor
subtask: false
---
对 $2 执行「$1」范围的安全审计。

scope 取值：
- full：全量（默认）
- quick：仅 manifest + 硬编码 + 网络明文（快速过一遍）
- manifest：仅 module.json5/app.json5 配置审计
- injection / crypto / network / icc / web / napi / dep：单领域深审

按 audit-workflow skill 执行：先初始化 run 目录并生成 project model，再 atlas_project open→攻击面测绘→worker pool 流水线→validate-ready→分层报告→finalize，最终写入 reports/ 目录并将 session 标记为 completed。
```

---

## 7. Custom Tools 设计（`.opencode/tools/*.ts`）

用 `@opencode-ai/plugin` 的 `tool()` + Zod。**agent 优先直接调 atlas MCP 工具**；custom tool 只做"编排多个 atlas 调用 + 解读"的复合流程。

| 工具 | 输入 | 输出 | 实现 |
|---|---|---|---|
| `taint_via_atlas` | `{ source_pattern, sink_pattern, entry? }` | 可达路径列表 + query_id | 复合：`atlas_search` 定位 source/sink → `atlas_path` 连接 → `atlas_trace(variable)` 验证 → 汇总可达链 |
| `arkts_decoration_parse` | `{ path }` 或 `{ glob }` | @Component/@State/@Builder/@Link 装饰器与状态绑定关系 | ts-morph（atlas 未明确覆盖的装饰器语义） |
| `semgrep_run` | 后续可选 | 本轮不实现、不调用 | 引入规则引擎时重新设计 |
| `cve_lookup` | `{ package, version }` | CVE 列表 + 修复版本 | 本地 `knowledge/` 离线库 + 可选 OSV API |
| `finding_dedupe` | `{ findings[] }` | 去重后 findings + 合并组 | 文件+行+模式指纹聚类 |

### 工具骨架示例（`.opencode/tools/taint_via_atlas.ts`）

```ts
import { tool } from "@opencode-ai/plugin"
import { z } from "zod"

export const taint_via_atlas = tool({
  description: "跨过程污点可达性查询。给定 source/sink 模式，用 atlas 定位符号、连接路径、反向回溯验证，返回可达链与 query_id。",
  args: z.object({
    source_pattern: z.string().describe("source 符号模式，如 TextInput.onChange"),
    sink_pattern: z.string().describe("sink 符号模式，如 eval / executeSql / loadUrl"),
    entry: z.string().optional().describe("可选入口符号，限定分析范围"),
  }),
  async execute({ source_pattern, sink_pattern, entry }, ctx) {
    // 1) atlas_search 定位 source/sink 符号
    // 2) atlas_path from=source to=sink 取最短路径
    // 3) 若不直达，atlas_trace kind=variable 在 sink 反向回溯
    // 4) 汇总可达链，附带 query_id 供 resume
    // 返回 { reachable: boolean, chains: [...], query_id }
  },
})
```

> `taint_via_atlas` 内部如何调用 atlas MCP：opencode 的 custom tool 在 plugin 上下文里可通过 `client` 调用 MCP 工具；或更简单地——不封装，让 `taint-analyst` 直接在 prompt 里编排 `atlas_search`→`atlas_path`→`atlas_trace`（参考 `atlas-query-patterns` skill）。封装版适合复用与可测，两种方式择一。

---

## 8. Plugin 设计（`.opencode/plugins/harmony-audit-plugin.ts`）

订阅事件，做**审计轨迹落盘** + **run 目录初始化**（不干预业务逻辑）：

```ts
import type { Plugin } from "@opencode-ai/plugin"

export const harmonyAuditPlugin: Plugin = async ({ project, client }) => {
  return {
    "tool.execute.after": async (input, output) => {
      // tool 名为 atlas_* / taint_via_atlas 时，
      // 把 input+output 追加到 reports/<run>/trace.jsonl，形成可复核证据链
    },
    "session.idle": async () => {
      // session 空闲时，扫描 reports/<run>/findings.json，刷新索引
    },
  }
}
```

可选进阶：plugin 注入 `audit_run_init` 工具，自动建 `reports/<timestamp>/` 目录并调 `atlas_project open`。

---

## 9. 知识库与规则库设计

- `knowledge/vuln-patterns/*.md`：每类漏洞一份，含**模式描述 + 正/反例 + 修复 + CWE**。被 `arkts-vuln-kb` skill 聚合引用。
- `knowledge/permission-catalog/`：鸿蒙权限等级映射表（从官方文档抽取，可脚本化更新）。
- `knowledge/cwe-map.yml`：`{ injection: CWE-94, hardcoded_secret: CWE-798, ... }`，统一 finding 的 cwe 字段。
- `rules/semgrep/`：后续规则引擎预留目录；当前版本不加载、不执行，也不以其结果声明覆盖。
- `knowledge/checklist/harmony-audit-checklist.md`：人工复核清单，报告附录引用。

---

## 10. 落地路线图（分 4 阶段）

| 阶段 | 交付 | 验收 |
|---|---|---|
| **P1 骨架 + atlas 接入** | `opencode.json`（含 atlas mcp）+ `AGENTS.md` + 目录结构 + harmony-auditor + attack-surface-mapper + path-finder + path-validator + report-composer + `/audit` 命令 + `audit-workflow` / `audit-orchestration` / `attack-patterns` skill | 对一个真实鸿蒙仓：能 `atlas_project open` → 产出 entry/seed → worker pool 流水线 → validate-ready → 分层报告 → finalize |
| **P1.5 误报治理框架** | 反证优先验证 + 六门槛 + `confirmed_vulnerability/protected_exposure/residual_risk/benign_business_flow/insufficient_evidence` 分层落盘与报告 | 正常业务 deeplink、有效 WebView 白名单、不可控 sink 参数等场景能够降级,不进入主漏洞报告 |
| **P1.6 确定性项目建模** | project-modeling skill + Python `json5` 解析库 + project_model 契约 + mapper/validator 职责拆分 + 报告准入检查 | app/module/build/dependency 可重复解析；每个入口候选有明确去向；解析失败不会静默形成虚假覆盖 |
| **P1.7 稀疏攻击矩阵** | entry/sink 归一化 + 数据驱动 route config + `attack_matrix.json` + per-work-item path-finder + 矩阵覆盖准入 | 不做无意义全量任务；每个有效 Entry × Sink × Pattern 单元都有唯一终态，routing/analysis gap 显式披露 |
| **P2 核心 + 污点** | crypto / network / icc / web 等领域专家 + Atlas scoped discovery/path/trace 增强 + `atlas-query-patterns` skill | 扩展常见漏洞覆盖并量化 analysis unit/candidate/Atlas gap |
| **P3 深度** | napi-auditor（atlas `lifecycle`/`branch_diff`/`fp_dispatches` for C/C++）+ dependency-auditor + `cve_lookup` + `finding_dedupe` + plugin 轨迹 | NAPI native 内存安全 + 依赖 CVE + 可追溯证据链 |
| **P4 进阶** | `tools/arkts-decoration-flow/`（装饰器/异步状态流补充）+ 可选知识检索 MCP + 报告导出（HTML/PDF） | 装饰器状态流覆盖 + 大仓稳定性 |

> 关键变化：**污点能力从 P4 提前到 P2**（atlas 现成，无需自研引擎）；自研 `tools/arkts-decoration-flow/` 降级为 P4 补充（仅覆盖 atlas 不支持的装饰器/异步场景）。

### 低优先级技术债

- **异步滑动 subagent 池**：当前 TaskTool 调用同步阻塞父 agent,因此 5 个槽位表现为批次并发。后续通过 OpenCode plugin + child session async API 维护 `task_id ↔ child_session_id`,监听单任务完成事件并立即执行 `complete → next` 补位。验收标准是长短任务混合时并发槽位持续利用,不再等待同批最慢任务。

---

## 11. 关键决策点（待确认）

1. **atlas 安装路径**：atlas 是 Rust 二进制，需提供 `command` 数组里的可执行文件绝对路径（如 `/usr/local/bin/atlas` 或 `~/.cargo/bin/atlas`）。是否已编译/下载？若未安装，是否需要我在 README 里补安装步骤？
2. **源码发现引擎**：当前决策为 **Atlas-only**：Manifest 锚点 + scoped search + 有界图扩展；Semgrep 暂不接入，NAPI 延后。
3. **模型与成本策略**：编排者/污点/验证/napi 用强模型，侦察/manifest/依赖用中低模型——分级降本；或全用同一档。
4. **目标鸿蒙形态**：主要审 **HarmonyOS Next（纯 ArkTS）** 还是要覆盖 **OpenHarmony / 含 Java/JS 的旧 FA 模型**？后者需加 Java/JS 审计 subagent（atlas 当前语言表未见 Java/JS，需另配工具链）。
5. **只读审计约束**：atlas 会在目标仓写 `.atlas/atlas.db`。是否接受？或要求审计前自动 copy/worktree 隔离？

---

## 12. 参考资料

### opencode 机制依据
- [opencode config](https://opencode.ai/docs/config/) · [agents](https://opencode.ai/docs/agents/) · [skills](https://opencode.ai/docs/skills/) · [commands](https://opencode.ai/docs/commands/) · [plugins](https://opencode.ai/docs/plugins/) · [tools](https://opencode.ai/docs/tools/) · [custom-tools](https://opencode.ai/docs/custom-tools/) · [mcp-servers](https://opencode.ai/docs/mcp-servers/) · [config.json schema](https://opencode.ai/config.json)

### atlas（代码理解引擎）
- [atlas GitHub](https://github.com/LordCasser/atlas) · README（部署/能力/性能） · `docs/architecture.md`（能力门控：lifecycle 仅 C/C++；ArkTS 无 CFG，TS grammar fallback，支持 dataflow/interprocedural） · `docs/performance.md`（lazy/focus 大仓基线）
- opencode 接入：`mcp.atlas = { type:"local", command:["/path/to/atlas","mcp"], enabled:true }`

### 鸿蒙 / ArkTS 安全参考
- [HarmonyOS 开发者文档](https://developer.harmonyos.com/) · [OpenHarmony 安全仓库](https://gitee.com/openharmony/security)
- 常见领域：权限过度/运行时校验缺失；SQL/命令/模板注入、eval；Ability 组件导出、隐式 Want 劫持、公共事件权限缺失；硬编码密钥、弱算法、huks 误用、明文存储；HTTPS 明文、证书校验/绑定缺失；Web() 不可信页面、JSBridge 过度暴露；NAPI 边界（参数校验/缓冲区/整数溢出/生命周期）；ohpm 依赖 CVE；分布式数据/任务调度攻击面
