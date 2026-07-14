# 鸿蒙 ArkTS 白盒安全审计多智能体方案（适配 opencode）

> 项目：harmonySecAnalyzer-v3.1
> 目标：面向 HarmonyOS / OpenHarmony ArkTS 代码仓的白盒安全审计与漏洞挖掘多智能体系统
> 运行平台：[opencode](https://opencode.ai)（SST 团队开源终端 AI 编程代理）
> 代码理解引擎：[atlas MCP](https://github.com/LordCasser/atlas)（适配 ArkTS 语法的代码索引/调用图/数据流工具）
> 日期：2026-07-12

---

## 0. 方案定位

一个**面向 HarmonyOS / OpenHarmony ArkTS 代码仓的白盒安全审计多智能体系统**，用 opencode 原生的 `agent + subagent + skill + command + custom tool + plugin` 机制编排，以"**编排者 + 领域专家 subagent**"模式运行，借助 **atlas MCP** 提供确定性的符号/调用图/数据流/路径查询能力，输出可复核的结构化漏洞报告（含 CWE 映射、污点链、修复建议）。

### 核心设计原则

1. **知识与分析分离**：漏洞模式、权限映射、CWE 表 → 做成按需加载的 `skill`（不污染上下文）；具体分析动作 → 做成 `custom tool` 或 atlas MCP（确定性执行）。
2. **专家分工 + 编排收敛**：每个 subagent 只管一个领域（manifest / 注入 / NAPI / 加密 / 网络 / ICC / Web / 依赖），编排者负责切片、派发、去重、定级。
3. **LLM 判断 + 确定性工具兜底**：调用图、污点可达性、符号定位走 atlas（可复现、可追溯），规则匹配走 semgrep，LLM 只做语义判断和误报过滤。
4. **审计可追溯**：plugin 记录每条 finding 的产生链路（哪个 agent、哪条规则/查询、哪个文件行），便于复核。

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
| 静态规则扫描 | semgrep（YAML 规则） | 外部 CLI | 模式匹配扫描 |
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
| 静态分析规则 | **Semgrep (YAML)** 为主 | 对 TS/JS 语法兼容好、规则快；与 atlas 互补（atlas 做图查询，semgrep 做模式匹配） |
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
├── .opencode/                    # opencode 项目级资源目录（复数子目录，官方约定）
│   ├── agents/                   # 主 agent + 所有 subagent（一个 .md 一个 agent）
│   │   ├── harmony-auditor.md        # primary｜编排者：切片/派发/去重/定级
│   │   ├── codebase-scout.md         # subagent｜只读侦察：用 atlas 摸清 audit surface
│   │   ├── manifest-auditor.md       # subagent｜module.json5 / app.json5 审计
│   │   ├── arkts-sast.md             # subagent｜ArkTS 通用静态分析（注入/硬编码/eval）
│   │   ├── taint-analyst.md          # subagent｜用 atlas path/trace 做跨过程污点可达
│   │   ├── napi-auditor.md           # subagent｜NAPI 边界 + C/C++ 内存安全（atlas lifecycle/branch_diff）
│   │   ├── crypto-secrets-auditor.md # subagent｜密钥/加密/安全存储(huks)
│   │   ├── network-auditor.md        # subagent｜HTTPS/证书绑定/明文/SSL 校验
│   │   ├── icc-auditor.md            # subagent｜Ability/Want/公共事件（atlas calls/path 追数据流）
│   │   ├── web-component-auditor.md  # subagent｜Web() 组件 JSBridge 风险
│   │   ├── dependency-auditor.md     # subagent｜第三方 SDK/ohpm 依赖 CVE
│   │   ├── vuln-verifier.md          # subagent｜对抗式验证：去误报/可复现性判定
│   │   └── report-composer.md        # subagent｜汇总成结构化报告
│   ├── commands/                 # 斜杠命令（用户入口）
│   │   ├── audit.md                  # /audit [full|quick|manifest|<domain>] [path]
│   │   ├── triage.md                 # /triage 对 findings 去重/分级
│   │   └── report.md                 # /report 生成/导出报告
│   ├── skills/                   # 按需加载的知识/流程（SKILL.md）
│   │   ├── audit-workflow/SKILL.md       # 端到端审计 SOP（编排者必读）
│   │   ├── atlas-query-patterns/SKILL.md # 如何用 atlas 查污点/调用链/影响面（新）
│   │   ├── arkts-vuln-kb/SKILL.md        # ArkTS 漏洞模式知识库
│   │   ├── harmony-permission-map/SKILL.md
│   │   ├── harmony-icc-model/SKILL.md
│   │   ├── napi-boundary-rules/SKILL.md
│   │   ├── crypto-storage-guide/SKILL.md
│   │   ├── cwe-mapping/SKILL.md
│   │   ├── report-template/SKILL.md
│   │   └── semgrep-rule-authoring/SKILL.md
│   ├── tools/                    # opencode custom tool（TS，复合分析流程）
│   │   ├── taint_via_atlas.ts        # 封装 atlas search→path→trace 的污点可达查询
│   │   ├── arkts_decoration_parse.ts # ts-morph 做装饰器/@State 数据流（atlas 未覆盖）
│   │   ├── module_json5_parse.ts     # 解析 module.json5/app.json5
│   │   ├── semgrep_run.ts            # 跑 rules/semgrep/*.yml
│   │   ├── cve_lookup.ts             # ohpm 依赖→CVE 查询
│   │   └── finding_dedupe.ts         # 基于位置+模式指纹去重
│   ├── plugins/
│   │   └── harmony-audit-plugin.ts    # 事件 hooks：记录审计轨迹/初始化 run 目录
│   ├── prompts/                  # agent 长 prompt 片段，被 {file:./} 引用
│   │   ├── orchestrator.txt
│   │   ├── verifier.txt
│   │   └── shared-guidelines.txt
│   └── package.json              # plugin/tool 依赖：@opencode-ai/plugin, zod, ts-morph, json5
├── rules/                        # 静态分析规则库（独立于 .opencode，可单测/复用）
│   ├── semgrep/
│   │   ├── arkts-injection.yml
│   │   ├── arkts-hardcoded-secrets.yml
│   │   ├── arkts-insecure-storage.yml
│   │   ├── arkts-web-component.yml
│   │   ├── arkts-icc.yml
│   │   ├── arkts-crypto.yml
│   │   ├── arkts-network.yml
│   │   └── napi-boundary.yml
│   └── codeql/                   # 可选：仅针对 C/C++ native 部分
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
│   └── semgrep-spec/
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
│   scout ─ manifest ─ arkts-sast ─ taint ─ napi ─ crypto ─    │
│   network ─ icc ─ web ─ dependency ─ verifier ─ composer     │
├─────────────────────────────────────────────────────────────┤
│  能力层   atlas MCP(符号/调用图/数据流/路径) +                │
│           skills(按需知识) + custom tools(复合流程)           │
│           + semgrep(规则扫描) + plugin(轨迹/事件)             │
├─────────────────────────────────────────────────────────────┤
│  资产层   rules/semgrep  knowledge/  cwe-map  examples/      │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 编排流程（端到端）

1. **`/audit full <repo-path>`** → 触发 `harmony-auditor`（primary）。
2. **激活 atlas**：编排者调 `atlas_project action=open project_path=<repo-path>`，打开/创建 `<repo>/.atlas/atlas.db`。后续所有 subagent 共享该 atlas 会话（focus lazy extraction，大仓友好）。
3. **侦察**：编排者调 `codebase-scout`（只读 subagent），用 `atlas_search`/`atlas_symbol`/`atlas_file_dependencies` + grep 摸清：模块边界、`module.json5` 清单、Ability/ExtensionAbility 入口、ohpm 依赖、NAPI 模块清单、Web 组件使用点。产出**审计面**（audit surface）。
4. **切片**：编排者加载 `audit-workflow` skill，按审计面切片（manifest / ArkTS 代码 / NAPI / 依赖）。
5. **并行派发**领域 subagent（`task` 工具，每个带切片上下文 + 领域 skill）。定位与可达性用 atlas，模式扫描用 semgrep。每个 subagent 产出**结构化 findings**（统一 schema）。
6. **验证**：`vuln-verifier` 对中高置信度 finding 做对抗式复核（用 atlas `path`/`trace` 验证可达性、构造 PoC 片段、判误报），输出最终置信度。
7. **去重**：`finding_dedupe` 工具按指纹（文件+行+模式）去重。
8. **报告**：`report-composer` 汇总，加载 `report-template` skill，生成 Markdown 报告写入 `reports/<run>/`。

### 3.3 关键机制利用

- **subagent 调用与权限收窄**：编排者 `permission.task` glob 只放行审计相关 subagent：

  ```json
  "permission": {
    "task": {
      "*": "deny",
      "codebase-scout": "allow",
      "*-auditor": "allow",
      "taint-analyst": "allow",
      "vuln-verifier": "allow",
      "report-composer": "allow"
    }
  }
  ```

  专家 subagent 默认 `task: deny`（不再级联）。

- **atlas 工具按 agent 启用**：opencode 中 atlas 工具名为 `atlas_*`。全局启用 atlas，再按 agent 用 `permission` 的 `atlas_*` glob 收窄（如 `report-composer` 设 `"atlas_*": "deny"`，`taint-analyst` 设 `"atlas_*": "allow"`）。

- **skill 按需加载**：知识库不进系统提示，subagent 需要时 `skill({name:"..."})` 拉取。

- **plugin 可追溯**：订阅 `tool.execute.after`，把 `atlas_*`/`semgrep_run`/`taint_via_atlas` 的输入输出落盘到 `reports/<run>/trace.jsonl`，形成审计证据链。

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

> ArkTS 无 CFG，故 `lifecycle`/`branch_diff`/`fp_dispatches` 不适用（这些门控为 C/C++）——它们正好用在 NAPI 的 native 层。装饰器（@Component/@State/@Builder）的专门语义 atlas 文档未明确，方案用 ts-morph 做补充（`arkts_decoration_parse` + P4 `tools/arkts-decoration-flow/`）。

**注意事项**：
- atlas 在被审计仓写 `.atlas/atlas.db`。若需只读审计，先 copy 目标仓或用 git worktree，避免污染原仓。
- atlas MCP 用客户端 cwd，但 `project open` 接受 `project_path` 绝对参数，故可审计任意路径的仓。
- 跨 Worker/TaskPool 的异步污点、装饰器状态流转是 atlas 当前未覆盖的场景，由 ts-morph 补充（P4）。

---

## 4. Agent 详细设计

### 4.1 Agent 一览

| Agent | mode | 模型建议 | 工具 | 职责 |
|---|---|---|---|---|
| `harmony-auditor` | primary | 强(opus/sonnet) | read/grep/glob + task + skill + todowrite + `atlas_project` | 编排：open atlas→侦察→切片→派发→收敛→报告 |
| `codebase-scout` | subagent | 中(haiku/sonnet) | read/grep/glob + `atlas_search`/`atlas_symbol`/`atlas_file_dependencies` | 摸清仓库结构，产出 audit surface |
| `manifest-auditor` | subagent | 中 | read + module_json5_parse + skill | 审计 module.json5/app.json5：权限过度/组件导出/visible |
| `arkts-sast` | subagent | 中 | read/grep/glob + semgrep_run + `atlas_search`/`atlas_symbol`/`atlas_explore` + skill | 通用静态分析：注入/硬编码/eval/不安全存储 |
| `taint-analyst` | subagent | 强 | read + taint_via_atlas + `atlas_path`/`atlas_trace`/`atlas_calls` + skill | 跨过程污点：source→sink 可达性 |
| `napi-auditor` | subagent | 强 | read/grep/glob + bash(semgrep/codeql) + `atlas_lifecycle`/`atlas_branch_diff`/`atlas_fp_dispatches` + skill | NAPI 边界 + C/C++ 内存安全 |
| `crypto-secrets-auditor` | subagent | 中 | read/grep + semgrep_run + skill | 密钥硬编码/弱算法/huks 误用/明文存储 |
| `network-auditor` | subagent | 中 | read/grep + semgrep_run + skill | HTTPS/证书绑定/明文/SSL 校验 |
| `icc-auditor` | subagent | 强 | read + module_json5_parse + `atlas_calls`/`atlas_path`/`atlas_trace` + skill | Ability/Want/公共事件/隐式调用/导出 |
| `web-component-auditor` | subagent | 中 | read/grep + semgrep_run + `atlas_trace` + skill | Web() 组件 JSBridge/JS 调原生/loadUrl 不可信 |
| `dependency-auditor` | subagent | 中 | read + cve_lookup + bash(ohpm) + skill | ohpm 依赖/三方 SDK CVE 与许可证 |
| `vuln-verifier` | subagent | 强(opus) | read/grep + `atlas_path`/`atlas_trace`/`atlas_impact` + skill | 对抗式复核：可达性/PoC/误报判定 |
| `report-composer` | subagent | 中 | read/write + skill（`atlas_*` deny） | 汇总→结构化报告（写 reports/） |

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
    codebase-scout: allow
    "*-auditor": allow
    taint-analyst: allow
    vuln-verifier: allow
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
| `audit-workflow` | 编排者启动时 | 端到端 SOP：open atlas→侦察→切片→派发→验证→去重→报告；切片粒度；并行度 |
| `atlas-query-patterns` | taint/icc/verifier 工作时 | 如何用 atlas 查污点/调用链/影响面：source/sink 如何定位、`path` vs `trace(variable/forward/callers)` 选择、`query_id`+`resume_query` 处理 lazy 未决 |
| `arkts-vuln-kb` | arkts-sast/taint 工作时 | ArkTS 漏洞模式库（注入/硬编码/eval/状态管理/UI 注入），每条含模式+示例+修复+CWE |
| `harmony-permission-map` | manifest/icc 工作时 | 鸿蒙权限等级（normal/system/user_grant）↔ 敏感资源↔ 风险矩阵 |
| `harmony-icc-model` | icc-auditor 工作时 | Stage/FA 模型 Ability/Want/公共事件/ExtensionAbility 数据流与攻击面 |
| `napi-boundary-rules` | napi-auditor 工作时 | NAPI 边界检查清单 + atlas `lifecycle`/`branch_diff` 用法 |
| `crypto-storage-guide` | crypto-secrets 工作时 | huks 正确用法/算法白名单/存储加密规范 |
| `cwe-mapping` | 所有 subagent 产出时 | 漏洞类型→CWE/OWASP Mobile Top10 映射 |
| `report-template` | report-composer 工作时 | 报告 schema、章节结构、severity 计数、修复优先级 |
| `semgrep-rule-authoring` | 需要补规则时 | 如何为 ArkTS 声明式 UI 语法写 semgrep 规则（含 .ets 解析坑） |

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
| `/triage` | — | 对 `reports/<run>/findings.json` 去重+重定级（调 vuln-verifier） |
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

按 audit-workflow skill 执行：先 atlas_project open，再侦察→切片→派发→验证→去重→报告，最终写入 reports/ 目录。
```

---

## 7. Custom Tools 设计（`.opencode/tools/*.ts`）

用 `@opencode-ai/plugin` 的 `tool()` + Zod。**agent 优先直接调 atlas MCP 工具**；custom tool 只做"编排多个 atlas 调用 + 解读"的复合流程。

| 工具 | 输入 | 输出 | 实现 |
|---|---|---|---|
| `taint_via_atlas` | `{ source_pattern, sink_pattern, entry? }` | 可达路径列表 + query_id | 复合：`atlas_search` 定位 source/sink → `atlas_path` 连接 → `atlas_trace(variable)` 验证 → 汇总可达链 |
| `arkts_decoration_parse` | `{ path }` 或 `{ glob }` | @Component/@State/@Builder/@Link 装饰器与状态绑定关系 | ts-morph（atlas 未明确覆盖的装饰器语义） |
| `module_json5_parse` | `{ path }` | abilities/extensionAbilities/requestPermissions/visible/exported | JSON5 解析 + 风险字段提取 |
| `semgrep_run` | `{ rules, target }` | 结构化 matches（rule/file/loc/message/severity） | 子进程调 `semgrep --json` |
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
      // tool 名为 atlas_* / semgrep_run / taint_via_atlas 时，
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
- `rules/semgrep/*.yml`：规则与知识库**一一对应**，单测放 `tests/semgrep-spec/`，正例 `examples/vulnerable-samples/`、反例 `examples/safe-samples/`。
- `knowledge/checklist/harmony-audit-checklist.md`：人工复核清单，报告附录引用。

---

## 10. 落地路线图（分 4 阶段）

| 阶段 | 交付 | 验收 |
|---|---|---|
| **P1 骨架 + atlas 接入** | `opencode.json`（含 atlas mcp）+ `AGENTS.md` + 目录结构 + harmony-auditor + codebase-scout（用 atlas 侦察）+ manifest-auditor + `/audit` 命令 + `audit-workflow` skill | 对一个真实鸿蒙仓：能 `atlas_project open` → 侦察出 audit surface → manifest 审计 → 报告 |
| **P2 核心 + 污点** | arkts-sast / crypto-secrets / network / icc / web-component subagent + semgrep 规则集 + `semgrep_run`/`module_json5_parse` + **taint-analyst（atlas path/trace）** + `atlas-query-patterns` skill + `arkts_decoration_parse` | 覆盖 8 类常见漏洞 + 跨过程污点可达性判定；规则有正反例回归 |
| **P3 深度** | napi-auditor（atlas `lifecycle`/`branch_diff`/`fp_dispatches` for C/C++）+ dependency-auditor + `cve_lookup` + vuln-verifier（atlas 复核）+ `finding_dedupe` + plugin 轨迹 | NAPI native 内存安全 + 依赖 CVE + 误报过滤 + 可追溯证据链 |
| **P4 进阶** | `tools/arkts-decoration-flow/`（装饰器/异步状态流补充）+ 可选知识检索 MCP + 报告导出（HTML/PDF） | 装饰器状态流覆盖 + 大仓稳定性 |

> 关键变化：**污点能力从 P4 提前到 P2**（atlas 现成，无需自研引擎）；自研 `tools/arkts-decoration-flow/` 降级为 P4 补充（仅覆盖 atlas 不支持的装饰器/异步场景）。

---

## 11. 关键决策点（待确认）

1. **atlas 安装路径**：atlas 是 Rust 二进制，需提供 `command` 数组里的可执行文件绝对路径（如 `/usr/local/bin/atlas` 或 `~/.cargo/bin/atlas`）。是否已编译/下载？若未安装，是否需要我在 README 里补安装步骤？
2. **静态分析引擎**：推荐 **Semgrep（ArkTS 模式扫描）+ atlas（图查询/污点）互补**，NAPI 的 C/C++ 部分可选 CodeQL。是否按此？
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
