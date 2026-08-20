# harmonySecAnalyzer → DeepSeek Harness (DSH) 迁移指南

> 状态：已实现并端到端验证（组件语义分析 → 确定性连接 → 六维验证 → 报告）。
> 迁移产物以 **DSH 自定义 Agent preset** 形态交付，与宿主内置的 `harmony_audit_*` 工具完全独立、互不干扰。

## 1. 迁移目标与原则

| 项 | 决策 |
|---|---|
| 编排形态 | 完整复现三 Agent 编排（组件语义分析 / 六维验证 / PoC 生成）+ harmony-auditor 编排循环 |
| 审计范围 | 保持 ArkTS + CAP-DOS-001，不扩展 Native/NAPI |
| 与宿主内置工具关系 | 独立实现，不调用 `harmony_audit_*` |
| 交付形态 | DSH 自定义 Agent preset（`~/.dsh/.agent-presets/harmony-auditor/`） |

**核心策略：只换编排壳，不动运行内核。**
本项目原架构中，`resources/skills/audit-orchestration/scripts/audit_runtime/*.py` 是一套**平台无关的确定性 Python 运行时**（prepare/claim-batch/reconcile-batch/finalize + SQLite `run.db`）。opencode/claude 侧的 Agent 循环只是它的"编排壳"。迁移到 DSH 时：

- **Python 运行时原样打包**进 preset 的 skills 目录（零改动，`pytest` 全绿验证）；
- **编排循环**由 DSH 的 `persona` + `audit-orchestration` skill 承载（与 opencode/claude 版同一逻辑：prepare → claim → reconcile → finalize）；
- **三个 worker 角色**由 DSH `subagent` 派发，统一走 `audit-worker` skill，按 `task.kind` 分派语义/验证/PoC 契约（DSH 子代理继承父 preset 组合，角色由任务内容区分，与原系统 task-driven 设计一致）。

## 2. 交付物清单

### 2.1 DSH Agent preset：`~/.dsh/.agent-presets/harmony-auditor/`

```
harmony-auditor/
├── preset.yml            # 显示元数据（name/description/order）
├── agent.cordis.yml      # 组合：standard 全量能力 + 自定义 persona + 自包含 skills
├── agents/               # 增量基线契约哈希所需（SKILL_DIR.parent.parent/agents）
│   ├── component-semantic-analyzer.md
│   ├── exploitability-validator.md
│   └── poc-generator.md
└── skills/               # dsh-skill-filesystem customSkillDirs 注册到 preset 层
    ├── audit-orchestration/   # SKILL.md + scripts/（完整运行时）+ config/schemas/（全部 JSON Schema + 能力注册表）
    ├── audit-worker/          # SKILL.md：三种 worker 角色的产出契约
    ├── audit-workflow/        # SKILL.md：共享工作流约定（组件语义单元/证据链/六维决策）
    ├── project-modeling/      # SKILL.md + scripts/（project_profiler.py + atlas_indexer.py）
    └── shared-conventions/    # 共享约定文档
```

### 2.2 运行时自包含性说明

运行时通过相对路径解析关键资源（与源码仓库部署后同一布局）：

- `SKILL_DIR = scripts/audit_orchestrator.py 的上级的上级`（即 `skills/audit-orchestration/`）
- `SCHEMAS_DIR = SKILL_DIR/config/schemas`（全部任务输出契约）
- `PROJECT_MODELING_SCRIPTS = SKILL_DIR.parent/project-modeling/scripts`（profiler + atlas indexer）
- 增量契约哈希读 `SKILL_DIR.parent.parent/agents/*.md`（所以 `agents/` 目录必须存在）

打包验证：以 preset 内运行时为被测对象跑 `tests/test_flow_runtime.py`、`test_poc_runtime.py`、`test_incremental_runtime.py`，**139 passed + 12 subtests**。

## 3. 使用方式（DSH web）

1. 在 DSH web GUI 新建会话，在 Agent preset 选择器中选择 **`harmony-auditor`**（预设默认仍为 `standard`，不影响日常编码会话）。
2. 在会话中发起审计：

```
/audit <repo-path>
/audit --incremental <repo-path>
/audit --capability CAP-INJ-001 <repo-path>
/audit --component EntryAbility <repo-path>
/audit --resume <run-dir>
```

3. 编排者（harmony-auditor persona + audit-orchestration skill）会：
   - `prepare`（profiler + Atlas 全量索引 + run 初始化 + 组件可达函数图 + 语义批次）；
   - 循环 `claim-batch` → 以 `subagent` 派发 worker（数量与句柄一致）→ `reconcile-batch`；
   - `claim-batch` 返回 `no_queued` 后 `finalize` 生成完整报告。
4. 报告与状态在目标仓库 `reports/<run>/` 下（`report.html` 可在浏览器实时刷新；`run.db`、`exports/attack_matrix.json`、`report.md`、`report_snapshot.json` 等随 finalize 生成）。

## 4. 源码事实核验方式（Atlas）

DSH web profile 默认未接线 Atlas MCP，因此 worker 的源码核验采用**自包含**方式：

- 运行时脚本（`AtlasGraphProvider`）直接**只读打开**目标仓库 `.atlas/atlas.db`（表：`files/symbols/symbol_edges/callsites/references`）做批量符号/调用查询；
- worker 沿用同一方式：python 只读查询 `.atlas/atlas.db`，或直接读目标源码文件核对符号与调用关系；
- 索引由 `prepare` 内部经 `atlas_indexer.py` 调用本机 `atlas index --analysis full` 建立（本机 `~/.cargo/bin/atlas` 支持 ArkTS）。

如需恢复 Atlas MCP 交互式核验，可在 DSH profile 层接线 `@deepseek-ai/dsh-mcp-client`（可选增强，非必需）。

## 5. 已验证证据（端到端）

在最小 ArkTS fixture（1 模块、2 组件、6 入口候选）上完整跑通：

| 阶段 | 结果 |
|---|---|
| `prepare --mode full` | ok；profiler 解析 2 组件/6 候选；Atlas 索引 2 文件/14 符号/9 边；run 创建 |
| `claim-batch` | 领取 2 个 `component_semantic_analysis` 任务 |
| worker（语义） | 真实 subagent 按 audit-worker 契约产出 schema 有效提交（DataShareExtAbility 无敏感操作；EntryAbility 记录 CAP-INJ-001 注入操作组） |
| `reconcile-batch` | 有效提交入库；缺失提交自动重试（missing_submission → queued） |
| correlation | 自动生成 `exploitability_validation` 任务 |
| worker（验证） | 六维判定；首次提交因决策表不一致被运行时业务校验拒绝 → 重试收敛为 `no_exploitable_path`（维度3 决定性反证：无真实 sink） |
| `reconcile-batch` → `finalize` | ok；`run.db`、9 个 exports、`report.md`、`report.html`（五视图）、`findings.json`、incremental-baseline 全套 |
| 模式矩阵 | `--mode capability`（CAP-INJ-001）✓；`--mode full --component DataShareExtAbility` ✓ |

决策表约束（如 `residual_risk_requires_established_core_path`）由 `contracts.py` 运行时校验器强制，worker 提交必须表内一致才入库——这保证了确定性判定，与源码仓库行为完全一致。

## 6. 卸载 / 回滚

```bash
# 删除 preset（不影响其他 preset 与宿主内置工具）
rm -rf ~/.dsh/.agent-presets/harmony-auditor

# 若曾修改过默认 preset，改回 standard（默认即 standard，通常无需操作）
# ~/.dsh/settings.yaml 中 agent-presets.default 保持 standard 即可
```

审计目标仓库上生成的 `.atlas/` 与 `reports/` 目录按需删除即可还原。

## 7. 与源码仓库的关系

- 本 preset 是源码仓库的**部署产物**（对应原 opencode/claude 的 `deploy.py` 角色），**不入库**。
- 运行时与 skill 的唯一事实源仍是源码仓库 `resources/skills/`；preset 内的副本由迁移脚本生成。
- 若修改源码仓库运行时，重新执行本迁移流程的"打包"步骤即可刷新 preset 副本（保持相对布局不变）。

## 8. 已知边界

- worker 的源码核验走只读 SQLite + 源码直读，而非 Atlas MCP 交互；对"符号探索/路径追踪"这类交互式查询，可用 python 脚本按 `atlas_graph.py` 的模式补查。
- PoC 阶段在本次端到端验证中未触发（结果无 confirmed/residual finding）；PoC 任务由运行时在确认/残余风险 Finding 落库时自动派生，逻辑与源码仓库一致（已有 `test_poc_runtime.py` 覆盖）。
- 宿主已注入的 `harmony_audit_*` 工具与本 preset 无关，不调用、不冲突。
