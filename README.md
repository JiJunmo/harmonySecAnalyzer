# harmonySecAnalyzer-v3.1

适配 opencode 的鸿蒙 ArkTS 代码仓白盒安全审计多智能体系统。

## 是什么

用 opencode 原生 `agent / subagent / skill / command` 机制 + [atlas MCP](https://github.com/LordCasser/atlas)（适配 ArkTS 的代码索引/调用图/数据流引擎）编排多智能体，对鸿蒙 ArkTS 代码仓做白盒安全审计与漏洞挖掘，输出分层结构化报告。

当前实现采用**确定性项目建模 + 攻击路径驱动 + 反证优先验证**：先由脚本解析 JSON5 工程配置、组件和入口候选，再由 agent + atlas 枚举攻击面、连接入口到 sink，最后按六门槛验证是否真的构成漏洞。外部可达、敏感 API、调用链存在只会被视为 exposure/capability/path，不能直接升级为漏洞。

调度状态机采用 **稀疏 Entry × Sink × Pattern 攻击矩阵 + 5 槽任务池 + streaming promotion**：Manifest 别名和重复 sink 分别归一化,机器路由在 discovery unit 关联范围内为有效矩阵单元生成 work item;中间转存节点不独立立项。path-finder 不再自行挑选 seed。路径结果通过 admission contract 后按 normalized seed/pattern 做根因级去重,每个根因只分配一个 `CAND-xxx` 和 validator,多种启动方式保留为 trigger variants。worker 使用状态机下发的绝对结果路径提交并回读产物;provider 中断、缺失/无效结果会自动重试最多 3 次。受当前 OpenCode 同步 TaskTool 限制,subagent 执行层表现为最多 5 个一批。矩阵和验证任务闭合后才能生成报告,报告产物复核通过后 session 才进入 `completed`。

项目建模阶段生成的每个入口候选都必须被 mapper 明确且唯一地接收、排除、标记未决或记录为 Atlas 覆盖缺口；遗漏、重复归类、未知 ID 或仍未决都会阻止 `validate-ready`。已终态化的 Atlas 缺口允许生成 `partial` 报告，但必须在报告中显式披露。

完整设计见 [DESIGN.md](./DESIGN.md)。

## 架构（当前流水线）

`项目解析 → 逻辑审计与漏洞发现 → 漏洞验证 → 报告生成`

| 阶段 | Agent | 状态 |
|---|---|---|
| 项目建模 | `project-modeling/scripts/project_profiler.py` | ✅ P1.6 |
| 编排 | `harmony-auditor`（primary） | ✅ P1 |
| 攻击面测绘 | `attack-surface-mapper` | ✅ P1 |
| 路径发现 | `path-finder` | ✅ P1 |
| 漏洞验证 | `path-validator` | ✅ P1 |
| 报告生成 | `report-composer` | ✅ P1 |
| 领域专家扩展 | crypto / network / icc / web / dependency | ⏳ P2/P3 |
| NAPI/native 审计 | 独立扩展 | ⏳ 后续 |

## 漏洞确认标准

`path-validator` 只有在六门槛全部满足时才输出 `confirmed_vulnerability`：

1. 外部可达
2. 攻击者可控关键参数
3. 可控值到达敏感 sink
4. guard 缺失或可绕过
5. 违反身份、权限、来源、域名、路径、组件、数据所有权或业务授权边界
6. 有具体安全影响

降级分类：

- `protected_exposure`：有外部暴露和敏感能力，但有效 guard 将行为约束在安全范围。
- `benign_business_flow`：属于预期公开业务能力，未越过安全边界。
- `residual_risk`：路径可疑或防护较弱，但缺少确认漏洞的关键证据。
- `insufficient_evidence`：证据不足，不臆造。

## 依赖

- [opencode](https://opencode.ai)
- [atlas](https://github.com/LordCasser/atlas)：已配置于 `/Users/jixiaokui/.cargo/bin/atlas`（见 `opencode.json` 的 `mcp.atlas`）
- Python `json5`：`python3 -m pip install -r requirements.txt`

## 使用

```bash
opencode
# 在 opencode 内
/audit manifest /path/to/harmony/repo
```

报告输出到 `reports/<project-name>-<target-path-hash>/<run-id>/`（`findings.json` + `report.md`）。每次审计由状态机原子分配独立 run，不覆盖或复用同一项目的历史结果。主报告只包含 `confirmed_vulnerability`，其余分层进入 protected exposure、residual risk、benign business flow、insufficient evidence 和攻击面附录。

## 配置模型

所有 agent 均未写死 `model` 字段，统一跟随 opencode 默认模型。运行前用 `opencode auth login` 配置 provider（anthropic / openai / glm 等），启动后在 TUI 用 `/model` 选择模型，所有 agent 即用该模型。

## 目录

- `.opencode/`：opencode 资源（agents/commands/skills/tools/plugins）—— opencode 强制约定目录
- `rules/`：静态规则预留目录（当前主流程不使用 Semgrep）
- `knowledge/`：漏洞知识库、权限映射、CWE 表
- `examples/` `tests/`：规则回归
- `reports/`：审计产出（gitignore）
- `.opencode/skills/audit-orchestration/scripts/`：`audit-orchestration` skill 私有状态机脚本
- `tools/`：独立 CLI 工具（P4）

## 状态存储

每次审计运行写入 `reports/<project-name>-<target-path-hash>/<YYYYMMDD-HHMMSS>-<scope>-<run-id>/`：

- `project/project_model.json`：确定性项目结构、组件、权限、依赖和入口候选
- `atlas/discovery_plan.json`：由 Manifest 锚点生成的 Atlas 分析单元及其覆盖终态
- `atlas/query_evidence.jsonl`：mapper 执行的 Atlas 查询与结果摘要
- `atlas/entry_list.json`、`atlas/danger_seed_list.json`：外部入口与可达危险能力种子
- `queue.jsonl`：任务当前状态、尝试次数、最后错误与重试历史
- `task_events.jsonl`：append-only 调度事件
- `candidate_index.json`：根因级增量去重、入口触发变体合并与稳定 candidate ID
- `analysis/danger_seeds.json`：按 sink 符号、位置和敏感参数归一化的危险操作
- `analysis/attack_matrix.json`：按 discovery unit 关联剪枝的稀疏 Entry × Sink × Pattern 工作项、终态 routing gap、中间节点排除与覆盖台账
- `paths/*.jsonl`：路径发现结果
- `validation/*.jsonl`：分层验证结果

## 路线图

- [x] **P1 骨架**：harmony-auditor + attack-surface-mapper + path-finder + path-validator + report-composer + `/audit` + audit-workflow/audit-orchestration skill + atlas 接入
- [x] **P1.5 误报治理框架**：六门槛验证 + 反证优先 + 分层报告
- [x] **P1.6 确定性项目建模**：`json5` 成熟解析库 + project_model/discovery_plan + Atlas scoped mapper
- [x] **P1.7 稀疏攻击矩阵**：entry/sink 归一化 + 数据驱动 `Entry × Sink × Pattern` 路由 + per-work-item 路径任务与覆盖闭合
- [ ] **P2 核心**：crypto / network / icc / web 等领域专家 + Atlas 查询模式与污点增强
- [ ] **P3 深度**：napi / dependency + finding_dedupe + plugin 轨迹
- [ ] **P4 进阶**：装饰器数据流 + 报告导出
- [ ] **P4/低优先级技术债**：基于 OpenCode async session/plugin 实现真正的滑动 subagent 池；任一任务完成后立即 `complete → next` 补位,替代当前 5 个一批的同步执行
