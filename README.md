# harmonySecAnalyzer-v3.1

面向 HarmonyOS ArkTS 项目的多智能体白盒安全审计系统，同时支持 OpenCode 与 Claude Code。脚本完成项目建模、Atlas 索引、组件探索状态和任务生成；组件语义 Agent 优先使用 Atlas 分轮探索源码事实，并以受限源码证据补全动态调用缺边，运行时从闭合节点生成最终语义结果，独立验证 Agent 再完成六维漏洞有效性判断。

OpenCode 使用 `.opencode/` 资源目录；Claude Code 使用 `.claude/` 资源目录（含 `.mcp.json` 的 Atlas MCP 与 `/audit` 命令）。部署时会把 Agent、Skill、脚本、Schema 和配置复制到对应工具的配置目录；运行时不依赖本源码仓库的相对路径。

## 使用

```text
/audit <repo-path>
/audit --incremental <repo-path>
/audit --resume <run-dir>
/audit --capability <CAP-ID> <repo-path>
/audit --component <AbilityName> <repo-path>
/audit --component <module/ExtensionAbilityName> --capability <CAP-ID> <repo-path>
```

`--incremental` 使用上次成功的无过滤审计作为基线。Git 项目记录两个审计提交之间的累计变化并纳入工作区，非 Git 项目使用内容哈希快照。受影响组件重新执行语义分析，未受影响组件复用已校验的语义结果；组件连接始终使用当前完整状态重新计算，操作组集合和安全语义均未变化时同时复用六维验证结论。报告按稳定 Finding ID 展示新增、结论变化、已消失和未变的风险路径。

`--resume` 用于最终报告存在 exhausted 任务的运行。参数是具体 run 目录；已完成结果保持不变，只重试失败任务，成功后覆盖生成该 run 的报告并推进合格基线。

`--component` 与 `--capability` 均可重复并可组合。组件过滤用于定点审计 Ability/ExtensionAbility，能力过滤用于只验证指定能力。项目建模不再为每个模块创建宽泛的 CommonEvent 子任务；相关代码只作为所属 Ability/ExtensionAbility 组件语义的一部分处理。

资源目录是部署生成物，不入库：`.opencode/`、`.claude/`、`opencode.json`、`.mcp.json`、`AGENTS.md`、`CLAUDE.md` 均由 `deploy.py` 按工具渲染生成。克隆后必须先用目标工具部署一次：

```bash
python3 -m pip install -r requirements.txt
python3 deploy.py --tool opencode          # 本项目内用 OpenCode 审计
python3 deploy.py --tool claude            # 本项目内用 Claude Code 审计
python3 deploy.py --tool opencode --global # 全局安装到 ~/.config/opencode
python3 deploy.py --tool claude --global   # 全局安装到 ~/.claude(并注册 atlas MCP)
python3 deploy.py --tool claude --uninstall
```

规范源位于 `resources/`（agents/commands/skills 模板、运行时脚本与共享约定文档）；生成器按 `--tool` 的 profile 渲染 frontmatter 与工具专属段落。

## 架构

| 阶段 | 组件 | 产出 |
|---|---|---|
| 审计准备与任务生成 | `project-modeling` Skill、Atlas Indexer、Python Runtime | 项目事实、完整索引、组件分析单元与任务 |
| 组件语义分析 | `component-semantic-analyzer` Agent、Atlas MCP、Semantic Exploration Runtime | Atlas 优先定位并由源码证据补全动态调用；优先走完当前路径，短路径结束后在同一轮继续下一条，长路径保存证据后换新上下文续跑 |
| 组件关联与六维验证 | Python Correlator、`exploitability-validator` Agent、Result Writer | 跨组件参数与身份链、带证据的三态六维结论；Agent 写草稿，`audit_orchestrator.py task-submit` 统一规范化、校验并即时落库 |
| PoC 生成 | `poc-generator` Agent、Result Writer | 已确认漏洞的可复现触发套件；脚本补齐固定字段、规范证据引用并标记“已生成但未编译验证” |
| 状态与报告 | `audit-orchestration` Skill | SQLite 状态、根因聚合、漏洞证据路径、JSON/Markdown/HTML |

CAP-DOS-001 用于 ArkTS 可用性安全审计，覆盖外部可触发的崩溃、无界或可放大的 CPU/内存/线程/队列/存储消耗，以及可重复的 IPC 和 CommonEvent 资源耗尽。Native/NAPI 层 DoS 不在当前范围内。

`run.db` 是运行状态唯一事实源。`exports/exploration_graph.json` 展示组件探索过程，`exports/attack_matrix.json` 是入口、实际操作组和 Finding 的确定性覆盖视图。

渐进探索遇到本轮容量不足时，保存事实和待分析断点，并通过 `pause_requested` 请求新上下文继续同一组件；未分析路径不会作为正常暂停的覆盖缺口。真实解析失败在 `gaps` 中一次性保存目标、原因和证据，组件总工作量终止仅由脚本决定。

当前函数内部尚未分析完时，用 `resume` 保存源码位置、剩余工作和安全状态，下一轮从同一函数的该位置继续，不当作循环去重。入口发现后的新证据可以更新同一份入口判断，不会将初始“不确定”固定为最终结论。

AI 不再填写步骤状态或重复的继续/停止标记：后续目标有正常停止原因时记录边界，否则继续排队；节点处理状态和覆盖结论由脚本推导。已提交结果的节点即使正常返回或存在缺口也不会被重复派发。沿途安全检查以源码位置、检查对象和校验属性传递，由脚本生成稳定标识。取值标准直接写在语义 Agent 与 Schema 中。运行数据版本更新后，旧格式的未完成探索需新建审计，不兼容续跑。

完整设计见 [DESIGN.md](DESIGN.md)。
