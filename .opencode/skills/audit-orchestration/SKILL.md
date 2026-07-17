---
name: audit-orchestration
description: 审计流水线状态机调用协议。harmony-auditor 调度时加载,定义如何用 scripts/audit_orchestrator.py 推进 worker-pool + streaming pipeline。
---

## 状态机脚本

`scripts/audit_orchestrator.py`(Python,确定性,跨平台;依赖根目录 `requirements.txt` 中的 `jsonschema`)。harmony-auditor **通过 bash 调用**,不手写 queue/session/candidate_index。所有命令输出 JSON。

状态机负责:

- `new-run`:按目标仓规范路径生成稳定 project key,并原子分配不可复用的 run 目录。
- `queue.jsonl`:任务当前状态。
- `task_events.jsonl`:append-only 调度事件。
- `candidate_index.json`:增量去重与稳定 `CAND-xxx` 分配。
- `project/project_model.json`:由 project-modeling skill 生成;状态机检查 schema/status,并核对每个 project entry candidate 是否恰好进入 entry/excluded/unresolved/coverage_gaps 之一。重复归类和未知 candidate ID 都会阻断报告。
- `atlas/discovery_plan.json`:Manifest 入口与 IPC service 候选生成的 Atlas analysis units;状态机检查每个 unit 的终态。
- `atlas/query_evidence.jsonl`:mapper 的 Atlas 查询输入、命中、query_id 与 diagnostics。
- `analysis/danger_seeds.json`:按 sink symbol/location/敏感参数归一化的危险操作。
- `analysis/attack_matrix.json`:确定性编译的稀疏 `Entry × Sink × Pattern` 矩阵;每个 work item 必须终态化。
- `config/audit_capabilities.json`:审计能力、分析模式、路由条件、真实实现状态、优先级和建设缺口的唯一机器配置。状态机从 capability 的 `routing` 编译 route,并拒绝缺少模式卡或实现声明的 enabled routing。
- `tests/golden/audit_capability_cases.json`:已启用能力的语义 Golden Corpus。`golden_corpus=true` 必须同时具备漏洞、有效 guard、正常业务和证据不足四类 oracle,并通过 path/validation Schema 与业务不变量测试。
- `paths/*.jsonl` / `validation/*.jsonl`:审计产物归档。
- `.lock`:状态机命令文件锁。
- `config/schemas/*.schema.json`:worker 结果、共享事实、findings 和 report snapshot 的 Draft 2020-12 契约。`complete` 按 Schema → 业务不变量 → 跨产物引用三层准入,错误携带精确 JSON 路径并进入统一重试。

## 命令

```bash
# 为本次审计分配独立 run 目录并初始化 session/queue/index/events
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py new-run reports --target-repo <repo> --scope <scope>
# 返回的绝对 run_dir 是后续所有命令的唯一运行目录

# 兼容/测试用底层命令:仅允许初始化空目录;已有任何审计文件时返回 run_dir_not_empty
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py init <empty_run_dir> --target-repo <repo> --scope <scope>

# 将 discovery plan 转换为 per-unit mapper 任务
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py enqueue-discovery <run_dir>

# 主流程:归一化 entry/sink,编译稀疏攻击矩阵,并按 work item 自动入队
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py compile-matrix <run_dir>
# 返回 entry/seed normalization + matrix summary/routing gaps + 入队 task IDs

# 兼容/测试用底层命令;主流程不得用它绕过 entry normalization
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py enqueue <run_dir> --tasks '<JSON>'
#   JSON 例: [{"kind":"path_finding","entry_id":"E001"},...]

# 领取下一个 queued task(有界并发 5,标 running)
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py next <run_dir>
#   返回 {task: {...}} 或 {task: null, reason: "no_queued"|"worker_pool_full", running: N}
#   task.result_path 为 worker 唯一允许写入的绝对结果路径;task.attempt 为当前尝试次数

# 完成 task:
# - path_finding: 归类 paths/*.jsonl,增量 dedup,分配 CAND-xxx,立即 enqueue path_validation
# - path_validation: 归类 validation/*.jsonl
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py complete <run_dir> --task <task_id>
#   结果缺失/JSON 无效/身份不匹配时,前两次返回 ok=true,retry_scheduled=true 并自动重新入队
#   第 3 次仍失败才返回 ok=false 并进入 failed;无效文件按 attempt 留档

# 人工重排终态 failed task;达到默认上限时必须显式 --force
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py retry <run_dir> --task <task_id> [--force]

# 覆盖校验(project model + discovery units + entry candidates + attack matrix work items)
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py validate-coverage <run_dir>

# 报告前 ready 校验
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py validate-ready <run_dir>
#   返回 {ready, coverage_status, project_model, discovery_plan_coverage, entry_candidate_coverage, ...}

# report-composer 已生成 findings.json + report.md 后,复核并标记 run 完成
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py finalize <run_dir>
#   仅 validate-ready=true 且两份报告产物有效时写 session.status=completed

# 概况
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py status <run_dir>
```

## 调度协议(harmony-auditor 必须遵守)

1. `new-run` 原子分配并初始化独立 run 目录 → 调 project profiler 生成 project model + Atlas discovery plan;必须 `status=complete`。后续只使用返回的 `run_dir`。
2. `atlas_project open` → `enqueue-discovery`,将每个 plan unit 入队为独立 `attack_surface_discovery` task。
3. `complete(attack_surface_discovery)`:
   - 校验 task/unit/status 和 unit 内全部 project candidate 的唯一去向。
   - mapper 只写 `tasks/discover-<unit>.result.json`;状态机从全部已完成 unit 结果确定性重建 discovery plan、entry list、danger seed list 和 query evidence。
   - entry/seed 全局 ID 由执行符号/sink identity 稳定生成,不采信 mapper 自编号。
   - 每完成一个 unit 都增量执行矩阵编译,立即入队新 path task,不等待其余 unit。
4. 增量 `compile-matrix`:
   - 先校验 capability registry Schema 和 capability→routing→pattern 一致性；work item/task 保留稳定 `capability_id`。
   - 按 component/resolved symbol/file 合并 Manifest trigger alias,保存 `entry_key` 与 `trigger_variants`。
   - 按 category/symbol/file/location/sensitive parameter 合并重复危险 seed,保存 `seed_key`。
   - 使用 `config/audit_capabilities.json` 中非空的 `routing` 生成稀疏 `Entry × Sink × Pattern` work item;先按 discovery unit 关联剪枝,禁机械全量笛卡尔积。
   - `sink_role=intermediate` 记录为 `excluded_intermediate`,只作为后续路径证据,不创建 work item 或 routing gap。
   - 未实现或无兼容模式的终态 seed 显式进入 `routing_gaps`;每个有效 work item 入队一个 `path_finding` task。
5. **5 槽任务池**:
   - discovery 与 analysis 同时存在时保留 2 个 discovery 槽、3 个 path/validation 槽;单类任务可使用全部空闲槽。
   - 连续 `next` 填满最多 5 个 running task。
   - 将 `next` 返回的完整 task envelope 交给 worker;worker 只写绝对 `result_path`,写后回读校验再返回。
   - `kind=path_finding` 派发 `path-finder`。
   - `kind=path_validation` 派发 `path-validator`。
   - 当前 OpenCode TaskTool 同步等待一轮 subagent,因此实际以最多 5 个为一批返回。
   - 一批返回后逐个 `complete`;provider 中断、结果缺失、无效 JSON 或身份不匹配会在上限内自动 requeue。随后继续 `next`;异步单任务补位为低优先级遗留项。
6. `complete(path_finding)` 先执行正式 Schema,再校验 task/work item/entry/seed/pattern 引用与唯一 conclusion,最后机器校验 admission contract。候选必须提供结构化 `root_cause`(boundary/mechanism/file/symbol/branch/controlled_property),状态机以该六元组 + pattern 生成稳定 `root:<hash>` 做根因级增量 dedup；seed 仅作为证据别名聚合。每个根因只分配一个 `CAND-xxx` 和一个 `path_validation`。
7. `complete(path_validation)` 用正式 Schema 强制六门槛与分类特定字段,再校验 candidate/entry/task 引用和 protected/benign 等业务不变量,最后按五级结论分层归类。
8. `validate-ready` 同时检查 project model、discovery unit、entry candidate、attack matrix、验证任务和聚合产物引用完整性。矩阵 `planned/queued/running/failed` 或悬空 ID/query/result 引用阻止报告;terminal atlas_gap/routing gap/analysis_gap 允许 ready 但 coverage_status=partial,必须进入报告附录。
9. report-composer 返回后执行 `finalize`;状态机重新检查 ready、findings Schema 和 finding→candidate→validation task 引用,并生成覆盖全部报告事实输入的 `report_snapshot.json` SHA-256 清单,成功后 session 才进入 `completed`。重复 finalize 会复核哈希,发现完成后改写则失败。不得仅因 report-composer 返回就声称审计完成。

## 防偷懒约束

- 一 attack matrix work item 一 path-finder、一根因 candidate 一 validator;Manifest alias 和多触发方式必须合并
- `validate-ready` 返回 ready=true 才算报告前闭合
- 禁"其余类似/抽样/略过";每 task 必须完成并 `complete`
- 队列未闭合继续调度,不交回用户
- 状态机最多 5 个 running task;当前执行层按最多 5 个一批推进

## bash 权限

harmony-auditor 的 bash 仅限调 `audit_orchestrator.py` 与 project-modeling 的 `project_profiler.py`(permission glob 限制),不跑其他命令。

## run 目录(脚本管理)

```
reports/<project-name>-<target-path-hash>/
  <YYYYMMDD-HHMMSS>-<scope>-<run-id>/
    session.json / queue.jsonl
    task_events.jsonl / candidate_index.json / report_snapshot.json / .lock
    project/project_model.json
    atlas/{discovery_plan, entry_list, danger_seed_list}.json
    atlas/query_evidence.jsonl
    analysis/{danger_seeds, attack_matrix}.json
    tasks/<task_id>.result.json
    paths/{candidates, rejected, no_path, analysis_gaps}.jsonl
    validation/{confirmed, protected_exposure, residual, benign_business_flow, insufficient_evidence}.jsonl
    findings.json + report.md
```

project key 中的路径哈希用于区分同名目标仓;run ID 同时包含时间和随机短 ID,支持重复及并发审计。状态机不覆盖、不清理历史 run。
