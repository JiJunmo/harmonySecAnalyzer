---
name: audit-orchestration
description: 审计流水线状态机调用协议。harmony-auditor 调度时加载,定义如何用 scripts/audit_orchestrator.py 推进 worker-pool + streaming pipeline。
---

## 状态机脚本

`scripts/audit_orchestrator.py`(Python,确定性,跨平台,无外部依赖)。harmony-auditor **通过 bash 调用**,不手写 queue/session/candidate_index。所有命令输出 JSON。

状态机负责:

- `new-run`:按目标仓规范路径生成稳定 project key,并原子分配不可复用的 run 目录。
- `queue.jsonl`:任务当前状态。
- `task_events.jsonl`:append-only 调度事件。
- `candidate_index.json`:增量去重与稳定 `CAND-xxx` 分配。
- `project/project_model.json`:由 project-modeling skill 生成;状态机检查 schema/status,并核对每个 project entry candidate 是否恰好进入 entry/excluded/unresolved/coverage_gaps 之一。重复归类和未知 candidate ID 都会阻断报告。
- `atlas/discovery_plan.json`:Manifest 锚点生成的 Atlas analysis units;状态机检查每个 unit 的终态。
- `atlas/query_evidence.jsonl`:mapper 的 Atlas 查询输入、命中、query_id 与 diagnostics。
- `analysis/danger_seeds.json`:按 sink symbol/location/敏感参数归一化的危险操作。
- `analysis/attack_matrix.json`:确定性编译的稀疏 `Entry × Sink × Pattern` 矩阵;每个 work item 必须终态化。
- `paths/*.jsonl` / `validation/*.jsonl`:审计产物归档。
- `.lock`:状态机命令文件锁。

## 命令

```bash
# 为本次审计分配独立 run 目录并初始化 session/queue/index/events
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py new-run reports --target-repo <repo> --scope <scope>
# 返回的绝对 run_dir 是后续所有命令的唯一运行目录

# 兼容/测试用底层命令:仅允许初始化空目录;已有任何审计文件时返回 run_dir_not_empty
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py init <empty_run_dir> --target-repo <repo> --scope <scope>

# 主流程:归一化 entry/sink,编译稀疏攻击矩阵,并按 work item 自动入队
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py compile-matrix <run_dir>
# 返回 entry/seed normalization + matrix summary/routing gaps + 入队 task IDs

# 兼容旧调用;当前等价于 compile-matrix
python .opencode/skills/audit-orchestration/scripts/audit_orchestrator.py enqueue-entries <run_dir>

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

兼容命令:

- `dedup-candidates`:保留但不再作为主流程使用;增量去重已在 `complete(path_finding)` 中执行。
- `enqueue-validation`:保留但不再作为主流程使用;validation 任务已在 `complete(path_finding)` 中自动入队。

## 调度协议(harmony-auditor 必须遵守)

1. `new-run` 原子分配并初始化独立 run 目录 → 调 project profiler 生成 project model + Atlas discovery plan;必须 `status=complete`。后续只使用返回的 `run_dir`。
2. `atlas_project open` → mapper 按 plan scope/anchor 做 Atlas scoped discovery,更新 unit 状态并落盘 query evidence/entry/seed。
3. 执行 `compile-matrix`:
   - 按 component/resolved symbol/file 合并 Manifest trigger alias,保存 `entry_key` 与 `trigger_variants`。
   - 按 category/symbol/file/location/sensitive parameter 合并重复危险 seed,保存 `seed_key`。
   - 使用 `config/attack_matrix_routes.json` 生成稀疏 `Entry × Sink × Pattern` work item;先按 discovery unit 关联剪枝,禁机械全量笛卡尔积。
   - `sink_role=intermediate` 记录为 `excluded_intermediate`,只作为后续路径证据,不创建 work item 或 routing gap。
   - 未实现或无兼容模式的终态 seed 显式进入 `routing_gaps`;每个有效 work item 入队一个 `path_finding` task。
4. **5 槽任务池**:
   - 连续 `next` 填满最多 5 个 running task。
   - 将 `next` 返回的完整 task envelope 交给 worker;worker 只写绝对 `result_path`,写后回读校验再返回。
   - `kind=path_finding` 派发 `path-finder`。
   - `kind=path_validation` 派发 `path-validator`。
   - 当前 OpenCode TaskTool 同步等待一轮 subagent,因此实际以最多 5 个为一批返回。
   - 一批返回后逐个 `complete`;provider 中断、结果缺失、无效 JSON 或身份不匹配会在上限内自动 requeue。随后继续 `next`;异步单任务补位为低优先级遗留项。
5. `complete(path_finding)` 先校验 task/work item/entry/seed/pattern 身份与唯一 conclusion,再机器校验 admission contract,按 `seed_key + pattern` 做根因级增量 dedup。每个根因只分配一个 `CAND-xxx` 和一个 `path_validation`。
6. `complete(path_validation)` 按 `confirmed_vulnerability|protected_exposure|residual_risk|benign_business_flow|insufficient_evidence` 分层归类。
7. `validate-ready` 同时检查 project model、discovery unit、entry candidate、attack matrix 与验证任务闭合。矩阵 `planned/queued/running/failed` 阻止报告;terminal atlas_gap/routing gap/analysis_gap 允许 ready 但 coverage_status=partial,必须进入报告附录。
8. report-composer 返回后执行 `finalize`;状态机重新检查 ready 与报告产物,成功后 session 才进入 `completed`。不得仅因 report-composer 返回就声称审计完成。

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
    task_events.jsonl / candidate_index.json / .lock
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
