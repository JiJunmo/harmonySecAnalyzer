---
name: audit-orchestration
description: 审计流水线状态机调用协议。harmony-auditor 调度时加载,定义如何用 bash 调 tools/audit_orchestrator.py 推进 run 目录/队列/覆盖校验。
---

## 状态机脚本

`tools/audit_orchestrator.py`(Python,确定性,跨平台,无外部依赖)。harmony-auditor **通过 bash 调用**,不手写 queue/session。所有命令输出 JSON。

## 命令

```bash
# 建 run 目录 + session
python tools/audit_orchestrator.py init <run_dir> --target-repo <repo> --scope <scope>

# 入队任务(一 entry 一 task / 一 candidate 一 task,禁合并)
python tools/audit_orchestrator.py enqueue <run_dir> --tasks '<JSON>'
#   JSON 例: [{"kind":"path_finding","entry_id":"E001"},...]
#            [{"kind":"path_validation","candidate_id":"CAND-001"},...]

# 领取下一个 queued task(有界并发 3,标 running)
python tools/audit_orchestrator.py next <run_dir>
#   返回 {task: {...}} 或 {task: null, reason: "no_queued"|"worker_pool_full"}

# 完成 task(读 tasks/<task_id>.result.json 归类到 paths/*.jsonl 或 validation/*.jsonl)
python tools/audit_orchestrator.py complete <run_dir> --task <task_id>

# 覆盖校验(entry_list - 已完成 path_finding task 差集)
python tools/audit_orchestrator.py validate-coverage <run_dir>
#   返回 {missing: [...], ready: bool}

# 候选去重(按 entry_id+seed_id+pattern 去重,分配 CAND-xxx id,重写 candidates.jsonl)
python tools/audit_orchestrator.py dedup-candidates <run_dir>
#   返回 {before: N, after: M}

# 自动入队验证任务(从 candidates.jsonl 读,每条一个 path_validation task)
python tools/audit_orchestrator.py enqueue-validation <run_dir>
#   返回 {added: N, total: M}

# 概况
python tools/audit_orchestrator.py status <run_dir>
```

## 调度协议(harmony-auditor 必须遵守)

1. `init` 建 run 目录 → `atlas_project open` → 派发 attack-surface-mapper(落盘 atlas/)
2. 读 entry_list → `enqueue`(每 entry 一个 path_finding task)
3. **路径发现循环**:`next` → 若 task=null 且 reason=no_queued 跳出;否则派发 path-finder(per-entry)→ path-finder 落盘 `tasks/<task_id>.result.json` → `complete`
4. `validate-coverage` → missing 非空**必须补发**(enqueue + next/complete),差集为空才放行
5. `dedup-candidates`(去重+分配 CAND-xxx)→ `enqueue-validation`(自动从 candidates.jsonl 入队 path_validation task)→ 循环 next/complete 派发 path-validator
6. 派发 report-composer 读 paths/+validation/ 生成报告

## 防偷懒约束

- **一 entry 一 task、一 candidate 一 task,禁合并**(50 entry = 50 次 path-finder)
- `next` 返回 null 才算阶段完成;`validate-coverage` 差集为空才放行
- 禁"其余类似/抽样/略过";每 task 必须完成并 `complete`
- 队列未闭合继续调度,不交回用户
- 派发等待期不轮询 status / 重复 next

## bash 权限

harmony-auditor 的 bash 仅限调 `audit_orchestrator.py`(permission glob 限制),不跑其他命令。

## run 目录(脚本管理)

```
reports/<repo>-<scope>-<NNN>/
  session.json / queue.jsonl          # 脚本管
  atlas/{entry_list, danger_seed_list}.json   # attack-surface-mapper 落盘
  tasks/<task_id>.result.json         # path-finder/path-validator 落盘
  paths/{candidates, rejected, no_path}.jsonl  # 脚本归类
  validation/{confirmed, residual}.jsonl
  findings.json + report.md           # report-composer 生成
```
