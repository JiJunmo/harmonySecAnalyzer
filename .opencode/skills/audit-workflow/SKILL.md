---
name: audit-workflow
description: 鸿蒙 ArkTS 白盒审计端到端 SOP(攻击路径驱动+状态机)。编排者启动审计时必读,定义流水线、状态机调度协议与可利用性门槛。
---

## 核心理念

**攻击者视角,路径驱动**:只发现"外部可达入口 → 危险操作(sink)"的完整攻击路径。sink 是从 source 追数据流追到的终点,不是预设清单。

**状态机驱动**:`tools/audit_orchestrator.py`(Python 脚本,确定性)管理 run 目录/队列/覆盖校验。harmony-auditor 通过 bash 调用,不手写 queue/session。防偷懒:一 entry 一 task、覆盖差集校验、差集为空才放行。详细命令见 `audit-orchestration` skill。

## 流水线(状态机驱动)

### 1. 准备
- `bash: python3 tools/audit_orchestrator.py init <run_dir> --target-repo <repo> --scope <scope>`
- `atlas_project open`(target_repo)

### 2. 攻击面测绘(attack-surface-mapper)
- 落盘 `atlas/entry_list.json` + `atlas/danger_seed_list.json`,返回概要

### 3. 入队路径发现
- 读 entry_list,`enqueue`(每 entry 一个 path_finding task)。**一 entry 一 task,禁合并。**

### 4. 路径发现循环(path-finder)✅
- `next` → 派发 path-finder(per-entry)→ path-finder 落盘 `tasks/<task_id>.result.json` → `complete`(脚本读 result 归类到 paths/*.jsonl)
- 循环到 next 返回 no_queued
- 方法:`atlas_path` 直连 / `atlas_calls` 双向探索 / `atlas_trace(variable)` 描 taint

### 5. 覆盖校验(防遗漏)✅
- `validate-coverage` → entry_list 差集
- missing 非空 → 补发 enqueue + next/complete,差集为空才放行

### 6. 路径验证(path-validator)✅
- `dedup-candidates`(去重+分配 CAND-xxx)→ `enqueue-validation`(自动从 candidates.jsonl 入队 path_validation task)
- `next` → 派发 path-validator(per-candidate)→ `complete`(归类到 validation/confirmed|residual.jsonl)
- 四门槛:可达 + 可控(`atlas_trace variable`)+ 深度追踪 + 有 impact(`atlas_impact`)

### 7. 报告(report-composer)✅
- 读 paths/ + validation/ 生成 findings.json + report.md
- 主报告=confirmed 攻击路径(按 severity),附录=residual + 孤立点 + 攻击面

## 防偷懒约束

- 一 entry 一 task、一 candidate 一 task,**禁合并**
- `next` 返回 null 才算阶段完成;`validate-coverage` 差集为空才放行
- 禁"其余类似/抽样/略过";每 task 必须完成并 `complete`
- 队列未闭合继续调度,不交回用户
- 派发等待期不轮询 status / 重复 next

## run 目录结构(脚本管理)

```
reports/<repo>-<scope>-<NNN>/
  session.json / queue.jsonl
  atlas/{entry_list, danger_seed_list}.json
  tasks/<task_id>.result.json
  paths/{candidates, rejected, no_path}.jsonl
  validation/{confirmed, residual}.jsonl
  findings.json + report.md
```

## 模式卡(attack-patterns skill)

path-finder / path-validator 加载,链形状表 + 各模式 source/sink/guard/reject 规则,开放可扩展。

## 当前实现状态

- ✅ attack-surface-mapper(落盘)
- ✅ attack-patterns skill(3 模式)
- ✅ audit-orchestration skill(状态机调用协议)
- ✅ path-finder(per-entry,落盘 result)
- ✅ path-validator(per-candidate,落盘 result)
- ✅ report-composer(读 jsonl)
- ✅ audit_orchestrator.py 状态机脚本(init/enqueue/next/complete/validate-coverage/status)
- ⏳ validate-ready 报告准入 + continuation follow-up(下一步)
