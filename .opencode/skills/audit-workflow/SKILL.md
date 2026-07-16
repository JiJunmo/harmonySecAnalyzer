---
name: audit-workflow
description: 鸿蒙 ArkTS 白盒审计端到端 SOP(攻击路径驱动+状态机)。编排者启动审计时必读,定义流水线、状态机调度协议与可利用性门槛。
---

## 核心理念

**攻击者视角,路径驱动,反证优先**:先发现"外部可达入口 → 危险操作(sink)"的完整路径,再验证它是否真的越过安全边界。外部可达、敏感 API、调用链存在只是 exposure/capability/path,不是漏洞本身。

## Finding 生命周期

审计结论必须按生命周期分层,不得把前置事实直接升级为漏洞:

1. `exposure`:外部可达入口、导出组件、WebView/JSBridge 暴露面。
2. `capability`:文件、SQL、网络、隐私、Ability 拉起等敏感能力。
3. `abuse_path`:外部输入可能控制敏感能力关键参数的可疑路径。
4. `vulnerability`:外部输入绕过有效防护与预期安全边界,造成具体安全影响。

**确定性底座**:`project-modeling` skill 生成统一项目模型与 Atlas discovery plan;`audit-orchestration` skill 管理 run 目录、entry/sink 归一化、稀疏攻击矩阵、候选准入、根因去重、队列与覆盖校验。harmony-auditor 不手写项目模型或状态文件;只有 `validate-ready` 闭合后才允许报告。具体调用协议只在对应 skill 中定义。

## 流水线(状态机驱动)

### 1. 准备
- 调用 `audit-orchestration` skill 的 `new-run`,从返回值取得本次审计唯一的绝对 `run_dir`;禁止复用或猜测历史 run 路径。
- 调用 `project-modeling` skill,传入 `<repo>` 与 `<run_dir>`;由该 skill 负责执行脚本并生成约定产物。
- profiler 只解析 JSON5,不读取源码内容;discovery plan 按 Manifest component/source scope 生成 Atlas anchors。
- project profiler 必须 `status=complete`;解析错误进入 diagnostics,不得让 agent 自行猜配置。
- `atlas_project open`(target_repo)

### 2. 攻击面测绘(attack-surface-mapper)
- 执行 `enqueue-discovery`,将 plan 中每个 unit 转换为独立 mapper task。
- 每个 mapper 只读取指定 unit,按 scope 执行 `atlas_search → atlas_symbol/explore → atlas_calls/file_dependencies`,只写自己的 `result_path`。
- 只从 Atlas 返回的可达定义源码与调用证据识别 Web/JSBridge 和危险能力,禁止逐文件 read/glob/grep。
- 每个 project entry candidate 必须在 unit 终态结果中归入 entry/excluded/coverage_gaps;仍 unresolved 时不得提交完成。
- `complete(attack_surface_discovery)` 先执行正式 JSON Schema,再校验候选唯一去向和 query ID 引用,由状态机重建共享 entry/seed/query evidence 并立即增量编译矩阵。

### 3. 增量编译攻击矩阵并入队路径发现
- 每个 discovery unit 完成后自动执行增量 `compile-matrix`:状态机归一化当前已发现的 execution entry 和 danger seed,再按 sink role、discovery unit 关联与机器路由配置编译稀疏 `Entry × Sink × Pattern` 矩阵。
- 重编译必须继承已有 work item 的 running/terminal 状态,只为新增矩阵单元创建任务。
- 编译前按 entry/seed 的 discovery unit 关联做保守剪枝;缺少 unit 信息时保留分析,避免错误排除跨单元路径。
- `intermediate` seed 只表示状态存储或参数转存,不独立创建 work item 或 routing gap;每个有效终态 work item 一个 path_finding task,未实现模式进入 routing gap。

### 4. 5 槽任务池(path-finder + path-validator)✅
- discovery 与 analysis 同时存在时使用 2+3 保留槽;只有单类任务时可占满 5 槽。
- 连续 `next` 填满最多 5 个 running task。
- `kind=attack_surface_discovery` → 派发 per-unit attack-surface-mapper。
- `next` 返回完整 task envelope 与绝对 `result_path`;worker 必须写入并回读该路径后才返回概要。
- `kind=path_finding` → 派发 path-finder(per-work-item)→ path-finder 落盘唯一结论 → `complete`。
- `complete(path_finding)` 执行正式 JSON Schema,校验 work/entry/seed/pattern 引用和候选 admission,按稳定的 seed_key/pattern 做根因级增量 dedup,写 `candidate_index.json`,并为每个独立根因立即 enqueue 一个 path_validation。
- `kind=path_validation` → 派发 path-validator(per-candidate)→ `complete` 用正式 Schema 强制六门槛/分类字段并校验 candidate/entry/task 引用,再归类到 validation/confirmed|protected_exposure|residual|benign_business_flow|insufficient_evidence。
- provider 流中断、结果缺失、无效 JSON 或任务身份不匹配时,`complete` 在最多 3 次内自动重新入队并保留 `retry_history`;成功后清除活动 error,达到上限才 failed。
- 当前 OpenCode TaskTool 同步等待本批 subagent,执行层以最多 5 个为一批;每批返回后逐个 complete,新生成的 validation task 可进入下一批。异步单任务补位列为低优先级遗留项。
- 六门槛:外部可达 + 攻击者可控关键参数 + 到达敏感 sink + guard 缺失/可绕过 + 违反安全边界 + 有具体 impact
- 反证优先:有效 guard、正常公开业务意图、未越过安全边界、不可控关键参数都必须降级。

### 5. 报告准入(validate-ready)✅
- `validate-ready` → 检查共享产物 Schema、project/discovery/candidate/matrix 覆盖、queue 和聚合引用完整性。planned/queued/running/failed/unresolved、Schema 错误或悬空 entry/seed/work/query/result 引用阻断;terminal atlas_gap/routing gap/analysis_gap 允许报告但 coverage_status=partial。
- ready=false 时必须继续调度或修复;ready=true 才能报告。

### 6. 报告(report-composer)✅
- 读 paths/ + validation/ 生成 findings.json + report.md
- 主报告=confirmed_vulnerability(按 severity),其余分层为 protected_exposure / residual_risk / benign_business_flow / insufficient_evidence + 终态 routing gap + 攻击面
- 报告生成后执行状态机 `finalize`;只有 findings Schema 有效、finding 引用能解析到 candidate/validation task、`report_snapshot.json` 已用 SHA-256 冻结全部报告事实输入且 session.status=completed 才结束审计。

## 六门槛与降级规则

`confirmed_vulnerability` 必须同时满足:

1. `externally_reachable`:入口可被外部触达。
2. `attacker_controlled`:攻击者能控制进入 sink 的关键参数。
3. `sink_reached`:可控值到达敏感 sink。
4. `guard_bypassed_or_absent`:防护缺失、无关、在 sink 后、未覆盖危险属性,或有明确绕过证据。
5. `boundary_violated`:越过身份/权限/来源/域名/路径/组件/数据所有权/业务授权边界。
6. `concrete_impact`:存在具体安全影响,不是仅"可调用敏感函数"。

降级分类:

- `protected_exposure`:外部可达且有敏感能力,但有效 guard 将行为约束在安全范围。
- `benign_business_flow`:属于预期公开业务能力,输入只影响允许的业务对象或路由,未越界。
- `residual_risk`:路径可疑或 guard 弱,但缺少确认漏洞的关键证据。
- `insufficient_evidence`:证据不足,不能臆造。

## 防偷懒约束

- 一 attack matrix work item 一 path-finder、一根因 candidate 一 validator;入口别名只作为触发变体
- `validate-ready` 返回 ready=true 才算报告前闭合
- 禁"其余类似/抽样/略过";每 task 必须完成并 `complete`
- 队列未闭合继续调度,不交回用户
- 派发等待期不轮询 status / 重复 next

## run 目录结构(脚本管理)

```
reports/<project-name>-<target-path-hash>/
  <YYYYMMDD-HHMMSS>-<scope>-<run-id>/
    session.json / queue.jsonl
    task_events.jsonl / candidate_index.json
    project/project_model.json
    atlas/{discovery_plan, entry_list, danger_seed_list}.json
    atlas/query_evidence.jsonl
    analysis/{danger_seeds, attack_matrix}.json
    tasks/<task_id>.result.json
    paths/{candidates, rejected, no_path, analysis_gaps}.jsonl
    validation/{confirmed, protected_exposure, residual, benign_business_flow, insufficient_evidence}.jsonl
    findings.json + report.md
```

## 模式卡(attack-patterns skill)

path-finder / path-validator 加载,链形状表 + 各模式 source/sink/guard/reject 规则,开放可扩展。

## 当前实现状态

- ✅ project-modeling(确定性 JSON5/Manifest 解析 + project_model/discovery_plan,不扫描源码)
- ✅ attack-surface-mapper(per-unit Atlas scoped search + 私有结果 + 状态机确定性合并)
- ⏳ NAPI/native 边界发现(后续扩展,本轮不实现)
- ✅ attack-patterns skill(3 模式)
- ✅ audit-orchestration skill(状态机调用协议)
- ✅ path-finder(per-attack-matrix-work-item,落盘唯一 result)
- ✅ path-validator(per-candidate,六门槛+分层落盘 result)
- ✅ report-composer(读 jsonl)
- ✅ audit_orchestrator.py 状态机脚本(init/enqueue-discovery/incremental compile-matrix/next/complete/retry/validate-coverage/validate-ready/finalize/status)
- ✅ streaming promotion(candidate_index + task_events)
