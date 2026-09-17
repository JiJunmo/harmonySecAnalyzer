# 组件范围探索协议

当前运行协议版本为 25。设计取舍和验收目标见 [分支覆盖改造方案](branch-aware-exploration-plan.md)。本文描述实现接口。

## 数据与职责

- exploration_nodes：源码范围结构，函数名是归属信息；start/end 和可选列号定位函数内分支。
- exploration_work_items：范围在具体输入条件、安全状态和等待依赖下的分析进度；状态为 queued/leased/completed。
- exploration_edges：具体工作间的顺序、分支、调用、返回、异常、循环和复用关系，带条件和位置证据。
- component_explorations：组件入口判断、轮次和最终覆盖状态。
- 所有数据保存在 run.db，不创建独立数据库。Agent 只能通过部署包中的 audit_orchestrator.py 读写。

源码结构与调度工作分离。一个工作可以批量登记已检查分支和多个待办范围；图节点不对应子 Agent。身份相同的源码结构可以共享，不同进入条件和等待依赖分别处理。

## 运行命令

任务文件提供绝对命令路径。实际入口为：

- explore-next：领取一个可执行范围，返回结构化工作现场。
- explore-context --work-id ID --offset N：读取当前组件内相关工作和证据，分页恢复历史。
- explore-record --input FILE：验证本次范围变化并事务落盘；accepted=false 时在当前上下文修正。
- explore-finish：已有待办则重排同一个任务，所有已登记范围闭合则生成最终语义结果。

这些命令都需要 run_dir、--task-id 和 --attempt。六维验证及 PoC 仍使用原有 task-submit。

## 提交结构

顶层只包含 work_id、pause_requested、result、ranges、transitions，以及需要更新时的 entry_assessment。

| 字段 | 含义 |
|---|---|
| result.checked | 当前实际检查的源码行范围；检查范围与委托子范围共同覆盖当前工作 |
| result.termination | 当前范围的退出/内部展开边界，包含 kind、reason 和定位 evidence；有后续时可以为空 |
| result.facts/security_checks/operation_groups/component_calls/gaps | 本范围已确认的事实或有依据的解析缺口 |
| ranges[].ref | 本次局部引用，不是持久 ID |
| ranges[].scope | symbol、start/end、可选 start_column/end_column、kind |
| ranges[].state/conditions | 输入控制、身份、安全检查和影响该范围的具体取值条件 |
| ranges[].result | null 表示待办；填写完整 result 表示本次批量分析已完成 |
| ranges[].wait_for | 必须先闭合的范围引用；用于调用结果依赖 |
| transitions | from/to、relation、condition、evidence；引用 $current、本次 ref 或已返回 work_id |

scope.kind 可取 function/block/choice/call/join/exit。同一行的不同结构位置使用列号区分。字段完整定义以部署包的 component-exploration-step.schema.json 为准。

不再填写函数级进度清单、单个函数续跑对象、重复的关系目标列表或工作状态。脚本负责 ID、去重和状态。

## 函数结构与范围闭合

进入函数后先检查局部结构，沿完整分支路径连续分析，再批量保存分支结果和未完成范围。普通语句和辅助函数调用并入路径证据，不要求逐个建图。大函数允许分段读取，但未检查区域保留为独立待办。choice 范围至少有两个分支出口；没有 else 的 false 出口同样存在。

result.checked 不代表源码已经穷尽；它表示 Agent 声明实际检查过的区域。运行时拒绝未被检查范围、委托范围或有依据缺口解释的剩余区域。

工作 completed 表示本次处理已保存。scope_complete 表示该范围及其所有正常后续工作都闭合。循环回边需要相同相关状态和证据；不会无限展开迭代。reuse 只能连接已闭合、条件和状态一致的结果。全部覆盖只针对已登记结构，不能宣称编译器级路径穷尽。

## 调用和停止

普通调用允许在当前路径内连续分析，不创建单独工作。显式登记的同步 call 同时保存 return/exception 后续；只有有据可查的尾部 return/throw 可以没有普通后续。依赖被调用结果的返回范围通过 wait_for 等待。依赖环或覆盖结构中的非循环回边环在提交时拒绝，不能拖到最后假装完成。

平台、第三方、组件边界必须保留调用者后续，不能把停止内部展开解释成关闭整个调用者。return/throw 只关闭当前分支，需核实 catch/finally。security_influence_ended 需要对数据、身份和调用触发都给出理由，单个参数变常量不足以停止。

Atlas 是优先索引，动态缺边必须围绕调用点核实源码。源码完整证明则继续，部分证明则继续已确认目标并记录剩余 gap，无法证明才只记录 gap。控制流位置可以直接用源码证明，不要求伪造 Atlas 调用。

## 跨轮上下文

next 返回当前 scope/state/conditions、coverage、transitions、wait_for。coverage 是相关工作的精简目录，保留检查范围、操作组标识、安全检查、缺口和停止原因，不默认重复展开事实和操作组证据链。当前 work.result 与 wait_for 依赖保留完整结果，当前工作和直接依赖优先排列。入边来自全部真实来源，不沿首次父节点恢复。

默认按 40 个相关工作分页，明确返回 next_offset，不要求关闭前遍历全部历史。detail_available 表示详细事实可查询；当历史事实影响当前分析或复用时，用 explore-context --work-id 读取完整 work.result。脚本自行检查已登记结构闭合，摘要不代替证据。

## 容量与恢复

当前默认每轮累计 2000 个检查行工作单位，每个零行处理至少计一个单位；组件总量保护为 200000。同一源码在不同条件下重新检查会再次计数。预算是工作量近似，不是 token 估算。

本轮预算达到或 pause_requested=true 时，保存已有范围并换上下文，不产生覆盖缺口；组件总量达到时未完成范围显式记为缺口。取消了按图节点数 64 和轮数 8 提前结束的旧保护。恢复失败轮次时只释放未完成工作租约，已提交事实保留。

没有可领取范围但仍存在未闭合依赖时返回 dependency_blocked，不能标记组件完成。

## 汇总、报告和兼容

所有已登记范围闭合后，semantic_results.py 汇总操作组和组件调用，沿用六维验证接口。报告展示范围位置、进入条件、去向、停止依据、等待关系和缺口。

旧数据库版本拒绝续跑，不尝试从摘要构造分支记录。增量契约哈希变化要求重新全量审计建立基线。安装仍使用 deploy.py，新增上下文模块随 Skill 自动复制；部署 smoke 实际执行范围领取、查询、提交和语义汇总。
