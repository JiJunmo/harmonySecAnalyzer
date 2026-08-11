你只处理一个 `component_semantic_analysis` 任务。input 中的组件候选由脚本根据 JSON5 确定性生成，不代表真实外部入口已经成立。使用 Atlas 完成源码语义分析，不进行漏洞分类和六维有效性判断。

所有面向报告的描述性字段必须使用中文，包括 `summary`、事实描述、组件功能、业务用途、防护行为、分支条件和覆盖注记；源码符号、文件路径、API 名称、参数名和必要的代码原文保持原样。

严格完成以下工作：

1. 根据 `entry.project_candidates` 和 facets 找到本组件的真实 callback、触发条件和输入。`entry_status` 判断的是“候选是否对应真实组件输入”，不是“外部攻击者是否可达”：至少一个候选能对应到真实 callback 且调用方数据能够进入组件时为 `confirmed`；所有候选均经核查排除、没有真实组件输入时为 `excluded`；受动态注册、间接调用或源码缺失影响而无法确认或排除时为 `uncertain`。多个候选按 `confirmed > uncertain > excluded` 汇总。仅有 `component_scope` 时，只要上游可调用的 callback 和输入成立也应为 `confirmed`，但不得据此声称外部可达；外部可达性由后续六维验证判断。
2. 在本组件边界内有界追踪可控数据，允许经过本组件使用的普通 helper 和异步回调。不能全仓枚举危险 API，也不能构造 Entry 与敏感 API 的组合。
3. 只记录实际可达的安全相关操作，以及沿途的参数转换、条件、权限检查、白名单、身份检查和源码直接可观察的效果。参数名、函数名、类型名、注释和业务词义只能产生 `effect_hypotheses`，不得写成事实或 `direct_observed_effect`。每个假设必须列出 `missing_proofs`；没有找到字段读取、控制分支和受影响操作时，效果必须保持未知。每个 安全检查 必须用 `subject_kind` 标明它实际约束的是原始调用者、直接调用者、传递参数、资源所有者还是安全边界；不要在此阶段判断其是否有效。
   - 当 `audit_scope` 包含 `CAP-DOS-001` 时，还必须检查外部输入或可重复调用是否可达未处理异常、进程终止、无界循环/递归/分配、输入规模放大的高开销解析或查询，以及可被频繁触发的线程、队列、存储、IPC 或事件资源消耗。不能只因为存在抛异常或高开销 API 就记录操作组，必须证明外部触发到失败或资源消耗的具体调用关系。
4. 按“操作源码位置 + 关键受控参数集合”归并操作。普通分支写入组内 `branches`，不能生成重复组。
5. 每组按实际调用顺序输出入口到操作的最短 `facts` 证据链、观察到的 安全检查 行为和业务上下文事实。`facts` 只能是源码事实，不允许使用 `effect` 类型承载推断；直接效果写入 `context.direct_observed_effect`，不能证明时填 `null`。`edges` 由运行时根据 facts 顺序生成，不需要输出；没有观察到外部受控参数时，`controlled_properties` 输出空数组。只描述代码做了什么，不判断 安全检查 是否有效，不判断是否越过安全边界，不输出漏洞、风险等级、CWE 或 PoC。
   - `CAP-DOS-001` 操作组的 `category` 使用 `availability`，并必须输出 `availability` 事实：受影响的资源或失败方式、攻击者如何影响触发或规模、代码中存在的上限或放大关系、异常处理或隔离、重复触发条件、影响范围和恢复方式。无法证明的项目明确写“未知”，不得猜测。
6. 可控数据到达另一个 Ability/ExtensionAbility 时立即停止深入下游组件。只在此时按需读取 `project_model` 中的 `components` 解析目标ID，然后在 `component_calls` 记录目标 `component_id`、调用位置、条件、transport、参数映射、控制性变化和安全检查。还必须记录本次边界的 `principal_transition`：谁发起组件调用、下游实际观察到谁、原始身份是否被调用组件替换，以及调用使用原始主体、源组件还是系统权限。只记录代码可证明的局部事实，无法证明使用 `unknown`。`preserved` 表示数据控制性保留，`constrained` 表示受约束但仍传递，`constant` 和 `unknown` 不会被连接器继续传播。
7. Atlas 无法证明目标组件或参数映射时写入 `coverage.unresolved_targets`，不得猜测补全，也不得输出缺少必填字段的跨组件调用记录。没有本地敏感操作时可输出空 `operation_groups`；没有跨组件调用时输出空 `component_calls`。

证据直接写在它所证明对象的 `evidence` 数组中，每条包含 `kind`、`source`、`summary` 和可选源码位置；效果假设的依据写入 `basis_evidence`。不要创建证据 ID，不要输出 `evidence_refs` 或顶层证据目录，编号、去重和引用关系由运行时完成。同一段源码用于多个事实时可以重复写相同证据，运行时会自动归并。

Task 文件中的 `result_schema_file` 指向完整输出 Schema，必要时单独读取。输出只能使用该 Schema 声明的字段；禁止使用旧格式的顶层 `conclusion`、`reasoning`，禁止用 `operation_location` 代替每个 operation group 必需的 `operation: {body, location, evidence}`。结果必须同时包含 `operation_groups` 和 `component_calls`，即使它们是空数组。结果写入当前任务的绝对 `submission_file`，在完整 JSON 成功写入前不得结束。
