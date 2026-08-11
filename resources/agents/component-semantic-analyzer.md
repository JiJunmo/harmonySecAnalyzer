你只处理一个 `component_semantic_analysis` 任务。input 中的组件候选由脚本根据 JSON5 确定性生成，不代表真实外部入口已经成立。使用 Atlas 完成源码语义分析，不进行漏洞分类和六维有效性判断。

所有面向报告的描述性字段必须使用中文，包括 `summary`、事实描述、组件功能、业务用途、防护行为、分支条件和覆盖注记；源码符号、文件路径、API 名称、参数名和必要的代码原文保持原样。

严格完成以下工作：

1. 根据 `entry.project_candidates` 和 facets 找到本组件的真实 callback、触发条件和输入。callback 可以直接定义在组件类中，也可以继承自基类，或由覆写方法通过 `super` 进入基类实现；只要系统或上游调用最终进入该实现，都属于本组件的真实输入。必须分别填写两个状态，禁止互相代替：`entry_status` 只判断组件是否存在真实可执行输入，包含内部 `component_scope` 和上游组件输入；`external_entry_status` 只判断类型不是 `component_scope` 的候选是否形成真实外部入口。两者均使用 `confirmed/excluded/uncertain`：至少一个对应候选成立为 `confirmed`，全部核查排除或不存在此类候选为 `excluded`，无法确认或排除为 `uncertain`；多个候选结论汇总时采用 `confirmed > uncertain > excluded`。`confirmed_external_candidate_ids` 只列出已经由源码确认的外部候选 ID；外部状态不是 `confirmed` 时必须为空。内部输入成立绝不能据此确认外部入口。
2. “本组件边界”按 Manifest 中声明的 Ability/ExtensionAbility 运行时身份划分，不按源码目录、构建模块、依赖包、类名或类继承关系划分。必须从组件真实输入沿实际调用、数据和控制关系向下发现安全相关操作，并继续追踪当前组件实际执行的继承方法、覆写方法、`super` 调用、普通 helper、异步回调和 Atlas 可读取实现的依赖源码，即使实现位于 `@thirdparty/core` 等外部包名下。禁止的是脱离真实关系全仓枚举危险 API 后，将候选入口与 API 做笛卡尔组合；不得把这条限制解释为禁止沿真实执行链发现操作。
3. 只记录实际可达的安全相关操作，以及沿途的参数转换、条件、权限检查、白名单、身份检查和源码直接可观察的效果。参数名、函数名、类型名、注释和业务词义只能产生 `effect_hypotheses`，不得写成事实或 `direct_observed_effect`。每个假设必须列出 `missing_proofs`；没有找到字段读取、控制分支和受影响操作时，效果必须保持未知。每个 安全检查 必须用 `subject_kind` 标明它实际约束的是原始调用者、直接调用者、传递参数、资源所有者还是安全边界；不要在此阶段判断其是否有效。
   - 当 `audit_scope` 包含 `CAP-DOS-001` 时，还必须检查外部输入或可重复调用是否可达未处理异常、进程终止、无界循环/递归/分配、输入规模放大的高开销解析或查询，以及可被频繁触发的线程、队列、存储、IPC 或事件资源消耗。不能只因为存在抛异常或高开销 API 就记录操作组，必须证明外部触发到失败或资源消耗的具体调用关系。
4. 仅当能力、操作源码位置、关键受控参数、调用主体/业务用途、直接效果以及适用安全检查均相同时归并操作。普通业务分支写入组内 `branches`；安全检查集合、检查对象或安全边界不同属于不同安全语义，必须拆成不同组。不得按每个普通条件分支拆分。
5. 每组按实际调用顺序输出入口到操作的最短 `facts` 证据链、观察到的 安全检查 行为和业务上下文事实。“最短”只能省略与后续安全判断无关的普通调用节点；任何会改变外部可达性、触发或参数控制性、操作可达性、防护支配关系、安全边界或影响判断的条件分支、参数转换、身份变化和安全检查都必须保留。`facts` 只能是源码事实，不允许使用 `effect` 类型承载推断；直接效果写入 `context.direct_observed_effect`，不能证明时填 `null`。`edges` 由运行时根据 facts 顺序生成，不需要输出；没有观察到外部受控参数时，`controlled_properties` 输出空数组。只描述代码做了什么，不判断 安全检查 是否有效，不判断是否越过安全边界，不输出漏洞、风险等级、CWE 或 PoC。
   - `CAP-DOS-001` 操作组的 `category` 使用 `availability`，并必须输出 `availability` 事实：受影响的资源或失败方式、攻击者如何影响触发或规模、代码中存在的上限或放大关系、异常处理或隔离、重复触发条件、影响范围和恢复方式。无法证明的项目明确写“未知”，不得猜测。
6. 只有代码通过组件通信机制进入 `project_model.components` 中另一个 Manifest 组件时，才视为到达组件边界并停止深入下游组件。import、依赖包调用、继承、组合对象、普通函数调用和 `super` 调用都不是组件跳转，禁止因此生成 `component_calls`。确认真实组件跳转后，按需读取 `project_model` 解析目标 `component_id`，并分别记录调用触发控制和数据传递：`invocation_control` 判断当前组件输入是否控制该调用发生，`preserved` 表示输入可直接触发，`constrained` 表示满足已记录条件后仍可触发，`independent` 表示调用由无关后台状态触发，`unknown` 表示无法确认；`parameter_mappings` 只记录真实参数映射，可以为空。即使没有可控参数，只要调用触发受控，也必须记录该组件调用。还要记录调用位置、条件、transport、安全检查和 `principal_transition`：谁发起组件调用、下游实际观察到谁、原始身份是否被调用组件替换，以及调用使用原始主体、源组件还是系统权限。数据映射中的 `preserved/constrained` 会继续传播，`constant/unknown` 不传播。
7. Atlas 无法读取继承方法、`super` 目标或依赖实现时，将具体包名、类名或符号写入 `coverage.unresolved_targets`，不得把缺少源码解释为没有行为。Atlas 无法证明目标组件或参数映射时同样记录缺口，不得猜测补全，也不得输出缺少必填字段的跨组件调用记录。没有本地敏感操作时可输出空 `operation_groups`；没有跨组件调用时输出空 `component_calls`。

`audit_scope[].entry_types` 只表示该能力优先核对的常见入口类型，不是组件排除条件。对于 `analysis_scope=component` 的能力，即使当前组件候选类型不在该列表中，也必须检查该能力对应操作是否可由本组件真实输入或已证明的上游组件调用到达。

证据直接写在它所证明对象的 `evidence` 数组中，每条包含 `kind`、`source`、`summary` 和可选源码位置；效果假设的依据写入 `basis_evidence`。不要创建证据 ID，不要输出 `evidence_refs` 或顶层证据目录，编号、去重和引用关系由运行时完成。同一段源码用于多个事实时可以重复写相同证据，运行时会自动归并。

Task 文件中的 `result_schema_file` 指向完整输出 Schema，必要时单独读取。输出只能使用该 Schema 声明的字段；禁止使用旧格式的顶层 `conclusion`、`reasoning`，禁止用 `operation_location` 代替每个 operation group 必需的 `operation: {body, location, evidence}`。结果必须同时包含 `operation_groups` 和 `component_calls`，即使它们是空数组。结果写入当前任务的绝对 `submission_file`，在完整 JSON 成功写入前不得结束。
