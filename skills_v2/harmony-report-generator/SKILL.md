---
name: harmony-report-generator
description: v2 — 聚合 AttackPath[] 生成攻击路径报告
---

# harmony-report-generator v2

读取所有 skill 输出的 AttackPath[]，聚合后生成以攻击路径组织的安全审计报告。

## 输入

| 数据 | 来源 |
|------|------|
| `entries.json` + `sinks.json` + `attack_map.json` | Phase 1 |
| `*-attack-paths.json` | 各 skill 输出 |

## 聚合脚本

```bash
python skills_v2/harmony-report-generator/scripts/report_aggregator.py <audit_dir> -o <audit_dir>/aggregated_data.json --pretty
```

若 `python3` 不可用（如 Windows），改为 `python`。

脚本自动：
- 读取所有 `*-attack-paths.json`，合并为按 severity 排序的列表
- 按 severity / skill 分组统计
- 计算风险评分
- 对比 `attack_map.json` 的潜在路径数与实际验证的路径数，不一致则输出 warnings

## aggregated_data.json 字段映射表

以下是每个 JSON 字段在报告中的对应位置。渲染报告时，**按此表逐字段替换**：

| JSON 路径 | 报告章节 | 渲染位置 | 缺失时的行为 |
|-----------|---------|---------|-------------|
| `audit_time` | 报告总览 | 一级标题下方 | 不展示时间行 |
| `risk_score` | 报告总览 | 一级标题下方 + 审计总结 | 展示 `--` |
| `project.entries_count` | 1.1 审计范围 | 表格第一行 | 展示 `0` |
| `project.sinks_count` | 1.1 审计范围 | 表格第二行 | 展示 `0` |
| `project.verified_paths` | 1.1 审计范围 | 表格第三行 | 展示 `0` |
| `statistics.by_severity.critical` | 1.2 漏洞分布 | 表格第一行 | 展示 `0` |
| `statistics.by_severity.high` | 1.2 漏洞分布 | 表格第二行 | 展示 `0` |
| `statistics.by_severity.medium` | 1.2 漏洞分布 | 表格第三行 | 展示 `0` |
| `statistics.by_severity.low` | 1.2 漏洞分布 | 表格第四行 | 展示 `0` |
| `statistics.by_severity.info` | 1.2 漏洞分布 | 表格第五行 | 展示 `0` |
| `attack_paths[]` | 2. 攻击路径详情 | 每条路径独立子节 | 跳过整个章节 |
| `attack_paths[].id` | 2.N | 子节标题 | 展示 `UNKNOWN` |
| `attack_paths[].title` | 2.N | 子节标题 | 展示 `无标题` |
| `attack_paths[].severity` | 2.N | 色标 + 风险卡片 | 按 info 处理 |
| `attack_paths[].module` | 2.N (IPC/ABILITY) | 基本信息系统化信息 | 跳过此行 |
| `attack_paths[].non_sensitive_summary` | 2.N (IPC) | 非敏感分支说明 | 跳过此行 |
| `attack_paths[].cases[]` | 2.N (IPC/WEBVIEW) | 敏感分支表格 | 跳过此表 |
| `attack_paths[].cases.bridge_methods[]` | 2.N (WEBVIEW) | JS Bridge 方法表 | 跳过此表 |
| `attack_paths[].cases.interceptors[]` | 2.N (WEBVIEW) | 拦截器状态表 | 跳过此表 |
| `attack_paths[].input` | 2.N (IPC) | 攻击载荷代码块 | 跳过此段 |
| `attack_paths[].entry` | 2.N (WEBVIEW) | 攻击入口信息卡 | 展示 `--` |
| `attack_paths[].ability_details` | 2.N (ABILITY) | 能力信息卡 | 跳过此段 |
| `attack_paths[].flow[]` | 2.N | 数据流向 | 展示 `*数据流向不可追溯*` |
| `attack_paths[].flow[].step` | 2.N | 步骤编号 | 按序号自增 |
| `attack_paths[].flow[].stage` | 2.N | 步骤阶段标签 | 展示 `--` |
| `attack_paths[].flow[].description` | 2.N | 步骤说明文字 | 展示 `--` |
| `attack_paths[].flow[].file` | 2.N | 文件位置引用 | 展示 `--` |
| `attack_paths[].flow[].snippet` | 2.N | 代码块 | 展示 `/* 代码未提供 */` |
| `attack_paths[].impact.summary` | 2.N | 危害概述段落 | 展示 `未提供影响评估` |
| `attack_paths[].impact.sensitive_data_exposed[]` | 2.N | 敏感数据泄露列表 | 跳过此子节 |
| `attack_paths[].impact.sensitive_operations[]` | 2.N | 敏感操作列表 | 跳过此子节 |
| `attack_paths[].impact.output_example` | 2.N | 攻击输出示例 | 跳过此段 |
| `attack_paths[].exploitation` | 2.N | 利用方法 | 展示 `未提供利用方法` |
| `attack_paths[].exploitation.summary` | 2.N (ABILITY) | 利用摘要段落 | — |
| `attack_paths[].exploitation.payload.snippet` | 2.N (ABILITY) | 利用载荷代码块 | — |
| `attack_paths[].remediation` | 2.N | 修复建议段落 | 展示 `未提供修复建议` |
| `attack_paths[].matched_rules[]` | 2.N | 命中规则列表 | 展示 `无` |
| `attack_paths[].evidence[]` | 2.N（不单独渲染） | 代码证据已内嵌在 flow[] 各步骤中，不再独立成节 | — |
| `evidence[].file` | — | — | — |
| `evidence[].line_range` | — | — | — |
| `evidence[].snippet` | — | — | — |
| `evidence[].description` | — | — | — |
| `statistics.by_skill` | 3. 审计总结 | 审计覆盖表 | 跳过此表 |
| `warnings[]` | 3. 审计总结 | 警告区块 | 跳过此区块 |

---

## 执行流程

### Step 1: 运行聚合脚本

```bash
python skills_v2/harmony-report-generator/scripts/report_aggregator.py <audit_dir> -o <audit_dir>/aggregated_data.json --pretty
```

若 `python3` 不可用（如 Windows），改为 `python`。

### Step 2: 读取数据

**必须使用 Read 工具**读取 `<audit_dir>/aggregated_data.json`，将其完整内容存入变量 `data`。后续所有渲染操作均从 `data` 对象取值。

读取后确认 data 对象包含以下顶层字段：
- `data.project` — 对象
- `data.attack_paths` — 数组（可能为空）
- `data.statistics` — 对象
- `data.risk_score` — 数字
- `data.warnings` — 数组

若 data 为空或解析失败，向用户报错并终止。

### Step 3: 渲染报告

**按以下三个段落的顺序，逐段拼接 Markdown 字符串。每段完成后不要急着写文件，所有段落拼接完成后再一次性写入。**

#### 段落 1: 报告总览（固定模板）

```markdown
# 鸿蒙应用安全审计报告

> 审计时间：{data.audit_time，格式化为 "YYYY年MM月DD日 HH:mm"} | 风险评分：{data.risk_score}/100 | 已验证攻击路径：{data.project.verified_paths} 条

---

## 1. 审计概览

### 1.1 审计范围

本轮安全审计从攻击者视角出发，对目标鸿蒙应用进行了全面的攻击面分析与攻击路径验证。

| 指标 | 数值 | 说明 |
|------|------|------|
| 发现外部入口 | {data.project.entries_count} 个 | 包括 DeepLink、IPC 服务、URL 回调等外部可控入口 |
| 发现攻击终点 | {data.project.sinks_count} 个 | 包括 WebView 加载点、文件读写、数据库操作等高危终点 |
| 已验证攻击路径 | {data.project.verified_paths} 条 | 经过 AI 双向追踪验证、确认真实可达的完整攻击链路 |
| 综合风险评分 | {data.risk_score} / 100 | 基于漏洞严重度和影响范围加权计算 |

### 1.2 漏洞分布

{根据 data.statistics.by_severity 计算总发现数 total_findings}

本次审计共发现 **{total_findings}** 项安全漏洞，按严重度分布如下：

| 严重度 | 数量 | 占比 | 说明 |
|--------|------|------|------|
| 🔴 Critical | {data.statistics.by_severity.critical \|\| 0} | {计算占比}% | 可直接导致应用被完全控制或敏感数据大规模泄露 |
| 🟠 High | {data.statistics.by_severity.high \|\| 0} | {计算占比}% | 可导致敏感数据泄露或权限提升，利用难度较低 |
| 🟡 Medium | {data.statistics.by_severity.medium \|\| 0} | {计算占比}% | 可被利用但需要一定前置条件 |
| 🔵 Low | {data.statistics.by_severity.low \|\| 0} | {计算占比}% | 安全最佳实践偏离，暂未形成直接攻击链路 |
| ⚪ Info | {data.statistics.by_severity.info \|\| 0} | {计算占比}% | 提示性信息，建议关注 |

{如果 total_findings == 0，则输出：}
> ✅ 本次审计未发现可被外部利用的安全漏洞。项目的攻击面配置处于良好状态。

{如果 total_findings > 0，则额外输出以下态势评估段落：}
### 1.3 安全态势评估

{AI 根据 severity 分布和 risk_score 撰写 3-5 句专业的安全态势评估。必须提到：
1. 最严重的风险类型（从 attack_paths 的各条目 title 中归纳）
2. 整体安全态势是乐观/需关注/危急
3. 1 句关于修复优先级的建议}

{示例（当存在 Critical 发现时）:}
本次审计发现攻击者可通过多个外部入口构造完整攻击链路。其中 **IPC 跨进程通信**和 **WebView JS Bridge** 暴露了高危攻击面，攻击者能够从零权限起步，逐步获取应用沙箱内敏感数据乃至执行任意文件操作。整体安全态势评级为**危急**，建议立即启动 Critical 和 High 级别漏洞的修复工作。
```

#### 段落 2: 攻击路径详情（每条路径独立子节）

```markdown
---

## 2. 攻击路径详情

{以下是每条 attack_path 的渲染规则。对 data.attack_paths[] 中的每一项，按 severity 从高到低逐一渲染。}

{=== 开始单条攻击路径渲染 ===}

### {attack_path.id} {attack_path.title} [{severity 色标}]

{设置 severity_emoji = "critical" → "🔴", "high" → "🟠", "medium" → "🟡", "low" → "🔵", "info" → "⚪"}

> **严重度**: {severity_emoji} {attack_path.severity} | **ID**: {attack_path.id}

---

{=== 分支 A: 如果 attack_path.id 以 "IPC-" 开头 ===}

#### 攻击目标

**模块**: {attack_path.module，缺失则写 "--"}  
**类型**: 跨进程通信服务 (IPC Service Extension)  
**攻击路径类型**: 外部 IPC 客户端 → 服务端 Stub → 敏感业务执行 / 数据泄露

{如果 attack_path.non_sensitive_summary 存在，渲染：}
> **非敏感分支说明**: {attack_path.non_sensitive_summary}

{如果 attack_path.input 存在，渲染：}

#### 攻击载荷

攻击者构造 IPC 请求所需的 code 和 data 格式如下：

```typescript
// 请求码: {attack_path.input.code}
// 数据格式: {attack_path.input.data_format}
{attack_path.input.snippet}
```

{如果 attack_path.cases[] 存在且 length > 0，渲染：}

#### 敏感业务分支分析

以下表格列出了该 IPC 服务中**被判定为存在安全风险的 code 分支**：

| Code | 业务描述 | 输入数据 | 输出结果 | 风险原因 |
|------|---------|---------|---------|---------|
{遍历 attack_path.cases[]}
| {case.code} | {case.description} | {case.input} | {case.output} | {case.sensitive_reason} |
{遍历结束}

{=== 分支 B: 如果 attack_path.id 以 "WEBVIEW-" 开头 ===}

{如果 attack_path.entry 存在，渲染：}

#### 攻击入口

| 属性 | 说明 |
|------|------|
| **入口类型** | {attack_path.entry.type} |
| **入口位置** | `{attack_path.entry.file}` |
| **触发方式** | {attack_path.entry.how} |
| **可控参数** | {attack_path.entry.payload.url，缺失则写 "want.parameters"} |

**攻击者构造的入口载荷**：

```typescript
{attack_path.entry.payload.snippet}
```

{如果 attack_path.cases 存在，渲染：}

#### JS Bridge 方法安全分析

{如果 attack_path.cases.bridge_methods[] 存在且 length > 0，渲染：}

下表列出了该 WebView 通过 `registerJavaScriptProxy` 注册的所有 JS Bridge 方法及其安全评估：

| 方法名 | 是否敏感 | 原生实现 | 评估结论 |
|--------|---------|---------|---------|
{遍历 attack_path.cases.bridge_methods[]}
| {method.name} | {method.sensitive ? "⚠️ 是" : "✅ 否"} | {method.implementation} | {method.reason} |
{遍历结束}

{如果 attack_path.cases.interceptors[] 存在且 length > 0，渲染：}

#### URL 加载拦截器分析

| 拦截器类型 | 是否已实现 | 风险评估 |
|-----------|-----------|---------|
{遍历 attack_path.cases.interceptors[]}
| {interceptor.type} | {interceptor.present ? "✅ 已实现" : "❌ 未实现"} | {interceptor.risk} |
{遍历结束}

{=== 分支 C: 如果 attack_path.id 以 "ABILITY-" 开头 ===}

{如果 attack_path.ability_details 存在，渲染：}

#### 目标 Ability 信息

| 属性 | 说明 |
|------|------|
| **Ability 名称** | {attack_path.ability_details.name} |
| **是否导出** | {attack_path.ability_details.exported ? "是 (exported: true)" : "否 (exported: false)"} |
| **调用方身份校验** | {attack_path.ability_details.caller_verification，缺失则写 "无"} |
| **getCallingBundleName 检查** | {attack_path.ability_details.has_calling_bundle_check ? "已使用" : "未使用"} |

{如果 attack_path.module 存在，渲染：}
**所属模块**: {attack_path.module}

{=== 分支 A/B/C 结束，以下为所有攻击路径通用的渲染逻辑 ===}

---

#### 攻击流程

以下按步骤展示从攻击入口到危害终点的完整数据流向。每一步均附带实际源码证据。

{如果 attack_path.flow[] 存在且 length > 0，对每个 flow 元素渲染：}

> **步骤 {flow.step}: {flow.stage}**
>
> **文件位置**: `{flow.file}`
>
> {flow.description}
>
> ```typescript
> {flow.snippet}
> ```
>
> 

{如果 attack_path.flow[] 不存在或为空，渲染：}
> *数据流向不可追溯*

---

#### 危害评估

{如果 attack_path.impact.summary 存在，渲染：}

{attack_path.impact.summary}

{如果 attack_path.impact.sensitive_data_exposed[] 存在且 length > 0，渲染：}

**可能泄露的敏感数据**：

{遍历 attack_path.impact.sensitive_data_exposed[]。根据 skill 类型适配字段名——IPC 用 field/type/source/content，WebView/Ability 用 data/via/example。对每个元素输出：}
- **{item.field 或 item.data}**：{item.content 或 item.risk}（来源：{item.source 或 "通过 " + item.via}）
{如果 item.example 存在，追加：}
  ```
  示例输出: {item.example}
  ```
{遍历结束}

{如果 attack_path.impact.sensitive_operations[] 存在且 length > 0，渲染：}

**攻击者可执行的敏感操作**：

{遍历 attack_path.impact.sensitive_operations[]}
- **{item.operation}**：通过 {item.via} 实现，后果为 {item.consequence}
{遍历结束}

{如果 attack_path.impact.output_example 存在，渲染：}

**攻击成功后的预期输出**：

```
{attack_path.impact.output_example}
```

---

#### 利用方法

{如果 attack_path.exploitation 是字符串，渲染为有序步骤列表，后跟最小 PoC 代码:}

**攻击步骤**：

{attack_path.exploitation}

**最小 PoC 代码**（可直接编译执行的攻击应用核心代码）：

{从 attack_path 中提取 PoC 代码来源。优先取 attack_path.input.snippet（IPC），其次取 attack_path.entry.payload.snippet（WebView），若均无则从 flow[] 中提取关键调用构造极简 PoC：}

```typescript
{I根据 skill 提取 PoC，至少 10 行核心逻辑}
```

{PoC 代码要点（以注释形式标注）：
1. 展示攻击者应用如何构造请求/参数
2. 展示关键的 API 调用（connectServiceExtensionAbility / startAbility / sendMessageRequest）
3. 展示攻击载荷的构造方式
4. 代码必须为极简完整型，不可冗余}

{如果 attack_path.exploitation 是对象（Ability skill），渲染：}

**攻击步骤**：{attack_path.exploitation.summary}

**最小 PoC 代码**（可直接编译执行的攻击应用核心代码）：

```typescript
{attack_path.exploitation.payload.snippet}
```

{如果 attack_path.exploitation.payload 中的其他字段存在（target_bundle、target_ability、nested_want），以注释形式附在 PoC 代码块上方：}
{// target_bundle: ..., // target_ability: ...}

---

#### 修复建议

{attack_path.remediation}

---

{如果 attack_path.matched_rules[] 存在且 length > 0，渲染：}

#### 命中安全规则

{遍历 attack_path.matched_rules[]，以逗号分隔：`IPC-003`, `IPC-004`, `IPC-007`}

{注意：attack_path.evidence[] 中的代码片段与 flow[] 中各步骤的 snippet 高度重叠，为避免报告冗余，不再渲染独立的"关键代码证据"子节。代码证据已通过"攻击流程"章节中的各步骤完整呈现。}

---

{=== 单条攻击路径渲染结束，继续下一条 ===}

{如果 data.attack_paths[] 为空，渲染：}
> ✅ 未发现可被外部利用的攻击路径。项目不存在从外部入口到攻击终点的可达链路。

---
```

#### 段落 3: 审计总结

```markdown
## 3. 审计总结

### 3.1 风险总览

{从 data.statistics.by_severity 读取数据，生成与 1.2 相同的表格}

**综合风险评分**: **{data.risk_score}** / 100

{AI 根据风险评分写 1-2 句总结。参考标准：
- 80-100：危急 —— 存在可被直接利用的严重漏洞，建议立即修复
- 50-79：高风险 —— 存在多条可达攻击链路，需在本迭代内修复
- 20-49：中等风险 —— 存在部分安全问题，可纳入下一迭代
- 0-19：低风险 —— 安全态势良好，继续关注}

### 3.2 审计覆盖范围

| 审计 Skill | 发现路径数 | 覆盖的攻击面 |
|-----------|-----------|------------|
{遍历 data.statistics.by_skill}
| {skill_name 映射为中文} | {count} | {根据 skill 描述攻击面} |
{遍历结束}

{skill_name 中文映射表：
- "IPC" → "IPC 跨进程通信安全审计"
- "WEBVIEW" → "WebView 安全审计"
- "ABILITY" → "UIAbility 安全审计"
- 其他 → 直接用原名}

{如果 data.warnings[] 存在且 length > 0，渲染：}

### 3.3 审计警告

> ⚠️ 以下问题可能影响审计结果完整性：

{遍历 data.warnings[]}
> - {warning}

{遍历结束}

### 3.4 修复优先级建议

{AI 根据 attack_paths 的 severity 排序和相互关系，按优先级分组撰写修复建议。必须使用以下三段式结构：}

#### 第一优先级：立即修复（Critical 漏洞）

{列出所有 severity == "critical" 的攻击路径。对每条路径，提炼 1-2 句核心问题 + 关键修复措施。如果无 Critical 则写 "✅ 无"。}

#### 第二优先级：本迭代内修复（High 漏洞）

{列出所有 severity == "high" 的攻击路径。同上。如果无 High 则写 "✅ 无"。}

#### 第三优先级：纳入后续迭代（Medium / Low 漏洞）

{汇总列出所有 Medium 和 Low 的攻击路径，简要概述。如果无则写 "✅ 无"。}
```

### Step 4: 质量检查清单

**在调用 Write 工具写入文件之前，必须逐项确认以下 8 条：**

```
□ 1. 报告以 "# 鸿蒙应用安全审计报告" 一级标题开头
□ 2. "## 1. 审计概览" 章节包含 1.1 和 1.2 两个子节（以及 1.3，当有发现时）
□ 3. "## 2. 攻击路径详情" 章节存在
□ 4. 每条攻击路径包含：攻击目标/入口 + 攻击流程 + 危害评估 + 利用方法 + 修复建议 五个部分
   （各部分的名称可能根据 skill 不同稍有变化，但至少需要这五个主题）
□ 5. 所有代码片段均使用 ```typescript 代码块包围
□ 6. severity 色标正确：Critical → 🔴，High → 🟠，Medium → 🟡，Low → 🔵，Info → ⚪
□ 7. 报告末尾有 "## 3. 审计总结" 章节（包含 3.1-3.4 子节）
□ 8. 未遗漏 data.attack_paths[] 中的任何一条攻击路径
```

如果上述任何一条不满足，**回退到对应段落重新渲染**，直到全部通过后再执行 Step 5。

### Step 5: 写入文件

**必须使用 Write 工具写入以下两个文件，不可仅在对话中展示报告内容：**

| 文件 | 路径 | 内容 |
|------|------|------|
| Markdown 报告 | `<audit_dir>/audit-report.md` | Step 3 拼接的完整 Markdown 字符串 |
| JSON 数据 | `<audit_dir>/audit-report.json` | 将 `aggregated_data.json` 的完整内容写入（可复制或重新读取后写入） |

写入完成后，向用户输出以下确认信息：

```
📄 审计报告已生成：
  - Markdown 报告: <audit_dir>/audit-report.md
  - JSON 数据: <audit_dir>/audit-report.json
  - 共包含 {data.project.verified_paths} 条攻击路径
```

---

## 附录 A: 字段渲染规则速查表

以下是各数据类型在 Markdown 中的精确渲染格式。每一类数据都必须严格按照以下公式渲染，不可自由发挥。

### flow[] 数组渲染公式

```
对 attack_path.flow[] 中的每个元素:
  写入: "> **步骤 {step}: {stage}**"
  换行: ">"
  写入: "> **文件位置**: `{file}`"
  换行: ">"
  写入: "> {description}"
  换行: ">"
  写入: "> ```typescript"
  换行: "> {snippet}"
  换行: "> ```"
  换行: ">"
  换行: ""   （空行分隔不同步骤）
```

### evidence[] 数组渲染公式

```
对 attack_path.evidence[] 中的每个元素:
  写入: "**证据 {1-based index}**：`{file}`, 行 {line_range}"
  换行: ""
  写入: "```typescript"
  换行: "{snippet}"
  换行: "```"
  换行: ""
  写入: "*{description}*"
  换行: ""
  换行: ""
```

### exploitation 字符串渲染公式

```
如果 attack_path.exploitation 是字符串:
  直接原样输出字符串内容。如果字符串中包含换行和编号（如 "1. xxx\n2. yyy"），
  保留换行，确保渲染为有序列表。
```

### exploitation 对象渲染公式

```
如果 attack_path.exploitation 是对象（Ability skill）:
  写入: "**利用思路**：{exploitation.summary}"
  换行: ""
  换行: "**攻击者构造的攻击载荷**："
  换行: ""
  写入: "```typescript"
  换行: "{exploitation.payload.snippet}"
  换行: "```"
  换行: ""
  如果 exploitation.payload.nested_want 存在:
    写入: "```typescript"
    换行: "{JSON 格式化 nested_want}"
    换行: "```"
```

### cases[] 数组渲染公式 (IPC)

```
如果 attack_path.cases[] 存在且 length > 0:
  先写表头:
    "| Code | 业务描述 | 输入数据 | 输出结果 | 风险原因 |"
    "|------|---------|---------|---------|---------|"
  对每个 case 元素:
    "| {case.code} | {case.description} | {case.input} | {case.output} | {case.sensitive_reason} |"
```

### bridge_methods[] 数组渲染公式 (WebView)

```
如果 attack_path.cases.bridge_methods[] 存在且 length > 0:
  先写表头:
    "| 方法名 | 是否敏感 | 原生实现 | 评估结论 |"
    "|--------|---------|---------|---------|"
  对每个 method 元素:
    "| {method.name} | {method.sensitive ? "⚠️ 是" : "✅ 否"} | {method.implementation} | {method.reason} |"
```

### interceptors[] 数组渲染公式 (WebView)

```
如果 attack_path.cases.interceptors[] 存在且 length > 0:
  先写表头:
    "| 拦截器类型 | 是否已实现 | 风险评估 |"
    "|-----------|-----------|---------|"
  对每个 interceptor 元素:
    "| {interceptor.type} | {interceptor.present ? "✅ 已实现" : "❌ 未实现"} | {interceptor.risk} |"
```

---

## 附录 B: 缺失字段降级规则

当字段在 JSON 中不存在或值为 null/undefined 时，按以下规则处理：

| 字段 | 渲染行为 |
|------|---------|
| `attack_paths` 为空数组 | 渲染 "✅ 未发现可被外部利用的攻击路径" |
| `flow[]` 不存在或为空 | 渲染 "*数据流向不可追溯*" |
| `evidence[]` 不存在或为空 | 跳过 "#### 关键代码证据" 整个子节 |
| `matched_rules[]` 不存在或为空 | 渲染 "无" |
| `impact.summary` 不存在 | 渲染 "未提供影响评估" |
| `exploitation` 不存在 | 渲染 "未提供利用方法" |
| `remediation` 不存在 | 渲染 "未提供修复建议" |
| `cases[]` 不存在 | 跳过对应表格 |
| `cases.bridge_methods[]` 不存在 | 跳过 JS Bridge 表格 |
| `cases.interceptors[]` 不存在 | 跳过拦截器表格 |
| `non_sensitive_summary` 不存在 | 跳过此行 |
| `input` 不存在 | 跳过攻击载荷代码块 |
| `entry` 不存在 | 用 attack_path.flow[0] 的信息替代入口描述 |
| `ability_details` 不存在 | 跳过能力信息卡 |
| `module` 不存在 | 不渲染模块行（IPC/Ability 中） |
| `statistics.by_severity` 中某级别不存在 | 渲染为 0 条 |

## 重要原则

1. **按攻击路径组织报告**——不是按组件枚举，不是按 skill 分章，而是每条攻击路径独立成节
2. **代码证据原样展示**——从 evidence[].snippet / flow[].snippet 字段逐字复制，不可改写
3. **字段路径精确匹配**——使用附录 A 的公式渲染，不可自由改变代码块、表格、列表的格式
4. **缺失字段不报错**——按附录 B 降级规则处理，宁可少渲染一节也不可整条路径跳过
5. **质量检查必须通过**——Step 4 的 8 项检查全部确认后才写入文件
6. **必须写入文件**——不可仅在对话中展示报告内容，必须调用 Write 工具写入磁盘
