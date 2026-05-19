---
name: harmony-report-generator
description: 按skill独立成章生成审计报告，包含项目总览、各安全审计模块详情、自定义规则覆盖和合规对标总结
---

# harmony-report-generator

安全审计报告生成器。读取聚合数据和各 skill 输出，生成**按 skill 独立成章**的专业审计报告（Markdown + JSON）。

## 触发条件

Phase 3 聚合完成后，Agent 自动调度本 Skill。

## 输入

| 数据 | 来源 |
|------|------|
| `aggregated_data.json` | Phase 3 聚合脚本输出（含 `analysis_reports` 字典 + `warnings` + findings 统计） |
| 审计工作目录 | 用于读取各 skill 的完整分析报告 |

## 报告结构

```
1. 项目总览                ← harmony-project-parser 输出
2-N. 各审计 skill 章节      ← 遍历 analysis_reports 字典动态生成（按发现统计排序）
  N.1 总览统计              ← 表：所有被审计实例 + 发现数 + 最高严重度
  N.2 详细分析 (Critical/High) ← 仅展开 Critical/High 实例的全层分析 + 漏洞详情
  N.3 摘要 (Medium)          ← 表格：Medium 实例的问题汇总
N+1. 审计总结               ← 风险总览 + rules/CWE/OWASP 覆盖 + 修复优先级 + 校验 warnings
附录 A                      ← 审计范围 / 待实现 skill
附录 B                      ← 完整分析（→ audit-report-appendix.md）
```

## 报告渲染规则

审计分析保持完整（全部实例全层存入各 skill 的 analysis.json 和附录），但报告正文按发现严重度**分级渲染**：

| 实例最高 severity | 报告正文 | 附录 |
|------------------|---------|------|
| Critical / High | 完整展开：所有 Layer + code_references + 完整漏洞诊断 | 同正文 |
| Medium | 表格摘要：每层一行 + 漏洞名（不展开 code_references） | 完整展开 |
| Low / Info | 不渲染：仅在总览统计表中出现 | 完整展开 |
| 无发现 | 不渲染：统计表中标记 ✅ | 不渲染 |

---

## 执行流程

### Step 1: 读取所有输入

1. 读取 `<audit_dir>/aggregated_data.json` 获取聚合统计数据
2. 从 `analysis_reports` 字典获取各 skill 的分析报告（含 call_chains / webview_instances）
3. 检查 `warnings` 数组，如有计数校验警告需在报告中展示
4. 按 `skill` 字段将 `items` 中的 findings 分组

### Step 2: 生成报告

生成三个文件：正文（分级渲染）+ 附录（完整分析）+ JSON。

**正文生成顺序**：

1. **项目总览**（固定模板，从 metadata 提取数据）
2. **遍历 `analysis_reports` 字典**：对每个有分析数据的 skill，动态生成章节
3. **审计总结**：风险总览 + 自定义规则命中 + CWE/OWASP 覆盖 + 修复优先级 + warnings
4. **附录 A**：审计范围 + 待实现 skill
5. **附录 B**：完整分析 → 写入 `audit-report-appendix.md`

**动态章节生成规则**：

```
对 analysis_reports 中的每个 skill:
  # N. {skill 中文名}
  > 审计 Skill: {skill_name} | 分析: {expected} 个实例 | 发现: {n} 项

  ## N.1 总览统计
  | 实例名 | 关键配置 | 发现数 | 最高严重度 |
  |--------|---------|--------|-----------|

  ## N.2 详细分析（仅 Critical/High 实例）
  仅渲染 highest_severity ∈ {critical, high} 的实例，完整展开所有 Layer

  ## N.3 摘要（仅 Medium 实例）
  | 实例名 | 层 | 问题 |
  表格形式，不展开 code_references

  # 注意：Low / Info / 无发现 实例不出现在正文中
```

**通用要求**：
- 所有代码片段从 `evidence` / `code_references` / `location.snippet` 字段原样复制
- 行号从 `line_range` / `line` 字段原样引用
- severity 色标：Critical 🔴、High 🟠、Medium 🟡、Low 🔵、Info ⚪
- 报告不设长度上限

---

#### 报告模板

```markdown
# 鸿蒙应用安全审计报告

> **审计时间**: `<audit.time>` | **风险评分**: **`<risk_score>`**/100 | **发现总数**: `<findings.total>`


# 1. 项目总览

## 1.1 执行摘要

| 严重度 | 数量 |
|--------|------|
| 🔴 Critical | `<by_severity.critical>` |
| 🟠 High | `<by_severity.high>` |
| 🟡 Medium | `<by_severity.medium>` |
| 🔵 Low | `<by_severity.low>` |
| ⚪ Info | `<by_severity.info>` |

### 安全态势评估

<AI 根据 severity 分布和 risk_score 写出 2-4 句专业评估。>

### Top 风险速览

<列出最严重的 3 项发现，每项一行，含严重度标记 + 标题>

---

## 1.2 项目基本信息

| 项目 | 值 |
|------|----|
| 应用名称 | `<project.name>` |
| 包名 | `<project.package_name>` |
| 版本 | `<project.version>` |
| 目标 SDK | `<sdk_version>` (API `<api_level>`) |
| 构建模式 | `<build_mode>` |
| 模块数 | `<module_count>` |
| ArkTS 源文件 | `<total_ets_files>` 个 |
| 代码总行数 | `<total_lines>` 行 |

---

## 1.3 安全攻击面

| 攻击面维度 | 当前状态 | 风险等级 |
|-----------|---------|----------|
| 申请权限 | `<total_permissions>` 个（高危 `<high_risk_permissions>` 个） | <AI 判定：高危权限>3 → 🟠 High> |
| 导出 Ability | `<exported_abilities>` 个 | <exported_abilities>0 → 🟡 Medium，否则 ⚪ Low> |
| 导出 Extension | `<exported_extensions>` 个 | <同上有则 Medium> |
| IPC 跨进程通信 | <has_ipc_service ? "已启用" : "未使用"> | <已启用 → 🟠 High> |
| 分布式能力 | <has_distributed ? "已启用" : "未使用"> | <已启用 → 🟡 Medium> |
| NAPI 原生模块 | <has_napi ? "已使用" : "未使用"> | <已使用 → 🟡 Medium> |
| WebView | <has_webview ? "已使用" : "未使用"> | <已使用 → 🟡 Medium> |
| 本地数据库 | <has_database ? "已使用" : "未使用"> | <已使用 → 🔵 Low> |

---

## 1.4 模块结构

<从 metadata.modules 中提取，以表格列出每个模块的关键信息：>

| 模块名 | Ability 数 | Extension 数 | 权限数 | 主要功能 |
|--------|-----------|-------------|--------|---------|
| `<module.name>` | `<abilities count>` | `<extensions count>` | `<permissions count>` | <从模块名推断> |

---


# 2-N. 各审计 Skill 章节（动态生成，遍历 analysis_reports 字典）

> 对 `aggregated_data.json` 的 `analysis_reports` 字典中的每个 skill，按以下结构生成章节。没有分析数据的 skill（仅有 findings 无 analysis）使用简化模板。

## <N>.1 {skill} 总览统计

| 实例名 | 模块/文件 | 关键配置 | 发现数 | 最高严重度 |
|--------|----------|---------|--------|-----------|
| <实例名> | <位置> | <配置摘要> | <n> | <severity 色标> |

<无 findings 的实例标记为 ✅>

## <N>.2 详细分析（仅 Critical/High 实例）

<对 highest_severity ∈ {critical, high} 的实例，使用完整模板展开。优先使用增强格式字段（root_cause / attack_scenario / impact / evidence），不存在则回退到基础格式。>

### <实例名> (<实例ID>) [<severity 色标>]

#### Layer 1: <layer_name>

- **分析**: <analysis 原文>
- **代码引用**: ...
- **识别到的潜在问题**: ...

<每个有发现且 severity ∈ {critical, high} 的 Layer 展开>

#### 漏洞详情

<按 severity 分组的 findings，参考下方模板>

## <N>.3 摘要（仅 Medium 实例）

<对 highest_severity == "medium" 的实例，表格形式呈现：>

| 实例名 | 层 | 问题 |
|--------|-----|------|
| <实例名> | <层> | <问题摘要> |

---

# 2. IPC 跨进程通信安全审计 (示例：旧模板保留作为参考)

<如果 call_chain_analysis.json 存在且 call_chains 非空，对每个 call_chain 输出。这部分是 AI 的思考过程。>

### 服务: `<service_name>` (`<chain.id>`)

**基本信息**: 模块=`<module>`, 类型=`<extension_type>`

<对 layers 按 order 排序输出每层分析：>

#### Layer `<order>`: `<layer>`

- **分析**: `<analysis>` <--- 原文，不可改写>

<如果 code_references 存在：>

**代码引用**:

<每个 code_reference 一个代码块：>

`<file>:<line_range>`
```typescript
<snippet>
```
*`<description>`*

<如果 issues_identified 存在：>

**识别到的潜在问题**: `<issues_identified 列表，逐条 bullet>`

---

**该服务风险评估**: <AI 汇总该服务所有层的 issues_identified，写 1-2 句整体评估>

---

<如果不存在调用链分析但存在 IPC findings:>

该项目未生成调用链分析，直接展示发现列表。

---

## 2.2 漏洞发现详情

<按 severity 分组：Critical → High → Medium → Low → Info>

### 🔴 Critical (`<n>`)

<对每条发现使用以下模板。优先使用增强格式字段（root_cause / attack_scenario / impact / evidence），不存在则回退到基础格式。>

#### `<finding.title>` [`<finding.id>`]

| 属性 | 内容 |
|------|------|
| **规则 ID** | `<rule_id>` |
| **严重度** | 🔴 Critical |
| **CWE** | `<cwe>` |
| **OWASP** | `<owasp>` |

##### 漏洞描述

<finding.description>

##### 根本原因

<root_cause 存在则原样输出，否则 AI 根据 description 推断>

##### 攻击场景

<attack_scenario 存在则原样输出，否则 AI 推断>

##### 影响评估

<impact 存在则原样输出，否则 AI 根据 severity 推断>

##### 关键证据

**证据 `<i>`**: `<evidence[i].file>`, 行 `<evidence[i].line_range>`
```typescript
<evidence[i].snippet>
```
*`<evidence[i].description>`*

<如果无 evidence 但有 location.snippet:>

**位置**: `<location.file>:<location.line>`
```typescript
<location.snippet>
```

##### 修复建议

<finding.remediation>

##### 参考

<finding.reference>

---

<如果该 severity 级别无发现: "✅ 未发现 **severity** 级别问题。">

### 🟠 High (`<n>`)
<同上>

### 🟡 Medium (`<n>`)
<同上>

### 🔵 Low (`<n>`)
<同上>

### ⚪ Info (`<n>`)
<同上>

---

## 2.3 本模块统计

| 统计项 | 值 |
|--------|-----|
| 发现总数 | `<n>` |
| Critical | `<n>` |
| High | `<n>` |
| Medium | `<n>` |
| Low | `<n>` |
| Info | `<n>` |

---


# 3. `<下一个已实现 skill 的章节>`

<对每一个已执行且有 findings 的 skill（非 project-parser / report-generator），按上述第 2 章模板生成。格式同理：>

```
# <N>. <skill 中文名称>

> **审计 Skill**: <skill_name> | **发现**: <n> 项

## <N>.1 <skill 专属分析内容>  ← 如果有像 IPC 那样的调用链分析
## <N>.2 漏洞发现详情
    <按 severity 分组，同上模板>
## <N>.3 本模块统计
```

<对已执行但无发现的 skill，缩简为一段：>

```
# <N>. <skill 名称>

> **审计 Skill**: <skill_name> | **发现**: 0 项

✅ 未发现任何安全问题。
```

<对未实现的 skill，不生成章节。>


# <N>. 审计总结

## <N>.1 风险总览

| 严重度 | 数量 | 占比 |
|--------|------|------|
| 🔴 Critical | `<n>` | `<%>` |
| 🟠 High | `<n>` | `<%>` |
| 🟡 Medium | `<n>` | `<%>` |
| 🔵 Low | `<n>` | `<%>` |
| ⚪ Info | `<n>` | `<%>` |

**综合风险评分**: **`<risk_score>`**/100

<AI 写 1 句总结>

---

## <N>.2 自定义规则命中统计

> 下表列出本次审计中**我们自定义的所有安全规则**命中情况。规则 ID 对应各 skill 的 `rules/*.json` 文件。

| 规则 ID | 规则标题 | 严重度 | 命中次数 | 涉及文件 |
|---------|---------|--------|----------|---------|
| `<rule_id>` | `<title>` | `<severity>` | `<count>` | `<distinct_file_count>` |

<数据来源：从 items 中按 rule_id 分组统计。rule_id 为空的发现归入 "N/A"。>

<若某 skill 定义了大量规则但均未命中，可在表格下方加一行说明。例如：>

> 以下规则已纳入审计范围但本次未命中：IPC-001, IPC-002, ...

---

## <N>.3 CWE 覆盖

| CWE | 描述 | 命中次数 |
|-----|------|----------|
| `<cwe>` | <常见 CWE 标签> | `<count>` |

<从 by_cwe 统计填充，补充每个 CWE 的中文描述>

---

## <N>.4 OWASP Mobile Top 10 (2024) 覆盖

| OWASP | 描述 | 命中次数 |
|-------|------|----------|
| M1: 身份认证与授权 | `<count>` |
| M3: 不安全通信 | `<count>` |
| M5: 授权与访问控制 | `<count>` |
| M7: 客户端代码质量 | `<count>` |
| M8: 代码篡改与完整性 | `<count>` |
| M9: 数据泄露与存储 | `<count>` |

<从 by_owasp 统计填充，OWASP ID 映射到标准标签>

---

## <N>.5 修复优先级建议

<AI 根据 findings 的 severity 和相互关系，按优先级分组给出修复建议：>

### 第一优先级（建议 2 周内修复）

<列出所有 Critical findings 的核心问题，按关联性合并同类项>

### 第二优先级（建议下一版本修复）

<列出所有 High findings>

### 第三优先级（建议纳入 backlog）

<列出 Medium / Low findings>

---

# 附录

## A. 审计范围

| Skill | 状态 | 发现数 |
|-------|------|--------|
<skills_executed → "✅ 已执行", skills_pending → "🔜 待实现">
| `<name>` | `<status>` | `<n>` |

## B. 审计执行信息

- **审计时间**: `<audit.time>`
- **风险评分**: `<risk_score>`/100
- **已执行 Skill**: `<skills_executed>`
- **待开发 Skill**: `<skills_pending>`

## C. 关于本报告

本报告由 harmony-report-generator 自动生成。报告中的代码证据、分析结论由各审计 Skill 的 AI 驱动分析产生，建议结合人工代码审查确认 Critical 和 High 级别发现。

> 报告生成时间: `<audit.time>`
```

---

### Step 3: 写入文件（必须执行）

**完成以上报告内容后，立即使用 Write 工具写入文件，不得仅在对话中展示。**

| 文件 | 路径 | 内容 |
|------|------|------|
| Markdown 报告（正文） | `<audit_dir>/audit-report.md` | 分级渲染后的正文 |
| JSON 数据 | `<audit_dir>/audit-report.json` | `aggregated_data.json` 完整内容 |
| 完整分析附录 | `<audit_dir>/audit-report-appendix.md` | 全部实例全层完整分析 |

> **严禁只把报告内容写在对话回复中。必须调用 Write 工具写入上述三个文件。**

---

## 生成注意事项

0. **必须写入文件** — 调用 Write 工具将所有报告写入磁盘，不要仅打印在对话中
1. **代码片段严禁改写** — 从 evidence/code_references/location.snippet 逐字复制
2. **行号必须准确** — 从 line_range/line 字段原样引用
3. **按 skill 独立成章** — 遍历 `analysis_reports` 字典动态生成，有 findings 的 skill 独立成章
4. **分级渲染** — 正文仅展开 Critical/High 实例的全层分析，Medium 表格摘要，Low/Info 不进入正文
5. **完整分析入附录** — 全部实例的全层完整分析写入 `audit-report-appendix.md`
6. **漏洞详情要深入** — root_cause/attack_scenario/impact 缺一则 AI 推断并标注
7. **规则命中统计** — 汇总章节必须列出所有命中的自定义规则 ID
8. **修复建议因人而施** — Critical/High 给代码级建议，Medium/Low 可以简略

## 依赖关系

- **上游**: Phase 3 聚合脚本 + IPC audit 的 call_chain_analysis.json
- **下游**: 无（最终输出）
