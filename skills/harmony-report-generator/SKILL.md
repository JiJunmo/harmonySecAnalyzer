---
name: harmony-report-generator
description: 聚合审计发现，生成包含风险评分、发现详情、OWASP对标的安全审计报告（Markdown+JSON双格式）
---

# harmony-report-generator

安全审计报告生成器。读取聚合后的审计数据，生成 Markdown 和 JSON 双格式报告。

## 触发条件

Phase 3 聚合完成后，Agent 自动调度本 Skill。

## 输入

| 数据 | 来源 |
|------|------|
| `aggregated_data.json` | Phase 3 聚合脚本输出 |
| 审计工作目录 | Phase 0 创建 |

## 执行流程

### Step 1: 读取聚合数据

读取 `<audit_dir>/aggregated_data.json`，获取：
- `project` — 项目概览
- `security_surface` — 安全攻击面
- `audit.skills_executed` — 已执行 skill
- `audit.skills_pending` — 未实现 skill
- `findings` — 统计数据和完整发现列表
- `risk_score` — 风险评分

### Step 2: 生成 Markdown 报告

按以下模板生成 `<audit_dir>/audit-report.md`。**严格要求**：

- 每个 finding 的 `description` 和 `remediation` 必须使用聚合数据中的原文
- `location.snippet` 必须原样保留代码片段
- severity 色标：`Critical` 🔴、`High` 🟠、`Medium` 🟡、`Low` 🔵、`Info` ⚪

#### 报告模板

```markdown
# 鸿蒙应用安全审计报告

> 审计时间: `<audit.time>` | 风险评分: **`<risk_score>`/100**

---

## 1. 执行摘要

| 严重度 | 数量 |
|--------|------|
| 🔴 Critical | `<by_severity.critical>` |
| 🟠 High | `<by_severity.high>` |
| 🟡 Medium | `<by_severity.medium>` |
| 🔵 Low | `<by_severity.low>` |
| ⚪ Info | `<by_severity.info>` |

**安全态势**：`<根据 findings 的 severity 分布和 risk_score，AI 写 1-3 句评估>`

- 若 risk_score > 60 或存在 Critical → "项目存在严重安全风险，建议立即修复 Critical 和 High 级别发现后再发布"
- 若 risk_score 30-60 且有 High → "项目存在中等风险，建议在下一版本中修复 High 级别发现"
- 若 risk_score < 30 且无 Critical/High → "项目安全状况良好，Medium 及以下发现可按节奏修复"

---

## 2. 项目概览

| 项目 | 值 |
|------|----|
| 应用名称 | `<project.name>` |
| 包名 | `<project.package_name>` |
| 目标 SDK | `<project.sdk_version>` (API `<project.api_level>`) |
| 模块数 | `<project.module_count>` |
| ArkTS 源文件 | `<project.total_ets_files>` 个 |
| 代码行数 | `<project.total_lines>` 行 |

### 攻击面

| 维度 | 状态 |
|------|------|
| 申请权限 | `<total_permissions>` 个（高危 `<high_risk_permissions>` 个） |
| 导出组件 | `<exported_abilities>` 个 Ability，`<exported_extensions>` 个 Extension |
| IPC 服务 | `<has_ipc_service ? "是" : "否">` |
| WebView | `<has_webview ? "是" : "否">` |
| 数据库 | `<has_database ? "是" : "否">` |
| 分布式 | `<has_distributed ? "是" : "否">` |
| NAPI 模块 | `<has_napi ? "是" : "否">` |

---

## 3. 发现详情

`<按 severity 分组：Critical → High → Medium → Low → Info。每组内按 finding.id 排序。>`

### 🔴 Critical (`<count>`)

#### `<finding.title>` [<finding.id>]

- **严重度**: Critical | CWE: `<cwe>` | OWASP: `<owasp>`
- **来源**: `<finding.skill>`
- **位置**: `<location.file>:<location.line>`
- **描述**: `<finding.description>`

```
<location.snippet>
```

- **修复建议**: `<finding.remediation>`
- **参考**: `<finding.reference>`

`<critical 没有时写 "未发现 Critical 级别问题">`

### 🟠 High (`<count>`)
`<同上模板>`

### 🟡 Medium (`<count>`)
`<同上模板>`

### 🔵 Low (`<count>`)
`<同上模板>`

### ⚪ Info (`<count>`)
`<同上模板>`

---

## 4. 合规对标

### OWASP Mobile Top 10 (2024) 覆盖

| OWASP | 描述 | 发现数 |
|-------|------|--------|
| `<owasp_id>` | `<owasp_label>` | `<count>` |

`<根据 by_owasp 统计填充，未覆盖的行标为 0>`

### CWE 覆盖

`<列出 by_cwe 中所有 CWE 及其发现数>`

---

## 5. 附录

### 审计范围

| Skill | 状态 |
|-------|------|
`<skills_executed 标记 ✅，skills_pending 标记 🔜>`

### 规则覆盖统计

`<根据 findings.by_skill 统计每个 skill 的发现数>`

---

> 报告由 harmony-report-generator 自动生成 | `<audit.time>`
```

### Step 3: 输出文件

| 文件 | 路径 |
|------|------|
| Markdown 报告 | `<audit_dir>/audit-report.md` |
| JSON 数据 | `<audit_dir>/audit-report.json`（直接写入聚合数据） |

---

## 依赖关系

- **上游**: Phase 3 聚合脚本 (`report_aggregator.py`)
- **下游**: 无（最终输出）
