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
- 读取所有 `*-attack-paths.json`，合并为按 skill+severity 排序的列表
- 按 severity / skill / CWE 分组统计
- 计算风险评分
- 对比 `attack_map.json` 的潜在路径数与实际验证的路径数，不一致则输出 warnings

## 报告结构

```
1. 项目概览（从 entries.json / sinks.json 提取）
2-N. 攻击路径详情（按 severity 排序，每个路径完整展示）
N+1. 审计总结（统计 + 修复优先级）
```

## 报告生成

读取 `aggregated_data.json` 后，按以下模板生成 `audit-report.md`：

```
# 鸿蒙应用安全审计报告 v2

## 1. 项目概览
- 外部入口: N 个
- 攻击终点: M 个
- 验证路径: K 条
- 风险评分: X/100

## 2-N. 攻击路径详情

每条路径的展示格式：

### <path.id> <path.title> [<severity>]

**攻击入口**
- 类型: <entry.type>
- 位置: <entry.file>
- 方式: <entry.how>

**攻击载荷**
```typescript
<entry.payload.snippet>
```

**数据流向**
<flow[] 每步以箭头展示，标注绕过点和文件位置>

**危害**
<impact.what>

**攻击成功后的输出示例**
```
<impact.output_example>
```

**代码证据**
<evidence[] 每个以代码块展示>

**修复建议**
<remediation>

---

## N+1. 审计总结
- 风险总览（severity 分布）
- 修复优先级
```

## 重要原则

1. 按攻击路径组织报告，不是按组件枚举
2. 每条路径必须展示 payload 和 output_example
3. 代码证据原样展示，不可改写
