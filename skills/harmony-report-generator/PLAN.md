# harmony-report-generator 实现方案

## 一、设计思路

报告生成器的核心原则：**对 skill 完全透明，对输出格式完全控制**。

```
任一 skill 输出 findings.json  →  report-generator 自动发现  →  合并去重  →  报告输出
```

不需要为新增 skill 修改报告生成器，只要 findings.json 遵循统一 Schema。

---

## 二、输入和输出

### 输入：审计工作目录

```
/tmp/harmony_audit_<timestamp>/
├── harmony-project-parser-findings.json   (metadata.json)
├── harmony-ipc-security-audit-findings.json
├── harmony-permission-audit-findings.json  (未来的 skill)
└── ...
```

### 输出

| 文件 | 格式 | 用途 |
|------|------|------|
| `audit-report.md` | Markdown | 人阅读的完整审计报告 |
| `audit-report.json` | JSON | 机器可读，含原始 findings |
| `audit-summary.txt` | 纯文本 | 一行摘要，适合 CI/CD 输出 |

---

## 三、报告结构

```
# 鸿蒙应用安全审计报告

## 1. 执行摘要
  - 审计时间、项目名称、目标 SDK
  - 风险评分 (0-100)
  - 发现总数统计表
  - 安全态势一句话评估

## 2. 项目概览
  - 从 metadata.json 提取：模块数、SDK版本、权限数、导出组件数
  - 攻击面速览

## 3. 发现详情（按 Critical → Info 排序）
  每条发现：
  - 标题 [ID] | 严重度标签 | CWE/OWASP
  - 位置 file:line + 代码片段
  - 描述（具体项目上下文）
  - 修复建议
  - 来源 skill

## 4. 合规对标
  - OWASP Mobile Top 10 覆盖热力图
  - 覆盖的 CWE 列表
  - 各 skill 发现统计

## 5. 附录
  - 审计范围：哪些 skill 已执行，哪些未实现
  - 规则覆盖统计
  - 报告生成时间戳
```

---

## 四、执行流程

### 方案选择：脚本做机械聚合 + AI 做报告润色

```
Phase A: 脚本机械聚合 → Phase B: AI 润色输出
```

**为什么不用纯 AI 生成报告**：计数、排序、去重、格式化是机械重复劳动，用脚本更稳定高效。

### Phase A: 聚合脚本 (`report_aggregator.py`)

职责（纯机械，无判断）：

1. 扫描审计目录，发现所有 `*-findings.json`
2. 合并所有 findings，按 (title, file, line) 去重
3. 计算统计量：按 severity、按 skill、按 CWE 分组计数
4. 从 metadata.json 提取项目概览数据
5. 输出 `aggregated_data.json`（供 AI 润色用）

**为什么不出最终 report.md**：格式美化、上下文关联、风险评语这些需要 AI 判断，脚本做不了。

### Phase B: AI 润色 (SKILL.md 指令)

AI 读取 `aggregated_data.json`，按报告模板输出：
1. 根据 findings 数量和严重度分布，写安全态势一句话评估
2. 对 Critical/High 发现写一段风险总结
3. 对 OWASP 覆盖情况做简要解读
4. 检查是否有未实现的 skill，在附录中列出

---

## 五、聚合脚本详细设计

### `report_aggregator.py`

```
用法: python3 report_aggregator.py <audit_dir> -o aggregated_data.json

输入: /tmp/harmony_audit_<timestamp>/
输出: /tmp/harmony_audit_<timestamp>/aggregated_data.json
```

### 输出结构

```json
{
  "project": {
    "name": "myapp",
    "package": "com.example.myapp",
    "sdk_version": "5.0.0(12)",
    "api_level": 12
  },
  "audit": {
    "start_time": "2026-05-12T...",
    "end_time": "2026-05-12T...",
    "skills_executed": ["harmony-project-parser", "harmony-ipc-security-audit"],
    "skills_pending": ["harmony-permission-audit", "harmony-component-audit", ...]
  },
  "findings": {
    "total": 18,
    "by_severity": {
      "critical": 3,
      "high": 5,
      "medium": 3,
      "low": 5,
      "info": 2
    },
    "by_skill": {
      "harmony-ipc-security-audit": 15,
      "harmony-project-parser": 3
    },
    "by_cwe": {
      "CWE-862": 4,
      "CWE-502": 1,
      ...
    },
    "by_owasp": {
      "M1": 6,
      "M8": 4,
      ...
    },
    "items": [
      { "... 完整 finding 对象 ..." }
    ]
  },
  "risk_score": 65
}
```

### 风险评分算法

```
score = 0
for each finding:
    score += severity_weights[severity] * base_weight

severity_weights = {critical: 10, high: 5, medium: 2, low: 1, info: 0}
max_score = max_possible_score  (假设每个规则最多 1 个 critical)

risk_score = min(100, round(score / max_score * 100))
```

---

## 六、扩展性设计

### 新增 skill 时报告生成器不需要任何改动

```
新 skill 开发步骤:
  1. 创建 skills/harmony-xxx-audit/SKILL.md
  2. 运行后输出 harmony-xxx-audit-findings.json 到审计目录
  3. 完成。report_aggregator.py 自动发现并合并
```

聚合脚本通过 `glob("*-findings.json")` 自动发现所有 skill 输出，无需注册。

### Skill 列表的发现

对于附录中"哪些 skill 已实现/未实现"的判断，有两种方案：

**方案 A（推荐）**：聚合脚本遍历 `skills/` 目录，检查哪些有 SKILL.md，然后对比审计目录中有哪些 `*-findings.json`，确定执行了哪些。

**方案 B**：在 agent.md 中维护已实现的 skill 列表，聚合脚本通过参数传入。

**选择方案 A**，因为它是自动发现的，不依赖手动维护列表。

### skills_pending 的发现逻辑

```python
all_skills = [d for d in os.listdir("skills/") if d.startswith("harmony-") and os.path.isdir(...)]
executed = {f.stem.replace("-findings", "") for f in Path(audit_dir).glob("*-findings.json")}
pending = all_skills - executed - {"harmony-project-parser"}  # parser 不是 audit skill
```

---

## 七、模板设计原则

1. **Markdown 为主**：人阅读的报告使用 Markdown，支持 GitHub/GitLab 渲染
2. **JSON 为副**：机器可读的完整数据使用 JSON，保留所有原始 finding 对象
3. **Critical/High 优先展示**：报告前半部分突出高危发现，Medium/Low 折叠或放后面
4. **代码片段原样呈现**：每个 finding 的 location.snippet 是代码原文，帮助开发者定位
5. **每个 finding 标注来源 skill**：读者知道是哪个审计维度发现的

---

## 八、文件结构

```
skills/harmony-report-generator/
├── SKILL.md                        # 告诉 AI 如何读取聚合数据并生成报告
├── PLAN.md                         # 本文件
└── scripts/
    └── report_aggregator.py        # 聚合脚本（纯机械）
```

---

## 九、与 Agent 的协作

```
Agent Phase 3 (聚合)
  │
  ├─ 执行: python3 report_aggregator.py <audit_dir> -o <audit_dir>/aggregated_data.json
  │
  └─ Agent Phase 4 (报告)
       │
       ├─ 加载 harmony-report-generator/SKILL.md
       ├─ AI 读取 aggregated_data.json
       ├─ AI 按模板生成 audit-report.md + audit-report.json
       └─ 输出到审计目录和用户指定目录
```
