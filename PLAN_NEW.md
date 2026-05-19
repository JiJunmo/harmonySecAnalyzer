# PLAN_NEW.md — 鸿蒙安全审计 Agent v2 升级方案

## 一、背景与目标

v1 已经验证了核心流程的可行性（`project-parser → parallel-audit → aggregate → report`），但在实际运行中暴露了三个共性问题和一个架构优化点：

| 问题 | 影响 |
|------|------|
| 审计对象多时分析不全 | 单 Task 处理 N 个实例，后面几个被截断/跳过 |
| 分析报告机制不统一 | IPC 有 `call_chain_analysis.json`，WebView 有 `webview_analysis_report.json`，但只有 IPC 的被打通到聚合器和报告生成器 |
| 报告详细但过长 | 所有实例全层展开，几十个 ExtensionAbility 时报告不可读 |
| 架构优化 | JSON5 解析、跨平台 python 命令、输出目录隔离 |

**目标**：将上述问题的解决方案统一纳入，升级到 v2。

---

## 二、架构总览（不变部分）

```
┌─────────┐    ┌──────────────┐    ┌──────────┐    ┌──────────┐
│ Phase 1 │ →  │   Phase 2    │ →  │ Phase 3  │ →  │ Phase 4  │
│项目发现  │    │ 并行审计      │    │ 聚合去重  │    │ 报告生成  │
└─────────┘    └──────────────┘    └──────────┘    └──────────┘
                  ↓
           每个 skill = 配置级脚本 + AI 深度分析
```

---

## 三、v2 核心改动

### 3.1 审计调度：从"按 Skill"到"按实例"

**v1 模式（单 Task 处理全部）：**

```
Phase 2:
  for skill in [ipc, webview, ...]:
      Task("分析此项目的全部 IPC 服务 / 全部 WebView 实例")  ← 一次 Task
```

问题：当 IPC 有 10 个服务或 WebView 有 5 个页面时，AI 在单次会话中分析 2-3 个后即认为"已完成"，后面全部跳过。

**v2 模式（按实例拆分，多 Task 并行）：**

```
Phase 2:
  for skill in dispatch_list:
      # 2a. 脚本列出所有实例（含 Layer 1 预填）
      instances = run("{skill}-auditor.py --list-instances")

      # 2b. 每个实例并行派发一个 Task
      for inst in instances:
          Task(
              subagent_type="general",
              task_id=f"{skill}-{inst.id}",
              prompt=f"仅分析这一个实例 {inst.name}，骨架已由脚本生成，补充 Layer 2-N"
          )

      # 2c. 校验 + 合并
      verify len(磁盘上的 analysis 分片) == len(instances)
      merge("{skill}-analysis-*.json") → {skill}-analysis.json
```

**实例定义：**

| Skill | 实例 | 发现方式 |
|-------|------|---------|
| IPC | 一个 `ExtensionAbility`（type=service, exported, 有 srcEntry） | metadata.modules |
| WebView | 一个 WebView 组件使用点（`Web({...})` 属性配置块） | 扫描 .ets 源文件 |
| 未来 skill | 由各自的 `--list-instances` 定义 | — |

每个实例独立分析，互不干扰，N 个实例就有 N 个 Task，不存在"分析不完"的问题。

---

### 3.2 分析报告：从写死到自动发现

**v1**：聚合器和报告生成器硬编码读取 `call_chain_analysis.json`，WebView 的 `webview_analysis_report.json` 被忽略。

**v2**：所有 skill 遵循统一命名约定：

```
{skill}-analysis.json           # 合并后的完整分析（供报告生成器使用）
{skill}-analysis-{instance_id}.json   # 每个实例的分片（Task 独立输出）
{skill}-instances.json          # 实例列表（供计数校验）
{skill}-findings.json           # 标准发现列表（已有）
```

聚合器自动扫描 `*-analysis.json`，按 skill 名索引到 `analysis_reports` 字典：

```json
{
  "analysis_reports": {
    "harmony-ipc-security-audit": {
      "total": 3,
      "analyzed": 3,
      "call_chains": [...]
    },
    "harmony-webview-audit": {
      "total": 5,
      "analyzed": 5,
      "webview_instances": [...]
    }
  },
  "warnings": [
    "harmony-ipc-security-audit: 共 3 个服务，分析了 2 个，缺少 DataService"
  ]
}
```

报告生成器遍历 `analysis_reports` 字典即可动态生成章节，新增 skill 无需改动聚合器和报告生成器。

---

### 3.3 计数量校验（防止漏分析）

聚合器在合并时做一致性校验：

```
expected = len(instances.json 中列出的实例)
actual   = len(analysis.json 中实际分析的实例)

expected == actual  → 通过
expected >  actual  → 输出 warning：缺少 {missing_instances}
expected <  actual  → 输出 warning：多余实例（可能是上一轮残留）
```

warning 会写入 `aggregated_data.json` 的 `warnings` 字段，在报告的审计总结中展示。

---

### 3.4 脚本预填 Layer 1（骨架生成）

脚本 `--list-instances` 模式不只是列名字，而是**预先生成每个实例的 Layer 1 分析**。这些数据直接从配置文件提取，无需 AI 参与：

**IPC 脚本预填 Layer 1：** 从 `module.json5` 的 `extensionAbilities[]` 中提取 exported、permissions、visible、srcEntry、type，写出结构化分析。

**WebView 脚本预填 Layer 1：** 从 `.ets` 源文件中提取 `javaScriptAccess`、`fileAccess`、`mixedMode`、`domStorageAccess`、`registerJavaScriptProxy` 调用及参数，写出结构化分析。

AI Task 拿到骨架后只需补充 Layer 2-N，大幅减少需要阅读的代码量和消耗的 token。

---

### 3.5 报告渲染：按严重度分级展开

**问题**：所有实例全层展开，报告过长，关键发现被淹没。

**方案**：分析完整性不牺牲，报告可见度做分级：

| 实例最高 severity | 报告处理 |
|------------------|---------|
| Critical / High | **完整展开**：所有 layer + code_references + 完整漏洞诊断 |
| Medium | **表格摘要**：每层一行 + 漏洞名（不展开 code_references） |
| Low / Info | **不渲染**：仅在总览统计表中出现 |
| 无发现 | **不渲染**：统计表中标记为 "✅ 无问题" |

**报告正文之外**，生成一个附加文件 `audit-report-appendix.md`，包含**全部实例的全部层的完整分析**，不做任何裁剪。正文短小精炼，想看全貌的人去看附录。

---

### 3.6 报告结构（v2）

```
# 1. 项目总览

# 2. IPC 跨进程通信安全审计
## 2.1 总览统计
| 服务名 | 模块 | 导出 | 权限 | 发现 | 最高 |
|--------|------|------|------|------|------|
| IpcService | entry | ✅ | 无 | 3 | Critical |
| DataService | entry | ✅ | 有 | 1 | Medium |
| LogService | entry | ❌ | — | 0 | ✅ |

## 2.2 详细分析（Critical/High）
### IpcService (chain-001) [🔴 Critical]
#### Layer 1: 服务注册层 ...
#### Layer 3: 服务请求处理层 ...

## 2.3 摘要（Medium）
| 服务名 | 层级 | 问题 |
|--------|------|------|
| DataService | 2-服务连接层 | onConnect 未校验身份 |

# 3. WebView 安全审计
## 3.1 总览统计
## 3.2 详细分析
## 3.3 摘要

# 4. 审计总结
  风险总览 + 规则命中 + CWE/OWASP 覆盖 + 修复优先级 + 校验 warnings

# 附录 A: 完整审计分析 → audit-report-appendix.md
```

---

### 3.7 输出目录结构（v2）

```
harmony_audit_results/
└── <YYYYMMDD_HHMMSS>/
    ├── metadata.json                              # Phase 1: 项目元数据
    ├── harmony-project-parser-findings.json
    │
    ├── harmony-ipc-security-audit-instances.json   # Phase 2a: 实例列表+骨架
    ├── harmony-ipc-security-audit-analysis-001.json # Phase 2b: 每实例分片
    ├── harmony-ipc-security-audit-analysis.json    # Phase 2c: 合并后
    ├── harmony-ipc-security-audit-findings.json
    │
    ├── harmony-webview-audit-instances.json
    ├── harmony-webview-audit-analysis-001.json
    ├── harmony-webview-audit-analysis.json
    ├── harmony-webview-audit-findings.json
    │
    ├── aggregated_data.json                       # Phase 3
    ├── audit-report.md                            # Phase 4
    ├── audit-report.json
    └── audit-report-appendix.md                   # 完整分析附录
```

---

### 3.8 跨平台兼容

- **python 命令**：`agent.md` 的 bash 块中，Phase 1 使用 `$(command -v python3 || echo python)` 自动适配 Windows/Linux/macOS
- **JSON5 解析**：`json5_parser.py` 已用 `json5` 标准库替代正则+`json.loads()`，原生支持单引号、无引号键名、注释、十六进制数字等

---

## 四、改动文件清单

### 核心流程

| 文件 | 当前状态 | v2 改动 |
|------|---------|--------|
| `agent.md` | 单 Task 处理全 skill | Phase 2 改为 `--list-instances` + 按实例派发 Task + 合并校验 |
| `agent.md` | IPC 写死 `call_chain_analysis.json` | 输出目录约定改为 `{skill}-analysis.json` 通用命名 |
| `agent.md` | 报告生成器结构写死 IPC 章节 | 改为遍历 `analysis_reports` + "分级渲染"规则 |

### 脚本

| 文件 | 当前状态 | v2 改动 |
|------|---------|--------|
| `ipc_auditor.py` | 仅 `-o findings.json` | 新增 `--list-instances` 参数，输出实例 JSON + Layer 1 骨架 |
| `webview_auditor.py` | 仅 `-o findings.json` | 新增 `--list-instances` 参数，输出实例 JSON + Layer 1 骨架 |

### 聚合器

| 文件 | 当前状态 | v2 改动 |
|------|---------|--------|
| `report_aggregator.py` | `call_chain_analysis` 写死字段 | 改为 `analysis_reports` 字典，自动发现 `*-analysis.json`；新增计数校验逻辑；输出 `warnings` |

### 报告生成器

| 文件 | 当前状态 | v2 改动 |
|------|---------|--------|
| `report-generator SKILL.md` | 第2章写死 IPC 调用链 | 遍历 `analysis_reports` 字典动态生成章节；按 severity 分级渲染；输出 `audit-report-appendix.md` |

### Skill 定义

| 文件 | 当前状态 | v2 改动 |
|------|---------|--------|
| `harmony-webview-audit SKILL.md` | 分析报告输出 `webview_analysis_report.json` | 改为每个实例输出 `harmony-webview-audit-analysis-{id}.json`，Step 1 脚本改为 `--list-instances` |
| `harmony-ipc-security-audit SKILL.md` | 分析报告输出 `call_chain_analysis.json` | 改为每个实例输出 `harmony-ipc-security-audit-analysis-{id}.json`，Step 1 脚本改为 `--list-instances` |

### 已完成的底层优化（v1 已实施）

| 文件 | 改动 | 状态 |
|------|------|------|
| `json5_parser.py` | 正则+hack → `json5` 标准库 | ✅ 已完成 |
| `project_scanner.py` | modules 输出增加 `module_path` 字段 | ✅ 已完成 |
| 4 个 Python 脚本 docstring | `python3` → `python` | ✅ 已完成 |
| `agent.md` 输出目录约定 | `/tmp/...` → `harmony_audit_results/<timestamp>/` | ✅ 已完成 |

---

## 五、实施优先级

| 优先级 | 改动 | 理由 |
|--------|------|------|
| P0 | `agent.md` Phase 2 调度改为按实例派发 Task | 解决分析不全的核心问题 |
| P0 | 脚本新增 `--list-instances` (IPC + WebView) | 调度改动的依赖 |
| P0 | 聚合器 `analysis_reports` 字典 + 计数校验 | 打通 webview 分析 + 防止漏分析 |
| P1 | 报告生成器分级渲染 + 动态章节 | 解决报告过长问题 |
| P1 | 报告附录 `audit-report-appendix.md` | 完整分析可追溯 |
| P2 | WebView SKILL.md 分析命名与流程对齐 | 使 webview 与 IPC 流程完全一致 |

---

## 六、与 v1 的对比

| 维度 | v1 | v2 |
|------|-----|-----|
| 调度粒度 | 一个 skill 一个 Task | 一个实例一个 Task |
| 分析覆盖率 | IPC 10 个服务可能只分析 3 个 | 10 个服务就一定 10 个 Task |
| 分析报告 | IPC 写死，WebView 断开 | 所有 skill 统一 `{skill}-analysis.json` |
| 报告长度 | 全展开，50 页+ | 分级渲染，正文 ~15 页 + 附录 |
| 漏分析检测 | 无 | 聚合时计数校验 |
| JSON5 解析 | 正则 hack，4 种失败场景 | json5 库，0 失败 |
| 跨平台 | 仅支持 python3 | python3 || python 自动适配 |
