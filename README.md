# harmonySecAnalyzer (鸿蒙应用安全审计 Agent 引擎)

`harmonySecAnalyzer` 是一个面向鸿蒙系统（OpenHarmony / HarmonyOS）应用程序的安全审计与攻击路径分析引擎。该项目通过**“AI 推理智能分析”**与**“静态代码关系校验”**相结合的双轨级联设计，自动从外部输入入口追踪数据流向，检测并验证可达的完整攻击路径（Attack Paths）。

---

## 🛠️ 核心架构与模块设计

本项目采用**混合智能双轨安全审计架构 (Hybrid Smart-Penetration Dual-Track Architecture)**，将审计流程划分为以下阶段：

```
Phase 1: 发现 (harmony-project-parser) ➔ 扫描入口与攻击终点，生成基础连通性关系图
  │
Phase 1.5: 预分析 (gitnexus_hints.py) ➔ 利用 GitNexus Cypher 检测代码物理数据流，标记置信度
  │
Phase 2: 验证 (双轨并行与级联调度)
  ├── 轨道一 (Track 1): IPC 垂直自闭环审计 (onConnect ➔ switch-case 业务分支深度挖掘)
  └── 轨道二 (Track 2): UIAbility 边界防卫与 WebView 级联审计
        ├── Stage 1: UIAbility 护卫与参数跨文件/跨页面状态流追踪
        └── Stage 2 (按需触发): WebView 专项深度审计 (基于 Stage 1 输出的 Warm-Start 级联上下文)
  │
Phase 3: 报告生成 (harmony-report-generator) ➔ 聚合各阶段生成的漏洞分片并生成结构化报告
```

### 1. 发现阶段 (Phase 1: Discovery)
*   **实现模块**：`skills_v2/harmony-project-parser/`
*   **功能**：静态解析配置文件（`module.json5`、`config.json`）及源码文件，提取所有暴露的外部入口（Entry，如导出的 UIAbility、IPC 服务、DeepLink 等）和高危操作终点（Sink，如 WebView 加载、文件写入、敏感 API 调用等）。
*   **产出物**：
    *   `<audit_dir>/entries.json`（外部可控入口）
    *   `<audit_dir>/sinks.json`（攻击终点）
    *   `<audit_dir>/attack_map.json`（基于邻近度的潜在连通对）

### 2. 数据流预分析阶段 (Phase 1.5: Pre-Analysis)
*   **实现模块**：`skills_v2/harmony-project-parser/scripts/gitnexus_hints.py`
*   **功能**：在项目被 GitNexus 索引后，通过 Cypher 执行图查询，提取 `ACCESSES`（属性写入）和 `CALLS`（方法/函数调用）关系，分析入口到终点的数据流走向。
*   **产出物**：为 `attack_map.json` 中的每条路径注入 `data_flow_hint` 属性，标记数据流调用链并标注 `verified=true/false`。

### 3. 验证阶段 (Phase 2: Verification)
由 AI 编排器（`agent_v2.md`）调度不同的审计 Skill 进行并行或级联分析：
*   **轨道一：IPC 服务自闭环审计 (`skills_v2/harmony-ipc-security-audit`)**
    *   对 IPC 服务进行垂直深度研判，分析连接校验（`onConnect`）和消息分发（`onRemoteMessageRequest`）的各个业务分支安全缺陷。
*   **轨道二：UIAbility 与 WebView 级联审计**
    *   **阶段 1 (`skills_v2/harmony-ability-security-audit`)**：审计 Ability 入口前置包名校验及重入一致性问题，并借助 GitNexus 追踪 `want.parameters` 经由 ArkTS 状态管理（`AppStorage`、`LocalStorage`）和路由（`router.pushUrl`）跨文件的传递路径。若受污参数流入 WebView，则生成 **Warm-Start Context JSON**。
    *   **阶段 2 (`skills_v2/harmony-webview-audit`)**：若无 Warm-Start JSON 则自动剪枝跳过。若存在，AI 将聚焦分析 Web 组件关联的 JS Bridge（Native 越权方法）及拦截器（弱域名过滤漏洞），并缝合端到端利用链。

### 4. 报告生成阶段 (Phase 3: Reporting)
*   **实现模块**：`skills_v2/harmony-report-generator/`
*   **功能**：对各阶段生成的多份攻击路径 JSON 碎片进行内容完整性、格式规范性校验。按照预定义渲染公式合成 Markdown 报告，自动进行风险评分，并输出漏洞修复建议。
*   **产出物**：
    *   `<audit_dir>/audit-report.md`（高可读性审计报告）
    *   `<audit_dir>/audit-report.json`（完整结构化数据）

---

## 📂 项目目录结构

```
├── README.md                              # 项目说明文档
├── AGENTS.md / CLAUDE.md                 # GitNexus 代码智能协作契约手册
├── agent_v2.md                           # 混合智能双轨编排管线核心说明
├── v2_weaknesses.md                      # 架构缺陷客观剖析与中长期演进蓝图
├── PLAN.md / PLAN_NEW.md                 # 历史设计规划备份
├── skills_v2/                            # 审计技能库 (Skills)
│   ├── harmony-project-parser/           # 项目扫描与连通性分析技能
│   │   └── scripts/
│   │       ├── project_scanner.py        # 静态资源与入口发现核心脚本
│   │       └── gitnexus_hints.py         # 自动执行的 Cypher 数据流预分析脚本
│   ├── harmony-ipc-security-audit/       # 轨道一：IPC 通信安全审计技能
│   ├── harmony-ability-security-audit/   # 轨道二：UIAbility 入口防卫与状态流向追踪技能
│   ├── harmony-webview-audit/            # 轨道二：WebView JS Bridge 与拦截器专项分析技能
│   └── harmony-report-generator/         # Phase 3：多源报告校验、缝合与聚合生成技能
│       └── scripts/
│           └── report_aggregator.py      # 报告数据处理与任务数漏审动态校验脚本
└── skills/                               # v1 遗留技能文件夹 (备份/参考)
```

---

## 🚀 审计运行工作流示范

当您需要针对一个全新的鸿蒙项目进行安全分析时，遵循以下执行步骤：

### 1. 扫描项目并提取入口与终点
运行项目解析扫描器，初始化审计目录并执行 Phase 1：
```bash
python skills_v2/harmony-project-parser/scripts/project_scanner.py <target_project_path> -o <audit_output_dir> --pretty
```

### 2. 建立 GitNexus 代码索引
进入目标项目源码目录，对代码库进行语义和关系索引（若环境受限，可跳过此步）：
```bash
cd <target_project_path>
npx gitnexus analyze --skip-git
```

### 3. 执行数据流预分析 (Phase 1.5)
如果第一步中没有包含 GitNexus，可再次手动执行 `gitnexus_hints.py`（通常由 `project_scanner.py` 内部自动调用）：
```bash
python skills_v2/harmony-project-parser/scripts/gitnexus_hints.py <target_project_path> <audit_output_dir> --pretty
```

### 4. 驱动 AI Agent 执行路径验证
根据 `agent_v2.md` 的编排流程：
1.  启动并批量分发 **轨道一 (IPC)** 和 **轨道二阶段 1 (Ability)** 审计任务。
2.  检查 `<audit_output_dir>/` 下是否生成了 `harmony-webview-warm-start-*.json` 级联上下文。
3.  如有，批量启动 **轨道二阶段 2 (WebView)** 审计任务。

### 5. 聚合数据并生成报告 (Phase 3)
收集所有验证节点生成的 `*-attack-paths*.json`，执行聚合：
```bash
python skills_v2/harmony-report-generator/scripts/report_aggregator.py <audit_output_dir> -o <audit_output_dir>/aggregated_data.json --pretty
```
最后驱动 AI 加载 `skills_v2/harmony-report-generator/SKILL.md`，执行格式精细渲染并最终输出 `audit-report.md`。
