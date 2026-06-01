# harmonySecAnalyzer (鸿蒙应用安全审计 Agent 引擎)

`harmonySecAnalyzer` 是一个面向鸿蒙系统（OpenHarmony / HarmonyOS）应用程序的安全审计与攻击路径分析引擎。该项目通过**“AI 推理智能分析”**与**“静态代码关系校验”**相结合的双轨级联设计，自动从外部输入入口追踪数据流向，检测并验证可达的完整攻击路径（Attack Paths）。

---

## 🛠️ 核心架构与模块设计

本项目采用**智能体驱动原生双轨安全审计架构 (Agent MCP-Driven Dual-Track Architecture)**，将审计流程划分为以下阶段：

```
Phase 1: 静态扫描与路径关系梳理 (Static Analysis & Path Mapping)
  ├── Step 1: 静态物理特征扫描 ➔ 提取物理入口 (entries.json) 与敏感操作终点 (sinks.json)
  ├── Step 2: GitNexus 关系建图与初始化 ➔ 显式在宿主目录建立依赖与调用链索引图
  └── Step 3: 双向拓扑碎片提取与语义搭桥 ➔ AI MCP 语义审查并缝合装配出 attack_map.json
  │
Phase 2: 漏洞深度验证 (Parallel Audit Verification)
  ├── 轨道一 (Track 1): IPC 垂直自闭环审计 (onConnect ➔ switch-case 业务分支深度挖掘)
  └── 轨道二 (Track 2): UIAbility 边界防卫与 WebView 级联审计
        ├── Stage 1: UIAbility 护卫与参数跨文件/跨页面状态流追踪
        └── Stage 2 (按需触发): WebView 专项深度审计 (基于 Stage 1 输出 of Warm-Start 级联上下文)
  │
Phase 3: 报告聚合与生成 (Unified Report Aggregation & Rendering) ➔ 聚合多源漏洞分片并生成结构化报告
```

### 1. 静态扫描与路径关系梳理阶段 (Phase 1: Static Analysis & Path Mapping)
该阶段深度结合物理特征匹配与 GitNexus 本地依赖图谱，提取并装配出潜在攻击路径网络。
*   **Step 1: 静态物理特征扫描**：运行 `project_scanner.py`，解析项目中的硬编码配置与文件引用，生成 `<audit_dir>/entries.json` 与 `<audit_dir>/sinks.json`。
*   **Step 2: GitNexus 关系建图与初始化**：由 Agent 自动在宿主目录中拉起 `npx gitnexus analyze --index-only`，在本地构建精准的依赖图与调用关系数据库。这一步解决了在未手动建图时调用链无法获取的致命问题。
*   **Step 3: 级联拓扑碎片提取与语义搭桥**：运行 `fragment_finder.py` 得到前向/反向路径碎片 `fragments.json`。由 AI 原生直连调用 MCP 工具在图上对碎片进行语义交联与可达性判定，消除误报，首尾缝合后写入 `<audit_dir>/attack_map.json`。

### 2. 漏洞深度验证阶段 (Phase 2: Verification)
由 AI 编排器（`agent_v2.md`）调度不同的审计 Skill 对 `attack_map.json` 中的各路径进行并行或级联分析：
*   **轨道一：IPC 服务自闭环审计 (`skills_v2/harmony-ipc-security-audit`)**
    *   对 IPC 服务进行垂直深度研判，分析连接校验（`onConnect`）和消息分发（`onRemoteMessageRequest`）的各个业务分支安全缺陷。
*   **轨道二：UIAbility 与 WebView 级联审计**
    *   **阶段 1 (`skills_v2/harmony-ability-security-audit`)**：审计 Ability 入口前置包名校验及重入一致性问题，并借助 GitNexus 追踪 `want.parameters` 经由 ArkTS 状态管理（`AppStorage`、`LocalStorage`）和路由（`router.pushUrl`）跨文件的传递路径。若受污参数流入 WebView，则生成 **Warm-Start Context JSON**。
    *   **阶段 2 (`skills_v2/harmony-webview-audit`)**：若无 Warm-Start JSON 则自动剪枝跳过。若存在，AI 将聚焦分析 Web 组件关联的 JS Bridge（Native 越权方法）及拦截器（弱域名过滤漏洞），并缝合端到端利用链。

### 3. 报告聚合与生成阶段 (Phase 3: Reporting)
*   **实现模块**：`skills_v2/harmony-report-generator/`
*   **功能**：对各阶段生成的多份攻击路径 JSON 碎片进行内容完整性、格式规范性校验。按照预定义渲染公式合成 Markdown 报告，自动进行风险评分，并输出漏洞修复建议。
*   **产出物**：
    *   `<audit_dir>/audit-report.md`（分级渲染的结构化审计报告）
    *   `<audit_dir>/audit-report.json`（完整结构化数据）
    *   `<audit_dir>/audit-report-appendix.md`（完整分析附录）

---

## 📂 项目目录结构

```
├── README.md                              # 项目说明文档
├── AGENTS.md / CLAUDE.md                 # GitNexus 代码智能协作契约手册
├── agent_v2.md                           # 智能体原生双轨编排管线核心说明
├── v2_weaknesses.md                      # 架构缺陷客观剖析与中长期演进蓝图
├── PLAN.md / PLAN_NEW.md                 # 历史设计规划备份
├── skills_v2/                            # 审计技能库 (Skills)
│   ├── harmony-project-parser/           # 项目扫描与特征发现技能 (Phase 1)
│   │   └── scripts/
│   │       └── project_scanner.py        # 静态资源与入口/Sink 发现核心脚本
│   ├── harmony-ipc-security-audit/       # 轨道一：IPC 通信安全审计技能 (Phase 2)
│   ├── harmony-ability-security-audit/   # 轨道二：UIAbility 入口防卫与状态流向追踪技能 (Phase 2)
│   ├── harmony-webview-audit/            # 轨道二：WebView JS Bridge 与拦截器专项分析技能 (Phase 2)
│   └── harmony-report-generator/         # Phase 3：多源报告校验、缝合与聚合生成技能
│       └── scripts/
│           └── report_aggregator.py      # 报告数据聚合、Deduplication 与多路径归并脚本
└── skills/                               # v1 遗留技能文件夹 (备份/参考)
```

---

## 🚀 审计运行工作流示范

当您需要针对一个全新的鸿蒙项目进行安全分析时，遵循以下执行步骤：

### 1. 扫描项目与路径关系梳理 (Phase 1)
这是整个审计工作流的第一阶段，包括静态扫描、依赖图谱初始化以及双向碎片缝合：

* **Step 1: 扫描物理入口与物理终点**
  运行项目解析扫描器，初始化审计目录并执行物理扫描：
  ```bash
  python skills_v2/harmony-project-parser/scripts/project_scanner.py <target_project_path> -o <audit_output_dir> --pretty
  ```

* **Step 2: 建立 GitNexus 代码索引**
  进入目标项目源码目录，对代码库进行语义和关系索引：
  ```bash
  cd <target_project_path>
  npx gitnexus analyze --skip-git
  ```

* **Step 3: 提取路径碎片与语义搭桥**
  运行碎片提取脚本并结合 AI MCP 自动进行图分析桥接，生成最终攻击映射图 `attack_map.json`：
  ```bash
  python skills_v2/harmony-project-parser/scripts/fragment_finder.py <target_project_path> -o <audit_output_dir>
  ```

### 2. 驱动 AI Agent 执行路径验证 (Phase 2)
根据 `agent_v2.md` 的编排流程：
1. 启动并批量分发 **轨道一 (IPC)** 和 **轨道二阶段 1 (Ability)** 审计任务。
2. 检查 `<audit_output_dir>/` 下是否生成了 `harmony-webview-warm-start-*.json` 级联上下文。
3. 如有，批量启动 **轨道二阶段 2 (WebView)** 审计任务。

### 3. 聚合数据并生成报告 (Phase 3)
收集所有验证节点生成的 `*-attack-paths*.json`，执行聚合：
```bash
python skills_v2/harmony-report-generator/scripts/report_aggregator.py <audit_output_dir> -o <audit_output_dir>/aggregated_data.json --pretty
```
最后驱动 AI 加载 `skills_v2/harmony-report-generator/SKILL.md`，执行格式精细渲染并最终输出 `audit-report.md`。
