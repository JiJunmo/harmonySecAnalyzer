---
name: harmony-ipc-security-audit
description: 审计鸿蒙IPC跨进程通信安全，逐层分析每个IPC调用链，输出完整调用链分析与结构化漏洞发现
---

# harmony-ipc-security-audit

HarmonyOS IPC 跨进程通信安全审计 Skill。**以 AI 代码理解为主**，逐层梳理每个 IPC 服务的完整通信链路，输出结构化调用链分析 + 逐漏洞详细诊断。

## 触发条件

Agent 读取 metadata 后，若以下任一条件为 true 则调度本 Skill：
- `security_surface.has_ipc_service` → true
- `security_surface.has_service_extension` → true
- `files.capabilities.uses_ipc` → true

## 前置输入

| 数据 | 来源 |
|------|------|
| metadata JSON | Phase 1 输出的 `<audit_dir>/harmony-project-parser-findings.json` |
| 项目根路径 | Agent 传递的 project_path |
| 规则知识库 | `skills/harmony-ipc-security-audit/rules/*.json` |
| IPC 领域知识 | `skills/harmony-ipc-security-audit/IPC_REFERENCE.md` |

## 输出产物

| 文件 | 内容 | 用途 |
|------|------|------|
| `harmony-ipc-security-audit-instances.json` | 所有 IPC 服务实例列表 + Layer 1 骨架 | 供 agent.md 按实例派发 Task |
| `harmony-ipc-security-audit-analysis-{id}.json` | 单个 IPC 服务的完整调用链分析分片 | 最终由聚合器合并 |
| `harmony-ipc-security-audit-analysis.json` | 合并后的完整调用链分析 | 供报告生成器使用 |
| `harmony-ipc-security-audit-findings.json` | 按 severity 排序的标准格式发现列表 | 供报告生成器使用 |

> **注意**：每个服务实例的分析是独立的 Task。脚本 `--list-instances` 预填 Layer 1 骨架，AI Task 补充 Layer 2-7 并写分片文件。Phase 3 聚合器负责合并和计数校验。

---

## Step 1: 脚本预处理（agent.md 在派发 Task 前执行）

Agent 在派发 AI Task 之前，先运行脚本获取实例列表：

```bash
python3 <skill_dir>/scripts/ipc_auditor.py --list-instances <metadata_path> <project_path> -o <audit_dir>/harmony-ipc-security-audit-instances.json --pretty
```

脚本输出每个 IPC 服务实例的 `instance_id`、`name`、`module`、`exported`、`src_entry`，以及预填的 Layer 1 骨架（服务注册层分析，直接从 module.json5 提取，无需 AI 参与）。

---

## Step 2: 分析单个实例（AI Task 核心步骤）

**重要：每次 Task 调用只分析一个 IPC 服务实例，不要尝试在一个 Task 中分析所有服务。**

Agent 会传入该实例的骨架 JSON。你的任务是：围绕这一个服务，按 7 层链路阅读源码，补充 Layer 2-7，并对照规则逐条筛查。
   - `files.ets_sources` — 所有 ArkTS 源文件列表（供定位用）
   - `security_surface.*` — 攻击面总览

2. **读取全部规则**，加载 `rules/critical.json`, `rules/high.json`, `rules/medium.json`, `rules/low.json`，将所有规则汇总为检查清单：
   ```
   规则 ID | 严重度 | 标题 | 检测类型
   ```

3. **读取 IPC_REFERENCE.md**，理解鸿蒙 IPC 的标准通信模式和安全基线。

---

## Step 2: 理解代码并输出单实例调用链分析

**重要：仅分析 Agent 传给你的这一个 IPC 服务实例，不要尝试分析其他服务。**

Agent 会传入该实例的骨架 JSON（其中 Layer 1 已由脚本预填，含 instance_id 和 overview）。你的任务是围绕这一个服务，按以下 7 层逐层阅读源码，补充 Layer 2-7，写出结构化分析。

### 输入

Agent 传入的实例骨架：
```json
{
  "instance_id": "ipc-001",
  "name": "IpcServiceExtAbility",
  "module": "entry",
  "exported": true,
  "src_entry": "./ets/serviceextability/ServiceExtAbility.ets",
  "skeleton": {
    "id": "chain-001",
    "service_name": "IpcServiceExtAbility",
    "module": "entry",
    "layers": [
      {
        "layer": "1-服务注册层",  ← 已预填
        "_source": "script"
      }
    ]
  }
}
```

### 2.1 服务注册层

- 读取 `module.json5` 中该 extensionAbility 的完整配置
- 分析 exported 值（true/false）、permissions 列表、srcEntry 路径
- 写出这段配置的含义和潜在暴露面

### 2.2 服务连接层

- 读取 srcEntry 指向的 ServiceExtensionAbility 实现文件
- 阅读 `onConnect(want)` 方法完整实现
- 分析：
  - want 参数是否被校验（想 bundleName / parameters 有无检查）
  - 返回了什么 Stub/RemoteObject
  - 是否存在 onDisconnect / onDestroy 的回调及清理逻辑

### 2.3 服务请求处理层

- 从 onConnect 的返回值追踪到 Stub/RemoteObject 实现文件
- 阅读 `onRemoteMessageRequest(code, data, reply, option)` 方法
- 按以下子层分析：
  1. **认证入口**：是否调用 getCallingUid() / getCallingPid()？返回值如何被使用？
  2. **Token 校验**：readInterfaceToken() 之后是否还有其他认证？
  3. **操作码分发**：switch(code) 的每个 case 做什么？default 分支是否有副作用？
  4. **数据读取**：readParcelable / readArrayBuffer / readString 之后做了什么校验？
  5. **数据使用**：读取的数据流向哪里（存变量/传 UI/写日志/网络请求）？
  6. **返回值**：每个路径的 return true/false 逻辑是什么？

### 2.4 服务数据层

- 读取自定义 Parcelable 实现
- 分析 marshalling() 和 unmarshalling() 的读写顺序是否一致
- unmarshalling 中对 readInt / readString 返回值有无校验

### 2.5 客户端连接层

- 搜索 `connectServiceExtensionAbility` 调用
- 分析 ConnectOptions 三个回调（onConnect / onDisconnect / onFailed）
- 连接有无超时机制、重试逻辑

### 2.6 客户端发送层

- 搜索 `sendMessageRequest` 调用
- 分析 MessageSequence 构造过程、数据加密情况
- 分析 reply 处理逻辑

### 2.7 客户端断连层

- 搜索 `disconnectServiceExtensionAbility` 调用
- 分析 proxy 引用清理、connectId 清理

### 2.8 输出分析分片

将这一个实例的完整调用链分析写入分片文件：

**保存路径**：`<audit_dir>/harmony-ipc-security-audit-analysis-{instance_id}.json`。**必须使用 Write 工具写入磁盘。**

> 分片文件由 Phase 3 聚合器自动合并为 `harmony-ipc-security-audit-analysis.json`。

---

## Step 3: 对照规则逐条筛查并生成详细诊断

读完代码并完成调用链分析后，从规则库逐条筛查。**每条匹配的规则都必须生成完整的诊断信息**。

### 3.1 筛查方法

对每条规则：

1. **config_pattern 类型**：直接在 metadata 中检查 extensionAbilities 配置字段
2. **code_pattern 类型**：回溯 Step 2 的调用链分析，确认 positive_patterns 是否存在、negative_patterns 是否缺失
3. **结合上下文判断 severity**：规则定义的 severity 是默认值，AI 需结合实际代码场景判定最终 severity

### 3.2 每个匹配发现的诊断要求

每条发现（finding）必须包含以下**全部字段**：

| 字段 | 要求 | 说明 |
|------|------|------|
| `id` | 规则 ID + 序号 | 如 `IPC-003-001` |
| `severity` | AI 判定 | 可不同于规则默认值 |
| `title` | 规则标题 | 可结合项目改写 |
| `description` | **针对该项目的具体描述** | 而非模板文字 |
| `call_chain_id` | 关联的调用链 ID | 指向 harmony-ipc-security-audit-analysis.json |
| `layer` | 关联的调用链层级 | 如 "3-服务请求处理层" |
| `root_cause` | **根本原因分析** | 解释为什么会存在此漏洞 |
| `attack_scenario` | **攻击场景** | 攻击者如何利用此漏洞的逐步描述 |
| `impact` | **影响评估** | 成功利用后对业务/安全的影响 |
| `evidence` | **关键证据数组** | 多个代码片段，每个含 file/line_range/snippet/description |
| `cwe` | CWE 编号 | 从规则继承 |
| `owasp` | OWASP 编号 | 从规则继承 |
| `remediation` | 可操作的修复建议 | 含具体代码示例 |
| `reference` | 参考文档链接 | 从规则继承 |

### 3.3 判断原则

1. **不确定时标注低一级 severity** — 宁可漏报 Low 也不虚报 Critical
2. **发现描述必须具体** — 写 "default 分支执行了 hilog.info" 而非 "default 分支有副作用"
3. **attack_scenario 必须可行** — 描述真实可达的攻击路径
4. **遇到不理解代码时标注 "需人工审查"** — 不硬套规则

---

## Step 4: 输出文件

### 4.1 诊断分行写入

将本实例的完整诊断追加到 findings 中（Phase 3 聚合器自动合并）。

### 4.2 harmony-ipc-security-audit-findings.json — 标准格式

调用 **Write 工具**写入 `<audit_dir>/harmony-ipc-security-audit-findings.json`。

> **Step 2 分析分片和 Step 4 findings 文件都必须使用 Write 工具写入磁盘，不可仅在对话中展示。**

---

## 重要原则

1. **AI 必须亲自读源文件**，不能依赖脚本做字符串匹配
2. **调用链分析是思考过程** — 每层至少写 2-3 句实质性分析
3. **诊断信息必须完整** — root_cause / attack_scenario / impact 缺一不可
4. **代码证据精确** — 文件路径、行号、代码原文三者必须一致
5. **severity 由 AI 根据上下文判定** — 规则标注的 severity 是默认值
6. **不确定时降级处理** — 宁可漏报 Low 也不虚报 Critical
7. **所有文件保存到 `<audit_dir>/`** — Agent 会在 Phase 2 创建此目录
