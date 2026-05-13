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

## 输出产物（三个文件）

| 文件 | 内容 | 用途 |
|------|------|------|
| `call_chain_analysis.json` | 每个 IPC 服务的完整调用链分析 | **报告中的思考过程** |
| `findings_raw.json` | 逐漏洞详细诊断（含成因、攻击场景、证据） | 供聚合器使用 |
| `harmony-ipc-security-audit-findings.json` | 按 severity 排序的标准格式发现列表 | 供报告生成器使用 |

---

## Step 1: 收集上下文

1. **读取 metadata.json**，提取：
   - `modules[*].extension_abilities` — 服务端注册的所有 extensionAbilities（含 exported, type, srcEntry, permissions, name）
   - `modules[*].request_permissions` — 各模块声明的权限
   - `files.ets_sources` — 所有 ArkTS 源文件列表（供定位用）
   - `security_surface.*` — 攻击面总览

2. **读取全部规则**，加载 `rules/critical.json`, `rules/high.json`, `rules/medium.json`, `rules/low.json`，将所有规则汇总为检查清单：
   ```
   规则 ID | 严重度 | 标题 | 检测类型
   ```

3. **读取 IPC_REFERENCE.md**，理解鸿蒙 IPC 的标准通信模式和安全基线。

---

## Step 2: 理解代码并输出调用链分析（核心步骤，输出思考过程）

**目标**：对每个检测到的 IPC 服务，按 7 层链路逐层阅读源码，写出结构化分析。**这是报告中展示的思考过程，必须详尽**。

### 2.0 识别所有 IPC 服务

从 metadata 的 `modules[*].extension_abilities` 中筛选出所有 IPC 相关服务（类型含 `service` 且有 `srcEntry`）。

对每个服务，按以下 7 层执行分析：

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

### 2.8 输出 call_chain_analysis.json

每读完一层，立即写出该层的结构化分析，**不要等到全部读完再写**。格式：

```json
{
  "_meta": {
    "auditor": "harmony-ipc-security-audit",
    "project_path": "<project_path>",
    "total_services": 2
  },
  "call_chains": [
    {
      "id": "chain-001",
      "service_name": "IPC_Service",
      "module": "entry",
      "extension_type": "service",
      "overview": "IPC_Service 是应用的主要 IPC 入口，导出给其他应用调用，负责处理客户端请求并返回数据",

      "layers": [
        {
          "layer": "1-服务注册层",
          "order": 1,
          "file": "entry/src/main/module.json5",
          "analysis": "extensionAbility 配置 exported: true 表示对外导出，但未设置 permissions 守卫，任何应用均可连接该服务。srcEntry 指向 ./ets/serviceextability/IPC_Service.ets",
          "code_references": [
            {
              "file": "entry/src/main/module.json5",
              "line_range": "45-55",
              "snippet": "{\n  \"name\": \"IPC_Service\",\n  \"srcEntry\": \"./ets/serviceextability/IPC_Service.ets\",\n  \"type\": \"service\",\n  \"exported\": true\n}",
              "description": "IPC_Service 的注册配置，exported: true 且无 permissions"
            }
          ],
          "issues_identified": ["缺少 permissions 权限守卫", "过度导出增加攻击面"]
        },
        {
          "layer": "2-服务连接层",
          "order": 2,
          "file": "entry/src/main/ets/serviceextability/IPC_Service.ets",
          "analysis": "onConnect(want) 直接返回 new StubServer('ipc_service_descriptor')，完全未校验 want.parameters 或 want.bundleName。攻击者可伪装成任意应用连接，直接获得 Stub 对象。同时缺少 onDisconnect 回调清理全局状态。",
          "code_references": [
            {
              "file": "entry/src/main/ets/serviceextability/IPC_Service.ets",
              "line_range": "20-30",
              "snippet": "onConnect(want: Want) {\n  hilog.info(DOMAIN, TAG, 'onConnect, want:' + JSON.stringify(want));\n  return new StubServer('ipc_service_descriptor');\n}",
              "description": "onConnect 未校验调用方身份，直接返回 Stub 实例"
            }
          ],
          "issues_identified": ["onConnect 未校验调用方身份", "缺少 onDisconnect 清理", "hilog.info 打印完整 want 参数泄露敏感信息"]
        }
      ]
    }
  ]
}
```

**关键要求**：
- 每层 `analysis` 必须包含 AI 对该层代码的**理解和判断**，而非简单描述
- `issues_identified` 列出该层发现的所有（潜在）问题，**不管规则是否覆盖**
- `code_references[*].snippet` 必须是代码原文，确保行号正确
- 如果某层不存在对应的代码实现（如项目没有自定义 Parcelable），将该层的 `analysis` 写为 "项目中未发现自定义 Parcelable"，issues_identified 为空

**保存路径**：`<audit_dir>/call_chain_analysis.json`。**必须使用 Write 工具写入磁盘。**

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
| `call_chain_id` | 关联的调用链 ID | 指向 call_chain_analysis.json |
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

### 4.1 findings_raw.json — 完整诊断

保存到 `<audit_dir>/findings_raw.json`，包含 Step 3 的完整诊断信息：

```json
{
  "_meta": {
    "auditor": "harmony-ipc-security-audit",
    "total_findings": 5,
    "severity_counts": { "critical": 2, "high": 2, "medium": 1, "low": 0, "info": 0 }
  },
  "findings": [
    {
      "id": "IPC-003-001",
      "rule_id": "IPC-003",
      "skill": "harmony-ipc-security-audit",
      "severity": "critical",
      "title": "onRemoteMessageRequest 未校验调用方身份",
      "description": "IPC_Service 的 StubServer.onRemoteMessageRequest 方法在处理敏感数据（读取 buffer 并写入全局 state）时，完全未调用 getCallingUid() 获取调用方身份。任何能连接到该 ServiceExtensionAbility 的应用均可发送任意请求，导致跨应用数据泄露。",
      "call_chain_id": "chain-001",
      "layer": "3-服务请求处理层",
      "root_cause": "开发者未意识到 IPC 服务导出后缺乏调用方身份校验的风险。Handler 方法虽调用了 getCallingUid() 但返回值未被使用。即使在 switch 前面获取 uid，后续分发到 handler 方法时 uid 信息丢失，未传递给实际的业务处理逻辑。",
      "attack_scenario": "1. 攻击者开发恶意应用，反编译目标应用获取 descriptor 字符串和 code 枚举值\n2. 在恶意应用中调用 connectServiceExtensionAbility 连接目标 Service\n3. 获取 rpc.RemoteObject 引用后，构造 MessageSequence 并调用 sendMessageRequest\n4. 传入任意 code 值，服务端无条件处理并返回数据\n5. 通过反复发送不同 code 值，批量获取服务端存储的敏感数据",
      "impact": "未授权访问导致服务端内部状态被任意应用读取。若 state 中存储了用户隐私数据（如账号、令牌、业务数据），攻击者可窃取所有已连接用户的数据。",
      "evidence": [
        {
          "file": "entry/src/main/ets/serviceextability/IPC_Service.ets",
          "line_range": "80-120",
          "snippet": "onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence, option: rpc.MessageOption): boolean {\n  let result: boolean = false;\n  let callerUid = this.getCallingUid(); // 获取了但未使用！\n  let token = data.readInterfaceToken();\n  \n  switch (code) {\n    case CODE_READ_DATA:\n      result = this.readAndProcessData(data, reply);\n      break;\n    default:\n      hilog.info(DOMAIN, TAG, 'unknown code: ' + code);\n      break;\n  }\n  return result;\n}",
          "description": "getCallingUid() 返回值被丢弃，未用于身份校验。code 无白名单限制。"
        }
      ],
      "cwe": "CWE-862",
      "owasp": "M1",
      "remediation": "在 onRemoteMessageRequest 入口处添加调用方校验：\nconst callerUid = this.getCallingUid();\nif (!this.isAuthorizedCaller(callerUid)) {\n  hilog.warn(DOMAIN, TAG, 'Unauthorized IPC call from uid: ' + callerUid);\n  return false;\n}\n\n同时维护允许的调用方 UID 白名单或通过 abilityAccessCtrl 校验权限。",
      "reference": "https://developer.huawei.com/consumer/cn/doc/harmonyos-references/js-apis-rpc"
    }
  ]
}
```

### 4.2 harmony-ipc-security-audit-findings.json — 标准格式（供聚合器使用）

调用 **Write 工具**写入 `<audit_dir>/harmony-ipc-security-audit-findings.json`。

此文件结构与 findings_raw.json 相同（直接写入同一份数据），聚合器从中读取 findings 数组。

> **Step 2 和 Step 4 产出的三个文件都必须使用 Write 工具写入磁盘，不可仅在对话中展示。**

---

## 重要原则

1. **AI 必须亲自读源文件**，不能依赖脚本做字符串匹配
2. **调用链分析是思考过程** — 每层至少写 2-3 句实质性分析
3. **诊断信息必须完整** — root_cause / attack_scenario / impact 缺一不可
4. **代码证据精确** — 文件路径、行号、代码原文三者必须一致
5. **severity 由 AI 根据上下文判定** — 规则标注的 severity 是默认值
6. **不确定时降级处理** — 宁可漏报 Low 也不虚报 Critical
7. **所有文件保存到 `<audit_dir>/`** — Agent 会在 Phase 2 创建此目录
