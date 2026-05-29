---
name: harmony-ipc-security-audit
description: v2 — 审计对三方应用开放的 IPC 服务，梳理完整业务流程，判断敏感度，对照规则发现漏洞并记录利用方法
---

# harmony-ipc-security-audit v2

审计鸿蒙应用中**对所有三方应用开放的 IPC 服务**（type=service、exported=true、非系统权限守卫），梳理每个服务的完整调用流程，判断是否存在敏感信息返回或敏感操作执行，对照安全规则检查漏洞，输出完整的漏洞利用路径。

## 前置条件

Phase 1 已筛选出需要审计的 IPC 模块。筛选条件：
- `type` = "service"
- `exported` = true
- `filtered_by_system_permission` = false（仅由系统未开放权限守卫的服务已自动排除）

满足以上条件的 IPC 服务就是对任意三方应用开放的，**每个都需要完整审计**。

## 输入

| 数据 | 来源 |
|------|------|
| 项目源码 | 用户提供的 project_path |
| IPC 服务列表 | Phase 1 entries.json 中 `type=ipc_service` 的条目 |
| 规则知识库 | `skills_v2/harmony-ipc-security-audit/rules/*.json` |
| IPC 领域知识 | `skills_v2/harmony-ipc-security-audit/IPC_REFERENCE.md` |

## 审计流程（四步）

### Step 1：梳理模块完整业务流程

对每个 IPC 服务，从 `onConnect()` 入口开始，完整追踪调用链：

```
onConnect(want)
    ↓
返回 Stub/RemoteObject
    ↓
onRemoteMessageRequest(code, data, reply, option)
    ↓
readInterfaceToken() 校验（若有）
    ↓
switch(code) 业务分发
    ↓
各 case 分支的具体业务执行
    ↓
reply 回包 / 全局状态变更 / 文件写入 / 数据库操作 / 网络请求（输出）
```

**必须搞清楚的内容**：
- **输入参数格式**：客户端需要传入什么 code？data 中要写入什么（Parcelable 字段？ArrayBuffer？String？）
- **业务分发逻辑**：switch(code) 有多少个 case？default 分支做了什么？code 有无白名单？
- **每个 case 的具体业务**：**逐一分析每个 code 分支**，不管是否敏感都要记录下来。某分支只写日志？某分支返回用户 token？某分支读文件？某分支写数据库？——每个分支独立分析，不可因为找到一个敏感分支就跳过其他分支，也不可因为前面几个非敏感就判定整体不敏感
- **输出结果**：每个 case 的 reply 回包写了什么？是否有副作用？

**产出**：对每个 code 分支的完整分析表 + 该服务的整体流程概述。

```
| code | 业务描述 | 输入 | 输出 | 是否敏感 | 原因 |
|------|---------|------|------|---------|------|
| 1001 | 读取 Parcelable 并存入全局状态 | MyParcelable(num, str) | reply.writeString("ok") | 是 | 攻击者 str 写入全局变量 |
| 1002 | 读取 ArrayBuffer 并解码后存入全局状态 | ArrayBuffer(UINT8_ARRAY) | 无回包 | 是 | 攻击者数据写入全局变量 |
| 1003 | 返回当前服务端状态 | 无 | reply.writeString(dataStatus.parcelableData) | 是 | 泄露全局状态中的敏感数据 |
| 1004 | 记录日志 | 无 | reply.writeString("ok") | 否 | 仅日志，无敏感操作 |
| default | 记录未知 code | 无 | 无 | 否 | 仅 hilog.info |
```

### Step 2：逐分支判断敏感度

**重要：按 code 分支逐一判断，不是对整个服务统一判定。** 一个服务可能同时有敏感分支和非敏感分支。

**非敏感分支**（记录但不继续审计）：

| 场景 | 示例 |
|------|------|
| 仅返回固定值 | `reply.writeString("ok")` |
| 仅做日志记录 | `hilog.info(...)` |
| 仅做纯计算后返回 | 对输入做 `+1` 后返回 |

**敏感分支**（标记为敏感，进入 Step 3）：

| 场景 | 为什么敏感 |
|------|-----------|
| 返回服务端内部状态（token、用户信息、全局变量值、配置） | 信息泄露 |
| 修改全局变量或单例状态 | 状态篡改，影响其他客户端 |
| 读写文件系统 | 数据泄露或篡改 |
| 操作数据库 | 数据泄露或篡改 |
| 发起网络请求 | SSRF、数据外传 |
| 执行系统命令或调用系统 API | 权限提升 |

**只要存在至少一个敏感分支，该服务就是敏感服务 → 继续 Step 3。** 在 Step 4 输出时，敏感分支和非敏感分支都要列出来（非敏感分支说明为何无需关注）。

### Step 3：对照安全规则与语义判定 (AI Audit Guide Verification)

确定是敏感业务后，请精准加载并阅读 `rules/` 目录下（`config.json`、`handler.json`、`data.json`、`lifecycle.json`、`business.json`）的匹配规则。

**必须严格执行以下两条标准进行漏洞判定**：
1. **严格对照并执行规则中的 `audit_guide` 自然语言因果校验向导**：绝对禁止仅凭特征关键字触发（如看到 `onRemoteMessageRequest` 就盲报 `IPC-003`），必须按照 `audit_guide` 的语义因果链分析 getCallingUid() 等是否真的起到了条件分支拦截逻辑，证明漏洞确实可被第三方利用。
2. **读取并应用 `severity_modifiers` 结构化条件降级场景**：仔细核对代码上下文事实（如服务端业务逻辑是否其实仅返回了固定字符串 `服务端业务逻辑仅返回固定字符串，无任何敏感数据或操作`，若是则必须直接 `skip` 跳过不报），执行相应的漏洞严重级别等级修正。

### Step 4：记录漏洞

对每个存在敏感分支的 IPC 服务，生成完整的漏洞记录。**核心要求**：

**A. 梳理敏感的 code 分支**

不要把所有非敏感分支都写入 `cases` 数组。`cases` 数组中仅保留**判定为敏感或有安全风险**的分支。对于其他非敏感分支，统一归纳到新增的 `non_sensitive_summary` 字段中说明即可，以节省输出空间。格式：

```json
"non_sensitive_summary": "code 1004 / default 仅做日志记录，无敏感操作",
"cases": [
  {
    "code": 1001,
    "description": "读取 Parcelable 并存入全局状态",
    "sensitive": true,
    "input": "MyParcelable { num: number, str: string }",
    "output": "reply.writeString('ok')",
    "snippet": "data.readParcelable(parcelable);\ndataStatus.updataParcelable(parcelable.str);",
    "sensitive_reason": "攻击者控制的 parcelable.str 被写入全局变量 dataStatus，所有客户端共享此状态"
  },
  {
    "code": 1002,
    "description": "读取 ArrayBuffer 并解码后存入全局状态",
    "sensitive": true,
    "input": "ArrayBuffer (TypeCode.UINT8_ARRAY)",
    "output": "无回包，数据写入 dataStatus.arrayBufferData",
    "snippet": "let result = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);\nlet stringData = decoder.decodeWithStream(new Uint8Array(result));\ndataStatus.updataArrayBuffer(stringData);",
    "sensitive_reason": "攻击者控制的 ArrayBuffer 解码后写入全局变量"
  },
  {
    "code": 1003,
    "description": "返回当前全局状态",
    "sensitive": true,
    "input": "无",
    "output": "reply.writeString(dataStatus.parcelableData + dataStatus.arrayBufferData)",
    "sensitive_reason": "直接返回全局状态，泄露其他客户端的数据"
  }
]
```

**B. 详细展示完整流程（每步带核心代码）**

flow 中每一跳必须有 `snippet`（实际代码），不可只有文字描述：

```json
"flow": [
  {
    "step": 1,
    "stage": "入口-连接",
    "description": "onConnect 返回全局单例 StubServer，未校验调用方 want.bundleName",
    "file": "ServiceExtAbility.ets:42-45",
    "snippet": "onConnect(want: Want): rpc.RemoteObject {\n  return getInstance();\n}"
  },
  {
    "step": 2,
    "stage": "入口-请求",
    "description": "onRemoteMessageRequest 接收客户端请求，仅做 descriptor 字符串比较",
    "file": "IPC_Service.ets:48-60",
    "snippet": "onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence, option: rpc.MessageOption): boolean {\n  let descriptor = this.getDescriptor();\n  if (descriptor != data.readInterfaceToken()) { return false; }\n  onHandleClientReq(code, data, reply);\n  return true;\n}"
  },
  {
    "step": 3,
    "stage": "分发",
    "description": "switch(code) 无白名单校验，case 1001 命中 handleReadData",
    "file": "IPC_Service.ets:93-98",
    "snippet": "switch (code) {\n  case 1001:\n    let parcelable = new MyParcelable(0, '');\n    data.readParcelable(parcelable);\n    dataStatus.updataParcelable(parcelable.str);\n    break;\n  case 1002:\n    let result = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);\n    let stringData = decoder.decodeWithStream(new Uint8Array(result));\n    dataStatus.updataArrayBuffer(stringData);\n    break;\n  default:\n    hilog.info(DOMAIN, TAG, 'unknown code');\n    break;\n}"
  }
]
```

**C. 全面评估危害**

不可只写"信息泄露"这种笼统描述。必须具体到**能获取什么数据、能执行什么操作**：

```json
"impact": {
  "summary": "任意三方应用可读写全局单例 dataStatus 中的所有字段",
  "sensitive_data_exposed": [
    { "field": "dataStatus.parcelableData", "type": "string", "source": "code 1001 写入，code 1003 可读取", "content": "攻击者可写入任意字符串，也可读取其他客户端写入的数据" },
    { "field": "dataStatus.arrayBufferData", "type": "string", "source": "code 1002 写入，code 1003 可读取", "content": "同上" }
  ],
  "sensitive_operations": [
    { "operation": "全局状态写入", "via": "code 1001 / 1002", "consequence": "可注入恶意数据，影响其他客户端业务逻辑" },
    { "operation": "全局状态读取", "via": "code 1003", "consequence": "可读取其他客户端存入的敏感数据（token、用户信息等）" }
  ],
  "output_example": "code=1003 时 reply.readString() → 'attacker_injected_data' + 'other_client_token: eyJhbG...'"
}
```

## 输出

每个 IPC 服务独立输出一个分片文件。**必须使用 Write 工具写入磁盘，不可仅在对话中展示 JSON。**

文件命名：`harmony-ipc-security-audit-attack-paths-{模块名}.json`

例如：`harmony-ipc-security-audit-attack-paths-IpcServiceExtAbility.json`

Phase 3 聚合器会自动合并所有 `harmony-ipc-security-audit-attack-paths-*.json` 分片。

### 整体输出结构

```json
{
  "attack_paths": [
    {
      "id": "IPC-001",
      "module": "IpcServiceExtAbility (entry)",
      "severity": "critical",
      "title": "IPC 服务无身份校验 → 任意应用可读写全局状态中的用户数据",

      "non_sensitive_summary": "default 分支仅做日志记录，无敏感操作",
      "cases": [
        {
          "code": 1001,
          "description": "读取 Parcelable 并存入全局状态",
          "sensitive": true,
          "input": "MyParcelable { num: number, str: string }",
          "output": "reply.writeString('ok')",
          "snippet": "let parcelable = new MyParcelable(0, '');\ndata.readParcelable(parcelable);\ndataStatus.updataParcelable(parcelable.str);\nhilog.info(DOMAIN, TAG, 'read parcelable: ' + parcelable.str);",
          "sensitive_reason": "攻击者控制的 parcelable.str 被写入全局变量 dataStatus，所有客户端共享此状态"
        },
        {
          "code": 1002,
          "description": "读取 ArrayBuffer 解码后存入全局状态",
          "sensitive": true,
          "input": "ArrayBuffer (TypeCode.UINT8_ARRAY)",
          "output": "无回包，写入 dataStatus.arrayBufferData",
          "snippet": "let result = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);\nlet decoder = util.TextDecoder.create('utf-8');\nlet stringData = decoder.decodeWithStream(new Uint8Array(result));\ndataStatus.updataArrayBuffer(stringData);",
          "sensitive_reason": "攻击者控制的 ArrayBuffer 解码后写入全局变量，且未检查 byteLength（可触发 OOM）"
        }
      ],

      "flow": [
        {
          "step": 1,
          "stage": "入口-连接",
          "description": "onConnect 直接返回全局单例 StubServer，未校验调用方身份",
          "file": "ServiceExtAbility.ets:42-45",
          "snippet": "onConnect(want: Want): rpc.RemoteObject {\n  return getInstance();\n}"
        },
        {
          "step": 2,
          "stage": "入口-请求",
          "description": "onRemoteMessageRequest 仅做 descriptor 字符串比较，未调用 getCallingUid()，返回值恒为 true",
          "file": "IPC_Service.ets:48-60",
          "snippet": "onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence, option: rpc.MessageOption): boolean {\n  let descriptor = this.getDescriptor();\n  if (descriptor != data.readInterfaceToken()) { return false; }\n  onHandleClientReq(code, data, reply);\n  return true;\n}"
        },
        {
          "step": 3,
          "stage": "分发+执行",
          "description": "switch(code) 无白名单，直接分发到 onHandleClientReq。case 1001 将攻击者数据写入全局状态，case 1002 读取 ArrayBuffer 写入全局状态",
          "file": "IPC_Service.ets:91-112",
          "snippet": "function onHandleClientReq(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence) {\n  switch (code) {\n    case 1001:\n      let parcelable = new MyParcelable(0, '');\n      data.readParcelable(parcelable);\n      dataStatus.updataParcelable(parcelable.str);\n      break;\n    case 1002:\n      let result = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);\n      let stringData = decoder.decodeWithStream(new Uint8Array(result));\n      dataStatus.updataArrayBuffer(stringData);\n      break;\n    default:\n      hilog.info(DOMAIN, TAG, 'onHandleClient-default,code: ' + 1001);\n      break;\n  }\n}"
        }
      ],

      "input": {
        "code": 1001,
        "data_format": "writeInterfaceToken('serverStub_app2') + writeParcelable(MyParcelable { num: 1, str: 'attacker_payload' })",
        "snippet": "let data = rpc.MessageSequence.create();\ndata.writeInterfaceToken(proxy.getDescriptor());\nlet p = new MyParcelable(1, 'attacker_string');\ndata.writeParcelable(p);\nproxy.sendMessageRequest(1001, data, reply, option);"
      },

      "impact": {
        "summary": "任意三方应用可读写全局单例 dataStatus 中的所有字段。由于 Stub 是全局单例、无会话隔离，攻击者的数据与合法用户数据混在同一存储中。",
        "sensitive_data_exposed": [
          { "field": "dataStatus.parcelableData", "type": "string", "source": "code 1001 写入", "risk": "攻击者可写入任意字符串；若服务端将用户 token 等敏感数据也存于此字段，攻击者可覆盖或读取" },
          { "field": "dataStatus.arrayBufferData", "type": "string", "source": "code 1002 写入", "risk": "攻击者可写入任意数据；无 byteLength 校验，可构造超大 ArrayBuffer 导致 OOM" }
        ],
        "sensitive_operations": [
          { "operation": "全局状态写入", "via": "code 1001 / 1002", "consequence": "可注入恶意数据，干扰其他客户端读取的业务数据" },
          { "operation": "DoS", "via": "code 1002（超大 ArrayBuffer）", "consequence": "服务端进程 OOM 崩溃" }
        ]
      },

      "exploitation": "1. 反编译目标应用，从 IPC_Service.ets 中提取 descriptor 字符串和 code 枚举值\n2. 编写恶意应用，调用 connectServiceExtensionAbility 连接 IpcServiceExtAbility\n3. 构造 MessageSequence：writeInterfaceToken + writeParcelable（或 writeArrayBuffer）\n4. proxy.sendMessageRequest(1001/data, reply) 写入攻击数据\n5. 换用 code 1002 发送超大 ArrayBuffer 触发 OOM",

      "remediation": "1. onConnect 中校验 want.bundleName\n2. onRemoteMessageRequest 入口调用 getCallingUid() 并校验\n3. code 做白名单校验\n4. 为每个连接创建独立 Stub 实例，避免全局状态共享\n5. readArrayBuffer 后校验 byteLength",

      "matched_rules": ["IPC-003", "IPC-004", "IPC-007", "IPC-008", "IPC-009", "IPC-011-CONNECT", "IPC-010-RETURN", "IPC-010-LOG"],
      "evidence": [
        { "file": "ServiceExtAbility.ets", "line_range": "42-45", "snippet": "onConnect(want) { return getInstance(); }", "description": "连接入口：无身份校验" },
        { "file": "IPC_Service.ets", "line_range": "48-60", "snippet": "onRemoteMessageRequest(...) { ... return true; }", "description": "请求入口：无身份校验，返回值恒 true" },
        { "file": "IPC_Service.ets", "line_range": "91-112", "snippet": "switch(code) { case 1001: ... case 1002: ... }", "description": "分发+执行：所有 code 分支" }
      ]
    }
  ]
}
```

## 重要原则

1. **先判敏感，再查规则**：非敏感业务跳过，避免在无价值业务上浪费审计
2. **完整流程必须梳理清楚**：输入 → 分发 → 执行 → 输出，四段缺一不可
3. **利用方法必须可执行**：逐步描述，包括如何获取 descriptor、如何构造 data、调用什么 API
4. **实际源码为证据**：所有判断必须有代码原文支撑，不可凭空猜测
5. **rule 是参考，不是教条**：规则定义默认 severity，AI 结合实际上下文可调整
