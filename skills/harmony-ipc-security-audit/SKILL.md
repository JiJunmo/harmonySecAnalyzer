# harmony-ipc-security-audit

HarmonyOS IPC 跨进程通信安全审计 Skill。**以 AI 代码理解为主**，先梳理完整 IPC 通信逻辑链路，再对照规则库筛查威胁。

## 触发条件

Agent 读取 metadata 后，若以下任一条件为 true 则调度本 Skill：
- `security_surface.has_ipc_service` → true
- `security_surface.has_service_extension` → true
- `files.capabilities.uses_ipc` → true

## 前置输入

| 数据 | 来源 |
|------|------|
| metadata JSON | Phase 1 输出的 `/tmp/harmony_audit_metadata.json` |
| 项目根路径 | 用户输入 |
| 规则知识库 | `skills/harmony-ipc-security-audit/rules/*.json` |
| IPC 领域知识 | `skills/harmony-ipc-security-audit/IPC_REFERENCE.md` |

## 执行流程（四步，全部 AI 完成）

---

### Step 1: 收集上下文

1. **读取 metadata.json**，提取：
   - `modules[*].extension_abilities` — 服务端注册了哪些 extension，各字段值（exported, type, permissions）
   - `files.ets_sources` — 哪些文件包含 IPC 相关 import（`@ohos.rpc` / `@kit.IPCKit`）
   - `security_surface.*` — 攻击面总览（exported_extensions 等）

2. **读取规则库**，加载 `rules/*.json`，将所有规则按 ID 列表化为待检查项：
   ```
   规则 ID | 严重度 | 标题 | 检测关注点
   ```

3. **读取 IPC_REFERENCE.md**，理解鸿蒙 IPC 的标准通信模式和安全基线。

---

### Step 2: 理解代码（核心步骤）

**不要逐文件扫描**，而是按以下 IPC 通信链路顺序阅读代码：

#### 2.1 服务端注册层
- 读取包含 `extensionAbilities` 的 `module.json5`
- 确认：哪些 extension 类型为 `service`？exported 是什么？有没有 permissions？

#### 2.2 服务端连接层
- 读取 ServiceExtensionAbility 实现文件（从 `srcEntry` 路径定位）
- 关注方法：`onConnect(want)` → 返回了什么？是否校验了 want 参数？
- 关注方法：`onDisconnect` / `onDestroy` → 有无资源清理？

#### 2.3 服务端请求处理层
- 读取 Stub/RemoteObject 实现文件（从 onConnect 的返回值追踪）
- 关注方法：`onRemoteMessageRequest(code, data, reply, option)` 
- 按以下顺序梳理逻辑：
  1. **入口**：方法签名、descriptor 获取
  2. **认证**：是否调用 `getCallingUid()` / `getCallingPid()`？是直接 return 还是赋值后继续？
  3. **Token校验**：`readInterfaceToken()` 之后是否还有其他认证？还是仅凭 descriptor 字符串比较？
  4. **操作码分发**：`switch(code)` / `if/else` 如何处理？default 分支有什么操作？
  5. **数据读取**：`readParcelable()` / `readArrayBuffer()` / `readString()` 之后做了什么校验？
  6. **数据使用**：读取的数据流向了哪里（存入全局变量？传给 UI？打印日志？）
  7. **返回**：return true/false 的逻辑是什么？失败路径返回什么？

#### 2.4 服务端数据层
- 读取 Parcelable 实现类
- 关注：`marshalling()` 写入顺序和 `unmarshalling()` 读取顺序是否一致？
- `unmarshalling()` 中对 `readInt()` / `readString()` 返回值有无校验？

#### 2.5 客户端连接层
- 读取调用 `connectServiceExtensionAbility` 的文件
- 关注：`ConnectOptions` 三个回调（onConnect / onDisconnect / onFailed）的实现
- 关注：连接是否有超时机制？失败处理是否完整？

#### 2.6 客户端发送层
- 读取调用 `sendMessageRequest` 的文件
- 关注：数据在写入 MessageSequence 之前有无加密？InterfaceToken 从何获取？
- 关注：reply 数据读取后有无校验？

#### 2.7 客户端断连层
- 读取调用 `disconnectServiceExtensionAbility` 的文件
- 关注：proxy 引用是否置空？connectId 是否清理？

---

### Step 3: 对照规则筛查

读完代码、完全理解 IPC 链路后，从规则库加载规则逐条筛查。

#### 3.1 加载规则

读取 `rules/` 目录下全部 JSON 文件，按 severity 排序（high → medium → low → info）。每条规则的关键字段：

| 字段 | 用途 |
|------|------|
| `id` | 规则编号 |
| `severity` | 默认严重度（AI 可据上下文调整） |
| `title` | 发现标题 |
| `description` | 风险描述模板 |
| `detection.positive_patterns` | 代码中**应存在**的模式（触发检查） |
| `detection.negative_patterns` | 代码中**不应缺失**的模式（缺失则告警） |
| `detection.type` | `code_pattern`（需读源文件）或 `config_pattern`（查 metadata 即可） |
| `remediation` | 修复建议模板 |

#### 3.2 筛查方法

对每条规则：

1. **`config_pattern` 类型**：直接在 metadata 中检查 extensionAbilities 配置字段
2. **`code_pattern` 类型**：
   - 检查 `positive_patterns`：在 Step 2 已理解的代码中确认该模式是否存在
   - 检查 `negative_patterns`：确认代码中是否缺失这些防护措施
   - 结合代码上下文判断 severity：如果服务本身设计为公共 API，某些"缺失"可能是有意为之

#### 3.3 判断原则

1. **不确定时标注为 Medium**——宁可漏报 Low 也不虚报 Critical
2. **severity 由 AI 根据上下文判定**——规则标注的 severity 是默认值，AI 可结合实际场景调整
3. **发现描述必须具体**——写"default 分支执行了 hilog.info"而非"default 分支有副作用"
4. **遇到不理解的代码不要硬套规则**——标记为"需人工审查"并以 Info 级别输出

---

### Step 4: 输出 findings.json

每条发现严格遵循以下格式，保存到 `<audit_dir>/harmony-ipc-security-audit-findings.json`：

```json
{
  "_meta": {
    "auditor": "harmony-ipc-security-audit",
    "total_findings": 12,
    "severity_counts": { "critical": 0, "high": 3, "medium": 6, "low": 2, "info": 1 }
  },
  "findings": [
    {
      "id": "HM-IPC-2026-0001",
      "skill": "harmony-ipc-security-audit",
      "severity": "high",
      "title": "onRemoteMessageRequest 中操作码 code 的 default 分支有副作用操作",
      "description": "switch(code) 的 default 分支执行了 hilog.info(DOMAIN, TAG, 'onHandleClient-default,code: ' + 1001)，攻击者可传入任意 code 值触发此日志操作。",
      "location": {
        "file": "entry/src/main/ets/serviceextability/IPC_Service.ets",
        "line": 109,
        "snippet": "default:\n      hilog.info(DOMAIN, TAG, 'onHandleClient-default,code: ' + 1001);\n      break;"
      },
      "cwe": "CWE-20",
      "owasp": "M8",
      "remediation": "在 switch(code) 前校验 code 范围，或 default 分支返回 false 拒绝请求",
      "reference": "https://developer.huawei.com/consumer/cn/doc/harmonyos-references/js-apis-rpc"
    }
  ]
}
```

**关键要求**：
- `location.snippet` 必须是代码原文（不是总结），包含实际行和上下文
- `description` 必须结合代码上下文，写出**在这个项目中具体发现了什么**，而非泛泛描述
- `remediation` 必须给出可操作的修复建议

---

## 脚本使用（仅辅助）

保留一个辅助脚本仅用于**准备上下文**，不做任何安全判断：

```bash
python3 skills/harmony-ipc-security-audit/scripts/ipc_context.py <metadata_path> --output /tmp/ipc_context.json
```

该脚本输出：
- 需要审计的 IPC 文件列表
- extensionAbilities 配置摘要
- 规则列表

然后 AI 读取这些上下文信息后，**亲自阅读每个相关源文件，执行 Step 2-4**。

---

## 重要原则

1. **AI 必须亲自读源文件**，不能依赖脚本做字符串匹配
2. **先理解流程，再匹配规则**——不理解的代码不要硬套规则
3. **发现描述必须具体**——写"default 分支执行了 hilog.info"而非"default 分支有副作用"
4. **severity 由 AI 根据上下文判定**——规则标注的 severity 是默认值，AI 可结合实际场景调整
5. **不确定时标注为 Medium**——宁可漏报 Low 也不虚报 Critical
