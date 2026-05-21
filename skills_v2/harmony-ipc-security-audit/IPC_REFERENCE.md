# 鸿蒙 IPC 跨进程通信功能介绍与安全审计要点

> 本文档基于华为官方 IPC ObjectTransfer 示例代码 (ipc_demo) 及 HarmonyOS IPC/RPC 开发指南编写，作为 `harmony-ipc-security-audit` Skill 的前置知识库。

---

## 一、HarmonyOS IPC 架构概述

### 1.1 什么是 IPC

HarmonyOS 的 IPC（Inter-Process Communication）机制允许不同应用或同一应用的不同进程之间进行数据交换和远程过程调用。鸿蒙基于 **OpenHarmony 分布式软总线** 构建了统一的 IPC/RPC 框架，核心模块为 **IPC Kit**（`@kit.IPCKit`，API 侧使用 `@ohos.rpc`）。

### 1.2 IPC 通信模型（基于 ipc_demo 分析）

```
┌─────────────────────────┐          ┌─────────────────────────┐
│     IPC_Client 进程       │          │     IPC_Service 进程      │
│                          │          │                          │
│  UIAbility               │          │  UIAbility               │
│    │                     │          │    │                     │
│    ▼                     │          │    ▼                     │
│  context.connectService  │          │  ServiceExtensionAbility │
│  ExtensionAbility(want)  │──────────│    │                     │
│    │                     │  connect │    ▼                     │
│    ▼                     │──────────│  onConnect() → return    │
│  OnConnect(proxy)        │  proxy   │  StubServer (RemoteObject)│
│    │                     │          │    │                     │
│    ▼                     │          │    ▼                     │
│  proxy.sendMessage       │──────────│  onRemoteMessageRequest() │
│  Request(code,data,reply)│  request │    │                     │
│    │                     │◀─────────│  reply.writeString(rsp)   │
│    ▼                     │  reply   │                          │
│  reply.readString()      │          │                          │
└─────────────────────────┘          └─────────────────────────┘
```

### 1.3 关键 API 总结

| API / 类 | 所属模块 | 作用 |
|----------|---------|------|
| `rpc.RemoteObject` | `@ohos.rpc` | Stub 基类，服务端实现此对象处理远程请求 |
| `rpc.IRemoteObject` | `@ohos.rpc` | Proxy 接口，客户端通过此接口调用服务端方法 |
| `rpc.MessageSequence` | `@ohos.rpc` | 序列化数据载体，支持写入/读取基础类型、Parcelable、ArrayBuffer |
| `rpc.MessageOption` | `@ohos.rpc` | 消息选项（同步/异步） |
| `rpc.Parcelable` | `@ohos.rpc` | 自定义序列化接口，需实现 `marshalling()` 和 `unmarshalling()` |
| `rpc.TypeCode` | `@ohos.rpc` | 数组类型枚举，如 `UINT8_ARRAY` |
| `rpc.RequestResult` | `@ohos.rpc` | 请求返回结果 |
| `sendMessageRequest(code, data, reply, option)` | `rpc.IRemoteObject` | 客户端发送请求 |
| `onRemoteMessageRequest(code, data, reply, option)` | `rpc.RemoteObject` | 服务端处理请求 |
| `connectServiceExtensionAbility(want, options)` | `common.UIAbilityContext` | 连接远程 ServiceAbility |
| `disconnectServiceExtensionAbility(id)` | `common.UIAbilityContext` | 断开连接 |

### 1.4 通信流程（基于 ipc_demo 源码关键代码）

**Step 1 — 配置服务端 ExtensionAbility** (`module.json5`):
```json5
"extensionAbilities": [{
  "name": "IpcServiceExtAbility",
  "srcEntry": "./ets/serviceextability/ServiceExtAbility.ets",
  "type": "service",
  "exported": true,        // ⚠️ 对外暴露
  "description": "service"
}]
```

**Step 2 — 客户端发起连接** (`IPC_Client.ets:126-147`):
```typescript
let want: Want = {
  bundleName: 'com.samples.ipc_service',
  abilityName: 'IpcServiceExtAbility',
}
let connect: common.ConnectOptions = {
  onConnect: (elementName, remoteProxy) => {
    proxy = remoteProxy;  // ⚠️ 获取远程代理对象
  },
  onDisconnect: (elementName) => { ... },
  onFailed: (code: number) => { ... },
}
connectid = context.connectServiceExtensionAbility(want, connect);
```

**Step 3 — 服务端返回 Stub** (`ServiceExtAbility.ets:42-45`):
```typescript
onConnect(want: Want): rpc.RemoteObject | Promise<rpc.RemoteObject> {
  return getInstance();  // 返回全局单例 StubServer
}
```

**Step 4 — 客户端发送数据** (`IPC_Client.ets:68-90`):
```typescript
let data = rpc.MessageSequence.create();
let reply = rpc.MessageSequence.create();
data.writeInterfaceToken(proxy.getDescriptor());  // ⚠️ Token 校验
data.writeParcelable(parcelable);                 // 序列化对象
proxy.sendMessageRequest(1001, data, reply, options);  // code=1001
```

**Step 5 — 服务端处理请求** (`IPC_Service.ets:48-60`):
```typescript
onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence,
  options: rpc.MessageOption): boolean | Promise<boolean> {
  let descriptor = this.getDescriptor();
  if (descriptor != data.readInterfaceToken()) {  // ⚠️ Token 校验
    return false;
  }
  onHandleClientReq(code, data, reply);  // 根据 code 分发
  return true;
}
```

**Step 6 — 服务端根据 code 分发处理** (`IPC_Service.ets:91-113`):
```typescript
function onHandleClientReq(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence) {
  switch (code) {
    case 1001:  // Parcelable 数据
      let parcelable = new MyParcelable(0, '');
      data.readParcelable(parcelable);
      dataStatus.updataParcelable(parcelable.str);
      break;
    case 1002:  // ArrayBuffer 数据
      let result = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);
      // 直接读取并使用，无长度校验
      break;
    default:
      break;
  }
}
```

---

## 二、HarmonyOS IPC 功能详解

### 2.1 数据传输方式

| 方式 | API | 说明 | 示例 |
|------|-----|------|------|
| 基础类型 | `writeInt/writeString/writeBoolean` | 直接写入基本类型 | `data.writeInt(42)` |
| Parcelable | `writeParcelable/readParcelable` | 自定义序列化对象，需实现 `rpc.Parcelable` 接口 | `data.writeParcelable(myObj)` |
| ArrayBuffer | `writeArrayBuffer/readArrayBuffer` | 原始二进制数据块 | `data.writeArrayBuffer(buf, rpc.TypeCode.UINT8_ARRAY)` |
| InterfaceToken | `writeInterfaceToken/readInterfaceToken` | 服务端描述符校验 | `data.writeInterfaceToken(proxy.getDescriptor())` |

### 2.2 Parcelable 序列化接口

```typescript
class MyParcelable implements rpc.Parcelable {
  public num: number = 0;
  public str: string = '';

  marshalling(messageSequence: rpc.MessageSequence): boolean {
    messageSequence.writeInt(this.num);
    messageSequence.writeString(this.str);
    return true;
  }

  unmarshalling(messageSequence: rpc.MessageSequence): boolean {
    this.num = messageSequence.readInt();
    this.str = messageSequence.readString();
    return true;
  }
}
```

### 2.3 Stub/Proxy 模式

- **Stub (RemoteObject)**: 服务端实现的远程对象基类，重写 `onRemoteMessageRequest()` 接收请求
- **Proxy (IRemoteObject)**: 客户端通过 `connectServiceExtensionAbility` 的 `onConnect` 回调获取，调用 `sendMessageRequest()` 发送请求

### 2.4 服务注册方式

| 方式 | 配置 | 场景 |
|------|------|------|
| ServiceExtensionAbility (`type: "service"`) | module.json5 中配置 `extensionAbilities` | 跨应用 IPC，服务端作为独立进程的后台服务 |
| UIAbility (`exported: true`) | module.json5 中配置 `abilities` | 启动 Ability 并附带参数 |
| DataShareExtensionAbility | module.json5 中配置 | 跨应用数据共享 |

### 2.5 系统应用权限要求

从 ipc_demo 的 README（第 271-320 行）可知：
- ServiceExtensionAbility 在普通应用上**不可用**，需系统应用权限
- 需要 `ohos-sdk-full`（Full SDK）
- 需要修改 `install_list_capability.json` 文件，添加 `"allowAppUsePrivilegeExtension": true`
- 需要通过 `hdc` 推送配置并重启设备

---

## 三、安全审计要点（基于 ipc_demo 的审计发现）

### 3.1 组件导出配置（模块级）

#### 检测项 3.1.1: ServiceExtensionAbility 是否对外暴露

**检测位置**: `**/src/main/module.json5`

**检测规则**:
```
检测 module.json5 中 extensionAbilities[*].exported = true 的配置
```

**ipc_demo 实例**: `IPC_Service/entry/src/main/module.json5:57`
```json5
"exported": true   // ⚠️ 任何知道 bundleName 和 abilityName 的应用都可连接
```

**安全风险**: `exported: true` 未配合 `visible` 白名单，任意应用查知 `bundleName` 后即可发起 IPC 连接。

**修复建议**:
```json5
"exported": true,
"visible": ["com.trusted.app1", "com.trusted.app2"]  // 添加调用方白名单
```

#### 检测项 3.1.2: 是否缺少 permission 守卫

**检测位置**: `**/src/main/module.json5`

**检测规则**:
```
extensionAbilities[*] 缺少 permissions 字段配置
```

**ipc_demo 实例**: `IPC_Service/entry/src/main/module.json5:53-59`
```json5
{
  "name": "IpcServiceExtAbility",
  "srcEntry": "./ets/serviceextability/ServiceExtAbility.ets",
  "type": "service",
  "exported": true,
  "description": "service"
  // ⚠️ 缺少 "permissions": ["xxx"] 守卫
}
```

**修复建议**:
```json5
"permissions": ["ohos.permission.xxx"]  // 添加权限守卫
```

---

### 3.2 调用方身份校验（代码级）

#### 检测项 3.2.1: onRemoteMessageRequest 是否校验调用方身份

**检测位置**: `**/*.ets` 和 `**/*.ts` 中的 `onRemoteMessageRequest` 方法

**检测规则**:
```
搜索 onRemoteMessageRequest 方法体，检查是否调用以下任一方法：
  - getCallingUid()
  - getCallingPid()
```

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/IPC_Service.ets:48-60`
```typescript
onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence,
  options: rpc.MessageOption): boolean | Promise<boolean> {
  // ⚠️ 只做了 descriptor 校验，未校验调用方 UID/PID/包名
  let descriptor = this.getDescriptor();
  if (descriptor != data.readInterfaceToken()) {
    return false;
  }
  onHandleClientReq(code, data, reply);
  return true;  // ⚠️ 直接返回 true
}
```

**安全风险**: 任何应用只要能连接上 ServiceExtensionAbility，即可发送任意请求。恶意应用可构造伪造的 InterfaceToken，绕过简单的 descriptor 比较。

**修复建议**:
```typescript
// 校验调用方身份
let callerUid = this.getCallingUid();
let callerPid = this.getCallingPid();
// 校验失败时应拒绝请求
if (callerUid < 0) {
  return false;
}
```

#### 检测项 3.2.2: onConnect 是否校验调用方

**检测位置**: `**/*.ets` 和 `**/*.ts` 中 ServiceExtensionAbility 的 `onConnect` 方法

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/ServiceExtAbility.ets:42-45`
```typescript
onConnect(want: Want): rpc.RemoteObject | Promise<rpc.RemoteObject> {
  // ⚠️ 直接返回 Stub，未校验 want.parameters 或调用方身份
  return getInstance();
}
```

---

### 3.3 InterfaceToken 校验（代码级）

#### 检测项 3.3.1: InterfaceToken 是否硬编码

**检测位置**: `**/*.ets` 中的 `getDescriptor()` 调用和 `writeInterfaceToken()` 调用

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/IPC_Service.ets:44-45`
```typescript
constructor(des: string) {
  super(des);  // 'serverStub_app2' 硬编码在 getInstance() 中
}
```

**客户端侧**: `IPC_Client/entry/src/main/ets/client/cnn/IPC_Client.ets:81`
```typescript
data.writeInterfaceToken(proxy.getDescriptor());  // 获取的是服务端 descriptor
```

**安全风险**: `InterfaceToken` 是一个简单的字符串 (`'serverStub_app2'`)，在代码中硬编码。只要客户端与服务端的 descriptor 一致即可通过校验。此校验可防止误连接但无法阻止恶意调用。

**检测规则**:
```
1. 检查 descriptor 是否为硬编码字符串
2. 检查服务端是否仅依赖 descriptor 做安全校验（无其他身份认证）
3. 检查客户端 writeInterfaceToken 的参数来源
```

---

### 3.4 数据传输安全（代码级）

#### 检测项 3.4.1: 数据传输是否明文

**检测位置**: `**/*.ets` 和 `**/*.ts` 中 `writeParcelable()` / `writeArrayBuffer()` / `writeString()` 等调用

**ipc_demo 实例**: `IPC_Client/entry/src/main/ets/client/cnn/IPC_Client.ets:83`
```typescript
data.writeParcelable(parcelable);  // ⚠️ 数据未加密直接写入
```

**安全风险**: Parcelable 对象中的数据未加密，在同设备跨进程传输时可能被其他进程截获。虽然鸿蒙沙箱提供了基本隔离，但在系统应用场景下仍有风险。

#### 检测项 3.4.2: 自定义 Parcelable 的 unmarshalling 是否校验数据

**检测位置**: `**/*.ets` 和 `**/*.ts` 中实现 `rpc.Parcelable` 接口的类

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/IPC_Service.ets:83-87`
```typescript
unmarshalling(messageSequence: rpc.MessageSequence): boolean {
  this.num = messageSequence.readInt();
  this.str = messageSequence.readString();
  return true;  // ⚠️ 不校验 num 范围、str 长度
}
```

**安全风险**: `unmarshalling` 无条件读取数据，不校验数值范围、字符串长度、字段完整性。攻击者构造畸形 `MessageSequence` 可能导致越界读取或内存异常。

---

### 3.5 输入校验（代码级）

#### 检测项 3.5.1: onRemoteMessageRequest 中 code 是否校验

**检测位置**: `**/*.ets` 中的 `switch(code)` 和 `if/else` 对 code 的处理

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/IPC_Service.ets:93`
```typescript
function onHandleClientReq(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence) {
  switch (code) {
    case 1001:  // ⚠️ code 是任意 int，未校验范围
      // ...
      break;
    case 1002:
      // ...
      break;
    default:
      // ⚠️ 未处理的 code 简单 break，不返回错误信息
      break;
  }
}
```

**安全风险**:
1. `code` 可以为任意整数值，未做范围校验
2. `default` 分支仅 break 不拒绝请求
3. 没有 code 白名单机制

#### 检测项 3.5.2: readArrayBuffer 后的数据长度校验

**检测位置**: `**/*.ets` 中的 `readArrayBuffer()` 调用

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/IPC_Service.ets:103-106`
```typescript
let result = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);
let decoder = util.TextDecoder.create('utf-8');
let stringData = decoder.decodeWithStream(new Uint8Array(result));
// ⚠️ 未检查 result 长度，可能导致 OOM
dataStatus.updataArrayBuffer(stringData);
```

**修复建议**:
```typescript
let result = data.readArrayBuffer(rpc.TypeCode.UINT8_ARRAY);
if (result.byteLength > MAX_BUFFER_SIZE) {
  hilog.warn(DOMAIN, TAG, 'Buffer too large');
  return false;
}
```

#### 检测项 3.5.3: readString 后的内容校验

**检测位置**: `**/*.ets` 中 `reply.readString()` 调用

**ipc_demo 实例**: `IPC_Client/entry/src/main/ets/client/cnn/IPC_Client.ets:169`
```typescript
let rsp = result.reply.readString();
// ⚠️ 未校验 rsp 是否为 null/undefined/异常长度
hilog.info(DOMAIN, TAG, 'IpcClient result.' + rsp);
```

---

### 3.6 服务端实例安全（代码级）

#### 检测项 3.6.1: Stub 是否全局单例

**检测位置**: `**/*.ets` 中 `rpc.RemoteObject` 的实例化代码

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/ServiceExtAbility.ets:25-29`
```typescript
let globalStubServer: StubServer | undefined;
function getInstance(): StubServer {
  if (globalStubServer == undefined) {
    globalStubServer = new StubServer('serverStub_app2');
  }
  return globalStubServer;  // ⚠️ 全局单例
}
```

**安全风险**: 
1. 单例模式导致所有客户端共享同一 Stub 实例
2. 不同客户端的数据通过 `dataStatus`（`@Observed` 类）共享，存在数据串扰风险
3. 多线程并发请求时可能存在竞态条件
4. 没有会话（session）隔离，一个客户端的请求可能影响另一个客户端的状态

#### 检测项 3.6.2: onRemoteMessageRequest 返回值正确性

**ipc_demo 实例**: `IPC_Service/entry/src/main/ets/serviceextability/IPC_Service.ets:58`
```typescript
return true;  // ⚠️ 无论处理成功与否都返回 true
```

**安全风险**: 即使业务处理失败（如数据解析异常、权限不足），仍返回 `true` 表示请求成功。客户端无法区分真实失败和恶意请求被拒。

---

### 3.7 日志信息泄露（代码级）

#### 检测项 3.7.1: hilog 是否打印敏感 IPC 数据

**检测位置**: `**/*.ets` 和 `**/*.ts` 中的 `hilog.info()` / `hilog.debug()` 调用

**ipc_demo 实例**:

`ServiceExtAbility.ets:34`:
```typescript
hilog.info(DOMAIN, TAG, 'ServiceExtensionAbility onCreate,want param:' + JSON.stringify(want));
// ⚠️ want 参数可能包含调用方信息、传递的数据
```

`IPC_Service.ets:50`:
```typescript
hilog.info(DOMAIN, TAG, 'Client Send code:' + code);
// ⚠️ 打印请求 code
```

`IPC_Service.ets:99`:
```typescript
hilog.info(DOMAIN, TAG, 'read parcelable: ' + parcelable.str);
// ⚠️ 打印客户端传来的字符串内容（可能含敏感信息）
```

`IPC_Client.ets:170`:
```typescript
hilog.info(DOMAIN, TAG, 'IpcClient result.' + rsp);
// ⚠️ 打印服务端返回内容
```

**安全风险**: 生产环境开启 hilog 调试时，IPC 通信内容（包括传输数据、want 参数、请求码等）会被记录到系统日志，可能被其他应用读取。

---

### 3.8 连接生命周期安全

#### 检测项 3.8.1: 断开连接后是否清理 proxy 引用

**ipc_demo 实例**: `IPC_Client/entry/src/main/ets/client/cnn/IPC_Client.ets:149-154`
```typescript
function disConnectIpc(context: common.UIAbilityContext) {
  if (connectid != undefined) {
    context.disconnectServiceExtensionAbility(connectid);
    proxy = undefined;  // ✅ 正确清理 proxy 引用
  }
}
```

**检测规则**:
```
检查 disconnect 方法中是否:
1. 调用了 disconnectServiceExtensionAbility
2. 将 proxy 引用置为 null/undefined
3. 是否有 try-finally 或 onDestroy 中调用断连
```

#### 检测项 3.8.2: 连接失败时是否有超时处理

**检测位置**: `context.connectServiceExtensionAbility()` 调用附近

**ipc_demo 实例**: 未设置超时，`onFailed` 回调只能捕获明确失败，**无连接超时机制**。

**安全风险**: 恶意服务端可无限期不返回 `onConnect`，客户端将一直等待。

---

### 3.9 权限配置审计

#### 检测项 3.9.1: 系统权限依赖

从 ipc_demo README 可知：
- IPC ServiceExtensionAbility **需要系统应用权限**
- 需要 `ohos-sdk-full`（Full SDK）
- 需要配置 `install_list_capability.json` 的 `allowAppUsePrivilegeExtension: true`

**检测规则**:
```
1. 检查 build-profile.json5 是否使用 Full SDK
2. 检查 install_list_capability.json 配置
3. 检查是否申明了不必要的系统权限
```

---

## 四、审计检测规则汇总

以下规则映射到 CWE 和 OWASP Mobile Top 10，供 `harmony-ipc-security-audit` skill 直接引用。

| 规则 ID | 严重度 | CWE | OWASP | 检测项 | 检测模式 |
|---------|--------|-----|-------|--------|----------|
| IPC-001 | High | CWE-927 | M1 | ServiceExtensionAbility exported:true 无 visible 白名单 | module.json5 模式匹配 |
| IPC-002 | High | CWE-862 | M1 | extensionAbilities 缺少 permissions 守卫 | module.json5 模式匹配 |
| IPC-003 | Critical | CWE-862 | M1 | onRemoteMessageRequest 未校验调用方身份 | 代码 AST/String Search |
| IPC-004 | High | CWE-290 | M1 | 仅依赖 InterfaceToken 字符串做认证 | 代码 + 配置联合分析 |
| IPC-005 | Medium | CWE-319 | M3 | IPC 数据明文传输 | 代码 String Search |
| IPC-006 | Medium | CWE-1287 | M8 | Parcelable.unmarshalling 未校验数据 | 代码 AST/Search |
| IPC-007 | High | CWE-20 | M8 | onRemoteMessageRequest code 未校验范围 | 代码 AST/Search |
| IPC-008 | Medium | CWE-20 | M8 | readArrayBuffer 未校验长度 | 代码 AST/Search |
| IPC-009 | Medium | CWE-543 | M5 | Stub 全局单例缺乏会话隔离 | 代码 Search |
| IPC-010 | Low | CWE-252 | M8 | onRemoteMessageRequest 返回值恒为 true | 代码 AST/Search |
| IPC-011 | Medium | CWE-532 | M9 | hilog 打印 IPC 通信数据 | 代码 Grep |
| IPC-012 | Low | CWE-404 | M7 | 断连后未清理 proxy 引用 | 代码 AST |
| IPC-013 | Medium | CWE-250 | M1 | 不必要地使用 Full SDK / 系统权限 | build-profile + module.json5 联合分析 |
| IPC-014 | Low | CWE-1104 | M9 | ServiceExtensionAbility 过度导出 | module.json5 模式匹配 |

---

## 五、ipc_demo 完整审计发现

基于以上分析，对 ipc_demo 的 IPC_Service 应用做完整审计发现：

| 发现 | 严重度 | 位置 | 描述 |
|------|--------|------|------|
| 缺少 calling uid 校验 | Critical | `IPC_Service.ets:48-60` | `onRemoteMessageRequest` 仅做 descriptor 字符串比较，未调用 `getCallingUid()` |
| exported:true 无 visible | High | `IPC_Service/module.json5:57` | ServiceExtensionAbility 导出但未设置调用方白名单 |
| 缺少权限守卫 | High | `IPC_Service/module.json5:53-59` | extensionAbilities 未配置 permissions |
| code 无范围校验 | High | `IPC_Service.ets:93` | switch(code) 接受任意 int 值，无白名单校验 |
| 硬编码 descriptor | High | `IPC_Service.ets:27` | `new StubServer('serverStub_app2')` 字符串硬编码 |
| ArrayBuffer 无长度校验 | Medium | `IPC_Service.ets:103` | `readArrayBuffer` 后直接使用结果，未检查 byteLength |
| Stub 全局单例 | Medium | `ServiceExtAbility.ets:25-29` | 所有客户端共享同一 StubServer 实例 |
| hilog 打印 IPC 数据 | Medium | `IPC_Service.ets:99`, `IPC_Client.ets:170` | `parcelable.str` 和 `rsp` 内容被记录到日志 |
| 明文传输数据 | Medium | `IPC_Client.ets:83` | Parcelable 数据未加密 |
| unmarshalling 无校验 | Medium | `IPC_Service.ets:83-87` | 不校验 readInt/readString 的结果 |
| onConnect 无身份校验 | High | `ServiceExtAbility.ets:42-45` | 直接返回 Stub 对象 |
| 返回值恒 true | Low | `IPC_Service.ets:58` | 无论处理结果如何都返回 true |

---

## 六、Skill 实现指引

### 6.1 文件扫描模式

```
必须扫描的文件：
  - **/src/main/module.json5                               (extensionAbilities 配置)
  - **/src/main/ets/**/*.ets                               (IPC 相关代码)
  - **/src/main/ts/**/*.ts                                 (IPC 相关代码)
  - **/build-profile.json5                                (SDK 类型检查)
  - **/src/main/resources/base/profile/*.json              (可能含 IPC 相关 profile)

搜索关键字：
  - rpc.RemoteObject                                       (Stub 类定义)
  - onRemoteMessageRequest                                (请求处理入口)
  - connectServiceExtensionAbility                        (客户端连接入口)
  - sendMessageRequest                                    (客户端发送请求)
  - writeInterfaceToken / readInterfaceToken              (token 校验)
  - writeParcelable / readParcelable                      (数据序列化)
  - writeArrayBuffer / readArrayBuffer                    (二进制数据传输)
  - getCallingUid / getCallingPid                         (调用方身份校验)
  - export class.*extends.*ServiceExtensionAbility        (服务端入口)
  - implements rpc.Parcelable                             (自定义序列化类)
  - getDescriptor                                         (descriptor 获取)
```

### 6.2 hook 到现有 Agent

该 skill 会在以下条件触发：
1. `metadata.security_surface.has_exported_extensions` 为 true（存在 extensionAbilities）
2. `metadata.files` 中存在直接使用 `@ohos.rpc` / `@kit.IPCKit` 导入的文件
3. `metadata.modules` 中 module.json5 配置了 `extensionAbilities`

### 6.3 审计策略

| 阶段 | 操作 |
|------|------|
| 配置审计 | 解析 module.json5 提取 extensionAbilities，检查 exported/permissions/visible |
| 代码搜索 | 在 .ets/.ts 文件中搜索 IPC API 调用模式 |
| 身份校验审计 | 分析 `onRemoteMessageRequest` 和 `onConnect` 调用链，检查是否调用了身份校验 API |
| 数据校验审计 | 分析 `unmarshalling`、`readArrayBuffer`、`readString` 后的数据校验逻辑 |
| 日志审计 | 检查 IPC 相关方法中 hilog.info 调用是否打印了通信数据 |
| 实例审计 | 检查 RemoteObject 是否全局单例，是否存在会话隔离 |

### 6.4 与已有 Skill 的关系

- **harmony-component-audit**: 负责 `abilities` 导出审计，IPC Skill 侧重 `extensionAbilities` 的 IPC 安全
- **harmony-permission-audit**: 负责权限申请审计，IPC Skill 侧重 extensionAbilities 的权限守卫和 IPC 调用身份校验
- **harmony-secrets-audit**: 负责硬编码密钥审计，与 IPC 无直接冲突
- **IPC 独有的审计点**: 调用方身份校验、InterfaceToken 安全、Parcelable 数据校验、Stub 实例隔离、IPC 通信生命周期安全
