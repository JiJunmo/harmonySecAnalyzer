---
name: harmony-ipc-verifier
description: IPC 通信安全专家规则库。专职校验 UID/PID 鉴权、反序列化边界、缓冲大小及操作码路由安全。
---

# harmony-ipc-verifier

本技能是一个纯粹的无状态规则库工具，专门用于对给定的鸿蒙 RPC Stub/ServiceExtensionAbility 代码执行通信层漏洞扫描。

## 📁 目录结构

* `references/`
  * [IPC_REFERENCE.md](file:///Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer/skills_v2/harmony-ipc-verifier/references/IPC_REFERENCE.md) — IPC/RPC 跨进程通信与协议序列化安全指南
* `rules/`
  * `ipc/` — 包含 IPC 通信匹配规则集

---

## 🔍 IPC/RPC 入口校验指南 (IPC Check)

**校验重点**：检查公开的 `ServiceExtensionAbility` 服务端 Stub（继承自 `RemoteObject`）对请求的控制能力。

**核对要点**：
1. **权限守卫**：`module.json5` 中对应的 `extensionAbility` 节点是否配置了守卫权限 `permissions` 或包名白名单 `visible`？
2. **调用方 UID/PID 校验**：`onRemoteMessageRequest` 执行前是否调用了 `getCallingUid()` / `getCallingPid()` 验证客户端身份？
3. **反序列化边界校验**：在 `unmarshalling()` 阶段通过 `MessageSequence` 提取数据时，是否对读出来的基本类型做了合法范围校验？是否对字符串做了长度匹配？
4. **缓冲大小校验**：在使用 `readArrayBuffer()` 读取二进制包后，是否对数据包长度 `byteLength` 做上限拦截以防范 OOM 攻击？
5. **操作码 (Code) 路由校验**：在 `switch(code)` 分发逻辑中，`default` 分支是否默认执行安全拦截？是否允许未定义操作码通过？
