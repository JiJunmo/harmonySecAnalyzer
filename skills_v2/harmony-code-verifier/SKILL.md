---
name: harmony-code-verifier
description: v2.5 — 统一代码安全性校验与安全规则库。支持对 UIAbility、WebView 以及 IPC 通信层进行深度漏洞语义判定。
---

# harmony-code-verifier v2.5

本技能（Skill）将原有的 **IPC、UIAbility、WebView** 三个独立维度的漏洞检查表、领域知识与校验规则全部整合归一，为 `vulnerability-auditor-agent` 提供统一的代码校验指令与安全基准参考。

## 📁 目录结构

* `references/`
  * [ABILITY_REFERENCE.md](file:///Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer/skills_v2/harmony-code-verifier/references/ABILITY_REFERENCE.md) — UIAbility 入口防卫与生命周期知识库
  * [IPC_REFERENCE.md](file:///Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer/skills_v2/harmony-code-verifier/references/IPC_REFERENCE.md) — IPC/RPC 跨进程通信与协议序列化安全指南
  * [WEBVIEW_REFERENCE.md](file:///Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer/skills_v2/harmony-code-verifier/references/WEBVIEW_REFERENCE.md) — WebView 容器安全、JSBridge 绑定及域名拦截校验机制
* `rules/`
  * `ability/` — 包含 UIAbility 匹配规则集（CWE/OWASP）
  * `ipc/` — 包含 IPC 通信匹配规则集
  * `webview/` — 包含 WebView/JSBridge 匹配规则集

---

## 🔍 核心审计指南：Source-to-Sink 利用链 (Exploit Chain) 校验

当子智能体（`vulnerability-auditor-agent`）调用本技能进行漏洞验证时，**严禁孤立审查某个组件**。必须遵循以下“入口 -> 链路 -> 终点”的级联逻辑进行关联判定：

### 阶段一：Source 规则 (入口防卫校验)
涵盖 UIAbility 入口与 IPC 通信服务入口。

#### 1. UIAbility 入口校验 (UIAbility Check)
- **校验重点**：检查 `exported=true` 的公开 Ability 在生命周期入口中提取并消费 `want` 参数时的防御等级。
- **核对要点**：
  1. **Calling Bundle 校验**：是否调用了 `getCallingBundleName()` 并设置了严格的白名单比对？
  2. **Ability 重定向校验**：嵌套的 `Want` 变量是否最终作为参数流入了 `context.startAbility(nestedWant)`？若存在，是否有目标组件白名单拦截？
  3. **敏感信息回传校验**：`terminateSelfWithResult(resultWant)` 返回的数据中是否泄露了敏感的 token、沙箱文件路径或本地数据库信息，且缺乏 Caller 身份安全拦截？
  4. **重入漏洞校验**：`onCreate(want)` 和 `onNewWant(want)` 的校验逻辑是否具备**防御一致性**？若 `onNewWant` 缺少校验，攻击者可通过重入机制实现绕过。

#### 2. IPC/RPC 入口校验 (IPC Check)
- **校验重点**：检查公开的 `ServiceExtensionAbility` 服务端 Stub（继承自 `RemoteObject`）对请求的控制能力。
- **核对要点**：
  1. **权限守卫**：`module.json5` 中对应的 `extensionAbility` 节点是否配置了守卫权限 `permissions` 或包名白名单 `visible`？
  2. **调用方 UID/PID 校验**：`onRemoteMessageRequest` 执行前是否调用了 `getCallingUid()` / `getCallingPid()` 验证客户端身份？
  3. **反序列化边界校验**：在 `unmarshalling()` 阶段通过 `MessageSequence` 提取数据时，是否对读出来的基本类型做了合法范围校验？是否对字符串做了长度匹配？
  4. **缓冲大小校验**：在使用 `readArrayBuffer()` 读取二进制包后，是否对数据包长度 `byteLength` 做上限拦截以防范 OOM 攻击？
  5. **操作码 (Code) 路由校验**：在 `switch(code)` 分发逻辑中，`default` 分支是否默认执行安全拦截？是否允许未定义操作码通过？

### 阶段二：Sink 规则 (终点利用与危险执行校验)
- **前置条件**：仅当数据流或控制流通过代码推理被明确证明触达了以下 Sink（如 WebView 容器）时，才激活此规则。如果不连通，则跳过。
- **上下文关联**：即使触发了以下风险项，也必须结合 Source 阶段传入的参数。如果攻击者通过 `want` 无法污染这里的执行流，则只能定为低危。

#### WebView 容器与 JSBridge 安全校验 (WebView Check)
- **校验重点**：检查 Web 容器的安全参数属性、JSBridge 暴露的方法敏感性，以及域名拦截器拦截深度。
- **核对要点**：
  1. **白名单域匹配校验**：检查 `registerJavaScriptProxy` 的第 5 个参数 `allowedOriginRules`。如果配置为 `["*"]` 或为空 `[]`，意味着任意外部域的网页都可以调用暴露的方法，属于高危。
  2. **JSBridge 暴露方法 analysis**：逐个审查 Native 暴露出的一系列 JavaScript 代理方法。只要发现直接调用了 `@ohos.file.fs` (文件 IO)、`@ohos.data.relationalStore` (数据库) 或发送网络请求的代码，而没有参数沙箱隔离（如任意读写 path 限制），直接判定可利用。
  3. **域名拦截器弱校验匹配**：
     - 使用 `startsWith` 校验域名（如 `url.startsWith('https://trusted.com')`）➔ 可被 `https://trusted.com.evil.com` 二级域名劫持绕过。
     - 使用 `includes` 校验域名（如 `url.includes('trusted.com')`）➔ 可在路径或参数中携带该子串绕过（如 `https://evil.com/trusted.com`）。
     - 正则表达式未对 Host 结尾字符做严格锚定（如 `/^https:\/\/trusted\.com/`）➔ 可在 Host 尾部拼接任意字符绕过。
     - 强逻辑校验标准：必须使用结构化解析器（如 `new Url.URL(url)`）提取 `hostname` 后执行全等比对。
