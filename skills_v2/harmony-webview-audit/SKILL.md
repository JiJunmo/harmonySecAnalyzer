---
name: harmony-webview-audit
description: v2 (混合智能双轨方案) — WebView 专项高能审计。继承 Ability/IPC 传递的 Warm-Start 级联上下文，深度审计 JS Bridge Native 暴露面与 URL 拦截器绕过风险，输出端到端拼接漏洞报告。
---

# harmony-webview-audit v2 (混合智能双轨版)

专职于 **Track 2 Stage 2 (WebView specialized audit)** 的核心引擎。

本 Skill **彻底剥离了冗余的外部 Entry/DeepLink 参数解析逻辑**。它通过**“热启动” (Warm Start)** 机制，直接承接 Stage 1 (Ability) 或 IPC 阶段输出的 Warm-Start 级联上下文，专注于 WebView 自身的攻击面深度剖析。

---

## 输入

| 数据 | 来源 |
|------|------|
| 项目源码 | 用户提供的 project_path |
| Warm-Start 上下文 | `harmony-webview-warm-start-{path_id}.json` 级联中转文件 |
| 规则知识库 | `skills_v2/harmony-webview-audit/rules/*.json` |
| WebView 领域知识 | `skills_v2/harmony-webview-audit/WEBVIEW_REFERENCE.md` |

---

## 审计流程（四步）

### Step 0：Warm-Start 热启动与上下文加载

1. 读取调度器传入的 `harmony-webview-warm-start-{path_id}.json`。
2. 继承前半段的 `propagation_flow`（包含 Ability 入口、受污变量、跨页面传递 Snippet）。
3. 锁定目标 WebView 的物理位置（由 `webview_sink.file` 与 `webview_sink.line` 标明）。
4. 解析 WebView 的核心安全配置：
   - `javaScriptAccess(true/false)`：若为 false，JS 无法执行，JS Bridge 无法被利用（直接判定漏洞不可达，安全退出）。
   - `fileAccess(true/false)`：沙箱文件本地加载访问权限。

---

### Step 1：逐 JS Bridge 方法分析敏感度

定位 `registerJavaScriptProxy` 的调用位置，阅读 Native 注册对象的所有方法实现。**严禁笼统判定“有 JS Bridge = 敏感”**，必须逐个分析方法 Native 代码的安全性：

```
| 方法名 | Native 实现（读代码） | 是否敏感 | 判定理由 |
|--------|---------------------|---------|---------|
| readFile | fileIo.openSync(path) + readTextSync | 是 | 允许任意读取沙箱内敏感文件，未对 path 做限定 |
| writeFile | fileIo.openSync(path, WRITE) + writeSync | 是 | 允许写入或篡改应用任意沙箱文件 |
| executeSql | db.executeSql(query) | 是 | 允许执行任意 SQL，存在注入/越权操作数据库风险 |
| showToast | promptAction.showToast({ message }) | 否 | 纯 UI 交互，无敏感数据与系统接口调用 |
```

#### 判定标准：
- **高危敏感方法信号**：调用了 `@ohos.file.fs`（文件 IO）、`@ohos.data.relationalStore`（数据库）、`deviceInfo`（系统及设备标识）、`http.createHttp`（可能构成 Native-SSRF）。
- **可调用域评估**：检查 `registerJavaScriptProxy` 的第 5 个参数 `allowedOriginRules`：
  - 若为 `["*"]` 或为空 `[]`：**任意外部域名网页均可调用此暴露的 Native 方法**（高危）。
  - 若有限定域名：检查域名白名单校验是否严密。

---

### Step 2：逐拦截器策略分析安全性 (Filter Bypass Analysis)

若 WebView 关联了以下拦截属性：`onLoadIntercept` / `onUrlLoadIntercept` / `onInterceptRequest` / `onWindowNew`，逐一阅读其过滤策略，评估是否存在绕过可能性：

| 拦截策略代码示例 | 绕过可能性 | 绕过 Payload 示例 | 漏洞原理 |
|---------------|:--------:|-----------------|---------|
| `url.startsWith('https://trusted.com')` | **高** | `https://trusted.com.evil.com` | 仅做前缀文本匹配，未校验 Host 真实边界 |
| `url.includes('example.com')` | **高** | `https://evil.com/example.com` | 仅做子串包含匹配，攻击者可在其域名路径下构造该子串 |
| `/^https?:\/\/trusted\.com/.test(url)` | **高** | `https://trusted.com.evil.com` | 正则未对主机名末尾做边界锚定（应使用 `(?=/|$|:)`） |
| `const u = new Url.URL(url); u.hostname === 'trusted.com'` | **极低** | — | 结构化解析校验，无法通过常规文本混淆绕过 |

---

### Step 3：对照安全规则深入研判 (Lazy Rules Retrieval)

请根据 Step 1 和 Step 2 识别出的高危 Sink 与脆弱拦截逻辑，使用 `grep_search` 在 `rules/` 目录下精准检索并加载匹配规则，避免 context 膨胀：

| 危害类型 | 关联规则编号 | 核心研判要点 |
|---------|:-----------:|------------|
| 拦截器绕过 | WEB-010 | 是否使用 startsWith / includes / 粗糙正则做域名白名单校验？ |
| JS Bridge 越权 | WEB-001 / WEB-003 | 是否将敏感 Native 操作通过 Bridge 暴露？是否缺失 allowedOriginRules 校验？ |
| 沙箱文件越权访问 | WEB-006 | fileAccess 是否非必要开启？Bridge 方法是否提供了任意文件读写？ |

---

### Step 4：端到端缝合与报告输出

将 Stage 1 传递的 `propagation_flow` 与本阶段分析出的 `JS Bridge 可利用危害` 和 `拦截器缺陷` 完美的**端到端缝合**，输出到 `harmony-webview-audit-attack-paths-batch-{i}.json`（若在批量任务中）或独立的 AttackPath 文件。

#### 端到端拼接结构要求：
1. **统一的 flow 编号**：将前半段 flow 与后半段 WebView 执行 flow 整合为一个单调递增的 `flow` 数组。
2. **完整行号代码 Snippet**：每一步必须有真实代码支持，包括 Ability 入口、状态写入、WebView 挂载、JS Bridge 注册、以及具体的 Native 敏感函数执行。

```json
{
  "attack_paths": [
    {
      "id": "WEBVIEW-001",
      "severity": "critical",
      "title": "DeepLink url 参数注入 ➜ 跨页面 AppStorage 状态流转 ➜ WebView 越权加载恶意网页 ➜ JS Bridge 沙箱文件窃取",
      "cases": {
        "bridge_methods": [
          { "name": "readFile", "sensitive": true, "implementation": "fileIo.openSync(path); fileIo.readTextSync(file)", "reason": "未校验路径前缀，允许读取应用沙箱内任意文件" }
        ],
        "interceptors": [
          { "type": "onLoadIntercept", "present": true, "risk": "使用 startsWith 过滤，可被二级域名绕过" }
        ]
      },
      "flow": [
        {
          "step": 1,
          "stage": "入口接收",
          "description": "want.parameters.url 被 EntryAbility 的 onCreate 提取，无包名校验，通过 AppStorage 注入全局状态键名 'webUrl'",
          "file": "EntryAbility.ets:42-45",
          "snippet": "let url = want.parameters?.url as string;\nAppStorage.setOrCreate('webUrl', url);"
        },
        {
          "step": 2,
          "stage": "跨页面状态流转",
          "description": "WebPage.ets 视图文件通过 @StorageLink 读取 webUrl 全局状态变量，并将其绑定至 Web 组件的 src 加载点",
          "file": "WebPage.ets:10-15",
          "snippet": "@StorageLink('webUrl') externalUrl: string = '';\n// ...\nWeb({ src: this.externalUrl, controller: this.ctrl })"
        },
        {
          "step": 3,
          "stage": "JS Bridge 暴露",
          "description": "注册 nativeBridge 且 allowedOriginRules 为空，允许任意页面调用其敏感的 readFile 方法",
          "file": "WebPage.ets:50-52",
          "snippet": "this.ctrl.registerJavaScriptProxy(nativeObj, 'nativeBridge', ['readFile'], [], [])"
        },
        {
          "step": 4,
          "stage": "Native 越权执行",
          "description": "readFile 未对入参路径做白名单拦截，直接执行沙箱文件读取并回传",
          "file": "WebPage.ets:110-115",
          "snippet": "readFile(path: string): string {\n  let file = fileIo.openSync(path);\n  return fileIo.readTextSync(file);\n}"
        }
      ],
      "exploitation": "1. 构造 DeepLink 唤醒 App: context.startAbility({ parameters: { url: 'https://trusted.com.evil.com/exploit.html' } })\n2. EntryAbility 接收并存入 AppStorage('webUrl')。\n3. WebPage.ets 获取此 URL，并通过 onLoadIntercept（startsWith 绕过）加载。\n4. 网页 exploit.html 执行恶意 JS: window.nativeBridge.readFile('/data/storage/el2/base/haps/entry/files/token.txt') 窃取敏感 Token 并外发。",
      "impact": {
        "summary": "任意三方 App 可构造绕过白名单的恶意 URL，注入目标应用 WebView，并通过 JS Bridge 越权窃取其全部沙箱文件。",
        "sensitive_data_exposed": [
          { "data": "应用沙箱内全部文件", "via": "readFile(path)", "example": "token.txt / 敏感数据库配置" }
        ],
        "sensitive_operations": [
          { "operation": "绕过 exported=true 宿主校验执行 Native 方法", "via": "registerJavaScriptProxy 允许任意域调用", "consequence": "实现 XSS ➔ Sandbox RCE" }
        ]
      },
      "remediation": "1. 拦截器使用 new Url.URL() 结构化解析 hostname 并进行绝对等于校验。\n2. allowedOriginRules 白名单中配置绝对合法的受信任域，禁止配置空数组。\n3. 对 Bridge Native 方法实现路径沙箱边界检查（仅允许访问特定子目录）。",
      "matched_rules": ["WEB-001", "WEB-006", "WEB-010"]
    }
  ]
}
```

---

## 重要原则

1. **坚持继承原则**：必须全量继承 Stage 1 生成的入口流，将其前置到漏洞 flow 中以构成端到端的完美攻击链，禁止抛弃前置流程。
2. **严禁在未确认 allowedOriginRules 和拦截器弱点前宣称可利用**：若 `allowedOriginRules` 极其严密且无可绕过的拦截器漏洞，即便 JS Bridge 方法再敏感，也是不可触达的，必须判定为安全。
3. **只做增量追加**：生成最终 JSON 时，要确信 path 级别的 ID 与 warm-start 中传入的 ID 一致，方便 Phase 3 报告聚合器反向缝合。
