# harmony-webview-audit 设计实现方案

> **状态**: 🟡 设计中 | **优先级**: P3 | **依赖**: harmony-project-parser (metadata)

## 一、设计思路

鸿蒙应用的 WebView（`@kit.ArkWeb`）安全审计，遵循与 IPC Skill 相同的两层架构：

1. **配置级审计**：解析 ArkWeb 组件的初始化配置，检查 `javaScriptAccess`、`fileAccess`、`mixedMode` 等安全开关
2. **代码级审计**：AI 阅读源文件，逐项检查 JS Bridge 注入、URL 拦截、Cookie 安全、SSL 校验等逻辑

**核心原则**：脚本做机械的配置提取和模式搜索，AI 做深度逻辑理解（如判断拦截器逻辑是否安全、JS Bridge 是否有注入风险）。

### 与其他 Skill 的边界

| 边界 | 归属 |
|------|------|
| WebView 的网络请求安全（SSL 校验、明文传输） | **network-audit** 负责 |
| WebView 中传输的硬编码密钥 | **secrets-audit** 负责 |
| WebView 页面中 SQL/JS 注入 | **code-quality-audit** 负责 |
| ArkWeb 组件配置 + JS Bridge + URL 拦截安全 | **本 Skill 负责** |

---

## 二、检测能力总览

共规划 **18 条审计规则**，覆盖 4 个攻击面维度。

### 2.1 攻击面总览

```
┌─────────────────────────────────────────────────────────────┐
│                     ArkWeb 安全攻击面                          │
├──────────────┬──────────────┬──────────────┬─────────────────┤
│ 组件配置安全  │ JS Bridge 安全│ 导航拦截安全  │ 数据存储安全     │
│ (5 规则)     │ (5 规则)     │ (5 规则)     │ (3 规则)        │
├──────────────┼──────────────┼──────────────┼─────────────────┤
│ javaScript   │ registerJS   │ onLoad       │ Cookie 配置     │
│ Access       │ Proxy 注入   │ Intercept    │ 与泄露          │
│              │              │              │                 │
│ fileAccess   │ JS Object    │ onIntercept  │ localStorage/   │
│              │ 暴露范围     │ Request 篡改  │ sessionStorage  │
│              │              │              │ 明文存储         │
│ mixedMode    │ JS→Native    │ onUrlLoad    │                 │
│              │ 参数注入     │ Intercept    │ DOM Storage     │
│ HTTPS Only   │              │ 绕过        │ API 滥用        │
│              │ Native→JS    │              │                 │
│ overviewMode │ 消息伪造     │ shouldOverride│                 │
│ 信息泄露     │              │ UrlLoading   │                 │
│              │ 跨域 JS      │              │                 │
│ certVerify   │ Bridge       │ window.open  │                 │
│ 证书校验     │ 白名单缺失   │ 弹窗管控     │                 │
└──────────────┴──────────────┴──────────────┴─────────────────┘
```

### 2.2 规则分级

#### Critical（2 条）

| ID | 标题 | 检测要点 |
|----|------|---------|
| WEB-001 | `registerJavaScriptProxy` 注入可执行任意系统 API 的对象 | JS Proxy 暴露了敏感原生能力（如文件读写、数据库操作），攻击者可通过 XSS 调用这些方法 |
| WEB-002 | `onInterceptRequest` 未校验外部 URL 即加载 | 拦截器无条件 `loadUrl` / `loadData` 任意传入 URL，可导致 SSRF 或任意网页加载 |

#### High（5 条）

| ID | 标题 | 检测要点 |
|----|------|---------|
| WEB-003 | `javaScriptAccess: true` 未限制 | JS 执行开启但未配合 CSP 或沙箱策略 |
| WEB-004 | `fileAccess: true` 同时 `fileFromUrlAccess: true` | 允许 Web 内容通过 `file://` 协议访问本地文件 |
| WEB-005 | `mixedMode: MixedContentMode.Allowed` | 允许 HTTPS 页面加载 HTTP 资源，导致中间人攻击 |
| WEB-006 | `onLoadIntercept` 逻辑可被绕过 | 拦截器仅判断 URL 前缀或存在正则绕过，未做完整校验 |
| WEB-007 | JS Bridge 暴露未做调用方鉴权 | Native 方法未校验调用来源（origin/URL），任意网页可调用 |

#### Medium（6 条）

| ID | 标题 | 检测要点 |
|----|------|---------|
| WEB-008 | `onUrlLoadIntercept` 缺失 | 未设置 URL 加载拦截，无法阻止导航到恶意站点 |
| WEB-009 | `certificateVerification` 关闭或自定义 X509 信任所有证书 | SSL 证书校验被绕过 |
| WEB-010 | JS Bridge 对象允许跨域访问 | 未通过 `allowedOriginRules` 限制 JS Bridge 的访问来源 |
| WEB-011 | Web Cookie 未设置 `SameSite` / `Secure` / `HttpOnly` | Cookie 配置不安全，可被 CSRF 或 XSS 窃取 |
| WEB-012 | `overviewModeEnabled: true` 且加载外部 URL | 缩略图模式下 WebView 在后台可能被恶意利用 |
| WEB-013 | `window.open` / `onWindowNew` 未做弹窗管控 | 恶意页面可无限弹窗或导航到钓鱼页面 |

#### Low（4 条）

| ID | 标题 | 检测要点 |
|----|------|---------|
| WEB-014 | `webDebuggingAccess` 在 release 构建中开启 | WebView 远程调试在生产环境未关闭 |
| WEB-015 | Web 存储 `domStorageAccess: true` 未限制 | DOM Storage 开启但无容量限制或数据清理策略 |
| WEB-016 | `onPageVisible` 回调未做敏感页面的可见性处理 | 应用切后台时 WebView 敏感页面仍可见 |
| WEB-017 | `databaseAccess: true` 未限制 | WebSQL/IndexedDB 开启但无数据隔离策略 |

#### Info（1 条）

| ID | 标题 | 检测要点 |
|----|------|---------|
| WEB-INFO-ALL | 项目使用了 ArkWeb 组件 | 通知性质，提醒审计人员关注 WebView 安全 |

---

## 三、配置级审计（脚本实现）

### 3.1 检测原理

`module.json5` 和 `app.json5` 中不直接包含 WebView 配置。ArkWeb 的安全配置主要在 `.ets` 源文件中的 `WebviewController` 初始化参数中。

因此"配置级审计"实际上是对 `.ets` 源文件中 `new WebviewController()` 及其附近代码进行**结构化参数提取**。

### 3.2 脚本职责

`webview_auditor.py` 脚本职责：

1. 读取 Phase 1 的 metadata JSON
2. 定位所有使用了 `@kit.ArkWeb` 或 `web_webview` 的 `.ets` 源文件
3. 搜索以下关键 API 调用，提取配置参数：
   - `new web_webview.WebviewController()`
   - `.setJavaScriptAccess(` / `javaScriptAccess:`
   - `.setFileAccess(` / `fileAccess:`
   - `.setMixedMode(` / `mixedMode:`
   - `.setOverviewModeEnabled(`
   - `.setDomStorageAccess(`
   - `.setDatabaseAccess(`
   - `registerJavaScriptProxy(`
   - `onLoadIntercept(` / `onInterceptRequest(` / `onUrlLoadIntercept(`
   - `onWindowNew(`
   - `webDebuggingAccess`
4. 提取每个配置项的值（true/false/字符串），生成结构化摘要
5. 按配置规则筛查，生成 findings

### 3.3 配置级规则定义

```json
{
  "id": "WEB-003",
  "severity": "high",
  "cwe": "CWE-79",
  "owasp": "M2",
  "title": "javaScriptAccess 开启未配合安全策略",
  "detection": {
    "type": "config_pattern",
    "file_pattern": "**/*.ets",
    "positive_patterns": ["setJavaScriptAccess(true)", "javaScriptAccess: true"],
    "negative_patterns": ["Content-Security-Policy", "setSandbox"]
  },
  "remediation": "仅信任的 HTTPS 源启用 javaScriptAccess，并配合 CSP Header 限制脚本来源"
}
```

---

## 四、代码级审计（AI 执行，核心厚度）

### 4.1 6 层 WebView 安全分析模型

不同于 IPC 的 7 层调用链，WebView 安全按**功能维度**分为 6 条分析路线：

```
Layer 1: 组件初始化配置
  → WebviewController 构造 + set* 方法调用链

Layer 2: JS Bridge 接口层
  → registerJavaScriptProxy 暴露的 Native 对象和方法

Layer 3: 导航拦截器层
  → onLoadIntercept / onUrlLoadIntercept / onInterceptRequest 逻辑

Layer 4: 资源加载与缓存层
  → onInterceptRequest + Cookie + DOM Storage + Database

Layer 5: 弹窗与窗口管理层
  → onWindowNew / window.open 处理逻辑

Layer 6: 生命周期与调试层
  → onPageVisible / onPageEnd / webDebuggingAccess 配置
```

### 4.2 每层分析要点

#### Layer 1 — 组件初始化配置

读取 WebView 初始化代码，分析：
- `javaScriptAccess` 是否为 `true`，若为 `true` 是否有 CSP、沙箱、URL 白名单等补偿控制
- `fileAccess` / `fileFromUrlAccess` 是否为 `true`，是否允许文件协议访问
- `mixedMode` 配置（`All` / `Compatibility` / `None`），是否允许混合内容
- `overviewModeEnabled` 是否开启，是否加载外部不可信 URL
- `domStorageAccess` / `databaseAccess` 是否开启

#### Layer 2 — JS Bridge 接口层

这是 WebView 安全中最关键的环节。分析：
- `registerJavaScriptProxy` 注册了哪些对象和方法
- 每个 Native 方法执行了什么操作（文件读写？系统 API？数据库？网络？）
- 是否有**调用方鉴权**（检查 origin / URL 白名单 / CSRF Token）
- 是否有**参数校验**（JS 传入的参数是否在 Native 层做了类型/范围/长度校验）
- **暴露面评估**：是否有不应暴露给 Web 端的系统 API（如 `@ohos.file.fs`、`@ohos.data.relationalStore`）
- 是否通过 `allowedOriginRules` 限制了 JS Bridge 的可访问域

#### Layer 3 — 导航拦截器层

分析拦截器的安全有效性：
- `onLoadIntercept` 返回值逻辑：是否有 URL 白名单/黑名单？正则是否可绕过？
- `onUrlLoadIntercept` 是否仅拦截特定 scheme？是否对 `javascript:` / `data:` / `file:` 伪协议做了拦截？
- `onInterceptRequest` 是否直接 `web.loadUrl(url)` 传入外部可控 URL？（SSRF 风险）
- `shouldOverrideUrlLoading` 处理逻辑是否有绕过可能

#### Layer 4 — 资源加载与缓存层

- Cookie 管理：`webCookie.config()` 是否设置了 `SameSite` / `Secure` 属性
- Cookie 泄露：是否在非 HTTPS 下设置了敏感 Cookie
- DOM Storage / WebSQL / IndexedDB：是否存储了敏感数据明文
- `onInterceptRequest` 是否对加载的资源做了内容校验（防止资源替换攻击）

#### Layer 5 — 弹窗与窗口管理层

- `onWindowNew` 是否阻止了恶意弹窗或导航
- 是否有 `window.open` 白名单
- 是否对弹窗请求中的 URL 做了安全校验

#### Layer 6 — 生命周期与调试层

- `webDebuggingAccess` 在 release 构建中是否关闭
- `onPageVisible` 回调是否做了敏感页面的遮罩或隐藏处理
- `onErrorReceive` 是否泄露了内部错误信息给 Web 页面

### 4.3 AI 分析要求（与 IPC Skill 一致）

每条代码级发现必须包含完整诊断：

| 字段 | 要求 |
|------|------|
| `root_cause` | 根本原因，解释为什么会存在此漏洞 |
| `attack_scenario` | 攻击者可执行的逐步攻击场景 |
| `impact` | 成功利用后的影响评估 |
| `evidence` | 多个代码证据，含 file / line_range / snippet / description |
| `remediation` | 可操作的修复建议，含具体代码示例（ArkWeb API） |

---

## 五、架构

```
┌─────────────────────────────────────────────┐
│  harmony-webview-audit (Skill)              │
│  - 调用脚本提取配置                          │
│  - AI 执行 6 层代码分析                       │
│  - 输出 findings.json + call_chain 类似物     │
└──────────────┬──────────────────────────────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌──────────────┐
│配置级审计│ │代码级审计│ │导航拦截分析   │
│(脚本)   │ │(AI)    │ │(AI+脚本混合)  │
│         │ │        │ │              │
│webview  │ │6层分析  │ │拦截逻辑       │
│_auditor │ │模型    │ │有效性评估     │
│.py      │ │        │ │              │
└────────┘ └────────┘ └──────────────┘
     │          │             │
     └──────────┼─────────────┘
                ▼
    ┌─────────────────────┐
    │  findings_raw.json  │
    │  webview_analysis   │
    │  _report.json       │
    │                     │
    │  harmony-webview-   │
    │  audit-findings.json│
    └─────────────────────┘
```

### 5.1 脚本模块

| 文件 | 职责 |
|------|------|
| `scripts/webview_auditor.py` | 主编排入口，搜索 WebView 配置、提取参数 |
| `rules/critical.json` | Critical 规则定义 (WEB-001 ~ WEB-002) |
| `rules/high.json` | High 规则定义 (WEB-003 ~ WEB-007) |
| `rules/medium.json` | Medium 规则定义 (WEB-008 ~ WEB-013) |
| `rules/low.json` | Low 规则定义 (WEB-014 ~ WEB-017) |
| `WEBVIEW_REFERENCE.md` | ArkWeb 安全审计参考知识库 |

---

## 六、检测规则详解

### 6.1 规则定义格式

```json
{
  "id": "WEB-001",
  "severity": "critical",
  "cwe": "CWE-749",
  "owasp": "M2",
  "title": "registerJavaScriptProxy 注入可执行任意系统 API 的对象",
  "description": "JS Bridge 暴露的对象方法内部调用了文件读写、数据库操作等系统 API，且未校验调用方身份和参数。攻击者通过 XSS 可在 Web 端调用这些方法，实现远程代码执行。",
  "detection": {
    "type": "code_pattern",
    "file_pattern": "**/*.ets",
    "positive_patterns": ["registerJavaScriptProxy"],
    "negative_patterns": ["allowedOriginRules"],
    "context_checks": [
      "检查 Proxy 对象内部是否调用了 @ohos.file.*",
      "检查 Proxy 对象内部是否调用了 @ohos.data.*",
      "检查方法参数是否做了校验",
      "检查是否有限制 origin 的 allowedOriginRules 配置"
    ]
  },
  "remediation": "1. 仅暴露必要的方法给 Web 端 2. 每个方法校验参数类型和范围 3. 通过 allowedOriginRules 限制访问来源 4. 敏感操作添加用户确认",
  "reference": "https://developer.huawei.com/consumer/cn/doc/harmonyos-references/js-apis-webview"
}
```

### 6.2 AI 判断原则

1. **severity 由 AI 结合实际判定** — 例如 `registerJavaScriptProxy` 仅暴露 `showToast` 方法，则降级为 Low
2. **不确定时降级处理** — 宁可漏报 Low 也不虚报 Critical
3. **暴露面评估是核心** — 重点分析 JS Bridge 暴露的能力是否可被恶意利用
4. **证据精确** — 文件路径、行号、代码原文三者必须一致
5. **攻击场景必须可行** — 描述真实可达的攻击路径，不可套用模板

---

## 七、输出产物

| 文件 | 内容 | 用途 |
|------|------|------|
| `webview_analysis_report.json` | 每个 WebView 实例的 6 层分析报告 | 报告中展示思考过程 |
| `findings_raw.json` | 逐漏洞详细诊断（含成因、攻击场景、证据） | 供聚合器使用 |
| `harmony-webview-audit-findings.json` | 按 severity 排序的标准格式发现列表 | 供报告生成器使用 |

### 7.1 webview_analysis_report.json 结构

```json
{
  "_meta": {
    "auditor": "harmony-webview-audit",
    "total_webview_instances": 2
  },
  "webview_instances": [
    {
      "id": "webview-001",
      "component_name": "WebView_on_Index",
      "file": "entry/src/main/ets/pages/Index.ets",
      "overview": "Index 页面的主 WebView，加载外部 HTTPS URL，注册了 JS Bridge",
      "layers": [
        {
          "layer": "1-组件初始化配置",
          "analysis": "...",
          "code_references": [...],
          "issues_identified": [...]
        },
        {
          "layer": "2-JS Bridge 接口层",
          "analysis": "...",
          "code_references": [...],
          "issues_identified": [...]
        }
      ]
    }
  ]
}
```

---

## 八、规则与 CWE/OWASP 映射

| 规则 ID | CWE | OWASP Mobile | 描述 |
|---------|-----|-------------|------|
| WEB-001 | CWE-749 | M2: 客户端注入 | JS Bridge 暴露危险系统 API |
| WEB-002 | CWE-918 | M2: 客户端注入 | 拦截器 SSRF |
| WEB-003 | CWE-79 | M2: 客户端注入 | JS 执行无限制 |
| WEB-004 | CWE-552 | M9: 数据泄露 | 文件协议访问本地文件 |
| WEB-005 | CWE-319 | M3: 不安全通信 | 混合内容 MITM |
| WEB-006 | CWE-602 | M2: 客户端注入 | 拦截器可绕过 |
| WEB-007 | CWE-862 | M5: 授权缺失 | JS Bridge 无鉴权 |
| WEB-008 | CWE-601 | M2: 客户端注入 | URL 重定向未拦截 |
| WEB-009 | CWE-295 | M3: 不安全通信 | SSL 证书校验绕过 |
| WEB-010 | CWE-942 | M5: 授权缺失 | JS Bridge 跨域访问 |
| WEB-011 | CWE-614 | M2: 客户端注入 | Cookie 不安全配置 |
| WEB-012 | CWE-200 | M9: 数据泄露 | 缩略图模式信息泄露 |
| WEB-013 | CWE-1022 | M2: 客户端注入 | 窗口弹窗未管控 |
| WEB-014 | CWE-489 | M8: 代码完整性 | 远程调试未关闭 |
| WEB-015 | CWE-922 | M9: 数据泄露 | DOM Storage 不安全 |
| WEB-016 | CWE-200 | M9: 数据泄露 | 生命周期可见性泄露 |
| WEB-017 | CWE-922 | M9: 数据泄露 | WebSQL 未隔离 |

---

## 九、输入与触发条件

### 9.1 输入

| 数据 | 来源 |
|------|------|
| metadata JSON | Phase 1 输出的 `<audit_dir>/harmony-project-parser-findings.json` |
| `security_surface.has_webview` | metadata 中的攻击面标识 |
| `files.ets_sources` | metadata 中的源文件列表 |
| 规则知识库 | `rules/*.json` |
| ArkWeb 领域知识 | `WEBVIEW_REFERENCE.md` |

### 9.2 触发条件

Agent 读取 metadata 后，若以下任一条件为 true 则调度本 Skill：

```
metadata.security_surface.has_webview == true
metadata.files.capabilities.uses_webview == true
```

当前 `harmony-project-parser` 通过以下方式检测 WebView 使用：
- `module.json5` 中包含 `@kit.ArkWeb` 字符串
- `.ets` 源文件中 import 了 `@kit.ArkWeb`
- `.ets` 源文件中直接使用了 `web_webview`

---

## 十、文件结构

```
skills/harmony-webview-audit/
├── SKILL.md                      # Skill 定义（opencode 用）
├── PLAN.md                       # 本文件
├── WEBVIEW_REFERENCE.md          # ArkWeb 安全审计参考知识库
├── scripts/
│   └── webview_auditor.py        # 配置级审计脚本
└── rules/
    ├── critical.json             # Critical 规则
    ├── high.json                 # High 规则
    ├── medium.json               # Medium 规则
    └── low.json                  # Low + Info 规则
```

---

## 十一、与 Agent 的协作

```
Agent (Phase 2)
  │
  ├─ 检查 metadata.security_surface.has_webview
  │
  ├─ 若 true → dispatch harmony-webview-audit skill
  │   │
  │   ├─ Step 1: 执行脚本
  │   │   python3 webview_auditor.py <metadata_path> <project_path> -o findings.json
  │   │
  │   ├─ Step 2: AI 读取源文件，执行 6 层代码分析
  │   │   → 输出 webview_analysis_report.json + findings_raw.json
  │   │
  │   └─ Step 3: 写入标准格式 harmony-webview-audit-findings.json
  │
  └─ Phase 3 聚合器读取 *-findings.json
```

---

## 十二、扩展性

| 扩展方向 | 方式 |
|---------|------|
| 新增检测规则 | 在对应 severity 的 JSON 文件中添加新 rule 条目 |
| 新增检测类型 | 在 `webview_auditor.py` 中添加对应的搜索函数 |
| 新增代码模式 | 在规则的 `positive_patterns` / `negative_patterns` 中添加 |
| JS Bridge 数据流分析 | 未来可扩展为解析 AST 追踪 Native 方法的数据流 |
| CSP 解析 | 未来可解析 HTML 中的 Content-Security-Policy meta 标签 |

---

## 十三、已知限制

1. **JS Bridge 深度分析依赖 AI**：脚本仅能检测 `registerJavaScriptProxy` 调用，无法判断暴露的对象方法是否危险。需要 AI 阅读方法实现代码来判断
2. **CSP 检测为盲区**：当前不解析 HTML 中的 `<meta http-equiv="Content-Security-Policy">`，仅检查 ArkWeb 的 `setSandbox` 等 API 配置
3. **第三方 WebView 组件**：如果应用封装了自定义 WebView 组件（非直接使用 `web_webview.WebviewController`），脚本可能漏报
4. **运行时动态配置**：如果 WebView 配置由服务端下发或在运行时根据条件动态设置，静态分析无法覆盖
5. **跨文件调用链**：例如 JS Bridge 对象的方法调用了另一个文件中的 `fileIo.open`，脚本无法追踪这种间接调用
6. **不支持 WebView2 / 多实例分析**：一个页面中可能有多于一个 WebView 实例，当前分析粒度为文件级

---

## 十四、后续版本规划

| 版本 | 功能 |
|------|------|
| v1.0 | 配置级脚本 + 6 层 AI 代码分析 + 17 条规则 |
| v1.1 | 增加 CSP 解析能力（解析 HTML meta 标签和 HTTP 响应头） |
| v2.0 | 引入 ArkTS AST 解析，做 JS Bridge Native 方法的数据流追踪 |
| v2.1 | 支持跨文件调用链分析 |
| v3.0 | 动态分析支持（模拟 WebView 沙箱环境执行安全测试用例） |
