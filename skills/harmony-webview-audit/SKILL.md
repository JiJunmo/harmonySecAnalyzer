---
name: harmony-webview-audit
description: 审计鸿蒙ArkWeb WebView组件安全，逐项检查组件配置、JS Bridge、导航拦截、Cookie/存储安全，输出结构化漏洞发现
---

# harmony-webview-audit

HarmonyOS ArkWeb WebView 安全审计 Skill。**以 AI 代码理解为主**，逐项检查每个 WebView 实例的安全配置和代码逻辑，输出结构化分析报告 + 逐漏洞详细诊断。

## 触发条件

Agent 读取 metadata 后，若以下任一条件为 true 则调度本 Skill：
- `security_surface.has_webview` → true
- `files.capabilities.uses_webview` → true

## 前置输入

| 数据 | 来源 |
|------|------|
| metadata JSON | Phase 1 输出的 `<audit_dir>/harmony-project-parser-findings.json` |
| 项目根路径 | Agent 传递的 project_path |
| 规则知识库 | `skills/harmony-webview-audit/rules/*.json` |
| WebView 领域知识 | `skills/harmony-webview-audit/WEBVIEW_REFERENCE.md` |

## 输出产物

| 文件 | 内容 | 用途 |
|------|------|------|
| `harmony-webview-audit-instances.json` | 所有 WebView 实例列表 + Layer 1 骨架 | 供 agent.md 按实例派发 Task |
| `harmony-webview-audit-analysis-{id}.json` | 单个 WebView 实例的 6 层分析分片 | 最终由聚合器合并 |
| `harmony-webview-audit-analysis.json` | 合并后的完整分析报告 | 供报告生成器使用 |
| `harmony-webview-audit-findings.json` | 按 severity 排序的标准格式发现列表 | 供报告生成器使用 |

> **注意**：每个 WebView 实例的分析是独立的 Task。脚本 `--list-instances` 预填 Layer 1 骨架，AI Task 补充 Layer 2-6 并写分片文件。Phase 3 聚合器负责合并和计数校验。

---

## Step 1: 脚本预处理（agent.md 在派发 Task 前执行）

Agent 在派发 AI Task 之前，先运行脚本获取实例列表和运行配置级检查：

```bash
# 实例发现
python3 <skill_dir>/scripts/webview_auditor.py --list-instances <metadata_path> <project_path> -o <audit_dir>/harmony-webview-audit-instances.json --pretty

# 配置级规则检查
python3 <skill_dir>/scripts/webview_auditor.py <metadata_path> <project_path> -o <audit_dir>/harmony-webview-audit-findings.json --pretty
```

脚本自动完成：
- 搜索所有 .ets 源文件中 WebView 组件使用点
- 提取每个 WebView 的 src URL、安全配置开关、JS Bridge 注册情况
- 预填 Layer 1（组件初始化配置）骨架
- 按 rules/*.json 做配置级和代码级模式匹配，生成初步 findings
- 搜索所有 .ets 源文件中 WebView 相关 API 调用
- 按 rules/*.json 中所有规则做 code_pattern 和 config_pattern 检查
- 检测 `registerJavaScriptProxy` 是否缺少 `allowedOriginRules`
- 检测 `javaScriptAccess`/`fileAccess`/`mixedMode` 等安全开关
- 检测 `onLoadIntercept` 是否仅做简单字符串匹配
- 检测 Cookie 是否缺少 Secure/HttpOnly 属性
- 输出标准 findings.json

---

## Step 2: AI 深入分析单个实例（6 层代码分析模型）

**重要：每次 Task 调用只分析一个 WebView 实例。Agent 会传入该实例的骨架 JSON（含 Layer 1 预填分析）。你只需围绕这一个实例，补充 Layer 2-6。**

### 输入

Agent 传入的实例骨架：
```json
{
  "instance_id": "webview-001",
  "name": "WebView_Index",
  "file": "entry/src/main/ets/pages/Index.ets",
  "src_url": "https://example.com",
  "config_summary": "JS=true, File=true, DOM=true, JSBridge=yes",
  "skeleton": {
    "id": "webview-001",
    "component_name": "WebView_on_Index",
    "layers": [
      {
        "layer": "1-组件初始化配置",  ← 已预填
        "_source": "script"
      }
    ]
  }
}
```

### 2.1 Layer 1 — 组件初始化配置

- 读取 WebView 初始化代码，提取所有 `.set*()` 或属性配置
- 分析以下安全开关的状态：
  - `javaScriptAccess`: JS 是否可执行
  - `fileAccess` / `fileFromUrlAccess`: 文件协议是否开启
  - `mixedMode`: 混合内容策略（All / Compatibility / None）
  - `domStorageAccess` / `databaseAccess`: 存储是否开启
  - `overviewModeEnabled`: 缩略图模式
- 对每个开关写出安全判断（如 `javaScriptAccess: true` 但无 CSP → 高风险）

### 2.2 Layer 2 — JS Bridge 接口层

这是 WebView 审计**最关键的环节**。对每个 `registerJavaScriptProxy` 调用：

1. **识别暴露的方法列表**：从注册代码中提取 methodList
2. **阅读每个 Native 方法的实现**：分析内部操作（纯 UI？文件 IO？数据库？网络？系统 API？）
3. **评估暴露面**：判断是否有不该暴露给 Web 端的能力
4. **鉴权检查**：
   - 是否通过 `allowedOriginRules` 限定了访问来源？
   - Native 方法内是否通过 `controller.getUrl()` 校验了当前页面 origin？
5. **参数校验**：每个方法是否对 JS 传入的参数做了类型/范围/长度校验？
6. **写出整体评估**：暴露面是否危险？攻击者通过 XSS 能造成什么影响？

### 2.3 Layer 3 — 导航拦截器层

对每个拦截回调（`onLoadIntercept` / `onUrlLoadIntercept` / `onInterceptRequest` / `onWindowNew`）：

1. **阅读拦截逻辑**：用何种方式判断 URL 是否安全？
2. **分析绕过可能**：
   - 字符串前缀匹配？→ 可绕过
   - `indexOf` / `includes`？→ 可绕过
   - 正则但不完整？→ 可能绕过
   - 结构化 URL 解析（`new URL()`）？→ 较安全
3. **检查伪协议拦截**：是否拦截了 `javascript:` / `data:` / `file:` 等危险 scheme？
4. **SSRF 检查**（`onInterceptRequest`）：拦截器是否直接 `web.loadUrl()` 外部传入的 URL？

### 2.4 Layer 4 — 资源加载与缓存层

1. **Cookie 安全**：
   - `setCookie` / `saveCookieAsync` 中的 Cookie 字符串是否包含 `Secure`、`HttpOnly`、`SameSite`？
   - 是否在 HTTP 连接上设置了无 `Secure` 属性的敏感 Cookie？
2. **DOM Storage**：
   - `domStorageAccess: true` 时，是否配置了数据清理策略？
3. **数据库**：
   - `databaseAccess: true` 时，不同 WebView 实例是否共享存储空间？

### 2.5 Layer 5 — 弹窗与窗口管理层

- `onWindowNew` 回调中是否无条件返回 `true`？
- 是否对弹窗 URL 做了安全校验？
- 是否有 `window.open` 的防护措施？

### 2.6 Layer 6 — 生命周期与调试层

- `webDebuggingAccess` 是否在非 debug 构建中开启？
- `onPageVisible` 是否为敏感页面做了切后台遮罩？
- `onErrorReceive` 是否向 Web 页面泄露了内部错误信息？

### 2.7 输出分析分片

**保存路径**：`<audit_dir>/harmony-webview-audit-analysis-{instance_id}.json`。**必须使用 Write 工具写入磁盘。**

> 分片文件由 Phase 3 聚合器自动合并为 `harmony-webview-audit-analysis.json`。

---

## Step 3: 对照规则逐条筛查并生成详细诊断

读完代码并完成 6 层分析后，从规则库逐条筛查。**每条匹配的规则都必须生成完整的诊断信息**。

### 3.1 筛查方法

1. **config_pattern 类型**：Step 1 的脚本已完成配置检查，AI 需复核脚本发现并补充上下文
2. **code_pattern 类型**：回溯 Step 2 的 6 层分析，确认规则是否匹配
3. **结合上下文判断 severity**：规则定义的 severity 是默认值，AI 需结合实际代码场景判定最终 severity

### 3.2 每个匹配发现的诊断要求

每条发现（finding）必须包含以下**全部字段**：

| 字段 | 要求 | 说明 |
|------|------|------|
| `id` | 规则 ID + 序号 | 如 `WEB-001-001` |
| `severity` | AI 判定 | 可不同于规则默认值 |
| `title` | 规则标题 | 可结合项目改写 |
| `description` | **针对该项目的具体描述** | 而非模板文字 |
| `webview_instance_id` | 关联的 WebView 实例 ID | 指向 webview_analysis_report.json |
| `layer` | 关联的分析层级 | 如 "2-JS Bridge 接口层" |
| `root_cause` | **根本原因分析** | 解释为什么会存在此漏洞 |
| `attack_scenario` | **攻击场景** | 攻击者如何利用此漏洞的逐步描述 |
| `impact` | **影响评估** | 成功利用后对业务/安全的影响 |
| `evidence` | **关键证据数组** | 多个代码片段，每个含 file/line_range/snippet/description |
| `cwe` | CWE 编号 | 从规则继承 |
| `owasp` | OWASP 编号 | 从规则继承 |
| `remediation` | 可操作的修复建议 | 含具体代码示例 |
| `reference` | 参考文档链接 | 从规则继承 |

### 3.3 判断原则

1. **severity 由 AI 结合实际判定** — `registerJavaScriptProxy` 仅暴露 `showToast` → 降级为 Low
2. **不确定时标注低一级 severity** — 宁可漏报 Low 也不虚报 Critical
3. **发现描述必须具体** — 写 "暴露了 fileIo.openSync 方法" 而非 "暴露了危险方法"
4. **attack_scenario 必须可行** — 描述真实可达的攻击路径
5. **遇到不理解代码时标注"需人工审查"** — 不硬套规则

---

## Step 4: 输出文件

### 4.1 findings_raw.json — 完整诊断

保存到 `<audit_dir>/findings_raw.json`，包含 Step 3 的完整诊断信息：

```json
{
  "_meta": {
    "auditor": "harmony-webview-audit",
    "total_findings": 3,
    "severity_counts": { "critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0 }
  },
  "findings": [
    {
      "id": "WEB-001-001",
      "rule_id": "WEB-001",
      "skill": "harmony-webview-audit",
      "severity": "critical",
      "title": "JS Bridge 暴露文件系统 API",
      "description": "Index.ets 中的 WebView 通过 registerJavaScriptProxy 注册了 nativeObj 对象，该对象暴露了 readFile 和 writeFile 方法。这两个方法内部直接调用了 @ohos.file.fs 的 openSync 和 writeSync，且未做任何调用方身份校验和参数校验。",
      "webview_instance_id": "webview-001",
      "layer": "2-JS Bridge 接口层",
      "root_cause": "开发者将文件 IO 能力直接暴露给 Web 端，未意识到 XSS 攻击可通过 JS Bridge 调用 Native 方法。registerJavaScriptProxy 的 allowedOriginRules 参数未设置，导致任意域的网页均可调用。",
      "attack_scenario": "1. 攻击者发现目标应用 WebView 加载了 https://example.com/page\n2. 通过 XSS 或钓鱼在页面注入恶意 JS\n3. 调用 window.nativeBridge.readFile('/data/storage/el2/base/haps/entry/files/token.txt')\n4. 由于 Native 方法无鉴权和参数校验，直接返回文件内容\n5. 攻击者将窃取的内容通过 fetch 发回自己的服务器",
      "impact": "攻击者可读取应用沙箱内的任意文件（用户 token、数据库文件、配置文件等），导致用户凭证泄露和账户接管。如有 writeFile 方法，攻击者还可写入恶意文件。",
      "evidence": [
        {
          "file": "entry/src/main/ets/pages/Index.ets",
          "line_range": "50-55",
          "snippet": "this.controller.registerJavaScriptProxy(nativeObj, 'nativeBridge', ['readFile', 'writeFile']);",
          "description": "JS Bridge 注册，暴露了文件读写方法，无 origin 限制"
        },
        {
          "file": "entry/src/main/ets/pages/Index.ets",
          "line_range": "10-20",
          "snippet": "readFile(path: string): string {\n  let file = fileIo.openSync(path);\n  let content = fileIo.readTextSync(file);\n  fileIo.closeSync(file);\n  return content;\n}",
          "description": "Native 方法直接调用了文件 IO，无权限校验和参数校验"
        }
      ],
      "cwe": "CWE-749",
      "owasp": "M2",
      "remediation": "1. 移除文件 IO 方法，仅保留 UI 交互方法\n2. 如必须保留，添加 allowedOriginRules: ['https://trusted.example.com']\n3. 在方法入口处校验 controller.getUrl() 的来源\n4. 对 path 参数做路径白名单校验，禁止访问敏感目录",
      "reference": "https://developer.huawei.com/consumer/cn/doc/harmonyos-references/js-apis-webview"
    }
  ]
}
```

### 4.2 harmony-webview-audit-findings.json — 标准格式

将 findings_raw.json 的 findings 数组写入 `<audit_dir>/harmony-webview-audit-findings.json`（结构与 findings_raw.json 相同）。

> **Step 1 脚本输出、Step 2 分析报告、Step 4 findings 文件都必须使用 Write 工具写入磁盘，不可仅在对话中展示。**

---

## 重要原则

1. **AI 必须亲自读源文件**，不能依赖脚本做字符串匹配
2. **6 层分析是思考过程** — 每层至少写 2-3 句实质性分析
3. **JS Bridge 是审计重点** — 必须阅读每个 Native 方法的实现，评估暴露面
4. **诊断信息必须完整** — root_cause / attack_scenario / impact 缺一不可
5. **代码证据精确** — 文件路径、行号、代码原文三者必须一致
6. **severity 由 AI 根据上下文判定** — 规则标注的 severity 是默认值
7. **不确定时降级处理** — 宁可漏报 Low 也不虚报 Critical
8. **所有文件保存到 `<audit_dir>/`** — Agent 会在 Phase 2 创建此目录

---

## 依赖关系

- **上游**: Phase 1 metadata JSON
- **下游**: Phase 3 report_aggregator.py + Phase 4 report-generator

## 脚本文件列表

| 文件 | 职责 |
|------|------|
| `scripts/webview_auditor.py` | 主入口，配置级与代码级模式匹配 |
| `rules/critical.json` | Critical 规则定义 (WEB-001 ~ WEB-002) |
| `rules/high.json` | High 规则定义 (WEB-003 ~ WEB-007) |
| `rules/medium.json` | Medium 规则定义 (WEB-008 ~ WEB-013) |
| `rules/low.json` | Low + Info 规则定义 (WEB-014 ~ WEB-INFO-ALL) |
| `WEBVIEW_REFERENCE.md` | ArkWeb 安全审计参考知识库 |
