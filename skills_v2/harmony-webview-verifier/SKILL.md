---
name: harmony-webview-verifier
description: Web 容器与 JSBridge 专家规则库。专职校验 allowedOriginRules、JSBridge 敏感方法暴露及域名拦截器绕过风险。
---

# harmony-webview-verifier

本技能是一个纯粹的无状态规则库工具，专门用于对明确暴露于外部数据流的 WebView 容器及 JSBridge 代码执行终点利用漏洞扫描。

## 📁 目录结构

* `references/`
  * [WEBVIEW_REFERENCE.md](file:///Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer/skills_v2/harmony-webview-verifier/references/WEBVIEW_REFERENCE.md) — WebView 容器安全、JSBridge 绑定及域名拦截校验机制
* `rules/`
  * `webview/` — 包含 WebView/JSBridge 匹配规则集

---

## 🔍 WebView 容器与 JSBridge 安全校验指南 (WebView Check)

**校验重点**：检查 Web 容器的安全参数属性、JSBridge 暴露的方法敏感性，以及域名拦截器拦截深度。

**核对要点**：
1. **白名单域匹配校验**：检查 `registerJavaScriptProxy` 的第 5 个参数 `allowedOriginRules`。如果配置为 `["*"]` 或为空 `[]`，意味着任意外部域的网页都可以调用暴露的方法，属于高危。
2. **JSBridge 暴露方法 analysis**：逐个审查 Native 暴露出的一系列 JavaScript 代理方法。只要发现直接调用了 `@ohos.file.fs` (文件 IO)、`@ohos.data.relationalStore` (数据库) 或发送网络请求的代码，而没有参数沙箱隔离（如任意读写 path 限制），直接判定可利用。
3. **域名拦截器弱校验匹配**：
   - 使用 `startsWith` 校验域名（如 `url.startsWith('https://trusted.com')`）➔ 可被 `https://trusted.com.evil.com` 二级域名劫持绕过。
   - 使用 `includes` 校验域名（如 `url.includes('trusted.com')`）➔ 可在路径或参数中携带该子串绕过（如 `https://evil.com/trusted.com`）。
   - 正则表达式未对 Host 结尾字符做严格锚定（如 `/^https:\/\/trusted\.com/`）➔ 可在 Host 尾部拼接任意字符绕过。
   - 强逻辑校验标准：必须使用结构化解析器（如 `new Url.URL(url)`）提取 `hostname` 后执行全等比对。
