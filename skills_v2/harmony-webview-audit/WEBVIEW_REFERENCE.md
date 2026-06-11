# 鸿蒙 ArkWeb (WebView) 安全审计参考知识库

> 基于 HarmonyOS ArkWeb 组件文档和 WebView 安全最佳实践编写，作为 `harmony-webview-audit` Skill 的前置知识库。

---

## 一、ArkWeb 组件概述

### 1.1 什么是 ArkWeb

ArkWeb 是 HarmonyOS 提供的 WebView 组件（`@kit.ArkWeb`），允许应用内嵌入 Web 浏览器引擎，加载和渲染 Web 页面。ArkWeb 支持 JS 执行、DOM 操作、Cookie 管理、资源拦截等完整的浏览器能力。

### 1.2 关键模块

| 模块 | 导入方式 | 说明 |
|------|---------|------|
| webview 控制器 | `import { webview } from '@kit.ArkWeb'` | 核心命名空间 |
| WebviewController | `new webview.WebviewController()` | WebView 实例控制器 |
| WebCookieManager | `webview.WebCookieManager` | Cookie 管理 |
| WebStorage | `webview.WebStorage` | DOM Storage 管理 |
| WebDataBase | `webview.WebDataBase` | WebSQL 数据库管理 |
| WebMessagePort | `webview.WebMessagePort` | Web 消息通道 |

---

## 二、核心安全配置

### 2.1 JavaScript 执行控制

```typescript
// 初始化配置
Web({ src: 'https://example.com', controller: this.controller })
  .javaScriptAccess(true)    // ⚠️ 允许 JS 执行
  .javaScriptAccess(false)   // ✅ 禁用 JS 执行

// 动态控制
this.controller.setJavaScriptAccess(true);
```

### 2.2 文件访问控制

```typescript
Web({ src: $rawfile('index.html'), controller: this.controller })
  .fileAccess(true)              // ⚠️ 允许 file:// 协议
  .fileFromUrlAccess(true)       // ⚠️ 允许网页通过 file:// 访问文件
```

### 2.3 混合内容

```typescript
import { webview } from '@kit.ArkWeb';

Web({ src: 'https://example.com', controller: this.controller })
  .mixedMode(webview.MixedMode.All)           // ⚠️ 允许 HTTP/HTTPS 混合
  .mixedMode(webview.MixedMode.Compatibility)  // 仅允许被动混合内容
  .mixedMode(webview.MixedMode.None)          // ✅ 禁止混合内容
```

### 2.4 DOM Storage 与数据库

```typescript
Web({ src: 'https://example.com', controller: this.controller })
  .domStorageAccess(true)           // ⚠️ 开启 localStorage/sessionStorage
  .databaseAccess(true)             // ⚠️ 开启 WebSQL/IndexedDB
```

### 2.5 setUrlTrustList (可信域名白名单硬拦截)

```typescript
// API 12+ 支持通过系统原生白名单限制 WebView 加载域：
this.controller.setUrlTrustList(["*.trusted.com", "https://example.com"]);
// 若试图加载白名单之外的域名，系统将直接拦截并触发 onLoadIntercept。

// ⚠️ 避坑指南：白名单中禁止配置通配符 "*" 或使用不安全的明文协议，例如：
// this.controller.setUrlTrustList(["*"]); // ❌ 绝对禁用，使白名单完全失效
// this.controller.setUrlTrustList(["http://*.example.com"]); // ❌ 避免使用 http 明文协议
```

---

## 三、JS Bridge（JavaScript Proxy）

### 3.1 注册机制

```typescript
// 注册 JS 对象，Web 端可通过 window.nativeBridge 调用
this.controller.registerJavaScriptProxy(
  nativeObject,                      // Native 对象
  'nativeBridge',                     // JS 端的对象名
  ['method1', 'method2'],            // 暴露的方法列表
  [],                                 // asyncMethodList
  ['https://trusted.example.com']    // ✅ allowedOriginRules: 域白名单，禁止配置为 ["*"] 泛匹配
);
```

### 3.2 安全风险

```
┌──────────────────────────────────────────────────────────┐
│  攻击场景：XSS → 调用 Native 方法 → 窃取文件/数据库/隐私    │
│                                                          │
│  Web 页面 (恶意脚本):                                     │
│    window.nativeBridge.readFile('/data/storage/token.txt')│
│                                    ↓                     │
│  Native 方法 (无鉴权):                                    │
│    readFile(path) { return fileIo.openSync(path); }       │
│                                    ↓                     │
│  结果：攻击者获得 token.txt 内容                           │
└──────────────────────────────────────────────────────────┘
```

### 3.3 安全基线

1. **最小暴露**：仅暴露 UI 交互方法（如 showToast、setTitle），不暴露数据层 API
2. **域白名单**：通过 `allowedOriginRules` 限制 JS Bridge 仅对特定 HTTPS 域可用
3. **参数校验**：所有 Native 方法入口处做参数类型/范围/长度校验
4. **安全调用方验证（防止时序/跳转劫持）**：
   // ❌ 避免使用不安全的 getUrl() 或 getOriginalUrl() 进行域名来源校验，
   // 因为这些 API 返回的是 WebView 窗口当前渲染的 URL，容易在页面重定向或并发调用时产生竞争条件。
   // ✅ 强烈推荐使用：
   const callingUrl = this.controller.getLastJavascriptProxyCallingFrameUrl();
   if (!callingUrl || !isTrustedOrigin(callingUrl)) {
     return; // 拒绝执行敏感操作
   }

---

## 四、导航拦截

### 4.1 三种拦截器

```typescript
// 1. onLoadIntercept — 页面加载前拦截（可阻止导航）
this.controller.onLoadIntercept((event) => {
  const url = event.data.getRequestUrl();
  if (!isAllowedHost(url)) {
    return true;  // 阻止加载
  }
  return false;   // 允许加载
});

// 2. onUrlLoadIntercept — URL 加载拦截
this.controller.onUrlLoadIntercept((event) => {
  const url = event.data.getRequestUrl();
  // 检查是否允许该 URL 加载
});

// 3. onInterceptRequest — 资源请求拦截（可修改响应）
this.controller.onInterceptRequest((event) => {
  const request = event.request;
  // ⚠️ 检查：不要直接 web.loadUrl(request.getRequestUrl())
});
```

### 4.2 常见绕过方式

| 绕过方式 | 示例 |
|---------|------|
| 字符串前缀绕过 | 白名单 `https://trusted.com`，攻击 URL `https://trusted.com.attacker.com` |
| 协议转换 | app 允许 `https://`，攻击者构造 `javascript:` URL |
| 编码绕过 | URL 编码：`https://trusted.com%40attacker.com` |
| 大小写绕过 | `HTTPS://TRUSTED.COM.attacker.com` |
| 302 重定向 | 第一次加载信任 URL，服务端 302 到恶意 URL |

### 4.3 安全基线

使用 URL 解析 API 做**结构化校验**：

```typescript
function isAllowedHost(urlStr: string, allowedHosts: string[]): boolean {
  const url = new Url.URL(urlStr);
  if (url.protocol !== 'https:') return false;  // 仅允许 HTTPS
  return allowedHosts.includes(url.hostname);    // 精确域名匹配
}
```

---

## 五、Cookie 安全

### 5.1 API

```typescript
import { webview } from '@kit.ArkWeb';

const cookieManager = webview.WebCookieManager.getInstance();

// 设置 Cookie
cookieManager.setCookie('https://example.com', 
  'sessionId=abc123; Secure; HttpOnly; SameSite=Strict');

// 获取 Cookie
cookieManager.getCookie('https://example.com');

// 检查是否允许 Cookie
cookieManager.isCookieAllowed();
```

### 5.2 安全属性

| 属性 | 说明 | 安全影响 |
|------|------|---------|
| `Secure` | 仅通过 HTTPS 传输 | 防止明文网络嗅探 |
| `HttpOnly` | JS 不可访问 | 防止 XSS 窃取 Cookie |
| `SameSite=Strict` | 仅同站请求携带 | 防止 CSRF 攻击 |
| `SameSite=Lax` | 顶级导航允许 | 比 Strict 宽松 |
| `SameSite=None` | ⚠️ 跨站携带（必须配合 Secure） | 无 CSRF 防护 |

---

## 六、SSL/TLS 证书校验

### 6.1 自定义证书校验

```typescript
import { webview } from '@kit.ArkWeb';

this.controller.certificateVerification((event) => {
  // ⚠️ 不要直接返回 success！必须实际校验证书
  const cert = event.data.getCertificates();
  
  // 校验证书链、有效期、域名匹配
  if (isValidCertificate(cert)) {
    return webview.CertErrorAction.SUCCESS;
  }
  return webview.CertErrorAction.CANCEL;
});
```

---

## 七、弹窗与窗口管理

### 7.1 onWindowNew

```typescript
this.controller.onWindowNew((event) => {
  const url = event.data.getRequestUrl();
  if (!isAllowedHost(url)) {
    return false;  // 阻止打开新窗口
  }
  // 在白名单内的 URL 允许打开
  return true;
});
```

---

## 八、生命周期与调试

### 8.1 页面可见性

```typescript
this.controller.onPageVisible((event) => {
  if (!event.data.visible) {
    // 应用切后台，对敏感页面做遮罩
  }
});
```

### 8.2 远程调试

```typescript
// 仅 debug 构建开启
webview.WebviewController.setWebDebuggingAccess(true);
```

---

## 九、安全检测模式汇总

### 9.1 关键 API 搜索模式

```
配置相关:
  javaScriptAccess:                    JS 执行开关
  setJavaScriptAccess(
  fileAccess:                          文件访问
  setFileAccess(
  fileFromUrlAccess:                   文件跨域访问
  mixedMode:                           混合内容
  setMixedMode(
  domStorageAccess:                    DOM 存储
  setDomStorageAccess(
  databaseAccess:                      Web 数据库
  setDatabaseAccess(
  overviewModeEnabled:                 缩略图模式
  setUrlTrustList(                     可信域名白名单
  setUrlTrustList:                     可信域名白名单属性

JS Bridge:
  registerJavaScriptProxy(             JS 对象注入
  allowedOriginRules                   域白名单

拦截器:
  onLoadIntercept(                     页面加载拦截
  onInterceptRequest(                  资源请求拦截
  onUrlLoadIntercept(                  URL 加载拦截
  onWindowNew(                         窗口创建拦截

Cookie:
  WebCookie                            Cookie 管理
  setCookie(
  saveCookieAsync(

SSL:
  certificateVerification              证书校验

调试:
  webDebuggingAccess                   远程调试
  setWebDebuggingAccess(

生命周期:
  onPageVisible(                       页面可见性

消息通道:
  WebMessagePort                       安全的消息通道
  createWebMessagePorts(
```

### 9.2 模块导入检测

```
import 模式:
  @kit.ArkWeb                          ArkWeb 模块
  web_webview                          webview 命名空间
  import { webview }                    webview 导入
```

---

## 十、敏感权限与地理位置管理

### 10.1 权限请求拦截器 (onPermissionRequest)

```typescript
Web({ src: 'https://example.com', controller: this.controller })
  .onPermissionRequest((event) => {
    // ⚠️ 避坑指南：严禁未经用户显式确认自动授权！
    // ❌ 不安全做法（静默自动授权）：
    // event.request.grant(event.request.getAccessibleResources());
    
    // ✅ 安全推荐做法（显式授权弹窗）：
    AlertDialog.show({
      title: '权限请求',
      message: `网页正在请求访问: ${event.request.getAccessibleResources().toString()}，是否允许？`,
      primaryButton: {
        value: '拒绝',
        action: () => { event.request.deny(); }
      },
      secondaryButton: {
        value: '允许',
        action: () => { event.request.grant(event.request.getAccessibleResources()); }
      }
    });
  })
```

### 10.2 地理位置授权 (onGeolocationShow)

```typescript
Web({ src: 'https://example.com', controller: this.controller })
  .onGeolocationShow((event) => {
    // ⚠️ 避坑指南：必须弹出确认框，禁止静默自动调用
    // ✅ 安全推荐做法：
    showLocationConsentDialog((agreed) => {
      if (agreed) {
        event.geolocation.invoke(event.origin, true, false); // 允许，不记住选择
      } else {
        event.geolocation.invoke(event.origin, false, false); // 拒绝
      }
    });
  })
```

---

## 十一、Web 侧脚本执行安全 (runJavaScript)

### 11.1 动态注入风险

```typescript
// ⚠️ 避坑指南：避免向网页中直接拼接执行未经校验的外部输入：
// ❌ 存在注入风险（XSS/UXSS）：
this.controller.runJavaScript(`changeUser('${username}')`); // 如果 username 包含 ' + alert(1) + '，会导致任意脚本执行

// ✅ 安全做法：
// 1. 在参数中对特殊字符进行转义和过滤
const safeUsername = sanitizeInput(username);
this.controller.runJavaScript(`changeUser('${safeUsername}')`);
// 2. 或使用 postMessage 发送结构化消息，由 H5 内部逻辑安全解析
```

---

## 十二、跨端消息通信安全 (postMessage)

### 12.1 postMessage 指定 Origin

```typescript
// ⚠️ 避坑指南：发送敏感消息时必须限制接收域的 Origin，禁止使用通配符 "*" 或忽略目标 Origin。
// ✅ 安全推荐做法：
const ports = this.controller.createWebMessagePorts();
// ❌ 不安全：未限制 targetOrigin
this.controller.postMessage("sensitiveData", ports, "*"); 

// ✅ 安全做法：限制特定的接收域名
this.controller.postMessage("sensitiveData", ports, "https://trusted.example.com");
```

---

## 十三、审计策略

| 阶段 | 操作 |
|------|------|
| 配置发现 | 搜索 .ets 文件，定位所有 WebviewController 实例化和配置代码 |
| 配置审计 | 检查 javaScriptAccess/fileAccess/mixedMode/domStorageAccess/setUrlTrustList 等安全开关 |
| JS Bridge 审计 | 分析 registerJavaScriptProxy 暴露的方法，评估暴露面，以及是否使用 getLastJavascriptProxyCallingFrameUrl 验证来源 |
| 拦截器与协议审计 | 分析 onLoadIntercept/onInterceptRequest 实现，评估绕过可能及自定义协议资源过滤安全性 |
| 权限与定位审计 | 检查 onPermissionRequest/onGeolocationShow 是否存在静默自动授权 |
| 跨端通信与注入审计 | 评估 runJavaScript 和 postMessage 调用是否限制 targetOrigin 或拼接动态不可信脚本 |
| Cookie 审计 | 检查 Cookie 配置是否包含 Secure/HttpOnly/SameSite 属性 |
| SSL 审计 | 检查 certificateVerification 是否做实际证书校验 |
| 生命周期审计 | 检查 onPageVisible/onErrorReceive 等回调的安全性 |
