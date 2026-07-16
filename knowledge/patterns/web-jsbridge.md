# 模式:Web 组件 → JS bridge → 原生 sink

## 匹配

Manifest 外部入口经项目内调用或依赖关系可达使用 `Web` 的页面/组件,并通过 `registerJavaScriptProxy` / `javaScriptProxy` 暴露项目对象/方法给 JS。不可信 URL 或 JS 输入经 bridge 触发危险操作。

## source

- `Web` 组件 `loadUrl(url)` 的 url(不可信页面)
- JS 调用 bridge 方法时传入的参数
- `Web` 的 `onControllerAttached` / `javaScriptOnDocumentStart` 等回调注入

## sink(追踪终点,开放)

- bridge 方法内调用 fs / 命令 / 敏感数据 / 原生 API
- `loadUrl` 加载不可信 url(file://、javascript:、intent scheme)
- `eval` JS 不可信内容
- bridge 方法执行 `startAbility` 转发可控 Want

## guard

- URL 白名单(限制 scheme/host)
- bridge 方法参数校验
- 限制 bridge 暴露面(只暴露只读 / 安全方法)
- 禁用危险 Web 配置(如允许 file 域访问)

## reject

- bridge 方法只读、无副作用、不触达敏感数据
- URL 来自可信源(应用内置、非外部可控)
- 暴露的 bridge 方法经严格参数校验且不可绕过

## 分析重点

- 暴露的 bridge 方法清单(列出方法名 + 参数)
- bridge 方法是否调 fs / 命令 / 敏感 API,参数是否来自 JS(可控)
- `loadUrl` 的 url 是否外部可控(deeplink → loadUrl 链)
- atlas `trace(callers)` of bridge 方法,看 JS 入口能否触达
