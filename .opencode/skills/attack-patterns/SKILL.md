---
name: attack-patterns
description: 鸿蒙 ArkTS 攻击链模式卡库。path-finder 做路径发现、path-validator 做路径验证时加载,提供链形状路由表与各模式的 source/sink/guard/reject 规则。
---

## 用法

1. 先从"链形状表"按 `entry.type × danger_seed.category` 选匹配的最小链。
2. 取对应模式的 source/sink/guard/reject 规则,用于标注路径节点 `stage` 与 `guard_status`。
3. 只取 1~2 个匹配模式;路径跨边界时再取相邻模式。
4. 模式开放可扩展,遇到新链形状就新增(同步更新本 skill 与 `knowledge/patterns/` 详细卡)。

## 链形状表

| 链形状 | entry.type × seed.category | 模式 |
|---|---|---|
| deeplink/scheme → 参数 → SQL/命令注入 | deeplink/implicit_want × sql/command/rce | deeplink-injection |
| 导出 Ability → Want 参数 → 文件读写/穿越 | exported_ability/implicit_want × fs/archive | exported-ability-file |
| Web → JS bridge → 原生 sink | (Web 组件入口) × jsbridge/fs/command/network | web-jsbridge |
| Want 重定向 → 私有组件 | exported_ability × ability_data | want-redirect(TODO) |
| 分布式调用 → 越权 | exported_ability × distributed | distributed-trust(TODO) |
| DataShare → 注入/穿越 | exported_ability × provider | datashare-inject(TODO) |
| 解压/动态加载 → 路径穿越/任意代码 | exported_ability × archive/rce | archive-load(TODO) |
| 公共事件 → 受保护动作 → 泄露 | exported_ability × ability_data/network | common-event(TODO) |

## 单模式路由(按信号)

| 观察信号 | 模式 |
|---|---|
| 导出 Ability 配 skills/uris,解析 want.uri 进 SQL/命令 | deeplink-injection |
| 导出 Ability/ExtensionAbility,Want 参数进文件路径 | exported-ability-file |
| Web 组件 + javaScriptProxy 暴露原生方法 | web-jsbridge |

## 模式规则

### deeplink-injection
- **匹配**:导出 Ability 配 `skills[].uris[]`,`onNewWant`/`onCreate` 解析 `want.uri`/`want.parameters` 进 SQL/命令/动态加载
- **source**:`want.uri` 的 query/path 段;`want.parameters`;`want.entity`
- **sink**:`executeSql`/`query` 拼接;`process.run`、NAPI `system`/`popen`/`exec` 拼接;动态 `import` 不可信路径
- **guard**:URI scheme/host/path 白名单(注意 `pathStartWith` 前缀匹配绕过);SQL 参数化;输入净化
- **reject**:`want.uri` 来自可信常量;已参数化;不可绕过白名单在 sink 前
- **分析重点**:`aa start -d` 的 query 是否流向 `executeSql` 拼接;前缀匹配能否被 `../` 绕过;`trace(forward)` from `onNewWant` 到 sink;中间有无 sanitize

### exported-ability-file
- **匹配**:导出 Ability/ExtensionAbility(`exported=true`),`onCreate`/`onConnect`/`onRequest`/`onNewWant` 处理 Want 参数进文件操作/DataShare
- **source**:`want.parameters` 的 `path`/`filename`/`uri`/`dir`;`want.uri` 解析路径段;`onRequest` parameters
- **sink**:`fs.write`/`read`/`delete`/`unlink`/`mkdir` 可控路径;`fs.open` 可控路径;DataShare 文件操作;zip 解压可控路径(zip-slip)
- **guard**:路径白名单/目录限制;`normalize` 后校验防 `../` 穿越;文件名/扩展名白名单
- **reject**:路径来自可信常量;不可绕过目录限制+规范化在 sink 前
- **分析重点**:`../` 穿越;任意文件读写;沙箱外写入;`trace(forward)` from Ability 入口到 fs,路径参数可控且无 normalize guard

### web-jsbridge
- **匹配**:`Web` 组件 `loadUrl` + `registerJavaScriptProxy`/`javaScriptProxy` 暴露原生方法
- **source**:`Web loadUrl(url)` 不可信页面;JS 调 bridge 方法传入参数;`onControllerAttached`/`javaScriptOnDocumentStart` 回调注入
- **sink**:bridge 方法内调 fs/命令/敏感数据/原生 API;`loadUrl` 不可信 url(`file://`、`javascript:`、intent scheme);`eval` JS 不可信内容;bridge 方法 `startAbility` 转发可控 Want
- **guard**:URL 白名单;bridge 方法参数校验;限制 bridge 暴露面;禁用危险 Web 配置
- **reject**:bridge 方法只读无副作用;URL 可信源;暴露方法经严格校验不可绕过
- **分析重点**:bridge 方法清单(名+参数);bridge 是否调 fs/命令/敏感 API 且参数来自 JS;`loadUrl` url 是否外部可控(deeplink→loadUrl);`trace(callers)` of bridge 方法看 JS 入口能否触达

## 待补模式

want-redirect / distributed-trust / datashare-inject / archive-load / common-event —— 遇到对应链形状时新增规则。
