---
name: attack-patterns
description: 鸿蒙 ArkTS 攻击链模式卡库。path-finder 做路径发现,path-validator 做反证优先验证时加载,提供链形状路由表与各模式的 source/sink/guard/降级规则。
---

## 用法

1. 状态机以 `audit-orchestration/config/attack_matrix_routes.json` 为机器可执行路由源,编译稀疏 `Entry × Sink × Pattern` 攻击矩阵。
2. path-finder 只消费指定 work item,使用本 skill 对应模式的语义规则分析路径,不得自行增删 seed 或替换 pattern。
3. path-validator 取对应模式的 source/sink/guard/正常业务形态/漏洞成立条件/降级条件/反证规则,做反证优先的六门槛验证。
4. 新增或修改链形状时,必须同步更新本 skill、`knowledge/patterns/` 详细卡与机器路由配置。

候选必须到达产生影响的终态 sink。若一个 seed 只是状态写入/参数转存,且同一条链已有下游危险 seed,只保留下游端到端候选。外部控制被独立 UI 输入或固定值替换后,不能仅凭代码可达晋级。

## 通用结论规则

- 外部可达、敏感 API、调用链存在只说明 exposure/capability/path,不能单独作为漏洞。
- `confirmed_vulnerability` 必须满足六门槛:外部可达、攻击者可控关键参数、到达敏感 sink、guard 缺失/可绕过、违反安全边界、有具体 impact。
- 有效 guard 降级为 `protected_exposure`。
- 预期公开业务能力且未越过安全边界降级为 `benign_business_flow`。
- 缺关键证据降级为 `residual_risk` 或 `insufficient_evidence`。

## 链形状表

本表用于解释语义;启用状态和确定性路由以 `attack_matrix_routes.json` 为准。标记 TODO 的模式会进入 routing gap,不会派发给 path-finder。

| 链形状 | entry.type × seed.category | 模式 |
|---|---|---|
| deeplink/scheme -> 参数 -> SQL/命令注入 | deeplink/implicit_want × sql/command/rce | deeplink-injection |
| 导出 Ability -> Want 参数 -> 文件读写/穿越 | exported_ability/implicit_want × fs/archive | exported-ability-file |
| 外部入口 -> 可达 Web/JSBridge -> 敏感能力 | deeplink/implicit_want/exported_ability/extension_uri × jsbridge/network/fs/command | web-jsbridge |
| Want 重定向 -> 私有组件 | exported_ability × ability_data | want-redirect(TODO) |
| 分布式调用 -> 越权 | exported_ability × distributed | distributed-trust(TODO) |
| DataShare -> 注入/穿越 | exported_ability × provider | datashare-inject(TODO) |
| 解压/动态加载 -> 路径穿越/任意代码 | exported_ability × archive/rce | archive-load(TODO) |
| 公共事件 -> 受保护动作 -> 泄露 | exported_ability × ability_data/network | common-event(TODO) |

## 单模式路由(按信号)

| 观察信号 | 模式 |
|---|---|
| 导出 Ability 配 skills/uris,解析 want.uri 进 SQL/命令 | deeplink-injection |
| 导出 Ability/ExtensionAbility,Want 参数进文件路径 | exported-ability-file |
| Manifest 入口经 Atlas 可达 Web 组件,且 javaScriptProxy 暴露项目方法 | web-jsbridge |

## 模式规则

### deeplink-injection

- **匹配**:导出 Ability 配 `skills[].uris[]`,`onNewWant`/`onCreate` 解析 `want.uri`/`want.parameters` 进 SQL/命令/动态加载。
- **source**:`want.uri` 的 query/path 段;`want.parameters`;`want.entity`。
- **sink**:`executeSql`/`query` 拼接;`process.run`;NAPI `system`/`popen`/`exec` 拼接;动态 `import` 不可信路径。
- **正常业务形态**:deeplink 打开公开页面/详情页/登录页/支付页;外部参数只作为业务对象 ID、路由名、展示参数、固定枚举或服务端授权查询条件。
- **漏洞成立条件**:外部参数控制 SQL 片段、命令片段、动态加载路径或高危开关;未参数化/未净化/guard 可绕过;效果超出公开业务授权。
- **有效 guard**:URI scheme/host/path 精确白名单且在解析和 sink 前生效;SQL 参数化绑定;命令参数数组化且无 shell 拼接;输入枚举化;服务端/本地权限校验约束数据所有权。
- **降级条件**:参数只进入正常业务路由或公开对象查询;已参数化;白名单不可绕过;只能触发预期页面跳转或只读公开数据。
- **反证重点**:`want.uri` 是否只选择业务对象;是否存在参数化查询;白名单是否校验 scheme/host/path 且无 `pathStartWith` 绕过;sink 参数是否来自常量/枚举/净化后值。
- **分析重点**:`aa start -d` 的 query 是否流向 `executeSql` 拼接;前缀匹配能否被 `../` 绕过;`trace(forward)` from `onNewWant` 到 sink;中间有无 sanitize。

### exported-ability-file

- **匹配**:导出 Ability/ExtensionAbility(`exported=true`),`onCreate`/`onConnect`/`onRequest`/`onNewWant` 处理 Want 参数进文件操作/DataShare。
- **source**:`want.parameters` 的 `path`/`filename`/`uri`/`dir`;`want.uri` 解析路径段;`onRequest` parameters。
- **sink**:`fs.write`/`read`/`delete`/`unlink`/`mkdir` 可控路径;`fs.open` 可控路径;DataShare 文件操作;zip 解压可控路径(zip-slip)。
- **正常业务形态**:导出组件接收文件名、媒体 uri 或业务附件 ID,只访问应用授权目录、用户选择文件或公开缓存。
- **漏洞成立条件**:外部参数控制完整路径/父目录/解压目标/删除目标;可穿越目录、覆盖敏感文件、读取非授权文件或写入可执行/配置位置。
- **有效 guard**:路径 `normalize`/canonical 后再校验目录前缀;文件名白名单而非完整路径透传;扩展名/MIME/大小校验;使用系统 picker 授权 uri;写入目录固定且不可由外部改变。
- **降级条件**:路径来自常量或内部映射;外部只控制业务 ID;规范化和目录限制在 sink 前不可绕过;操作仅限公开缓存/临时文件且无敏感影响。
- **反证重点**:是否先 normalize 再校验;是否存在 `../`、绝对路径、软链接、zip-slip 绕过面;sink 是否使用可控路径的危险部分。
- **分析重点**:`../` 路径穿越;任意文件读写;沙箱外写入;`trace(forward)` from Ability 入口到 fs,路径参数可控且无 normalize guard。

### web-jsbridge

- **匹配**:从 Manifest 外部入口经 Atlas 项目内调用/依赖可达 `Web` 组件,其 `loadUrl` 加载来源或 `registerJavaScriptProxy`/`javaScriptProxy` 暴露方法形成 Web 边界。
- **source**:`Web loadUrl(url)` 不可信页面;JS 调 bridge 方法时传入的参数;`onControllerAttached`/`javaScriptOnDocumentStart` 等回调注入。
- **sink**:bridge 方法内调 fs/命令/敏感数据/原生 API;`loadUrl` 不可信 url(`file://`、`javascript:`、intent scheme);`eval` JS 不可信内容;bridge 方法 `startAbility` 转发可控 Want。
- **正常业务形态**:WebView 只加载可信业务域或本地受控页面;JSBridge 为可信页面提供受限业务能力;bridge 参数再次校验并绑定当前用户/会话。
- **漏洞成立条件**:攻击者可控制 WebView 加载来源或注入 JS;来源校验缺失/可绕过;恶意页面可调用 bridge 敏感方法;bridge 参数进入文件/命令/隐私/Ability 转发等 sink 并越权。
- **有效 guard**:loadUrl 前对 scheme/host/path 做严格 allowlist;禁止 `file:`/`javascript:`/不可信重定向;bridge 只在可信页面注册或按 origin 校验;bridge 方法参数与权限二次校验;危险 Web 配置关闭。
- **降级条件**:URL 来源不可被外部控制;allowlist 覆盖真实加载 URL 且不可绕过;bridge 只读无副作用;bridge 参数不控制敏感 sink;敏感方法有独立鉴权。
- **反证重点**:白名单是否校验真实 URL 而非原始字符串;是否处理重定向、大小写、编码、子域、用户信息、混合 scheme;bridge 注册是否绑定可信 origin;敏感方法是否只对可信页面可见。
- **分析重点**:bridge 方法清单(名+参数);bridge 是否调 fs/命令/敏感 API 且参数来自 JS;`loadUrl` url 是否外部可控(deeplink -> loadUrl);`trace(callers)` of bridge 方法看 JS 入口能否触达。

## 待补模式

want-redirect / distributed-trust / datashare-inject / archive-load / common-event -- 遇到对应链形状时新增规则。
