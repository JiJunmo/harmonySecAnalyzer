# HarmonyOS 综合安全审计测试 APP 设计

## 1. 文档用途

本文档用于指导改造 `HarmonyAppAnalyzerDemo`，目标是在一个可安装、可操作的 HarmonyOS
APP 中覆盖 harmonySecAnalyzer 当前启用的 12 项审计能力，并观察 1 项尚未启用能力的表现。

本文档属于测试标准答案，不应放入被审计 APP 仓库。正式盲测前，被测仓中不得保留
`PLAN.md`、漏洞清单、预期结论或其他能够泄露答案的材料。

## 2. 总体目标

测试 APP 命名为“协作空间”，提供搜索、文档、网页工作台、通知跳转、DataShare 数据
访问、备份服务和自动化任务等正常业务。

测试 APP 必须满足：

1. 所有用例位于同一个 HAP。
2. 每条缺陷路径都从真实外部入口到达真实终态 API。
3. 每项当前能力至少有一条缺陷路径和一条独立安全对照。
4. 安全与缺陷路径不通过外部可控的 `mode=safe/unsafe` 切换。
5. 不使用日志、返回 `true`、拼接但不执行等方式模拟 Sink。
6. 所有文件、数据库和 IPC 操作仅影响 APP 测试目录与测试数据。
7. 源码、组件名、方法名、注释和 UI 不出现“漏洞”“安全模式”“Unsafe”等答案式文本。

## 3. 设计原则

### 3.1 独立路径

安全对照和缺陷路径可以在同一个组件中，但必须由不同且固定的业务路由、URI 或
Transaction Code 进入。攻击者不能通过一个 `mode` 参数关闭校验。

例如：

- `/search/archive` 使用历史搜索实现。
- `/search/catalog` 使用结构化查询实现。

两个路径应调用不同的业务方法，不能在同一方法内根据 `mode` 分支。

### 3.2 真实入口

只有下列来源可以作为测试入口：

- Manifest 导出的 Ability 与 Deeplink/Want。
- DataShare Extension 的 `query`、`openFile` 等系统回调。
- Service Extension 发布的 RemoteObject Transaction。
- Common Event Subscriber 收到的事件。

APP 首页按钮只用于方便人工触发，不能成为唯一调用入口。

### 3.3 真实 Sink

缺陷路径必须调用真实终态 API，例如：

- `RdbStore.querySql`
- `fileIo.openSync`、`fileIo.unlinkSync`
- `WebviewController.loadUrl`
- `registerJavaScriptProxy` 后的真实文件或数据操作
- `UIAbilityContext.startAbility`
- DataShare `query/openFile`
- `RemoteObject.onRemoteMessageRequest` 下游的文件或数据操作

### 3.4 中性命名

推荐业务命名：

- `ArchiveSearchAbility`
- `CatalogSearchAbility`
- `AttachmentPreviewAbility`
- `PartnerPortalAbility`
- `WorkspaceProvider`
- `BackupServiceExtension`

禁止命名：

- `UnsafeSearchAbility`
- `VulnerableProvider`
- `safeQuery`
- `testSqlInjection`

## 4. 业务与组件架构

```text
协作空间 APP
├── EntryAbility                         # 首页和正常业务入口
├── ArchiveSearchAbility                 # 历史知识库搜索
├── CatalogSearchAbility                 # 新版目录搜索
├── AttachmentPreviewAbility             # 外部附件预览
├── SharedDocumentAbility                # 工作区文档预览
├── PartnerPortalAbility                 # 合作方网页入口
├── SupportCenterAbility                 # 官方帮助中心
├── WorkspacePortalAbility               # 带 Native Bridge 的网页工作台
├── NotificationRelayAbility             # 通知目标转发
├── NotificationCenterAbility            # 固定通知场景映射
├── AdminConsoleAbility                  # 私有敏感组件，exported=false
├── WorkspaceDataShareExtension          # 查询、文件与账户数据
├── BackupServiceExtension               # 对外备份 IPC 服务
└── AutomationEventManager               # 由 EntryAbility 生命周期管理的动态公共事件订阅
```

## 5. Manifest 设计

### 5.1 UIAbility

| 组件 | exported | 外部入口 | 用途 |
|---|---:|---|---|
| `EntryAbility` | true | Launcher | 首页并管理 CommonEvent 订阅生命周期，不直接实现 Sink |
| `ArchiveSearchAbility` | true | `collab://search/archive` | SQL 注入路径 |
| `CatalogSearchAbility` | true | `collab://search/catalog` | SQL 安全对照 |
| `AttachmentPreviewAbility` | true | `collab://attachment/open` | 文件路径缺陷 |
| `SharedDocumentAbility` | true | `collab://document/open` | 文件安全对照 |
| `PartnerPortalAbility` | true | `collab://portal/partner` | 外部 URL 导航 |
| `SupportCenterAbility` | true | `collab://portal/support` | Web 导航安全对照 |
| `WorkspacePortalAbility` | true | `collab://portal/workspace` | JSBridge 测试 |
| `NotificationRelayAbility` | true | `collab://notice/relay` | Want Redirect |
| `NotificationCenterAbility` | true | `collab://notice/open` | Want 安全对照 |
| `AdminConsoleAbility` | false | 无 | 被重定向的私有敏感组件 |

### 5.2 ExtensionAbility

以下组件必须声明在 `extensionAbilities`，不能放在普通 `abilities` 中。

| 组件 | type | exported | 必须实现 |
|---|---|---:|---|
| `WorkspaceDataShareExtension` | DataShare 对应类型 | true | 真实 `query`、`openFile` 回调 |
| `BackupServiceExtension` | Service 对应类型 | true | `onConnect` 返回 RemoteObject |

组件类必须继承对应的 DataShare/Service Extension 基类。

`AutomationEventManager` 是普通业务类，不声明为独立 Ability/Extension。`EntryAbility.onCreate`
创建并注册订阅者，`EntryAbility.onDestroy` 退订并释放；这样可证明订阅在真实 APP 生命周期中
成立，避免存在源码但订阅永远没有注册。

## 6. 数据准备

APP 首次启动时创建以下无害测试数据：

```text
filesDir/
├── inbox/
│   ├── welcome.txt
│   └── release-note.txt
├── shared/
│   ├── public-guide.txt
│   └── team-roadmap.txt
├── backups/
│   ├── snapshot-a.json
│   └── snapshot-b.json
└── private/
    └── account-profile.json
```

数据库包含：

- `articles(id, title, content, category)`
- `documents(id, name, owner_id, local_path, visibility)`
- `accounts(id, owner_id, display_name, contact)`

所有测试删除、读取和恢复操作只能针对上述目录和测试表。

## 7. 当前能力测试用例

### T01 历史知识库搜索

**能力：** `CAP-INJ-001`

**入口：**

```text
collab://search/archive?keyword=<external>
```

**缺陷路径：**

```text
ArchiveSearchAbility.onCreate/onNewWant
→ 读取 Want URI keyword
→ 拼接 SELECT ... LIKE '%keyword%'
→ RdbStore.querySql(sql)
```

不得只打印 SQL，必须实际调用 `querySql`。

**安全对照：**

```text
collab://search/catalog?keyword=<external>
→ CatalogSearchAbility
→ RdbPredicates.like 或绑定参数
→ RdbStore.query(...)
```

**正常业务：** 固定文章 ID 使用 `equalTo(id)` 查询。

### T02 外部附件预览

**能力：** `CAP-FS-001`

**入口：**

```text
collab://attachment/open?name=<external>
```

**缺陷路径：**

```text
AttachmentPreviewAbility
→ 读取 name
→ filesDir + "/inbox/" + name
→ fileIo.openSync(path, READ_ONLY)
```

允许 `../` 改变最终文件目标，但测试数据应限制在 APP 沙箱内。

**安全对照：**

```text
collab://document/open?id=<external>
→ 根据固定文档 ID 查数据库
→ 获取服务端保存的文件名
→ canonical/normalized path 必须位于 filesDir/shared
→ fileIo.openSync
```

MIME 白名单只能作为附加校验，不能替代路径范围校验。

### T03 合作方网页导航

**能力：** `CAP-WEB-001`

**入口：**

```text
collab://portal/partner?url=<external>
```

**缺陷路径：**

```text
PartnerPortalAbility
→ 读取外部 url
→ 传递给页面
→ WebviewController.loadUrl(url)
```

WebView 不注册 JSBridge，使该用例只表达导航边界。

**安全对照：**

```text
collab://portal/support?article=<external>
→ article 只能映射到固定路径
→ 固定 https scheme 和精确 host
→ 对重定向后的最终 URL 再校验
→ loadUrl
```

**正常业务：** 固定 `resource://rawfile/help.html`，不注册 Bridge。

**能力认证变体：**

- `host-substring`：使用 host 子串判断，使 `trusted.example.attacker.test` 可进入带应用会话的 Web 上下文。
- `decode-order`：先校验原始字符串、后解码并加载，解码后目标可变为本地资源 scheme。
- `redirect-gap`：只校验初始合作方 Origin，重定向后的最终目标不复验且仍携带应用特权上下文。
- `isolated-browser`：允许任意公开网络 URL，但不携带应用会话、特权 header、本地资源或 Native Bridge；预期为正常业务。
- `redirect-unresolved`：最终目标和依赖内策略无法由 Atlas 解析；预期为证据不足，不得猜测漏洞或安全。

每个变体都应使用独立业务函数和稳定路由参数，便于 `/audit capability CAP-WEB-001` 对根因、
控制组件和最终分类做确定性比对；不要通过复制多个 Ability 制造入口噪声。

### T04 Web 工作台 Native Bridge

**能力：** `CAP-WEB-002`

**入口：**

```text
collab://portal/workspace?url=<external>
```

**缺陷路径：**

```text
WorkspacePortalAbility
→ 外部 URL 加载完成
→ registerJavaScriptProxy
→ exportDocument(name)
→ filesDir/shared/name
→ fileIo.openSync
```

Bridge 必须包含至少一个真实敏感 Native 操作。只记录日志、返回版本号或在 WebView 内执行
JavaScript 不足以构成该能力的终态 Sink。

**安全对照：**

- 最终 Origin 必须是精确允许的 scheme/host/port。
- Bridge 只在可信页面完成校验后注册。
- 方法使用固定白名单。
- `exportDocument` 使用文档 ID 映射，不接受任意路径。
- 导航到其他 Origin 时移除或禁用 Bridge。

导航控制和 Bridge 暴露是两个独立根因，审计器可以分别报告。

**能力认证变体：**

- `persistent-after-navigation`：在可信页注册 Bridge，之后导航到不可信 Origin，但 Bridge 未撤销且仍可调用敏感方法。
- `native-authorization`：不可信 Origin 可以调用 Bridge，但 Native 方法独立校验用户会话、对象所有权和参数；预期为有效防护。
- `method-allowlist-only`：仅暴露固定敏感方法，但方法参数可选择任意对象且没有所有权授权；预期仍为漏洞。
- `readonly-local`：固定本地页只暴露语言、主题、版本 getter，没有敏感 source 或副作用 sink；预期为正常业务。
- `registration-unresolved`：依赖封装导致最终 Origin、注册时机或跨导航撤销关系不可解析；预期为证据不足。

每个敏感变体必须绑定稳定的 bridge object、method、registration callsite 和真实 Native sink，
不能只通过增加 `javaScriptProxy` 文本制造测试命中。

### T05 通知目标转发

**能力：** `CAP-ICC-001`

**入口：**

```text
collab://notice/relay
参数：bundleName、moduleName、abilityName、resourceId
```

**缺陷路径：**

```text
NotificationRelayAbility
→ 从外部参数构造 Want target
→ 原样转发 resourceId
→ UIAbilityContext.startAbility(want)
```

`AdminConsoleAbility` 设置为 `exported=false`，并根据 `resourceId` 执行删除测试草稿等敏感业务。

**安全对照：**

```text
collab://notice/open?scene=workspace
→ scene 映射到固定 Ability
→ 只转发该场景允许的固定参数
→ startAbility
```

`windowStage.loadContent` 和 `router.pushUrl` 不能代替该用例的组件 Want 调度。

**能力认证变体：**

- `dynamic-target-operation`：外部 nested Want 同时控制目标 Ability 和敏感 operation，目标未重新授权；预期为漏洞。
- `fixed-target-sensitive-parameter`：目标 Ability 固定，但外部 `operation/resourceId` 被整包或逐项透传到受保护操作；预期仍为漏洞。
- `caller-without-object-authorization`：代理只验证 caller TokenId，目标未校验 `resourceId` 所有权；预期仍为漏洞，根因是对象授权缺失而非身份绕过。
- `reconstructed-authorized`：目标由不可变映射选择，新建 Want 仅复制参数白名单，目标再校验操作权限与对象所有权；预期为有效防护。
- `public-internal-route`：固定内部组件仅展示公开对象，无受保护操作；预期为正常业务。
- `wrapper-unresolved`：依赖封装隐藏目标映射、转发字段或目标授权；预期为证据不足，不能猜测私有影响。

每个变体必须真实调用 `startAbility*`，并保留可追踪的入口参数、Want 构造、目标 Ability 和目标业务操作；
目标选择与参数转发是两个独立控制维度，不能只通过切换 `abilityName` 制造差异。

### T06 DataShare 查询

**能力：** `CAP-PROVIDER-001`

**入口：** `WorkspaceDataShareExtension.query`

**缺陷 URI：**

```text
datashare:///workspace/records/archive?filter=<external>
```

**缺陷路径：**

```text
query callback
→ 从 URI/Predicates 提取 filter
→ 拼接 SELECT
→ RdbStore.querySql
→ 返回 ResultSet
```

**安全 URI：**

```text
datashare:///workspace/records/catalog?filter=<external>
```

使用结构化 Predicates/绑定参数，并限制 projection、order、limit 等结构属性。

### T07 DataShare 文件访问

**能力：** `CAP-PROVIDER-002`

**入口：** `WorkspaceDataShareExtension.openFile`

**缺陷 URI：**

```text
datashare:///workspace/files/raw/<external-path>
```

**缺陷路径：**

```text
openFile callback
→ URI path 直接拼接 filesDir/shared
→ fileIo.openSync(path, callerMode)
→ 返回 fd
```

**安全 URI：**

```text
datashare:///workspace/files/item/<document-id>
```

安全实现必须同时验证：

- URI route 精确匹配。
- document ID 映射到服务端保存的文件名。
- canonical path 位于 `filesDir/shared`。
- mode 仅允许业务需要的只读或固定模式。
- 不把“返回文件句柄”本身当成路径安全措施。

### T08 IPC 未授权事务

**能力：** `CAP-IPC-001`

`BackupServiceExtension.onConnect` 返回 `BackupRemoteObject`，后者实现
`onRemoteMessageRequest`。

| Code | 业务 | 设计 |
|---:|---|---|
| 1 | 查询服务版本 | 公开信息，无需授权，正常业务 |
| 100 | 删除测试快照 | 只校验 Interface Token，不校验调用者 |
| 101 | 删除测试快照 | 校验 TokenId、Permission 和业务角色 |

Code 100 的真实路径：

```text
onRemoteMessageRequest
→ readInterfaceToken
→ readString(snapshotId)
→ 根据 ID 映射 filesDir/backups 内文件
→ fileIo.unlinkSync
```

Interface Token 只证明协议身份，不能作为调用者授权。

### T09 IPC 消息字段到敏感操作

**能力：** `CAP-IPC-002`

| Code | 业务 | 设计 |
|---:|---|---|
| 200 | 从路径恢复备份 | 调用者授权有效，但直接使用 MessageSequence 路径 |
| 201 | 从备份 ID 恢复 | 授权有效，检查读取结果、长度和 ID 映射 |

Code 200 的真实路径：

```text
onRemoteMessageRequest
→ 完成真实调用者授权
→ data.readString()
→ fileIo.openSync(messagePath, READ_ONLY)
→ 读取并解析测试备份
```

这里先完成调用者授权，是为了把根因隔离为消息输入校验，而不是再次产生未授权事务。

Code 201 使用固定 snapshot ID 映射、长度限制、读取结果检查和 canonical containment。

### T10 IPC 服务身份代理

**能力：** `CAP-IPC-003`

| Code | 业务 | 设计 |
|---:|---|---|
| 300 | 删除调用方选择的受保护快照 | 未在身份切换前校验 caller、permission 和 snapshot owner |
| 301 | 删除已授权快照 | 切换前绑定原始 TokenId、permission、owner 和固定操作 |

Code 300 的真实路径：

```text
onRemoteMessageRequest
→ 保存调用方提供的 snapshotId
→ IPCSkeleton.resetCallingIdentity()
→ 以服务权限删除对应快照
→ finally 中 restoreCallingIdentity()
```

`restoreCallingIdentity` 只证明身份恢复，不代表此前删除操作已获授权。Code 301 必须在
身份切换前保存原始 caller，并完成 permission、对象所有权和操作范围校验。

### T11 自定义公共事件触发固定操作

**能力：** `CAP-ICC-002`

`EntryAbility.onCreate` 创建 `AutomationEventManager`，后者使用一个独立
`CommonEventSubscribeInfo` 订阅：

```text
collab.automation.PURGE_CURRENT
```

**缺陷路径：**

```text
EntryAbility.onCreate
→ createSubscriber({ events: ['collab.automation.PURGE_CURRENT'] })
→ commonEventManager.subscribe
→ CommonEvent callback
→ SnapshotRepository.deleteCurrentSnapshot()
→ 固定映射 filesDir/backups/snapshot-a.json
→ fileIo.unlinkSync
```

事件数据不参与目标选择，事件一旦到达就执行固定的受保护删除操作。订阅信息不配置
`publisherBundleName` 或 `publisherPermission`，回调中也不执行业务授权。该路径只表达
“不可信发布者可以触发固定受保护操作”，不能与参数注入合并为同一根因。

**安全对照：**

使用另一个订阅者和独立事件：

```text
collab.automation.PURGE_APPROVED
```

对应 `CommonEventSubscribeInfo` 必须同时配置：

- `publisherBundleName = 'com.jihe.neu.AutomationService'`。
- `publisherPermission = 'com.jihe.neu.permission.AUTOMATION_PUBLISH'`。
- `module.json5#definePermissions` 声明该自定义权限的授权方式和可用级别，能够排除普通三方应用。
- callback 在删除前校验固定业务角色和当前账户允许操作的快照。

发布侧 `CommonEventPublishData.subscriberPermissions/bundleName` 不能代替上述订阅侧限制。

**正常业务：**

`collab.automation.REFRESH_PUBLIC` 不限制发布者，但只更新内存中的公开列表刷新标记和 UI，
不读取、删除或修改受保护状态，应判为正常业务而不是漏洞。

### T12 自定义公共事件数据控制敏感参数

**能力：** `CAP-ICC-003`

**缺陷事件：**

```text
collab.automation.IMPORT_RAW
```

**缺陷路径：**

```text
CommonEventData.parameters['filePath']
→ 类型检查为 string
→ DocumentImporter.importFromPath(filePath)
→ fileIo.openSync(filePath, READ_ONLY)
→ 读取 APP 沙箱内测试文件
```

订阅信息不限制发布者，且路径没有 allowlist、固定目录映射或 canonical containment。类型检查
只能证明值是字符串，不能证明路径位于授权范围。测试 payload 仅访问 APP 测试目录。

**安全对照：**

使用独立事件 `collab.automation.IMPORT_SHARED`：

```text
CommonEventData.parameters['documentId']
→ 检查类型、长度和固定 ID allowlist
→ 服务端映射到 filesDir/shared 下的文件名
→ canonical path 必须位于 filesDir/shared
→ fileIo.openSync(path, READ_ONLY)
```

该安全路径可以保持发布者公开，用于单独证明完整的数据与领域约束足以阻止越界；不能通过
外部 `mode` 参数切换到 `IMPORT_RAW` 的实现。

**入口与反例约束：**

- 所有订阅均由 `EntryAbility` 的真实生命周期注册，不能只保留一个从未启动的
  `exported=false` Ability。
- 动态订阅只在 APP 运行且满足前台回调条件时触发，测试步骤应先启动并保持 APP 前台。
- 系统公共事件和 `@ohos.events.emitter` 不属于这两个用例。
- 自定义事件名称全局唯一只避免冲突，不是发布者认证。
- APP 内自发布按钮只能用于功能 smoke；攻击者可达性需要由外部测试发布器验证。

## 8. 尚未启用能力的观察用例

### T13 跨账户数据所有权

**目标能力：** `CAP-PROVIDER-003`

DataShare 使用结构化 Predicates，不存在 SQL 注入，但允许调用者传入任意 `owner_id` 查询
其他账户记录。安全对照从调用者身份推导 owner scope，不采信外部 owner。

当前系统不应把它错误报告为 SQL 注入。理想表现是明确记录未覆盖能力或分析缺口。

## 9. 预期结果矩阵

| 用例 | 缺陷路径预期 | 安全对照预期 |
|---|---|---|
| T01 SQL | confirmed/candidate | protected 或 benign |
| T02 File | confirmed/candidate | protected |
| T03 Web Navigation | confirmed/candidate | protected |
| T04 JSBridge | confirmed/candidate | protected |
| T05 Want Redirect | confirmed/candidate | benign/protected |
| T06 DataShare Query | confirmed/candidate | protected |
| T07 DataShare File | confirmed/candidate | protected |
| T08 IPC Authorization | confirmed/candidate | protected |
| T09 IPC Message | confirmed/candidate | protected |
| T10 IPC Deputy | confirmed/candidate | protected/benign |
| T11 Common Event Trigger | confirmed/candidate | protected/benign |
| T12 Common Event Data | confirmed/candidate | protected/benign |
| T13 Owner | 不应误报为 SQL 注入 | planned capability gap |

## 10. 代码组织建议

```text
entry/src/main/ets/
├── abilities/
│   ├── search/
│   ├── document/
│   ├── web/
│   └── notification/
├── extensions/
│   ├── datashare/
│   └── backup/
├── services/
│   ├── ArticleRepository.ets
│   ├── DocumentRepository.ets
│   ├── PathPolicy.ets
│   └── CallerPolicy.ets
├── pages/
└── model/
```

安全与缺陷方法应分开，但使用正常业务命名，例如：

- `queryArchive` / `queryCatalog`
- `openRawAttachment` / `openSharedDocument`
- `relayNotification` / `openNotificationScene`

## 11. 盲测约束

正式审计版本中必须删除或移出：

- `PLAN.md`
- 本设计文档
- 漏洞编号与预期结果
- `safe/unsafe/vulnerable` 类名和方法名
- “这里存在注入”“测试路径穿越”等注释
- UI 上的安全/不安全模式标签

测试标准答案保存在 harmonySecAnalyzer 仓库或独立测试台账中。

## 12. 实施顺序

1. 修正 Manifest 和 Extension 继承关系。
2. 实现数据库与测试文件初始化。
3. 完成 T01、T02、T03、T05 四类 Ability 路径。
4. 完成 T06、T07 DataShare 回调。
5. 完成 T08、T09、T10 RemoteObject Transaction。
6. 完成 T04 WebView 与 Bridge Origin 控制。
7. 完成 T11、T12 CommonEvent 动态订阅、缺陷路径和独立安全对照。
8. 添加 T13 能力缺口观察项。
9. 移除所有答案式标记，完成外部触发和功能验收。
10. 复制一份干净仓库执行盲测，不在审计后回写被测代码。

## 13. APP 验收清单

- [ ] HAP 可以编译、安装和启动。
- [ ] 每个导出 Ability 可以从外部 Deeplink/Want 触发。
- [ ] DataShare 是真实 Extension，外部客户端可以调用 `query/openFile`。
- [ ] Service 是真实 Extension，外部客户端可以连接并发送 Transaction。
- [ ] 12 条缺陷路径全部到达真实终态 API。
- [ ] 12 条安全路径使用独立、不可被外部关闭的 安全检查。
- [ ] 正常业务路径没有越过安全边界。
- [ ] T13 不会被错误归类为已启用能力。
- [ ] 源码中没有答案式命名、注释和 UI。
- [ ] 被测仓中没有本设计文档和标准答案。
