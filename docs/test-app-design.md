# HarmonyOS 综合安全审计测试 APP 设计

## 1. 文档用途

本文档用于指导改造 `HarmonyAppAnalyzerDemo`，目标是在一个可安装、可操作的 HarmonyOS
APP 中覆盖 harmonySecAnalyzer 当前启用的 9 项审计能力，并观察 2 项尚未启用能力的表现。

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
└── AutomationSubscriber                 # 自动化公共事件订阅
```

## 5. Manifest 设计

### 5.1 UIAbility

| 组件 | exported | 外部入口 | 用途 |
|---|---:|---|---|
| `EntryAbility` | true | Launcher | 首页，不承载测试缺陷 |
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

`AutomationSubscriber` 可以由正常 Ability 生命周期动态注册，不需要伪装成 Extension。

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

## 8. 尚未启用能力的观察用例

### T10 跨账户数据所有权

**目标能力：** `CAP-PROVIDER-003`

DataShare 使用结构化 Predicates，不存在 SQL 注入，但允许调用者传入任意 `owner_id` 查询
其他账户记录。安全对照从调用者身份推导 owner scope，不采信外部 owner。

当前系统不应把它错误报告为 SQL 注入。理想表现是明确记录未覆盖能力或分析缺口。

### T11 公共事件触发受保护操作

**目标能力：** `CAP-ICC-002`

订阅 `collab.automation.RUN`：

```text
CommonEventData
→ action/snapshotId
→ 启动备份或删除测试快照
```

缺陷路径不验证发布权限或可信发布者；安全对照使用受权限保护的独立事件，并限制 action
与参数。仅刷新 UI 的事件作为正常业务。

当前系统不得把普通订阅行为直接确认为漏洞。

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
| T10 Owner | 不应误报为 SQL 注入 | planned capability gap |
| T11 Common Event | 不应仅因订阅而确认 | disabled routing/coverage gap |

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
5. 完成 T08、T09 RemoteObject Transaction。
6. 完成 T04 WebView 与 Bridge Origin 控制。
7. 添加 T10、T11 能力缺口观察项。
8. 移除所有答案式标记，完成外部触发和功能验收。
9. 复制一份干净仓库执行盲测，不在审计后回写被测代码。

## 13. APP 验收清单

- [ ] HAP 可以编译、安装和启动。
- [ ] 每个导出 Ability 可以从外部 Deeplink/Want 触发。
- [ ] DataShare 是真实 Extension，外部客户端可以调用 `query/openFile`。
- [ ] Service 是真实 Extension，外部客户端可以连接并发送 Transaction。
- [ ] 9 条缺陷路径全部到达真实终态 API。
- [ ] 9 条安全路径使用独立、不可被外部关闭的 Guard。
- [ ] 正常业务路径没有越过安全边界。
- [ ] T10/T11 不会被错误归类为已启用能力。
- [ ] 源码中没有答案式命名、注释和 UI。
- [ ] 被测仓中没有本设计文档和标准答案。
