# 鸿蒙 ArkTS 攻击链模式卡索引

本文件把代码信号路由到合适的攻击链模式卡。模式卡提供 source/sink/guard/reject 行为规则,供 path-finder 与 path-validator 使用。

## 加载顺序

1. 先从"组合利用链"选择与实际代码行为匹配的最小链。
2. 只加载 1~2 张匹配模式卡,获取 source/sink/guard/reject 规则;路径跨越其他边界时再加载相邻卡。
3. 候选提升前应用可利用性门槛(可达 + 可控 + 深度追踪到 sink + 有 impact)。

模式卡应至少提供:路由信号、非显然 API 行为、或降低误报的闭合条件之一。**模式卡开放可扩展,遇到新的攻击链形状就新增卡片。**

## 组合利用链(鸿蒙)

| 链形状 | 高信号代码行为 | 模式卡 |
|---|---|---|
| deeplink/scheme → 参数解析 → SQL/命令注入 | 导出 Ability 的 onNewWant 解析 want.uri/parameters,进入 executeSql/process | [deeplink-injection](deeplink-injection.md) |
| 导出 Ability → Want.params → 文件读写/路径穿越 | 可控路径进入 fs/DataShare 文件操作 | [exported-ability-file](exported-ability-file.md) |
| 外部入口 → 可达 Web/JS bridge → 敏感能力 | Manifest 入口经 Atlas 可达 Web,不可信页面经 javaScriptProxy 调项目能力 | [web-jsbridge](web-jsbridge.md) |
| 导出 Ability → 转发可控 Want → 私有组件 | 转发可控 Want/extras 到内部组件 | want-redirect (TODO) |
| 分布式调用 → 越权访问 | 分布式 Ability 调用未校验来源 | distributed-trust (TODO) |
| DataShareExtension → 注入/穿越 | 可控 path/query 进入 DataShare | datashare-inject (TODO) |
| 解压/动态加载 → 路径穿越/任意代码 | zip 解压或动态加载不可信路径 | archive-load (TODO) |
| 公共事件 → 受保护动作 → 结果泄露 | 外部 action 触发敏感工作并经结果泄露 | common-event (TODO) |

## 单模式路由

| 观察信号 | 方向 | 模式卡 |
|---|---|---|
| 导出 Ability 配置 skills/uris,解析 want.uri 进 SQL/命令 | deeplink 注入 | [deeplink-injection](deeplink-injection.md) |
| 导出 Ability/ExtensionAbility,Want 参数进文件路径 | 文件读写/穿越 | [exported-ability-file](exported-ability-file.md) |
| Manifest 入口经 Atlas 可达 Web + javaScriptProxy | JS bridge | [web-jsbridge](web-jsbridge.md) |
| 可控 path/query 进 DataShareExtension | Provider 注入/穿越 | datashare-inject (TODO) |
| zip 解压 / 动态 import 不可信路径 | 解压/动态加载 | archive-load (TODO) |
| 分布式 Ability 调用未校验来源 | 分布式越权 | distributed-trust (TODO) |
| 转发嵌套 Want/selector/component 到私有组件 | Want 重定向 | want-redirect (TODO) |
