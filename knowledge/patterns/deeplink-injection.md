# 模式:deeplink / scheme → 参数解析 → SQL/命令注入

## 匹配

导出 Ability 配置 `skills[].uris[]`(scheme/host/path),`onNewWant(want)` / `onCreate(want)` 解析 `want.uri` 或 `want.parameters`,其值进入 SQL 拼接、命令执行或动态加载。

## source

- `want.uri`(scheme://host/path?query) 的 query / path 段
- `want.parameters`(key-value)
- `want.entity` / 其他 Want 字段

## sink(追踪终点,开放)

- `relationalStore.executeSql` / `query` 拼接不可信输入
- `process.run`、NAPI 调 `system` / `popen` / `exec` 拼接
- 动态 `import` 不可信路径、插件加载

## guard

- URI scheme/host/path 白名单校验(注意 `pathStartWith` 等前缀匹配的绕过)
- SQL 参数化(参数绑定而非拼接)
- 输入净化/转义

## reject(不提升为发现)

- `want.uri` 来自可信常量、非外部可控
- 已用参数化查询,无拼接
- 不可绕过的白名单在 sink 之前拦截

## 分析重点

- `aa start -d <uri>` 的 query 参数是否流向 `executeSql` 的字符串拼接
- 前缀匹配校验(`pathStartWith`)能否被 `../` 或构造绕过
- 参数解析中间是否有 helper,atlas `trace(forward)` from `onNewWant` 追到 sink
- 中间节点是否有 sanitize(guard),无则确认 taint 可达
