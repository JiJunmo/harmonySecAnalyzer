# 模式:导出 Ability → Want 参数 → 文件读写/路径穿越

## 匹配

导出 Ability / ExtensionAbility(`exported=true`),`onCreate` / `onConnect` / `onRequest` / `onNewWant` 处理 Want 参数,其值(路径 / filename / uri)进入文件操作或 DataShare。

## source

- `want.parameters` 的 `path` / `filename` / `uri` / `dir` 等
- `want.uri` 解析出的路径段
- ExtensionAbility 请求参数(`onRequest` 的 parameters)

## sink(追踪终点,开放)

- `fs.write` / `read` / `delete` / `unlink` / `mkdir` 接受可控路径
- `fs.open` 可控路径
- DataShareExtension 文件操作
- zip 解压(`decompress`)到可控路径 → 路径穿越(zip-slip)

## guard

- 路径白名单 / 目录限制(限制在应用沙箱或指定目录)
- 路径规范化(`normalize`)后校验,防 `../` 穿越
- 文件名 / 扩展名白名单

## reject

- 路径来自可信常量
- 不可绕过的目录限制 + 规范化校验在 sink 之前

## 分析重点

- `../` 路径穿越:可控路径是否经规范化校验
- 任意文件读写:外部能否控制写入路径 / 文件名
- 应用沙箱外写入(如分布式文件、公共目录)
- atlas `trace(forward)` from Ability 入口追到 fs 调用,确认路径参数可控且无 normalize guard
