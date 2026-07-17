# exported-ability-file

## 根因

导出 Ability/Extension 输入控制文件目标,突破应用目录、URI 授权、文件完整性或数据所有权边界。

## 必须证明

- 外部 path/filename/URI/archive entry 到达真实文件读写删或解压目标。
- 控制覆盖危险路径部分,并能访问授权范围外的具体目标。
- 当前不是带 `datashare_file` 标签的 provider 根因。

## 有效反证

- canonical 后固定目录 containment、文件名 allowlist、不可变资源映射。
- system picker URI grant、MIME/大小限制和目标所有权授权。

## 正常业务

固定公开缓存、用户授权文件、应用导出目录或外部只选择有界资源 ID。

## 禁止推理

- 看到导出组件调用 `fs` 就确认任意文件访问。
- 用 lexical normalize 或字符串前缀代替 canonical containment 证据。

## 证据要求

外部字段到文件参数的 trace、最终 canonical scope、操作类型、guard 支配关系与可访问目标影响。
