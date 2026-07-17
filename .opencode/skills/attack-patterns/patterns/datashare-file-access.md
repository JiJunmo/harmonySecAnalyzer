# datashare-file-access

## 根因

DataShare caller 控制 URI/path/mode,突破 provider 声明的目录、文件模式、permission 或数据所有权范围。

## 必须证明

- caller URI/path/mode 到达真实文件操作或返回的文件描述符。
- 最终 canonical target 或访问模式超出 provider 分享契约。
- 能说明未授权读取、覆盖、删除或权限扩大的具体影响。

## 有效反证

- read/write permission、精确 URI matcher、canonical fixed-base containment。
- 不可变资源 ID 映射、mode allowlist 和 owner authorization。

## 正常业务

固定公开缓存、媒体文件或只读资源通过有界 ID 分享。

## 禁止推理

- 仅凭实现 `openFile`、调用 `fs.open` 或返回 descriptor 确认漏洞。
- 只检查 URI 字符串或 lexical normalize,不验证真实 canonical target。

## 证据要求

provider URI/permission、path/mode trace、真实文件参数、canonical scope、分享契约与文件影响。
