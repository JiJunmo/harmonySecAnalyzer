# ipc-confused-deputy-identity

## 根因

IPC 服务未绑定真实 caller 与授权目标,切换为服务身份后替调用方执行其无权完成的特权操作。

## 必须证明

- entry 绑定真实发布的 Stub、descriptor 与具体 transaction code。
- caller 输入选择特权操作目标,路径经过身份切换并以更高权限到达终态 sink。
- caller、permission 和目标对象授权未在身份切换前完整生效。

## 有效反证

- 身份切换前绑定 calling TokenId/UID、permission 与目标所有权。
- 目标由固定映射重建、delegation 范围有界,且 `finally` 恢复身份。

## 正常业务

已授权 caller 请求固定内部维护操作,服务仅在已批准范围内短暂使用自身身份。

## 禁止推理

- 看到 `resetCallingIdentity` 就确认 confused deputy。
- 把切换后的服务身份检查当作原始 caller 授权,或用 restore 证明操作已获授权。

## 证据要求

publication/code、原始 caller、受控目标、授权顺序、identity transition、特权 sink、权限扩大与 restore 路径。
