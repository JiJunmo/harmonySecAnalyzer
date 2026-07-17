# ipc-unauthorized-transaction

## 根因

远端已发布的 IPC transaction 未验证 caller 身份、permission、设备或业务授权即可执行受保护操作。

## 必须证明

- Stub 真实远端发布,entry 绑定 Stub + descriptor + transaction code + publication point。
- caller 可选择该 transaction,且分支到达具体受保护终态操作。
- 授权缺失或可绕过,影响超过公开服务契约。

## 有效反证

- TokenId/UID/permission/签名/设备身份校验支配对应 code 分支。
- transaction allowlist、对象所有权和业务授权在敏感操作前生效。

## 正常业务

任意 caller 均可使用的公开只读、有界 transaction,且不访问受保护状态。

## 禁止推理

- 把 interface token/descriptor 当作 caller authorization。
- 看到 `RemoteObject` 就认为已远端发布,或用其他 code 分支的 guard 保护当前分支。

## 证据要求

publication path、remote reachability、descriptor/code、transaction-to-sink path、caller guard 和未授权 impact。
