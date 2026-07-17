# ipc-untrusted-message-to-sensitive-sink

## 根因

IPC `MessageSequence.read*` 字段未经完整 schema 与领域约束即控制终态 sink 的安全敏感参数。

## 必须证明

- entry 绑定已发布 Stub 的具体 descriptor/code。
- 可定位具体 read 字段,并以变量 trace 到达具体 sink 参数。
- 攻击者控制在传播中未被固定映射或内部输入替换,且产生越界影响。

## 有效反证

- 字段类型/读取状态、数量、长度、范围、枚举和 allowlist 完整。
- SQL 参数化、canonical path、Ability target 重建等领域 guard。
- 操作对象具有独立业务授权。

## 正常业务

有界业务 ID、枚举或公开内容只影响 IPC 契约允许的对象和操作。

## 禁止推理

- 用“parcel 可控 + 敏感 API 可达”代替参数级 trace。
- 用 interface token 证明 message 字段安全,或把 caller 授权与输入校验合并成一个根因。

## 证据要求

message schema、read symbol/type、read-to-sink trace、真实 sink 参数、字段 guard 和具体 impact。
