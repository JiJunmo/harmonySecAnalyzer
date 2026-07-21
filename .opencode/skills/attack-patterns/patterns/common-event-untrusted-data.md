# common-event-untrusted-data

## 根因

自定义 CommonEvent 的 `event/code/data/parameters` 字段未经发布者约束、消息 schema 与领域校验即控制终态 sink 的安全敏感属性。

## 必须证明

- 动态自定义事件订阅与 callback 真实绑定,普通三方发布者可在可达条件下提供事件数据。
- 定位具体 CommonEventData 字段,并以变量 trace 到真实 sink 参数或操作选择器。
- 攻击者控制未被固定映射、内部重赋值或完整领域约束切断,并产生越界影响。

## 有效反证

- 有效 `publisherBundleName/publisherPermission` 排除不可信发布者。
- 类型、长度、范围、枚举、allowlist 及路径/SQL/Want 等领域 guard 覆盖真实 sink 属性。
- 操作对象具有独立业务授权。

## 正常业务

有界事件字段只选择公开对象、固定枚举或公开查询,不访问受保护状态。

## 禁止推理

- 用 callback 与 sink 共现代替字段级 trace,或把事件名唯一性当作认证。
- 用发布侧接收者限制证明事件数据可信,或把公开业务参数控制当作安全边界突破。

## 证据要求

订阅绑定、事件字段来源、field-to-sink trace、发布者 guard、字段与领域校验、真实 sink 参数和具体影响。
