# common-event-unauthorized-trigger

## 根因

动态订阅的自定义 CommonEvent 未限制可信发布者或业务授权,事件到达即可触发固定受保护操作。

## 必须证明

- `createSubscriber` 信息、`subscribe` 调用与 callback 真实绑定,事件为自定义事件。
- 动态订阅在应用运行/前台条件下可触发,事件到达选择或触发具体受保护终态操作。
- 普通三方发布者未被有效排除,且影响超过事件的公开业务契约。

## 有效反证

- `publisherBundleName` 精确限制可信包,或普通三方不可获得的有效 `publisherPermission`。
- callback 在操作前执行真实调用方等价授权、对象所有权或业务授权。

## 正常业务

自定义事件只触发公开 UI 刷新、公开有界同步或不访问受保护状态的通知处理。

## 禁止推理

- 把唯一事件名、系统事件、Emitter 或发布侧 `subscriberPermissions/bundleName` 当作订阅侧发布者认证。
- 仅因存在订阅和敏感 API 就确认漏洞,或忽略动态订阅生命周期。

## 证据要求

自定义事件名、注册与 callback 绑定、动态可达条件、发布者限制、callback-to-sink 路径、业务边界和具体影响。
