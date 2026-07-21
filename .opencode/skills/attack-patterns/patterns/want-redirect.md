# want-redirect

## 根因

外部代理入口将攻击者控制的目标或安全敏感参数转发到组件调度,使其突破 component export、caller permission、对象范围或业务授权边界。

## 必须证明

- 区分攻击者控制完整/nested Want、目标 bundle/module/ability/action/uri,还是仅控制固定目标的 parameters。
- 控制经过 copy/map/rebuild 后仍到达真实 `startAbility*` 调度参数;Want 构造、字段赋值或路由保存不是终态 sink。
- 解析实际目标组件及其 Manifest/export/permission 事实,并绑定目标执行的具体 protected operation。
- 证明代理入口授权范围小于目标最终能力,且调用者影响到达目标操作或对象参数。

## 有效反证

- 入口使用可靠 caller identity 与不可由普通三方获得的 permission,并在调度前生效。
- 目标由不可变映射/精确 allowlist 选择,新建 Want 且只复制该路由允许的字段,不透传 nested Want 或任意 parameters。
- 目标组件重新校验用户会话、操作权限、对象所有权和安全敏感参数;仅检查调用者身份不能替代对象授权。

## 正常业务

固定公开页面、公开详情/登录/支付回调等有界协议路由,外部只选择公开对象 ID,目标虽为内部实现组件但不执行受保护操作。

## 禁止推理

- 仅凭 `startAbility*`、nested Want、目标 `exported=false` 或内部组件身份确认漏洞。
- 把 target allowlist 自动当作 parameter allowlist,或因有 caller TokenId 检查就忽略目标对象与操作授权。
- 未解析实际目标和目标操作时猜测私有能力或具体影响。

## 证据要求
Flow 必须记录调度 API、目标控制模式、解析目标、转发模式、受控字段和目标操作；Validator 必须复核目标事实、参数流、Guard 维度、保护依据、边界与 impact。目标或 wrapper 无法解析时终态为 gap/insufficient evidence。
