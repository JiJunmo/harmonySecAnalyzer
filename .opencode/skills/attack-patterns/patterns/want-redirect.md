# want-redirect

## 根因

外部入口代理转发 Want,使攻击者突破目标组件不可外部访问、caller permission 或业务授权边界。

## 必须证明

- 外部输入控制目标选择或目标操作使用的安全敏感 extras。
- 该影响到达真实 Ability 调度 API,未被固定映射或参数重建切断。
- 目标执行了超出公开代理入口契约的具体受保护操作。

## 有效反证

- 签名 permission 或可靠 caller TokenId/UID 校验。
- 精确目标 allowlist、不可变映射、重建 Want 且只复制允许字段。
- 目标组件再次执行用户、会话、对象所有权和操作授权。

## 正常业务

固定公开页面路由、外部只选择有界业务 ID、登录/支付回调按公开协议转发。

## 禁止推理

- 仅凭 `startAbility`、nested Want 或目标 `exported=false` 确认代理绕过。
- 把内部实现组件等同于受保护业务能力。

## 证据要求

受控 Want 字段 trace、真实调度 sink、project model 目标组件事实、caller/target/parameter guard 和目标 impact。
