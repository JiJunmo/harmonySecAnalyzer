# web-jsbridge-origin-exposure

## 根因

不可信最终 Web origin 可调用具体 JSBridge 方法并到达原生敏感能力,突破 web origin、native capability、data owner 或业务授权边界。

## 必须证明

- 最终页面 origin 不可信或攻击者可进入,并定位 bridge object、具体 method、注册 API 与注册/撤销生命周期。
- 页面可实际调用该 method;仅有对象定义、注册代码或 Web 与 Bridge 共现不成立。
- method invocation 或具体 JS 参数到达带 `jsbridge` 标签的真实原生终态 sink,不能把注册节点当 sink。
- 说明 Native 操作类型、目标参数、调用者影响和文件/数据/命令/组件等具体越权影响。

## 有效反证

- 最终 origin 经精确策略确认后才注册,重定向和后续导航复验,离开可信 origin 时撤销或禁用 Bridge。
- 暴露 method 使用固定最小 allowlist,且敏感方法在 Native 侧独立执行权限、对象所有权和参数约束。
- 独立 Native 授权必须支配真实 sink;只校验 Web origin 不能替代对象范围与业务授权。

## 正常业务

固定可信本地页使用只读最小 Bridge,仅返回主题、语言、版本等公开值,且不存在敏感 source 或副作用 sink。

## 禁止推理

- 将“外部可达 Web + 存在 JSBridge”、Bridge 注册、JavaScript 执行或 method 名称敏感直接等同于漏洞。
- 用初始 URL allowlist 代替最终 origin 与 Bridge 生命周期证明,或忽略跨 origin 导航后仍存活的 Bridge。
- 因有 method allowlist 就忽略参数、对象所有权和独立 Native 授权;也不得为只读公开方法编造影响。

## 证据要求
Operation Group 必须记录 object/method、注册范围、最终 origin、生命周期、调用可达性、Native capability、参数控制和操作；组件分析必须复核 origin/lifecycle/method Guard、保护依据、边界与 impact。关键绑定无法解析时记录 gap/insufficient evidence。
