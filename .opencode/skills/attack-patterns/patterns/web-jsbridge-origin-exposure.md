# web-jsbridge-origin-exposure

## 根因

不可信 Web origin 可调用具体 JSBridge 方法并到达原生敏感能力,突破 origin 与 native capability 边界。

## 必须证明

- 页面实际 origin 可由攻击者控制或进入。
- 可定位 bridge object + method,且该方法下游到达带 `jsbridge` 标签的真实终态 sink。
- JS 参数或调用选择仍控制敏感操作,并产生越权影响。

## 有效反证

- bridge 只在可信 origin 校验后注册并在离开时注销。
- 每次调用复核 origin/会话,敏感方法具有权限、所有权和参数校验。

## 正常业务

固定可信页面使用只读公开 bridge,仅返回主题、语言、版本等非敏感值。

## 禁止推理

- “外部可达 Web + 存在 JSBridge”直接等同于漏洞。
- 把 bridge 注册节点当作终态 sink,或省略具体 method identity。

## 证据要求

最终 origin、注册时序、bridge method、JS 参数 trace、原生终态 sink、独立鉴权与具体 impact。
