# deeplink-injection

## 根因

Manifest 外部输入控制 SQL、命令或动态执行结构,突破查询语言或执行边界。

## 必须证明

- `want.uri`/`want.parameters` 的具体字段到达终态 sink 的结构参数。
- 攻击者控制 SQL/命令/加载结构,而不只是普通值或业务 ID。
- 执行效果超过 deeplink 声明的公开业务能力。

## 有效反证

- SQL 参数绑定、无 shell 拼接的参数数组、固定枚举或不可变映射。
- scheme/host/path guard 支配 sink,且业务对象授权完整。

## 正常业务

打开公开页面、选择公开对象、使用有界 ID 查询或触发声明内的固定业务动作。

## 禁止推理

- 看到 deeplink 与 `executeSql`/`process.run` 共存就确认漏洞。
- 把攻击者可控的绑定值等同于查询结构可控。

## 证据要求

入口候选、Atlas 变量 trace、真实 sink 参数、结构构造方式、guard 位置与具体 impact。
