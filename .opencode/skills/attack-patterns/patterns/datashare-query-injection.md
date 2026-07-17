# datashare-query-injection

## 根因

DataShare caller 输入控制数据库查询语言结构,而非仅提供查询值。

## 必须证明

- URI/predicates/projection/order/limit 的具体字段到达真实 SQL/RDB 查询参数。
- 攻击者控制字段、运算符、排序、分组、限制或拼接结构。
- 查询效果超过 provider 公开契约。

## 有效反证

- 固定 SQL + 参数绑定或受约束的结构化 predicates。
- URI route、projection、order、limit 精确 allowlist 和入口 permission。

## 正常业务

公开 provider 使用有界业务 ID 查询公开数据,caller 只控制绑定值。

## 禁止推理

- 把 DataShare query、predicate 对象或 attacker-selected value 自动判为注入。
- 将数据所有权越权混入本根因；它属于独立 authorization 能力。

## 证据要求

query entry、结构字段 trace、最终数据库参数、绑定/allowlist guard 与越界查询影响。
