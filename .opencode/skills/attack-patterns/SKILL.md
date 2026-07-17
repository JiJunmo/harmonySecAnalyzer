---
name: attack-patterns
description: 攻击路径发现与反证验证的统一判定协议。按 work item 的 pattern 加载 patterns/<pattern>.md 差异卡。
---

## 职责

本 skill 规定“凭什么确认漏洞”,不维护机器路由,也不充当鸿蒙 API 教材。

- 路由、启用状态和 capability identity 以 `audit-orchestration/config/audit_capabilities.json` 为唯一机器配置。
- 领域差异卡固定使用 `patterns/<pattern-id>.md`;不得自行选择相近卡片或替换任务 pattern。
- API 含义、调用关系和变量传播以 project model 与 Atlas 证据为准,不得用卡片文本代替代码事实。

## 加载流程

1. 从任务读取唯一 `capability_id` 与 `pattern`。
2. 加载本 skill 的 `patterns/<pattern>.md`。文件缺失时输出 `analysis_gap`,不得按常识临时创造规则。
3. path-finder 按卡片的“必须证明”和“证据要求”执行五项 admission。
4. path-validator 先检查“有效反证”和“正常业务”,再执行六门槛。

## 全局判定协议

- 外部可达、敏感 API、调用链存在只分别证明 exposure、capability、path,不能单独证明 vulnerability。
- 候选必须到达产生影响的终态 sink;注册、解析、赋值、转存和参数组装默认是 intermediate。
- 攻击者必须控制 sink 的安全敏感属性,或直接选择固定敏感操作;固定映射、内部重赋值和独立用户输入会切断控制。
- `confirmed_vulnerability` 必须同时证明外部可达、攻击者可控、终态 sink、guard 缺失/可绕过、安全边界被突破和具体 impact。
- 有效 guard 为 `protected_exposure`;预期公开且未越界为 `benign_business_flow`;关键事实不可解析为 `insufficient_evidence` 或 `residual_risk`。
- guard 必须在 sink 前生效、支配所有相关路径并校验真实危险属性;名称相似或位于其他分支不算有效。
- finding 按独立根因建立;共享 entry、sink 或发现信号不代表应合并授权、输入校验、origin、路径等不同边界。

## 差异卡契约

每张卡只保留：

- **根因**：该 pattern 唯一表达的安全边界。
- **必须证明**：在全局六门槛之外必须成立的领域事实。
- **有效反证**：足以降级或拒绝的领域 guard。
- **正常业务**：常见但不越界的合法形态。
- **禁止推理**：该领域最容易产生的错误捷径。
- **证据要求**：必须从 project model、Atlas 或代码位置获得的最小证据。

详细正反例属于 `tests/golden/audit_capability_cases.json`,不复制进模式卡。
