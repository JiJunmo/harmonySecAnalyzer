# 规则库优化方案

## 背景

当前 `skills_v2` 下 IPC、Ability、WebView 三个审计模块各自维护独立的 `rules/*.json` 文件。经过内容与格式两方面审视，发现若干共性问题需要系统性修复。

---

## 前提：规则库的正确定位

审计引擎是 LLM，不是静态分析器。LLM 读代码时天然做语义理解，不需要先把代码转换成关键字再查表。

真正的安全漏洞几乎都是上下文相关的：
- `getCallingUid()` 存在 ≠ 身份校验有效（可能调用了但忽略返回值）
- `readArrayBuffer` 存在 ≠ 有漏洞（可能后面确实检查了 byteLength）
- `startAbility` 存在 ≠ 能力重定向（target 可能是硬编码的内部组件）

这些判断需要理解代码的**因果关系**，关键字只能检测**共现关系**。用关键字逼近语义判断是结构性缺陷，调参无法根治。

因此规则库的正确定位是：

- **`detection.positive_patterns`**：粗粒度触发器，告诉 AI 去哪里找，**不作为漏洞判定依据**
- **`audit_guide`（新增字段）**：自然语言描述，告诉 AI 命中触发器后应该验证什么、怎么判定是否真的存在漏洞
- **`severity_modifiers`**：结构化的条件降级/升级，把 SKILL.md 里散落的上下文判断收归规则本身

`negative_patterns` 的作用随之收窄：仅用于过滤**明确无歧义的安全情形**（如某配置字段的值确定为 false），不再试图用关键字模拟语义校验。

---

## 一、格式统一

### 1.1 引入 `audit_guide` 字段，取代关键字语义判断

**方案**：每条规则新增 `audit_guide` 字段，用自然语言描述 AI 命中触发器后的完整判定逻辑。`detection` 只保留 `type`、`file_pattern`、`positive_patterns`，删除 `context_patterns`、`context_checks`（两者语义相同但命名不一致，且 SKILL.md 未定义引擎如何处理）。`negative_patterns` 保留但仅用于无歧义的安全过滤。

```json
{
  "id": "IPC-003",
  "severity": "critical",
  "title": "onRemoteMessageRequest 未校验调用方身份",
  "description": "...",
  "detection": {
    "type": "code_pattern",
    "file_pattern": "**/*.ets",
    "positive_patterns": ["onRemoteMessageRequest"]
  },
  "audit_guide": "找到 onRemoteMessageRequest 实现后：1) 检查方法体内是否调用了 getCallingUid() 或 getCallingPid()；2) 若调用了，进一步确认返回值是否被用于条件判断（而非仅打日志）；3) 若服务仅返回固定字符串或无敏感操作，可降级或跳过。判定漏洞成立的条件：有敏感操作 + 无有效身份校验。",
  "severity_modifiers": [...]
}
```

`config_pattern` 类型保留 `config_check` 子对象，不变。

---

### 1.2 所有规则补充 `severity_modifiers`

当前只有 `business_logic.json` 里的规则有条件降级字段，其他文件的上下文判断全靠 SKILL.md 自然语言描述，AI 执行时不稳定。

**方案**：对所有存在上下文相关降级场景的规则，补充结构化的 `severity_modifiers` 字段。`condition` 用自然语言描述场景，`effect` 用枚举值。

```json
"severity_modifiers": [
  {
    "condition": "服务端业务逻辑仅返回固定字符串，无任何敏感数据或操作",
    "effect": "skip",
    "reason": "无敏感操作，该规则不适用"
  },
  {
    "condition": "handler 内已调用 getCallingUid() 且返回值参与了条件判断",
    "effect": "downgrade_one",
    "reason": "已有有效身份校验，风险降低一级"
  }
]
```

`effect` 取值：`skip`（跳过不报）、`downgrade_one`（降一级）、`upgrade_one`（升一级）。

---

### 1.3 规则 ID 重新规范化

当前命名混乱：`IPC-003`、`IPC-010-LOG`、`IPC-010-RETURN`、`IPC-BIZ-001`、`IPC-INFO-ALL` 并存，且 `REFERENCE.md` 中的 ID 与 `rules/` 实现已经漂移。

**方案**：统一格式为 `{MODULE}-{类别前缀}{三位序号}`。

| 类别前缀 | 含义 |
|---------|------|
| 无前缀 | 结构/配置型规则 |
| `B` | 业务逻辑敏感操作（Business） |
| `I` | 信息提示（Info） |

示例：
- `IPC-003` → `IPC-003`（保持，无需改）
- `IPC-010-LOG` → `IPC-010`，`IPC-010-RETURN` → `IPC-011`（释放编号冲突）
- `IPC-BIZ-001` → `IPC-B01`
- `IPC-INFO-ALL` → `IPC-I01`

同步更新 `IPC_REFERENCE.md` 中的规则汇总表，使其与 `rules/` 保持一致。

---

### 1.4 按检测目标重组文件，而非按 severity 分割

当前按 `critical/high/medium/low` 分文件，导致 AI grep 到一个 API 关键字后需要扫描所有文件才能获得完整规则视图。`business_logic.json` 内部又跨 severity，与其他文件分类维度不一致。

**方案**：改为按检测目标分文件，每个模块统一采用以下结构：

```
rules/
├── config.json       # 针对 module.json5 的配置项检测
├── handler.json      # 针对核心处理函数的代码检测（IPC handler、onCreate 等）
├── data.json         # 数据读写校验类检测
├── lifecycle.json    # 连接/组件生命周期类检测
├── business.json     # 业务操作敏感性检测（原 business_logic.json）
└── info.json         # 信息提示类（原混在 low.json 末尾的 info 条目）
```

每条规则保留 `severity` 字段，severity 的区分在规则内部体现，不再用文件名体现。

---

### 1.5 三模块规则库结构对齐

当前 Ability 模块只有 `critical.json` 和 `high.json`，缺少 `medium`、`business`、`info` 层；WebView 和 IPC 的 `low.json` 末尾混入 `info` 条目。

**方案**：按 1.4 的文件结构对齐三个模块。Ability 补充 `business.json`（覆盖参数流向低危 sink 的分级场景）和 `info.json`（检测到 UIAbility 使用的信息提示）。

---

## 二、内容修复

### 2.1 删除无效的 negative_patterns 条目

以下条目在真实代码中不可能出现，必须删除：

| 规则 | 问题条目 | 原因 |
|------|---------|------|
| `IPC-BIZ-010` | `"path traversal sanitized"` | 自然语言，不是代码关键字 |
| `WEB-002` | `"white"` | 匹配范围过宽，会命中注释 |
| `WEB-003` | `"Content-Security-Policy"` | CSP 在服务端响应头设置，ETS 代码中不会出现 |

---

### 2.2 修复过宽的 positive_patterns

以下 pattern 几乎在所有相关文件中都存在，提供零区分度，需缩窄：

| 规则 | 问题 pattern | 修复方案 |
|------|------------|---------|
| `IPC-009` | `"RemoteObject"` | 改为要求 `"getInstance"` 与 `"RemoteObject"` 同时出现（移入 `context_window_patterns`） |
| `ABILITY-001` | `"onCreate"`, `"onNewWant"` | 这两个 pattern 单独存在无意义，删除；只保留 `"startAbility"` 作为触发点，`"want.parameters"` 移入 `context_window_patterns` |
| `ABILITY-002` | `"onCreate"`, `"onNewWant"` | 同上，只保留 `"terminateSelfWithResult"` 作为触发点 |

---

### 2.3 合并重复规则

`WEB-007`（high）和 `WEB-010`（medium）均检测 `registerJavaScriptProxy` 缺少 origin 鉴权，职责重叠。

**方案**：合并为一条规则，用 `severity_modifiers` 区分两种场景：

```json
{
  "id": "WEB-007",
  "severity": "high",
  "title": "JS Bridge 暴露的方法未限制调用域",
  "detection": {
    "type": "code_pattern",
    "file_pattern": "**/*.ets",
    "positive_patterns": ["registerJavaScriptProxy"],
    "negative_patterns": ["allowedOriginRules", "getUrl(", "getOriginalUrl(", "origin"]
  },
  "severity_modifiers": [
    {
      "condition": "bridge_methods_are_ui_only",
      "effect": "downgrade_one",
      "reason": "暴露的方法仅为 UI 交互（showToast 等），无系统 API 调用"
    }
  ]
}
```

删除原 `WEB-010`。

---

### 2.4 调整 IPC-005 严重级别

`IPC-005`（IPC 数据传输未经加密，当前 medium）在 HarmonyOS 同设备沙箱模型下实际威胁有限，与 critical/high 级别规则并列会干扰审计优先级判断。

**方案**：降为 `low`，并在 `description` 中注明"仅在系统应用或跨设备场景下风险显著"。

---

### 2.5 Ability 补充 medium 级业务规则

当前 Ability 规则库缺少对"参数流向低危 sink"的覆盖，导致审计只能发现 critical/high 漏洞，遗漏中等风险场景。

建议在 `business.json` 中补充两条 medium 规则：

- **ABILITY-B01**：外部 want 参数流向 `hilog.info` 日志打印（信息泄露，medium）
- **ABILITY-B02**：外部 want 参数流向固定 UI 展示但无内容过滤（XSS-like，medium）

---

### 2.6 修复 `reference` 字段

当前 IPC 模块 90% 的规则 `reference` 指向同一顶层文档页，无增量价值。

**方案**：`reference` 改为双字段：

```json
"reference": {
  "internal": "IPC_REFERENCE.md#3.2",
  "external": "https://developer.huawei.com/consumer/cn/doc/harmonyos-references/js-apis-rpc#onremotemessagerequest"
}
```

`internal` 指向本地 REFERENCE.md 的具体章节，`external` 尽量指向华为文档的具体 API 锚点而非总览页。

---

## 三、实施优先级

| 优先级 | 改动项 | 影响范围 |
|--------|-------|---------|
| P0 | 删除无效 negative_patterns（2.1） | 3条规则，直接减少漏报/误报 |
| P0 | 合并 WEB-007 与 WEB-010（2.3） | 消除重复报告 |
| P1 | 各规则补充 audit_guide 字段（1.1） | 全部规则文件，将判定逻辑从 SKILL.md 迁入规则自身 |
| P1 | 收窄无效 positive_patterns（2.2） | IPC-009、ABILITY-001/002，减少无意义触发 |
| P1 | 所有规则补充 severity_modifiers（1.2） | 将 SKILL.md 自然语言降级判断结构化 |
| P2 | 规则 ID 重新规范化（1.3） | 需同步更新 REFERENCE.md 汇总表 |
| P2 | 按检测目标重组文件（1.4） | 三模块全部 rules/ 目录重构 |
| P2 | 调整 IPC-005 级别（2.4） | 单条规则改动 |
| P3 | Ability 补充 medium 规则（2.5） | 新增两条规则 |
| P3 | 修复 reference 字段（2.6） | 全部规则文件，工作量大但优先级低 |
