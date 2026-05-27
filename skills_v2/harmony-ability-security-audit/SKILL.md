---
name: harmony-ability-security-audit
description: v2 (混合智能双轨方案) — 审计对外暴露的 UIAbility 边界防卫与参数流向追踪。发现 Ability 重定向与敏感信息回传漏洞，若发现参数流向 WebView，输出 Warm-Start 上下文级联触发 WebView 专项审计。
---

# harmony-ability-security-audit v2 (混合智能双轨版)

审计鸿蒙应用中**对所有三方应用开放的 UIAbility**（`exported=true`、非系统权限守卫），担任 **Track 2 Stage 1 (UIAbility Guard & Flow Tracing)** 的核心引擎。

它的核心职责是：
1. **入口防卫审计**：对 `onCreate(want)` / `onNewWant(want)` 进行统一的安全过滤（包名校验、重入防绕过、自定义权限校验）。
2. **跨页面/状态数据流追踪**：使用 **GitNexus 语义索引**追踪受污参数流向。
3. **分流与级联触发**：
   - **分支 A (Ability 闭环)**：若流向 `context.startAbility` (能力重定向) 或 `terminateSelfWithResult` (信息回传泄露)，对照规则深入研判并输出 `harmony-ability-security-audit-attack-paths-*.json`。
   - **分支 B (级联唤醒 WebView)**：若流向 WebView 组件，**不直接进行 WebView 审计**，而是输出 **Warm-Start WebView Task Context** 文件（命名为 `harmony-webview-warm-start-{path_id}.json`），由 Phase 2 调度器自动热启动触发 WebView 专项审计。

---

## 前置条件

Phase 1 已发现的外部入口（`type=exported_ability`）和组件终点。

---

## 输入

| 数据 | 来源 |
|------|------|
| 项目源码 | 用户提供的 project_path |
| UIAbility 列表 | Phase 1 entries.json 中 `type=exported_ability` 的条目 |
| 规则知识库 | `skills_v2/harmony-ability-security-audit/rules/*.json` |
| UIAbility 领域知识 | `skills_v2/harmony-ability-security-audit/ABILITY_REFERENCE.md` |

---

## 审计流程（四步）

### Step 1：双向链路追踪与校验分析 (Top-Down & Bottom-Up Hybrid)

你必须理清从公开 Ability 被外部唤醒到危险操作执行的完整链条，重点检查是否有有效的前置身份校验：

#### 1. 寻找入口与参数读取
定位该 UIAbility 对应的 `.ets` 源码文件（由 `src_entry` 指向），在以下生命周期方法中寻找外部传入的 `Want` 变量捕获点：
* `onCreate(want: Want, launchParam: AbilityConstant.LaunchParam)`
* `onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam)`

#### 2. 轨道一：自顶向下追踪 (Top-Down)
追踪 `want.parameters` 或 `want.uri` 的流向，看它们被赋值给了哪些成员变量、或是如何作为路由参数传递到了前端的 Page 视图。
```
# 使用 GitNexus 追踪 want 参数在 onCreate/onNewWant 的流转
gitnexus_query({query: "want.parameters 往下游变量的赋值与流动"})
```

#### 3. 跨页面状态传递与缝合 (ArkUI State Suture)
由于 ArkTS 的声明式 UI 机制，页面跳转和变量传递通常通过 `AppStorage`/`LocalStorage` 状态共享或 `router` 发生。当传统 AST 断流时，你必须使用以下 GitNexus 查询进行数据流桥接：
- **AppStorage 共享追踪**：若代码调用 `AppStorage.setOrCreate('key', taintedVal)`，立刻运行以下查询：
  `gitnexus_query({query: "查找所有引用了状态键名 'key' 的装饰器声明，如 @StorageLink('key') 或 @StorageProp('key')" })`
- **Router 跳转传递追踪**：若代码调用 `router.pushUrl({ url: 'pages/WebPage', params: { urlParam: taintedVal } })`，立刻定位到 `WebPage.ets` 文件并寻找 `router.getParams()` 中对 `urlParam` 的消费。

#### 4. 关键点防御审计：有无身份校验与重入遗漏？
检查该 Ability 是否存在防御机制：
* **包名白名单校验**：是否调用了 `getCallingBundleName()`（配合 `startAbilityForResult` 启动）？是否对返回的包名进行了校验？
* **生命周期重入一致性审计**：当 `entries.json` 中包含多个提取入口行号时，必须使用 GitNexus 分析 `onCreate` 与 `onNewWant` 下游的校验逻辑。若 `onNewWant` 缺失了 `onCreate` 的包名白名单校验，判定构成高危的**“重入防御缺失绕过”**利用链！

---

### Step 2：判定漏洞利用链类型 (Vulnerability Chain Types)

根据参数的流向和终点（Sink）的属性，判定该 UIAbility 是否构成以下三种高危真实漏洞路径之一：

#### 类型 A：Ability 重定向漏洞（Intent Redirection / Ability Redirection）
* **原理**：公开的 Ability 接受外部传入的嵌套 `Want`，在未核实调用者身份的前提下，直接将其传给 `context.startAbility(nestedWant)` 或 `context.startAbilityForResult(nestedWant)` 启动。
* **判定标志**：有 `startAbility` Sink，且传入的 Want 数据全部或部分可被外部 `want.parameters` 操纵。
* **处理动作**：进入 Step 3 深度审计该 Ability 闭环链条。

#### 类型 B：敏感信息回传泄露（Result Leakage）
* **原理**：公开 Ability 作为组件被其他 App 通过 `startAbilityForResult` 唤起。它在调用 `terminateSelfWithResult(resultWant)` 结束自己并向 Caller 返回数据时，未校验 Caller 身份，直接将用户的敏感数据（Token、文件路径、持久化配置等）写入 `resultWant` 中返回。
* **判定标志**：有 `terminateSelfWithResult` Sink，且回传的数据包含敏感机密。
* **处理动作**：进入 Step 3 深度审计该 Ability 闭环链条。

#### 类型 C：级联 WebView 攻击路径（SSRF / JS Bridge Native Bypass）
* **原理**：外部 want 传入的 URL 或敏感状态，直接流向了 `Web({ src })` 组件加载点。
* **判定标志**：受污数据流流入 WebView 的 `src`（无论是直接赋值还是通过 `@StorageLink` 状态驱动）。
* **处理动作**：**绝不在此 Skill 中直接审计 WebView。** 立刻跳转至输出 “Warm-Start WebView Task Context” 机制。

---

### Step 3：对照安全规则深入研判 (Lazy Rules Retrieval)

结合匹配的特征 API，使用 `grep_search` 在 `rules` 目录下检索具体规则加载，重点关注以下风险模式：

| 风险类别 | 对应规则 | 重点关注 |
|--------|---------|---------|
| 越权 Ability 重定向 | ABILITY-001 | 是否将 `want.parameters` 转换为了新的 `Want` 并启动？ |
| 敏感信息回传泄露 | ABILITY-002 | `terminateSelfWithResult` 是否回传了未加密敏感信息？是否校验了 `getCallingBundleName`？ |
| 本地命令/越权操作 | ABILITY-003 | 外部 want 参数是否流向了 `fileIo` / `relationalStore` 等高危 API？ |
| 弱包名白名单校验 | ABILITY-004 | 校验调用包名时是否使用了 `includes` 或脆弱的前缀正则（可伪造）？ |

---

### Step 4：记录漏洞或输出级联上下文

根据判定结果，执行以下两种动作之一：

#### 动作 1：针对类型 A / 类型 B 闭环漏洞，生成攻击链报告
将分析结果写入 `harmony-ability-security-audit-attack-paths-{path_id}.json`。

```json
{
  "attack_paths": [
    {
      "id": "ABILITY-001",
      "module": "EntryAbility (entry)",
      "severity": "critical",
      "title": "公开 UIAbility 存在能力重定向漏洞 ➜ 任意三方应用可越权调起内部私有组件",
      "ability_details": {
        "name": "EntryAbility",
        "exported": true,
        "caller_verification": "none",
        "has_calling_bundle_check": false
      },
      "flow": [
        {
          "step": 1,
          "stage": "入口",
          "description": "外部 Want 被 EntryAbility 的 onCreate() 接收，参数 redirWant 被提取为 Want 对象，未作任何调用方包名或权限校验",
          "file": "EntryAbility.ets:10-15",
          "snippet": "let redirWant = want.parameters?.redirWant as Want;\nif (redirWant) {\n  this.target = redirWant;\n}"
        },
        {
          "step": 2,
          "stage": "传递与执行",
          "description": "系统使用 this.context.startAbility 启动嵌套的 target Want 导致重定向",
          "file": "EntryAbility.ets:22-25",
          "snippet": "this.context.startAbility(this.target);"
        }
      ],
      "exploitation": {
        "summary": "编写恶意 App，构造包含目标私有 Ability 信息的嵌套 Want，发送给公开的 EntryAbility，受害 App 代为拉起私有组件。",
        "payload": {
          "snippet": "let want: Want = {\n  bundleName: 'com.example.victim',\n  abilityName: 'EntryAbility',\n  parameters: {\n    redirWant: {\n      bundleName: 'com.example.victim',\n      abilityName: 'PrivateAbility',\n      parameters: { admin_action: true }\n    } as Want\n  }\n};\ncontext.startAbility(want);"
        }
      },
      "impact": {
        "summary": "任意三方应用可通过此 Ability 重定向越权访问 App 内部全部非导出组件。",
        "sensitive_operations": [
          { "operation": "绕过 exported=false 限制调起私有组件", "via": "context.startAbility(nestedWant)", "consequence": "可进入管理员或核心敏感设置界面" }
        ]
      },
      "remediation": "校验 getCallingBundleName() 并设置严格包名白名单校验，对传入的 nestedWant 做严格白名单过滤。",
      "matched_rules": ["ABILITY-001", "ABILITY-004"],
      "evidence": [
        { "file": "EntryAbility.ets", "line_range": "10-25", "snippet": "let redirWant = want.parameters?.redirWant as Want; ... this.context.startAbility(this.target);" }
      ]
    }
  ]
}
```

#### 动作 2：针对类型 C (WebView 攻击路径)，输出 Warm-Start 级联上下文
**必须使用 Write 工具将已追踪的前半段流写入磁盘，不可跳过！**
文件名统一为：`harmony-webview-warm-start-{path_id}.json`（存放在 `<audit_dir>/` 下）。

```json
{
  "path_id": "path-003",
  "entry_type": "exported_ability",
  "entry_file": "EntryAbility.ets",
  "tainted_parameter": "want.parameters.url",
  "propagation_flow": [
    {
      "step": 1,
      "stage": "入口",
      "description": "want.parameters.url 被 EntryAbility 的 onCreate 提取，无安全校验，通过 AppStorage 注入全局状态键名 'webUrl'",
      "file": "EntryAbility.ets:42-45",
      "snippet": "let url = want.parameters?.url as string;\nAppStorage.setOrCreate('webUrl', url);"
    },
    {
      "step": 2,
      "stage": "跨页面状态流转",
      "description": "WebPage.ets 视图文件通过 @StorageLink 读取 webUrl 全局状态变量，并将其绑定至 Web 组件的 src 加载点",
      "file": "WebPage.ets:10-15",
      "snippet": "@StorageLink('webUrl') externalUrl: string = '';\n// ...\nWeb({ src: this.externalUrl, controller: this.ctrl })"
    }
  ],
  "webview_sink": {
    "file": "WebPage.ets",
    "line": 15,
    "variable": "this.externalUrl"
  }
}
```

---

## 重要原则

1. **绝对坚持利用链第一原则**：禁止仅凭“缺少 getCallingBundleName 校验”报告漏洞。如果入参未流向 startAbility/terminateSelfWithResult/WebView 等危险 API，视为不可利用，直接跳过。
2. **不允许在本 Skill 中直接推导 JS Bridge 逻辑**：发现 WebView 参数流后，必须通过 **Warm-Start Context** 进行级联中转，将后续的 JS Bridge 评估交由更专业的 `harmony-webview-audit` 执行，实现 cognitive load 解耦。
