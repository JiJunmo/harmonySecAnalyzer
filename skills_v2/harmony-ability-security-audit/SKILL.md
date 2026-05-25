---
name: harmony-ability-security-audit
description: v2 — 审计对三方应用开放的 UIAbility 漏洞路径：分析从 want 参数输入到高危 API 执行或能力重定向的全流程，确认漏洞真实可利用性，输出完整利用 Payload
---

# harmony-ability-security-audit v2

审计鸿蒙应用中**对所有三方应用开放的 UIAbility**（`exported=true`、非系统权限守卫），梳理每个 UIAbility 从 `want` 参数输入、参数校验、再到执行具体功能（如启动其他 Ability、返回敏感数据、本地文件读写等）的完整可利用漏洞路径。

## 前置条件

Phase 1 已发现的外部入口（`type=exported_ability`）和组件终点（`sink_type=start_ability`、`sink_type=terminate_result` 或其他高危 Sinks）。

**优先审计路径**：
- 在 `attack_map.json` 中被标记为 `"confidence": "high_verified_ability"` 的路径为**最高优先级**。这些路径直接关联了公开 UIAbility 入口与高危能力启动点，利用成功率极高。

## 输入

| 数据 | 来源 |
|------|------|
| 项目源码 | 用户提供的 project_path |
| UIAbility 列表 | Phase 1 entries.json 中 `type=exported_ability` 的条目 |
| 规则知识库 | `skills_v2/harmony-ability-security-audit/rules/*.json` |
| UIAbility 领域知识 | `skills_v2/harmony-ability-security-audit/ABILITY_REFERENCE.md` |

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

#### 3. 轨道二：自底向上逆向 (Bottom-Up)
如果在中途由于状态机或跨文件路由断流，立刻以 Sinks（如 `context.startAbility`、`terminateSelfWithResult`）为起点向上反查变量来源，在交汇处实现缝合。

#### 4. 关键点防御审计：有无身份校验？
检查该 Ability 是否存在防御机制。在鸿蒙中，UIAbility 没有直接获取调用者包名的 API，只有当使用 `startAbilityForResult` 启动且回传结果时，可以通过 `getCallingBundleName()` 检查 Caller：
* 是否调用了 `getCallingBundleName()`？
* 是否对返回的包名进行了白名单或硬编码域名正则校验？是否可被绕过？
* 该 Ability 在 `module.json5` 里是否被配置了特定的自定义权限守卫？

---

### Step 2：判定漏洞利用链类型 (Vulnerability Chain Types)

根据参数的流向和终点（Sink）的属性，判定该 UIAbility 是否构成以下三种高危真实漏洞路径之一：

#### 类型 A：Ability 重定向漏洞（Intent Redirection / Ability Redirection）
* **原理**：公开的 Ability 接受外部传入的嵌套 `Want`（通常作为 parameters 中的某个 key），在未核实调用者身份的前提下，直接将其传给 `context.startAbility(nestedWant)` 或 `context.startAbilityForResult(nestedWant)` 启动。
* **利用链**：恶意 App 传入一个精心设计的 `nestedWant`（靶向目标为受害 App 内部 `exported: false` 的私有 Ability，或者高权限系统设置 Ability），借用受害 App 的身份越权调起该私有 Ability。
* **判定标志**：有 `startAbility` Sink，且传入的 Want 数据全部或部分可被 `want.parameters` 操纵。

#### 类型 B：敏感信息回传泄露（Result Leakage）
* **原理**：该公开 Ability 是一个专门提供交互、授权或选择的组件（如自定义登录页、文件选择器、支付页），被其他 App 通过 `startAbilityForResult` 唤起。它在调用 `terminateSelfWithResult(resultWant)` 结束自己并向 Caller 返回数据时，未校验 Caller 身份（`getCallingBundleName()` 为空或无校验），直接将用户的敏感数据（Token、文件路径、持久化配置等）写入 `resultWant` 中返回。
* **利用链**：恶意 App 直接启动该 Ability，在 `onAbilityResult` 中坐收回传的敏感数据。
* **判定标志**：有 `terminateSelfWithResult` Sink，且回传的数据包含敏感机密。

#### 类型 C：越权本地高危操作（Unauthorized High-Risk Local Action）
* **原理**：外部 `want.parameters` 传入的值，直接被作为参数流向了本地的沙箱文件读写、数据库 SQL 执行、网络 SSRF 等高危 Sinks，且完全没有合法性与路径白名单限制。
* **判定标志**：有 `file_write`/`database`/`network` 终点，且参数由 `want` 控制。

---

### Step 3：对照安全规则深入研判

结合匹配的特征 API，使用 `grep_search` 在 `rules` 目录下检索具体规则加载，重点关注以下风险模式：

| 风险类别 | 对应规则 | 重点关注 |
|--------|---------|---------|
| 越权 Ability 重定向 | ABILITY-001 | 是否将 `want.parameters` 转换为了新的 `Want` 并启动？ |
| 敏感信息回传泄露 | ABILITY-002 | `terminateSelfWithResult` 是否回传了未加密敏感信息？是否校验了 `getCallingBundleName`？ |
| 本地命令/越权操作 | ABILITY-003 | 外部 want 参数是否流向了 `fileIo` / `relationalStore` 等高危 API？ |
| 弱包名白名单校验 | ABILITY-004 | 校验调用包名时是否使用了 `includes` 或脆弱的前缀正则（可伪造）？ |

---

### Step 4：记录漏洞与生成攻击链报告

针对存在敏感利用链的 UIAbility，**生成详细的漏洞记录，写入磁盘**。

#### 核心要求与 WebView 极其一致：
1. **漏洞必须具备“可利用性”**：禁止空泛的单点代码建议。
2. **详尽披露完整流程（Flow）**：每一步必须携带**真实源码 Snippet** 与行号。
3. **提供完整的漏洞利用 Want Payload 示例（Exploitation Payload）**：展示攻击者 App 该如何构造 Want 才能触发此漏洞。

#### 输出文件命名：
`harmony-ability-security-audit-attack-paths-{path_id}.json`
（例如 `harmony-ability-security-audit-attack-paths-path-001.json`）

#### 整体输出结构：

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
          "snippet": "this.context.startAbility(this.target).then(() => {\n  hilog.info(0x0000, 'TAG', 'Ability redirected successfully');\n});"
        }
      ],

      "exploitation": {
        "summary": "编写恶意 App，构造包含目标私有 Ability (PrivateAbility) 信息的嵌套 Want，发送给公开的 EntryAbility，受害 App 会代为启动该私有 Ability 从而越权。",
        "payload": {
          "target_bundle": "com.example.victim",
          "target_ability": "EntryAbility",
          "nested_want": {
            "bundleName": "com.example.victim",
            "abilityName": "PrivateAbility",
            "parameters": {
              "admin_action": true
            }
          },
          "snippet": "let want: Want = {\n  bundleName: 'com.example.victim',\n  abilityName: 'EntryAbility',\n  parameters: {\n    redirWant: {\n      bundleName: 'com.example.victim',\n      abilityName: 'PrivateAbility',\n      parameters: { admin_action: true }\n    } as Want\n  }\n};\ncontext.startAbility(want);"
        }
      },

      "impact": {
        "summary": "任意三方应用可通过此 Ability 重定向越权访问 App 内部的全部敏感未导出页面或执行敏感的私有业务逻辑。",
        "sensitive_operations": [
          { "operation": "绕过 exported=false 限制调起私有组件", "via": "context.startAbility(nestedWant)", "consequence": "可进入管理员或核心敏感设置界面，实现越权数据操作" }
        ]
      },

      "remediation": "1. 将 `EntryAbility` 设为 `exported: false`（如无外部调用必要）。\n2. 若必须对外公开，通过校验 `getCallingBundleName()` 并设置严格包名白名单拦截不合法调用（需配合 startAbilityForResult ）。\n3. 对传入的 nestedWant 做严格的白名单校验（仅允许拉起特定的合法目标，如第三方地图或分享插件），禁止任意 Want 转发。",
      
      "matched_rules": ["ABILITY-001", "ABILITY-004"],
      "evidence": [
        { "file": "EntryAbility.ets", "line_range": "10-25", "snippet": "let redirWant = want.parameters?.redirWant as Want;\n... \nthis.context.startAbility(this.target);", "description": "存在重定向调用且无防守逻辑" }
      ]
    }
  ]
}
```

## 重要原则

1. **绝对坚持利用链第一原则**：禁止只报“没有调用 `getCallingBundleName`”等单点代码缺陷。必须证明这个 want 参数真的流向了 `startAbility`、`terminateSelfWithResult` 或其他危险 API。如果中途变量丢失或未被使用，视为不可利用，直接跳过。
2. **PoC/Payload 的具体性**：利用代码片段必须可以无缝拷入 TypeScript 编译执行，其中的嵌套 Want 必须展示出清晰的越权设计意图。
3. **真实源码说话**：调用流程中每一跳都必须附带**实际源码片段**，绝不凭空猜测。
