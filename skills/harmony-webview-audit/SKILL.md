---
name: harmony-webview-audit
description: 端到端审计 WebView 攻击路径——从外部入口（DeepLink/Want参数）出发，追踪参数流向到 WebView 加载和 JS Bridge 调用，找到真实可达的漏洞
---

# harmony-webview-audit

HarmonyOS WebView 攻击路径审计 Skill。**不孤立检查每个 WebView 的配置**，而是从外部入口出发，追踪参数如何流入 WebView 的 `src`、拦截器和 JS Bridge，找到攻击者可利用的完整链路。

## 核心审计模型：3 段式攻击链路

```
┌──────────────┐     ┌─────────────────┐     ┌────────────────┐
│  入口段 Entry  │ ──→ │  传播段 Prop.     │ ──→ │  影响段 Impact   │
├──────────────┤     ├─────────────────┤     ├────────────────┤
│ 外部输入点      │     │ 参数传递过程       │     │ 攻击终点         │
│               │     │                  │     │                  │
│ DeepLink      │     │ 变量赋值          │     │ WebView 加载     │
│ want.parameters│    │ 跨组件传递         │     │ 攻击者 URL       │
│ 推送消息       │     │ 全局状态写入       │     │                  │
│               │     │ 路由参数传递       │     │ JS Bridge 被调   │
│               │     │                  │     │ 用敏感 API       │
│               │     │                  │     │                  │
│ 入口来源：      │     │ 关键检查：         │     │ 危害评估：       │
│ entries.json  │     │ 参数是否被校验     │     │ 文件读写/数据库/  │
│               │     │ 是否可追踪到 Web   │     │ 网络/隐私泄露    │
└──────────────┘     └─────────────────┘     └────────────────┘
```

**只有 3 段都成立，才构成一条有效漏洞。** 孤立存在但无入口触达的薄弱配置不视为漏洞。

## 触发条件

Agent 读取 metadata 后，若以下任一条件为 true 则调度本 Skill：
- `security_surface.has_webview` → true
- `files.capabilities.uses_webview` → true

## 前置输入

| 数据 | 来源 |
|------|------|
| metadata JSON | Phase 1 输出的 `<audit_dir>/harmony-project-parser-findings.json` |
| 项目根路径 | Agent 传递的 project_path |
| 规则知识库 | `skills/harmony-webview-audit/rules/*.json` |
| WebView 领域知识 | `skills/harmony-webview-audit/WEBVIEW_REFERENCE.md` |

## 输出产物

| 文件 | 内容 | 用途 |
|------|------|------|
| `harmony-webview-audit-attack-paths.json` | 所有可达的 WebView 攻击路径（3 段式） | 供报告生成器使用 |
| `harmony-webview-audit-findings.json` | 按 severity 排序的标准格式发现列表 | 供聚合器使用 |

## Step 1: 获取入口列表和 WebView 实例

在分析之前，先读取 Phase 1.5 输出的入口列表和 audit-plan 中的 WebView 实例：

```bash
# 入口列表（Phase 1.5 已生成）
读取 <audit_dir>/harmony-project-parser-entries.json

# WebView 实例（audit-plan 中已列出）
读取 <audit_dir>/harmony-project-parser-audit-plan.json → dispatch.harmony-webview-audit.instances
```

## Step 2: 对每个入口 → WebView 组合追踪攻击链路

**每个 Task 只分析一对 (入口, WebView实例) 的攻击链路。** 对于每个组合：

### 2.1 入口段分析

- 读取入口所在文件，理解外部参数如何被接收和存储
- 判断哪些参数是攻击者可完全控制的（`want.parameters?.url`、`event.data.getRequestUrl()`）
- 写出：攻击者如何构造输入、输入格式是什么

### 2.2 传播段分析

- 追踪入口参数从接收点到 WebView 的 `src` 属性或 `loadUrl()` 调用的路径
- 逐跳记录：变量赋值 → 跨函数传递 → 组件属性绑定
- 关键检查：路径中是否有 URL 校验？是字符串前缀匹配还是结构化解析？

### 2.3 影响段分析

- 一旦攻击者控制了 WebView 加载的 URL，能造成什么危害？
- 检查 JS Bridge 暴露的方法，评估其可被利用的程度
- 检查拦截器是否可被绕过（加载攻击者 URL 后能否导航到更多恶意站点）
- 评估最终影响：文件读写、数据库访问、凭证窃取、任意代码执行

### 2.4 输出攻击路径

每条完整路径输出到 `<audit_dir>/harmony-webview-audit-attack-paths.json`：

```json
{
  "attack_paths": [
    {
      "attack_path_id": "wv-path-001",
      "severity": "critical",
      "entry_id": "entry-001",
      "webview_instance_id": "webview-001",
      "title": "DeepLink 参数注入 → WebView 加载恶意 URL → JS Bridge 读取文件",
      "entry": {
        "type": "deeplink",
        "file": "entry/src/main/ets/entryability/EntryAbility.ets",
        "line": 42,
        "controlled_param": "url",
        "how": "want.parameters?.url 未校验即存入 this.externalUrl",
        "snippet": "let url = want.parameters?.url as string; this.externalUrl = url;"
      },
      "propagation": [
        {
          "step": 1,
          "file": "entry/src/main/ets/entryability/EntryAbility.ets",
          "line_range": "42-45",
          "action": "want.parameters.url → this.externalUrl",
          "snippet": "this.externalUrl = want.parameters?.url as string;"
        },
        {
          "step": 2,
          "file": "entry/src/main/ets/pages/WebPage.ets",
          "line_range": "15-17",
          "action": "this.externalUrl → Web({ src: ... })",
          "snippet": "Web({ src: this.externalUrl, controller: this.ctrl })"
        }
      ],
      "impact": {
        "how": "WebView 加载攻击者提供的 URL，该页面通过 JS Bridge 调用 Native 方法",
        "vulnerability": "JS Bridge 注册时有 allowedOriginRules: []（无限制），且暴露了 readFile() 方法",
        "affected_api": "@ohos.file.fs → openSync / readTextSync",
        "consequence": "可读取应用沙箱内任意文件"
      },
      "evidence": [...],
      "remediation": "1. 校验 deeplink url 参数为白名单域名\n2. WebView 加载前做 new URL() 结构化校验\n3. JS Bridge 移除文件 IO 方法"
    }
  ]
}
```

**关键要求**：
- 如果入口参数不流向任何 WebView，该入口不产生有效攻击路径
- 如果 WebView 只加载 `$rawfile()` 本地资源，且无可控外部输入，该 WebView 不产生攻击路径
- 传播段每一跳都要有代码证据（file + line_range + snippet）
- 影响段必须评估实际可达的危害，不能套用模板

---

## Step 3: 对照规则生成 findings

从攻击路径中提取符合规则的发现，每条 finding 关联到对应的 `attack_path_id`。

## Step 4: 输出文件

1. 攻击路径写入 `<audit_dir>/harmony-webview-audit-attack-paths.json`
2. 标准 findings 写入 `<audit_dir>/harmony-webview-audit-findings.json`

**必须使用 Write 工具写入磁盘，不可仅在对话中展示。**

---

## 重要原则

1. **可达性优先**：没有入口触达的薄弱配置不视为漏洞
2. **3 段必须完整**：入口 → 传播 → 影响，缺一不可
3. **传播段逐跳追踪**：每步都要有代码证据
4. **危害评估具体**：不能用模板文字，必须写"通过 JS Bridge 的 readFile() 方法可读取 /data/storage/xxx/token.txt"
5. **severity 结合可达性判定**：不可达的配置不报，可达但需前置条件的降级
6. **所有文件保存到 `<audit_dir>/`**

## 依赖关系

- **上游**: Phase 1.5 entries.json + Phase 1 audit-plan.json
- **下游**: Phase 3 report_aggregator.py + Phase 4 report-generator
