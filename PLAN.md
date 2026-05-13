# 鸿蒙应用白盒安全审计 Agent 方案

## 一、整体架构

```
┌──────────────────────────────────────────────────────┐
│                   用户输入 (项目路径)                     │
└──────────────────────┬───────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────┐
│               Agent 编排器 (Orchestrator)               │
│  1. 项目发现 → 2. 并行审计 → 3. 聚合去重 → 4. 报告生成    │
└──────┬───────┬───────┬───────┬───────┬──────────────┘
       ▼       ▼       ▼       ▼       ▼
   ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐
   │Skill│ │Skill│ │Skill│ │Skill│ │Skill│ ... (并行执行)
   └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘
      ▼       ▼       ▼       ▼       ▼
┌──────────────────────────────────────────────────────┐
│                   规则知识库 (Rules DB)                  │
│     YAML/JSON 格式的检测规则 + CWE + OWASP 映射           │
└──────────────────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────┐
│               报告生成器 (Report Generator)              │
│     Markdown / JSON / HTML 多格式输出                   │
└──────────────────────────────────────────────────────┘
```

---

## 二、Skill 拆解（共 11 个核心 Skill）

| # | Skill 名称 | 职责 | 关键检测项 |
|---|-----------|------|-----------|
| 1 | `harmony-project-parser` | 项目结构解析 | 解析 `build-profile.json5`、`module.json5`、`oh-package.json5`；识别所有 ability、page、module；构建依赖图；提取 SDK/API 版本 |
| 2 | `harmony-permission-audit` | 权限审计 | `requestPermissions` 过度申请检测；`ohos.permission.*` 危险权限组合分析；ACL 权限合理性；权限描述缺失 |
| 3 | `harmony-component-audit` | 组件安全 | `exported: true` 未鉴权的 ability；`visible` 配置缺失；intent-filter 注入风险；ServiceAbility/DataAbility URI 权限绕过；startAbility 参数校验 |
| 4 | `harmony-secrets-audit` | 硬编码密钥检测 | API Key、Token、AppSecret、加密密钥、数据库密码、签名私钥；注释中的敏感信息；`.gitignore` 缺失敏感文件 |
| 5 | `harmony-network-audit` | 网络安全 | `cleartextTraffic` 明文传输；SSL 证书校验绕过 (`sslVerify: false`)；证书固定 (certificate pinning)；`network_config.json` 域名白名单审计；WebSocket 安全 |
| 6 | `harmony-webview-audit` | WebView 安全 | `javaScriptAccess` 未限制；`fileAccess` 开启；混合内容 (mixed content)；`onUrlLoadIntercept` 缺失；JS Bridge 接口注入 (`javaScriptProxy`) |
| 7 | `harmony-crypto-audit` | 密码学安全 | 弱算法 (MD5/SHA1/DES/RC4)；`cryptoFramework` API 不安全用法；硬编码 IV/Salt；不安全的随机数 (`Math.random`)；密钥长度不足 |
| 8 | `harmony-data-storage-audit` | 数据存储安全 | `relationalStore` / `preferences` 明文存储敏感数据；数据库加密 (`encrypt: false`)；`distributedObject` 跨设备同步泄露；文件路径遍历；`BackupExtension` 备份泄露 |
| 9 | `harmony-code-quality-audit` | 代码质量/漏洞 | SQL 注入 (`rdbStore.executeSql` 拼接)；XSS；路径遍历；日志泄露 (`hilog.info` 打印敏感数据)；输入校验缺失；WebSocket/HTTP 请求参数注入 |
| 10 | `harmony-ipc-security-audit` | IPC 通信安全 | ServiceExtensionAbility 导出配置审计；调用方身份校验 (`getCallingUid`)；InterfaceToken 认证强度；Parcelable/ArrayBuffer 数据校验；Stub 实例隔离；IPC 日志泄露 |
| 11 | `harmony-report-generator` | 报告生成 | 汇总所有发现；风险分级 (Critical/High/Medium/Low/Info)；CWE 映射；OWASP Mobile Top 10 对标；修复建议；生成 Markdown + JSON 双格式报告 |

---

## 三、规则知识库设计

### 3.1 规则定义格式

以 YAML 文件定义规则，示例：

```yaml
# rules/permissions/critical.yaml
- id: HARMONY-PERM-001
  severity: high
  cwe: CWE-250
  owasp: M1
  title: "ohos.permission.MANAGE_LOCAL_ACCOUNTS 权限过度申请"
  description: "该权限允许管理本地账号，普通应用不应申请"
  detection:
    file_pattern: "**/module.json5"
    content_pattern: 'MANAGE_LOCAL_ACCOUNTS'
  remediation: "确认业务是否需要此系统级权限，如非必要请移除"
  reference: "https://developer.huawei.com/consumer/cn/doc/harmonyos-guides/permissions"
```

### 3.2 规则字段说明

| 字段 | 必须 | 说明 |
|------|------|------|
| `id` | 是 | 全局唯一规则标识 |
| `severity` | 是 | `critical` / `high` / `medium` / `low` / `info` |
| `cwe` | 否 | CWE 编号，如 `CWE-250` |
| `owasp` | 否 | OWASP Mobile Top 10 编号，如 `M1` |
| `title` | 是 | 规则标题 |
| `description` | 是 | 规则详细描述 |
| `detection` | 是 | 检测配置：`file_pattern` + `content_pattern` |
| `remediation` | 是 | 修复建议 |
| `reference` | 否 | 参考链接 |

### 3.3 严重度定义

| 严重度 | 说明 | 示例 |
|--------|------|------|
| `critical` | 可直接导致完全沦陷 | 硬编码签名私钥、系统权限绕过 |
| `high` | 可导致敏感数据泄露或权限提升 | 未加密存储密码、组件未鉴权导出 |
| `medium` | 可被利用但需要前置条件 | 弱加密算法、日志泄露敏感字段 |
| `low` | 安全最佳实践偏离 | 缺少证书固定、权限描述不完整 |
| `info` | 通知/建议性质 | SDK 版本过旧但暂无已知漏洞 |

---

## 四、Agent 工作流

```
Step 1: 项目解析
  ├─ 扫描项目目录结构
  ├─ 解析 module.json5 → 提取 abilities, permissions, 配置
  ├─ 解析 oh-package.json5 → 提取依赖版本
  └─ 输出: 项目元数据 JSON

Step 2: 并行审计 (Skills 2-9 同时执行)
  ├─ 每个 skill 独立运行，读取项目文件 + 规则库
  ├─ 输出: 结构化 Findings 列表
  └─ 每个 Finding: { id, skill, severity, title, description, location, cwe, remediation }

Step 3: 聚合与去重
  ├─ 合并所有 findings
  ├─ 去重 (同文件同问题合并)
  ├─ 关联分析 (如 secrets + network 结合判断风险链)
  └─ 按 severity / 模块 / CWE 多维度排序

Step 4: 报告生成
  ├─ 执行摘要 (风险评分、关键发现数、安全评级)
  ├─ 项目概览 (模块数、权限数、ability 数)
  ├─ 详细发现 (按严重度分组，含代码定位、修复建议)
  ├─ 合规对标 (OWASP Mobile Top 10 / 鸿蒙安全设计规范)
  └─ 附录 (完整权限清单、组件清单、审计范围)
```

### 4.1 Findings 数据结构

```typescript
interface Finding {
  id: string;           // 唯一标识, 如 "HM-2026-0001"
  skill: string;        // 来源 skill 名称
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;        // 发现标题
  description: string;  // 详细描述
  location: {
    file: string;       // 文件路径
    line?: number;      // 行号
    snippet?: string;   // 代码片段
  };
  cwe?: string;         // CWE 编号
  owasp?: string;       // OWASP Mobile Top 10 编号
  remediation: string;  // 修复建议
  reference?: string;   // 参考链接
}
```

---

## 五、报告模板结构

```
1. 执行摘要
   - 整体风险评分: 0-100
   - Critical/High/Medium/Low/Info 发现统计
   - 安全态势评估

2. 项目概览
   - 目标 SDK / API Level
   - Module 列表及类型
   - 申请权限总数及危险权限数
   - 组件导出情况

3. 发现详情 (按严重度分组)
   每个发现:
   - [HM-2026-0001] 发现标题
   - 严重度: High | CWE: CWE-xxx
   - 位置: entry/src/main/ets/pages/Login.ets:42
   - 代码片段: `const apiKey = "sk-xxxxxxxxxxxx"`  
   - 描述: xxx
   - 风险: xxx
   - 修复建议: xxx
   - 参考: xxx

4. 合规对标
   - OWASP Mobile Top 10 (2024)
   - 鸿蒙安全设计指南对齐情况

5. 附录
   - 审计范围与限制
   - 完整检测规则列表
   - 第三方SDK版本清单
   - 发现列表总表
```

---

## 六、项目文件结构

```
harmony-security-auditor/
├── PLAN.md                     # 本方案文档
├── agent.md                    # Agent 主编排逻辑
├── skills/
│   ├── harmony-project-parser/
│   │   ├── SKILL.md
│   │   └── rules/
│   │       └── project-parser-rules.yaml
│   ├── harmony-permission-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   │       ├── critical.yaml
│   │       └── high.yaml
│   ├── harmony-component-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   ├── harmony-secrets-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   ├── harmony-network-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   ├── harmony-webview-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   ├── harmony-crypto-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   ├── harmony-data-storage-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   ├── harmony-code-quality-audit/
│   │   ├── SKILL.md
│   │   └── rules/
│   ├── harmony-ipc-security-audit/
│   │   ├── SKILL.md
│   │   ├── PLAN.md
│   │   ├── IPC_REFERENCE.md
│   │   ├── scripts/
│   │   │   └── ipc_auditor.py
│   │   └── rules/
│   │       ├── critical.yaml
│   │       ├── high.yaml
│   │       ├── medium.yaml
│   │       └── low.yaml
│   └── harmony-report-generator/
│       ├── SKILL.md
│       └── templates/
│           ├── report-template.md
│           └── finding-template.md
├── rules/                      # 公共规则库
│   ├── severity-mapping.yaml
│   ├── cwe-mapping.yaml
│   └── owasp-mobile-top10.yaml
├── examples/                   # 测试用例
│   └── sample-harmony-project/
└── output/                     # 审计报告输出目录
    └── .gitkeep
```

---

## 七、实现优先级

| 优先级 | 内容 | 理由 | 状态 |
|--------|------|------|------|
| P0 | `harmony-project-parser` | 骨架，先跑通全流程 | ✅ 已完成 |
| P0 | `harmony-ipc-security-audit` | IPC 攻击面独立，与组件审计互补 | ✅ 已完成 |
| P0 | `harmony-report-generator` | 报告生成，完成全流程闭环 | ✅ 已完成 |
| P1 | `harmony-permission-audit` + `harmony-secrets-audit` | 覆盖面最广，最容易出高危发现 | 🔜 待实现 |
| P2 | `harmony-network-audit` + `harmony-component-audit` | 网络和组件是常见攻击面 | 🔜 待实现 |
| P3 | `harmony-data-storage-audit` + `harmony-webview-audit` | 本地数据泄露与 WebView 风险 | 🔜 待实现 |
| P4 | `harmony-crypto-audit` + `harmony-code-quality-audit` | 密码学与代码层漏洞 | 🔜 待实现 |

---

## 八、关键技术点

### 8.1 鸿蒙项目关键文件

| 文件 | 路径模式 | 关键审计内容 |
|------|---------|------------|
| `module.json5` | `**/src/main/module.json5` | 权限、组件、网络、元数据配置 |
| `build-profile.json5` | `根目录` | SDK 版本、目标 API level |
| `oh-package.json5` | `根目录` / `**/oh_modules/` | 第三方依赖版本 |
| `network_config.json` | `**/src/main/resources/base/profile/` | 证书固定、域名白名单 |
| `.ets` 源文件 | `**/src/main/ets/**/*.ets` | 业务代码审计 |
| `.ts` 源文件 | `**/src/main/ts/**/*.ts` | TypeScript 代码审计 |
| `.hml` 布局 | `**/src/main/js/**/*.hml` | JS FA 模式布局 |
| `app.json5` | `**/src/main/app.json5` | 应用全局配置 |

### 8.2 鸿蒙特有安全机制

| 机制 | 说明 | 审计关注点 |
|------|------|-----------|
| ACL 权限 | 应用级访问控制 | 是否申请了不必要的 ACL 权限 |
| 应用沙箱 | 文件隔离 | 是否有沙箱绕过风险 |
| 分布式数据管理 | 跨设备数据同步 | 敏感数据是否被不当同步 |
| 组件导出控制 | `exported` / `visible` | 组件是否被意外暴露 |
| 证书固定 | SSL Pinning | 是否启用证书固定 |
| 应用分身 | AppMultiplier | 多实例场景下的数据隔离 |
| 加密数据库 | RDB Store Encrypt | 数据库是否开启加密 |
