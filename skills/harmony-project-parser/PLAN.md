# harmony-project-parser Skill 实现方案

## 一、设计原则

**核心思路：脚本做机械工作，Skill 做逻辑编排。**

- **Python 脚本** 负责文件扫描、JSON5 解析、数据提取等机械性重复劳动，输出结构化 JSON
- **Skill (opencode)** 负责调用脚本、读取结果、转化为下游 skill 可用的结构化元数据

这样做的好处：
1. 大幅减少 Agent 调用 `Read` / `Grep` 的次数，降低 token 消耗
2. JSON5 的注释剥离、容错解析等逻辑用脚本实现更稳定可靠
3. 脚本输出可复用于所有下游 skill，无需重复解析
4. 脚本可独立运行和测试，不依赖 Agent 上下文

---

## 二、架构

```
┌─────────────────────────────────────┐
│  harmony-project-parser (Skill)     │
│  - 调用脚本                          │
│  - 读取 project-metadata.json       │
│  - 结构化输出给 Agent 编排器           │
└──────────────┬──────────────────────┘
               │ 调用
               ▼
┌─────────────────────────────────────┐
│  project_scanner.py (脚本)           │
│  - 递归扫描目录                       │
│  - 解析 JSON5 配置文件                │
│  - 统计源文件信息                     │
│  - 输出 project-metadata.json        │
└─────────────────────────────────────┘
```

---

## 三、Python 脚本详细设计

### 3.1 脚本入口

```
python3 project_scanner.py <project_path> -o <output.json>
```

**参数：**
- `project_path` (必须): 鸿蒙项目根目录路径
- `-o / --output` (可选): 输出 JSON 文件路径，默认 `./project-metadata.json`
- `--verbose` (可选): 输出详细日志

### 3.2 脚本核心模块

脚本拆分为 4 个独立模块，各司其职：

```
project_scanner.py          # 入口 & 编排
├── json5_parser.py         # JSON5 解析器
├── file_collector.py       # 文件收集器
├── module_analyzer.py      # module.json5 分析器
└── dependency_analyzer.py  # oh-package.json5 依赖分析器
```

#### 模块职责

| 模块 | 职责 |
|------|------|
| `json5_parser.py` | 剥离 JSON5 注释 (单行 `//` + 多行 `/* */`) 和尾逗号，转为标准 JSON 后解析 |
| `file_collector.py` | 递归扫描目录，按文件类型统计 .ets / .ts / .json5 / .hml / .css 等，估算总代码行数 |
| `module_analyzer.py` | 解析所有 `module.json5`，提取 abilities、permissions、pages、metadata、network 等关键信息 |
| `dependency_analyzer.py` | 解析 `oh-package.json5` 和 `oh_modules`，提取第三方 SDK 名称和版本 |

### 3.3 JSON5 解析器实现

JSON5 与标准 JSON 的差异：
- 支持单行注释 `//`
- 支持多行注释 `/* */`
- 支持尾逗号 `{ key: value, }`
- 支持无引号键名
- 支持十六进制数字 `0xFF`

**解析策略：逐字符状态机 + 正则**

```python
def parse_json5(text: str) -> dict:
    """
    三步处理：
    1. 正则剥离所有注释（单行 + 多行）
    2. 正则移除尾逗号
    3. json.loads() 解析（无引号键名暂不支持，鸿蒙配置通常带引号）
    """
    # Step 1: 移除多行注释 /* ... */
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # Step 2: 移除单行注释 // ...  
    text = re.sub(r'//.*$', '', text, flags=re.MULTILINE)
    # Step 3: 移除尾逗号
    text = re.sub(r',\s*([}\]])', r'\1', text)
    # Step 4: 处理无引号键名 (可选，鸿蒙配置通常带引号可跳过)
    text = re.compile(r'(?<!")([a-zA-Z_]\w*)(?=(\s*:))', re.M).sub(r'"\1"', text)
    return json.loads(text)
```

**容错设计**：
- 遇到解析失败，记录文件路径和错误行，不影响其他文件
- 部分 key 缺失时使用默认值，标记 `_parse_warnings: [...]`
- 最终输出 JSON 中的 `_parse_errors` 字段记录所有异常

### 3.4 文件收集器

**收集策略：**

```
扫描目录 → 按 glob 模式匹配 → 统计 → 生成文件清单
```

**收集的文件类型：**

| 类型 | glob 模式 | 用途 |
|------|----------|------|
| ArkTS 源文件 | `**/*.ets` | 业务代码审计 |
| TS 源文件 | `**/*.ts` | TypeScript 审计 |
| JSON5 配置 | `**/*.json5` | 配置解析 |
| HML 布局 | `**/*.hml` | JS FA 模式布局 |
| CSS 样式 | `**/*.css` | 样式审计 |
| C++ 源码 | `**/*.cpp`, `**/*.h` | NAPI 模块审计 |
| 资源文件 | `**/resources/**/*` | 资源审计 |
| 证书文件 | `**/*.p12`, `**/*.cer`, `**/*.p7b` | 签名证书检查 |
| CMake | `**/CMakeLists.txt` | NAPI 构建检查 |

**排除目录：**
```
node_modules, oh_modules, build, .git, .idea, .hvigor, .preview
```

**输出结构：**
```json
{
  "total_ets_files": 42,
  "total_ts_files": 8,
  "total_json5_files": 5,
  "total_lines_estimated": 5230,
  "ets_sources": [
    { "path": "entry/src/main/ets/pages/Index.ets", "lines": 120 },
    { "path": "entry/src/main/ets/pages/Login.ets", "lines": 85 }
  ],
  "ts_sources": [...],
  "json5_configs": [
    "entry/src/main/module.json5",
    "entry/build-profile.json5"
  ],
  "certificates": ["entry/src/main/resources/rawfile/xxx.p12"],
  "napi_sources": [...]
}
```

### 3.5 Module 分析器

**解析 `module.json5` 关键字段：**

```json5
{
  "module": {
    "name": "entry",                        // module 名称
    "type": "entry",                        // entry | feature | hsp | har
    "srcEntry": "./ets/Application/...",    // 入口
    "description": "...",
    "mainElement": "EntryAbility",          // 主 ability
    "deviceTypes": ["phone", "tablet"],
    "deliveryWithInstall": true,
    "installationFree": false,
    "pages": "$profile:main_pages",         // pages 配置引用

    // ===== 核心审计字段 =====
    "abilities": [                          // Ability 列表
      {
        "name": "EntryAbility",
        "srcEntry": "./ets/entryability/EntryAbility.ets",
        "exported": true,                   // ⚠️ 是否导出
        "visible": ["com.other.app"],       // 可见性白名单
        "permissions": [],                  // ability 级权限
        "launchType": "singleton",
        "skills": [{                        // Intent Filter
          "actions": ["ohos.want.action.home"],
          "entities": ["entity.system.home"],
          "uris": [{ "scheme": "https", "host": "example.com" }]
        }]
      }
    ],
    "extensionAbilities": [...],            // ExtensionAbility
    "requestPermissions": [                 // 权限列表
      {
        "name": "ohos.permission.INTERNET",
        "reason": "$string:internet_reason",
        "usedScene": {
          "abilities": ["EntryAbility"],
          "when": "always"
        }
      }
    ],
    "metadata": [...],                      // 元数据
    "network": {                            // 网络配置
      "cleartextTraffic": false,            // ⚠️ 明文流量
      "domains": [
        {
          "name": "example.com",
          "isNeedVerifySSL": true           // ⚠️ SSL 校验
        }
      ]
    },
    "routerMap": [...],                     // 路由表
    "appStartup": {...}                     // 启动配置
  }
}
```

**分析器输出结构：**

```json
{
  "modules": [
    {
      "name": "entry",
      "type": "entry",
      "src_path": "entry/src/main/module.json5",
      "main_element": "EntryAbility",
      "device_types": ["phone", "tablet"],
      "abilities": [
        {
          "name": "EntryAbility",
          "type": "UIAbility",
          "src_entry": "./ets/entryability/EntryAbility.ets",
          "exported": true,
          "visible": ["com.other.app"],
          "permissions": [],
          "launch_type": "singleton",
          "skills": [
            {
              "actions": ["ohos.want.action.home"],
              "entities": ["entity.system.home"],
              "uris": [{ "scheme": "https", "host": "example.com" }]
            }
          ]
        }
      ],
      "extension_abilities": [...],
      "permissions": [
        {
          "name": "ohos.permission.INTERNET",
          "reason": "$string:internet_reason",
          "used_scene": { "abilities": ["EntryAbility"], "when": "always" }
        }
      ],
      "network_config": {
        "cleartext_traffic": false,
        "domains": [
          { "name": "example.com", "ssl_verify": true }
        ]
      },
      "pages": ["pages/Index", "pages/Login", "pages/Settings"],
      "pages_profile_path": "src/main/resources/base/profile/main_pages.json"
    }
  ]
}
```

### 3.6 依赖分析器

**解析 `oh-package.json5`：**

```json5
{
  "name": "myapp",
  "version": "1.0.0",
  "description": "...",
  "main": "Index.ets",
  "author": "",
  "license": "ISC",
  "dependencies": {
    "@ohos/hamock": "1.0.0-rc",
    "@ohos/hypium": "1.0.15",
    "@ohos/axios": "^2.2.0",
    "@ohos/crypto-js": "^2.0.4"
  },
  "devDependencies": {
    "@ohos/hvigor": "5.5.4",
    "@ohos/hvigor-ohos-plugin": "5.5.4"
  }
}
```

**输出结构：**

```json
{
  "project_name": "myapp",
  "project_version": "1.0.0",
  "dependencies": {
    "production": [
      { "name": "@ohos/axios", "version": "^2.2.0", "source": "oh_modules" },
      { "name": "@ohos/crypto-js", "version": "^2.0.4", "source": "oh_modules" }
    ],
    "dev": [
      { "name": "@ohos/hvigor", "version": "5.5.4", "source": "node_modules" },
      { "name": "@ohos/hvigor-ohos-plugin", "version": "5.5.4", "source": "node_modules" }
    ],
    "hsp_modules": [...],
    "har_modules": [...],
    "napi_modules": [...]
  },
  "sdk": {
    "compile_sdk_version": 12,
    "compatible_sdk_version": 12,
    "target_sdk_version": 12
  }
}
```

### 3.7 最终输出 JSON Schema

```json
{
  "_meta": {
    "scanner_version": "1.0.0",
    "scan_time": "2026-05-11T10:30:00Z",
    "project_path": "/path/to/project",
    "parse_errors": [],
    "parse_warnings": []
  },
  "project": {
    "name": "myapp",
    "version": "1.0.0",
    "package_name": "com.example.myapp"
  },
  "build": {
    "compile_sdk_version": 12,
    "compatible_sdk_version": 12,
    "target_sdk_version": 12,
    "build_mode": "debug"
  },
  "modules": [ ... ],
  "dependencies": { ... },
  "files": {
    "total_ets_files": 42,
    "total_ts_files": 8,
    "total_lines": 5230,
    "ets_sources": [...],
    "ts_sources": [...],
    "json5_configs": [...],
    "certificates": [...]
  },
  "security_surface": {
    "total_permissions": 8,
    "dangerous_permissions": 3,
    "exported_abilities": 2,
    "exported_extensions": 0,
    "network_domains_count": 1,
    "uses_webview": false,
    "uses_database": true,
    "uses_distributed": false,
    "has_napi": false
  }
}
```

---

## 四、文件结构

```
skills/harmony-project-parser/
├── SKILL.md                      # Skill 定义（opencode 用）
├── scripts/
│   ├── project_scanner.py        # 主编排入口
│   ├── json5_parser.py           # JSON5 解析器
│   ├── file_collector.py         # 文件收集器
│   ├── module_analyzer.py        # Module 分析器
│   └── dependency_analyzer.py    # 依赖分析器
└── templates/
    └── project-metadata-schema.json  # 输出 JSON Schema
```

---

## 五、Skill (opencode) 定义

`SKILL.md` 核心逻辑：

```
1. 接收输入: 待审计的鸿蒙项目路径
2. 执行脚本: python3 scripts/project_scanner.py <project_path> -o /tmp/project-metadata.json
3. 读取 /tmp/project-metadata.json
4. 做轻量级后处理:
   - 解析 $string:xxx 引用（从 resources/string.json 获取实际值）
   - 解析 $profile:xxx 引用（读取对应的 profile json 文件）
5. 将结构化数据作为 skill 输出，供 Agent 编排器分发给其他 skill
```

**Skill 输入参数：**
```yaml
input:
  project_path: string    # 鸿蒙项目根目录路径（必须）
  output_dir: string      # 报告输出目录（可选，默认 ./output）
```

**Skill 输出：**
```yaml
output:
  metadata: object        # 完整 project-metadata.json 内容
  summary: string         # 人类可读的项目摘要
```

---

## 六、与下游 Skill 的协作

项目解析器输出后，Agent 编排器将 metadata 分发给其他 skill：

```
project-parser 输出
    │
    ├─→ permission-audit: modules[].permissions
    ├─→ component-audit:  modules[].abilities, modules[].extensionAbilities
    ├─→ secrets-audit:    files.ets_sources, files.ts_sources
    ├─→ network-audit:    modules[].network_config, files.certificates
    ├─→ webview-audit:    files.ets_sources (搜索 WebView 使用)
    ├─→ crypto-audit:     files.ets_sources (搜索 cryptoFramework)
    ├─→ data-storage-audit: files.ets_sources (搜索 rdb/preferences)
    ├─→ code-quality-audit: files.ets_sources, files.ts_sources
    └─→ report-generator: 全部 metadata
```

每个下游 skill 无需重新扫描项目，直接基于 metadata 定位目标文件。

---

## 七、边界情况处理

| 场景 | 处理方式 |
|------|---------|
| module.json5 不存在 | 标记为 `module_found: false`，不阻断流程 |
| JSON5 解析失败 | 记录到 `_parse_errors`，跳过该文件继续 |
| `$string:xxx` 引用 | 脚本尽量解析，解析不到的在 Skill 层从 `element/string.json` 查找 |
| `$profile:xxx` 引用 | 解析 profile 文件路径，读取对应 JSON |
| 空项目目录 | 输出警告，files 为空列表 |
| 多 module 项目 | 正常解析所有 module，按 name 区分 |
| NAPI (C++) 模块 | 检测 CMakeLists.txt，收集 .cpp/.h 文件 |
| 超大项目 (>10k files) | 脚本内限制文件扫描深度，不做无上限递归 |

---

## 八、优化方案：脚本预计算审计调度，AI 只读结论

### 8.1 问题

当前流程中，`harmony-project-parser-findings.json` 是完整元数据的倾泻——包含每个模块的全部配置、每个文件的路径和行数、所有权限列表、所有依赖信息。大型项目可能有数十个模块、数千个文件，这个 JSON 膨胀到上百 KB。

能力较弱的 AI 模型拿到这个大 JSON 后：
- 需要逐字段理解结构才能提取出"该调哪些 skill"
- 解析过程消耗大量 token，挤占真正用于审计的上下文
- 容易遗漏关键信息或做出错误判断

但实际上，**"该调哪些 skill、每个 skill 有多少个实例"这个决策完全可以通过脚本预计算**——脚本已经遍历了所有数据，只是没有把这个结论独立输出。

### 8.2 方案：双文件输出

脚本在生成完整 metadata 的同时，额外输出一个 `audit-plan.json`，专门给 AI 编排器做任务分发。

```
project_scanner.py
    │
    ├─→ harmony-project-parser-findings.json   (完整元数据，供下游 skill + 报告)
    │
    └─→ audit-plan.json                        (审计调度计划，供 AI 编排器)
```

AI 编排器只需读取 `audit-plan.json`（通常 < 2KB），不再需要读完整的 metadata。

### 8.3 audit-plan.json 结构

```json
{
  "project": {
    "name": "com.example.app",
    "sdk_version": "5.0.0(12)",
    "module_count": 3,
    "total_ets_files": 120,
    "total_lines": 8500
  },
  "parse_errors": [],

  "dispatch": {
    "harmony-ipc-security-audit": {
      "run": true,
      "reason": "发现 3 个导出的 service 类型 ExtensionAbility（非系统权限守卫）",
      "instance_count": 3,
      "instances": [
        {"instance_id": "ipc-001", "name": "IpcServiceA", "module": "entry", "exported": true, "src_entry": "./ets/..."},
        {"instance_id": "ipc-002", "name": "IpcServiceB", "module": "feature1", "exported": true, "src_entry": "./ets/..."},
        {"instance_id": "ipc-003", "name": "IpcServiceC", "module": "feature2", "exported": true, "src_entry": "./ets/..."}
      ],
      "filtered_out": 2,
      "filtered_reason": "2 个 service 由系统未开放权限守卫，普通应用无法调用"
    },
    "harmony-webview-audit": {
      "run": true,
      "reason": "检测到 @kit.ArkWeb 使用",
      "instance_count": 5,
      "instances": [...]
    },
    "harmony-permission-audit": {
      "run": true,
      "reason": "项目申请了 8 个权限（含 3 个高危）",
      "total_permissions": 8,
      "high_risk_permissions": 3
    },
    "harmony-secrets-audit": {
      "run": true,
      "reason": "项目包含 120 个 .ets 源文件"
    },
    "harmony-network-audit": {
      "run": false,
      "reason": "未发现网络配置（无 cleartext_traffic、无 domains）"
    },
    "harmony-crypto-audit": {
      "run": true,
      "reason": "源文件中检测到 cryptoFramework 使用"
    }
  },

  "summary": {
    "total_permissions": 8,
    "high_risk_permissions": 3,
    "dangerous_permissions": 5,
    "exported_abilities": 2,
    "exported_extensions": 5,
    "filtered_extensions": 2,
    "has_cleartext_traffic": false,
    "network_domains_count": 0,
    "has_webview": true,
    "has_database": true,
    "has_distributed": false,
    "has_napi": false,
    "uses_crypto": true
  }
}
```

### 8.4 关键设计点

**实例内嵌**：IPC 和 WebView 的 `--list-instances` 结果直接嵌入 `audit-plan.json` 的 `dispatch` 字段中，不需要 AI 再去读单独的 `-instances.json` 文件。AI 可以直接遍历 `dispatch[skill].instances` 派发 Task。

**决策逻辑下沉**：dispatch 中每个 skill 的 `run` 字段由脚本根据安全攻击面自动计算，AI 不需要自己做 if-else 判断。只有脚本明确标记 `run: true` 的 skill 才需要调度。

**过滤原因说明**：`filtered_out` 和 `filtered_reason` 解释为什么某些实例不需要审计，AI 可以展示给用户，增加透明度。

### 8.5 AI 编排器的新流程

```
Phase 1:
  1. 运行 project_scanner.py（生成两个文件）
  2. 只读取 audit-plan.json（不读完整 metadata）
  3. 向用户展示项目摘要（从 audit-plan.project 提取）

Phase 2:
  for each skill in plan.dispatch:
      if skill.run == False:
          记录 "该审计项不需要：{reason}"
          continue
      if skill.instances 存在:
          遍历 skill.instances 逐实例派发 Task
      else:
          派发单 Task
```

### 8.6 脚本改动

`project_scanner.py` 新增 `--audit-plan` 参数，或直接默认生成 `audit-plan.json`。

函数 `generate_audit_plan(metadata) → dict`：
1. 从 `security_surface` 计算所有 skill 是否需要执行
2. 对 IPC skill，内嵌 `list_instances()` 的结果
3. 对 WebView skill，调用 `webview_auditor.py --list-instances` 的结果（或内联执行）
4. 输出 `audit-plan.json`

### 8.7 效果对比

| 维度 | 当前 | 优化后 |
|------|------|--------|
| AI 需要读取的文件 | metadata.json (50-200KB) | audit-plan.json (< 2KB) |
| AI 解析负担 | 理解完整 JSON 结构 + 提取有效信息 | 直接按字段取值 |
| 大项目 token 消耗 | 数万 token 用于解析 | 数百 token |
| dispatch 决策 | AI 自己 if-else | 脚本预计算，AI 直接执行 |
| 弱模型可用性 | 可能错误或遗漏 | 结论已固化，不会出错 |
