---
name: harmony-project-parser
description: v2.5 — 发现项目外部入口、攻击终点与双向断裂路径碎片，输出 entries.json + sinks.json + fragments.json + attack_map.json
---

# harmony-project-parser v2.5

扫描鸿蒙项目，发现所有外部入口和攻击终点，提取双向断裂的路径碎片，并预判哪些入口可以流向哪些终点。

## 执行

### Step 1: 扫描物理入口与物理终点

```bash
python skills_v2/harmony-project-parser/scripts/project_scanner.py <project_path> -o <audit_dir> --pretty
```

若 `python3` 不可用（如 Windows），改为 `python`。

### Step 2: 提取双向断裂路径碎片 (Cascade Hybrid v2.5)

对于因为 AppStorage、Emitter 事件总线、动态路由等机制导致的静态物理调用链断裂（拓扑断裂），运行以下提取器生成前向与反向碎片及候选桥：

```bash
python skills_v2/harmony-project-parser/scripts/fragment_finder.py <project_path> -o <audit_dir>
```

## 输出

| 文件 | 内容 |
|------|------|
| `entries.json` | 所有外部可控入口（DeepLink/Want 参数/IPC 消息/URL 回调） |
| `sinks.json` | 所有攻击终点（WebView 加载/文件写入/数据库/网络） |
| `fragments.json` | 包含 `forward_fragments` (前向拼图)、`reverse_fragments` (反向拼图) 与 `candidate_bridges` (候选桥配对) |
| `attack_map.json` | 入口→sink 完整缝合配对，标记置信度 + **data_flow_hint**（Phase 1.5 AI 研判缝合注入） |

## Phase 1.5: 智能体语义直连桥接验证与缝合

在 `fragments.json` 导出后，AI Agent 将读取其内容，并针对 `candidate_bridges` 中的每一对候选桥：
1. **源码调阅**：利用 `view_file` 或 MCP 调阅对应源码的上下文。
2. **因果语义判定**：分析动态生成的键值或事件，确认它们在运行时是否确实共享同一个全局槽（排除因为模糊匹配引起的不交联误报），以及传导参数可控性。
3. **首尾缝合**：通过验证的拼图首尾相连，组装成完整的 `attack_map.json` 交付 Phase 2 深度审计。

## 入口类型

| type | 含义 |
|------|------|
| `deeplink` | `want.parameters.xxx` 取值点 |
| `ipc` | `onRemoteMessageRequest` 调用 |
| `ipc_service` | exported service ExtensionAbility |
| `url_callback` | `onLoadIntercept` / `onUrlLoadIntercept` 回调 |

## Sink 类型

| type | 含义 |
|------|------|
| `webview` | `Web({ src: ... })` 加载点 |
| `file_write` | `fileIo.openSync` / `writeSync` 调用 |
| `database` | `executeSql` / `relationalStore` 操作 |
| `network` | `http.request` / `fetch` 调用 |

