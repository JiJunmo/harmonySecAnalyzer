---
name: harmony-project-parser
description: v2 — 发现项目外部入口和攻击终点，预判可连性，输出 entries.json + sinks.json + attack_map.json
---

# harmony-project-parser v2

扫描鸿蒙项目，发现所有外部入口和攻击终点，并预判哪些入口可以流向哪些终点。

## 执行

```bash
python skills_v2/harmony-project-parser/scripts/project_scanner.py <project_path> -o <audit_dir> --pretty
```

若 `python3` 不可用（如 Windows），改为 `python`。

## 输出

| 文件 | 内容 |
|------|------|
| `entries.json` | 所有外部可控入口（DeepLink/Want 参数/IPC 消息/URL 回调） |
| `sinks.json` | 所有攻击终点（WebView 加载/文件写入/数据库/网络） |
| `attack_map.json` | 入口→sink 配对，标记置信度 + **data_flow_hint**（Phase 1.5 GitNexus 预分析注入） |

## Phase 1.5: GitNexus 数据流预分析（自动执行）

扫描完成后，`project_scanner.py` 自动调用 `gitnexus_hints.py`，使用 GitNexus Cypher 查询 ACCESSES/CALLS 边，为每条 attack_map 路径注入 `data_flow_hint`：

```json
{
  "id": "path-001",
  "confidence": "high_verified_deeplink",
  "data_flow_hint": {
    "trace": [
      "onCreate → write(externalUrl) (EntryAbility.ets) [外部参数注入]",
      "onNewWant → write(externalUrl) (EntryAbility.ets) [外部参数注入]"
    ],
    "verified": true,
    "source": "gitnexus_cypher"
  }
}
```

跳过此步骤：`--skip-gitnexus`

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
