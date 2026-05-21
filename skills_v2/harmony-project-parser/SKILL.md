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
| `attack_map.json` | 同文件/同目录的入口→sink 配对，标记置信度 |

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
