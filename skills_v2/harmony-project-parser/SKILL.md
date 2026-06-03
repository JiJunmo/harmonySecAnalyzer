---
name: harmony-project-parser
description: v2.5 — 发现项目外部入口、攻击终点与双向断裂路径碎片，输出 entries.json + sinks.json + fragments.json + attack_map.json
---

# harmony-project-parser v2.5

扫描鸿蒙项目，发现所有外部入口和攻击终点，提取双向断裂的路径碎片，并预判哪些入口可以流向哪些终点。

## 执行

### Step 1: 扫描物理入口与物理终点

根据项目规模大小，支持以下两种扫描方式：

#### 方式 A：一键自动扫描（支持中小型项目及配置了 build-profile.json5 的多模块超大型项目）

直接对项目根目录进行单次全局扫描：

```bash
python skills_v2/harmony-project-parser/scripts/project_scanner.py <project_path> -o <audit_dir> --pretty
```

* **自动识别与路由**：若检测到项目根目录下存在 `build-profile.json5` 且配置了 `modules` 列表，该扫描器将**全自动按顺序执行各子模块扫描**并输出临时分片 json，最后**全自动触发全局合并流程**生成最终全局的 `entries.json` 与 `sinks.json`。
* **单模块/传统项目**：若不存在 `build-profile.json5`，则会自动回退为单次全局扫描。

#### 方式 B：超大型项目（手动分模块独立任务派发 + 全局合并，规避超时）

在需要手动或更细粒度控制扫描流程时，可以显式以各 hap/hsp/har 模块文件夹（即包含 `module.json5` 的子目录）为单位独立进行单线程扫描，最后由合并引擎输出：

1. **对每个模块文件夹单独派发任务**：
   ```bash
   python skills_v2/harmony-project-parser/scripts/project_scanner.py <project_path> --module-dir <project_path>/<module_name> -o <audit_dir> --pretty
   ```
   该模式下仅扫描指定模块文件夹并做相对路径自动映射。单次任务内为**纯单线程顺序扫描**以降低内存与 CPU 开销。扫描结束后，审计目录下会输出相应的 `entries_<module_name>.json` 和 `sinks_<module_name>.json` 临时分片。

2. **全局结果去重与确定性合并**：
   模块任务扫描全部完成后，运行以下指令将所有临时分片合并、全局去重和稳定重新分配 ID，得到标准的统一结果文件：
   ```bash
   python skills_v2/harmony-project-parser/scripts/project_scanner.py <project_path> --merge -o <audit_dir> --pretty
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
| `attack_map.json` | 入口→sink 完整缝合配对，标记置信度 + **data_flow_hint**（Step 3 AI Atlas 研判缝合注入） |

### Step 3: 智能体语义直连桥接验证与缝合

在 `fragments.json` 导出后，AI Agent 将读取其内容，并针对 `candidate_bridges` 中的每一对候选桥：
1. **源码调阅**：利用 `view_file` 或本地 `atlas trace caller-path`、`atlas search` 等命令行工具调阅对应源码的上下文与跨文件依赖。
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
| `telephony` | `@kit.TelephonyKit` 或 `@ohos.telephony.*` 蜂窝通信操作 |
| `location` | `@kit.LocationKit` 或 `@ohos.geoLocationManager` 定位操作 |
| `calendar` | `@kit.CalendarKit` 或 `@ohos.calendarManager` 日历增删改查 |

