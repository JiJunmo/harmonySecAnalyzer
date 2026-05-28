# v2 缺点分析与优化方案

## 缺点 1：attack_map 基于文件邻近度猜测，不是基于数据流

**现状**：`build_attack_map()` 的配对逻辑是：

```python
if entry["file"] == sink["file"]:
    confidence = "same_file"          # 同文件 → 假设可达
elif same_dir:
    confidence = "same_dir"           # 同目录 → 假设可达
elif (entry_type, sink_type) in CROSS_MODULE_PAIRS:
    confidence = "cross_module"       # 预定义配对 → 假设可达
```

这导致两个问题：
- **大量假阳性**：一个 500 行的文件里，第 10 行的 `want.parameters.url` 和第 400 行的 `Web({ src: this.localPage })`（本地固定页面）也会被配对成一条"潜在路径"，因为它们在同一个文件中。
- **可能漏真路径**：如果某个 sink 类型没在 `CROSS_MODULE_PAIRS` 里（比如 `deeplink` → `start_ability`），即使真实存在跨文件调用链，也根本不会进 attack_map。

**优化方案**：利用 GitNexus 做数据流预分析

**实测验证通过**（需用 `--skip-git` 单独索引目标项目）。GitNexus 的图查询能力可以替代手工写的 `data_flow_hints.py`：

**方式一：用 Cypher 查询直接构建预追踪链**

```cypher
// Step A: 从入口方法出发，追踪属性写入链
MATCH (m:Method)-[:CodeRelation {type: 'ACCESSES', reason: 'write'}]->(p:Property)
WHERE m.name IN ['onCreate', 'onNewWant']
RETURN m.name, p.name, p.filePath

// Step B: 追踪函数调用链
MATCH (a)-[:CodeRelation {type: 'CALLS'}*1..3]->(b)
WHERE a.name = 'onHandleClientReq'
RETURN a.name, b.name, b.filePath

// Step C: 组合 ACCESSES + CALLS 构建完整数据流
```

**方式二：用 `gitnexus_query` 语义搜索直接发现路径**

```python
gitnexus_query({
  query: "EntryAbility onCreate 中 want.parameters.url 是如何流向 WebView 的 src 的",
  repo: target_repo
})
```

**落地步骤**：

1. Phase 1 扫描完成后，对目标项目运行 `npx gitnexus analyze`（或 `--skip-git`）
2. 新增 `skills_v2/harmony-project-parser/scripts/gitnexus_hints.py`（~150 行），使用 GitNexus MCP 工具（`gitnexus_cypher`）自动执行预定义的数据流查询
3. 为每条 attack_map 路径追加 `data_flow_hint` 字段，标注预追踪链

**优势**：
- 不需要自己写正则解析器（GitNexus 已做好 AST 解析）
- 查询语言更精确（`ACCESSES write → externalUrl` 比正则 `this\.externalUrl\s*=` 更准确）
- 自动跨文件（CALLS 边跨越文件边界）
- 可扩展（添加新查询模式无需改解析器）

---

## 缺点 2：AI Task 只有入口信息，缺少可达性预判上下文

**现状**：Phase 2 的 Task prompt 是：

```
请验证以下 N 条 WebView 攻击路径是否真实可达：
- 路径 path-001: 入口 entry-001 → 终点 sink-004
```

AI 完全从零开始分析。对于弱模型，它要自己读文件、找变量、追流向、判断可达性——这和"让实习生不看文档直接 debug 一个陌生项目"差不多。

**优化方案**：Task prompt 附带 GitNexus 预分析上下文

修改 agent_v2.md 的 Phase 2 调度逻辑。在派发 Task 之前，先用 GitNexus Cypher 查询提取预追踪链：

```
请验证以下 WebView 攻击路径：

路径 path-001: 入口 entry-001 → 终点 sink-004
预追踪链（脚本已提取，请验证并补充）:
  url ← want.parameters?.url (EntryAbility.ets:16)
  externalUrl ← url (EntryAbility.ets:18)
  router.pushUrl(params.url = externalUrl) (Index.ets:25)
  Web({ src: this.url }) ← params.url (WebPage.ets:62)

如果预追踪链正确 → 直接基于此生成 attack_path
如果预追踪链有误 → 修正后生成 attack_path
如果不可达 → 写入空 attack_paths 标记完成
```

AI 的职责从"从零发现"变为"验证 + 补充 + 深度分析"，弱模型也能产出合格结果。

---

## 缺点 3：attack_map 置信度标注未充分利用

**现状**：Phase 1 已经为每条路径标注了 confidence（`high_verified_deeplink` / `same_file` / `cross_module` 等 6 个等级），但 Phase 2 调度时完全忽略了这个信息。5 条 `high_verified_deeplink` 和 5 条 `cross_module` 混在同一个 batch 里，AI 得不到优先级提示。

**优化方案**：按置信度分级调度

修改 agent_v2.md 的 Phase 2 调度规则：

| 置信度 | 调度策略 | 理由 |
|--------|---------|------|
| `high_verified_deeplink` / `high_verified_ability` | 优先调度（第一批 Task） | 真实外部入口，利用成功率最高 |
| `same_file` / `same_dir` | 次优先调度 | 有静态证据支撑 |
| `same_module` / `cross_module` | 最后调度或可选调度 | 纯猜测，AI 可能找不到真实链路 |

同时每条路径的 Task prompt 中显式告知 confidence：

```
路径 path-001: 置信度 = high_verified_deeplink（入口通过 module.json5 确认 + 同文件 sink）
   → AI 应重点分析，预期能找到可达路径
路径 path-014: 置信度 = cross_module（跨模块配对，未经验证）
   → AI 快速筛查，若 2 步内找不到可达链路即判定不可达
```

---

## 缺点 4：缺少面向弱模型的中间产物——"代码事实提取"

**现状**：Phase 1 脚本提取了 entry 和 sink，但没有提取任何关于"代码在做什么"的结构化事实。例如：

- `onConnect` 是否返回了全局单例？
- `switch(code)` 有多少个 case？
- `registerJavaScriptProxy` 注册了哪些方法名？
- `onLoadIntercept` 是否存在？

这些信息在 Phase 1 完全可以通过正则提取，但 v2 把它们全部留给了 AI 去读源码。

**优化方案**：Phase 1.5 代码事实提取器

新增 `skills_v2/harmony-project-parser/scripts/code_facts.py`（~250 行），在 Phase 1 扫描之后、Phase 2 派发之前运行，为每个入口关联的源文件提取结构化事实：

```json
{
  "entry_id": "entry-004",
  "code_facts": {
    "onConnect": {
      "returns": "StubServerInstance.getInstance()",
      "has_global_singleton": true,
      "has_bundle_check": false
    },
    "onRemoteMessageRequest": {
      "has_getCallingUid": false,
      "has_getCallingPid": false,
      "has_descriptor_check": true,
      "always_returns_true": true
    },
    "switch_codes": [1001, 1002, 1003, 1004],
    "sensitive_apis": [
      "dataStatus.updateParcelableData",
      "dataStatus.updateArrayBufferData",
      "reply.writeString"
    ],
    "js_bridge_methods": ["readFile", "writeFile", "showToast", "getDeviceId", "sendRequest"]
  }
}
```

这些事实在 Phase 2 Task prompt 中直接附上，AI 不用再做"有没有调用 getCallingUid"这种低层次判断，直接聚焦于安全分析。

---

## 缺点 5：entry 和 sink 的类型覆盖有盲区

**现状**：入口只覆盖了 deeplink/ipc/ipc_service/url_callback/exported_ability 五种。以下入口类型未覆盖：

| 遗漏入口 | 攻击场景 |
|---------|---------|
| 推送消息 | `pushService.on('receive')` 的消息 payload 被直接使用 |
| 文件 scheme processor | `file://` scheme 携带的参数可能被注入 |
| 剪贴板数据 | `pasteboard.getData()` 读取的数据进入敏感操作 |
| 通知点击 | `Notification.clickAction` 携带的参数 |
| NAPI 模块接收的数据 | 从 native 层传入的参数 |

**优化方案**：逐步扩展入口发现规则

在 `discover_entries()` 中新增正则匹配，不改变架构：

```python
# 推送消息入口
for m in re.finditer(r"pushService\s*\.\s*on\s*\(['\"]receive['\"]", content):
    entries.append({ "type": "push_message", ... })

# 剪贴板数据入口
for m in re.finditer(r"pasteboard\s*\.\s*getData\s*\(", content):
    entries.append({ "type": "clipboard", ... })

# 文件 scheme 入口
for m in re.finditer(r"onFileRequest\s*\(|fileUri\s*[:=]", content):
    entries.append({ "type": "file_scheme", ... })
```

同时扩展 `CROSS_MODULE_PAIRS` 以覆盖新的 entry→sink 组合。

---

## 缺点 6：report_aggregator 校验太粗糙

**现状**：`report_aggregator.py` 的校验只有一条：

```python
if actual_tasks < expected:
    warnings.append(f"潜在路径 {expected} 条，实际完成 Task {actual_tasks} 个，可能漏分析")
```

只对数量，不对内容。可能出现的情况：
- AttackPath JSON 不完整（缺 flow/impact/exploitation）→ 聚合器不报错
- severity 值不在合法范围内 → 聚合器不报错
- id 重复 → 后者覆盖前者

**优化方案**：聚合器增加内容完整性校验

在 `aggregate()` 函数中新增校验代码：

```python
REQUIRED_FIELDS = ["id", "title", "severity", "flow", "impact", "exploitation", "remediation"]
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

for p in all_paths:
    missing = [f for f in REQUIRED_FIELDS if f not in p]
    if missing:
        warnings.append(f"AttackPath {p.get('id', '?')} 缺少必要字段: {missing}")
    if p.get("severity") not in VALID_SEVERITIES:
        warnings.append(f"AttackPath {p.get('id', '?')} severity 不合法: {p.get('severity')}")
    if not p.get("flow"):
        warnings.append(f"AttackPath {p.get('id', '?')} flow 为空")

# 去重检查
ids = [p["id"] for p in all_paths if "id" in p]
dupes = [i for i in ids if ids.count(i) > 1]
if dupes:
    warnings.append(f"重复的 AttackPath ID: {set(dupes)}")
```

---

## 缺点 7：没有审计基线/回归测试

**现状**：修改 scanner 脚本后无法快速验证是否引入了回归——某些应该被检测到的 entry/sink 是否漏了。修改 SKILL.md 或 rule 后也无法验证 AI 产出质量是否下降。

**优化方案**：建立审计基线数据集

1. 在 `demo_test_scanner/` 基础上，为每个源码文件标注"预期发现的 entry 和 sink"，存为 `expected_entries.json` 和 `expected_sinks.json`
2. 每次修改 scanner 脚本后运行：

```bash
python project_scanner.py demo_test_scanner -o /tmp/scan_test/
python scripts/validate_scan.py /tmp/scan_test/entries.json demo_test_scanner/expected_entries.json
# 输出: 召回率 100% (5/5 entry 均被发现), 新增发现: 0
```

3. 对于 AI 产出质量，建立最小 AttackPath 黄金数据集——将 demo 产出的 3 条 attack_path 视为黄金标准，文档化其结构和判定依据。

---

## 缺点 8：攻击路径输出数据结构冗余

**现状**：AttackPath JSON 中 `flow[].snippet` 和 `evidence[].snippet` 存在大量重复代码。虽然报告模板中去掉了 evidence section，但数据层面的冗余没有解决。每条 attack_path 的 JSON 体积很大（IPC-001 约 8KB），对于弱模型来说产出成本很高。

**优化方案**：精简 AttackPath 数据结构

1. 删除 `evidence[]` 字段——所有代码证据已包含在 `flow[]` 中
2. 限制 `flow[].snippet` 每步不超过 15 行，多余用 `// ...` 省略
3. 将 `matched_rules[]` 从独立字段改为附在修复建议后的 inline 格式
4. 修改各 skill 的 SKILL.md 输出格式定义，去掉 evidence 字段引用

---

## 优先级建议

| 优先级 | 优化项 | 影响 | 工作量 |
|--------|--------|------|--------|
| **P0** | 缺点 1：GitNexus 数据流预分析 (gitnexus_hints.py) | 直接提升 attack_map 准确率，减少 Phase 2 AI 工作量 | 1.5天 |
| **P0** | 缺点 2：Task prompt 附带预分析上下文 | 显著提升弱模型的攻击路径验证质量 | 0.5天 |
| **P1** | 缺点 4：代码事实提取器 (code_facts.py) | 让 AI 专注于安全分析而非读代码 | 2天 |
| **P1** | 缺点 6：聚合器内容完整性校验 | 低成本高回报，防止劣质输出进入报告 | 0.5天 |
| **P2** | 缺点 8：精简 AttackPath 数据结构 | 降低 AI 产出成本，减少冗余 | 1天 |
| **P2** | 缺点 3：按置信度分级调度 | 优化调度效率，优先验证高置信路径 | 0.5天 |
| **P3** | 缺点 5：扩展入口发现规则 | 渐进增强攻击面覆盖 | 1天/每类入口 |
| **P3** | 缺点 7：审计基线/回归测试 | 保证长期可维护性 | 1天 |
