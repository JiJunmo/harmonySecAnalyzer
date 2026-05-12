# harmony-ipc-security-audit 实现方案

## 一、设计思路

IPC 安全审计分为两个层次：

1. **配置级审计**：解析 module.json5 中 extensionAbilities 的配置，检查 exported、visible、permissions 等字段
2. **代码级审计**：搜索源文件中的 IPC API 调用模式，检测身份校验缺失、数据校验缺失等问题

配置级审计依赖 Phase 1 的 metadata JSON（无需重新解析 module.json5），代码级审计通过正则模式匹配在源文件中搜索关键 API 调用。

## 二、检测能力

基于 `IPC_REFERENCE.md` 的分析，提取 16 条审计规则：

### 配置级（无需读源文件）

| 规则 ID | 检测方式 | 说明 |
|---------|---------|------|
| IPC-001 | metadata.extensions 检查 | exported=true 无 visible |
| IPC-002 | metadata.extensions 检查 | 缺少 permissions 字段 |
| IPC-013 | metadata + sdk 版本联动 | Full SDK + 无权限守卫 |
| IPC-014 | metadata.extensions 检查 | 过度导出 |

### 代码级（需搜索源文件）

| 规则 ID | 检测方式 | 说明 |
|---------|---------|------|
| IPC-003 | 模式匹配 | onRemoteMessageRequest 无身份校验 |
| IPC-004 | 模式匹配 | InterfaceToken 作为唯一认证 |
| IPC-005 | 模式匹配 | 明文数据传输 |
| IPC-006 | 模式匹配 | unmarshalling 无校验 |
| IPC-007 | 模式匹配 | code 无范围校验 |
| IPC-008 | 模式匹配 | readArrayBuffer 无长度校验 |
| IPC-009 | 模式匹配 | Stub 全局单例 |
| IPC-010-LOG | 模式匹配 | hilog 打印 IPC 数据 |
| IPC-010-RETURN | 模式匹配 | 返回值恒 true |
| IPC-011-CONNECT | 模式匹配 | onConnect 无身份校验 |
| IPC-012-CLEANUP | 模式匹配 | 断连未清理 proxy |
| IPC-015 | 模式匹配 | descriptor 硬编码 |
| IPC-016 | 模式匹配 | 连接无超时 |
| IPC-INFO-ALL | 模式匹配 | 项目使用了 IPC |

## 三、脚本设计

`ipc_auditor.py` 职责：

1. 读取 Phase 1 metadata JSON
2. 加载规则 YAML 文件
3. 配置级检查：遍历 modules[].extension_abilities 应用配置规则
4. 代码级检查：遍历 files.ets_sources 每行搜索 IPC API 调用模式
5. 输出标准化的 findings.json

### 性能考虑

- 代码级检查使用 `content in file` 方式，对大文件高效
- 规则 YAML 仅加载一次
- 输出 JSON 流式写入

## 四、与 Agent 的协作

```
Agent (Phase 2)
  │
  ├─ 检查 metadata.security_surface.has_ipc_service
  │
  ├─ 若 true → 执行此 skill
  │   └─ python3 ipc_auditor.py <metadata_path> <project_path> -o findings.json
  │
  ├─ 读取 findings.json
  │
  └─ 返回 findings 列表给 Agent 做 Phase 3 聚合
```

## 五、扩展性

| 扩展方向 | 方式 |
|---------|------|
| 新增规则 | 在对应 severity 的 YAML 文件中添加新 rule 条目 |
| 新增检测类型 | 在 ipc_auditor.py 中添加对应的检测函数 |
| 新增代码模式 | 在规则的 positive_patterns / negative_patterns 中添加 |
| IPC 数据流分析 | 未来可扩展为解析 AST 做数据流追踪 |

## 六、已知限制

1. 当前代码级检查基于字符串模式匹配，非 AST 级别。对于复杂的分支逻辑（如条件式 return），可能存在误报或漏报
2. 无法检测跨文件的调用链（如 helper 函数中调用 getCallingUid）
3. 无法检测运行时行为（如反射调用、动态代理）
4. 不追踪 Full SDK 实际使用情况，仅检查 SDK 版本字符串

这些限制将在后续版本中通过引入 AST 分析和数据流分析来解决。
