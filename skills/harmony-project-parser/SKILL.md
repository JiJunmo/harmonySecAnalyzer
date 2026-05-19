---
name: harmony-project-parser
description: 解析鸿蒙应用项目结构，提取模块、权限、组件、依赖等安全审计元数据，输出标准化JSON供下游skill使用
---

# harmony-project-parser

HarmonyOS 应用项目结构解析器。扫描鸿蒙项目目录，解析所有配置文件（module.json5、build-profile.json5、oh-package.json5），收集源文件信息，输出标准化的项目元数据 JSON，供下游安全审计 skill 使用。

## 触发条件

当用户请求以下操作时使用此 skill：
- 对鸿蒙应用项目进行安全审计
- 分析鸿蒙项目的结构和配置
- 获取项目的模块、权限、组件等元数据
- 作为安全审计流程的第一步（项目发现）

## 前置条件

- Python 3.8+ 可用
- 鸿蒙项目根目录路径作为输入

## 执行流程

### Step 1: 运行扫描脚本

使用 Bash 工具执行项目扫描脚本，将结果输出到临时文件：

```bash
python3 <skill_dir>/scripts/project_scanner.py <project_path> -o /tmp/harmony_project_metadata.json --pretty
```
若 `python3` 不可用（如 Windows），改为 `python`。

参数说明：
- `<project_path>`: 用户提供的鸿蒙项目根目录绝对路径
- `<skill_dir>`: 本 skill 所在目录 (即 `skills/harmony-project-parser/`)
- `-o /tmp/harmony_project_metadata.json`: 输出到临时文件
- `--pretty`: 格式化 JSON，方便阅读和调试

**注意**：务必先确认 `<project_path>` 目录存在。若不存在，向用户报错并终止。

### Step 2: 验证输出

脚本执行完成后，检查：
1. 脚本退出码是否为 0，非 0 则报告脚本错误并终止
2. 读取 `/tmp/harmony_project_metadata.json` 文件
3. 检查 `_meta.parse_errors` 数组，如有解析错误，在输出中提醒用户

### Step 3: 生成人类可读的项目摘要

基于元数据 JSON，向用户呈现以下项目概览：

```
📱 项目概览
  - 项目名称: <project.name>
  - 包名: <project.package_name>
  - 目标 SDK: <build.compile_sdk_version>
  - 目标 API Level: <build.target_sdk_api>
  - 模块数: <modules.length>
  - ArkTS 文件: <files.total_ets_files> 个, 共约 <files.total_lines> 行

🔒 安全攻击面速览
  - 申请权限: <security_surface.total_permissions> 个 (其中高危 <security_surface.total_high_risk_permissions> 个)
  - 导出组件: <security_surface.exported_abilities_count> 个 Ability, <security_surface.exported_extensions_count> 个 Extension
  - 明文流量: <security_surface.has_cleartext_traffic ? "⚠️ 已开启" : "✅ 已关闭">
  - WebView: <security_surface.has_webview ? "⚠️ 使用了" : "✅ 未使用">
  - 数据库: <security_surface.has_database ? "⚠️ 使用了" : "✅ 未使用">
  - 分布式: <security_surface.has_distributed ? "⚠️ 使用了" : "✅ 未使用">
  - NAPI 模块: <security_surface.has_napi ? "是" : "否">

📦 模块列表
  <遍历 modules，对每个 module 输出>:
  - <module.name> (<module.type>)
    - Abilities: <module.abilities.length> 个 <列出导出标记>
    - Extensions: <module.extension_abilities.length> 个
    - 权限: <module.permissions.length> 个
    - Pages: <module.pages.length> 个

📊 依赖统计
  - 生产依赖: <dependencies.production.length> 个
  - 开发依赖: <dependencies.dev.length> 个
  - 第三方 SDK: <dependencies.third_party_count> 个
```

### Step 4: 返回结构化数据（供 agent 编排器分发）

将以下信息返回给 Agent 编排器，供后续 skill 并行使用：

```yaml
output:
  # 完整元数据（传给 report-generator）
  metadata: <完整的 project-metadata JSON 对象>

  # 下游 skill 会使用的关键数据
  project_path: <项目根路径>
  module_count: <模块数>
  total_files: <源文件总数>

  # 各 skill 的输入指针
  permission_audit_input:
    modules: <modules 中的 permissions 部分>

  component_audit_input:
    modules: <modules 中的 abilities + extension_abilities 部分>

  secrets_audit_input:
    ets_sources: <files.ets_sources>
    ts_sources: <files.ts_sources>

  network_audit_input:
    network_config: <modules 中的 network_config 部分>
    certificates: <files.certificates>

  webview_audit_input:
    uses_webview: <security_surface.has_webview>
    ets_sources: <files.ets_sources>

  crypto_audit_input:
    uses_crypto: <security_surface.uses_crypto>
    ets_sources: <files.ets_sources>

  data_storage_audit_input:
    has_database: <security_surface.has_database>
    ets_sources: <files.ets_sources>

  code_quality_audit_input:
    ets_sources: <files.ets_sources>
    ts_sources: <files.ts_sources>

  report_generator_input:
    metadata: <完整的 project-metadata JSON 对象>
```

## 依赖关系

- **上游**: 无 (这是审计流程的第一个 skill)
- **下游**: harmony-permission-audit, harmony-component-audit, harmony-secrets-audit, harmony-network-audit, harmony-webview-audit, harmony-crypto-audit, harmony-data-storage-audit, harmony-code-quality-audit, harmony-report-generator

## 输出文件的 Schema

参见 `templates/project-metadata-schema.json`

## 错误处理

| 场景 | 处理方式 |
|------|---------|
| 项目路径不存在 | 立即报错给用户，不继续执行 |
| Python 未安装 | 提示用户安装 Python 3.8+ |
| module.json5 解析失败 | 记录到 `_meta.parse_errors`，不阻断其他模块 |
| build-profile.json5 不存在 | 标记 version 信息为空，不阻断 |
| oh-package.json5 不存在 | 标记依赖信息为空，不阻断 |
| 脚本执行超时(>120s) | 终止脚本，提示用户项目可能过大 |
| 空项目目录 | 输出警告，文件统计均为 0 |

## 脚本文件列表

| 文件 | 职责 |
|------|------|
| `scripts/project_scanner.py` | 主入口，编排所有分析器 |
| `scripts/json5_parser.py` | JSON5 解析器 |
| `scripts/file_collector.py` | 文件收集器 |
| `scripts/module_analyzer.py` | module.json5 分析器 |
| `scripts/dependency_analyzer.py` | 依赖和构建配置分析器 |
