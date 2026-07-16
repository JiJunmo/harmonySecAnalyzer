---
name: project-modeling
description: 确定性解析 HarmonyOS/OpenHarmony JSON5 工程配置，生成 project_model.json 与 Atlas discovery_plan.json。编排者在攻击面测绘前调用；不读取或扫描源码内容。
---

## 定位

`scripts/project_profiler.py` 只读取 Harmony JSON5 配置并生成 Atlas 查询锚点，不读取源码内容，也不判断漏洞、风险等级或 guard 是否有效。源码结构、调用关系和 Web/JSBridge 能力统一交给 Atlas MCP 按需分析。

运行前安装依赖：项目内执行 `python3 -m pip install -r requirements.txt`；全局 skill 环境可执行 `python3 -m pip install 'json5>=0.12,<1'`。

## 调用

调用方提供 `target_repo` 和 `run_dir`。skill 负责将它们映射为以下确定性命令；其他 agent 不应复制或改写这条命令：

```bash
python3 .opencode/skills/project-modeling/scripts/project_profiler.py \
  <target_repo> \
  --output <run_dir>/project/project_model.json \
  --plan-output <run_dir>/atlas/discovery_plan.json
```

命令输出 JSON 摘要；完整模型写入指定位置。

## project_model.json

模型包含：

- `application`：`app.json5` 中的应用标识、版本和厂商事实。
- `modules`：每个 `module.json5` 的模块类型、设备类型、权限与组件声明。
- `components`：Ability/ExtensionAbility 的统一扁平视图，含 exported、permission、skills、URI 和生命周期候选。
- `entry_candidates`：由 Manifest 事实确定性推导的入口候选；它只是事实候选，不等于外部可达。
- `dependencies`：`oh-package.json5` 的 dependencies/devDependencies/dynamicDependencies。
- `build_profiles`：`build-profile.json5` 中的 products/modules 摘要。
- `diagnostics`：解析失败、结构异常或缺失配置。`status=partial` 时不得静默当作完整覆盖。

## discovery_plan.json

- 每个具有 Manifest 入口候选的组件生成一个 `AU-xxx` analysis unit。
- unit 包含 Atlas `search` 必需的 project-relative `scope`、组件/生命周期 anchors、source file hint 和 project candidate IDs。
- 初始状态为 `planned`;mapper 更新为 `completed/excluded/unresolved/atlas_gap`。
- `source_content_scanned=false` 是固定契约,确保 profiler 不承担源码扫描。

## 职责边界

- profiler 记录 `exported=true`、URI、permission、source scope/file hint 等 Manifest 事实。
- `attack-surface-mapper` 按 discovery plan 用 Atlas 判断入口类型、关联真实代码符号并从可达上下文发现 Web/JSBridge。
- `path-validator` 基于模型事实和代码证据判断实际外部可达、guard 与安全边界。
- profiler 不生成 `entry_list.json`、`danger_seed_list.json` 或 finding。
- NAPI/native 分析不在本轮 project-modeling 和 mapper 流程中,后续单独扩展。
