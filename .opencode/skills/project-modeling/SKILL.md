---
name: project-modeling
description: 确定性解析 HarmonyOS JSON5 工程配置，为组件任务生成提供项目事实与入口候选。
slash: false
---

`project_profiler.py` 使用 `json5` 解析 app/module/package/build-profile 配置。根级 `build-profile.json5` 定义实际参与构建的生产模块；没有模块声明时，才回退到仓库中全部生产 `module.json5`。`test/ohosTest/mock` 配置不进入审计范围。

模型为每个模块生成由“模块根路径+模块名”确定的稳定 `module_id`，明确记录 HAP/HSP/HAR 输出类型、Product/Target 归属、Build Mode、组件和模块内权限。审计范围默认使用所有 Product 的模块并集，避免漏掉渠道或企业版模块。模块 `oh-package.json5` 中指向本仓库模块的 `file:` 依赖会生成 `module_dependencies` 边。每个构建组件生成一个不表示外部可达的 `component_scope` 候选，运行时将它和 Manifest 触发渠道按组件归并，保证每个组件只创建一个语义任务；候选是否对应真实 callback 由组件任务确认。

```bash
python3 .opencode/skills/project-modeling/scripts/project_profiler.py \
  <target_repo> --output <run_dir>/project/project_model.json
```

项目模型完成后准备 Atlas 索引：

```bash
python3 .opencode/skills/project-modeling/scripts/atlas_indexer.py \
  <target_repo> --output <run_dir>/atlas/index_status.json
```

索引准入条件为 `ok=true,status=ready,files_indexed>0`。Profiler 的输出边界是 JSON5/Manifest 项目事实与入口候选；ArkTS 源码事实由 Atlas 和后续分析 Agent 处理。
