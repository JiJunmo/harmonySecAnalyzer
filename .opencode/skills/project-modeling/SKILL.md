---
name: project-modeling
description: 确定性解析 HarmonyOS JSON5 工程配置，为组件任务生成提供项目事实与入口候选。
---

`project_profiler.py` 使用 `json5` 解析 app/module/package/build-profile 配置，输出 module、component、权限、依赖及 `entry_candidates`。运行时根据这些候选确定性生成组件分析单元；候选是否对应真实 callback 由组件任务确认。

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
