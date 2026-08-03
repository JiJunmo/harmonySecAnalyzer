# 里程碑 4：Project Model v2 与故障恢复

状态：已完成  
完成日期：2026-07-31

## Project Model v2

Profiler 现在确定性解析：

- `app.json5`：bundle、vendor、版本和 API 级别。
- 根 `build-profile.json5`：产品、Build Mode、模块根、Target 和产品参与关系。
- `module.json5`：HAP/HSP/HAR、Ability、ExtensionAbility、组件属性和生命周期。
- `oh-package.json5`：dependencies/devDependencies/dynamicDependencies、本地 file 依赖和模块依赖图。
- requestPermissions、definePermissions、Used Scene 和组件权限。
- Deeplink、Implicit Want、CommonEvent、IPC/RPC Service 和 DataShare Provider 入口锚点。

声明了根 build profile 时，只有声明参与构建的模块进入活动组件和入口集合；测试源码集和未声明模块不会进入审计范围，但会保留诊断及 discovered 统计。

模型生成后执行 Draft 2020-12 Schema 校验。状态为：

- `complete`：没有错误诊断。
- `partial`：配置可建模但存在缺失 Manifest 或解析错误。
- `failed`：输出不满足 Project Model Schema。

## 任务租约

claim 写入：

```text
claimed_at
lease_expires_at
worker_id
```

过期租约可确定性回收到 queued；旧执行提交时因任务已不再 running 而被忽略。新 worker 再次 claim 时 attempt 递增。

## Resume Generation

每次显式 resume：

1. 回收所有遗留 running task。
2. 可重试 exhausted task，并重置其 attempts。
3. 将 failed/complete_with_gaps 恢复为 running。
4. `resume_generation` 加一。
5. LangGraph thread ID 使用 `<run-id>:g<generation>`。

旧 checkpoint 保留用于审计，但不会让新执行直接返回旧 failed/complete 状态。`run.db` 始终是恢复事实源。

## CLI

```text
audit <repository>
status <run-directory>
resume <run-directory> [--capacity 1..5]
cancel <run-directory>
report <run-directory>
```

- 成功输出稳定 JSON，退出码 0。
- 运行错误输出 JSON，退出码 1。
- 参数错误输出 usage 和 JSON，退出码 2。
- `report` 只重建报告，不改变 Run 状态。
- `cancel` 将 queued/running task 一并置为 cancelled。

## 验证覆盖

- 声明式多模块 HAP/HSP 工程。
- 产品、Target、权限和本地 file 依赖。
- 排除 ohosTest 和未参与构建模块。
- CommonEvent 与 IPC/RPC 锚点。
- 过期租约回收和 stale execution 拒绝。
- failed Run 回收 running task。
- cancel 后禁止 resume。
- graph.db 缺失时从 run.db 重建报告。
- 保留 failed checkpoint 时通过新 generation 完成恢复。
- status/report/cancel CLI。
