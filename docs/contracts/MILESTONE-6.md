# 里程碑 6：Web 审计控制台与服务接口

状态：已完成  
完成日期：2026-07-31  
依赖：里程碑 5

## 已交付

- `packages/interface`：路径授权、后台任务、运行登记、事件总线和 Application Service。
- `apps/server`：无领域重复逻辑的 HTTP API、SSE、Bearer Token、静态控制台与报告服务。
- `apps/web`：项目解析、范围选择、运行列表、5 槽状态、任务进度、Finding、覆盖缺口和报告预览。
- `AuditStore.status()` 提供只读任务与 Finding 快照，继续以 `run.db` 为唯一事实源。
- Web 创建任务后立即返回 Job；项目准备、运行和完成通过 SSE 更新。
- 支持导入、取消、恢复已有 Run，并从规范化事实重建报告。

## 不变量

- Web 前端不得读取 SQLite、执行 Atlas 或持有模型密钥。
- API 不接受相对路径或白名单外路径。
- 关闭浏览器不取消审计任务。
- `report.html` 仍是可离线交付的冻结产物；控制台只负责运行管理和预览。
- CLI 和 Web 必须调用同一 Orchestrator 与 Domain Runtime。

## 验证门槛

- Application Service 的 Run 导入、报告重建和路径逃逸测试。
- HTTP API 的认证、Run 查询、报告重建和静态页面测试。
- 前端 JavaScript 语法检查。
- 全 workspace 类型检查、测试和构建通过。

## 后续边界

多用户 RBAC、OIDC、HTTPS 终止、跨进程持久化 Job Registry、分布式 Worker 和生产级指标后端不属于本里程碑。
