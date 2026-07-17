# harmonySecAnalyzer-v3.1

面向 HarmonyOS ArkTS 工程的白盒安全审计多智能体系统，运行于
[OpenCode](https://opencode.ai)，使用 [Atlas](https://github.com/LordCasser/atlas)
完成代码检索、调用关系和数据流分析。

系统采用“确定性建模 + 攻击路径发现 + 反证优先验证”的方式工作。外部可达、敏感
API 或调用链本身只代表攻击面；只有攻击者可控输入越过有效安全边界并产生具体影响，
才会被确认为漏洞。

## 快速开始

安装 Python 依赖：

```bash
python3 -m pip install -r requirements.txt
```

启动 OpenCode 后执行：

```text
/audit manifest /path/to/harmony/repo
```

审计产物写入独立目录：

```text
reports/<project>-<path-hash>/<timestamp>-<scope>-<run-id>/
```

同一项目重复审计不会复用或覆盖历史运行。

## 工作流

```text
项目建模 -> 攻击面测绘 -> 攻击路径发现 -> 漏洞验证 -> 报告生成
```

| 环节 | 实现组件 | 职责 |
|---|---|---|
| 总控 | `harmony-auditor` Agent | 启动运行、调度任务、检查准入 |
| 项目建模 | `project-modeling` Skill | 解析 JSON5/Manifest，生成项目模型和发现计划 |
| 攻击面测绘 | `attack-surface-mapper` Agent | 按分析单元使用 Atlas 识别入口和危险能力 |
| 路径编译与调度 | `audit-orchestration` Skill | 归一化入口/危险点，编译稀疏攻击矩阵，管理状态 |
| 路径发现 | `path-finder` Agent | 验证入口到危险操作的可达路径与数据控制关系 |
| 漏洞验证 | `path-validator` Agent | 按六门槛检查防护、边界和影响 |
| 报告 | `report-composer` Agent | 聚合已经验证的结构化结论 |

完整边界和数据契约见 [DESIGN.md](./DESIGN.md)。

## 结论分层

`confirmed_vulnerability` 必须同时满足：

1. 外部可达；
2. 攻击者可控关键参数；
3. 可控值到达敏感操作；
4. 防护缺失或可绕过；
5. 越过身份、权限、来源、域名、路径、组件、数据所有权或业务授权边界；
6. 造成具体安全影响。

未满足全部门槛的路径按证据降级为：

- `protected_exposure`：存在敏感能力，但有效防护限制了滥用。
- `benign_business_flow`：属于预期公开业务，未越过安全边界。
- `residual_risk`：存在可疑路径或薄弱防护，但证据不足以确认漏洞。
- `insufficient_evidence`：关键事实缺失。

## 目录

```text
.opencode/
  commands/audit.md                 # 用户入口
  agents/                           # 编排与工作 Agent
  skills/
    project-modeling/               # 确定性项目建模
    audit-orchestration/            # 状态机、配置和数据契约
    attack-patterns/                # 审计语义与模式卡
    audit-workflow/                 # 端到端流程约束
docs/                               # 辅助设计和测试文档
reports/                            # 运行产物，不提交版本库
tests/                              # 单元、契约与语义回归
deploy.py                           # 部署与完整性检查
```

能力启用状态、路由条件和模式绑定的唯一机器配置是
`.opencode/skills/audit-orchestration/config/audit_capabilities.json`。漏洞判定的领域语义
由 `.opencode/skills/attack-patterns/patterns/` 中的模式卡维护。

## 验证

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 deploy.py --check-only
```

`deploy.py` 会检查必需组件、JSON Schema、能力注册表与脚本可执行性。项目当前不接入
Semgrep，也不包含 NAPI/native 审计实现。
