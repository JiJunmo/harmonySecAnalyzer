# harmonySecAnalyzer-v3.1

适配 opencode 的鸿蒙 ArkTS 代码仓白盒安全审计多智能体系统。

## 是什么

用 opencode 原生 `agent / subagent / skill / command` 机制 + [atlas MCP](https://github.com/LordCasser/atlas)（适配 ArkTS 的代码索引/调用图/数据流引擎）编排多智能体，对鸿蒙 ArkTS 代码仓做白盒安全审计与漏洞挖掘，输出结构化漏洞报告（含 CWE 映射、污点链、修复建议）。

完整设计见 [DESIGN.md](./DESIGN.md)。

## 架构（四阶段流水线）

`项目解析 → 逻辑审计与漏洞发现 → 漏洞验证 → 报告生成`

| 阶段 | Agent | 状态 |
|---|---|---|
| 编排 | `harmony-auditor`（primary） | ✅ P1 |
| 项目解析 / 侦察 | `codebase-scout` | ✅ P1 |
| 逻辑审计 | `manifest-auditor` | ✅ P1 |
|  | arkts-sast / taint-analyst / crypto / network / icc / web / napi / dependency | ⏳ P2/P3 |
| 漏洞验证 | `vuln-verifier` | ⏳ P3 |
| 报告生成 | `report-composer` | ✅ P1 |

## 依赖

- [opencode](https://opencode.ai)
- [atlas](https://github.com/LordCasser/atlas)：已配置于 `/Users/jixiaokui/.cargo/bin/atlas`（见 `opencode.json` 的 `mcp.atlas`）
- semgrep（P2 起需要）

## 使用

```bash
opencode
# 在 opencode 内
/audit manifest /path/to/harmony/repo
```

报告输出到 `reports/<run>/`（`findings.json` + `report.md`）。

## 配置模型

所有 agent 均未写死 `model` 字段，统一跟随 opencode 默认模型。运行前用 `opencode auth login` 配置 provider（anthropic / openai / glm 等），启动后在 TUI 用 `/model` 选择模型，所有 agent 即用该模型。

## 目录

- `.opencode/`：opencode 资源（agents/commands/skills/tools/plugins）—— opencode 强制约定目录
- `rules/`：semgrep 规则库
- `knowledge/`：漏洞知识库、权限映射、CWE 表
- `examples/` `tests/`：规则回归
- `reports/`：审计产出（gitignore）
- `tools/`：独立 CLI 工具（P4）

## 路线图

- [x] **P1 骨架**：harmony-auditor + codebase-scout + manifest-auditor + report-composer + `/audit` + audit-workflow skill + atlas 接入
- [ ] **P2 核心**：arkts-sast / taint-analyst / crypto / network / icc / web + semgrep 规则 + atlas 污点
- [ ] **P3 深度**：napi / dependency + vuln-verifier + finding_dedupe + plugin 轨迹
- [ ] **P4 进阶**：装饰器数据流 + 报告导出
