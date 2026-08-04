type Row = Record<string, unknown>;
const rows = (value: unknown): Row[] => Array.isArray(value) ? value as Row[] : [];
const obj = (value: unknown): Row => value && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const strings = (value: unknown): string[] => Array.isArray(value) ? value.map(String) : [];
const escapeHtml = (value: unknown) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const escapeMd = (value: unknown) => String(value ?? "").replaceAll("|", "\\|").replaceAll("\r", "").trim();
const inlineMd = (value: unknown) => escapeMd(value).replaceAll("\n", " ");
const codeMd = (value: unknown) => String(value ?? "-").replaceAll("`", "\\`");
const jsonText = (value: unknown) => JSON.stringify(value ?? {}, null, 2);

const labels: Record<string, string> = {
  complete: "已完成", complete_with_gaps: "完成（存在覆盖缺口）", failed: "失败", cancelled: "已取消", running: "运行中",
  confirmed_vulnerability: "已确认漏洞", residual_risk: "残余风险", insufficient_evidence: "证据不足",
  protected_exposure: "已有有效防护", benign_business_flow: "正常业务行为", verification_incomplete: "验证未完成",
  no_security_relevant_operation: "未发现安全相关操作", entry_excluded: "入口已排除", entry_uncertain: "入口状态不确定",
  confirmed: "已确认", excluded: "已排除", uncertain: "不确定", cross_component: "跨组件", local: "组件内",
  critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示",
  filesystem: "文件系统", injection: "注入", web: "Web 安全", icc: "组件通信", provider: "数据提供", ipc_rpc: "IPC/RPC",
  archive: "压缩包", privacy: "隐私", network: "网络", crypto: "密码学", distributed: "分布式", native_dependency: "Native 与依赖",
  exhausted_task: "任务达到最大重试次数", uncertain_entry: "入口状态不确定", unresolved_targets: "存在未解析调用目标",
  unvalidated_operation_group: "安全相关操作未完成六维验证",
  absent: "未发现有效防护", bypassable: "防护可绕过", effective: "防护有效", unknown: "无法确认",
  direct: "直接证据", derived: "基于源码推导", hypothesis: "待验证假设",
  type_check: "类型检查", publisher_restriction: "发布者限制", permission_check: "权限检查", path_check: "路径检查",
};
const label = (value: unknown) => labels[String(value ?? "")] ?? String(value ?? "-");
const dimensionStatus = (value: unknown): string => {
  if (value === true || value === false) return String(value);
  return String(obj(value).status ?? "unknown");
};
const yesNo = (value: unknown) => dimensionStatus(value) === "true" ? "满足" : dimensionStatus(value) === "false" ? "不满足" : "未知";
const dimensionBasis = (value: unknown) => {
  const dimension = obj(value);
  return [dimension.reason, dimension.evidence_level ? `证据等级：${label(dimension.evidence_level)}` : ""].filter(Boolean).join("；") || "-";
};
const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function reportData(report: Row) {
  const findings = rows(report.findings).slice().sort((a, b) => (severityOrder[String(a.severity)] ?? 9) - (severityOrder[String(b.severity)] ?? 9) || String(a.title).localeCompare(String(b.title)));
  return {
    run: obj(report.run), summary: obj(report.summary), project: obj(report.project), coverage: obj(report.coverage), findings,
    validations: rows(report.validations), groups: rows(report.operation_groups), components: rows(report.component_results),
    paths: rows(report.paths), matrix: rows(report.attack_matrix), evidence: rows(report.evidence), taskCounts: obj(report.task_counts),
  };
}

function validationFor(finding: Row, validations: Row[]): Row {
  const causes = new Set(strings(finding.causes));
  return validations.find((item) => causes.has(String(item.validation_id))) ?? validations.find((item) => item.group_id === finding.root_cause_key) ?? {};
}

function groupFor(finding: Row, groups: Row[]): Row { return groups.find((item) => item.group_id === finding.root_cause_key) ?? {}; }

function evidenceFor(refs: unknown, evidence: Row[]): Row[] {
  const wanted = new Set(strings(refs));
  return evidence.filter((item) => wanted.has(String(item.evidence_id)) || wanted.has(String(item.local_evidence_id)));
}

function pocArtifact(finding: Row): Row {
  const artifact = obj(finding.poc_artifact);
  return Object.keys(obj(artifact.payload)).length ? obj(artifact.payload) : artifact;
}

function pocCode(finding: Row): string {
  const artifact = pocArtifact(finding); const code = String(artifact.code ?? "");
  if (code) return `入口类型：${String(artifact.entry_type ?? "-")}\n触发方式：${String(obj(artifact.trigger).kind ?? "-")}\n\n${code}`;
  return String(finding.poc || "");
}

function pocMarkdown(finding: Row): string {
  const artifact = pocArtifact(finding);
  const preamble: string[] = [];
  const trigger = obj(artifact.trigger); const payload = trigger.payload;
  if (String(artifact.entry_type ?? "")) preamble.push(`- 入口类型：\`${codeMd(artifact.entry_type)}\``);
  if (String(trigger.kind ?? "")) preamble.push(`- 触发方式：\`${codeMd(trigger.kind)}\``);
  const payloadText = typeof payload === "string" ? payload : JSON.stringify(payload);
  if (payloadText && payloadText !== "{}") preamble.push(`- 触发载荷：\`${codeMd(payloadText)}\``);
  if (String(artifact.language ?? "")) preamble.push(`- 语言：\`${codeMd(artifact.language)}\``);
  const prerequisites = strings(artifact.prerequisites);
  if (prerequisites.length) preamble.push(`- 前置条件：${prerequisites.map((item) => `\`${codeMd(item)}\``).join("、")}`);
  if (preamble.length) preamble.push("");
  const expected = String(artifact.expected_observation ?? "");
  const limitations = String(artifact.limitations ?? "");
  const body = [
    ...preamble,
    expected ? `**预期现象**：${inlineMd(expected)}` : "",
    limitations ? `> 复现限制：${inlineMd(limitations)}` : "",
  ].filter((line) => line.length);
  const code = String(artifact.code ?? "") || String(finding.poc || "");
  return [...body, code ? `\`\`\`${codeMd(artifact.language || "typescript")}\n${code}\n\`\`\`` : "未提供 PoC"].join("\n");
}

function recommendations(finding: Row, group: Row): string[] {
  const category = String(group.category ?? ""); const cwe = String(finding.cwe ?? "");
  const common = ["在修复后增加针对外部入口、边界条件和绕过路径的自动化回归测试。"];
  if (category === "filesystem" || ["CWE-22", "CWE-73"].includes(cwe)) return ["对外部输入的文件路径执行规范化，并将最终路径限制在明确的业务目录白名单内。", "在执行文件读写前校验调用来源、业务授权和目标资源所有权；不要只依赖字符串类型检查。", ...common];
  if (category === "injection" || cwe.startsWith("CWE-89")) return ["使用参数化查询或结构化 API，禁止将外部输入拼接到查询语句、谓词或命令中。", "按业务语义校验允许的字段、操作符和取值范围，并拒绝未知输入。", ...common];
  if (category === "web") return ["对可加载 URL 实施协议、主机和路径白名单，默认拒绝非预期来源。", "缩小 JSBridge 暴露面，并在每个桥接方法内重新校验页面来源、调用身份和参数。", ...common];
  if (["icc", "provider", "ipc_rpc"].includes(category)) return ["收紧组件导出和路由配置，并通过系统权限或签名级权限限制调用方。", "在敏感操作执行点校验真实调用主体、资源所有权和受控参数，避免只在上游界面校验。", ...common];
  if (String(group.capability_id).includes("DOS")) return ["为外部可触发操作设置输入上限、频率限制、超时和资源配额。", "将异常处理与故障隔离放在敏感资源操作边界，确保单次输入不会造成持续不可用。", ...common];
  return ["在敏感操作执行点落实报告中描述的预期安全边界，并对调用主体与关键参数进行强校验。", ...common];
}

function mdList(values: unknown, empty = "无"): string { const items = strings(values); return items.length ? items.map((item) => `\`${codeMd(item)}\``).join("、") : empty; }

export function renderMarkdown(report: Row): string {
  const { run, summary, project, coverage, findings, validations, groups, components, paths, matrix, evidence, taskCounts } = reportData(report);
  const application = obj(project.application); const scope = obj(run.audit_scope); const classification = obj(summary.classifications); const severity = obj(summary.severities);
  const incremental = obj(run.incremental); const changeSet = obj(incremental.change_set); const impactPlan = obj(incremental.impact_plan); const riskChanges = obj(incremental.risk_path_changes);
  const lines: string[] = [
    "# HarmonyOS 应用白盒安全审计报告", "",
    "> 本报告基于项目静态解析、组件语义路径发现和六维有效性验证生成。报告结论仅覆盖本次配置的代码、组件与能力范围。", "",
    "## 1. 审计概览", "",
    `- 应用：${inlineMd(application.bundle_name || "未识别应用包名")}`,
    `- 审计目标：\`${codeMd(run.target_repo)}\``,
    `- 运行编号：\`${codeMd(run.run_id)}\``,
    `- 审计状态：**${label(run.status)}**`,
    `- 创建时间：${inlineMd(run.created_at)}`,
    `- 组件范围：${mdList(scope.components, "全部组件")}`,
    `- 能力范围：${mdList(scope.capabilities, "全部已启用能力")}`, "",
    "### 结果摘要", "",
    "| 指标 | 数量 |", "|---|---:|",
    `| 组件目录 | ${summary.entries ?? 0} |`, `| 已分析组件 | ${summary.analyzed_components ?? 0} |`,
    `| 跨组件路径 | ${summary.paths ?? 0} |`, `| 组件调用 | ${summary.component_calls ?? 0} |`,
    `| 安全相关操作组 | ${summary.operation_groups ?? 0} |`, `| 六维验证结果 | ${summary.validations ?? 0} |`,
    `| 需要处置的安全发现 | ${summary.findings ?? 0} |`, `| 覆盖缺口 | ${summary.coverage_gaps ?? 0} |`, "",
    "### 风险分布", "",
    `- 已确认漏洞：${classification.confirmed_vulnerability ?? 0}`,
    `- 残余风险：${classification.residual_risk ?? 0}`,
    `- 已有有效防护：${classification.protected_exposure ?? 0}`,
    `- 正常业务行为：${classification.benign_business_flow ?? 0}`,
    `- 证据不足：${classification.insufficient_evidence ?? 0}`,
    `- 风险等级：严重 ${severity.critical ?? 0} / 高危 ${severity.high ?? 0} / 中危 ${severity.medium ?? 0} / 低危 ${severity.low ?? 0} / 提示 ${severity.info ?? 0}`, "",
  ];
  if (scope.mode === "incremental") lines.push(
    "### 增量审计摘要", "",
    `- 基线运行：\`${codeMd(changeSet.baseline_run_id || "-")}\``,
    `- 变化文件：${changeSet.changed_file_count ?? 0}`,
    `- 重新分析入口：${strings(impactPlan.affected_entries).length}`,
    `- 复用语义入口：${strings(impactPlan.reusable_entries).length}`,
    `- 风险变化：新增 ${rows(riskChanges.added).length} / 变化 ${rows(riskChanges.changed).length} / 已消失 ${rows(riskChanges.removed).length} / 未变化 ${rows(riskChanges.unchanged).length}`, "",
  );
  lines.push("## 2. 需要处置的安全发现", "");
  if (!findings.length) lines.push("本次审计未生成已确认漏洞或残余风险。该结果不等同于形式化安全证明，请结合覆盖缺口和组件审计结果判断。", "");
  findings.forEach((finding, index) => {
    const validation = validationFor(finding, validations); const assessment = obj(validation.payload); const group = groupFor(finding, groups); const groupPayload = obj(group.payload);
    const intent = obj(assessment.business_intent); const boundary = obj(assessment.security_boundary); const principal = obj(assessment.principal_analysis); const exploitability = obj(assessment.exploitability);
    const facts = rows(groupPayload.facts); const referenced = evidenceFor(assessment.evidence_refs, evidence); const fixes = recommendations(finding, group);
    lines.push(
      `### 2.${index + 1} ${inlineMd(finding.title)}`, "",
      `- 风险编号：\`${codeMd(finding.finding_id)}\``, `- 判定：**${label(finding.classification || validation.classification)}**`,
      `- 风险等级：**${label(finding.severity)}**`, `- CWE：\`${codeMd(finding.cwe || "-")}\``,
      `- 所属能力：\`${codeMd(group.capability_id || validation.capability_id || "-")}\``, `- 影响组件：\`${codeMd(group.entry_id || "-")}\``,
      `- 敏感操作：\`${codeMd(obj(groupPayload.operation).body || obj(groupPayload.operation).location || "-")}\``,
      `- 源码位置：\`${codeMd(obj(groupPayload.operation).location || "-")}\``, "",
      "#### 影响", "", escapeMd(finding.impact || "未记录具体影响。"), "",
      "#### 根因与安全边界", "",
      `- 业务用途：${inlineMd(intent.declared_or_inferred_purpose || obj(groupPayload.context).intended_behavior || "-")}`,
      `- 预期安全边界：${inlineMd(boundary.expected_boundary || "-")}`,
      `- 边界突破原因：${inlineMd(boundary.reason || "-")}`,
      `- 防护判定：${label(assessment.security_check_outcome)}`,
      ...(Object.keys(principal).length ? [`- 身份与权限：来源主体 ${inlineMd(principal.origin_principal || "-")}，目标观察主体 ${inlineMd(principal.target_observed_principal || "-")}，使用权限 ${inlineMd(principal.authority_used || "-")}`] : []), "",
      "#### 六维有效性验证", "",
      "| 维度 | 结果 | 依据 |", "|---|---|---|",
      `| 外部可达 | ${yesNo(exploitability.externally_reachable)} | ${inlineMd(dimensionBasis(exploitability.externally_reachable))} |`,
      `| 关键参数可控 | ${yesNo(exploitability.attacker_controlled)} | ${inlineMd(dimensionBasis(exploitability.attacker_controlled))} |`,
      `| 可达敏感操作 | ${yesNo(exploitability.sink_reached)} | ${inlineMd(dimensionBasis(exploitability.sink_reached))} |`,
      `| 防护缺失或可绕过 | ${yesNo(exploitability.security_check_bypassed_or_absent)} | ${inlineMd(dimensionBasis(exploitability.security_check_bypassed_or_absent))} |`,
      `| 安全边界被突破 | ${yesNo(exploitability.boundary_violated)} | ${inlineMd(dimensionBasis(exploitability.boundary_violated))} |`,
      `| 存在具体影响 | ${yesNo(exploitability.concrete_impact)} | ${inlineMd(dimensionBasis(exploitability.concrete_impact))} |`, "",
    );
    const checks = rows(groupPayload.security_checks); if (checks.length) {
      lines.push("#### 已识别防护", "");
      for (const check of checks) lines.push(`- **${inlineMd(check.type || "安全检查")}**：${inlineMd(check.behavior || check.protects || "-")}；校验对象 \`${codeMd(check.validated_property || "-")}\`；位置 \`${codeMd(check.location || "-")}\``);
      lines.push("");
    }
    const counters = rows(assessment.counter_evidence); if (counters.length) { lines.push("#### 反证与降级依据", "", ...counters.map((item) => `- ${inlineMd(item.reason || item.kind)}`), ""); }
    if (facts.length || referenced.length) {
      lines.push("#### 源码证据链", "");
      for (const fact of facts) lines.push(`- **${inlineMd(fact.type)}**：${inlineMd(fact.body)}；位置 \`${codeMd(fact.location || "-")}\``);
      for (const item of referenced) lines.push(`- **${inlineMd(item.kind)}**：${inlineMd(obj(item.payload).summary || item.source)}；位置 \`${codeMd(item.location || item.source || "-")}\``);
      lines.push("");
    }
    lines.push("#### 修复建议", "", ...fixes.map((item) => `- ${inlineMd(item)}`), "");
    lines.push("#### 验证方式 / PoC", "", pocMarkdown(finding), "");
  });

  lines.push("## 3. 组件审计结果", "", "本节覆盖所有进入审计目录的组件，包括未发现漏洞、已有有效防护和未完成验证的组件。", "");
  components.forEach((component, index) => {
    const componentCoverage = obj(component.coverage); const operationGroups = rows(component.operation_groups);
    lines.push(
      `### 3.${index + 1} ${inlineMd(component.component_name || component.entry_id)}`, "",
      `- 审计结论：**${label(component.status)}**`, `- 所属模块：\`${codeMd(component.module_name || component.module_id || "-")}\``,
      `- 源码入口：\`${codeMd(component.source || "-")}\``, `- 是否导出：${component.exported === true ? "是" : component.exported === false ? "否" : "未知"}`,
      `- 组件功能：${inlineMd(component.function_summary)}`, `- 入口状态：${label(componentCoverage.entry_status)}`,
      `- 已检查入口：${mdList(componentCoverage.entry_symbols_checked)}`, `- 已检查操作位置：${mdList(componentCoverage.operation_sites_checked)}`, "",
      "#### 安全相关操作与验证", "",
    );
    if (!operationGroups.length) lines.push("- 未识别到可达的安全相关操作。", "");
    for (const group of operationGroups) {
      const payload = obj(group.payload); const operation = obj(payload.operation); const validation = obj(group.validation); const assessment = obj(validation.payload);
      lines.push(`- **${inlineMd(group.title)}** · ${label(group.classification)} · ${label(group.scope)}`,
        `  - 操作：\`${codeMd(operation.body || "-")}\``, `  - 位置：\`${codeMd(operation.location || "-")}\``,
        `  - 外部受控属性：${mdList(payload.controlled_properties, "无")}`, `  - 结论：${inlineMd(assessment.impact || assessment.demotion_reason || assessment.evidence_gap || "尚未形成完整验证结论")}`);
    }
    if (operationGroups.length) lines.push("");
    const notes = strings(component.review_notes); if (notes.length) lines.push("#### 人工复核提示", "", ...notes.map((note) => `- ${inlineMd(note)}`), "");
  });

  lines.push("## 4. 跨组件攻击路径", "");
  if (!paths.length) lines.push("未形成跨组件路径。", "");
  paths.forEach((path, index) => { const payload = obj(path.payload); lines.push(
    `### 4.${index + 1} ${inlineMd(path.root_entry_id)} → ${inlineMd(path.target_entry_id)}`, "",
    `- 路径编号：\`${codeMd(path.path_id)}\``, `- 组件链：${mdList(payload.component_ids)}`, `- 入口链：${mdList(payload.entry_ids)}`,
    `- 调用链：${mdList(payload.call_keys)}`, `- 是否存在环：${path.cycle ? "是" : "否"}`,
    `- 来源主体：${inlineMd(obj(payload.principal_state).origin_principal || "-")}`, `- 目标观察主体：${inlineMd(obj(payload.principal_state).target_observed_principal || "-")}`, "",
  ); });

  const modules = rows(project.modules); const projectComponents = rows(project.components);
  lines.push("## 5. 项目结构与攻击面", "", `- 应用包名：\`${codeMd(application.bundle_name || "-")}\``, `- 版本：${inlineMd(application.version_name || "-")}（${inlineMd(application.version_code || "-")}）`,
    `- 模块数量：${modules.length}`, `- 组件数量：${projectComponents.length}`, `- 申请权限：${rows(project.requested_permissions).length}`, `- 依赖数量：${rows(project.dependencies).length}`, "",
    "### 模块", "", "| 模块 | 类型 | 根目录 | 构建产物 |", "|---|---|---|---|",
    ...modules.map((item) => `| ${inlineMd(item.name)} | ${inlineMd(item.type)} | \`${codeMd(item.root)}\` | ${inlineMd(item.output_kind)} |`), "",
    "### 组件", "", "| 组件 | 类型 | 模块 | 导出 | 权限 | 源码 |", "|---|---|---|---|---|---|",
    ...projectComponents.map((item) => `| ${inlineMd(item.name)} | ${inlineMd(item.extension_type || item.kind)} | ${inlineMd(item.module_name)} | ${item.exported === true ? "是" : item.exported === false ? "否" : "未知"} | ${inlineMd(strings(item.permissions).join("、") || "-")} | \`${codeMd(item.source_file_hint || item.src_entry || "-")}\` |`), "",
    "## 6. 覆盖情况与缺口", "", `- 覆盖状态：**${coverage.status === "complete" ? "完整" : "部分完成"}**`,
    `- 任务状态：${Object.entries(taskCounts).map(([key, value]) => `${label(key)} ${value}`).join(" / ") || "无任务记录"}`, "",
  );
  const gaps = rows(coverage.gaps); if (!gaps.length) lines.push("未记录覆盖缺口。", ""); else gaps.forEach((gap) => lines.push(`- **${label(gap.kind)}** \`${codeMd(gap.subject_id)}\`：${inlineMd(typeof gap.details === "string" ? gap.details : jsonText(gap.details))}`));
  lines.push("", "## 7. 攻击矩阵附录", "", "| 入口 | 能力 | 范围 | 验证结论 | Finding |", "|---|---|---|---|---|",
    ...matrix.map((item) => `| \`${codeMd(item.entry_id)}\` | \`${codeMd(item.capability_id)}\` | ${label(item.scope)} | ${label(item.classification)} | \`${codeMd(item.finding_id || "-")}\` |`), "",
    "---", "", "本报告由 HarmonyOS 白盒安全审计插件自动生成。建议由安全工程师结合源码、运行环境和业务设计进行最终复核。", "");
  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trim()}\n`;
}

const badge = (value: unknown) => `<span class="badge ${escapeHtml(value)}">${escapeHtml(label(value))}</span>`;
const codeList = (value: unknown) => strings(value).length ? strings(value).map((item) => `<code>${escapeHtml(item)}</code>`).join(" ") : '<span class="muted">无</span>';
const dimensionNames: Record<string, string> = { externally_reachable: "外部可达", attacker_controlled: "关键参数可控", sink_reached: "到达敏感操作", security_check_bypassed_or_absent: "防护缺失或可绕过", boundary_violated: "突破安全边界", concrete_impact: "存在具体影响" };

export function renderHtml(report: Row): string {
  const data = reportData(report); const { run, summary, project, coverage, findings, validations, groups, components, paths, matrix, evidence, taskCounts } = data;
  const application = obj(project.application); const title = application.bundle_name || "HarmonyOS 应用安全审计"; const classification = obj(summary.classifications);
  const incremental = obj(run.incremental); const changeSet = obj(incremental.change_set); const impactPlan = obj(incremental.impact_plan); const riskChanges = obj(incremental.risk_path_changes);
  const incrementalHtml = obj(run.audit_scope).mode === "incremental" ? `<div class="panel"><h2>增量审计</h2><dl class="kv"><dt>基线运行</dt><dd><code>${escapeHtml(changeSet.baseline_run_id || "-")}</code></dd><dt>变化文件</dt><dd>${escapeHtml(changeSet.changed_file_count ?? 0)}</dd><dt>重新分析入口</dt><dd>${strings(impactPlan.affected_entries).length}</dd><dt>复用语义入口</dt><dd>${strings(impactPlan.reusable_entries).length}</dd><dt>风险变化</dt><dd>新增 ${rows(riskChanges.added).length} / 变化 ${rows(riskChanges.changed).length} / 已消失 ${rows(riskChanges.removed).length} / 未变化 ${rows(riskChanges.unchanged).length}</dd></dl></div>` : "";
  const findingHtml = findings.length ? findings.map((finding, index) => {
    const validation = validationFor(finding, validations); const assessment = obj(validation.payload); const group = groupFor(finding, groups); const payload = obj(group.payload); const operation = obj(payload.operation);
    const intent = obj(assessment.business_intent); const boundary = obj(assessment.security_boundary); const principal = obj(assessment.principal_analysis); const exploitability = obj(assessment.exploitability);
    const dimensions = Object.entries(dimensionNames).map(([key, name]) => {
      const status = dimensionStatus(exploitability[key]);
      return `<div class="dimension ${status === "true" ? "pass" : "fail"}" title="${escapeHtml(dimensionBasis(exploitability[key]))}"><i>${status === "true" ? "✓" : status === "false" ? "×" : "–"}</i><span>${escapeHtml(name)}</span><b>${escapeHtml(yesNo(exploitability[key]))}</b></div>`;
    }).join("");
    const checks = rows(payload.security_checks).map((check) => `<div class="fact"><strong>${escapeHtml(check.type || "安全检查")}</strong><p>${escapeHtml(check.behavior || check.protects || "-")}</p><small>校验 ${escapeHtml(check.validated_property || "-")} · ${escapeHtml(check.location || "-")}</small></div>`).join("");
    const referenced = evidenceFor(assessment.evidence_refs, evidence); const facts = rows(payload.facts);
    const evidenceHtml = [...facts.map((fact) => `<div class="fact"><strong>${escapeHtml(label(fact.type))}</strong><p>${escapeHtml(fact.body)}</p><small>${escapeHtml(fact.location || "-")}</small></div>`), ...referenced.map((item) => `<div class="fact"><strong>${escapeHtml(label(item.kind))}</strong><p>${escapeHtml(obj(item.payload).summary || item.source)}</p><small>${escapeHtml(item.location || item.source || "-")}</small></div>`)].join("");
    const fixes = recommendations(finding, group).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    const poc = pocArtifact(finding); const pocTrigger = obj(poc.trigger);
    const pocMeta = [String(poc.entry_type ?? ""), String(pocTrigger.kind ?? ""), String(poc.language ?? "")].filter(Boolean).map((item) => `<code>${escapeHtml(item)}</code>`).join(" ");
    const pocPrereqs = strings(poc.prerequisites).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    const pocExpected = String(poc.expected_observation ?? ""); const pocLimitations = String(poc.limitations ?? "");
    const pocHtml = Object.keys(poc).length ? `<details open><summary>查看验证方式 / PoC <b class="badge ${escapeHtml(finding.severity)}">${escapeHtml(poc.entry_type || "PoC")}</b></summary><dl class="kv">${pocMeta ? `<dt>入口 / 触发 / 语言</dt><dd>${pocMeta}</dd>` : ""}${pocExpected ? `<dt>预期现象</dt><dd>${escapeHtml(pocExpected)}</dd>` : ""}${pocLimitations ? `<dt>复现限制</dt><dd>${escapeHtml(pocLimitations)}</dd>` : ""}</dl>${pocPrereqs ? `<h5>前置条件</h5><ul class="notes">${pocPrereqs}</ul>` : ""}<pre><code>${escapeHtml(pocCode(finding))}</code></pre></details>` : `<details><summary>查看验证方式 / PoC</summary><pre><code>${escapeHtml(finding.poc || "未提供 PoC")}</code></pre></details>`;
    return `<article class="finding" data-search="${escapeHtml([finding.title, finding.severity, finding.cwe, group.capability_id].join(" ").toLowerCase())}"><header><span class="finding-index">${String(index + 1).padStart(2, "0")}</span><div><p>${badge(finding.classification || validation.classification)} ${badge(finding.severity)}</p><h3>${escapeHtml(finding.title)}</h3><small>${escapeHtml(finding.finding_id)} · ${escapeHtml(finding.cwe)} · ${escapeHtml(group.capability_id || validation.capability_id)}</small></div></header><div class="finding-body"><div class="callout danger"><b>安全影响</b><p>${escapeHtml(finding.impact)}</p></div><div class="grid-2"><section><h4>根因与敏感操作</h4><dl class="kv"><dt>敏感操作</dt><dd><code>${escapeHtml(operation.body || "-")}</code></dd><dt>源码位置</dt><dd><code>${escapeHtml(operation.location || "-")}</code></dd><dt>业务用途</dt><dd>${escapeHtml(intent.declared_or_inferred_purpose || obj(payload.context).intended_behavior || "-")}</dd><dt>防护判定</dt><dd>${escapeHtml(label(assessment.security_check_outcome))}</dd></dl></section><section><h4>安全边界</h4><dl class="kv"><dt>预期边界</dt><dd>${escapeHtml(boundary.expected_boundary || "-")}</dd><dt>突破原因</dt><dd>${escapeHtml(boundary.reason || "-")}</dd><dt>来源主体</dt><dd>${escapeHtml(principal.origin_principal || "-")}</dd><dt>权限使用</dt><dd>${escapeHtml(principal.authority_used || "-")}</dd></dl></section></div><h4>六维有效性验证</h4><div class="dimensions">${dimensions}</div>${checks ? `<h4>已识别防护事实</h4><div class="facts">${checks}</div>` : ""}${evidenceHtml ? `<h4>源码证据链</h4><div class="facts">${evidenceHtml}</div>` : ""}<h4>修复建议</h4><ul class="notes">${fixes}</ul>${pocHtml}</div></article>`;
  }).join("") : '<div class="empty"><strong>未发现需要处置的安全问题</strong><p>请同时查看组件审计结果和覆盖缺口。</p></div>';

  const componentHtml = components.map((component) => { const c = obj(component.coverage); const operationGroups = rows(component.operation_groups);
    const operations = operationGroups.map((group) => { const payload = obj(group.payload); const operation = obj(payload.operation); const validation = obj(group.validation); const assessment = obj(validation.payload); return `<div class="operation"><div><strong>${escapeHtml(group.title)}</strong>${badge(group.classification)}</div><dl class="kv"><dt>敏感操作</dt><dd><code>${escapeHtml(operation.body || "-")}</code></dd><dt>源码位置</dt><dd><code>${escapeHtml(operation.location || "-")}</code></dd><dt>受控属性</dt><dd>${codeList(payload.controlled_properties)}</dd><dt>验证结论</dt><dd>${escapeHtml(assessment.impact || assessment.demotion_reason || assessment.evidence_gap || "尚未完成六维验证")}</dd></dl></div>`; }).join("") || '<p class="muted">未识别到可达的安全相关操作。</p>';
    const notes = strings(component.review_notes).map((note) => `<li>${escapeHtml(note)}</li>`).join("");
    return `<details class="component" data-search="${escapeHtml([component.component_name, component.module_name, component.function_summary, component.status].join(" ").toLowerCase())}"><summary><div>${badge(component.status)}<strong>${escapeHtml(component.component_name || component.entry_id)}</strong><span>${escapeHtml(component.module_name || component.module_id || "-")}</span></div><p>${escapeHtml(component.function_summary)}</p><b>${operationGroups.length} 项安全相关操作</b></summary><div class="component-body"><div class="grid-2"><dl class="kv"><dt>源码入口</dt><dd><code>${escapeHtml(component.source || "-")}</code></dd><dt>是否导出</dt><dd>${component.exported === true ? "是" : component.exported === false ? "否" : "未知"}</dd><dt>入口状态</dt><dd>${escapeHtml(label(c.entry_status))}</dd><dt>初始审计范围</dt><dd>${component.initial_scope ? "是" : "由路径扩展发现"}</dd></dl><dl class="kv"><dt>已检查入口</dt><dd>${codeList(c.entry_symbols_checked)}</dd><dt>操作位置</dt><dd>${codeList(c.operation_sites_checked)}</dd><dt>未解析目标</dt><dd>${codeList(c.unresolved_targets)}</dd></dl></div><h4>安全相关操作与验证</h4>${operations}${notes ? `<h4>人工复核提示</h4><ul class="notes">${notes}</ul>` : ""}</div></details>`;
  }).join("");

  const pathHtml = paths.map((path) => { const payload = obj(path.payload); const related = groups.filter((group) => group.path_id === path.path_id); return `<details class="path"><summary><span>${badge(related[0]?.classification || "verification_incomplete")}<strong>${escapeHtml(path.root_entry_id)} → ${escapeHtml(path.target_entry_id)}</strong></span><code>${escapeHtml(path.path_id)}</code></summary><div class="path-body"><dl class="kv"><dt>组件链</dt><dd>${codeList(payload.component_ids)}</dd><dt>入口链</dt><dd>${codeList(payload.entry_ids)}</dd><dt>调用链</dt><dd>${codeList(payload.call_keys)}</dd><dt>来源主体</dt><dd>${escapeHtml(obj(payload.principal_state).origin_principal || "-")}</dd><dt>目标观察主体</dt><dd>${escapeHtml(obj(payload.principal_state).target_observed_principal || "-")}</dd><dt>权限使用</dt><dd>${escapeHtml(obj(payload.principal_state).authority_used || "-")}</dd></dl>${rows(payload.parameter_chains).length ? `<h4>参数传递链</h4>${rows(payload.parameter_chains).map((chain) => `<div class="fact"><strong>${escapeHtml(chain.origin_property)} → ${escapeHtml(chain.current_property)}</strong><p>${escapeHtml(strings(chain.transforms).join(" → "))}</p><small>控制状态：${escapeHtml(chain.control_state)}</small></div>`).join("")}` : ""}</div></details>`; }).join("") || '<div class="empty">未形成跨组件路径</div>';

  const modules = rows(project.modules); const projectComponents = rows(project.components); const permissions = rows(project.requested_permissions); const dependencies = rows(project.dependencies); const gaps = rows(coverage.gaps);
  const gapHtml = gaps.map((gap) => `<div class="gap"><strong>${escapeHtml(label(gap.kind))}</strong><code>${escapeHtml(gap.subject_id)}</code><p>${escapeHtml(typeof gap.details === "string" ? gap.details : jsonText(gap.details))}</p></div>`).join("") || '<div class="empty">未记录覆盖缺口</div>';
  const matrixHtml = matrix.map((item) => `<tr><td><code>${escapeHtml(item.entry_id)}</code></td><td><code>${escapeHtml(item.capability_id)}</code></td><td>${escapeHtml(label(item.scope))}</td><td>${badge(item.classification)}</td><td><code>${escapeHtml(item.finding_id || "-")}</code></td></tr>`).join("");
  const reportJson = JSON.stringify({ schema_version: report.schema_version, run_id: run.run_id }).replaceAll("<", "\\u003c");
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · 安全审计报告</title><style>
:root{--ink:#18211d;--muted:#6c7671;--paper:#f4f6f3;--surface:#fff;--line:#dfe4df;--green:#174d3b;--lime:#c4df70;--red:#a83f35;--orange:#b86c32;--blue:#396b82}*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--paper);font:14px/1.65 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}button,input{font:inherit}.top{position:sticky;top:0;z-index:5;border-bottom:1px solid var(--line);background:#fff}.top-inner{max-width:1200px;margin:auto;padding:22px 28px 16px}.eyebrow{margin:0;color:var(--green);font-size:10px;font-weight:800;letter-spacing:.15em}.top h1{margin:5px 0 6px;font-size:26px}.runmeta{display:flex;flex-wrap:wrap;gap:6px 20px;color:var(--muted);font-size:11px}.tabs{display:flex;max-width:1200px;margin:auto;padding:0 22px;overflow:auto}.tab{padding:11px 15px;border:0;border-bottom:3px solid transparent;color:var(--muted);background:transparent;cursor:pointer;white-space:nowrap}.tab.active{border-color:var(--green);color:var(--ink);font-weight:750}.view{display:none;max-width:1200px;margin:auto;padding:28px 28px 70px}.view.active{display:block}.hero{padding:28px;border-radius:14px;color:white;background:linear-gradient(135deg,#153f32,#24644e)}.hero h2{margin:5px 0 8px;font-size:25px}.hero p{max-width:820px;margin:0;color:#d5e3dc}.metrics{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:1px;margin:18px 0 22px;border:1px solid var(--line);background:var(--line)}.metric{padding:16px;background:white}.metric strong{display:block;font-size:24px}.metric span{color:var(--muted);font-size:10px}.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{margin-bottom:18px;padding:20px;border:1px solid var(--line);border-radius:10px;background:#fff}.panel h2,.panel h3,.panel h4{margin-top:0}.result-list{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.result{display:flex;justify-content:space-between;padding:11px;border-radius:7px;background:#f7f9f6}.badge{display:inline-block;margin-right:5px;padding:2px 7px;border:1px solid var(--line);border-radius:20px;background:#f5f6f5;font-size:10px;white-space:nowrap}.badge.confirmed_vulnerability,.badge.critical,.badge.high{color:var(--red);border-color:#e8bbb6;background:#fff4f2}.badge.residual_risk,.badge.insufficient_evidence,.badge.verification_incomplete,.badge.medium,.badge.entry_uncertain{color:var(--orange);border-color:#e5c39f;background:#fff8ef}.badge.protected_exposure,.badge.benign_business_flow,.badge.no_security_relevant_operation,.badge.complete,.badge.low{color:var(--green);border-color:#b8d2c5;background:#f1f8f4}.toolbar{display:flex;gap:10px;margin-bottom:14px}.toolbar input{width:min(520px,100%);padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:#fff}.finding,.component,.path{margin-bottom:12px;border:1px solid var(--line);border-radius:10px;background:#fff}.finding>header{display:flex;gap:16px;padding:19px 21px;border-bottom:1px solid var(--line)}.finding-index{color:#a0aaa5;font:700 20px ui-monospace,monospace}.finding h3{margin:5px 0 2px;font-size:18px}.finding header p,.finding header small{margin:0;color:var(--muted)}.finding-body,.component-body,.path-body{padding:20px}.callout{padding:13px 15px;border-left:3px solid var(--orange);background:#fff9f1}.callout.danger{border-color:var(--red);background:#fff5f3}.callout p{margin:4px 0 0}.kv{display:grid;grid-template-columns:120px 1fr;gap:7px 12px}.kv dt{color:var(--muted)}.kv dd{margin:0;min-width:0;overflow-wrap:anywhere}.dimensions{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.dimension{display:grid;grid-template-columns:24px 1fr auto;align-items:center;padding:9px;border:1px solid var(--line);border-radius:7px}.dimension i{font-style:normal;color:var(--muted)}.dimension.pass i{color:var(--green)}.dimension b{font-size:10px}.facts{display:grid;gap:8px}.fact,.operation,.gap{padding:12px;border:1px solid var(--line);border-radius:7px;background:#fafbf9}.fact p,.gap p{margin:4px 0}.fact small{color:var(--muted)}.operation{margin-bottom:8px}.operation>div{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:9px}details>summary{cursor:pointer}.finding details{margin-top:18px}.finding details summary{font-weight:700}.finding pre{max-height:430px;overflow:auto;padding:14px;border-radius:7px;color:#dfeae4;background:#132c24;white-space:pre-wrap}.code-list code,.kv code{display:inline-block;margin:2px;padding:2px 5px;border-radius:4px;background:#edf1ed;font-size:11px}.component>summary{display:grid;grid-template-columns:1.2fr 1.5fr auto;align-items:center;gap:15px;padding:15px 18px;list-style:none}.component>summary div{display:flex;align-items:center;gap:7px}.component>summary span,.component>summary p,.component>summary b{margin:0;color:var(--muted);font-size:11px}.path>summary{display:flex;align-items:center;justify-content:space-between;padding:14px 17px;list-style:none}.path>summary span{display:flex;align-items:center;gap:8px}.notes{color:var(--muted)}.empty{padding:36px;border:1px dashed var(--line);border-radius:9px;color:var(--muted);background:#fff;text-align:center}.empty p{margin-bottom:0}.structure{width:100%;border-collapse:collapse;background:#fff}.structure th,.structure td{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.structure th{color:var(--muted);font-size:10px;background:#fafbf9}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px}.gap{margin-bottom:8px;border-left:3px solid var(--orange)}.gap code{display:block;color:var(--muted);font-size:10px}.muted{color:var(--muted)}.hidden-result{display:none!important}@media(max-width:900px){.metrics{grid-template-columns:repeat(3,1fr)}.grid-2{grid-template-columns:1fr}.dimensions{grid-template-columns:1fr 1fr}.component>summary{grid-template-columns:1fr}.component>summary p{display:none}}@media(max-width:560px){.top-inner,.view{padding-left:14px;padding-right:14px}.metrics{grid-template-columns:1fr 1fr}.dimensions{grid-template-columns:1fr}.kv{grid-template-columns:1fr}.finding>header{padding:15px}.finding-body{padding:14px}}
</style></head><body><header class="top"><div class="top-inner"><p class="eyebrow">HARMONYOS WHITE-BOX SECURITY AUDIT</p><h1>${escapeHtml(title)}</h1><div class="runmeta"><span>运行编号 <b>${escapeHtml(run.run_id)}</b></span><span>状态 <b>${escapeHtml(label(run.status))}</b></span><span>覆盖 <b>${coverage.status === "complete" ? "完整" : "部分完成"}</b></span><span>目标 <b>${escapeHtml(run.target_repo)}</b></span></div></div><nav class="tabs"><button class="tab active" data-view="overview">概览</button><button class="tab" data-view="findings">安全发现</button><button class="tab" data-view="components">组件审计</button><button class="tab" data-view="paths">攻击路径</button><button class="tab" data-view="project">项目结构</button><button class="tab" data-view="coverage">覆盖与缺口</button></nav></header><main>
<section id="overview" class="view active"><div class="hero"><p class="eyebrow">EXECUTIVE SUMMARY</p><h2>HarmonyOS 应用白盒安全审计报告</h2><p>本报告基于项目解析、组件语义路径发现和六维有效性验证生成。结论仅覆盖本次配置的代码、组件与能力范围。</p></div><div class="metrics"><div class="metric"><strong>${summary.findings ?? 0}</strong><span>需要处置的发现</span></div><div class="metric"><strong>${classification.confirmed_vulnerability ?? 0}</strong><span>已确认漏洞</span></div><div class="metric"><strong>${summary.analyzed_components ?? 0}</strong><span>已分析组件</span></div><div class="metric"><strong>${summary.paths ?? 0}</strong><span>跨组件路径</span></div><div class="metric"><strong>${summary.validations ?? 0}</strong><span>六维验证</span></div><div class="metric"><strong>${summary.coverage_gaps ?? 0}</strong><span>覆盖缺口</span></div></div>${incrementalHtml}<div class="grid-2"><div class="panel"><h2>分析结果</h2><div class="result-list">${["confirmed_vulnerability","residual_risk","protected_exposure","benign_business_flow","insufficient_evidence","verification_incomplete"].map((key) => `<div class="result"><span>${badge(key)}</span><b>${classification[key] ?? 0}</b></div>`).join("")}</div></div><div class="panel"><h2>审计范围</h2><dl class="kv"><dt>组件</dt><dd>${codeList(obj(run.audit_scope).components)}</dd><dt>能力</dt><dd>${codeList(obj(run.audit_scope).capabilities)}</dd><dt>入口目录</dt><dd>${summary.entries ?? 0}</dd><dt>安全操作组</dt><dd>${summary.operation_groups ?? 0}</dd><dt>证据记录</dt><dd>${summary.evidence ?? 0}</dd></dl></div></div><div class="panel"><h2>重点结论</h2>${findings.slice(0,5).map((finding) => `<div class="fact"><strong>${escapeHtml(finding.title)}</strong><p>${badge(finding.severity)} ${escapeHtml(finding.impact)}</p></div>`).join("") || '<div class="empty">未发现需要处置的安全问题</div>'}</div></section>
<section id="findings" class="view"><h2>需要处置的安全发现</h2><p class="muted">每项发现包含根因、业务意图、安全边界、六维有效性验证、证据和验证方式。</p><div class="toolbar"><input data-filter=".finding" placeholder="搜索标题、等级、CWE 或能力"></div>${findingHtml}</section>
<section id="components" class="view"><h2>组件审计结果</h2><p class="muted">所有进入审计目录的组件均在此展示；“未发现问题”仅代表已检查范围内没有形成可利用结论。</p><div class="toolbar"><input data-filter=".component" placeholder="搜索组件、模块、功能或结论"></div>${componentHtml}</section>
<section id="paths" class="view"><h2>跨组件攻击路径</h2><p class="muted">展示组件连接、身份迁移、参数传递和关联验证结果。</p>${pathHtml}</section>
<section id="project" class="view"><div class="grid-2"><div class="panel"><h2>应用信息</h2><dl class="kv"><dt>包名</dt><dd>${escapeHtml(application.bundle_name || "-")}</dd><dt>版本</dt><dd>${escapeHtml(application.version_name || "-")} (${escapeHtml(application.version_code || "-")})</dd><dt>厂商</dt><dd>${escapeHtml(application.vendor || "-")}</dd><dt>目标 API</dt><dd>${escapeHtml(application.target_api_version || "-")}</dd><dt>模块</dt><dd>${modules.length}</dd><dt>组件</dt><dd>${projectComponents.length}</dd></dl></div><div class="panel"><h2>权限与依赖</h2><p><b>申请权限 ${permissions.length}</b></p>${permissions.map((item) => `<div class="fact"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.reason || "未记录用途")}</small></div>`).join("") || '<p class="muted">未声明申请权限</p>'}<p><b>依赖 ${dependencies.length}</b></p>${dependencies.slice(0,30).map((item) => `<div class="fact"><strong>${escapeHtml(item.name)} ${escapeHtml(item.version || "")}</strong><small>${escapeHtml(item.group || "dependency")}</small></div>`).join("") || '<p class="muted">未记录依赖</p>'}</div></div><div class="panel"><h2>模块</h2><div class="table-wrap"><table class="structure"><thead><tr><th>模块</th><th>类型</th><th>根目录</th><th>构建产物</th></tr></thead><tbody>${modules.map((item) => `<tr><td><strong>${escapeHtml(item.name)}</strong></td><td>${escapeHtml(item.type || "-")}</td><td><code>${escapeHtml(item.root)}</code></td><td>${escapeHtml(item.output_kind)}</td></tr>`).join("")}</tbody></table></div></div><div class="panel"><h2>组件</h2><div class="table-wrap"><table class="structure"><thead><tr><th>组件</th><th>类型</th><th>模块</th><th>导出</th><th>权限</th><th>源码</th></tr></thead><tbody>${projectComponents.map((item) => `<tr><td><strong>${escapeHtml(item.name)}</strong></td><td>${escapeHtml(item.extension_type || item.kind)}</td><td>${escapeHtml(item.module_name)}</td><td>${item.exported === true ? "是" : item.exported === false ? "否" : "未知"}</td><td>${escapeHtml(strings(item.permissions).join(", ") || "-")}</td><td><code>${escapeHtml(item.source_file_hint || item.src_entry || "-")}</code></td></tr>`).join("")}</tbody></table></div></div></section>
<section id="coverage" class="view"><div class="metrics"><div class="metric"><strong>${coverage.status === "complete" ? "完整" : "部分"}</strong><span>覆盖状态</span></div><div class="metric"><strong>${summary.entries ?? 0}</strong><span>组件目录</span></div><div class="metric"><strong>${summary.analyzed_components ?? 0}</strong><span>已分析组件</span></div><div class="metric"><strong>${summary.operation_groups ?? 0}</strong><span>操作组</span></div><div class="metric"><strong>${summary.evidence ?? 0}</strong><span>证据记录</span></div><div class="metric"><strong>${summary.coverage_gaps ?? 0}</strong><span>覆盖缺口</span></div></div><div class="grid-2"><div class="panel"><h2>任务状态</h2>${Object.entries(taskCounts).map(([key,value]) => `<div class="result"><span>${escapeHtml(label(key))}</span><b>${escapeHtml(value)}</b></div>`).join("") || '<p class="muted">无任务记录</p>'}</div><div class="panel"><h2>覆盖缺口</h2>${gapHtml}</div></div><div class="panel"><h2>攻击矩阵</h2><div class="table-wrap"><table class="structure"><thead><tr><th>入口</th><th>能力</th><th>范围</th><th>验证结论</th><th>Finding</th></tr></thead><tbody>${matrixHtml}</tbody></table></div></div></section></main><script type="application/json" id="report-meta">${reportJson}</script><script>
document.querySelectorAll('.tab').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(item=>item.classList.toggle('active',item===button));document.querySelectorAll('.view').forEach(view=>view.classList.toggle('active',view.id===button.dataset.view));scrollTo({top:0,behavior:'smooth'})}));document.querySelectorAll('[data-filter]').forEach(input=>input.addEventListener('input',()=>{const query=input.value.trim().toLowerCase();document.querySelectorAll(input.dataset.filter).forEach(item=>item.classList.toggle('hidden-result',!!query&&!item.dataset.search.includes(query)))}));
</script></body></html>`;
}
