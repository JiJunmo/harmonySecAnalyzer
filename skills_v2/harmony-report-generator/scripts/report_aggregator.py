#!/usr/bin/env python3
"""
v2 攻击路径聚合器。扫描审计目录中所有 skill 的 attack-paths.json，合并统计。

用法:
    python report_aggregator.py <audit_dir> [-o aggregated_data.json]

输入: 审计工作目录（含 entries.json, sinks.json, attack_map.json, *-attack-paths.json）
输出: aggregated_data.json
"""

import argparse
import json
import sys
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

_SCRIPT_DIR = Path(__file__).resolve().parent


import hashlib

def compute_fingerprint(p: dict) -> str:
    """计算漏洞的唯一性指纹。"""
    # 提取 rule_id
    matched_rules = p.get("matched_rules", [])
    rule_id = matched_rules[0] if matched_rules else ""
    if not rule_id:
        rule_id = p.get("id", "").split("-")[0]
    
    # 提取 sink_file & sink_signature
    flow = p.get("flow", [])
    sink_file = ""
    sink_signature = ""
    if flow:
        sink_step = flow[-1]
        sink_file = sink_step.get("file", "")
        snippet = sink_step.get("snippet", "")
        # 去除注释和空白字符
        snippet_no_comments = re.sub(r'//.*|/\*[\s\S]*?\*/', '', snippet)
        sink_signature = re.sub(r'\s+', '', snippet_no_comments)
    else:
        evidence = p.get("evidence", [])
        if evidence:
            ev = evidence[0]
            sink_file = ev.get("file", "")
            snippet = ev.get("snippet", "")
            snippet_no_comments = re.sub(r'//.*|/\*[\s\S]*?\*/', '', snippet)
            sink_signature = re.sub(r'\s+', '', snippet_no_comments)

    fp_string = f"{rule_id}@{sink_file}@{sink_signature}"
    return hashlib.md5(fp_string.encode("utf-8")).hexdigest()


def aggregate(audit_dir: str) -> dict:
    audit_path = Path(audit_dir)
    if not audit_path.exists():
        raise FileNotFoundError(f"审计目录不存在: {audit_dir}")

    # 读取所有 attack-paths 分片（匹配 *-attack-paths*.json）
    all_paths = []
    processed_files_count = 0
    for fpath in sorted(audit_path.glob("*-attack-paths*.json")):
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            all_paths.extend(data.get("attack_paths", []))
            processed_files_count += 1
        except (json.JSONDecodeError, OSError):
            pass

    # 对所有路径按指纹归并
    groups = defaultdict(list)
    for p in all_paths:
        fp = compute_fingerprint(p)
        groups[fp].append(p)

    merged_paths = []
    for fp, paths in groups.items():
        if not paths:
            continue
        # 以第一个作为主路径模板
        primary = dict(paths[0])
        
        # 提取并合并所有入口路径与 Flow
        entry_paths = []
        seen_entry_keys = set()
        for idx, path in enumerate(paths):
            entry = path.get("entry")
            # 针对没有顶层 entry 的 IPC 服务等适配生成结构化 entry
            if not entry:
                if "input" in path:
                    entry = {
                        "type": "ipc_message",
                        "file": path.get("flow", [{}])[0].get("file", "") if path.get("flow") else "",
                        "how": "发送特定的 IPC 消息请求",
                        "payload": {
                            "code": path["input"].get("code"),
                            "snippet": path["input"].get("snippet")
                        }
                    }
                else:
                    entry = {
                        "type": "unknown",
                        "file": path.get("flow", [{}])[0].get("file", "") if path.get("flow") else "",
                        "how": "外部输入传导"
                    }
            
            entry_key = f"{entry.get('type')}@{entry.get('file')}@{entry.get('how')}"
            if entry_key in seen_entry_keys:
                continue
            seen_entry_keys.add(entry_key)

            entry_paths.append({
                "path_id": path.get("id"),
                "entry": entry,
                "flow": path.get("flow", [])
            })

        primary["entry_paths"] = entry_paths

        # 清理原顶层的单例 entry 和 flow
        if "entry" in primary:
            del primary["entry"]
        if "flow" in primary:
            del primary["flow"]

        # 严重度提升：保留同一漏洞中最高的严重级别
        max_severity = "info"
        for path in paths:
            sev = path.get("severity", "info").lower()
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity.lower(), 0):
                max_severity = sev
        primary["severity"] = max_severity

        # 漏洞 ID 重构：如果归并了多条路径，给予 VULN 前缀以区分
        if len(paths) > 1:
            primary["id"] = f"VULN-{primary['id']}"

        merged_paths.append(primary)

    # 排序
    merged_paths.sort(key=lambda p: SEVERITY_RANK.get(p.get("severity", "info"), 1), reverse=True)

    # 统计唯一漏洞数
    by_severity = {}
    by_skill = {}
    for p in merged_paths:
        sv = p.get("severity", "info")
        by_severity[sv] = by_severity.get(sv, 0) + 1
        skill = p.get("id", "").split("-")[0] if "-" in p.get("id", "") else "unknown"
        # 移除可能带有 VULN- 前缀的情况
        if skill.startswith("VULN"):
            skill = p.get("id", "").split("-")[1] if len(p.get("id", "").split("-")) > 1 else "unknown"
        by_skill[skill] = by_skill.get(skill, 0) + 1

    # 风险评分（基于去重后的唯一漏洞）
    risk = 0
    if merged_paths:
        total = sum(SEVERITY_WEIGHT.get(p.get("severity", "info"), 0) for p in merged_paths)
        max_p = len(merged_paths) * 10
        risk = min(100, round(total / max_p * 100)) if max_p else 0


    # 计数校验：动态计算预期任务文件数（防断流/剪枝误报）
    warnings = []
    expected_files = 0
    entries_path = audit_path / "entries.json"
    if entries_path.exists():
        try:
            entries_data = json.loads(entries_path.read_text(encoding="utf-8"))
            entries = entries_data.get("entries", [])
            ipc_count = sum(1 for e in entries if e.get("type") == "ipc_service")
            ability_count = sum(1 for e in entries if e.get("type") == "exported_ability")
            
            # 计算批次数量 (向上取整，每 5 个一批)
            expected_ipc_batches = (ipc_count + 4) // 5
            expected_ability_batches = (ability_count + 4) // 5
            
            # 统计实际生成的 warm-start 文件数以获取触发的 WebView 任务预期批次数
            warm_start_count = len(list(audit_path.glob("harmony-webview-warm-start-*.json")))
            expected_webview_batches = (warm_start_count + 4) // 5
            
            expected_files = expected_ipc_batches + expected_ability_batches + expected_webview_batches
        except Exception:
            pass

    if expected_files > 0 and processed_files_count < expected_files:
        warnings.append(
            f"预期完成 {expected_files} 个批次任务文件，实际完成 {processed_files_count} 个，可能存在漏分析"
        )

    # 读取项目概览
    entries_count = 0
    sinks_count = 0
    for fname in ["entries.json", "sinks.json"]:
        fp = audit_path / fname
        if fp.exists():
            try:
                d = json.loads(fp.read_text(encoding="utf-8"))
                if fname == "entries.json":
                    entries_count = d.get("_meta", {}).get("count", 0)
                else:
                    sinks_count = d.get("_meta", {}).get("count", 0)
            except (json.JSONDecodeError, OSError):
                pass

    return {
        "project": {
            "entries_count": entries_count,
            "sinks_count": sinks_count,
            "verified_paths": len(merged_paths),
        },
        "attack_paths": merged_paths,
        "statistics": {
            "by_severity": dict(sorted(by_severity.items(), key=lambda x: SEVERITY_RANK.get(x[0], 0), reverse=True)),
            "by_skill": dict(sorted(by_skill.items(), key=lambda x: x[1], reverse=True)),
        },
        "risk_score": risk,
        "warnings": warnings,
        "audit_time": datetime.now(timezone.utc).isoformat(),
    }


def generate_security_assessment(data: dict) -> str:
    """动态生成专业的安全态势评估总结。"""
    paths = data.get("attack_paths", [])
    if not paths:
        return "本次安全审计未发现可直接利用的高危攻击路径。当前应用的攻击面暴露较少，整体安全态势较为乐观，建议继续保持现有的安全开发规范。"

    risk_score = data.get("risk_score", 0)
    severities = [p.get("severity", "info").lower() for p in paths]

    # 从漏洞标题或 ID 归纳关键风险类型
    risk_types = []
    for p in paths:
        title = p.get("title", "")
        pid = p.get("id", "")
        if "IPC" in title or "跨进程" in title or pid.startswith("IPC"):
            risk_types.append("跨进程通信 (IPC)")
        elif "WebView" in title or "JS Bridge" in title or "WEBVIEW" in pid:
            risk_types.append("WebView JS Bridge 接口暴露")
        elif "Ability" in title or "ABILITY" in pid:
            risk_types.append("UIAbility 外部组件导出")

    risk_types = list(set(risk_types))
    if not risk_types:
        risk_types = ["外部输入参数传导"]

    risk_desc = "、".join(risk_types)

    if risk_score >= 80 or "critical" in severities:
        state = "**危急**"
        recommendation = "建议立即启动 Critical 和 High 级别漏洞的修复工作，限制外部组件导出并加强参数校验以阻断攻击链。"
    elif risk_score >= 50 or "high" in severities:
        state = "**高风险**"
        recommendation = "建议在当前开发迭代内安排修复计划，优先处理涉及敏感数据泄露或敏感操作的攻击路径。"
    elif risk_score >= 20 or "medium" in severities:
        state = "**需关注**"
        recommendation = "建议在后续迭代中逐步优化相关输入校验和权限控制，防范潜在的链路缝合攻击。"
    else:
        state = "**低风险**"
        recommendation = "建议遵循安全最佳实践，在日常维护中逐步完善底层防御。"

    return f"本次审计发现，攻击者可通过多个外部入口构造攻击链路。其中**{risk_desc}**暴露了主要攻击面，可能导致敏感业务逻辑被绕过或敏感数据泄露。整体安全态势评级为{state}，{recommendation}"


def generate_markdown_report(data: dict) -> str:
    """根据 aggregated_data.json 的完整结构，自动渲染标准的 Markdown 报告，避免大报告由于 token 限制而截断。"""
    try:
        dt = datetime.fromisoformat(data.get("audit_time", ""))
        audit_time_str = dt.strftime("%Y年%m月%d日 %H:%M")
    except Exception:
        audit_time_str = datetime.now().strftime("%Y年%m月%d日 %H:%M")

    risk_score = data.get("risk_score", 0)
    verified_paths = data.get("project", {}).get("verified_paths", 0)
    entries_count = data.get("project", {}).get("entries_count", 0)
    sinks_count = data.get("project", {}).get("sinks_count", 0)

    md = []
    md.append("# 鸿蒙应用安全审计报告")
    md.append("")
    md.append(f"> 审计时间：{audit_time_str} | 风险评分：{risk_score}/100 | 已验证攻击路径：{verified_paths} 条")
    md.append("")
    md.append("---")
    md.append("")
    md.append("## 1. 审计概览")
    md.append("")
    md.append("### 1.1 审计范围")
    md.append("")
    md.append("本轮安全审计从攻击者视角出发，对目标鸿蒙应用进行了全面的攻击面分析与攻击路径验证。")
    md.append("")
    md.append("| 指标 | 数值 | 说明 |")
    md.append("|------|------|------|")
    md.append(f"| 发现外部入口 | {entries_count} 个 | 包括 DeepLink、IPC 服务、URL 回调等外部可控入口 |")
    md.append(f"| 发现攻击终点 | {sinks_count} 个 | 包括 WebView 加载点、文件读写、数据库操作等高危终点 |")
    md.append(f"| 已验证攻击路径 | {verified_paths} 条 | 经过 AI 双向追踪验证、确认真实可达的完整攻击链路 |")
    md.append(f"| 综合风险评分 | {risk_score} / 100 | 基于漏洞严重度和影响范围加权计算 |")
    md.append("")
    md.append("### 1.2 漏洞分布")
    md.append("")

    severity_stats = data.get("statistics", {}).get("by_severity", {})
    critical = severity_stats.get("critical", 0)
    high = severity_stats.get("high", 0)
    medium = severity_stats.get("medium", 0)
    low = severity_stats.get("low", 0)
    info = severity_stats.get("info", 0)
    total_findings = critical + high + medium + low + info

    md.append(f"本次审计共发现 **{total_findings}** 项安全漏洞，按严重度分布如下：")
    md.append("")
    md.append("| 严重度 | 数量 | 占比 | 说明 |")
    md.append("|--------|------|------|------|")

    def get_pct(val):
        if not total_findings:
            return "0.0"
        return f"{(val / total_findings * 100):.1f}"

    md.append(f"| 🔴 Critical | {critical} | {get_pct(critical)}% | 可直接导致应用被完全控制或敏感数据大规模泄露 |")
    md.append(f"| 🟠 High | {high} | {get_pct(high)}% | 可导致敏感数据泄露或权限提升，利用难度较低 |")
    md.append(f"| 🟡 Medium | {medium} | {get_pct(medium)}% | 可被利用但需要一定前置条件 |")
    md.append(f"| 🔵 Low | {low} | {get_pct(low)}% | 安全最佳实践偏离，暂未形成直接攻击链路 |")
    md.append(f"| ⚪ Info | {info} | {get_pct(info)}% | 提示性信息，建议关注 |")
    md.append("")

    if total_findings == 0:
        md.append("> ✅ 本次审计未发现可被外部利用的安全漏洞。项目的攻击面配置处于良好状态。")
        md.append("")
    else:
        md.append("### 1.3 安全态势评估")
        md.append("")
        assessment = generate_security_assessment(data)
        md.append(assessment)
        md.append("")

    md.append("---")
    md.append("")
    md.append("## 2. 攻击路径详情")
    md.append("")

    paths = data.get("attack_paths", [])
    if not paths:
        md.append("> ✅ 未发现可被外部利用的攻击路径。项目不存在从外部入口到攻击终点的可达链路。")
        md.append("")
    else:
        severity_emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪"
        }
        for path in paths:
            pid = path.get("id", "UNKNOWN")
            title = path.get("title", "无标题")
            sev = path.get("severity", "info").lower()
            emoji = severity_emojis.get(sev, "⚪")

            md.append(f"### {pid} {title} [{emoji}]")
            md.append("")
            md.append(f"> **严重度**: {emoji} {path.get('severity', 'info')} | **ID**: {pid}")
            md.append("")
            md.append("---")
            md.append("")

            # Branch A: IPC
            if pid.startswith("IPC-"):
                md.append("#### 攻击目标")
                md.append("")
                md.append(f"**模块**: {path.get('module', '--')}  ")
                md.append("**类型**: 跨进程通信服务 (IPC Service Extension)  ")
                md.append("**攻击路径类型**: 外部 IPC 客户端 → 服务端 Stub → 敏感业务执行 / 数据泄露")
                md.append("")
                if "non_sensitive_summary" in path:
                    md.append(f"> **非敏感分支说明**: {path['non_sensitive_summary']}")
                    md.append("")
                if "input" in path and path["input"]:
                    md.append("#### 攻击载荷")
                    md.append("")
                    md.append("攻击者构造 IPC 请求所需的 code 和 data 格式如下：")
                    md.append("")
                    md.append("```typescript")
                    md.append(f"// 请求码: {path['input'].get('code')}")
                    md.append(f"// 数据格式: {path['input'].get('data_format', 'MessageSequence')}")
                    md.append(path["input"].get("snippet", ""))
                    md.append("```")
                    md.append("")
                if "cases" in path and path["cases"]:
                    md.append("#### 敏感业务分支分析")
                    md.append("")
                    md.append("以下表格列出了该 IPC 服务中**被判定为存在安全风险的 code 分支**：")
                    md.append("")
                    md.append("| Code | 业务描述 | 输入数据 | 输出结果 | 风险原因 |")
                    md.append("|------|---------|---------|---------|---------|")
                    for case in path["cases"]:
                        md.append(f"| {case.get('code')} | {case.get('description')} | {case.get('input')} | {case.get('output')} | {case.get('sensitive_reason')} |")
                    md.append("")

            # Branch B: WEBVIEW
            elif "WEBVIEW" in pid:
                md.append("#### JS Bridge 方法安全分析")
                md.append("")
                cases = path.get("cases", {})
                if isinstance(cases, dict) and "bridge_methods" in cases and cases["bridge_methods"]:
                    md.append("下表列出了该 WebView 通过 `registerJavaScriptProxy` 注册的所有 JS Bridge 方法及其安全评估：")
                    md.append("")
                    md.append("| 方法名 | 是否敏感 | 原生实现 | 评估结论 |")
                    md.append("|--------|---------|---------|---------|")
                    for method in cases["bridge_methods"]:
                        sens_str = "⚠️ 是" if method.get("sensitive") else "✅ 否"
                        md.append(f"| {method.get('name')} | {sens_str} | {method.get('implementation')} | {method.get('reason')} |")
                    md.append("")
                if isinstance(cases, dict) and "interceptors" in cases and cases["interceptors"]:
                    md.append("#### URL 加载拦截器分析")
                    md.append("")
                    md.append("| 拦截器类型 | 是否已实现 | 风险评估 |")
                    md.append("|-----------|-----------|---------|")
                    for interceptor in cases["interceptors"]:
                        pres_str = "✅ 已实现" if interceptor.get("present") else "❌ 未实现"
                        md.append(f"| {interceptor.get('type')} | {pres_str} | {interceptor.get('risk')} |")
                    md.append("")

            # Branch C: ABILITY
            elif "ABILITY" in pid:
                details = path.get("ability_details")
                if details:
                    md.append("#### 目标 Ability 信息")
                    md.append("")
                    md.append("| 属性 | 说明 |")
                    md.append("|------|------|")
                    md.append(f"| **Ability 名称** | {details.get('name')} |")
                    exp_str = "是 (exported: true)" if details.get("exported") else "否 (exported: false)"
                    md.append(f"| **是否导出** | {exp_str} |")
                    md.append(f"| **调用方身份校验** | {details.get('caller_verification') or '无'} |")
                    check_str = "已使用" if details.get("has_calling_bundle_check") else "未使用"
                    md.append(f"| **getCallingBundleName 检查** | {check_str} |")
                    md.append("")
                if "module" in path:
                    md.append(f"**所属模块**: {path['module']}")
                    md.append("")

            # Common Sections: Flow
            entry_paths = path.get("entry_paths", [])
            md.append("#### 攻击入口与数据流向")
            md.append("")
            md.append(f"该漏洞可以通过以下 **{len(entry_paths)}** 个不同的外部入口和传导链路触发：")
            md.append("")

            for ep_idx, ep in enumerate(entry_paths, 1):
                entry = ep.get("entry", {})
                md.append(f"##### 【入口 {ep_idx}】: {entry.get('type')} ({entry.get('file')})")
                md.append("")
                md.append(f"*   **触发方式**: {entry.get('how')}")
                if "payload" in entry and isinstance(entry["payload"], dict) and "url" in entry["payload"]:
                    md.append(f"*   **可控参数**: {entry['payload']['url']}")
                if "payload" in entry and isinstance(entry["payload"], dict) and "snippet" in entry["payload"]:
                    md.append("")
                    md.append("**入口参数载荷**:")
                    md.append("")
                    md.append("```typescript")
                    md.append(entry["payload"]["snippet"])
                    md.append("```")
                md.append("")
                md.append("**数据流传导路径**:")
                md.append("")

                flow = ep.get("flow", [])
                if flow:
                    for step in flow:
                        md.append(f"> **步骤 {step.get('step')}: {step.get('stage')}**")
                        md.append(">")
                        md.append(f"> **文件位置**: `{step.get('file')}`")
                        md.append(">")
                        md.append(f"> {step.get('description')}")
                        md.append(">")
                        md.append("> ```typescript")
                        snippet_lines = step.get('snippet', '').split('\n')
                        for sl in snippet_lines:
                            md.append(f"> {sl}")
                        md.append("> ```")
                        md.append(">")
                        md.append("")
                else:
                    md.append("> *数据流向不可追溯*")
                    md.append("")

            md.append("---")
            md.append("")

            # Impact
            md.append("#### 危害评估")
            md.append("")
            impact = path.get("impact", {})
            if isinstance(impact, dict) and "summary" in impact:
                md.append(impact["summary"])
                md.append("")
            else:
                md.append("未提供影响评估")
                md.append("")

            if isinstance(impact, dict) and "sensitive_data_exposed" in impact and impact["sensitive_data_exposed"]:
                md.append("**可能泄露的敏感数据**：")
                md.append("")
                for item in impact["sensitive_data_exposed"]:
                    field_name = item.get("field") or item.get("data", "未知数据")
                    content_val = item.get("content") or item.get("risk", "可能被窃取")
                    source_val = item.get("source") or ("通过 " + item.get("via", "外部调用"))
                    md.append(f"- **{field_name}**：{content_val}（来源：{source_val}）")
                    if "example" in item:
                        md.append(f"  ```")
                        md.append(f"  示例输出: {item['example']}")
                        md.append(f"  ```")
                md.append("")

            if isinstance(impact, dict) and "sensitive_operations" in impact and impact["sensitive_operations"]:
                md.append("**攻击者可执行的敏感操作**：")
                md.append("")
                for item in impact["sensitive_operations"]:
                    md.append(f"- **{item.get('operation')}**：通过 {item.get('via')} 实现，后果为 {item.get('consequence')}")
                md.append("")

            if isinstance(impact, dict) and "output_example" in impact:
                md.append("**攻击成功后的预期输出**：")
                md.append("")
                md.append("```")
                md.append(impact["output_example"])
                md.append("```")
                md.append("")

            md.append("---")
            md.append("")

            # Exploitation
            md.append("#### 利用方法")
            md.append("")
            exploitation = path.get("exploitation")
            if isinstance(exploitation, str):
                md.append("**攻击步骤**：")
                md.append("")
                md.append(exploitation)
                md.append("")
                md.append("**最小 PoC 代码**（可直接编译执行的攻击应用核心代码）：")
                md.append("")
                poc_code = ""
                if "input" in path and "snippet" in path["input"]:
                    poc_code = path["input"]["snippet"]
                elif "entry" in path and "payload" in path["entry"] and "snippet" in path["entry"]["payload"]:
                    poc_code = path["entry"]["payload"]["snippet"]
                elif entry_paths:
                    ep = entry_paths[0]
                    if "entry" in ep and "payload" in ep["entry"] and "snippet" in ep["entry"]["payload"]:
                        poc_code = ep["entry"]["payload"]["snippet"]
                    elif "flow" in ep and ep["flow"]:
                        poc_code = ep["flow"][0].get("snippet", "")

                md.append("```typescript")
                md.append(poc_code or "// 未提供核心 PoC 代码")
                md.append("```")
                md.append("")
            elif isinstance(exploitation, dict):
                md.append(f"**攻击步骤**：{exploitation.get('summary')}")
                md.append("")
                md.append("**最小 PoC 代码**（可直接编译执行的攻击应用核心代码）：")
                md.append("")
                payload = exploitation.get("payload", {})
                if "target_bundle" in payload or "target_ability" in payload:
                    md.append(f"// target_bundle: {payload.get('target_bundle')}")
                    md.append(f"// target_ability: {payload.get('target_ability')}")
                md.append("```typescript")
                md.append(payload.get("snippet", ""))
                md.append("```")
                md.append("")
            else:
                md.append("未提供利用方法")
                md.append("")

            md.append("---")
            md.append("")

            # Remediation
            md.append("#### 修复建议")
            md.append("")
            md.append(path.get("remediation") or "未提供修复建议")
            md.append("")
            md.append("---")
            md.append("")

            # Matched Rules
            if "matched_rules" in path and path["matched_rules"]:
                md.append("#### 命中安全规则")
                md.append("")
                md.append(", ".join(path["matched_rules"]))
                md.append("")
                md.append("---")
                md.append("")

    # Paragraph 3: Audit Summary
    md.append("## 3. 审计总结")
    md.append("")
    md.append("### 3.1 风险总览")
    md.append("")
    md.append("| 严重度 | 数量 | 占比 | 说明 |")
    md.append("|--------|------|------|------|")
    md.append(f"| 🔴 Critical | {critical} | {get_pct(critical)}% | 可直接导致应用被完全控制或敏感数据大规模泄露 |")
    md.append(f"| 🟠 High | {high} | {get_pct(high)}% | 可导致敏感数据泄露或权限提升，利用难度较低 |")
    md.append(f"| 🟡 Medium | {medium} | {get_pct(medium)}% | 可被利用但需要一定前置条件 |")
    md.append(f"| 🔵 Low | {low} | {get_pct(low)}% | 安全最佳实践偏离，暂未形成直接攻击链路 |")
    md.append(f"| ⚪ Info | {info} | {get_pct(info)}% | 提示性信息，建议关注 |")
    md.append("")
    md.append(f"**综合风险评分**: **{risk_score}** / 100")
    md.append("")

    if risk_score >= 80:
        md.append("评级：**危急** —— 存在可被直接利用的严重漏洞，建议立即修复。")
    elif risk_score >= 50:
        md.append("评级：**高风险** —— 存在多条可达攻击链路，需在本迭代内修复。")
    elif risk_score >= 20:
        md.append("评级：**中等风险** —— 存在部分安全问题，可纳入下一迭代。")
    else:
        md.append("评级：**低风险** —— 安全态势良好，继续关注。")
    md.append("")

    md.append("### 3.2 审计覆盖范围")
    md.append("")
    md.append("| 审计 Skill | 发现路径数 | 覆盖的攻击面 |")
    md.append("|-----------|-----------|------------|")

    by_skill = data.get("statistics", {}).get("by_skill", {})
    skill_names = {
        "IPC": "IPC 跨进程通信安全审计",
        "WEBVIEW": "WebView 安全审计",
        "ABILITY": "UIAbility 安全审计"
    }
    skill_descs = {
        "IPC": "ExtensionAbility 导出、RPC 跨进程消息通信分支及可读写数据流审计",
        "WEBVIEW": "WebView 容器 JavaScriptProxy 接口导出及 URL 拦截校验机制审计",
        "ABILITY": "UIAbility 启动过滤、Want 外部可控参数校验及重入行为审计"
    }
    for sk, count in by_skill.items():
        sk_zh = skill_names.get(sk, sk)
        sk_desc = skill_descs.get(sk, "安全机制与数据流向审计")
        md.append(f"| {sk_zh} | {count} | {sk_desc} |")
    md.append("")

    warnings = data.get("warnings", [])
    if warnings:
        md.append("### 3.3 审计警告")
        md.append("")
        md.append("> ⚠️ 以下问题可能影响审计结果完整性：")
        md.append(">")
        for warning in warnings:
            md.append(f"> - {warning}")
        md.append("")

    md.append("### 3.4 修复优先级建议")
    md.append("")

    # First Priority
    md.append("#### 第一优先级：立即修复（Critical 漏洞）")
    md.append("")
    critical_paths = [p for p in paths if p.get("severity", "").lower() == "critical"]
    if critical_paths:
        for p in critical_paths:
            md.append(f"- **{p.get('id')} {p.get('title')}**")
            md.append(f"  *问题概述*: {p.get('impact', {}).get('summary', '高危漏洞影响')}")
            md.append(f"  *修复建议*: {p.get('remediation', '立即限制接口访问控制')}")
    else:
        md.append("✅ 无")
    md.append("")

    # Second Priority
    md.append("#### 第二优先级：本迭代内修复（High 漏洞）")
    md.append("")
    high_paths = [p for p in paths if p.get("severity", "").lower() == "high"]
    if high_paths:
        for p in high_paths:
            md.append(f"- **{p.get('id')} {p.get('title')}**")
            md.append(f"  *问题概述*: {p.get('impact', {}).get('summary', '高风险漏洞影响')}")
            md.append(f"  *修复建议*: {p.get('remediation', '完善输入验证和权限控制')}")
    else:
        md.append("✅ 无")
    md.append("")

    # Third Priority
    md.append("#### 第三优先级：纳入后续迭代（Medium / Low 漏洞）")
    md.append("")
    medium_low_paths = [p for p in paths if p.get("severity", "").lower() in ["medium", "low"]]
    if medium_low_paths:
        for p in medium_low_paths:
            md.append(f"- **{p.get('id')} {p.get('title')}** ({p.get('severity')})")
            md.append(f"  *问题概述*: {p.get('impact', {}).get('summary', '中低风险漏洞')}")
    else:
        md.append("✅ 无")
    md.append("")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="v2 攻击路径聚合器")
    parser.add_argument("audit_dir", help="审计工作目录路径")
    parser.add_argument("-o", "--output", default=None, help="输出路径")
    parser.add_argument("-m", "--markdown", default=None, help="Markdown 报告输出路径")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON")
    args = parser.parse_args()

    try:
        data = aggregate(args.audit_dir)
    except Exception as e:
        print(f"[ERROR] 聚合失败: {e}", file=sys.stderr)
        sys.exit(1)

    indent = 2 if args.pretty else None
    out = json.dumps(data, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        p = Path(args.output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(out, encoding="utf-8")
        print(f"[DONE] v2 聚合完成，共 {len(data['attack_paths'])} 条攻击路径，输出: {p}")
    else:
        print(out)

    if args.markdown:
        mp = Path(args.markdown)
        mp.parent.mkdir(parents=True, exist_ok=True)
        report_md = generate_markdown_report(data)
        mp.write_text(report_md, encoding="utf-8")
        print(f"[DONE] Markdown 报告渲染完成，输出: {mp}")


if __name__ == "__main__":
    main()
