#!/usr/bin/env python3
"""
HarmonyOS ArkWeb WebView 安全审计器 —— 配置级与代码级规则检查。

用法:
    python3 webview_auditor.py <metadata_json> <project_path> [-o findings.json]

功能:
    1. 读取 Phase 1 输出的项目元数据 JSON
    2. 加载 WebView 安全审计规则 JSON
    3. 搜索 .ets 源文件中的 WebView 配置和 API 调用
    4. 按规则逐条筛查，输出标准化的 findings.json

说明:
    深层逻辑分析（JS Bridge 暴露面评估、拦截器绕过分析等）由 AI 执行（见 SKILL.md），
    本脚本负责配置扫描和模式匹配。
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_COUNTER = [0]


def _next_finding_id() -> str:
    _COUNTER[0] += 1
    return f"HM-WEB-2026-{_COUNTER[0]:04d}"


def _make_finding(
    rule: dict,
    file_path: str = "",
    line_no: int | None = None,
    snippet: str = "",
    extra_desc: str = "",
    context: str = "",
) -> dict:
    description = rule.get("description", "")
    if extra_desc:
        description = (description + " " + extra_desc).strip()
    if context:
        description = (description + " 上下文: " + context).strip()
    return {
        "id": _next_finding_id(),
        "skill": "harmony-webview-audit",
        "rule_id": rule.get("id", ""),
        "severity": rule.get("severity", "info"),
        "title": rule.get("title", ""),
        "description": description,
        "location": {
            "file": file_path,
            "line": line_no,
            "snippet": snippet,
        },
        "cwe": rule.get("cwe"),
        "owasp": rule.get("owasp"),
        "remediation": rule.get("remediation", ""),
        "reference": rule.get("reference", ""),
    }


def load_rules(rules_dir: Path) -> list[dict]:
    """加载所有规则 JSON 文件，返回扁平的规则列表。"""
    all_rules: list[dict] = []
    for json_file in sorted(rules_dir.glob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "rules" in data:
                all_rules.extend(data["rules"])
        except Exception as e:
            print(f"[WARN] 规则文件 {json_file} 解析失败: {e}", file=sys.stderr)
    return all_rules


def _read_file_content(filepath: str) -> str | None:
    """安全读取文件内容。"""
    try:
        return Path(filepath).read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return None


def _find_line_number(content: str, pattern: str) -> int | None:
    """在内容中查找 pattern 出现的行号。"""
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if pattern in line:
            return i + 1
    return None


def _extract_snippet(content: str, pattern: str, context_lines: int = 2) -> str:
    """提取匹配行及其上下文作为代码片段。"""
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if pattern in line:
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            snippet_lines = []
            for j in range(start, end):
                prefix = ">>> " if j == i else "    "
                snippet_lines.append(f"{prefix}{j + 1}: {lines[j]}")
            return "\n".join(snippet_lines)
    return ""


def _search_source_files(metadata: dict, project_path: str) -> list[dict]:
    """从 metadata 中提取需要审计的 .ets 源文件列表。"""
    project_root = Path(project_path).resolve()
    file_list: list[dict] = []

    ets_sources = metadata.get("files", {}).get("ets_sources", [])
    for sf in ets_sources:
        file_path = str(project_root / sf["path"])
        if os.path.exists(file_path):
            file_list.append({"path": file_path, "rel": sf["path"], "lines": sf.get("lines", 0)})

    return file_list


def check_code_pattern_rules(
    source_files: list[dict], rules: list[dict]
) -> list[dict]:
    """代码级模式匹配检查。

    对每个 type=code_pattern 的规则，在源文件中搜索 positive_patterns，
    若找到则检查 negative_patterns 是否存在安全防护。
    同时支持 context_checks 做额外的上下文检查。
    """
    findings: list[dict] = []

    # 缓存已读文件内容
    file_contents: dict[str, str] = {}

    for rule in rules:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            continue
        if detection.get("type") != "code_pattern":
            continue

        positive_patterns = detection.get("positive_patterns", [])
        negative_patterns = detection.get("negative_patterns", [])
        context_checks = detection.get("context_checks", [])
        context_patterns = detection.get("context_patterns", [])

        for sf in source_files:
            filepath = sf["path"]
            rel = sf["rel"]

            if filepath not in file_contents:
                content = _read_file_content(filepath)
                file_contents[filepath] = content or ""
            content = file_contents[filepath]
            if not content:
                continue

            # 检查 positive_patterns
            has_positive = any(p in content for p in positive_patterns)
            if not has_positive:
                continue

            # 检查 negative_patterns（安全防护是否缺失）
            has_negative = any(n in content for n in negative_patterns)

            # 检查 context_patterns（需要同时存在的上下文）
            has_context = True
            for cp in context_patterns:
                if cp not in content:
                    has_context = False
                    break

            # 检查 context_checks（额外的危险模式检查）
            context_hits: list[str] = []
            for cc in context_checks:
                if cc in content:
                    context_hits.append(cc)

            # 决定是否报告
            should_report = False
            extra_desc_parts: list[str] = []

            if negative_patterns and not has_negative:
                should_report = True
                extra_desc_parts.append(f"缺少安全检查: {', '.join(negative_patterns)}")
            elif has_positive and not negative_patterns:
                should_report = True
            elif context_hits:
                should_report = True
                extra_desc_parts.append(f"发现危险能力调用: {', '.join(context_hits)}")

            if context_patterns and not has_context:
                should_report = False

            if not should_report:
                continue

            # 定位行号
            first_pos = positive_patterns[0]
            line_no = _find_line_number(content, first_pos)
            snippet = _extract_snippet(content, first_pos)

            # 在所在行附近搜索额外上下文
            context_extra = ""
            if context_hits:
                for ch in context_hits:
                    cl = _find_line_number(content, ch)
                    if cl:
                        context_extra += f"行{cl}: {ch}; "

            findings.append(_make_finding(
                rule,
                file_path=rel,
                line_no=line_no,
                snippet=snippet,
                extra_desc=" ".join(extra_desc_parts),
                context=context_extra.strip(),
            ))

            # 每个文件每条规则只报告一次
            break

    return findings


def check_config_pattern_rules(
    source_files: list[dict], rules: list[dict]
) -> list[dict]:
    """配置级检查：在源文件中搜索 WebView 配置模式。

    对 type=config_pattern 的规则，搜索 positive_patterns，
    若匹配且 negative_patterns 缺失则生成发现。
    """
    findings: list[dict] = []
    file_contents: dict[str, str] = {}

    for rule in rules:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            continue
        if detection.get("type") != "config_pattern":
            continue

        positive_patterns = detection.get("positive_patterns", [])
        negative_patterns = detection.get("negative_patterns", [])

        for sf in source_files:
            filepath = sf["path"]
            rel = sf["rel"]

            if filepath not in file_contents:
                content = _read_file_content(filepath)
                file_contents[filepath] = content or ""
            content = file_contents[filepath]
            if not content:
                continue

            has_positive = any(p in content for p in positive_patterns)
            if not has_positive:
                continue

            has_negative = any(n in content for n in negative_patterns)
            if has_negative:
                continue

            first_pos = positive_patterns[0]
            line_no = _find_line_number(content, first_pos)
            snippet = _extract_snippet(content, first_pos)

            extra = ""
            if negative_patterns:
                extra = f"缺少: {', '.join(negative_patterns)}"

            findings.append(_make_finding(
                rule,
                file_path=rel,
                line_no=line_no,
                snippet=snippet,
                extra_desc=extra,
            ))

            break

    return findings


def run_webview_audit(
    metadata_path: str, project_path: str, rules_dir: str | None = None
) -> dict:
    """运行 WebView 安全审计，返回完整 findings 数据。"""
    if rules_dir is None:
        rules_dir = str(_SCRIPT_DIR / ".." / "rules")

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    rules = load_rules(Path(rules_dir))
    source_files = _search_source_files(metadata, project_path)

    if not source_files:
        print("[INFO] 未找到 .ets 源文件", file=sys.stderr)
        return {
            "_meta": {
                "auditor": "harmony-webview-audit",
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "project_path": project_path,
                "total_findings": 0,
                "severity_counts": {
                    sev: 0 for sev in ["critical", "high", "medium", "low", "info"]
                },
                "note": "未找到 .ets 源文件",
            },
            "findings": [],
        }

    # 分离规则类型
    config_rules = [r for r in rules if r.get("detection", {}).get("type") == "config_pattern"]
    code_rules = [r for r in rules if r.get("detection", {}).get("type") == "code_pattern"]

    # 执行两种检查
    config_findings = check_config_pattern_rules(source_files, config_rules)
    code_findings = check_code_pattern_rules(source_files, code_rules)

    all_findings = config_findings + code_findings
    all_findings.sort(
        key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 0), reverse=True
    )

    severity_counts = {
        sev: sum(1 for f in all_findings if f.get("severity") == sev)
        for sev in ["critical", "high", "medium", "low", "info"]
    }

    return {
        "_meta": {
            "auditor": "harmony-webview-audit",
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "project_path": project_path,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "note": "配置级与代码级模式匹配检查。深层逻辑分析（JS Bridge 暴露面评估、拦截器绕过分析）由 AI 执行。",
        },
        "findings": all_findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="HarmonyOS ArkWeb WebView 安全审计器（配置级与代码级规则检查）",
    )
    parser.add_argument("metadata_path", help="Phase 1 输出的 metadata JSON 文件路径")
    parser.add_argument("project_path", help="鸿蒙项目根目录路径")
    parser.add_argument("-o", "--output", default=None, help="输出 findings JSON 文件路径")
    parser.add_argument("--rules-dir", default=None, help="规则文件目录")
    parser.add_argument("--pretty", action="store_true", help="格式化 JSON 输出")

    args = parser.parse_args()

    if not os.path.exists(args.metadata_path):
        print(f"[ERROR] metadata 文件不存在: {args.metadata_path}", file=sys.stderr)
        sys.exit(1)

    try:
        output = run_webview_audit(args.metadata_path, args.project_path, args.rules_dir)
    except Exception as e:
        print(f"[ERROR] 审计失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    indent = 2 if args.pretty else None
    json_output = json.dumps(output, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_output, encoding="utf-8")
        print(f"[DONE] WebView 安全审计完成，共 {output['_meta']['total_findings']} 个发现，输出: {output_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
