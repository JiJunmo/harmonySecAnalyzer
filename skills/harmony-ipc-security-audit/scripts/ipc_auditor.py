#!/usr/bin/env python3
"""
HarmonyOS IPC 安全审计器。

用法:
    python3 ipc_auditor.py <metadata_json> <project_path> [-o findings.json]

功能:
    1. 读取 Phase 1 输出的项目元数据 JSON
    2. 加载 IPC 安全审计规则 (JSON)
    3. 执行配置级和代码级安全检测
    4. 输出标准化的 findings.json
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
    return f"HM-IPC-2026-{_COUNTER[0]:04d}"


def _check_rule_config(pattern_type: str) -> bool:
    return pattern_type in ("config_pattern", "config_combined")


def _check_rule_code(pattern_type: str) -> bool:
    return pattern_type in ("code_pattern",)


def _make_finding(
    rule: dict,
    file_path: str = "",
    line_no: int | None = None,
    snippet: str = "",
    extra_desc: str = "",
) -> dict:
    return {
        "id": _next_finding_id(),
        "skill": "harmony-ipc-security-audit",
        "severity": rule.get("severity", "info"),
        "title": rule.get("title", ""),
        "description": (rule.get("description", "") + (" " + extra_desc if extra_desc else "")).strip(),
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


def _find_line_number(file_path: str, pattern: str) -> int | None:
    """在文件中搜索模式，返回首次匹配的行号。"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                if pattern in line:
                    return i
    except (OSError, PermissionError):
        pass
    return None


def _find_line_snippet(file_path: str, line_no: int, context: int = 1) -> str:
    """读取文件指定行及上下文。"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, line_no - 1 - context)
        end = min(len(lines), line_no + context)
        return "".join(lines[start:end]).strip()
    except (OSError, PermissionError):
        return ""


def check_config_rules(metadata: dict, rules: list[dict]) -> list[dict]:
    """执行配置级规则检查（module.json5 配置）。"""
    findings: list[dict] = []
    modules = metadata.get("modules", [])

    for mod in modules:
        if mod.get("_parse_error"):
            continue

        mod_path = mod.get("_path", mod.get("name", "unknown"))
        exts = mod.get("extension_abilities", [])
        if not exts:
            continue

        for rule in rules:
            detection = rule.get("detection", {})
            if not isinstance(detection, dict):
                continue
            dtype = detection.get("type", "")
            rid = rule.get("id", "")

            if not _check_rule_config(dtype):
                continue

            for ext in exts:
                ext_name = ext.get("name", "")
                ext_type = (ext.get("type", "") or "").lower()

                if rid == "IPC-002":
                    if not ext.get("permissions") and ext_type:
                        findings.append(_make_finding(
                            rule, file_path=mod_path,
                            extra_desc=f"extensionAbility '{ext_name}' 未配置 permissions 字段。",
                        ))

                if rid == "IPC-014":
                    exported = ext.get("exported", False)
                    has_visible = bool(ext.get("visible"))
                    has_permissions = bool(ext.get("permissions"))
                    if exported and not has_visible and not has_permissions and ext_type:
                        findings.append(_make_finding(
                            rule, file_path=mod_path,
                            extra_desc=f"extensionAbility '{ext_name}' 导出但未设置任何访问控制。",
                        ))

    return findings


def check_code_rules(project_root: str, metadata: dict, rules: list[dict]) -> list[dict]:
    """执行代码级规则检查（搜索源文件模式）。"""
    findings: list[dict] = []
    project_path = Path(project_root)
    files_data = metadata.get("files", {})
    ets_sources = files_data.get("ets_sources", [])
    ts_sources = files_data.get("ts_sources", [])

    all_sources = ets_sources + ts_sources
    if not all_sources:
        return findings

    for rule in rules:
        detection = rule.get("detection", {})
        if not isinstance(detection, dict):
            continue
        dtype = detection.get("type", "")
        rid = rule.get("id", "")

        if not _check_rule_code(dtype):
            continue

        positive_patterns = detection.get("positive_patterns", [])
        negative_patterns = detection.get("negative_patterns", [])

        for source in all_sources:
            file_rel_path = source.get("path", source) if isinstance(source, dict) else source
            file_path = project_path / file_rel_path

            if not file_path.exists():
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                continue

            if positive_patterns:
                if not any(p in content for p in positive_patterns):
                    continue

            if negative_patterns:
                if any(p in content for p in negative_patterns):
                    continue

            # --- 按规则 ID 精确判断 ---

            if rid == "IPC-003" and "onRemoteMessageRequest" in content:
                line_no = _find_line_number(str(file_path), "onRemoteMessageRequest")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet,                     extra_desc="onRemoteMessageRequest 方法内未调用 getCallingUid/getCallingPid 做调用方身份校验。"))

            if rid == "IPC-004" and "readInterfaceToken" in content:
                line_no = _find_line_number(str(file_path), "readInterfaceToken")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="InterfaceToken 校验后未见其他身份认证。"))

            if rid == "IPC-005":
                line_no = _find_line_number(str(file_path), "writeParcelable") or _find_line_number(str(file_path), "writeArrayBuffer")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="数据以明文形式写入 MessageSequence。"))

            if rid == "IPC-006" and "unmarshalling" in content:
                line_no = _find_line_number(str(file_path), "unmarshalling")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="unmarshalling 方法无条件返回 true，未校验数据。"))

            if rid == "IPC-007" and re.search(r'switch\s*\(\s*code\s*\)', content):
                # 找到 switch(code) 之后的 default 分支，检查是否有副作用操作
                switch_pos = content.find("switch(code)")
                after_switch = content[switch_pos:]
                default_match = re.search(r'default\s*:\s*\n\s*([^\n]*)', after_switch)
                if default_match:
                    default_line = default_match.group(1).strip()
                    # default 仅 break/return/空 → 无风险，跳过
                    if default_line in ("break;", "break", "return;", "return", ""):
                        continue
                line_no = _find_line_number(str(file_path), "switch")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc=f"switch(code) 的 default 分支存在操作（{default_line[:40] if default_match else '未知'}），可能被任意 code 值触发。"))

            if rid == "IPC-008" and "readArrayBuffer" in content:
                line_no = _find_line_number(str(file_path), "readArrayBuffer")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="readArrayBuffer 后未检查 byteLength。"))

            if rid == "IPC-009" and "RemoteObject" in content:
                if "getInstance" in content or "globalStub" in content:
                    line_no = _find_line_number(str(file_path), "getInstance")
                    snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                    findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                        snippet=snippet, extra_desc="Stub 实例通过单例模式共享，缺乏会话隔离。"))

            if rid == "IPC-010-LOG":
                if "hilog.info" in content and ("JSON.stringify(want" in content or "read parcelable" in content or "readString" in content):
                    line_no = _find_line_number(str(file_path), "hilog.info")
                    snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                    findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                        snippet=snippet, extra_desc="hilog.info 打印了 IPC 通信数据。"))

            if rid == "IPC-011-CONNECT" and "onConnect" in content and "ServiceExtensionAbility" in content:
                line_no = _find_line_number(str(file_path), "onConnect")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="onConnect 直接返回 Stub，未校验调用方身份。"))

            if rid == "IPC-012-CLEANUP" and "disconnectServiceExtensionAbility" in content:
                line_no = _find_line_number(str(file_path), "disconnectServiceExtensionAbility")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="disconnectServiceExtensionAbility 后未见 proxy 清理。"))

            if rid == "IPC-010-RETURN" and "onRemoteMessageRequest" in content:
                line_no = _find_line_number(str(file_path), "onRemoteMessageRequest")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="onRemoteMessageRequest 方法体中未发现 return false 路径。"))

            if rid == "IPC-015" and "super(" in content:
                descriptor_match = re.findall(r"super\(['\"]([^'\"]+)['\"]", content)
                if descriptor_match:
                    line_no = _find_line_number(str(file_path), "super(")
                    snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                    findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                        snippet=snippet, extra_desc=f"descriptor 硬编码为 '{descriptor_match[0]}'。"))

            if rid == "IPC-016" and "connectServiceExtensionAbility" in content:
                line_no = _find_line_number(str(file_path), "connectServiceExtensionAbility")
                snippet = _find_line_snippet(str(file_path), line_no) if line_no else ""
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    snippet=snippet, extra_desc="connectServiceExtensionAbility 未设置连接超时保护。"))

            if rid == "IPC-INFO-ALL":
                line_no = _find_line_number(str(file_path), "@ohos.rpc") or _find_line_number(str(file_path), "@kit.IPCKit") or 1
                findings.append(_make_finding(rule, file_path=str(file_rel_path), line_no=line_no,
                    extra_desc="文件使用了 IPC Kit 进行跨进程通信。"))

    return findings


def run_audit(metadata_path: str, project_path: str, rules_dir: str | None = None) -> list[dict]:
    """运行 IPC 安全审计，返回 findings 列表。"""
    if rules_dir is None:
        rules_dir = str(_SCRIPT_DIR / ".." / "rules")

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    rules = load_rules(Path(rules_dir))

    config_findings = check_config_rules(metadata, rules)
    code_findings = check_code_rules(project_path, metadata, rules)

    all_findings = config_findings + code_findings
    all_findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 0), reverse=True)

    return all_findings


def main():
    parser = argparse.ArgumentParser(
        description="HarmonyOS IPC 安全审计器",
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
        findings = run_audit(args.metadata_path, args.project_path, args.rules_dir)
    except Exception as e:
        print(f"[ERROR] 审计失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    output = {
        "_meta": {
            "auditor": "harmony-ipc-security-audit",
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "project_path": args.project_path,
            "total_findings": len(findings),
            "severity_counts": {
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
                "info": sum(1 for f in findings if f["severity"] == "info"),
            },
        },
        "findings": findings,
    }

    indent = 2 if args.pretty else None
    json_output = json.dumps(output, ensure_ascii=False, indent=indent, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_output)
        print(f"[DONE] IPC 审计完成，共 {len(findings)} 个发现，输出: {output_path}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
