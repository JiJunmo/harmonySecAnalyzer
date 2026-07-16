#!/usr/bin/env python3
"""Deterministic HarmonyOS/OpenHarmony manifest profiler.

Parses JSON5 project files and builds Atlas discovery anchors. It never reads
source contents; source semantics are resolved through Atlas MCP.
"""

import argparse
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import json5


SCHEMA_VERSION = 1
SKIP_DIRS = {
    ".git", ".atlas", ".idea", ".vscode", "node_modules", "oh_modules",
    "build", "outputs", "reports", "coverage", ".hvigor",
}
CONFIG_NAMES = {"app.json5", "module.json5", "build-profile.json5", "oh-package.json5"}


def parse_json5(path):
    with path.open(encoding="utf-8-sig") as handle:
        return json5.load(handle)


def relpath(path, root):
    return path.relative_to(root).as_posix()


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def strings(value):
    return [str(v) for v in as_list(value) if v is not None]


def walk_config_files(root):
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name in CONFIG_NAMES:
                yield Path(current) / name


def lifecycle_candidates(kind, extension_type):
    if kind == "ability":
        return ["onCreate", "onNewWant"]
    ext = str(extension_type or "").lower()
    if "datashare" in ext:
        return ["onCreate", "query", "insert", "update", "delete", "openFile"]
    if "service" in ext:
        return ["onCreate", "onConnect", "onDisconnect", "onRequest"]
    if "form" in ext:
        return ["onAddForm", "onUpdateForm", "onFormEvent"]
    if "uiextension" in ext:
        return ["onCreate", "onSessionCreate", "onSessionDestroy"]
    return ["onCreate", "onConnect", "onRequest"]


def normalize_uri(uri):
    if isinstance(uri, str):
        return {"uri": uri}
    if not isinstance(uri, dict):
        return {"raw": uri}
    keys = (
        "scheme", "host", "port", "path", "pathStartWith", "pathRegex",
        "type", "linkFeature", "linkFeatureMode",
    )
    return {key: uri.get(key) for key in keys if key in uri}


def normalize_skill(skill, index):
    if not isinstance(skill, dict):
        return {"skill_index": index, "actions": [], "entities": [], "uris": [], "mime_types": [], "raw": skill}
    uris = [normalize_uri(uri) for uri in as_list(skill.get("uris"))]
    mime_types = strings(skill.get("type")) + strings(skill.get("types"))
    return {
        "skill_index": index,
        "actions": strings(skill.get("actions")),
        "entities": strings(skill.get("entities")),
        "uris": uris,
        "mime_types": sorted(set(mime_types)),
    }


def normalize_component(raw, kind, module_name, module_file, module_scope, component_id):
    raw = raw if isinstance(raw, dict) else {}
    skills = [normalize_skill(skill, i) for i, skill in enumerate(as_list(raw.get("skills")))]
    permissions = []
    for key in ("permissions", "permission", "readPermission", "writePermission"):
        permissions.extend(strings(raw.get(key)))
    extension_type = raw.get("type") if kind == "extension_ability" else None
    src_entry = raw.get("srcEntry")
    source_file_hint = None
    if src_entry:
        src_entry_path = str(src_entry)
        if src_entry_path.startswith("./"):
            src_entry_path = src_entry_path[2:]
        source_file_hint = (Path(module_scope) / src_entry_path).as_posix()
    return {
        "component_id": component_id,
        "module_name": module_name,
        "module_file": module_file,
        "kind": kind,
        "name": raw.get("name"),
        "src_entry": src_entry,
        "source_scope": module_scope,
        "source_file_hint": source_file_hint,
        "extension_type": extension_type,
        "exported": raw.get("exported") if isinstance(raw.get("exported"), bool) else None,
        "enabled": raw.get("enabled") if isinstance(raw.get("enabled"), bool) else None,
        "permissions": sorted(set(permissions)),
        "uri": raw.get("uri"),
        "skills": skills,
        "lifecycle_candidates": lifecycle_candidates(kind, extension_type),
    }


def make_entry_candidates(components):
    candidates = []
    next_id = 1

    def add(entry_type, component, location, trigger_facts):
        nonlocal next_id
        candidates.append({
            "candidate_id": f"PE-{next_id:03d}",
            "type": entry_type,
            "source": "manifest",
            "component_id": component["component_id"],
            "component_name": component.get("name"),
            "module_name": component.get("module_name"),
            "location": location,
            "exported": component.get("exported"),
            "permissions": component.get("permissions", []),
            "src_entry": component.get("src_entry"),
            "lifecycle_candidates": component.get("lifecycle_candidates", []),
            "trigger_facts": trigger_facts,
        })
        next_id += 1

    for component in components:
        base = f"{component['module_file']}#{component['kind']}:{component.get('name') or component['component_id']}"
        if component.get("exported") is True:
            add("exported_component", component, base, {"exported": True})
        for skill in component.get("skills", []):
            location = f"{base}.skills[{skill['skill_index']}]"
            if skill.get("uris"):
                add("deeplink", component, location, {"uris": skill["uris"], "actions": skill.get("actions", [])})
            if skill.get("actions") or skill.get("entities") or skill.get("mime_types"):
                add("implicit_want", component, location, {
                    "actions": skill.get("actions", []),
                    "entities": skill.get("entities", []),
                    "mime_types": skill.get("mime_types", []),
                    "uris": skill.get("uris", []),
                })
        if component.get("uri"):
            add("extension_uri", component, base, {"uri": component["uri"], "extension_type": component.get("extension_type")})

    return candidates


def build_discovery_plan(model):
    candidates_by_component = {}
    for candidate in model.get("entry_candidates", []):
        component_id = candidate.get("component_id")
        if component_id:
            candidates_by_component.setdefault(component_id, []).append(candidate["candidate_id"])

    units = []
    for component in model.get("components", []):
        candidate_ids = sorted(candidates_by_component.get(component["component_id"], []))
        if not candidate_ids:
            continue
        anchors = []
        if component.get("name"):
            anchors.append({"kind": "component", "query": component["name"]})
        anchors.extend(
            {"kind": "lifecycle", "query": name}
            for name in component.get("lifecycle_candidates", [])
        )
        units.append({
            "unit_id": f"AU-{len(units) + 1:03d}",
            "component_id": component["component_id"],
            "entry_candidate_ids": candidate_ids,
            "scope": component["source_scope"],
            "source_file_hint": component.get("source_file_hint"),
            "anchors": anchors,
            "status": "planned",
            "resolved_symbols": [],
            "atlas_query_ids": [],
            "gaps": [],
        })
    return {
        "schema_version": 1,
        "project_model_schema_version": model.get("schema_version"),
        "target_repo": model.get("target_repo"),
        "strategy": "manifest_anchors_atlas_scoped_expansion",
        "source_content_scanned": False,
        "units": units,
        "summary": {
            "total": len(units),
            "planned": len(units),
            "completed": 0,
            "excluded": 0,
            "unresolved": 0,
            "atlas_gap": 0,
        },
    }


def profile_project(target_repo):
    root = Path(target_repo).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"target repo is not a directory: {root}")

    files = list(walk_config_files(root))
    by_name = {}
    for path in files:
        by_name.setdefault(path.name, []).append(path)

    diagnostics = []
    parsed_files = []

    def load(path, kind):
        record = {"path": relpath(path, root), "kind": kind, "status": "parsed"}
        try:
            value = parse_json5(path)
            if not isinstance(value, dict):
                raise ValueError(f"{path}: root must be an object")
            parsed_files.append(record)
            return value
        except (OSError, ValueError) as exc:
            record["status"] = "error"
            record["error"] = str(exc)
            parsed_files.append(record)
            diagnostics.append({"severity": "error", "kind": "parse_error", "file": record["path"], "message": str(exc)})
            return None

    application = None
    app_files = sorted(by_name.get("app.json5", []))
    if not app_files:
        diagnostics.append({"severity": "warning", "kind": "missing_config", "file": None, "message": "app.json5 not found"})
    for path in app_files:
        data = load(path, "app")
        if not data:
            continue
        app = data.get("app", data)
        if isinstance(app, dict) and application is None:
            application = {
                "file": relpath(path, root),
                "bundle_name": app.get("bundleName"),
                "vendor": app.get("vendor"),
                "version_code": app.get("versionCode"),
                "version_name": app.get("versionName"),
                "min_api_version": app.get("minAPIVersion"),
                "target_api_version": app.get("targetAPIVersion"),
            }

    modules = []
    components = []
    requested_permissions = []
    module_files = sorted(by_name.get("module.json5", []))
    if not module_files:
        diagnostics.append({"severity": "error", "kind": "missing_config", "file": None, "message": "module.json5 not found"})
    for path in module_files:
        data = load(path, "module")
        if not data:
            continue
        module = data.get("module", data)
        if not isinstance(module, dict):
            diagnostics.append({"severity": "error", "kind": "invalid_structure", "file": relpath(path, root), "message": "module must be an object"})
            continue
        module_name = module.get("name") or path.parent.name
        permission_rows = []
        for item in as_list(module.get("requestPermissions")):
            if isinstance(item, str):
                permission_rows.append({"name": item})
            elif isinstance(item, dict):
                permission_rows.append({
                    "name": item.get("name"),
                    "reason": item.get("reason"),
                    "used_scene": item.get("usedScene"),
                })
        requested_permissions.extend(row for row in permission_rows if row.get("name"))
        module_file = relpath(path, root)
        module_scope = relpath(path.parent, root)
        module_components = []
        for key, kind in (("abilities", "ability"), ("extensionAbilities", "extension_ability")):
            for raw in as_list(module.get(key)):
                component_id = f"CMP-{len(components) + 1:03d}"
                component = normalize_component(raw, kind, module_name, module_file, module_scope, component_id)
                components.append(component)
                module_components.append(component_id)
        modules.append({
            "module_id": f"MOD-{len(modules) + 1:03d}",
            "file": module_file,
            "name": module_name,
            "type": module.get("type"),
            "src_entry": module.get("srcEntry"),
            "source_scope": module_scope,
            "device_types": strings(module.get("deviceTypes")),
            "delivery_with_install": module.get("deliveryWithInstall"),
            "installation_free": module.get("installationFree"),
            "virtual_machine": module.get("virtualMachine"),
            "request_permissions": permission_rows,
            "component_ids": module_components,
        })

    dependencies = []
    for path in sorted(by_name.get("oh-package.json5", [])):
        data = load(path, "oh_package")
        if not data:
            continue
        for group in ("dependencies", "devDependencies", "dynamicDependencies"):
            values = data.get(group, {})
            if not isinstance(values, dict):
                continue
            for name, version in sorted(values.items()):
                dependencies.append({"name": name, "version": version, "group": group, "file": relpath(path, root)})

    build_profiles = []
    for path in sorted(by_name.get("build-profile.json5", [])):
        data = load(path, "build_profile")
        if not data:
            continue
        app = data.get("app", {}) if isinstance(data.get("app", {}), dict) else {}
        build_profiles.append({
            "file": relpath(path, root),
            "products": app.get("products", data.get("products", [])),
            "modules": app.get("modules", data.get("modules", [])),
        })

    entry_candidates = make_entry_candidates(components)
    status = "partial" if any(d["severity"] == "error" for d in diagnostics) else "complete"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_repo": str(root),
        "status": status,
        "summary": {
            "modules": len(modules),
            "components": len(components),
            "entry_candidates": len(entry_candidates),
            "requested_permissions": len({row["name"] for row in requested_permissions}),
            "dependencies": len(dependencies),
            "parse_errors": sum(1 for d in diagnostics if d["severity"] == "error"),
        },
        "application": application,
        "modules": modules,
        "components": components,
        "entry_candidates": entry_candidates,
        "requested_permissions": requested_permissions,
        "dependencies": dependencies,
        "build_profiles": build_profiles,
        "parsed_files": parsed_files,
        "diagnostics": diagnostics,
    }


def write_json_atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(json_safe(value), handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def json_safe(value):
    if isinstance(value, float) and not math.isfinite(value):
        return "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    return value


def main():
    parser = argparse.ArgumentParser(description="Deterministically profile a HarmonyOS/OpenHarmony project")
    parser.add_argument("target_repo")
    parser.add_argument("--output", required=True)
    parser.add_argument("--plan-output", required=True)
    args = parser.parse_args()
    try:
        model = profile_project(args.target_repo)
        plan = build_discovery_plan(model)
        write_json_atomic(args.output, model)
        write_json_atomic(args.plan_output, plan)
        print(json.dumps({
            "ok": True,
            "status": model["status"],
            "output": str(Path(args.output).resolve()),
            "plan_output": str(Path(args.plan_output).resolve()),
            "summary": model["summary"],
            "discovery_units": len(plan["units"]),
            "diagnostics": model["diagnostics"],
        }, ensure_ascii=False, indent=2))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
