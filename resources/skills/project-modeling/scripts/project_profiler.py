#!/usr/bin/env python3
"""Deterministic HarmonyOS/OpenHarmony manifest profiler.

Parses JSON5 project files and builds Atlas discovery anchors. It never reads
source contents; source semantics are resolved through Atlas MCP.
"""

import argparse
import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import json5


SCHEMA_VERSION = 2
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


def stable_id(prefix, *parts):
    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


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


def normalize_component(raw, kind, module_id, module_name, module_root, module_file,
                        module_scope, component_id):
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
        "module_id": module_id,
        "module_name": module_name,
        "module_root": module_root,
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


def is_production_source_scope(scope):
    parts = {part.lower() for part in Path(str(scope or "")).parts}
    return not parts.intersection({"test", "ohostest", "mock", "unittest"})


def module_root_for_manifest(path):
    """Return the module root for the conventional <module>/src/<set>/module.json5 layout."""
    if path.parent.parent.name == "src":
        return path.parent.parent.parent
    return path.parent


def module_output_kind(module_type):
    return {
        "entry": "hap", "feature": "hap", "shared": "hsp", "har": "har",
    }.get(str(module_type or "").lower(), "unknown")


def make_entry_candidates(components):
    candidates = []

    def add(entry_type, component, location, trigger_facts):
        candidates.append({
            "candidate_id": stable_id("PE", component["component_id"], entry_type, location),
            "type": entry_type,
            "source": "manifest",
            "component_id": component["component_id"],
            "component_name": component.get("name"),
            "module_id": component.get("module_id"),
            "module_name": component.get("module_name"),
            "module_root": component.get("module_root"),
            "location": location,
            "exported": component.get("exported"),
            "permissions": component.get("permissions", []),
            "src_entry": component.get("src_entry"),
            "lifecycle_candidates": component.get("lifecycle_candidates", []),
            "trigger_facts": trigger_facts,
        })

    for component in components:
        if not is_production_source_scope(component.get("source_scope")):
            continue
        base = f"{component['module_file']}#{component['kind']}:{component.get('name') or component['component_id']}"
        add("component_scope", component, base, {
            "component_scope": True,
            "requires_upstream_reachability_evidence": component.get("exported") is not True,
        })
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
        extension_type = str(component.get("extension_type") or "").lower()
        if "service" in extension_type:
            add("ipc_service_candidate", component, base, {
                "extension_type": component.get("extension_type"),
                "requires_stub_publication_evidence": True,
            })

    return candidates


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

    # Root build profiles define which local module roots participate in a product.
    build_profiles = []
    build_products = set()
    build_modes = set()
    declarations = {}
    for path in sorted(by_name.get("build-profile.json5", [])):
        data = load(path, "build_profile")
        if not data:
            continue
        app = data.get("app", {}) if isinstance(data.get("app", {}), dict) else {}
        products = app.get("products", data.get("products", []))
        product_names = sorted({
            str(row.get("name")) for row in as_list(products)
            if isinstance(row, dict) and row.get("name")
        })
        build_products.update(product_names)
        build_modes.update(
            str(row.get("name")) for row in as_list(app.get("buildModeSet"))
            if isinstance(row, dict) and row.get("name")
        )
        profile_modules = data.get("modules", app.get("modules", []))
        profile_declarations = []
        for row in as_list(profile_modules):
            if not isinstance(row, dict) or not row.get("srcPath"):
                continue
            module_path = (path.parent / str(row["srcPath"])).resolve()
            try:
                module_root = relpath(module_path, root)
            except ValueError:
                diagnostics.append({
                    "severity": "warning", "kind": "external_module_path",
                    "file": relpath(path, root), "message": f"module srcPath is outside repository: {row['srcPath']}",
                })
                continue
            targets = [target for target in as_list(row.get("targets")) if isinstance(target, dict)]
            target_names = sorted({str(target.get("name")) for target in targets if target.get("name")})
            applied_products = sorted({
                str(product) for target in targets for product in as_list(target.get("applyToProducts"))
                if product is not None
            })
            if not applied_products:
                applied_products = product_names
            declaration = {
                "name": row.get("name"), "root": module_root, "src_path": str(row["srcPath"]),
                "targets": target_names, "products": applied_products,
                "build_profile": relpath(path, root),
            }
            profile_declarations.append(declaration)
            existing = declarations.setdefault(module_root, declaration)
            existing["targets"] = sorted(set(existing["targets"]) | set(target_names))
            existing["products"] = sorted(set(existing["products"]) | set(applied_products))
        build_profiles.append({
            "file": relpath(path, root), "products": product_names,
            "module_declarations": profile_declarations,
        })

    modules = []
    components = []
    requested_permissions = []
    defined_permissions = []
    module_files = sorted(
        path for path in by_name.get("module.json5", [])
        if is_production_source_scope(relpath(path.parent, root))
    )
    if not module_files:
        diagnostics.append({"severity": "error", "kind": "missing_config", "file": None, "message": "production module.json5 not found"})
    discovered_roots = set()
    for path in module_files:
        data = load(path, "module")
        if not data:
            continue
        module = data.get("module", data)
        if not isinstance(module, dict):
            diagnostics.append({"severity": "error", "kind": "invalid_structure", "file": relpath(path, root), "message": "module must be an object"})
            continue
        module_root_path = module_root_for_manifest(path)
        module_root = relpath(module_root_path, root)
        discovered_roots.add(module_root)
        declaration = declarations.get(module_root)
        included_in_build = not declarations or declaration is not None
        module_name = module.get("name") or (declaration or {}).get("name") or module_root_path.name
        module_id = stable_id("MOD", module_root, module_name)
        permission_rows = []
        for item in as_list(module.get("requestPermissions")):
            if isinstance(item, str):
                permission_rows.append({"name": item})
            elif isinstance(item, dict):
                permission_rows.append({
                    "name": item.get("name"), "reason": item.get("reason"),
                    "used_scene": item.get("usedScene"),
                })
        requested_permissions.extend(row for row in permission_rows if row.get("name") and included_in_build)
        defined_permission_rows = []
        for item in as_list(module.get("definePermissions")):
            if not isinstance(item, dict) or not item.get("name"):
                continue
            defined_permission_rows.append({
                "name": item.get("name"), "grant_mode": item.get("grantMode"),
                "available_level": item.get("availableLevel"),
                "provision_enable": item.get("provisionEnable"),
                "distributed_scene_enable": item.get("distributedSceneEnable"),
            })
        if included_in_build:
            defined_permissions.extend(defined_permission_rows)
        module_file = relpath(path, root)
        module_scope = relpath(path.parent, root)
        module_components = []
        for key, kind in (("abilities", "ability"), ("extensionAbilities", "extension_ability")):
            for index, raw in enumerate(as_list(module.get(key))):
                raw_object = raw if isinstance(raw, dict) else {}
                component_id = stable_id(
                    "CMP", module_id, kind, raw_object.get("name"), raw_object.get("srcEntry"), index,
                )
                component = normalize_component(
                    raw, kind, module_id, module_name, module_root, module_file,
                    module_scope, component_id,
                )
                component["included_in_build"] = included_in_build
                components.append(component)
                module_components.append(component_id)
        modules.append({
            "module_id": module_id, "file": module_file, "root": module_root,
            "name": module_name, "build_name": (declaration or {}).get("name"),
            "type": module.get("type"), "output_kind": module_output_kind(module.get("type")),
            "included_in_build": included_in_build,
            "products": (declaration or {}).get("products", []),
            "targets": (declaration or {}).get("targets", []),
            "build_profile": (declaration or {}).get("build_profile"),
            "src_entry": module.get("srcEntry"), "source_scope": module_scope,
            "device_types": strings(module.get("deviceTypes")),
            "delivery_with_install": module.get("deliveryWithInstall"),
            "installation_free": module.get("installationFree"),
            "virtual_machine": module.get("virtualMachine"),
            "request_permissions": permission_rows, "defined_permissions": defined_permission_rows,
            "component_ids": module_components, "package_name": None, "dependency_ids": [],
        })
        if not included_in_build:
            diagnostics.append({
                "severity": "warning", "kind": "module_not_in_build",
                "file": module_file, "message": f"module root is not declared by a root build profile: {module_root}",
            })
    for module_root, declaration in sorted(declarations.items()):
        if module_root not in discovered_roots:
            diagnostics.append({
                "severity": "error", "kind": "missing_module_manifest",
                "file": declaration["build_profile"],
                "message": f"declared module has no production module.json5: {module_root}",
            })

    # Associate module-local package manifests, then resolve local file dependencies.
    modules_by_root = {row["root"]: row for row in modules}
    package_docs = []
    packages_by_name = {}
    for path in sorted(by_name.get("oh-package.json5", [])):
        data = load(path, "oh_package")
        if not data:
            continue
        package_docs.append((path, data))
        source = modules_by_root.get(relpath(path.parent, root))
        if source and data.get("name"):
            source["package_name"] = data["name"]
            packages_by_name[str(data["name"])] = source

    dependencies = []
    module_dependencies = []
    seen_edges = set()
    for path, data in package_docs:
        source = modules_by_root.get(relpath(path.parent, root))
        for group in ("dependencies", "devDependencies", "dynamicDependencies"):
            values = data.get(group, {})
            if not isinstance(values, dict):
                continue
            for name, version in sorted(values.items()):
                target = None
                reference = str(version) if isinstance(version, str) else None
                if reference and reference.startswith("file:"):
                    local_path = (path.parent / reference.removeprefix("file:")).resolve()
                    try:
                        target = modules_by_root.get(relpath(local_path, root))
                    except ValueError:
                        target = None
                if target is None:
                    target = packages_by_name.get(str(name))
                dependency = {
                    "name": name, "version": version, "group": group,
                    "file": relpath(path, root),
                    "source_module_id": source.get("module_id") if source else None,
                    "target_module_id": target.get("module_id") if target else None,
                    "local": bool(source and target),
                }
                dependencies.append(dependency)
                if not source or not target:
                    continue
                edge_key = (source["module_id"], target["module_id"], str(name), group)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)
                edge_id = stable_id("DEP", *edge_key)
                source["dependency_ids"].append(edge_id)
                module_dependencies.append({
                    "dependency_id": edge_id, "source_module_id": source["module_id"],
                    "target_module_id": target["module_id"], "name": name,
                    "group": group, "reference": version, "declaration_file": relpath(path, root),
                })

    active_modules = [row for row in modules if row["included_in_build"]]
    active_module_ids = {row["module_id"] for row in active_modules}
    active_components = [row for row in components if row["module_id"] in active_module_ids]
    entry_candidates = make_entry_candidates(active_components)
    status = "partial" if any(d["severity"] == "error" for d in diagnostics) else "complete"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_repo": str(root),
        "status": status,
        "summary": {
            "modules": len(active_modules),
            "discovered_modules": len(modules),
            "components": len(active_components),
            "entry_candidates": len(entry_candidates),
            "requested_permissions": len({row["name"] for row in requested_permissions}),
            "defined_permissions": len({row["name"] for row in defined_permissions}),
            "dependencies": len(dependencies),
            "module_dependencies": len(module_dependencies),
            "parse_errors": sum(1 for d in diagnostics if d["severity"] == "error"),
        },
        "build": {
            "scope": "declared_modules" if declarations else "discovered_production_modules",
            "product_scope": "union",
            "products": sorted(build_products),
            "build_modes": sorted(build_modes),
            "declared_module_roots": sorted(declarations),
        },
        "application": application,
        "modules": modules,
        "components": active_components,
        "entry_candidates": entry_candidates,
        "requested_permissions": requested_permissions,
        "defined_permissions": defined_permissions,
        "dependencies": dependencies,
        "module_dependencies": module_dependencies,
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
    args = parser.parse_args()
    try:
        model = profile_project(args.target_repo)
        write_json_atomic(args.output, model)
        print(json.dumps({
            "ok": True,
            "status": model["status"],
            "output": str(Path(args.output).resolve()),
            "summary": model["summary"],
            "diagnostics": model["diagnostics"],
        }, ensure_ascii=False, indent=2))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
