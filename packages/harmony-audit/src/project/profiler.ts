import { readFile, stat } from "node:fs/promises";
import { relative, resolve, dirname, basename } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import fg from "fast-glob";
import JSON5 from "json5";
import { contentHash, stableId } from "../runtime/identity.js";

type Row = Record<string, unknown>;
const ignored = ["**/.git/**", "**/.atlas/**", "**/.idea/**", "**/.vscode/**", "**/node_modules/**", "**/oh_modules/**", "**/build/**", "**/outputs/**", "**/reports/**", "**/coverage/**", "**/.hvigor/**"];
const array = <T>(value: T | T[] | undefined): T[] => value === undefined ? [] : Array.isArray(value) ? value : [value];
const strings = (value: unknown): string[] => array(value).filter((item) => item !== null && item !== undefined).map(String);
const rel = (path: string, root: string) => relative(root, path).replaceAll("\\", "/") || ".";
const isProduction = (path: string) => !path.split("/").map((part) => part.toLowerCase()).some((part) => ["test", "ohostest", "mock", "unittest"].includes(part));
const rows = (value: unknown): Row[] => array(value).filter((item): item is Row => !!item && typeof item === "object" && !Array.isArray(item));

export interface ProjectModel {
  readonly schema_version: 2; readonly generated_at: string; readonly target_repo: string;
  readonly status: "complete" | "partial" | "failed"; readonly summary: Record<string, number>;
  readonly build: Row; readonly application: Row | null; readonly modules: Row[]; readonly components: Row[];
  readonly entry_candidates: Row[]; readonly requested_permissions: Row[]; readonly defined_permissions: Row[];
  readonly dependencies: Row[]; readonly module_dependencies: Row[]; readonly build_profiles: Row[];
  readonly parsed_files: Row[]; readonly diagnostics: Row[];
}

export function selectComponents(model: ProjectModel, requested: readonly string[]): string[] {
  if (!requested.length) return [];
  const selected: string[] = [];
  for (const selector of requested) {
    const matches = model.components.filter((item) => item.component_id === selector || item.name === selector);
    if (!matches.length) throw new Error(`component_not_found:${selector}`);
    if (matches.length > 1) throw new Error(`component_ambiguous:${selector}:${matches.map((item) => item.component_id).sort().join(",")}`);
    selected.push(String(matches[0]!.component_id));
  }
  return [...new Set(selected)];
}

function lifecycle(kind: string, extensionType: unknown): string[] {
  if (kind === "ability") return ["onCreate", "onNewWant"];
  const type = String(extensionType ?? "").toLowerCase();
  if (type.includes("datashare")) return ["onCreate", "query", "insert", "update", "delete", "openFile"];
  if (type.includes("service")) return ["onCreate", "onConnect", "onDisconnect", "onRequest"];
  if (type.includes("form")) return ["onAddForm", "onUpdateForm", "onFormEvent"];
  if (type.includes("uiextension")) return ["onCreate", "onSessionCreate", "onSessionDestroy"];
  return ["onCreate", "onConnect", "onRequest"];
}

function moduleRoot(manifest: string): string {
  const parent = dirname(manifest); return basename(dirname(parent)) === "src" ? dirname(dirname(parent)) : parent;
}

function outputKind(type: unknown): string { return ({ entry: "hap", feature: "hap", shared: "hsp", har: "har" } as Record<string, string>)[String(type ?? "").toLowerCase()] ?? "unknown"; }

function normalizedSkill(skill: Row, index: number): Row {
  const uris = array(skill.uris).map((uri) => typeof uri === "string" ? { uri } : uri && typeof uri === "object" ? uri : { raw: uri });
  return { skill_index: index, actions: strings(skill.actions), entities: strings(skill.entities), uris, mime_types: [...new Set([...strings(skill.type), ...strings(skill.types)])].sort() };
}

function makeEntries(components: Row[]): Row[] {
  const result: Row[] = [];
  const add = (type: string, component: Row, location: string, trigger: Row) => result.push({
    candidate_id: stableId("PE", component.component_id, type, location), type, source: "manifest", component_id: component.component_id,
    component_name: component.name ?? null, module_id: component.module_id, module_name: component.module_name, module_root: component.module_root,
    location, exported: component.exported ?? null, permissions: component.permissions ?? [], src_entry: component.src_entry ?? null,
    lifecycle_candidates: component.lifecycle_candidates ?? [], trigger_facts: trigger,
  });
  for (const component of components) {
    const base = `${String(component.module_file)}#${String(component.kind)}:${String(component.name ?? component.component_id)}`;
    add("component_scope", component, base, { component_scope: true, requires_upstream_reachability_evidence: component.exported !== true });
    if (component.exported === true) add("exported_component", component, base, { exported: true });
    for (const skill of rows(component.skills)) {
      const location = `${base}.skills[${String(skill.skill_index)}]`;
      if (array(skill.uris).length) add("deeplink", component, location, { uris: skill.uris, actions: skill.actions });
      if (array(skill.actions).length || array(skill.entities).length || array(skill.mime_types).length) add("implicit_want", component, location, { actions: skill.actions, entities: skill.entities, mime_types: skill.mime_types, uris: skill.uris });
    }
    if (component.uri) add("extension_uri", component, base, { uri: component.uri, extension_type: component.extension_type });
    const extensionType = String(component.extension_type ?? "").toLowerCase();
    if (extensionType.includes("service")) add("ipc_service_candidate", component, base, { extension_type: component.extension_type, requires_stub_publication_evidence: true });
  }
  return result;
}

export async function profileProject(targetRepository: string): Promise<ProjectModel> {
  const root = resolve(targetRepository); const rootStat = await stat(root).catch(() => undefined); if (!rootStat?.isDirectory()) throw new Error(`target_repo_not_directory:${root}`);
  const diagnostics: Row[] = []; const parsedFiles: Row[] = [];
  const files = (await fg(["**/app.json5", "**/module.json5", "**/build-profile.json5", "**/oh-package.json5"], { cwd: root, absolute: true, ignore: ignored })).sort();
  const byName = new Map<string, string[]>(); for (const file of files) byName.set(basename(file), [...(byName.get(basename(file)) ?? []), file]);
  const load = async (file: string, kind: string): Promise<Row | undefined> => {
    const record: Row = { path: rel(file, root), kind, status: "parsed" };
    try { const value = JSON5.parse(await readFile(file, "utf8")); if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("root must be an object"); parsedFiles.push(record); return value as Row; }
    catch (error) { record.status = "error"; record.error = error instanceof Error ? error.message : String(error); parsedFiles.push(record); diagnostics.push({ severity: "error", kind: "parse_error", file: rel(file, root), message: record.error }); return undefined; }
  };

  let application: Row | null = null;
  for (const file of byName.get("app.json5") ?? []) {
    const document = await load(file, "app"); const app = (document?.app as Row | undefined) ?? document;
    if (app && !application) application = { file: rel(file, root), bundle_name: app.bundleName ?? null, vendor: app.vendor ?? null, version_code: app.versionCode ?? null, version_name: app.versionName ?? null, min_api_version: app.minAPIVersion ?? null, target_api_version: app.targetAPIVersion ?? null };
  }
  if (!application) diagnostics.push({ severity: "warning", kind: "missing_config", file: null, message: "app.json5 not found" });

  const declarations = new Map<string, Row>(); const buildProfiles: Row[] = []; const products = new Set<string>(); const buildModes = new Set<string>();
  for (const file of byName.get("build-profile.json5") ?? []) {
    const document = await load(file, "build_profile"); if (!document) continue; const app = (document.app as Row | undefined) ?? {};
    const productNames = rows(app.products ?? document.products).map((item) => String(item.name)).filter(Boolean).sort(); productNames.forEach((item) => products.add(item));
    rows(app.buildModeSet).map((item) => String(item.name)).filter(Boolean).forEach((item) => buildModes.add(item));
    const profileDeclarations: Row[] = [];
    for (const item of rows(document.modules ?? app.modules)) {
      if (!item.srcPath) continue; const absolute = resolve(dirname(file), String(item.srcPath)); const moduleRoot = rel(absolute, root);
      if (moduleRoot.startsWith("../")) { diagnostics.push({ severity: "warning", kind: "external_module_path", file: rel(file, root), message: `module srcPath is outside repository: ${String(item.srcPath)}` }); continue; }
      const targets = rows(item.targets); const targetNames = targets.map((target) => String(target.name)).filter(Boolean).sort();
      const applied = [...new Set(targets.flatMap((target) => strings(target.applyToProducts)))].sort();
      const declaration: Row = { name: item.name ?? null, root: moduleRoot, src_path: item.srcPath, targets: targetNames, products: applied.length ? applied : productNames, build_profile: rel(file, root) };
      profileDeclarations.push(declaration); const previous = declarations.get(moduleRoot);
      declarations.set(moduleRoot, previous ? { ...previous, targets: [...new Set([...strings(previous.targets), ...targetNames])].sort(), products: [...new Set([...strings(previous.products), ...strings(declaration.products)])].sort() } : declaration);
    }
    buildProfiles.push({ file: rel(file, root), products: productNames, module_declarations: profileDeclarations });
  }

  const modules: Row[] = []; const allComponents: Row[] = []; const requestedPermissions: Row[] = []; const definedPermissions: Row[] = []; const discoveredRoots = new Set<string>();
  const moduleFiles = (byName.get("module.json5") ?? []).filter((file) => isProduction(rel(dirname(file), root)));
  if (!moduleFiles.length) diagnostics.push({ severity: "error", kind: "missing_config", file: null, message: "production module.json5 not found" });
  for (const file of moduleFiles) {
    const document = await load(file, "module"); if (!document) continue; const module = (document.module as Row | undefined) ?? document;
    const rootPath = moduleRoot(file); const moduleRootPath = rel(rootPath, root); discoveredRoots.add(moduleRootPath); const declaration = declarations.get(moduleRootPath);
    const included = !declarations.size || !!declaration; const name = String(module.name ?? declaration?.name ?? basename(rootPath)); const moduleId = stableId("MOD", moduleRootPath, name);
    const requestRows = array(module.requestPermissions).flatMap((item): Row[] => typeof item === "string" ? [{ name: item }] : item && typeof item === "object" ? [{ name: (item as Row).name ?? null, reason: (item as Row).reason ?? null, used_scene: (item as Row).usedScene ?? null }] : []);
    const defineRows = rows(module.definePermissions).filter((item) => item.name).map((item) => ({ name: item.name, grant_mode: item.grantMode ?? null, available_level: item.availableLevel ?? null, provision_enable: item.provisionEnable ?? null, distributed_scene_enable: item.distributedSceneEnable ?? null }));
    if (included) { requestedPermissions.push(...requestRows.filter((item) => item.name)); definedPermissions.push(...defineRows); }
    const componentIds: string[] = [];
    for (const [field, kind] of [["abilities", "ability"], ["extensionAbilities", "extension_ability"]] as const) {
      for (const [index, raw] of array(module[field]).entries()) {
        const item = raw && typeof raw === "object" ? raw as Row : {}; const componentId = stableId("CMP", moduleId, kind, item.name, item.srcEntry, index); componentIds.push(componentId);
        const extensionType = kind === "extension_ability" ? item.type ?? null : null; const scope = rel(dirname(file), root); const src = item.srcEntry ? String(item.srcEntry) : null;
        const permissions = [...new Set(["permissions", "permission", "readPermission", "writePermission"].flatMap((key) => strings(item[key])))].sort();
        allComponents.push({ component_id: componentId, module_id: moduleId, module_name: name, module_root: moduleRootPath, module_file: rel(file, root), kind, name: item.name ?? null, src_entry: src, source_scope: scope, source_file_hint: src ? `${scope}/${src.replace(/^\.\//, "")}` : null, extension_type: extensionType, exported: typeof item.exported === "boolean" ? item.exported : null, enabled: typeof item.enabled === "boolean" ? item.enabled : null, permissions, uri: item.uri ?? null, skills: rows(item.skills).map(normalizedSkill), lifecycle_candidates: lifecycle(kind, extensionType), included_in_build: included });
      }
    }
    modules.push({ module_id: moduleId, file: rel(file, root), root: moduleRootPath, name, build_name: declaration?.name ?? null, type: module.type ?? null, output_kind: outputKind(module.type), included_in_build: included, products: strings(declaration?.products), targets: strings(declaration?.targets), build_profile: declaration?.build_profile ?? null, src_entry: module.srcEntry ?? null, source_scope: rel(dirname(file), root), device_types: strings(module.deviceTypes), delivery_with_install: module.deliveryWithInstall ?? null, installation_free: module.installationFree ?? null, virtual_machine: module.virtualMachine ?? null, request_permissions: requestRows, defined_permissions: defineRows, component_ids: componentIds, package_name: null, dependency_ids: [] });
    if (!included) diagnostics.push({ severity: "warning", kind: "module_not_in_build", file: rel(file, root), message: `module root is not declared by a root build profile: ${moduleRootPath}` });
  }
  for (const [declaredRoot, declaration] of declarations) if (!discoveredRoots.has(declaredRoot)) diagnostics.push({ severity: "error", kind: "missing_module_manifest", file: declaration.build_profile, message: `declared module has no production module.json5: ${declaredRoot}` });

  const modulesByRoot = new Map(modules.map((module) => [String(module.root), module])); const packagesByName = new Map<string, Row>(); const packageDocs: [string, Row][] = [];
  for (const file of byName.get("oh-package.json5") ?? []) { const document = await load(file, "oh_package"); if (!document) continue; packageDocs.push([file, document]); const source = modulesByRoot.get(rel(dirname(file), root)); if (source && document.name) { source.package_name = document.name; packagesByName.set(String(document.name), source); } }
  const dependencies: Row[] = []; const moduleDependencies: Row[] = []; const seen = new Set<string>();
  for (const [file, document] of packageDocs) {
    const source = modulesByRoot.get(rel(dirname(file), root));
    for (const group of ["dependencies", "devDependencies", "dynamicDependencies"]) {
      const values = document[group]; if (!values || typeof values !== "object" || Array.isArray(values)) continue;
      for (const [name, version] of Object.entries(values as Row).sort(([left], [right]) => left.localeCompare(right))) {
        let target: Row | undefined; const reference = typeof version === "string" ? version : null;
        if (reference?.startsWith("file:")) target = modulesByRoot.get(rel(resolve(dirname(file), reference.slice(5)), root)); target ??= packagesByName.get(name);
        dependencies.push({ name, version, group, file: rel(file, root), source_module_id: source?.module_id ?? null, target_module_id: target?.module_id ?? null, local: !!source && !!target });
        if (!source || !target) continue; const edgeKey = contentHash([source.module_id, target.module_id, name, group]); if (seen.has(edgeKey)) continue; seen.add(edgeKey);
        const dependencyId = stableId("DEP", source.module_id, target.module_id, name, group); (source.dependency_ids as string[]).push(dependencyId);
        moduleDependencies.push({ dependency_id: dependencyId, source_module_id: source.module_id, target_module_id: target.module_id, name, group, reference: version, declaration_file: rel(file, root) });
      }
    }
  }
  const activeModules = modules.filter((module) => module.included_in_build); const activeIds = new Set(activeModules.map((module) => module.module_id)); const components = allComponents.filter((component) => activeIds.has(component.module_id));
  const entryCandidates = makeEntries(components);
  entryCandidates.push({
    candidate_id: stableId("PE", "project_scope", root), type: "project_scope", source: "project_model",
    component_id: stableId("PROJECT", root), component_name: "项目级审计", module_id: stableId("MOD", "project_scope", root),
    module_name: "project", module_root: ".", location: application?.file ?? ".", exported: null, permissions: [],
    src_entry: null, lifecycle_candidates: [], trigger_facts: { project_scope: true, requires_external_reachability_evidence: false },
  });
  let status: "complete" | "partial" | "failed" = diagnostics.some((item) => item.severity === "error") ? "partial" : "complete";
  const model: ProjectModel = { schema_version: 2, generated_at: new Date().toISOString(), target_repo: root, status,
    summary: { modules: activeModules.length, discovered_modules: modules.length, components: components.length, entry_candidates: entryCandidates.length, requested_permissions: new Set(requestedPermissions.map((item) => item.name)).size, defined_permissions: new Set(definedPermissions.map((item) => item.name)).size, dependencies: dependencies.length, module_dependencies: moduleDependencies.length, parse_errors: diagnostics.filter((item) => item.severity === "error").length },
    build: { scope: declarations.size ? "declared_modules" : "discovered_production_modules", product_scope: "union", products: [...products].sort(), build_modes: [...buildModes].sort(), declared_module_roots: [...declarations.keys()].sort() },
    application, modules, components, entry_candidates: entryCandidates, requested_permissions: requestedPermissions, defined_permissions: definedPermissions, dependencies, module_dependencies: moduleDependencies, build_profiles: buildProfiles, parsed_files: parsedFiles, diagnostics };
  const schema = JSON.parse(await readFile(new URL("../../resources/schemas/project-model.schema.json", import.meta.url), "utf8")); const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
  if (!validate(model)) { diagnostics.push({ severity: "error", kind: "schema_validation", file: null, message: new Ajv2020().errorsText(validate.errors) }); status = "failed"; (model as { status: string }).status = status; }
  return model;
}
