import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { execa } from "execa";
import fg from "fast-glob";
import type { ProjectModel } from "./project/profiler.js";
import { canonicalJson, contentHash } from "./runtime/identity.js";

type Row = Record<string, unknown>;

export const INCREMENTAL_BASELINE_SCHEMA_VERSION = 1;
export const INCREMENTAL_BASELINE_DIRECTORY = "incremental-baseline";

const ignored = [
  "**/.git/**", "**/.atlas/**", "**/.idea/**", "**/.vscode/**", "**/node_modules/**", "**/oh_modules/**",
  "**/build/**", "**/outputs/**", "**/reports/**", "**/coverage/**", "**/.hvigor/**", "**/test/**", "**/ohosTest/**",
];
const trackedSuffixes = new Set([".ets", ".ts", ".js", ".json5", ".json", ".yaml", ".yml"]);
const trackedNames = new Set(["hvigorfile.ts", "oh-package-lock.json5"]);
const configNames = new Set(["app.json5", "module.json5", "build-profile.json5", "oh-package.json5"]);

export interface FileManifestEntry { readonly sha256: string; readonly size: number; }
export type FileManifest = Readonly<Record<string, FileManifestEntry>>;

export interface IncrementalBaseline {
  readonly metadata: Row;
  readonly projectModel: ProjectModel;
  readonly semanticResults: Readonly<Record<string, Row>>;
  readonly validationResults: Row;
  readonly findings: readonly Row[];
  readonly pocs: readonly Row[];
}

export interface IncrementalPlan {
  readonly baseline: IncrementalBaseline;
  readonly currentManifest: FileManifest;
  readonly currentGit: Row | null;
  readonly changeSet: Row;
  readonly impactPlan: Row;
}

export interface IncrementalRunFiles {
  readonly root: string;
  readonly changeSet: string;
  readonly impactPlan: string;
  readonly baselineSemantics: string;
  readonly baselineValidations: string;
  readonly baselineFindings: string;
  readonly baselinePocs: string;
}

export function incrementalRunFiles(runDirectory: string): IncrementalRunFiles {
  const root = resolve(runDirectory, "incremental");
  return {
    root,
    changeSet: join(root, "change-set.json"),
    impactPlan: join(root, "impact-plan.json"),
    baselineSemantics: join(root, "baseline-semantic-results.json"),
    baselineValidations: join(root, "baseline-validation-results.json"),
    baselineFindings: join(root, "baseline-findings.json"),
    baselinePocs: join(root, "baseline-poc-results.json"),
  };
}

export function incrementalBaselineFiles(targetRepository: string) {
  const root = resolve(targetRepository, "reports", INCREMENTAL_BASELINE_DIRECTORY);
  return {
    root,
    metadata: join(root, "baseline.json"),
    projectModel: join(root, "project-model.json"),
    semanticResults: join(root, "semantic-results.json"),
    validationResults: join(root, "validation-results.json"),
    findings: join(root, "findings.json"),
    pocs: join(root, "poc-results.json"),
  };
}

async function jsonFile(path: string, fallback?: unknown): Promise<any> {
  try { return JSON.parse(await readFile(path, "utf8")); }
  catch (error) {
    if (fallback !== undefined && (error as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw error;
  }
}

async function writeJsonAtomic(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await rename(temporary, path);
}

function extension(path: string): string {
  const name = basename(path); const index = name.lastIndexOf(".");
  return index >= 0 ? name.slice(index).toLowerCase() : "";
}

export async function fileManifest(targetRepository: string): Promise<FileManifest> {
  const root = resolve(targetRepository);
  const files = (await fg(["**/*"], { cwd: root, absolute: true, onlyFiles: true, dot: true, ignore: ignored, followSymbolicLinks: false })).sort();
  const manifest: Record<string, FileManifestEntry> = {};
  for (const file of files) {
    const name = basename(file);
    if (!trackedNames.has(name) && !trackedSuffixes.has(extension(file))) continue;
    const metadata = await lstat(file).catch(() => undefined);
    if (!metadata?.isFile() || metadata.isSymbolicLink()) continue;
    const body = await readFile(file).catch(() => undefined);
    if (!body) continue;
    const path = relative(root, file).replaceAll("\\", "/");
    manifest[path] = { sha256: createHash("sha256").update(body).digest("hex"), size: metadata.size };
  }
  return Object.freeze(manifest);
}

async function git(targetRepository: string, args: readonly string[]) {
  return execa("git", ["-C", resolve(targetRepository), ...args], { reject: false });
}

export async function gitState(targetRepository: string): Promise<Row | null> {
  const root = resolve(targetRepository);
  const top = await git(root, ["rev-parse", "--show-toplevel"]);
  if (top.exitCode !== 0) return null;
  const gitRoot = resolve(top.stdout.trim());
  const head = await git(root, ["rev-parse", "HEAD"]);
  if (head.exitCode !== 0) return null;
  const prefix = relative(gitRoot, root).replaceAll("\\", "/");
  if (prefix.startsWith("../")) return null;
  const status = await git(root, ["status", "--porcelain=v1", "--untracked-files=normal", "--", ".", ":(exclude)reports/**", ":(exclude).atlas/**"]);
  return { root: gitRoot, target_prefix: prefix === "." ? "" : prefix, commit: head.stdout.trim(), dirty: Boolean(status.stdout.trim()) };
}

async function gitRange(targetRepository: string, baseline: Row | null, current: Row | null): Promise<Row | null> {
  if (!baseline || !current) return null;
  if (baseline.root !== current.root) throw new Error("git_repository_changed_full_audit_required");
  const base = String(baseline.commit ?? ""); const head = String(current.commit ?? "");
  const ancestor = await git(targetRepository, ["merge-base", "--is-ancestor", base, head]);
  if (ancestor.exitCode !== 0) throw new Error("git_baseline_not_ancestor_full_audit_required");
  const args = ["diff", "--name-status", "-M", `${base}..${head}`];
  if (current.target_prefix) args.push("--", String(current.target_prefix));
  const result = await git(targetRepository, args);
  if (result.exitCode !== 0) throw new Error(`git_command_failed:${result.stderr.trim() || "unknown"}`);
  const commitChanges = result.stdout.split("\n").filter(Boolean).map((line) => {
    const parts = line.split("\t");
    return { status: parts[0], path: parts.at(-1), ...(parts[0]?.startsWith("R") && parts.length >= 3 ? { old_path: parts.at(-2) } : {}) };
  });
  return { base_commit: base, target_commit: head, commit_changes: commitChanges };
}

export async function auditContractHash(): Promise<string> {
  const files = [
    new URL("../resources/audit_capabilities.json", import.meta.url),
    new URL("../resources/schemas/component-semantic-result.schema.json", import.meta.url),
    new URL("../resources/schemas/exploitability-validation-result.schema.json", import.meta.url),
    new URL("../resources/schemas/poc-result.schema.json", import.meta.url),
    new URL("../resources/skills/harmony-component-analysis/SKILL.md", import.meta.url),
    new URL("../resources/skills/harmony-exploitability-validation/SKILL.md", import.meta.url),
    new URL("../resources/skills/harmony-poc-generation/SKILL.md", import.meta.url),
  ];
  const digest = createHash("sha256");
  for (const file of files) { digest.update(basename(file.pathname)); digest.update(await readFile(file)); }
  return digest.digest("hex");
}

export async function loadIncrementalBaseline(targetRepository: string): Promise<IncrementalBaseline | null> {
  const files = incrementalBaselineFiles(targetRepository);
  const metadata = await jsonFile(files.metadata, null) as Row | null;
  const projectModel = await jsonFile(files.projectModel, null) as ProjectModel | null;
  const semanticResults = await jsonFile(files.semanticResults, null) as Record<string, Row> | null;
  const validationResults = await jsonFile(files.validationResults, null) as Row | null;
  if (!metadata || metadata.schema_version !== INCREMENTAL_BASELINE_SCHEMA_VERSION || !projectModel || projectModel.status !== "complete" || !semanticResults) return null;
  if (!validationResults || validationResults.schema_version !== 1 || typeof validationResults.entries !== "object") throw new Error("incremental_validation_baseline_missing_full_audit_required");
  const findingDocument = await jsonFile(files.findings, { schema_version: 1, items: [] }) as Row;
  const pocDocument = await jsonFile(files.pocs, { schema_version: 1, items: [] }) as Row;
  return { metadata, projectModel, semanticResults, validationResults, findings: Array.isArray(findingDocument.items) ? findingDocument.items as Row[] : [], pocs: Array.isArray(pocDocument.items) ? pocDocument.items as Row[] : [] };
}

export function projectEntryGroups(model: ProjectModel): Readonly<Record<string, Row>> {
  const groups = new Map<string, Row[]>();
  for (const candidate of model.entry_candidates) {
    const componentId = String(candidate.component_id ?? candidate.candidate_id);
    groups.set(componentId, [...(groups.get(componentId) ?? []), candidate]);
  }
  return Object.fromEntries([...groups].sort(([left], [right]) => left.localeCompare(right)).map(([componentId, candidates]) => [
    `component:${componentId}`,
    { entry_key: `component:${componentId}`, component_id: componentId, module_id: candidates[0]?.module_id, module_root: candidates[0]?.module_root, candidates },
  ]));
}

function manifestChanges(previous: FileManifest, current: FileManifest): Row {
  const before = new Set(Object.keys(previous)); const after = new Set(Object.keys(current));
  return {
    added: [...after].filter((path) => !before.has(path)).sort(),
    modified: [...after].filter((path) => before.has(path) && previous[path]!.sha256 !== current[path]!.sha256).sort(),
    deleted: [...before].filter((path) => !after.has(path)).sort(),
  };
}

function inRoot(path: string, root: unknown): boolean {
  const normalized = path.replace(/^\/+|\/+$/g, ""); const base = String(root ?? ".").replace(/^\/+|\/+$/g, "");
  return !base || base === "." || normalized === base || normalized.startsWith(`${base}/`);
}

function moduleConfiguration(module: Row | undefined): Row | undefined {
  if (!module) return undefined;
  return Object.fromEntries(Object.entries(module).filter(([key]) => !["module_id", "component_ids"].includes(key)));
}

function componentSources(model: ProjectModel): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const component of model.components) {
    const path = String(component.source_file_hint ?? "").replace(/^\/+/, ""); const id = String(component.component_id ?? "");
    if (path && id) result.set(path, new Set([...(result.get(path) ?? []), id]));
  }
  return result;
}

function moduleImpacts(changedFiles: readonly string[], previous: ProjectModel, current: ProjectModel) {
  const currentModules = new Map(current.modules.map((row) => [String(row.module_id), row]));
  const previousModules = new Map(previous.modules.map((row) => [String(row.module_id), row]));
  const currentByFile = new Map(current.modules.filter((row) => row.file).map((row) => [String(row.file), row]));
  const previousByFile = new Map(previous.modules.filter((row) => row.file).map((row) => [String(row.file), row]));
  const sources = componentSources(previous);
  for (const [path, ids] of componentSources(current)) sources.set(path, new Set([...(sources.get(path) ?? []), ...ids]));
  const affectedModules = new Set<string>(); const affectedComponents = new Set<string>(); let globalChange = false;
  const allModules = [...current.modules, ...previous.modules];
  for (const path of changedFiles) {
    const direct = sources.get(path);
    if (direct) { direct.forEach((id) => affectedComponents.add(id)); continue; }
    if (basename(path) === "module.json5") {
      const before = previousByFile.get(path); const after = currentByFile.get(path);
      if (before && after) {
        if (canonicalJson(moduleConfiguration(before)) !== canonicalJson(moduleConfiguration(after))) affectedModules.add(String(after.module_id));
        continue;
      }
    }
    const matches = allModules.filter((row) => inRoot(path, row.root));
    if (configNames.has(basename(path)) && !matches.length) globalChange = true;
    else if (matches.length) {
      const deepest = Math.max(...matches.map((row) => String(row.root ?? "").length));
      matches.filter((row) => String(row.root ?? "").length === deepest).forEach((row) => affectedModules.add(String(row.module_id)));
    } else globalChange = true;
  }
  if (globalChange) currentModules.forEach((_row, id) => affectedModules.add(id));
  const reverse = new Map<string, Set<string>>();
  for (const model of [previous, current]) for (const edge of model.module_dependencies) {
    const target = String(edge.target_module_id ?? ""); const source = String(edge.source_module_id ?? "");
    if (target && source) reverse.set(target, new Set([...(reverse.get(target) ?? []), source]));
  }
  const queue = [...affectedModules];
  while (queue.length) for (const source of reverse.get(queue.shift()!) ?? []) if (!affectedModules.has(source)) { affectedModules.add(source); queue.push(source); }
  return { affectedModules, affectedComponents, globalChange };
}

export async function planIncremental(targetRepository: string, currentModel: ProjectModel): Promise<IncrementalPlan> {
  const baseline = await loadIncrementalBaseline(targetRepository);
  if (!baseline) throw new Error("incremental_baseline_missing_run_full_audit_first");
  if (baseline.metadata.audit_contract_hash !== await auditContractHash()) throw new Error("audit_contract_changed_full_audit_required");
  const currentManifest = await fileManifest(targetRepository);
  const changes = manifestChanges((baseline.metadata.file_manifest ?? {}) as FileManifest, currentManifest);
  const changedFiles = [...new Set([...(changes.added as string[]), ...(changes.modified as string[]), ...(changes.deleted as string[])])].sort();
  const currentGit = await gitState(targetRepository); const currentType = currentGit ? "git" : "snapshot";
  if (baseline.metadata.source_type !== currentType) throw new Error("baseline_source_type_changed_full_audit_required");
  const range = await gitRange(targetRepository, (baseline.metadata.git as Row | null) ?? null, currentGit);
  const previousEntries = projectEntryGroups(baseline.projectModel); const currentEntries = projectEntryGroups(currentModel);
  const previousKeys = new Set(Object.keys(previousEntries)); const currentKeys = new Set(Object.keys(currentEntries));
  const addedEntries = [...currentKeys].filter((key) => !previousKeys.has(key)).sort();
  const deletedEntries = [...previousKeys].filter((key) => !currentKeys.has(key)).sort();
  const changedEntries = [...currentKeys].filter((key) => previousKeys.has(key) && canonicalJson(previousEntries[key]!.candidates) !== canonicalJson(currentEntries[key]!.candidates)).sort();
  const impacts = moduleImpacts(changedFiles, baseline.projectModel, currentModel);
  const reasons: Record<string, string[]> = Object.fromEntries([...currentKeys].map((key) => [key, []]));
  for (const key of addedEntries) reasons[key]!.push("new_entry");
  for (const key of changedEntries) reasons[key]!.push("entry_definition_changed");
  for (const [key, entry] of Object.entries(currentEntries)) {
    if (changedFiles.length && (entry.candidates as Row[]).some((candidate) => candidate.type === "project_scope")) reasons[key]!.push("project_file_changed");
    if (impacts.affectedModules.has(String(entry.module_id))) reasons[key]!.push("module_source_or_dependency_changed");
    if (impacts.affectedComponents.has(String(entry.component_id))) reasons[key]!.push("component_source_changed");
    if (!baseline.semanticResults[key]) reasons[key]!.push("baseline_semantics_missing");
  }
  const deletedComponents = new Set(deletedEntries.map((key) => String(previousEntries[key]?.component_id ?? "")).filter(Boolean));
  if (deletedComponents.size) for (const [key, snapshot] of Object.entries(baseline.semanticResults)) {
    if (!currentKeys.has(key)) continue;
    const result = (snapshot.result ?? {}) as Row;
    if ((Array.isArray(result.component_calls) ? result.component_calls as Row[] : []).some((call) => deletedComponents.has(String(call.target_component_id)))) reasons[key]!.push("called_component_deleted");
  }
  const affectedEntries = Object.keys(reasons).filter((key) => reasons[key]!.length).sort();
  const reusableEntries = [...currentKeys].filter((key) => !affectedEntries.includes(key)).sort();
  const generatedAt = new Date().toISOString();
  return {
    baseline, currentManifest, currentGit,
    changeSet: { schema_version: 1, source_type: currentType, baseline_run_id: baseline.metadata.run_id, baseline_completed_at: baseline.metadata.completed_at, generated_at: generatedAt, files: changes, changed_file_count: changedFiles.length, git: range, working_tree_dirty: Boolean(currentGit?.dirty) },
    impactPlan: { schema_version: 1, generated_at: generatedAt, added_entries: addedEntries, deleted_entries: deletedEntries, changed_entries: changedEntries, affected_entries: affectedEntries, reusable_entries: reusableEntries, affected_modules: [...impacts.affectedModules].sort(), affected_components: [...impacts.affectedComponents].sort(), global_change: impacts.globalChange, reasons: Object.fromEntries(Object.entries(reasons).filter(([, values]) => values.length).map(([key, values]) => [key, [...new Set(values)].sort()])) },
  };
}

export async function persistIncrementalPlan(runDirectory: string, plan: IncrementalPlan): Promise<void> {
  const files = incrementalRunFiles(runDirectory); await mkdir(files.root, { recursive: true });
  await Promise.all([
    writeJsonAtomic(files.changeSet, plan.changeSet), writeJsonAtomic(files.impactPlan, plan.impactPlan),
    writeJsonAtomic(files.baselineSemantics, plan.baseline.semanticResults), writeJsonAtomic(files.baselineValidations, plan.baseline.validationResults),
    writeJsonAtomic(files.baselineFindings, { schema_version: 1, items: plan.baseline.findings }),
    writeJsonAtomic(files.baselinePocs, { schema_version: 1, items: plan.baseline.pocs }),
  ]);
}

function stableGroup(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableGroup);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Row)
    .filter(([key]) => !["group_id", "producer_task_ids"].includes(key))
    .map(([key, item]) => [key, stableGroup(item)]));
}

export function validationGroupFingerprint(group: Row): string { return contentHash(stableGroup(group)); }

function riskSnapshot(report: Row): Row[] {
  const groups = new Map((Array.isArray(report.operation_groups) ? report.operation_groups as Row[] : []).map((group) => [String(group.group_id), group]));
  return (Array.isArray(report.findings) ? report.findings as Row[] : []).map((finding) => {
    const group = groups.get(String(finding.root_cause_key));
    return { ...finding, risk_key: contentHash(stableGroup(group?.payload ?? group ?? finding.root_cause_key)) };
  }).sort((left, right) => String(left.risk_key).localeCompare(String(right.risk_key)));
}

export async function attachIncrementalReport(runDirectory: string, report: Row): Promise<Row> {
  const scope = ((report.run as Row | undefined)?.audit_scope as Row | undefined) ?? {};
  if (scope.mode !== "incremental") return report;
  const files = incrementalRunFiles(runDirectory);
  const changeSet = await jsonFile(files.changeSet, {}); const impactPlan = await jsonFile(files.impactPlan, {});
  const baseline = await jsonFile(files.baselineFindings, { items: [] }) as Row;
  const previous = new Map((Array.isArray(baseline.items) ? baseline.items as Row[] : []).map((item) => [String(item.risk_key), item]));
  const currentRows = riskSnapshot(report); const current = new Map(currentRows.map((item) => [String(item.risk_key), item]));
  const comparisonKeys = ["classification", "title", "severity", "cwe", "impact"];
  const terminal = ["complete", "complete_with_gaps"].includes(String((report.run as Row | undefined)?.status));
  const changes: Row = { status: terminal ? "complete" : "pending", added: [], removed: [], changed: [], unchanged: [] };
  if (!terminal) {
    const run = report.run as Row;
    return { ...report, run: { ...run, incremental: { change_set: changeSet, impact_plan: impactPlan, risk_path_changes: changes } } };
  }
  for (const key of [...current.keys()].filter((key) => !previous.has(key)).sort()) (changes.added as Row[]).push(current.get(key)!);
  for (const key of [...previous.keys()].filter((key) => !current.has(key)).sort()) (changes.removed as Row[]).push(previous.get(key)!);
  for (const key of [...current.keys()].filter((key) => previous.has(key)).sort()) {
    const before = previous.get(key)!; const after = current.get(key)!;
    const same = comparisonKeys.every((field) => canonicalJson(before[field]) === canonicalJson(after[field]));
    ((changes[same ? "unchanged" : "changed"] as Row[])).push(after);
  }
  const run = report.run as Row;
  return { ...report, run: { ...run, incremental: { change_set: changeSet, impact_plan: impactPlan, risk_path_changes: changes } } };
}

export async function saveIncrementalBaseline(runDirectory: string, report: Row): Promise<Row> {
  const db = new Database(resolve(runDirectory, "run.db"), { readonly: true });
  try {
    const run = db.prepare("SELECT run_id,target_repo,status,audit_scope_json FROM runs").get() as { run_id: string; target_repo: string; status: string; audit_scope_json: string };
    const scope = JSON.parse(run.audit_scope_json) as Row;
    if (!["full", "incremental"].includes(String(scope.mode ?? "full")) || (Array.isArray(scope.components) && scope.components.length) || run.status !== "complete") return { updated: false, reason: run.status !== "complete" ? "run_has_coverage_gaps" : "filtered_audit" };
    const semanticResults: Record<string, Row> = {};
    const semantics = db.prepare(`SELECT e.candidate_key,t.result_json FROM entries e JOIN tasks t ON t.subject_id=e.entry_id AND t.kind='component_semantic_analysis' WHERE t.status='completed' ORDER BY e.candidate_key`).all() as { candidate_key: string; result_json: string }[];
    for (const row of semantics) semanticResults[row.candidate_key] = { result: JSON.parse(row.result_json) };
    const validationEntries: Record<string, Row> = {};
    const validations = db.prepare(`SELECT e.candidate_key,t.input_json,t.result_json FROM entries e JOIN tasks t ON t.subject_id=e.entry_id AND t.kind='exploitability_validation' WHERE t.status='completed' ORDER BY e.candidate_key`).all() as { candidate_key: string; input_json: string; result_json: string }[];
    for (const row of validations) {
      const input = JSON.parse(row.input_json) as Row; const groups = Array.isArray(input.operation_groups) ? input.operation_groups as Row[] : [];
      validationEntries[row.candidate_key] = { group_fingerprints: Object.fromEntries(groups.map((group) => [String(group.group_id), validationGroupFingerprint(group)])), result: JSON.parse(row.result_json) };
    }
    const target = resolve(run.target_repo); const model = await jsonFile(resolve(runDirectory, "project-model.json")) as ProjectModel;
    const currentGit = await gitState(target); const manifest = await fileManifest(target); const findings = riskSnapshot(report);
    // Baseline snapshots store the raw accepted submission (tasks.result_json) so a
    // reused snapshot passes the current model-facing schema; poc_artifacts.payload_json
    // is the materialized shape and would fail it.
    const pocs = (db.prepare(`SELECT p.finding_id,f.root_cause_key,p.entry_type,t.result_json FROM poc_artifacts p
      JOIN findings f ON f.finding_id=p.finding_id
      JOIN tasks t ON t.subject_id=p.finding_id AND t.kind='poc_generation' AND t.status='completed'
      ORDER BY p.poc_id`).all() as { finding_id: string; root_cause_key: string; entry_type: string; result_json: string }[]).map((row) => {
      const group = db.prepare("SELECT payload_json FROM operation_groups WHERE group_id=?").get(row.root_cause_key) as { payload_json: string } | undefined;
      return { finding_id: row.finding_id, root_cause_key: row.root_cause_key, group_fingerprint: group ? validationGroupFingerprint(JSON.parse(group.payload_json)) : "", entry_type: row.entry_type, result: JSON.parse(row.result_json) };
    });
    const metadata = { schema_version: INCREMENTAL_BASELINE_SCHEMA_VERSION, run_id: run.run_id, completed_at: new Date().toISOString(), source_type: currentGit ? "git" : "snapshot", git: currentGit, file_manifest: manifest, semantic_results: Object.keys(semanticResults).length, validation_results: Object.keys(validationEntries).length, audit_contract_hash: await auditContractHash(), findings: findings.length, pocs: pocs.length };
    const files = incrementalBaselineFiles(target); await mkdir(files.root, { recursive: true });
    await Promise.all([
      writeJsonAtomic(files.projectModel, model), writeJsonAtomic(files.semanticResults, semanticResults),
      writeJsonAtomic(files.validationResults, { schema_version: 1, entries: validationEntries }),
      writeJsonAtomic(files.findings, { schema_version: 1, items: findings }),
      writeJsonAtomic(files.pocs, { schema_version: 1, items: pocs }),
    ]);
    // Metadata is the commit marker. Readers never observe a new baseline until
    // all fact snapshots have been replaced successfully.
    await writeJsonAtomic(files.metadata, metadata);
    return { updated: true, path: files.metadata, source_type: metadata.source_type };
  } finally { db.close(); }
}
