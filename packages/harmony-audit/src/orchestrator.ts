import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  GraphApplication, GraphRegistry, McpManager, PiSessionFactory, SkillManager,
  type McpPolicyConfig, type SkillConfigDocument,
  type Orchestrator, type OrchestratorContext,
} from "@agent-platform/core";
import { AtlasProfile, prepareAtlasIndex, SEMANTIC_TOOLS, VALIDATION_TOOLS } from "./atlas.js";
import { resolveCapabilities } from "./capabilities.js";
import { HarmonyAuditGraphPlugin } from "./graph.js";
import { planIncremental } from "./incremental.js";
import { HarmonyPoolBackend } from "./pool-backend.js";
import { HARMONY_DEFAULT_AGENT_CAPACITY, harmonyAgentCapacity } from "./pool-policy.js";
import { profileProject, selectComponents } from "./project/profiler.js";
import { AuditStore } from "./runtime/store.js";
import { HarmonyAuditWorker } from "./worker.js";

export interface HarmonyAuditOptions {
  readonly atlasExecutable: string; readonly capacity?: number; readonly model?: string;
  readonly piAgentDir?: string; readonly piCwd?: string; readonly mcp?: McpPolicyConfig; readonly skills?: SkillConfigDocument;
  readonly onRunCreated?: (run: { readonly runId: string; readonly runDirectory: string; readonly target: string }) => void;
}

export async function createHarmonyAuditSessions(options: HarmonyAuditOptions): Promise<PiSessionFactory> {
  const sessions = await PiSessionFactory.create({
    ...(options.piAgentDir ? { agentDir: options.piAgentDir } : {}),
    cwd: options.piCwd ?? process.cwd(),
  });
  sessions.models.resolve(options.model);
  return sessions;
}

export async function createHarmonyAuditSkills(options: HarmonyAuditOptions): Promise<SkillManager> {
  const bundledRoot = fileURLToPath(new URL("../resources/skills", import.meta.url));
  const skills = await new SkillManager().discover([bundledRoot, ...(options.skills?.roots ?? [])]);
  const assignments = { component_semantic_analysis: "harmony-component-analysis", exploitability_validation: "harmony-exploitability-validation", ...(options.skills?.tasks ?? {}) };
  for (const [task, skill] of Object.entries(assignments)) skills.assign(task, skill);
  skills.activate("component_semantic_analysis", SEMANTIC_TOOLS);
  skills.activate("exploitability_validation", VALIDATION_TOOLS);
  return skills;
}

export class HarmonyAuditOrchestrator implements Orchestrator {
  readonly name = "harmony-audit";
  constructor(readonly options: HarmonyAuditOptions) { harmonyAgentCapacity(options.capacity); }
  matches(request: { prompt: string }): boolean { return /^\s*\/audit\b/.test(request.prompt) || /鸿蒙|HarmonyOS|ArkTS/i.test(request.prompt); }

  async run(context: OrchestratorContext): Promise<unknown> {
    const target = resolve(String(context.request.metadata?.target ?? context.request.cwd));
    const sessions = await createHarmonyAuditSessions(this.options);
    const skills = await createHarmonyAuditSkills(this.options);
    const model = await profileProject(target);
    if (model.status !== "complete") throw new Error(`project_model_incomplete:${JSON.stringify(model.diagnostics)}`);
    const atlas = new AtlasProfile(this.options.atlasExecutable);
    await atlas.validate();
    const index = await prepareAtlasIndex(target, atlas);
    if (!index.ok) throw new Error(`atlas_index_not_ready:${JSON.stringify(index)}`);
    const requestedCapabilities = (context.request.metadata?.capabilities as string[] | undefined) ?? [];
    const incremental = context.request.metadata?.incremental === true;
    const requestedComponents = (context.request.metadata?.components as string[] | undefined) ?? [];
    if (incremental && (requestedCapabilities.length || requestedComponents.length)) throw new Error("incremental_mode_cannot_filter_scope");
    const capabilities = await resolveCapabilities(requestedCapabilities);
    const components = selectComponents(model, requestedComponents);
    const incrementalPlan = incremental ? await planIncremental(target, model) : undefined;
    const store = await AuditStore.create(target, model, { mode: incremental ? "incremental" : requestedCapabilities.length ? "capability" : "full", capabilities, components }, incrementalPlan);
    this.options.onRunCreated?.({ runId: store.runId(), runDirectory: store.runDirectory, target });
    return this.runStore(store, atlas, sessions, skills);
  }

  async resume(runDirectory: string): Promise<unknown> {
    const store = AuditStore.openExisting(runDirectory); const state = store.status(); const run = state.run as Record<string, unknown>;
    const sessions = await createHarmonyAuditSessions(this.options);
    const skills = await createHarmonyAuditSkills(this.options);
    const atlas = new AtlasProfile(this.options.atlasExecutable); await atlas.validate();
    const index = await prepareAtlasIndex(String(run.target_repo), atlas); if (!index.ok) throw new Error(`atlas_index_not_ready:${JSON.stringify(index)}`);
    const recovery = store.resume(); const result = await this.runStore(store, atlas, sessions, skills);
    return { recovery, ...(result as Record<string, unknown>) };
  }

  private async runStore(store: AuditStore, atlas: AtlasProfile, sessions: PiSessionFactory, skills: SkillManager): Promise<unknown> {
    const runCapacity = harmonyAgentCapacity(this.options.capacity ?? HARMONY_DEFAULT_AGENT_CAPACITY);
    const mcp = new McpManager({ maxSessions: runCapacity, ...this.options.mcp });
    const worker = new HarmonyAuditWorker(sessions, mcp, skills, atlas, store, this.options.model);
    const backend = new HarmonyPoolBackend(store, worker);
    const registry = new GraphRegistry().register(new HarmonyAuditGraphPlugin(store, backend, runCapacity));
    try {
      const result = await new GraphApplication(registry).run("harmony-audit", store.runDirectory);
      return { runDirectory: store.runDirectory, result };
    } finally { await mcp.close(); }
  }
}
