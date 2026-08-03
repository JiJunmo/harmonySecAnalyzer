import { type ChildExecutionResult, type McpManager, type PiSessionFactory, type SkillManager, type SubAgentInstance } from "@agent-platform/core";
import { AtlasProfile, SEMANTIC_TOOLS, VALIDATION_TOOLS } from "./atlas.js";
import type { AuditStore } from "./runtime/store.js";

export class HarmonyAuditWorker {
  readonly #submissions = new Map<string, Record<string, unknown>>();
  constructor(readonly sessions: PiSessionFactory, readonly mcp: McpManager, readonly skills: SkillManager, readonly atlas: AtlasProfile, readonly store: AuditStore, readonly modelOverride?: string) {}

  take(agentId: string): Record<string, unknown> | undefined { const result = this.#submissions.get(agentId); this.#submissions.delete(agentId); return result; }

  async execute(instance: SubAgentInstance): Promise<ChildExecutionResult> {
    const task = await this.store.taskDocument(instance.handle);
    const input = task.input as Record<string, unknown>;
    const target = instance.kind === "component_semantic_analysis" ? String(input.target_repo) : String((input.verification_scope as Record<string, unknown>).target_repo);
    const tools = instance.kind === "component_semantic_analysis" ? SEMANTIC_TOOLS : VALIDATION_TOOLS;
    const skill = this.skills.activate(instance.kind, tools);
    const session = await this.mcp.connect("atlas", this.atlas.mcpServer(target, tools));
    try {
      const result = await this.sessions.runStructured<Record<string, unknown>>({
        cwd: target,
        systemPrompt: skill.body,
        task,
        tools: await session.tools(),
        outputSchema: task.result_schema as object,
        taskKind: instance.kind,
        ...(this.modelOverride ? { model: this.modelOverride } : {}),
        submissionToolName: "submit_audit_result",
        trace: (event) => this.store.appendTaskTrace(instance.taskId, instance.attempt, event),
      });
      this.#submissions.set(instance.agentId, result);
      return { instance, status: "completed" };
    } finally { await session.close(); }
  }
}
