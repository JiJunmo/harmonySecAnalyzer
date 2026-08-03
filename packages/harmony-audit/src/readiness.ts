import { AtlasProfile } from "./atlas.js";
import { createHarmonyAuditSessions, createHarmonyAuditSkills, type HarmonyAuditOptions } from "./orchestrator.js";

export interface HarmonyAuditReadinessCheck {
  readonly id: "atlas" | "model" | "skills";
  readonly ok: boolean;
  readonly message: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface HarmonyAuditReadiness {
  readonly ready: boolean;
  readonly checks: readonly HarmonyAuditReadinessCheck[];
  readonly defaults: Readonly<{ capacity: number; model: string }>;
}

const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);

async function inspect(id: HarmonyAuditReadinessCheck["id"], action: () => Promise<Readonly<Record<string, unknown>>>): Promise<HarmonyAuditReadinessCheck> {
  try {
    const details = await action();
    return Object.freeze({ id, ok: true, message: `${id}_ready`, details: Object.freeze({ ...details }) });
  } catch (error) {
    return Object.freeze({ id, ok: false, message: errorMessage(error) });
  }
}

export async function inspectHarmonyAuditReadiness(options: HarmonyAuditOptions): Promise<HarmonyAuditReadiness> {
  const checks = await Promise.all([
    inspect("atlas", async () => {
      await new AtlasProfile(options.atlasExecutable).validate();
      return { executable: options.atlasExecutable };
    }),
    inspect("model", async () => {
      const sessions = await createHarmonyAuditSessions(options);
      return {
        selected: options.model ?? sessions.models.defaultAlias,
        available: sessions.models.aliases,
      };
    }),
    inspect("skills", async () => {
      const skills = await createHarmonyAuditSkills(options);
      return { loaded: skills.list().map((skill) => skill.name) };
    }),
  ]);
  const model = checks.find((check) => check.id === "model")?.details?.selected;
  return Object.freeze({
    ready: checks.every((check) => check.ok),
    checks: Object.freeze(checks),
    defaults: Object.freeze({ capacity: options.capacity ?? 5, model: typeof model === "string" ? model : options.model ?? "unavailable" }),
  });
}
