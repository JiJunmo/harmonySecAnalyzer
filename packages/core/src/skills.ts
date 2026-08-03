import { readFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import fg from "fast-glob";

export interface SkillDescriptor {
  readonly name: string;
  readonly description: string;
  readonly file: string;
  readonly orchestrators: readonly string[];
  readonly requiredTools: readonly string[];
  readonly body: string;
}

function list(value?: string): string[] {
  return (value ?? "").replace(/^\[|\]$/g, "").split(",").map((item) => item.trim().replace(/^['\"]|['\"]$/g, "")).filter(Boolean);
}

export async function discoverSkills(roots: readonly string[]): Promise<SkillDescriptor[]> {
  const files = new Set<string>();
  for (const root of roots) {
    for (const file of await fg(["SKILL.md", "*/SKILL.md"], { cwd: resolve(root), absolute: true })) files.add(file);
  }
  return Promise.all([...files].sort().map(async (file) => {
    const text = await readFile(file, "utf8");
    const match = /^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/.exec(text);
    const metadata: Record<string, string> = {};
    for (const line of (match?.[1] ?? "").split("\n")) {
      const separator = line.indexOf(":");
      if (separator > 0) metadata[line.slice(0, separator).trim()] = line.slice(separator + 1).trim().replace(/^['\"]|['\"]$/g, "");
    }
    const body = match?.[2] ?? text;
    const name = metadata.name ?? basename(dirname(file));
    return {
      name, file, body,
      description: metadata.description ?? body.split(/\n\s*\n/).find((part) => !part.trim().startsWith("#"))?.trim() ?? name,
      orchestrators: list(metadata.orchestrators),
      requiredTools: list(metadata.required_tools ?? metadata.tools),
    };
  }));
}

export class SkillRegistry {
  readonly #skills = new Map<string, SkillDescriptor>();
  register(skill: SkillDescriptor): this { this.#skills.set(skill.name, skill); return this; }
  get(name: string): SkillDescriptor {
    const skill = this.#skills.get(name);
    if (!skill) throw new Error(`skill_not_registered:${name}`);
    return skill;
  }
  forOrchestrator(name: string): SkillDescriptor[] { return [...this.#skills.values()].filter((skill) => skill.orchestrators.includes(name)); }
  list(): SkillDescriptor[] { return [...this.#skills.values()].sort((a, b) => a.name.localeCompare(b.name)); }
}

export class SkillManager {
  readonly #registry = new SkillRegistry();
  readonly #taskSkills = new Map<string, string>();
  async discover(roots: readonly string[]): Promise<this> {
    for (const skill of await discoverSkills(roots)) this.#registry.register(skill);
    return this;
  }
  register(skill: SkillDescriptor): this { this.#registry.register(skill); return this; }
  assign(taskKind: string, skillName: string): this { this.#registry.get(skillName); this.#taskSkills.set(taskKind, skillName); return this; }
  activate(taskKind: string, availableTools: readonly string[]): SkillDescriptor {
    const name = this.#taskSkills.get(taskKind); if (!name) throw new Error(`skill_not_assigned:${taskKind}`);
    const skill = this.#registry.get(name); const available = new Set(availableTools);
    const missing = skill.requiredTools.filter((tool) => !available.has(tool));
    if (missing.length) throw new Error(`skill_required_tools_missing:${name}:${missing.join(",")}`);
    return skill;
  }
  list(): SkillDescriptor[] { return this.#registry.list(); }
}
