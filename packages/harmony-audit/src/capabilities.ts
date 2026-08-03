import { readFile } from "node:fs/promises";

export interface Capability {
  readonly capability_id: string; readonly status: string; readonly title?: string; readonly domain?: string;
  readonly entry_types?: readonly string[]; readonly analysis_scope?: "component" | "project"; readonly guidance?: readonly string[];
}

export async function listCapabilities(): Promise<Capability[]> {
  const document = JSON.parse(await readFile(new URL("../resources/audit_capabilities.json", import.meta.url), "utf8")) as { capabilities: Capability[] };
  return document.capabilities.map((item) => Object.freeze({ ...item })).sort((a, b) => a.capability_id.localeCompare(b.capability_id));
}

export async function resolveCapabilities(requested: readonly string[]): Promise<string[]> {
  const enabled = new Set((await listCapabilities()).filter((item) => item.status === "enabled").map((item) => item.capability_id));
  if (!requested.length) return [...enabled];
  for (const id of requested) if (!enabled.has(id)) throw new Error(`capability_not_enabled:${id}`);
  return [...new Set(requested)];
}
