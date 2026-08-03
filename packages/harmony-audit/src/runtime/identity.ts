import { createHash } from "node:crypto";

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

export function canonicalJson(value: unknown): string { return JSON.stringify(canonical(value)); }
export function contentHash(value: unknown): string { return createHash("sha256").update(typeof value === "string" ? value : canonicalJson(value)).digest("hex"); }
export function stableId(prefix: string, ...identity: unknown[]): string { return `${prefix}-${contentHash(identity).slice(0, 16)}`; }
