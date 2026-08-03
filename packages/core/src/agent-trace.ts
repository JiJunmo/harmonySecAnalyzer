export type AgentTraceEventType =
  | "agent_started"
  | "assistant_message"
  | "tool_call_started"
  | "tool_call_completed"
  | "submission_started"
  | "submission_accepted"
  | "submission_rejected"
  | "agent_completed"
  | "agent_failed";

export interface AgentTraceEvent {
  readonly type: AgentTraceEventType;
  readonly timestamp: string;
  readonly payload?: unknown;
}

export type AgentTraceSink = (event: AgentTraceEvent) => void | Promise<void>;

const secret = /api[-_]?key|authorization|password|secret|token|credential/i;
const maxString = 8_000;
const maxArray = 100;
const maxDepth = 8;

function safe(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  if (typeof value === "string") return value.length > maxString ? `${value.slice(0, maxString)}\n…[truncated ${value.length - maxString} chars]` : value;
  if (value === null || typeof value === "number" || typeof value === "boolean" || value === undefined) return value;
  if (depth >= maxDepth) return "[max-depth]";
  if (Array.isArray(value)) return value.slice(0, maxArray).map((item) => safe(item, depth + 1, seen));
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[circular]";
  seen.add(value);
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 200)) {
    result[key] = secret.test(key) ? "[redacted]" : safe(item, depth + 1, seen);
  }
  return result;
}

/** Makes tool arguments and provider-visible messages safe and bounded before persistence. */
export function sanitizeAgentTraceValue(value: unknown): unknown {
  return safe(value, 0, new WeakSet());
}
