export const HARMONY_DEFAULT_AGENT_CAPACITY = 5;
export const HARMONY_MAX_AGENT_CAPACITY = 5;

export function harmonyAgentCapacity(value: unknown = HARMONY_DEFAULT_AGENT_CAPACITY): number {
  const capacity = Number(value);
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > HARMONY_MAX_AGENT_CAPACITY) {
    throw new Error(`harmony_audit_capacity_must_be_1_to_${HARMONY_MAX_AGENT_CAPACITY}`);
  }
  return capacity;
}
