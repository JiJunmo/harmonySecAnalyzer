export type DimensionStatus = true | false | "unknown";

export function dimension(status: DimensionStatus, evidenceRefs: string[] = status === "unknown" ? [] : ["EV-V"]) {
  return {
    status: status === "unknown" ? "unknown" : String(status),
    reason: status === "unknown" ? "证据不足" : status ? "源码核验成立" : "源码核验不成立",
    evidence_level: status === "unknown" ? "hypothesis" : "direct",
    evidence_refs: evidenceRefs,
  };
}

export function sixDimensions(overrides: Partial<Record<string, DimensionStatus>> = {}, evidenceRefs: string[] = ["EV-V"]) {
  const status = (key: string) => overrides[key] ?? true;
  return Object.fromEntries([
    "externally_reachable", "attacker_controlled", "sink_reached",
    "security_check_bypassed_or_absent", "boundary_violated", "concrete_impact",
  ].map((key) => [key, dimension(status(key), status(key) === "unknown" ? [] : evidenceRefs)]));
}

export const validationEvidence = {
  evidence_id: "EV-V", kind: "atlas_source", source: "atlas", summary: "六维阶段重新读取并核验完整效果链", location: "A.ets:12",
};

export function effectChain(evidenceRefs: string[] = ["EV-V"]) {
  const proof = (description: string) => ({ description, location: "A.ets:12", evidence_refs: evidenceRefs });
  return {
    controlled_value_use: proof("受控值在安全关键表达式中被读取"),
    security_behavior_change: proof("受控值改变安全相关分支"),
    protected_operation: proof("变化后的分支到达受保护操作"),
    concrete_impact: proof("受保护操作产生具体安全影响"),
  };
}
