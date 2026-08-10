export type Row = Record<string, unknown>;
export type DimensionStatus = true | false | "unknown";

export function evidenceRow(summary = "六维阶段重新读取并核验完整效果链", location = "A.ets:12") {
  return { kind: "atlas_source", source: "atlas", summary, location };
}

/** v3.1-aligned support: semantic_refs cite the group's admissible scope, verification is fresh inline source evidence. */
export function support(semanticRefs: readonly string[] = [], verification: Row[] = [evidenceRow()]) {
  return { semantic_refs: [...semanticRefs], verification };
}

export function dimension(status: DimensionStatus, semanticRefs: readonly string[] = []) {
  const isTrue = status === true || status === "true";
  return {
    status: status === "unknown" ? "unknown" : String(status),
    reason: status === "unknown" ? "证据不足" : isTrue ? "源码核验成立" : "源码核验不成立",
    evidence_level: status === "unknown" ? "hypothesis" : "direct",
    evidence: support(semanticRefs, isTrue ? [evidenceRow()] : []),
  };
}

export function sixDimensions(overrides: Partial<Record<string, DimensionStatus>> = {}, semanticRefs: readonly string[] = []) {
  const status = (key: string) => overrides[key] ?? true;
  return Object.fromEntries([
    "externally_reachable", "attacker_controlled", "sink_reached",
    "security_check_bypassed_or_absent", "boundary_violated", "concrete_impact",
  ].map((key) => [key, dimension(status(key), status(key) === "unknown" ? [] : semanticRefs)]));
}

export function effectChain(semanticRefs: readonly string[] = [], verification: Row[] = [evidenceRow()]) {
  const proof = (description: string) => ({ description, location: "A.ets:12", evidence: support(semanticRefs, verification) });
  return {
    controlled_value_use: proof("受控值在安全关键表达式中被读取"),
    security_behavior_change: proof("受控值改变安全相关分支"),
    protected_operation: proof("变化后的分支到达受保护操作"),
    concrete_impact: proof("受保护操作产生具体安全影响"),
  };
}

/** Evidence ids the validation task may cite for one group (from its evidence_scope). */
export function admissibleRefs(group: Row): string[] {
  const scope = (group.evidence_scope as Row | undefined) ?? {};
  return (Array.isArray(scope.admissible) ? scope.admissible as Row[] : []).map((row) => String(row.evidence_id));
}
