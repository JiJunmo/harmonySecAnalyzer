export type Row = Record<string, unknown>;
export type DimensionStatus = true | false | "unknown";

export function semanticCoverage(task: Record<string, any>, entryStatus = "confirmed", externalStatus?: string) {
  const entry = (task.input?.entry ?? {}) as Record<string, any>;
  const candidates = (entry.project_candidates ?? task.input?.entry_candidates ?? []) as Record<string, any>[];
  const externalIds = candidates
    .filter((candidate) => !["component_scope", "project_scope"].includes(String(candidate.type)) && typeof candidate.candidate_id === "string")
    .map((candidate) => String(candidate.candidate_id)).sort();
  const resolvedExternal = externalStatus ?? (entryStatus === "excluded" || !externalIds.length ? "excluded" : entryStatus);
  return {
    entry_status: entryStatus,
    external_entry_status: resolvedExternal,
    confirmed_external_candidate_ids: resolvedExternal === "confirmed" ? externalIds : [],
    entry_notes: [],
    entry_symbols_checked: entryStatus === "confirmed" ? [String(entry.component_name ?? "A") + ".onCreate"] : [],
    operation_sites_checked: [],
    unresolved_targets: [],
  };
}

export function invocationControl(state: "preserved" | "constrained" | "independent" | "unknown" = "preserved") {
  return { control_state: state, condition: state === "constrained" ? "guarded branch" : "caller selects call", evidence: [] };
}

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
    evidence: support(semanticRefs, status === "unknown" ? [] : [evidenceRow()]),
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
