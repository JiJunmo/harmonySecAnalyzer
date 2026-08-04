import { invariant } from "./invariant-errors.js";

type Row = Record<string, unknown>;
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => !!item && typeof item === "object") : [];
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

function unique(values: readonly string[]): boolean { return new Set(values).size === values.length; }
function refs(value: Row): string[] { return strings(value.evidence_refs); }

function allSemanticRefs(candidate: Row): string[] {
  const result = [...rows(candidate.operation_groups).flatMap((group) => [
    ...refs(group), ...refs((group.context as Row | undefined) ?? {}), ...refs((group.availability as Row | undefined) ?? {}),
    ...rows(group.branches).flatMap(refs), ...rows(group.facts).flatMap(refs), ...rows(group.edges).flatMap(refs),
    ...rows(group.security_checks).flatMap(refs),
  ]), ...rows(candidate.component_calls).flatMap((call) => [
    ...refs(call), ...refs((call.principal_transition as Row | undefined) ?? {}), ...rows(call.security_checks).flatMap(refs),
  ])];
  return result;
}

export interface SemanticValidationContext {
  taskId: string; entryId: string; capabilities: readonly string[]; enabledCapabilities: ReadonlySet<string>;
  componentIds: ReadonlySet<string>; capabilityDomains?: ReadonlyMap<string, string>;
}

export function validateSemanticSubmission(candidate: Row, context: SemanticValidationContext): void {
  invariant(candidate.task_id === context.taskId, "TASK_ID_MISMATCH", { expected: context.taskId, actual: candidate.task_id });
  invariant(candidate.entry_id === context.entryId, "ENTRY_ID_MISMATCH", { expected: context.entryId, actual: candidate.entry_id });
  const evidenceIds = rows(candidate.evidence).map((item) => String(item.evidence_id ?? ""));
  invariant(evidenceIds.every(Boolean) && unique(evidenceIds), "DUPLICATE_LOCAL_ID", { entity: "evidence" });
  const evidence = new Set(evidenceIds);
  const coverage = (candidate.coverage as Row | undefined) ?? {};
  if (coverage.entry_status === "confirmed") invariant(strings(coverage.entry_symbols_checked).length > 0, "CONFIRMED_ENTRY_SYMBOL_MISSING");
  if (coverage.entry_status === "excluded") invariant(rows(candidate.operation_groups).length === 0 && rows(candidate.component_calls).length === 0, "EXCLUDED_ENTRY_HAS_OUTPUTS");
  for (const ref of allSemanticRefs(candidate)) invariant(evidence.has(ref), "UNKNOWN_EVIDENCE_REF", { ref });

  const groupKeys = rows(candidate.operation_groups).map((group) => String(group.group_key ?? ""));
  invariant(groupKeys.every(Boolean) && unique(groupKeys), "DUPLICATE_LOCAL_ID", { entity: "operation_group" });
  for (const group of rows(candidate.operation_groups)) {
    const capability = String(group.capability_id ?? "");
    invariant(context.enabledCapabilities.has(capability), "CAPABILITY_NOT_ENABLED", { capability });
    invariant(context.capabilities.includes(capability), "CAPABILITY_OUT_OF_SCOPE", { capability });
    const expectedCategory = context.capabilityDomains?.get(capability);
    if (expectedCategory) invariant(expectedCategory === group.category, "CAPABILITY_CATEGORY_MISMATCH", { capability, category: group.category, expectedCategory });
    if (capability === "CAP-DOS-001") invariant(group.category === "availability" && !!group.availability, "DOS_SEMANTIC_MISMATCH");
    const facts = rows(group.facts).map((fact) => String(fact.fact_key ?? ""));
    invariant(facts.every(Boolean) && unique(facts), "DUPLICATE_LOCAL_ID", { entity: "fact", group: group.group_key });
    const factSet = new Set(facts);
    for (const edge of rows(group.edges)) {
      invariant(factSet.has(String(edge.from)) && factSet.has(String(edge.to)) && edge.from !== edge.to, "INVALID_FACT_EDGE", edge);
    }
  }

  const callKeys = rows(candidate.component_calls).map((call) => String(call.call_key ?? ""));
  invariant(callKeys.every(Boolean) && unique(callKeys), "DUPLICATE_LOCAL_ID", { entity: "component_call" });
  for (const call of rows(candidate.component_calls)) {
    invariant(context.componentIds.has(String(call.target_component_id ?? "")), "UNKNOWN_TARGET_COMPONENT", { target: call.target_component_id });
    for (const mapping of rows(call.parameter_mappings)) {
      invariant(["preserved", "constrained", "constant", "unknown"].includes(String(mapping.control_state)), "INVALID_PARAMETER_MAPPING", mapping);
    }
  }
}

export interface ValidationContext { taskId: string; entryId: string; groups: readonly Row[]; inheritedEvidence: ReadonlySet<string>; entryStatus?: string; }

export function validateExploitabilitySubmission(candidate: Row, context: ValidationContext): void {
  invariant(candidate.task_id === context.taskId, "TASK_ID_MISMATCH", { expected: context.taskId, actual: candidate.task_id });
  invariant(candidate.entry_id === context.entryId, "ENTRY_ID_MISMATCH", { expected: context.entryId, actual: candidate.entry_id });
  const localIds = rows(candidate.evidence).map((item) => String(item.evidence_id ?? ""));
  invariant(localIds.every(Boolean) && unique(localIds), "DUPLICATE_LOCAL_ID", { entity: "evidence" });
  const allowedEvidence = new Set([...context.inheritedEvidence, ...localIds]);
  const expected = new Set(context.groups.map((group) => String(group.group_id)));
  const validations = rows(candidate.validations);
  const actual = validations.map((validation) => String(validation.group_id ?? ""));
  invariant(unique(actual), "DUPLICATE_GROUP_VALIDATION");
  for (const groupId of expected) invariant(actual.includes(groupId), "MISSING_GROUP_VALIDATION", { groupId });
  for (const groupId of actual) invariant(expected.has(groupId), "UNEXPECTED_GROUP_VALIDATION", { groupId });

  for (const validation of validations) {
    const group = context.groups.find((item) => item.group_id === validation.group_id)!;
    invariant(validation.capability_id === group.capability_id, "CAPABILITY_CATEGORY_MISMATCH", { groupId: validation.group_id });
    const classification = String(validation.classification);
    const dimensions = (validation.exploitability as Row | undefined) ?? {};
    if (classification === "confirmed_vulnerability") {
      if (context.entryStatus) invariant(context.entryStatus === "confirmed", "CONFIRMED_ENTRY_REQUIRED", { entryStatus: context.entryStatus });
      invariant(["externally_reachable", "attacker_controlled", "sink_reached", "security_check_bypassed_or_absent", "boundary_violated", "concrete_impact"].every((key) => dimensions[key] === true), "CONFIRMED_DIMENSIONS_INCOMPLETE");
      invariant(["impact", "severity", "cwe", "poc"].every((key) => typeof validation[key] === "string" && String(validation[key]).length > 0), "CONFIRMED_DETAILS_INCOMPLETE");
    } else invariant(typeof validation.demotion_reason === "string" && validation.demotion_reason.length > 0, "DEMOTION_REASON_MISSING");
    if (["residual_risk", "insufficient_evidence"].includes(classification)) invariant(typeof validation.evidence_gap === "string" && validation.evidence_gap.length > 0, "EVIDENCE_GAP_MISSING");
    if (classification === "protected_exposure") invariant(validation.security_check_outcome === "effective", "PROTECTION_OUTCOME_MISMATCH");
    invariant(!(validation.security_check_outcome === "effective" && dimensions.security_check_bypassed_or_absent === true), "SECURITY_CHECK_OUTCOME_CONFLICT");
    const boundary = (validation.security_boundary as Row | undefined) ?? {};
    invariant(boundary.violation === dimensions.boundary_violated, "BOUNDARY_DIMENSION_MISMATCH");
    if (["protected_exposure", "benign_business_flow"].includes(classification)) invariant(rows(validation.counter_evidence).length > 0, "DEMOTION_REASON_MISSING", { reason: "counter_evidence_required" });
    if (group.capability_id === "CAP-DOS-001") {
      const availability = (validation.availability_analysis as Row | undefined) ?? {};
      invariant(Object.keys(availability).length > 0, "DOS_SEMANTIC_MISMATCH");
      if (classification === "confirmed_vulnerability") invariant(availability.single_trigger_fatal_or_repeatable === true && availability.amplified_consumption_or_fatal_failure === true && availability.effective_containment === false && availability.material_availability_loss === true, "DOS_SEMANTIC_MISMATCH");
    }
    if (group.scope === "cross_component") {
      const expected = (group.principal_state as Row | undefined) ?? {}; const principal = (validation.principal_analysis as Row | undefined) ?? {};
      const expectedAnalysis: Row = {
        origin_principal: expected.origin_principal,
        target_observed_principal: expected.target_observed_principal,
        authority_used: expected.authority_used,
        origin_bound_to_observed_principal: expected.origin_binding === "preserved",
        delegation_risk: expected.origin_binding === "replaced_by_caller",
      };
      const mismatchedFields = Object.keys(expectedAnalysis).filter((field) => principal[field] !== expectedAnalysis[field]);
      invariant(
        mismatchedFields.length === 0,
        "PRINCIPAL_CHAIN_INCOMPLETE", {
          groupId: validation.group_id,
          mismatched_fields: mismatchedFields,
          expected: expectedAnalysis,
          actual: Object.fromEntries(Object.keys(expectedAnalysis).map((field) => [field, principal[field]])),
        },
      );
    }
    for (const ref of [...refs(validation), ...refs((validation.business_intent as Row | undefined) ?? {}), ...refs((validation.security_boundary as Row | undefined) ?? {}), ...refs((validation.principal_analysis as Row | undefined) ?? {}), ...refs((validation.availability_analysis as Row | undefined) ?? {}), ...rows(validation.counter_evidence).flatMap(refs)]) invariant(allowedEvidence.has(ref), "UNKNOWN_EVIDENCE_REF", { ref });
  }
}

export interface PocValidationContext {
  taskId: string; entryId: string; findingId: string; allowedEntryTypes: ReadonlySet<string>;
  allowedEvidence: ReadonlySet<string>;
}

export function validatePocSubmission(candidate: Row, context: PocValidationContext): void {
  invariant(candidate.task_id === context.taskId, "TASK_ID_MISMATCH", { expected: context.taskId, actual: candidate.task_id });
  invariant(candidate.finding_id === context.findingId, "FINDING_ID_MISMATCH", { expected: context.findingId, actual: candidate.finding_id });
  const entryType = String(candidate.entry_type ?? "");
  invariant(context.allowedEntryTypes.has(entryType), "POC_ENTRY_TYPE_MISMATCH", { entry_type: entryType, allowed: [...context.allowedEntryTypes].sort() });
  const localIds = rows(candidate.evidence).map((item) => String(item.evidence_id ?? ""));
  invariant(localIds.every(Boolean) && unique(localIds), "DUPLICATE_LOCAL_ID", { entity: "evidence" });
  const allowedEvidence = new Set([...context.allowedEvidence, ...localIds]);
  invariant(typeof candidate.code === "string" && String(candidate.code).length > 0, "POC_CODE_REQUIRED");
  invariant(typeof candidate.expected_observation === "string" && String(candidate.expected_observation).length > 0, "POC_EXPECTED_OBSERVATION_REQUIRED");
  const trigger = (candidate.trigger as Row | undefined) ?? {};
  invariant(typeof trigger.kind === "string" && String(trigger.kind).length > 0, "POC_TRIGGER_KIND_REQUIRED");
  invariant(typeof trigger.payload !== "undefined", "POC_TRIGGER_PAYLOAD_REQUIRED");
  for (const ref of refs(candidate)) invariant(allowedEvidence.has(ref), "UNKNOWN_EVIDENCE_REF", { ref });
}
