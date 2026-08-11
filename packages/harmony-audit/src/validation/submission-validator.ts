import { invariant } from "./invariant-errors.js";
import { validationSemanticRefs } from "../runtime/evidence.js";

type Row = Record<string, unknown>;
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => !!item && typeof item === "object" && !Array.isArray(item)) : [];
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const isRow = (value: unknown): value is Row => !!value && typeof value === "object" && !Array.isArray(value);

function unique(values: readonly string[]): boolean { return new Set(values).size === values.length; }
function refs(value: Row): string[] { return strings(value.evidence_refs); }

export interface SemanticValidationContext {
  taskId: string; entryId: string; capabilities: readonly string[]; enabledCapabilities: ReadonlySet<string>;
  componentIds: ReadonlySet<string>; capabilityDomains?: ReadonlyMap<string, string>;
}

export function validateSemanticSubmission(candidate: Row, context: SemanticValidationContext): void {
  invariant(candidate.task_id === context.taskId, "TASK_ID_MISMATCH", { expected: context.taskId, actual: candidate.task_id });
  invariant(candidate.entry_id === context.entryId, "ENTRY_ID_MISMATCH", { expected: context.entryId, actual: candidate.entry_id });
  const coverage = (candidate.coverage as Row | undefined) ?? {};
  if (coverage.entry_status === "confirmed") invariant(strings(coverage.entry_symbols_checked).length > 0, "CONFIRMED_ENTRY_SYMBOL_MISSING");
  if (coverage.entry_status === "excluded") invariant(rows(candidate.operation_groups).length === 0 && rows(candidate.component_calls).length === 0, "EXCLUDED_ENTRY_HAS_OUTPUTS");

  const groupKeys = rows(candidate.operation_groups).map((group) => String(group.group_key ?? ""));
  invariant(groupKeys.every(Boolean) && unique(groupKeys), "DUPLICATE_LOCAL_ID", { entity: "operation_group" });
  for (const group of rows(candidate.operation_groups)) {
    const capability = String(group.capability_id ?? "");
    invariant(context.enabledCapabilities.has(capability), "CAPABILITY_NOT_ENABLED", { capability });
    invariant(context.capabilities.includes(capability), "CAPABILITY_OUT_OF_SCOPE", { capability });
    const expectedCategory = context.capabilityDomains?.get(capability);
    if (expectedCategory) invariant(expectedCategory === group.category, "CAPABILITY_CATEGORY_MISMATCH", { capability, category: group.category, expectedCategory });
    if (capability === "CAP-DOS-001") invariant(group.category === "availability" && !!group.availability, "DOS_SEMANTIC_MISMATCH");
    const semanticContext = (group.context as Row | undefined) ?? {};
    for (const hypothesis of rows(semanticContext.effect_hypotheses)) {
      invariant(rows(hypothesis.basis_evidence).length > 0, "HYPOTHESIS_BASIS_MISSING", { group: group.group_key, claim: hypothesis.claim });
    }
    if (semanticContext.direct_observed_effect !== null) {
      invariant(rows(semanticContext.evidence).length > 0, "DIRECT_EFFECT_EVIDENCE_MISSING", { group: group.group_key });
    }
    const facts = rows(group.facts).map((fact) => String(fact.fact_key ?? ""));
    invariant(facts.every(Boolean) && unique(facts), "DUPLICATE_LOCAL_ID", { entity: "fact", group: group.group_key });
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

export interface ValidationContext {
  taskId: string; entryId: string; groups: readonly Row[];
  /** group_id -> evidence ids the group may cite (source-backed, from the group's own payload). */
  admissibleEvidence: ReadonlyMap<string, ReadonlySet<string>>;
  /** group_id -> hypothesis basis evidence ids that must not support validation conclusions. */
  hypothesisOnlyEvidence: ReadonlyMap<string, ReadonlySet<string>>;
  entryStatus?: string;
}

const EMPTY: ReadonlySet<string> = new Set();

const DIMENSIONS = ["externally_reachable", "attacker_controlled", "sink_reached", "security_check_bypassed_or_absent", "boundary_violated", "concrete_impact"] as const;
const EFFECT_PROOFS = ["controlled_value_use", "security_behavior_change", "protected_operation", "concrete_impact"] as const;

export function validateExploitabilitySubmission(candidate: Row, context: ValidationContext): void {
  invariant(candidate.task_id === context.taskId, "TASK_ID_MISMATCH", { expected: context.taskId, actual: candidate.task_id });
  invariant(candidate.entry_id === context.entryId, "ENTRY_ID_MISMATCH", { expected: context.entryId, actual: candidate.entry_id });
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

    const admissible = context.admissibleEvidence.get(String(validation.group_id)) ?? EMPTY;
    const hypothesisOnly = context.hypothesisOnlyEvidence.get(String(validation.group_id)) ?? EMPTY;
    const semanticRefs = validationSemanticRefs(validation);
    const outside = [...semanticRefs].filter((ref) => !admissible.has(ref) && !hypothesisOnly.has(ref)).sort();
    invariant(outside.length === 0, "EVIDENCE_OUTSIDE_OPERATION_GROUP", { groupId: validation.group_id, refs: outside });
    const inadmissible = [...semanticRefs].filter((ref) => hypothesisOnly.has(ref)).sort();
    invariant(inadmissible.length === 0, "HYPOTHESIS_EVIDENCE_NOT_ADMISSIBLE", { groupId: validation.group_id, refs: inadmissible });

    for (const key of DIMENSIONS) {
      const dimension = (dimensions[key] as Row | undefined) ?? {};
      const support = isRow(dimension.evidence) ? dimension.evidence : {};
      const hasSupport = strings(support.semantic_refs).length > 0 || rows(support.verification).length > 0;
      if (dimension.status === "true" || dimension.status === "false") {
        const code = dimension.status === "true" ? "TRUE_DIMENSION_EVIDENCE_INSUFFICIENT" : "FALSE_DIMENSION_EVIDENCE_INSUFFICIENT";
        invariant(dimension.evidence_level !== "hypothesis" && hasSupport, code, { groupId: validation.group_id, dimension: key });
      }
    }
    if (classification === "confirmed_vulnerability") {
      if (context.entryStatus) invariant(context.entryStatus === "confirmed", "CONFIRMED_ENTRY_REQUIRED", { entryStatus: context.entryStatus });
      invariant(DIMENSIONS.every((key) => ((dimensions[key] as Row | undefined) ?? {}).status === "true"), "CONFIRMED_DIMENSIONS_INCOMPLETE");
      invariant(["impact", "severity", "cwe"].every((key) => typeof validation[key] === "string" && String(validation[key]).length > 0), "CONFIRMED_DETAILS_INCOMPLETE");
      const effectChain = (validation.effect_chain as Row | undefined) ?? {};
      for (const key of EFFECT_PROOFS) {
        const proof = (effectChain[key] as Row | undefined) ?? {};
        const support = isRow(proof.evidence) ? proof.evidence : {};
        const hasSupport = strings(support.semantic_refs).length > 0 || rows(support.verification).length > 0;
        invariant(typeof proof.location === "string" && proof.location.length > 0 && hasSupport, "CONFIRMED_EFFECT_CHAIN_INCOMPLETE", { groupId: validation.group_id, proof: key });
        invariant(rows(support.verification).length > 0, "CONFIRMED_EFFECT_NOT_INDEPENDENTLY_VERIFIED", { groupId: validation.group_id, proof: key });
      }
    } else invariant(typeof validation.demotion_reason === "string" && validation.demotion_reason.length > 0, "DEMOTION_REASON_MISSING");
    if (["residual_risk", "insufficient_evidence"].includes(classification)) invariant(typeof validation.evidence_gap === "string" && validation.evidence_gap.length > 0, "EVIDENCE_GAP_MISSING");
    const guardStatus = String(((dimensions.security_check_bypassed_or_absent as Row | undefined) ?? {}).status ?? "");
    const expectedGuardStatus: Record<string, string> = { absent: "true", bypassable: "true", effective: "false", unknown: "unknown" };
    invariant(guardStatus === expectedGuardStatus[String(validation.security_check_outcome)], "SECURITY_CHECK_OUTCOME_DIMENSION_MISMATCH", {
      groupId: validation.group_id, securityCheckOutcome: validation.security_check_outcome, guardStatus,
    });

    const coreStatuses = ["externally_reachable", "attacker_controlled", "sink_reached"].map((key) => String(((dimensions[key] as Row | undefined) ?? {}).status ?? ""));
    const finalStatuses = ["security_check_bypassed_or_absent", "boundary_violated", "concrete_impact"].map((key) => String(((dimensions[key] as Row | undefined) ?? {}).status ?? ""));
    const publicApi = ((validation.business_intent as Row | undefined) ?? {}).is_public_api === true;
    const classificationMatches = classification === "confirmed_vulnerability"
      ? DIMENSIONS.every((key) => ((dimensions[key] as Row | undefined) ?? {}).status === "true")
      : classification === "protected_exposure"
        ? coreStatuses[0] === "true" && coreStatuses[1] === "true" && validation.security_check_outcome === "effective" && guardStatus === "false"
        : classification === "no_exploitable_path"
          ? coreStatuses.includes("false")
          : classification === "benign_business_flow"
            ? coreStatuses.every((status) => status === "true") && publicApi
              && ((dimensions.boundary_violated as Row | undefined) ?? {}).status === "false"
              && ((dimensions.concrete_impact as Row | undefined) ?? {}).status === "false"
            : classification === "residual_risk"
              ? coreStatuses.every((status) => status === "true") && !finalStatuses.includes("false")
              : classification === "insufficient_evidence"
                ? coreStatuses.includes("unknown") && !coreStatuses.includes("false")
                : false;
    invariant(classificationMatches, "CLASSIFICATION_DECISION_MISMATCH", { groupId: validation.group_id, classification, coreStatuses, finalStatuses });
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
  }
}

export interface PocValidationContext {
  taskId: string; entryId: string; findingId: string; allowedEntryTypes: ReadonlySet<string>;
  /** Evidence ids inherited from the semantic and validation phases; nothing else may be cited. */
  allowedEvidence: ReadonlySet<string>;
}

const PLACEHOLDER_PATTERN = /略|省略|\.\.\.|…|TODO|TBD|your[\s_-]?(code|command|payload)|[《<](?:填入|替换|your)[^》>]*[》>]/;
const FORBIDDEN_POC_OUTPUTS = ["classification", "exploitability", "severity", "cwe", "impact", "assurance_status"] as const;
const SHELL_PREFIX = /^\s*(hdc|adb|curl|aa)\b/;
const ARKTS_TRIGGER_API = /startAbility|rpc\.|commonEventManager|dataAbilityHelper|runJavaScript|webview|createChannel|requestSubmitJob|wifiManager/;

/** v3.1-aligned PoC contract: refs within inherited scope, inline symbol evidence, executable code, phase boundary. */
export function validatePocSubmission(candidate: Row, context: PocValidationContext): void {
  invariant(candidate.task_id === context.taskId, "TASK_ID_MISMATCH", { expected: context.taskId, actual: candidate.task_id });
  invariant(candidate.finding_id === context.findingId, "FINDING_ID_MISMATCH", { expected: context.findingId, actual: candidate.finding_id });
  for (const forbidden of FORBIDDEN_POC_OUTPUTS) invariant(!(forbidden in candidate), "POC_FORBIDDEN_OUTPUT", { field: forbidden });
  const entryType = String(candidate.entry_type ?? "");
  invariant(context.allowedEntryTypes.has(entryType), "POC_ENTRY_TYPE_MISMATCH", { entry_type: entryType, allowed: [...context.allowedEntryTypes].sort() });
  invariant(typeof candidate.code === "string" && String(candidate.code).length > 0, "POC_CODE_REQUIRED");
  invariant(!PLACEHOLDER_PATTERN.test(String(candidate.code)), "POC_PLACEHOLDER_FOUND");
  invariant(typeof candidate.expected_observation === "string" && String(candidate.expected_observation).length > 0, "POC_EXPECTED_OBSERVATION_REQUIRED");
  const trigger = (candidate.trigger as Row | undefined) ?? {};
  invariant(typeof trigger.kind === "string" && String(trigger.kind).length > 0, "POC_TRIGGER_KIND_REQUIRED");
  invariant(typeof trigger.payload !== "undefined", "POC_TRIGGER_PAYLOAD_REQUIRED");
  invariant(!(typeof trigger.payload === "object" && trigger.payload !== null && Object.keys(trigger.payload as Row).length === 0), "POC_TRIGGER_PAYLOAD_EMPTY");
  const language = String(candidate.language ?? "");
  const triggerKind = String(trigger.kind ?? "");
  if (language === "shell") {
    invariant(SHELL_PREFIX.test(String(candidate.code)), "POC_SHELL_COMMAND_REQUIRED", { code: String(candidate.code).slice(0, 60) });
    invariant(["adb_shell", "ability_want"].includes(triggerKind), "POC_SHELL_TRIGGER_MISMATCH", { trigger_kind: triggerKind });
  }
  if (language === "arkts") {
    invariant(triggerKind !== "adb_shell", "POC_ARKTS_TRIGGER_MISMATCH", { trigger_kind: triggerKind });
    invariant(ARKTS_TRIGGER_API.test(String(candidate.code)), "POC_ARKTS_API_REQUIRED", { code: String(candidate.code).slice(0, 60) });
  }
  for (const ref of refs(candidate)) invariant(context.allowedEvidence.has(ref), "UNKNOWN_EVIDENCE_REF", { ref });
  for (const symbolRef of rows(candidate.symbol_refs)) {
    invariant(rows(symbolRef.evidence).length > 0, "SYMBOL_REF_EVIDENCE_MISSING", { symbol: symbolRef.symbol });
  }
}
