import { canonicalJson, contentHash, stableId } from "../runtime/identity.js";

export type ControlState = "preserved" | "constrained" | "constant" | "unknown";
export type InvocationControlState = "preserved" | "constrained" | "independent" | "unknown";
export type OriginBinding = "preserved" | "replaced_by_caller" | "not_observable" | "unknown";
export type Authority = "origin" | "source_component" | "system" | "none" | "unknown";
type Row = Record<string, unknown>;

export interface ParameterHop {
  readonly component_id: string;
  readonly source_property: string;
  readonly target_property: string;
  readonly control_state: ControlState;
  readonly transform: string;
}

export interface ParameterChain {
  readonly origin_property: string;
  readonly current_property: string;
  readonly control_state: ControlState;
  readonly transforms: readonly string[];
  readonly hops: readonly ParameterHop[];
}

export interface PrincipalState {
  readonly origin_principal: string;
  readonly immediate_caller: string;
  readonly target_observed_principal: string;
  readonly origin_binding: OriginBinding;
  readonly authority_used: Authority;
}

export interface InvocationHop {
  readonly component_id: string;
  readonly control_state: InvocationControlState;
  readonly condition: string;
}

export interface ComponentPath {
  readonly path_id: string;
  readonly fingerprint: string;
  readonly root_entry_id: string;
  readonly target_entry_id: string;
  readonly component_ids: readonly string[];
  readonly entry_ids: readonly string[];
  readonly call_keys: readonly string[];
  readonly producer_task_ids: readonly string[];
  readonly parameter_chains: readonly ParameterChain[];
  readonly invocation_control_state: InvocationControlState;
  readonly invocation_hops: readonly InvocationHop[];
  readonly principal_state: PrincipalState;
  readonly security_checks: readonly Row[];
  readonly evidence_refs: readonly string[];
  readonly cycle: boolean;
}

const asRows = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => !!item && typeof item === "object") : [];
const asStrings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const unique = <T>(values: readonly T[]): T[] => [...new Set(values)];

function control(left: ControlState, right: ControlState): ControlState {
  if (left === "unknown" || right === "unknown") return "unknown";
  if (left === "constant" || right === "constant") return "constant";
  if (left === "constrained" || right === "constrained") return "constrained";
  return "preserved";
}

function invocationControl(left: InvocationControlState, right: InvocationControlState): InvocationControlState {
  if (left === "independent" || right === "independent") return "independent";
  if (left === "unknown" || right === "unknown") return "unknown";
  if (left === "constrained" || right === "constrained") return "constrained";
  return "preserved";
}

function invocation(call: Row, sourceComponentId: string): InvocationHop {
  const value = (call.invocation_control as Row | undefined) ?? {};
  return {
    component_id: sourceComponentId,
    control_state: String(value.control_state ?? "unknown") as InvocationControlState,
    condition: String(value.condition ?? call.condition ?? "unknown"),
  };
}

function binding(left: OriginBinding, right: OriginBinding): OriginBinding {
  if (left === "replaced_by_caller" || right === "replaced_by_caller") return "replaced_by_caller";
  if (left === "unknown" || right === "unknown") return "unknown";
  if (left === "not_observable" || right === "not_observable") return "not_observable";
  return "preserved";
}

function mappings(call: Row, sourceComponentId: string): ParameterHop[] {
  return asRows(call.parameter_mappings).map((mapping) => ({
    component_id: sourceComponentId,
    source_property: String(mapping.source_property), target_property: String(mapping.target_property),
    control_state: String(mapping.control_state) as ControlState, transform: String(mapping.transform),
  }));
}

function firstChains(call: Row, sourceComponentId: string): ParameterChain[] {
  return mappings(call, sourceComponentId).filter((hop) => ["preserved", "constrained"].includes(hop.control_state)).map((hop) => ({
    origin_property: hop.source_property, current_property: hop.target_property, control_state: hop.control_state,
    transforms: [hop.transform], hops: [hop],
  }));
}

export function composeParameterChains(existing: readonly ParameterChain[], call: Row, sourceComponentId: string): ParameterChain[] {
  const next = mappings(call, sourceComponentId); const result: ParameterChain[] = [];
  for (const chain of existing) {
    for (const hop of next.filter((candidate) => candidate.source_property === chain.current_property)) {
      const state = control(chain.control_state, hop.control_state);
      if (!["preserved", "constrained"].includes(state)) continue;
      result.push({
        origin_property: chain.origin_property, current_property: hop.target_property,
        control_state: state, transforms: [...chain.transforms, hop.transform], hops: [...chain.hops, hop],
      });
    }
  }
  return dedupeChains(result);
}

function dedupeChains(chains: readonly ParameterChain[]): ParameterChain[] {
  const byKey = new Map<string, ParameterChain>();
  for (const chain of chains) byKey.set(canonicalJson([chain.origin_property, chain.current_property, chain.control_state, chain.transforms]), chain);
  return [...byKey.values()].sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
}

function transition(call: Row): Row { return (call.principal_transition as Row | undefined) ?? {}; }
function pathChecks(call: Row, sourceComponentId: string, hopIndex: number, originBinding: OriginBinding): Row[] {
  return asRows(call.security_checks).map((check) => ({
    ...check, source_component_id: sourceComponentId, hop_index: hopIndex,
    applies_to_origin: check.subject_kind === "origin_principal" || check.subject_kind === "transferred_property"
      || (check.subject_kind === "immediate_caller" && originBinding === "preserved"),
  }));
}

function pathIdentity(path: Omit<ComponentPath, "path_id" | "fingerprint">): ComponentPath {
  const identity = {
    root_entry_id: path.root_entry_id, target_entry_id: path.target_entry_id, component_ids: path.component_ids,
    call_keys: path.call_keys, parameter_chains: path.parameter_chains,
    invocation_control_state: path.invocation_control_state, invocation_hops: path.invocation_hops,
    principal_state: path.principal_state, cycle: path.cycle,
  };
  const fingerprint = contentHash(identity);
  return { ...path, fingerprint, path_id: stableId("PATH", fingerprint) };
}

export function seedPath(args: { sourceEntryId: string; sourceComponentId: string; sourceTaskId: string; targetEntryId: string; targetComponentId: string; call: Row }): ComponentPath {
  const principal = transition(args.call); const invocationHop = invocation(args.call, args.sourceComponentId);
  return pathIdentity({
    root_entry_id: args.sourceEntryId, target_entry_id: args.targetEntryId,
    component_ids: [args.sourceComponentId, args.targetComponentId], entry_ids: [args.sourceEntryId, args.targetEntryId],
    call_keys: [String(args.call.call_key)], producer_task_ids: [args.sourceTaskId], parameter_chains: firstChains(args.call, args.sourceComponentId),
    invocation_control_state: invocationHop.control_state, invocation_hops: [invocationHop],
    principal_state: {
      origin_principal: String(principal.caller_principal ?? "unknown"), immediate_caller: args.sourceComponentId,
      target_observed_principal: String(principal.callee_observed_principal ?? "unknown"),
      origin_binding: String(principal.origin_binding ?? "unknown") as OriginBinding,
      authority_used: String(principal.authority_used ?? "unknown") as Authority,
    },
    security_checks: pathChecks(args.call, args.sourceComponentId, 0, String(principal.origin_binding ?? "unknown") as OriginBinding),
    evidence_refs: unique([
      ...asStrings(args.call.evidence_refs),
      ...asStrings(((args.call.invocation_control as Row | undefined) ?? {}).evidence_refs),
      ...asStrings(principal.evidence_refs), ...asRows(args.call.security_checks).flatMap((item) => asStrings(item.evidence_refs)),
    ]),
    cycle: args.sourceComponentId === args.targetComponentId,
  });
}

export function extendPath(path: ComponentPath, args: { sourceEntryId: string; sourceComponentId: string; sourceTaskId: string; targetEntryId: string; targetComponentId: string; call: Row }): ComponentPath {
  const principal = transition(args.call); const cycle = path.component_ids.includes(args.targetComponentId);
  const invocationHop = invocation(args.call, args.sourceComponentId);
  return pathIdentity({
    root_entry_id: path.root_entry_id, target_entry_id: args.targetEntryId,
    component_ids: [...path.component_ids, args.targetComponentId], entry_ids: [...path.entry_ids, args.targetEntryId],
    call_keys: [...path.call_keys, String(args.call.call_key)], producer_task_ids: unique([...path.producer_task_ids, args.sourceTaskId]),
    parameter_chains: composeParameterChains(path.parameter_chains, args.call, args.sourceComponentId),
    invocation_control_state: invocationControl(path.invocation_control_state, invocationHop.control_state),
    invocation_hops: [...path.invocation_hops, invocationHop],
    principal_state: {
      origin_principal: path.principal_state.origin_principal, immediate_caller: args.sourceComponentId,
      target_observed_principal: String(principal.callee_observed_principal ?? "unknown"),
      origin_binding: binding(path.principal_state.origin_binding, String(principal.origin_binding ?? "unknown") as OriginBinding),
      authority_used: String(principal.authority_used ?? "unknown") as Authority,
    },
    security_checks: [...path.security_checks, ...pathChecks(args.call, args.sourceComponentId, path.call_keys.length, binding(path.principal_state.origin_binding, String(principal.origin_binding ?? "unknown") as OriginBinding))],
    evidence_refs: unique([
      ...path.evidence_refs, ...asStrings(args.call.evidence_refs),
      ...asStrings(((args.call.invocation_control as Row | undefined) ?? {}).evidence_refs),
      ...asStrings(principal.evidence_refs), ...asRows(args.call.security_checks).flatMap((item) => asStrings(item.evidence_refs)),
    ]),
    cycle,
  });
}

export function isPathControllable(path: ComponentPath): boolean {
  return path.parameter_chains.length > 0 || ["preserved", "constrained"].includes(path.invocation_control_state);
}

export function buildCrossComponentGroup(path: ComponentPath, localGroup: Row): Row | undefined {
  const controlled = new Set(asStrings(localGroup.controlled_properties));
  const chains = path.parameter_chains.filter((chain) => controlled.has(chain.current_property));
  const invocationControlled = controlled.size === 0
    && ["preserved", "constrained"].includes(path.invocation_control_state);
  if (!chains.length && !invocationControlled) return undefined;
  const groupKey = `cross:${path.fingerprint.slice(0, 16)}:${String(localGroup.group_key)}`;
  const principal = path.principal_state;
  return {
    ...localGroup, group_key: groupKey, title: `跨组件：${String(localGroup.title)}`,
    controlled_properties: invocationControlled ? ["$invocation"] : unique(chains.map((chain) => chain.origin_property)),
    control_mode: invocationControlled ? "invocation" : "data",
    security_checks: [...path.security_checks, ...asRows(localGroup.security_checks)],
    evidence_refs: unique([...path.evidence_refs, ...asStrings(localGroup.evidence_refs)]),
    scope: "cross_component", path_id: path.path_id, path_context: path,
    parameter_chains: chains,
    principal_state: principal,
  };
}
