type Row = Record<string, unknown>;
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => !!item && typeof item === "object" && !Array.isArray(item)) : [];
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const unique = (values: readonly string[]) => [...new Set(values)].sort();

/** Normalize deterministic fields before schema/domain validation, as the v3.1 runtime did. */
export function normalizeSemanticSubmission(candidate: Row, entryId: string, capabilityDomains: ReadonlyMap<string, string>): Row {
  const normalized = structuredClone(candidate);
  normalized.entry_id = entryId;
  for (const group of rows(normalized.operation_groups)) {
    const capability = String(group.capability_id ?? "");
    const domain = capabilityDomains.get(capability);
    if (domain) group.category = domain;
    group.controlled_properties = unique(strings(group.controlled_properties));
    group.branches = rows(group.branches).sort((left, right) => canonicalJson([left.condition, strings(left.locations).sort()]).localeCompare(canonicalJson([right.condition, strings(right.locations).sort()])));
    const facts = rows(group.facts);
    const used = new Set<string>();
    for (const [index, fact] of facts.entries()) {
      const base = String(fact.fact_key ?? `fact-${index + 1}`);
      let key = base;
      for (let suffix = 2; used.has(key); suffix += 1) key = `${base}-${suffix}`;
      fact.fact_key = key;
      used.add(key);
    }
    const operation = (group.operation as Row | undefined) ?? {};
    const operationFacts = facts.filter((fact) => fact.type === "operation");
    if (operationFacts.length) {
      operationFacts[0]!.body = operation.body ?? operationFacts[0]!.body;
      operationFacts[0]!.location = operation.location ?? operationFacts[0]!.location;
      for (const extra of operationFacts.slice(1)) extra.type = "reachability";
    } else if (operation.body && operation.location) {
      let key = "operation";
      for (let suffix = 2; used.has(key); suffix += 1) key = `operation-${suffix}`;
      facts.push({ fact_key: key, type: "operation", body: operation.body, location: operation.location, evidence_refs: strings(group.evidence_refs) });
    }
    group.facts = facts;
    group.edges = facts.slice(0, -1).map((fact, index) => ({
      from: fact.fact_key,
      to: facts[index + 1]!.fact_key,
      kind: "next",
      evidence_refs: unique([...strings(fact.evidence_refs), ...strings(facts[index + 1]!.evidence_refs)]),
    }));
    const coverage = (normalized.coverage as Row | undefined) ?? {};
    coverage.operation_sites_checked = unique([...strings(coverage.operation_sites_checked), ...(typeof operation.location === "string" ? [operation.location] : [])]);
  }
  const merged = new Map<string, Row>();
  for (const group of rows(normalized.operation_groups)) {
    const operation = (group.operation as Row | undefined) ?? {};
    const identity = canonicalJson([entryId, operation.location, strings(group.controlled_properties).sort()]);
    const existing = merged.get(identity);
    if (!existing) { merged.set(identity, group); continue; }
    const richer = rows(group.facts).length > rows(existing.facts).length ? group : existing;
    const duplicate = richer === group ? existing : group;
    for (const key of ["branches", "security_checks"] as const) {
      const values = new Map([...rows(richer[key]), ...rows(duplicate[key])].map((item) => [canonicalJson(item), item]));
      richer[key] = [...values.values()];
    }
    richer.evidence_refs = unique([...strings(richer.evidence_refs), ...strings(duplicate.evidence_refs)]);
    const context = (richer.context as Row | undefined) ?? {};
    const duplicateContext = (duplicate.context as Row | undefined) ?? {};
    context.evidence_refs = unique([...strings(context.evidence_refs), ...strings(duplicateContext.evidence_refs)]);
    richer.context = context;
    merged.set(identity, richer);
  }
  normalized.operation_groups = [...merged.values()];
  const calls = new Map<string, Row>();
  for (const call of rows(normalized.component_calls)) {
    const mappings = new Map(rows(call.parameter_mappings).map((item) => [canonicalJson(item), item]));
    call.parameter_mappings = [...mappings.values()].sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
    const identity = canonicalJson([call.target_component_id, call.call_location, call.parameter_mappings, call.principal_transition ?? {}]);
    if (!calls.has(identity)) calls.set(identity, call);
  }
  normalized.component_calls = [...calls.values()];
  return normalized;
}

export function normalizeValidationSubmission(candidate: Row, entryId: string): Row {
  const normalized = structuredClone(candidate);
  normalized.entry_id = entryId;
  for (const validation of rows(normalized.validations)) for (const key of ["impact", "severity", "cwe", "poc", "demotion_reason", "evidence_gap"]) {
    if (typeof validation[key] === "string" && !String(validation[key]).trim()) delete validation[key];
  }
  return normalized;
}
import { canonicalJson } from "../runtime/identity.js";
