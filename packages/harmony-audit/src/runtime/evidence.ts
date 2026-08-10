/** Evidence ownership and admissibility for AI task boundaries (v3.1-aligned inline model). */
import { canonicalJson, contentHash } from "./identity.js";

export type Row = Record<string, unknown>;
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => !!item && typeof item === "object" && !Array.isArray(item)) : [];
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const unique = (values: readonly string[]): string[] => [...new Set(values)].sort();
const isRow = (value: unknown): value is Row => !!value && typeof value === "object" && !Array.isArray(value);

export type EvidenceRow = Row & { kind: string; source: string; summary: string };

const EVIDENCE_FIELDS = ["kind", "source", "summary", "location", "content_ref", "sha256"] as const;

export function evidenceRow(value: unknown): EvidenceRow {
  return Object.fromEntries(EVIDENCE_FIELDS
    .filter((key) => isRow(value) && value[key] !== undefined)
    .map((key) => [key, isRow(value) ? value[key] : undefined])) as EvidenceRow;
}

/** Content-addressed local id: identical evidence rows collapse to one id per producer task. */
export function evidenceLocalId(row: EvidenceRow): string { return contentHash(canonicalJson(row)); }

export type EvidenceCollector = Map<string, EvidenceRow>;

function register(out: EvidenceCollector, items: unknown): string[] {
  const ids: string[] = [];
  for (const item of rows(items)) {
    const row = evidenceRow(item);
    const id = evidenceLocalId(row);
    out.set(id, row);
    ids.push(id);
  }
  return unique(ids);
}

/** Recursively replace inline `evidence` arrays with runtime-numbered `evidence_refs`. */
function materializeInline(value: unknown, out: EvidenceCollector): unknown {
  if (Array.isArray(value)) return value.map((item) => materializeInline(item, out));
  if (!isRow(value)) return value;
  const result: Row = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === "evidence" && Array.isArray(item)) result.evidence_refs = register(out, item);
    else if (key === "basis_evidence" && Array.isArray(item)) result.basis_evidence_refs = register(out, item);
    else result[key] = materializeInline(item, out);
  }
  return result;
}

/** Source-backed evidence that may support a security conclusion. */
export function semanticAdmissibleRefs(group: Row): Set<string> {
  const refs = [
    ...strings(group.evidence_refs),
    ...strings(isRow(group.operation) ? group.operation.evidence_refs : []),
  ];
  for (const key of ["facts", "edges", "branches", "security_checks"]) {
    for (const item of rows(group[key])) refs.push(...strings(item.evidence_refs));
  }
  const context = isRow(group.context) ? group.context : {};
  const availability = isRow(group.availability) ? group.availability : {};
  refs.push(...strings(context.evidence_refs), ...strings(availability.evidence_refs));
  return new Set(refs);
}

/** Hypothesis basis evidence that is not admissible: untrusted for validation conclusions. */
export function semanticHypothesisRefs(group: Row): Set<string> {
  const context = isRow(group.context) ? group.context : {};
  const refs: string[] = [];
  for (const hypothesis of rows(context.effect_hypotheses)) refs.push(...strings(hypothesis.basis_evidence_refs));
  const admissible = semanticAdmissibleRefs(group);
  return new Set(refs.filter((ref) => !admissible.has(ref)));
}

export function componentCallRefs(call: Row): Set<string> {
  const refs = [...strings(call.evidence_refs)];
  const transition = isRow(call.principal_transition) ? call.principal_transition : {};
  refs.push(...strings(transition.evidence_refs));
  for (const check of rows(call.security_checks)) refs.push(...strings(check.evidence_refs));
  return new Set(refs);
}

export function materializeSemanticGroup(group: Row, out: EvidenceCollector): Row {
  const materialized = materializeInline(group, out) as Row;
  const facts = rows(materialized.facts);
  materialized.edges = facts.slice(0, -1).map((fact, index) => ({
    from: String(fact.fact_key),
    to: String(facts[index + 1]!.fact_key),
    kind: "next",
    evidence_refs: unique([...strings(fact.evidence_refs), ...strings(facts[index + 1]!.evidence_refs)]),
  }));
  materialized.evidence_refs = [...semanticAdmissibleRefs(materialized)].sort();
  return materialized;
}

export function materializeComponentCall(call: Row, out: EvidenceCollector): Row {
  const materialized = materializeInline(call, out) as Row;
  materialized.evidence_refs = [...componentCallRefs(materialized)].sort();
  return materialized;
}

export function materializeValidation(validation: Row, out: EvidenceCollector): Row {
  function convert(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(convert);
    if (!isRow(value)) return value;
    const result: Row = {};
    for (const [key, item] of Object.entries(value)) {
      if (key === "evidence" && isRow(item) && "semantic_refs" in item && "verification" in item) {
        const semantic = strings(item.semantic_refs);
        const verification = register(out, item.verification);
        result.evidence_refs = unique([...semantic, ...verification]);
      } else {
        result[key] = convert(item);
      }
    }
    return result;
  }
  return convert(validation) as Row;
}

/** All semantic refs a validation cites across every `evidence: {semantic_refs, verification}` support. */
export function validationSemanticRefs(value: unknown): Set<string> {
  const refs = new Set<string>();
  const walk = (item: unknown): void => {
    if (Array.isArray(item)) { item.forEach(walk); return; }
    if (!isRow(item)) return;
    const support = item.evidence;
    if (isRow(support) && "semantic_refs" in support && "verification" in support) {
      strings(support.semantic_refs).forEach((ref) => refs.add(ref));
    }
    for (const [key, child] of Object.entries(item)) if (key !== "evidence") walk(child);
  };
  walk(value);
  return refs;
}

export function materializePoc(poc: Row, out: EvidenceCollector): Row {
  const materialized = structuredClone(poc) as Row;
  const materializedRefs: string[] = [];
  for (const symbolRef of rows(materialized.symbol_refs)) {
    const refs = register(out, symbolRef.evidence);
    if (refs.length) {
      symbolRef.evidence_refs = refs;
      delete symbolRef.evidence;
      materializedRefs.push(...refs);
    }
  }
  materialized.evidence_refs = unique([...strings(materialized.evidence_refs), ...materializedRefs]);
  return materialized;
}
