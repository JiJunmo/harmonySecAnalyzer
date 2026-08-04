import type Database from "better-sqlite3";
import type { Capability } from "../capabilities.js";

type Row = Record<string, unknown>;
const rows = (value: unknown): Row[] => Array.isArray(value) ? value.filter((item): item is Row => !!item && typeof item === "object" && !Array.isArray(item)) : [];
const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

function facet(candidate: Row): Row {
  const type = String(candidate.type ?? "unknown");
  const transports: Record<string, string> = {
    component_scope: "component", exported_component: "want", deeplink: "uri", implicit_want: "want",
    extension_uri: "uri", ipc_service_candidate: "ipc",
    common_event_candidate: "common_event",
  };
  return {
    entry_type: type,
    transport: transports[type] ?? "unknown",
    symbol: candidate.src_entry ?? candidate.component_name ?? `${String(candidate.module_name ?? "project")}:${type}`,
    discriminator: candidate.trigger_facts ?? {},
    external_reachability: candidate.exported === true ? "reachable" : "unknown",
    project_candidate_ids: [candidate.candidate_id],
    evidence_refs: [],
  };
}

function sourceFile(location: string): string {
  const match = /^(.*):\d+$/.exec(location);
  return match?.[1] ?? location;
}

export function semanticTaskInput(raw: Row, capabilities: readonly Capability[]): Row {
  const scope = (raw.audit_scope as Row | undefined) ?? {};
  const selected = new Set(strings(scope.capabilities));
  const profiles = capabilities
    .filter((item) => selected.has(item.capability_id))
    .map((item) => ({ capability_id: item.capability_id, title: item.title ?? "", domain: item.domain ?? "", analysis_scope: item.analysis_scope ?? "component", guidance: item.guidance ?? [] }));
  const candidates = rows(raw.entry_candidates);
  const first = (raw.entry as Row | undefined) ?? candidates[0] ?? {};
  const facets = candidates.map(facet);
  const entry = {
    ...first,
    entry_id: first.candidate_id,
    entry_key: `component:${String(first.component_id ?? first.candidate_id ?? "unknown")}`,
    component: first.component_name ?? `${String(first.module_name ?? "project")} dynamic ${String(first.type ?? "entry")}`,
    symbol: facets[0]?.symbol ?? first.src_entry ?? first.component_name,
    facets,
    profiles: [...selected],
    external_reachability: facets.some((item) => item.external_reachability === "reachable") ? "reachable" : "unknown",
    project_candidates: candidates,
  };
  const analysisContract: Row = {
    task_unit: "one deterministic component analysis unit",
    phases: ["confirm_component_inputs", "trace_within_component", "collect_operations", "record_component_calls", "merge_equivalent_operations", "record_gaps"],
    group_by: ["operation_location", "controlled_properties"],
    stop_at: "component_call",
    forbidden_outputs: ["classification", "exploitability", "severity", "cwe", "poc"],
    evidence_model: {
      facts: "only directly observed source facts",
      effect_hypotheses: "untrusted search leads with explicit missing proofs",
      forbidden_as_fact: ["name_based_effect_inference", "comment_based_effect_inference", "unverified_runtime_effect"],
    },
  };
  if (selected.has("CAP-DOS-001")) analysisContract.availability_requirements = [
    "externally_triggered_failure_or_resource_consumption", "attacker_scale_or_repeatability", "bounds_and_amplification",
    "exception_handling_or_isolation", "affected_scope_and_recovery",
  ];
  return {
    target_repo: raw.target_repo,
    entry,
    audit_scope: profiles,
    analysis_contract: analysisContract,
    project_summary: raw.project_summary ?? {},
    project_context: raw.project_context ?? {},
    component_directory: raw.component_directory ?? [],
    upstream_calls: raw.upstream_calls ?? [],
  };
}

export function validationTaskInput(db: Database.Database, raw: Row, entryId: string): Row {
  const analysis = db.prepare("SELECT summary,coverage_json FROM semantic_analyses WHERE entry_id=? ORDER BY created_at DESC LIMIT 1").get(entryId) as { summary: string; coverage_json: string } | undefined;
  const coverage = analysis ? JSON.parse(analysis.coverage_json) as Row : {};
  const groups = rows(raw.operation_groups);
  const locations = new Set(strings(coverage.operation_sites_checked));
  for (const group of groups) {
    const operation = (group.operation as Row | undefined) ?? {};
    if (typeof operation.location === "string") locations.add(operation.location);
    for (const fact of rows(group.facts)) if (typeof fact.location === "string") locations.add(fact.location);
    for (const check of rows(group.security_checks)) if (typeof check.location === "string") locations.add(check.location);
    for (const branch of rows(group.branches)) for (const location of strings(branch.locations)) locations.add(location);
  }
  const selectedCoverage = Object.fromEntries(["entry_status", "entry_notes", "unresolved_targets"]
    .filter((key) => coverage[key] !== undefined).map((key) => [key, coverage[key]]));
  const targetRepo = String(((raw.verification_scope as Row | undefined) ?? {}).target_repo ?? "");
  return {
    semantic_analysis: { summary: analysis?.summary ?? "", coverage: selectedCoverage, operation_groups: groups },
    validation_contract: {
      semantic_effect_hypotheses_are_untrusted: true,
      dimensions_require_status_reason_evidence_level_and_refs: true,
      confirmed_effect_chain: ["controlled_value_use", "security_behavior_change", "protected_operation", "concrete_impact"],
      confirmed_effect_chain_requires_fresh_validation_evidence: true,
    },
    principal_contracts: groups.filter((group) => group.scope === "cross_component").map((group) => {
      const state = (group.principal_state as Row | undefined) ?? {};
      return {
        group_id: group.group_id,
        origin_principal: state.origin_principal,
        target_observed_principal: state.target_observed_principal,
        authority_used: state.authority_used,
        origin_bound_to_observed_principal: state.origin_binding === "preserved",
        delegation_risk: state.origin_binding === "replaced_by_caller",
      };
    }),
    verification_scope: {
      target_repo: targetRepo,
      seed_locations: [...locations].sort(),
      seed_files: [...new Set([...locations].map(sourceFile))].sort(),
      seed_symbols: strings(coverage.entry_symbols_checked),
    },
  };
}

export function pocTaskInput(db: Database.Database, raw: Row, entryId: string): Row {
  const finding = (raw.finding as Row | undefined) ?? {};
  const validation = (raw.validation as Row | undefined) ?? {};
  const group = (raw.operation_group as Row | undefined) ?? {};
  const entry = (raw.entry as Row | undefined) ?? {};
  const facets = rows(entry.facets ?? (entry.project_candidates as unknown)).map(facet);
  const locations = new Set<string>();
  const operation = (group.operation as Row | undefined) ?? {};
  if (typeof operation.location === "string") locations.add(operation.location);
  for (const fact of rows(group.facts)) if (typeof fact.location === "string") locations.add(fact.location);
  for (const check of rows(group.security_checks)) if (typeof check.location === "string") locations.add(check.location);
  for (const branch of rows(group.branches)) for (const location of strings(branch.locations)) locations.add(location);
  const allowedEntryTypes = new Set([...facets.flatMap((item) => {
    const type = String(item.entry_type ?? "");
    return { exported_component: ["exported_ability", "want"], deeplink: ["deeplink"], implicit_want: ["want"], extension_uri: ["provider"], ipc_service_candidate: ["ipc_transaction"], common_event_candidate: ["common_event"], project_scope: ["project"] }[type] ?? [type];
  })]);
  return {
    finding,
    validation,
    operation_group: group,
    entry: { ...entry, facets },
    allowed_entry_types: [...allowedEntryTypes].sort(),
    verification_scope: {
      target_repo: String(((raw.verification_scope as Row | undefined) ?? {}).target_repo ?? ""),
      seed_locations: [...locations].sort(),
      seed_files: [...new Set([...locations].map(sourceFile))].sort(),
      seed_symbols: strings((raw.verification_scope as Row | undefined)?.seed_symbols),
    },
    output_contract: {
      task_unit: "one deterministic PoC generation unit for one confirmed finding",
      entry_type_constraint: "entry_type 必须来自 allowed_entry_types",
      trigger_kind: ["adb_shell", "ability_want", "common_event", "ipc_client", "provider_query", "web_navigation", "jsbridge_call", "network", "crypto", "archive", "distributed", "generic"],
      forbidden_outputs: ["classification", "exploitability", "severity", "cwe"],
    },
  };
}
