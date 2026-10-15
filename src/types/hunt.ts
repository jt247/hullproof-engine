// Types of the hunt files under <out>/<commit>/hunt/. Documented in docs/INTERFACES.md. The confirmation engine that reads them is
// open; the step that calls a model and writes the answers is not part of this repository.
export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export interface LeadStep { file: string; line: number; note: string }

// A condition of the map query language (src/confirm/query.ts).
export type Cond =
  | { all: Cond[] } | { any: Cond[] } | { not: Cond }
  | { field: string; op: 'eq' | 'ne' | 'in' | 'contains' | 'startsWith' | 'exists' | 'gt' | 'lt'; value?: Json }
  | { some: string; where?: Cond } | { none: string; where?: Cond };
export interface Query { where: Cond }

export type EvidenceProposal =
  | { kind: 'map_query'; query: Query }
  | { kind: 'semgrep_rule'; rule_yaml: string; control_code: string; control_extension: string }
  | { kind: 'generated_test' }
  | { kind: 'none'; rejected?: string };

export interface Lead {
  lead_id: string;
  entry_point: string;
  requirement_ids: string[];      // sorted, unique
  claim: string;
  path: LeadStep[];               // entry point first, sink last
  quoted_code: string;            // the code at the sink, as it stands in the file
  evidence_proposal: EvidenceProposal;
  claim_truncated?: true;         // the model's claim was longer than the limit and was shortened
}

// One saved answer: one call for one entry point in one run. Written as soon as it arrives.
export interface HuntAnswer {
  schema_version: '1.0.0';
  run: number;
  entry_id: string;
  status: 'complete' | 'incomplete';
  stop: string | null;            // why an incomplete call stopped: refusal, safety, rate_limit, timeout, length, ...
  detail: string | null;
  provider: string;
  model: string;
  context_sha256: string;
  truncated: boolean;
  usage: { input_tokens: number; output_tokens: number };
  output: Json;                   // the model's JSON as received; null for an incomplete call
}

export interface HuntPlan {
  schema_version: '1.0.0';
  commit: string | null;
  runs: number;
  entries: string[];              // entry point ids in hunting order
}

export type Confirmation =
  | { status: 'confirmed'; method: 'map_query' | 'semgrep_rule' | 'sandbox_test'; run: number; detail: string; tool: string; rule_id: string; tool_version: string; config_sha256: string }
  | { status: 'not_confirmed'; method: 'map_query' | 'semgrep_rule' | 'generated_test' | 'none'; detail: string; reason?: 'unknown_protection'; helpers?: string[] }
  | { status: 'not_run'; method: 'semgrep_rule'; detail: string };

export interface LeadOut {
  key: string;
  claim_truncated?: true;
  entry_point: string;
  requirement_ids: string[];
  claim: string;
  path: LeadStep[];
  sink: { file: string; line: number };
  runs_raised: number;
  runs: number[];
  confirmation: Confirmation;
}

export interface HuntResult {
  schema_version: '1.0.0';
  engine_version: string;
  commit: string | null;
  runs: number;
  entries_hunted: number;
  calls: { complete: number; incomplete: number; missing: number };
  incomplete: { entry_id: string; run: number; stop: string; detail: string }[];
  malformed: { count: number; items: { run: number; entry_id: string; lead_id: string; reason: string }[] };
  hallucinations: { count: number; items: { run: number; entry_id: string; lead_id: string; reason: string }[] };
  confirmed: LeadOut[];
  leads: LeadOut[];               // everything not confirmed, most runs first
  usage: { calls: number; input_tokens: number; output_tokens: number };
}

export interface HuntSynthesis {
  schema_version: '1.0.0';
  status: 'complete' | 'incomplete';
  stop: string | null;
  detail: string | null;
  provider: string;
  model: string;
  summary: string;
  explanations: { key: string; text: string }[];
  usage: { input_tokens: number; output_tokens: number };
}
