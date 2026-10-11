// The findings record (the JSON inside the hullproof-findings block of report.findings.md), schema 1.1.0.
// The schema file is schemas/findings.schema.json, a copy of the kit's docs/hullproof/findings.schema.json; the kit file is the
// source of truth and the copy is checked by test/schemas.test.ts. Field limits (lengths, counts, patterns) live in the schema;
// cross field rules live in the kit's validate-findings.mjs. The engine writes schema_version "1.1.0".

export type Severity = 'BLOCKER' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FailClass = 'finding' | 'missing_control' | 'hardening_note';
export type RouteStateWord = 'NEEDS DASHBOARD' | 'NEEDS BUILD' | 'NEEDS DYNAMIC TEST' | 'ASK OWNER' | 'ATTESTATION' | 'UNKNOWN';

export interface FileLineNote { file: string; line: number; note: string }

export interface Boundary { principal: string; input: string; intended_control: string; crossed: string; affected: string; result: string }
export interface TraceStep extends FileLineNote { kind: 'entrypoint' | 'handoff' | 'sink' }

// New in 1.1.0. A fail record carrying this may be class "finding" without a trace: the rule hit is the evidence.
export interface MachineEvidence {
  tool: string;                    // "semgrep", "gitleaks", "trivy", "hullproof-check" and so on
  rule_id: string;                 // scanner rule id or engine check id
  tool_version: string;
  config_sha256: string | null;
}

export interface FailRecord {
  fingerprint: string;             // "<SEC id|GAP|OBS>:<file or ->:<slug>"
  kind: 'fail';
  sec_ids: string[];
  title: string;
  class: FailClass;
  gap_in_standard: boolean;
  severity: Severity;
  confidence: 'VERIFIED' | 'SUSPECTED';
  demonstrated: boolean;
  root_cause: string;
  raised_by: string[];
  impact_statement: string;
  remediation: { strategy: string; confirm: string };
  evidence: FileLineNote[];
  boundary?: Boundary;
  trace?: TraceStep[];
  absence_search?: { command: string; files_searched: number; count: number; practice: 'absent' | 'present_unsafe' };
  preventing_layer?: FileLineNote[];
  paths_enumerated?: { count: number; method: string };
  expiry_condition?: string;
  owner_evidence?: { file: string; hash: string; hash_kind: 'git_blob' | 'sha256'; date: string; commit: string; note: string }[];
  lowering?: { from: Severity; to: Severity; evidence: FileLineNote[] };
  verified_by?: { agent: 'hullproof-finding-verifier'; mode: 'finding'; outcome: 'UPHELD' | 'ADJUSTED' | 'INSUFFICIENT'; own_severity?: Severity; own_class?: FailClass; call: number };
  machine_evidence?: MachineEvidence;
}

export interface RoutedRecord {
  fingerprint: string;
  kind: 'routed';
  sec_ids: string[];
  title: string;
  state: RouteStateWord;
  reason: string;
  owner_action: string;
  check_card: string | null;
  raised_by: string[];
  boundary: Boundary;
  trace?: TraceStep[];
  verified_by?: { agent: 'hullproof-finding-verifier'; mode: 'handoff'; outcome: 'UPHELD' | 'ADJUSTED' | 'INSUFFICIENT'; call: number };
}

export interface RefutedRecord {
  fingerprint: string;
  kind: 'refuted';
  sec_ids: string[];
  title: string;
  claim: string;
  reason: string;
  preventing_layer: FileLineNote[];
  raised_by: string[];
  verified_by: { agent: 'hullproof-finding-verifier'; mode: 'finding' | 'handoff'; outcome: 'REFUTED'; call: number };
}

export interface ObservationRecord {
  fingerprint: string;
  kind: 'observation';
  sec_ids: string[];
  title: string;
  where: FileLineNote[];
  note: string;
  raised_by: string[];
}

export type FindingRecord = FailRecord | RoutedRecord | RefutedRecord | ObservationRecord;

export interface FindingsReport {
  commit: string;
  tree: string;
  tree_clean: boolean;
  stage: 'LAUNCH' | 'GROWTH' | 'SCALE';
  profile: 'quick' | 'standard' | 'deep';
  scope: 'full' | 'partial';
  scope_note?: string;
  run_status: 'complete' | 'incomplete';
  incomplete_reason?: 'budget_exhausted' | 'agent_failure' | 'owner_stopped' | 'deterministic_only'; // deterministic_only: schema 1.1.0, engine run, no verifier by design
  agent_calls: number;
  budget: number | null;
}

export interface FindingsFile {
  schema_version: '1.0.0' | '1.1.0';
  report: FindingsReport;
  records: FindingRecord[];        // sorted by fingerprint
}
