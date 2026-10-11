// Types local to the scanner adapters. The contract types (Hit, HitsFile, ToolMeta, RunContext, ScannerAdapter) live in
// src/types/scan.ts and are not changed here. Fields the contract has no room for yet (rule version, evidence, advisory
// data, the reason a tool did not run) go into scan/<tool>.detail.json, described by DetailFile below.
import type { Hit, RunContext, ScannerAdapter, ScannerId, ToolMeta } from '../types/index.ts';
import type { DependencyPolicy, SeverityClass } from '../mapping/dependency-policy.ts';

export interface ScanOptions extends RunContext {
  rulesDir?: string;            // default: <engine>/rules
  rulePack?: string | null;     // optional external Semgrep rule pack folder (for example a rule pack of your own); see src/scanners/semgrep.ts
  controlsPath?: string;        // default: see src/mapping/controls.ts
  asOf?: string;                // YYYY-MM-DD, the date OSV advisories are judged against. Default: today (UTC).
  policy?: DependencyPolicy;
  env?: NodeJS.ProcessEnv;      // base environment (tests use it to hide a tool from PATH)
}

export interface SecretDetail {
  redacted: string;             // the match as Gitleaks printed it with --redact, masked again by us
  fingerprint: string;          // Gitleaks fingerprint: [commit:]file:rule:line. Holds no secret.
  source: 'dir' | 'git';
  commit: string | null;
  tracked: boolean;             // false: the file is on disk but not tracked by git
}

export interface AdvisoryDetail {
  id: string;
  aliases: string[];
  package: string;
  ecosystem: string;
  version: string;
  severity_class: SeverityClass;
  cvss_score: number | null;
  fixed_versions: string[];
  published: string | null;     // YYYY-MM-DD
  deadline_days: number;
  past_deadline: boolean;
  decision: 'fail' | 'report';
  mapped_sec_ids: string[];     // what the hit maps to when it fails; sec_ids is [] when the decision is report
}

export interface DetailHit extends Hit {
  rule_version: string;
  end_line: number;
  evidence: string | null;      // short, masked; null when it could expose a secret
  mapped_by: 'rule metadata' | 'controls tests' | 'map rule_id' | 'map default' | 'policy report only' | 'none';
  unmapped: boolean;
  secret?: SecretDetail;
  advisory?: AdvisoryDetail;
}

export interface ToolError { type: string; file: string; rule_id: string }

export interface DetailFile {
  schema_version: '0.1.0';
  tool: ScannerId;
  status: ToolMeta['status'];
  not_run_reason: string | null;
  tool_version: string | null;
  commands: string[][];         // every command run, absolute paths replaced by <placeholders>
  files: { scanned: number | null; tracked: number | null; scanned_not_tracked: number | null; tracked_not_scanned: number | null };
  as_of: string | null;         // OSV only
  policy: DependencyPolicy | null; // OSV only
  sec_ids_not_in_controls: string[];
  tool_errors: ToolError[];
  hits: DetailHit[];
}

export interface Exec { argv: string[]; stdout: string; stderr: string; status: number | null; error?: string }

// What an adapter needs on top of the shared ScannerAdapter interface.
export interface Adapter extends ScannerAdapter {
  tool: string;                 // executable name
  // Runs the tool (one or more commands) and returns detail hits. Throws on a tool failure.
  execute(opts: ScanOptions, env: Env): AdapterResult;
  possibleSecIds(opts: ScanOptions): string[];
  notApplicableReason(opts: ScanOptions): string | null;
}

export interface Env {
  version: string;
  tracked: Set<string> | null;
  rulesDir: string;
  scratch: string;              // empty temp folder, removed after the run
  run(argv: string[]): Exec;
}

export interface AdapterResult {
  hits: DetailHit[];
  commands: string[][];
  configSha256: string | null;
  scanned: string[] | null;     // repository relative files the tool read, when it says
  exitCode: number | null;
  toolErrors: ToolError[];
  dbDate?: string | null;
  asOf?: string | null;
  policy?: DependencyPolicy | null;
}
