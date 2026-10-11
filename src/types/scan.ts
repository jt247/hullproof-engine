// Scanner adapters and their normalised output. JSON schemas: schemas/scan-hits.schema.json, schemas/scan-meta.schema.json.
// Written by the adapters in src/scanners/. Documented in docs/INTERFACES.md.
import type { Stack } from './stack.ts';

export type ScannerId = 'semgrep' | 'osv-scanner' | 'gitleaks' | 'trivy' | 'checkov';

// One normalised scanner hit. No secret value, no tool message text, no absolute path, no timing.
export interface Hit {
  tool: ScannerId;
  rule_id: string;              // the tool's own rule or check id, as the tool prints it
  file: string;                 // repository relative POSIX path
  line: number;                 // 1 based; 0 only when the tool gives no line (for example a lockfile level advisory)
  sec_ids: string[];            // requirement IDs from the rule metadata or engine/maps/<tool>.json; [] means unmapped
  severity_hint: string | null; // the tool's own severity word, kept for the report; never used by the gate
  message_key: string;          // key into the engine's plain English text, normally `${tool}:${rule_id}`
}

// scan/<tool>.json
export interface HitsFile {
  schema_version: '1.0.0';
  tool: ScannerId;
  hits: Hit[];                  // sorted by file, line, tool, rule_id
}

// scan/<tool>.meta.json. The reproducibility record.
export interface ToolMeta {
  schema_version: '1.0.0';
  tool: ScannerId;
  status: 'ran' | 'skipped: not installed' | 'skipped: not applicable' | 'skipped: network not allowed' | 'failed';
  version: string | null;
  tested_version_range: string;
  version_tested: boolean;      // false when the installed version is outside tested_version_range
  argv: string[];               // exact command, no shell; [] when skipped
  config_sha256: string | null;
  commit: string | null;
  files_scanned: number | null;
  files_tracked: number | null;
  exit_code: number | null;
  db_date: string | null;       // OSV Scanner advisory data date, else null
  not_assessed_sec_ids: string[]; // IDs that stay NOT ASSESSED because this tool did not run
}

export interface RunContext {
  repo: string;                 // absolute path of the repository being scanned
  out: string;                  // absolute path of the output folder
  stack: Stack;
  allowNetwork: boolean;
  edition: 'free' | 'pro';
  kit?: string | null;          // the kit folder the scan resolved; absent or null: the path order in src/mapping/controls.ts
  history?: boolean;            // set by the scan step after its git configuration check; lets `gitleaks git` run
}

export interface ScannerAdapter {
  id: ScannerId;
  versionCommand: string[];
  testedVersions: string;
  needsNetwork: boolean;
  applies(stack: Stack): boolean;
  command(ctx: RunContext): string[];
  configFiles(ctx: RunContext): string[];
  parse(stdout: string, ctx: RunContext): Hit[];
}
