// Executable checks: the definition format (checks/*.json) and the result format (checks.json).
// JSON schemas: schemas/check.schema.json, schemas/check-results.schema.json. Documented in docs/INTERFACES.md.
import type { StackCategory } from './stack.ts';
import type { ResultWord } from './results.ts';

export type CheckOp =
  | 'file_exists' | 'file_exists_for_each' | 'file_absent'
  | 'regex_present' | 'regex_absent' | 'json_value'
  | 'sql_every_table_has' | 'workflow_uses_pinned_sha' | 'workflow_permissions' | 'version_in_table'
  | 'code';                                     // a check written as TypeScript, see CodeCheckDefinition

// One declarative check definition (checks/*.json). Data only, no code. The interpreter in src/checks/ runs it.
export interface CheckDefinition {
  id: string;                                   // "check.<area>.<name>", for example "check.supply.lockfile-committed"
  sec_ids: string[];
  // Runs only when every named stack category has an item whose id is listed, or any item when the value is "*".
  applies_when: Partial<Record<StackCategory, string[] | '*'>>;
  op: CheckOp;
  params: Record<string, unknown>;              // op specific, documented per op in docs/INTERFACES.md by the checks author
  on_true: ResultWord;
  on_false: ResultWord;
  fixtures: { pass: string; fail: string };     // folders under test/fixtures/checks/
}

// A check written as TypeScript when no declarative op can say it: op "code", no params, and module names the file in
// src/checks/code/ that exports it. The five code checks keep this metadata in their module (src/checks/types.ts CodeCheck).
export interface CodeCheckDefinition extends Omit<CheckDefinition, 'op' | 'params'> {
  op: 'code';
  module: string;                               // for example "src/checks/code/webhook-verify.ts"
}

export interface CheckEvidence { file: string; line?: number; key?: string; note: string }

// The search that supports an absence result (same idea as absence_search in the findings record).
export interface AbsenceSearch { pattern: string; files_searched: number; file_globs: string[]; matches: number }

export interface CheckResult {
  check_id: string;
  sec_ids: string[];
  result: ResultWord;
  evidence: CheckEvidence[];                    // sorted by file, then line
  absence_search: AbsenceSearch | null;
  message_key: string;                          // key into the engine's plain English text, normally the check id
}

// checks.json
export interface CheckResultsFile {
  schema_version: '1.0.0';
  commit: string | null;
  results: CheckResult[];                       // sorted by check_id
  not_run: { check_id: string; reason: string }[]; // sorted by check_id
}
