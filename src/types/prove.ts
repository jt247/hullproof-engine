// Types of the proof sandbox (Phase 4): the test spec language, the recipe that starts an app, and the files under <out>/<commit>/prove/.
// Documented in docs/INTERFACES.md and docs/PHASE-4-DESIGN.md.
import type { Json } from './hunt.ts';

export type Method = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type Phase = 'setup' | 'control' | 'attack';

export type Assertion =
  | { kind: 'status'; op: 'eq' | 'ne' | 'in'; value: number | number[] }
  | { kind: 'json'; path: string; op: 'eq' | 'ne' | 'contains' | 'exists' | 'absent'; value?: string | number | boolean | null }
  | { kind: 'text'; op: 'contains' | 'absent'; value: string }
  | { kind: 'header'; name: string; op: 'eq' | 'contains' | 'exists' | 'absent'; value?: string };

export interface Capture { name: string; from: 'json' | 'header' | 'status'; path?: string }

export interface SpecStep {
  id: string; phase: Phase; actor: string; method: Method; path: string;
  headers?: Record<string, string>; body?: { [k: string]: Json } | null; captures?: Capture[]; assert: Assertion[];
}

export interface Spec {
  schema_version: '1.0.0';
  spec_id: string; title: string; claim: string;
  lead_key: string | null;                         // the hunt lead this spec tests, when it came from one
  target: { entry_point: string; file: string; line: number };
  requirement_ids: string[];
  actors: Record<string, { headers?: Record<string, string> }>;
  steps: SpecStep[];
  expect: { outcome: 'flaw_present' };             // the attack steps' assertions describe the flaw; they all hold when it is there
}

export interface StepRecord {
  id: string; phase: Phase; actor: string;
  error: string | null;                            // the request could not be made (connection, timeout, bad variable)
  request: { method: Method; path: string; headers: Record<string, string>; body: Json };
  response: { status: number; headers: Record<string, string>; json: Json | undefined; text: string | undefined; truncated: boolean } | null;
  captures: Record<string, Json>;
  assertions: { ok: boolean; desc: string }[];
}

export type RunOutcome = 'proven' | 'not_proven' | 'invalid' | 'error';
export type SpecOutcome = RunOutcome | 'unstable' | 'not_provable';

// One run of one spec, as stored under prove/runs/<spec_id>/run-N.json. The hash covers everything but itself.
export interface RunRecord {
  schema_version: '1.0.0'; spec_id: string; spec_sha256: string; run: number;
  outcome: RunOutcome; detail: string; steps: StepRecord[]; transcript_sha256: string;
}

export interface ProveRunSummary { run: number; outcome: RunOutcome; transcript_sha256: string; detail: string }
export interface ProveSpecResult {
  spec_id: string; spec_sha256: string; lead_key: string | null; title: string; claim: string;
  entry_point: string; requirement_ids: string[]; sink: { file: string; line: number };
  outcome: SpecOutcome; reason: string; runs: ProveRunSummary[];
}

export type NotProvableCode =
  | 'no_package_json' | 'unsupported_stack' | 'hosted_service' | 'unsupported_datastore' | 'no_lockfile' | 'needs_install_scripts'
  | 'no_start_command' | 'port_unknown' | 'db_path_hardcoded' | 'no_seed' | 'no_runtime' | 'refused_unsafe_backend' | 'build_failed' | 'start_failed' | 'health_failed' | 'time_limit' | 'too_large';
export interface NotProvable { code: NotProvableCode; reason: string }

export interface ProveMeta { schema_version: '1.0.0'; commit: string | null; runner: string; runs_required: number; recipe_sha256: string | null; not_provable: NotProvable | null; left_behind: number; copy_excluded: string[] }
export interface ProveResult {
  schema_version: '1.0.0'; engine_version: string; commit: string | null; runner: string; runs_required: number;
  recipe_sha256: string | null; not_provable: NotProvable | null;
  specs: ProveSpecResult[];
  dropped: { file: string; reason: string }[];       // spec files that failed validation and were not run
  left_behind: number;                               // containers, images or networks still there after teardown (0 when clean)
  copy_excluded: string[];                           // what was left out of the copy that went into the sandbox
  counts: { specs: number; proven: number; not_proven: number; invalid: number; unstable: number; error: number; not_provable: number; dropped: number };
}

export interface Recipe {
  schema_version: '1.0.0'; stack: 'node-express' | 'python-flask'; base_image: string;
  install_scripts?: boolean;                       // true only when the owner passed --allow-install-scripts: install scripts run (a Python package may build from source) in the build container
  install: string[] | null;                        // argv of the build phase install, null when nothing is installed
  vendored_modules: boolean;                       // node_modules of the repository is part of the copy (no install, no registry); always false for Python
  seed: string | null; start: string; port: number; port_from_env: boolean; health_path: string;
  data_store: { kind: 'none' } | { kind: 'sqlite'; env: string[] } | { kind: 'postgres'; migrations: string[]; seed_sql: string | null };
  env: Record<string, string>;                     // dummy values only; {DATA} stands for the writable data folder
  notes: string[];
}
export type RecipeResult = { ok: true; recipe: Recipe } | ({ ok: false } & NotProvable);
