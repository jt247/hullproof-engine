// The stack pack manifest (packs/<id>/pack.json) and the fixture result (packs/<id>/fixture-result.json): their types, the
// depth levels, and the one function that says which level a recorded result supports. Format: docs/PACK-GUIDE.md.

export const LEVELS = ['L0', 'L1', 'L2', 'L3', 'L4'] as const;
export type Level = typeof LEVELS[number];
export const rank = (l: Level): number => LEVELS.indexOf(l);
export const isLevel = (x: unknown): x is Level => typeof x === 'string' && (LEVELS as readonly string[]).includes(x);

export const LEVEL_NAMES: Record<Level, string> = { L0: 'Generic', L1: 'Detected', L2: 'Mapped', L3: 'Checked', L4: 'Provable' };

// Thresholds a recorded result must reach. Written once, here, and quoted in the guide.
export const L3_MIN_RECALL = 0.5;   // share of planted flaws the pack's rules and checks must find, on a blind answer key
export const REAL_APP_MIN_RECALL = 0.9; // share of a sample of real route registrations the map must hold, on every real app measured for the pack
export const MIN_RUNS = 3;          // identical runs needed to call the output stable

export interface FileRef { file: string; pro?: boolean }
export interface RuleRef { file: string; tests: string[]; pro?: boolean }
export interface CheckRef { id: string; pro?: boolean }
export interface RecipeRef { file: string; recipe: string; pro?: boolean }

export interface PackManifest {
  schema: 1;
  id: string;
  name: string;
  summary: string;
  edition: 'free' | 'pro';             // where the pack's own files ship; a part marked pro is skipped when the Pro folders are absent
  languages: string[];                 // stack.json language ids
  frameworks: string[];                // stack.json framework, mobile or data store ids the pack covers
  level: Level;                        // what the pack declares for everything it lists
  scopes?: { where: string; level: Level }[]; // narrower scopes that reach a higher level
  limits?: string[];                   // what the pack does not cover, in plain words; shown in the coverage table
  parts: {
    detectors?: string[];              // detector ids (detectors/*.json) the pack relies on
    extractors?: FileRef[];            // entry point extractors and config readers
    auth_patterns?: FileRef[];         // the files that name session, role and signature patterns
    sources_sinks?: FileRef[];         // taint rule files (sources and sinks)
    rules?: RuleRef[];                 // Semgrep rule files, each with the fixture files that test them
    checks?: CheckRef[];               // executable checks that apply to the stack
    mapping?: FileRef[];               // where the checks and rules map to requirement IDs
    start_recipe?: RecipeRef;          // how the proof sandbox starts the app
  };
  fixture: {
    dir: string;                       // the fixture app with planted flaws
    fixed_dir: string;                 // the fixed copy
    internal?: boolean;                // the fixture is not in any edition, so its folders are checked only where they exist
    answer_keys: ('in_repo' | 'outside_repo' | 'independent')[]; // where the keys are: in packs/<id>/answer-key.json, in ../bench-targets/answer-keys/<id>.json (local only), or an independent source
    result: string;                    // packs/<id>/fixture-result.json
  };
}

// One measurement on one fixture. A pack can have several (a synthetic app and a demo app, for example).
export interface Measurement {
  name: string;                        // what was measured: a folder or an app
  kind: 'synthetic' | 'demo' | 'third_party';
  blind_key: boolean;                  // the answer key was written apart from the extractor and kept out of the repository, or is independent
  source: string;                      // how the numbers were made: a script, or the report they were recorded from
  mapped: { what: string; expected: number; matched: number; extra: number } | null; // what the map holds for this stack: entry points, or tables and policies
  flaws: { planted: number; found: number; false_findings: number } | null; // false findings: on the fixed copy, or judged by hand on the planted app when there is none
  stability: { runs: number; identical: boolean };
}

export interface FixtureResult {
  schema: 1;
  pack: string;
  measured: string;                    // YYYY-MM-DD
  engine: string;
  detect: { expected: string[]; found: string[] };
  measurements: Measurement[];
  proof: { scope: string; planted: number; proven: number; runs: number; false_proofs_fixed: number; identical: boolean; source: string }[];
  notes: string[];
}

const stable = (m: Measurement): boolean => m.stability.runs >= MIN_RUNS && m.stability.identical;
const exact = (m: Measurement): boolean => !!m.mapped && m.mapped.expected >= 1 && m.mapped.matched === m.mapped.expected && m.mapped.extra === 0 && stable(m);
// A real application is the hardest test of the extractor. A pack that fell short on one cannot claim L2, whatever the synthetic fixtures say.
const realAppShort = (m: Measurement): boolean => m.kind === 'third_party' && !!m.mapped && (m.mapped.expected < 1 || m.mapped.matched / m.mapped.expected < REAL_APP_MIN_RECALL || !stable(m));
const recallOk = (m: Measurement): boolean => !!m.flaws && m.blind_key && m.flaws.planted >= 1 && m.flaws.found / m.flaws.planted >= L3_MIN_RECALL && m.flaws.false_findings === 0 && stable(m);

// The highest level the result supports for a scope (null: the whole pack). Levels build on each other, so a gap stops the climb.
export function supportedLevel(r: FixtureResult, scope: string | null = null): Level {
  const found = new Set(r.detect.found);
  if (!r.detect.expected.length || !r.detect.expected.every((x) => found.has(x))) return 'L0';
  if (!r.measurements.some(exact) || r.measurements.some(realAppShort)) return 'L1';
  if (!r.measurements.some(recallOk)) return 'L2';
  if (scope === null) return 'L3';
  const pr = r.proof.find((p) => p.scope === scope);
  return pr && pr.planted >= 1 && pr.proven === pr.planted && pr.false_proofs_fixed === 0 && pr.runs >= MIN_RUNS && pr.identical ? 'L4' : 'L3';
}

// The measurements the coverage table shows: what the map holds comes from the best exact measurement, the flaws from the best flaw
// measurement (one with a blind key and a pass first). They can be two different fixtures; the table says so.
export const mappedFrom = (r: FixtureResult): Measurement | null => r.measurements.find((m) => exact(m) && m.blind_key && m.mapped && m.kind !== 'third_party') ?? r.measurements.find((m) => exact(m) && m.kind !== 'third_party') ?? r.measurements.find((m) => exact(m)) ?? r.measurements.find((m) => m.mapped) ?? null;
export const flawsFrom = (r: FixtureResult): Measurement | null => r.measurements.find(recallOk) ?? r.measurements.find((m) => m.flaws) ?? null;

// The level a manifest claims for the whole pack and for each scope, as [scope or null, level] pairs.
export const claims = (m: PackManifest): [string | null, Level][] => [[null, m.level], ...(m.scopes ?? []).map((s): [string, Level] => [s.where, s.level])];
export const topLevel = (m: PackManifest): Level => claims(m).map((c) => c[1]).reduce((a, b) => (rank(b) > rank(a) ? b : a));
