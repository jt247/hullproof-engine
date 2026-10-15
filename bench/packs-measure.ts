// Measures a stack pack on its fixture and writes packs/<id>/fixture-result.json (Phase 6).
//   node bench/packs-measure.ts [--write] [--date YYYY-MM-DD] [pack id ...]
// Internal: it reads fixtures that are not all in the public export. The answer key is packs/<id>/answer-key.json for a synthetic fixture
// whose key lives in the repository, or ../bench-targets/answer-keys/<id>.json (outside the repository, local only) for a blind key.
// What it computes: the entry points (or tables and rules) the map holds for the fixture's stacks against the key, the planted flaws the
// free map checks find on the fixture, the findings they report on the fixed copy, and whether three fresh runs give the same bytes.
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeContext } from '../src/checks/context.ts';
import { getMap } from '../src/checks/map/shared.ts';
import { loadChecks, runChecks } from '../src/checks/run.ts';
import { PRO_MAP_CHECKS } from '../src/checks/pro-map.ts';
import { discover } from '../src/discover/discover.ts';
import type { FixtureResult, Measurement, PackManifest } from '../src/packs/manifest.ts';
import { stableJson } from '../src/util.ts';
import { ENGINE_VERSION } from '../src/version.ts';
import type { CodeMap } from '../src/types/index.ts';

export const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const OUTSIDE_KEYS = join(ROOT, '../bench-targets/answer-keys');

export interface Key {
  pack: string;
  fail_dir: string; pass_dir: string;                     // relative to the engine root
  stacks: string[];                                       // sub folders of the fixture that belong to this pack
  detect_expected: string[];                              // stack ids discovery must find in those folders
  mapped_what: 'entry points' | 'tables' | 'rules';
  mapped: string[];                                       // what the map must hold for these stacks (see facts())
  protections?: Record<string, string[]>;                // entry points only: what must protect each one (enforced, medium or high confidence), by the same text as mapped
  flaws: { name?: string; check: string | string[]; stack: string; file?: string; note?: string; pro?: boolean }[]; // planted flaws: one of these checks must fail in this stack of the fixture (in a file whose path holds `file` and with a note that holds `note`, when given); pro: only a Pro check can find it
  recorded?: Measurement[];                               // measurements taken on other apps, typed from their reports
  proof?: FixtureResult['proof'];
  notes?: string[];
}

export const keyPaths = (m: PackManifest): { kind: 'in_repo' | 'outside_repo'; path: string }[] => [
  ...(m.fixture.answer_keys.includes('in_repo') ? [{ kind: 'in_repo' as const, path: join(ROOT, 'packs', m.id, 'answer-key.json') }] : []),
  ...(m.fixture.answer_keys.includes('outside_repo') ? [{ kind: 'outside_repo' as const, path: join(OUTSIDE_KEYS, `${m.id}.json`) }] : []),
];
export const loadKeys = (m: PackManifest): { kind: 'in_repo' | 'outside_repo'; key: Key }[] => keyPaths(m).filter((k) => existsSync(k.path)).map((k) => ({ kind: k.kind, key: JSON.parse(readFileSync(k.path, 'utf8')) as Key }));

// The key lists the access control protections only; input validation, rate limits and audit records are not compared.
const AUTHZ = new Set(['session_read', 'role_check', 'owner_filter', 'signature_verify']);
const inStack = (file: string, stacks: string[]): boolean => stacks.some((s) => s === '.' || file === s || file.startsWith(`${s}/`));
const PRO_IDS = new Set(PRO_MAP_CHECKS.map((c) => c.id));
// The checks a pack lists, without the Pro only ones: the measurement is the same in both editions.
const packChecks = (m: PackManifest, withPro = false) => { const want = new Set((m.parts.checks ?? []).filter((c) => withPro || (!c.pro && !PRO_IDS.has(c.id))).map((c) => c.id)); return loadChecks().filter((c) => want.has(c.id)); };

function facts(map: CodeMap, key: Key): string[] {
  if (key.mapped_what === 'entry points') return map.entry_points.filter((e) => inStack(e.file, key.stacks)).map((e) => `${e.kind} ${e.method ?? '-'} ${e.path ?? e.name}`).sort();
  if (key.mapped_what === 'tables') return (map.config.supabase?.tables ?? []).filter((t) => inStack(t.file, key.stacks)).map((t) => `table ${t.name} rls=${t.rls_enabled} policies=${t.policies.length} grants=${t.grants.length}`).sort();
  return (map.config.firebase?.rules ?? []).filter((r) => inStack(r.file, key.stacks)).map((r) => `rule ${r.service} ${r.path} ${r.ops.join(',')}`).sort();
}

function pass(dir: string, m: PackManifest, withPro = false): { map: CodeMap; checks: string; fails: { id: string; file: string; note: string }[] } {
  const abs = join(ROOT, dir);
  const stack = discover(abs);
  const ctx = makeContext(abs, stack, [], null);
  const map = getMap(ctx);
  const res = runChecks(ctx, packChecks(m, withPro));
  const fails = res.results.filter((r) => r.result === 'FAIL').flatMap((r) => r.evidence.map((e) => ({ id: r.check_id.replace(/^check\.(?:map\.)?/, ''), file: e.file, note: e.note })));
  return { map, checks: stableJson(res), fails };
}

export function measure(m: PackManifest, key: Key, kind: 'in_repo' | 'outside_repo'): { measurement: Measurement; detect: { expected: string[]; found: string[] }; diff: { missing: string[]; extra: string[]; wrong_protections: string[]; missed_flaws: string[]; false_findings: string[]; with_pro?: string[] } } {
  const runs = [pass(key.fail_dir, m), pass(key.fail_dir, m), pass(key.fail_dir, m)];
  const fixed = [pass(key.pass_dir, m), pass(key.pass_dir, m), pass(key.pass_dir, m)];
  const bytes = (p: ReturnType<typeof pass>): string => stableJson(p.map) + p.checks;
  const identical = runs.every((r) => bytes(r) === bytes(runs[0])) && fixed.every((r) => bytes(r) === bytes(fixed[0]));

  const want = key.mapped.slice().sort();
  const have = facts(runs[0].map, key);
  const left = have.slice();
  const missing: string[] = [];
  for (const w of want) { const i = left.indexOf(w); if (i < 0) missing.push(w); else left.splice(i, 1); }
  // An entry point whose protections differ from the key counts as not matched.
  const wrongProt: string[] = [];
  if (key.protections && key.mapped_what === 'entry points') {
    for (const [sig, kinds] of Object.entries(key.protections)) {
      const eps = runs[0].map.entry_points.filter((e) => inStack(e.file, key.stacks) && `${e.kind} ${e.method ?? '-'} ${e.path ?? e.name}` === sig);
      for (const e of eps) {
        const got = [...new Set(e.protections.filter((p) => p.confidence !== 'low' && p.enforced !== false && AUTHZ.has(p.kind)).map((p) => p.kind))].sort();
        if (got.join(',') !== kinds.slice().sort().join(',')) wrongProt.push(`${sig}: key says [${kinds.join(',')}], the map says [${got.join(',')}]`);
      }
    }
  }
  const checksOf = (f: Key['flaws'][number]): string[] => (Array.isArray(f.check) ? f.check : [f.check]);
  const flawsFound = key.flaws.filter((f) => runs[0].fails.some((x) => checksOf(f).includes(x.id) && inStack(x.file, [f.stack]) && (!f.file || x.file.includes(f.file)) && (!f.note || x.note.includes(f.note))));
  const missedFlaws = key.flaws.filter((f) => !flawsFound.includes(f)).map((f) => `${f.name ?? checksOf(f).join(' or ')} in ${f.stack}`);
  const falseFindings = fixed[0].fails.filter((x) => inStack(x.file, key.stacks)).map((x) => `${x.id} in ${x.file}`);

  const found = new Set<string>();
  for (const s of key.stacks) {
    const st = discover(join(ROOT, key.fail_dir, s));
    for (const cat of [st.languages, st.frameworks, st.mobile, st.data_stores, st.auth]) for (const i of cat) found.add(i.id);
  }
  // With the Pro checks, when this tree has them: printed for the report, never written to the result file.
  let withPro: string[] | undefined;
  if (PRO_IDS.size > 0 && (m.parts.checks ?? []).some((c) => c.pro)) {
    const p = pass(key.fail_dir, m, true);
    const q = pass(key.pass_dir, m, true);
    const got = key.flaws.filter((f) => p.fails.some((x) => checksOf(f).includes(x.id) && inStack(x.file, [f.stack]) && (!f.file || x.file.includes(f.file)) && (!f.note || x.note.includes(f.note))));
    withPro = [`with the Pro checks: flaws ${got.length}/${key.flaws.length}, findings on the fixed copy ${q.fails.filter((x) => inStack(x.file, key.stacks)).length}`, ...key.flaws.filter((f) => !got.includes(f)).map((f) => `missed with Pro: ${f.name ?? checksOf(f).join(' or ')}`)];
  }
  return {
    measurement: {
      name: `${key.fail_dir} and ${key.pass_dir}`, kind: 'synthetic', blind_key: kind === 'outside_repo',
      source: `node bench/packs-measure.ts ${m.id} (key ${kind === 'in_repo' ? `packs/${m.id}/answer-key.json` : 'kept outside the repository'})`,
      mapped: { what: key.mapped_what, expected: want.length, matched: want.length - missing.length - wrongProt.length, extra: left.length },
      flaws: { planted: key.flaws.length, found: flawsFound.length, false_findings: falseFindings.length },
      stability: { runs: 3, identical },
    },
    detect: { expected: key.detect_expected.slice().sort(), found: [...found].sort() },
    diff: { missing, extra: left, wrong_protections: wrongProt, missed_flaws: missedFlaws, false_findings: falseFindings, with_pro: withPro },
  };
}

export function buildResult(m: PackManifest, keys: { kind: 'in_repo' | 'outside_repo'; key: Key }[], date: string, previous: FixtureResult | null): { result: FixtureResult; lines: string[] } {
  const measurements: Measurement[] = [];
  const lines: string[] = [];
  let detect: { expected: string[]; found: string[] } = { expected: [], found: [] };
  const recorded: Measurement[] = [];
  const proof: FixtureResult['proof'] = [];
  const notes: string[] = [];
  for (const { kind, key } of keys) {
    const x = measure(m, key, kind);
    measurements.push(x.measurement);
    detect = { expected: [...new Set([...detect.expected, ...x.detect.expected])].sort(), found: [...new Set([...detect.found, ...x.detect.found])].sort() };
    recorded.push(...(key.recorded ?? []));
    proof.push(...(key.proof ?? []));
    notes.push(...(key.notes ?? []));
    const me = x.measurement;
    lines.push(`${m.id} [${kind}]: mapped ${me.mapped!.matched}/${me.mapped!.expected} (extra ${me.mapped!.extra}), flaws ${me.flaws!.found}/${me.flaws!.planted}, false findings ${me.flaws!.false_findings}, identical ${me.stability.identical}`);
    for (const [k, v] of Object.entries(x.diff)) if (v && v.length) lines.push(`  ${k}: ${v.join(' | ')}`);
  }
  // A key that is not on this machine (the blind key is local only) keeps the measurement recorded earlier.
  const kept = m.fixture.answer_keys.includes('outside_repo') && !keys.some((k) => k.kind === 'outside_repo');
  if (previous && kept) for (const p of previous.measurements) if ((p.kind === 'synthetic' && p.blind_key) || p.kind === 'third_party') measurements.push(p);
  if (previous && kept) { for (const p of previous.proof) if (!proof.some((q) => q.scope === p.scope)) proof.push(p); detect = { expected: [...new Set([...detect.expected, ...previous.detect.expected])].sort(), found: [...new Set([...detect.found, ...previous.detect.found])].sort() }; }
  return { lines, result: { schema: 1, pack: m.id, measured: date, engine: ENGINE_VERSION, detect, measurements: [...measurements, ...recorded], proof, notes: [...new Set(notes)] } };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const write = args.includes('--write');
  const di = args.indexOf('--date');
  const date = di >= 0 ? args[di + 1] : new Date().toISOString().slice(0, 10);
  const ids = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--date');
  for (const id of ids.length ? ids : readdirSync(join(ROOT, 'packs')).sort()) {
    const mf = join(ROOT, 'packs', id, 'pack.json');
    if (!existsSync(mf)) continue;
    const m = JSON.parse(readFileSync(mf, 'utf8')) as PackManifest;
    const keys = loadKeys(m);
    if (!keys.length) { process.stdout.write(`${id}: NOT RUN, no answer key found (${keyPaths(m).map((k) => k.path).join(', ')})\n`); continue; }
    const out = join(ROOT, m.fixture.result);
    const previous = existsSync(out) ? (JSON.parse(readFileSync(out, 'utf8')) as FixtureResult) : null;
    const { result, lines } = buildResult(m, keys, di >= 0 ? date : previous?.measured ?? date, previous);
    for (const l of lines) process.stdout.write(l + '\n');
    if (write) writeFileSync(out, stableJson(result));
  }
}
