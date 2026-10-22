// Stack packs (Phase 6a and 6b): the manifest validator rejects incomplete packs, every shipped pack passes, the levels follow from the
// recorded fixture results, and the README table is the generator's output.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { coverageMarkdown, coverageRows, README_END, README_START, readmeBlock, reportSection } from '../src/packs/coverage.ts';
import { isLevel, supportedLevel, type FixtureResult, type PackManifest } from '../src/packs/manifest.ts';
import { defaultEnv, validateAll, validatePack, type Env } from '../src/packs/validate.ts';
import { discover } from '../src/discover/discover.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const CLI = join(ROOT, 'src/cli.ts');
const env = defaultEnv();
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);

// A scratch tree that sees the engine's real files through links and has its own packs folder, so a test can break a copy of a pack.
function sandbox(): { root: string; env: Env; put(id: string, m: PackManifest, r?: FixtureResult | null): string } {
  const root = mkdtempSync(join(tmpdir(), 'hp-pack-'));
  for (const d of ['src', 'rules', 'test', 'detectors', 'checks']) if (existsSync(join(ROOT, d))) symlinkSync(join(ROOT, d), join(root, d));
  mkdirSync(join(root, 'packs'));
  return {
    root, env: { ...env, root },
    put(id, m, r) {
      const dir = join(root, 'packs', id);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'pack.json'), JSON.stringify(m, null, 2));
      if (r !== null) writeFileSync(join(dir, 'fixture-result.json'), JSON.stringify(r ?? read<FixtureResult>('go', 'fixture-result.json'), null, 2));
      return dir;
    },
  };
}
const read = <T>(id: string, file: string): T => JSON.parse(readFileSync(join(ROOT, 'packs', id, file), 'utf8')) as T;
const goPack = (over: Partial<PackManifest> = {}): PackManifest => ({ ...read<PackManifest>('go', 'pack.json'), ...over });
const codes = (m: PackManifest, r?: FixtureResult | null, tweak?: (e: Env) => void): string[] => {
  const s = sandbox();
  if (tweak) tweak(s.env);
  const dir = s.put(m.id, m, r);
  return validatePack(dir, s.env).issues.map((i) => i.code);
};

test('every pack in packs/ passes the validator', () => {
  const all = validateAll(undefined, env);
  assert.ok(all.length >= 8, 'the eight first wave packs are there');
  for (const c of all) assert.deepEqual(c.issues, [], `${c.manifest?.id}: ${JSON.stringify(c.issues)}`);
  for (const id of ['node-ts', 'python', 'supabase', 'firebase', 'go', 'rails', 'laravel', 'expo']) assert.ok(all.some((c) => c.manifest?.id === id), id);
});

test('the Go pack is the baseline for the rejection tests: it passes in the scratch tree too', () => {
  assert.deepEqual(codes(goPack()), []);
});

test('an install without a test folder (the npm package) skips the rule test files and the fixture folders, and the pack still passes', () => {
  assert.deepEqual(codes(goPack(), undefined, (e) => { rmSync(join(e.root, 'test'), { force: true }); }), []);
});

test('a pack with no manifest, or a manifest that is not JSON, is rejected', () => {
  const s = sandbox();
  mkdirSync(join(s.root, 'packs', 'empty'));
  assert.deepEqual(validatePack(join(s.root, 'packs', 'empty'), s.env).issues.map((i) => i.code), ['manifest_missing']);
  mkdirSync(join(s.root, 'packs', 'junk'));
  writeFileSync(join(s.root, 'packs', 'junk', 'pack.json'), '{ nope');
  assert.deepEqual(validatePack(join(s.root, 'packs', 'junk'), s.env).issues.map((i) => i.code), ['manifest_unreadable']);
});

test('a pack missing a part its level needs is rejected, one code per missing part', () => {
  const m = goPack();
  assert.ok(codes({ ...m, parts: { ...m.parts, extractors: [] } }).includes('part_missing'));
  assert.ok(codes({ ...m, parts: { ...m.parts, auth_patterns: undefined } }).includes('part_missing'));
  assert.ok(codes({ ...m, parts: { ...m.parts, detectors: [] } }).includes('part_missing'));
  const l3 = goPack({ level: 'L3' });
  const without = (k: keyof PackManifest['parts']): string[] => codes({ ...l3, parts: { ...l3.parts, [k]: [] } }, read<FixtureResult>('node-ts', 'fixture-result.json'));
  assert.ok(without('checks').includes('part_missing'));
  assert.ok(without('mapping').includes('part_missing'));
  const l4 = goPack({ level: 'L3', scopes: [{ where: 'Go with SQLite', level: 'L4' }] });
  assert.ok(codes(l4, read<FixtureResult>('node-ts', 'fixture-result.json')).includes('part_missing'), 'a scope at L4 needs a start recipe');
});

test('a rule without a test is rejected: no test files, a missing file, or a rule id with no ruleid and ok lines', () => {
  const m = goPack();
  const rule = m.parts.rules![0];
  assert.ok(codes({ ...m, parts: { ...m.parts, rules: [{ file: rule.file, tests: [] }] } }).includes('rule_without_test'));
  assert.ok(codes({ ...m, parts: { ...m.parts, rules: [{ file: rule.file, tests: ['test/fixtures/rules/does-not-exist.go'] }] } }).includes('file_missing'));
  // The Python fixture holds no lines for the Go rule ids.
  const wrongTests = codes({ ...m, parts: { ...m.parts, rules: [{ file: rule.file, tests: ['test/fixtures/rules/taint-python.py'] }] } });
  assert.ok(wrongTests.filter((c) => c === 'rule_without_test').length >= 2, wrongTests.join(','));
});

test('a pack with no fixture result is rejected, and so is one whose result is not shaped right', () => {
  assert.ok(codes(goPack(), null).includes('fixture_result_missing'));
  const r = read<FixtureResult>('go', 'fixture-result.json');
  assert.ok(codes(goPack(), { ...r, measurements: [] }).includes('fixture_result_invalid'));
  assert.ok(codes(goPack(), { ...r, pack: 'someone-else' }).includes('fixture_result_invalid'));
  assert.ok(codes(goPack(), { ...r, measured: 'yesterday' }).includes('fixture_result_invalid'));
  assert.ok(codes(goPack(), { ...r, measurements: [{ ...r.measurements[0], source: '' }] }).includes('fixture_result_invalid'));
  assert.ok(codes(goPack(), { ...r, measurements: [{ ...r.measurements[0], mapped: { what: 'entry points', expected: 3, matched: 9, extra: 0 } }] }).includes('fixture_result_invalid'));
  const m = goPack();
  assert.ok(codes({ ...m, fixture: { ...m.fixture, result: 'packs/go/nothing-here.json' } }).includes('fixture_result_missing'));
  assert.ok(codes({ ...m, fixture: { ...m.fixture, dir: 'test/fixtures/not-a-folder' } }).includes('fixture_missing'));
});

test('bad levels are rejected', () => {
  assert.ok(codes(goPack({ level: 'L9' as never })).includes('level'));
  assert.ok(codes(goPack({ level: undefined as never })).includes('level'));
  assert.ok(codes(goPack({ scopes: [{ where: 'Go with SQLite', level: 'LX' as never }] })).includes('level'));
  assert.ok(codes(goPack({ scopes: [{ where: 'Go with SQLite', level: 'L1' }] })).includes('level'), 'a scope must reach a higher level than the pack');
  assert.ok(codes(goPack({ scopes: [{ where: '', level: 'L4' }] })).includes('level'));
  assert.ok(isLevel('L4') && !isLevel('L5') && !isLevel(4));
});

test('a pack that claims more than its recorded result supports is rejected', () => {
  const m = goPack({ level: 'L3' });
  const c = codes(m, undefined, undefined);
  assert.ok(c.includes('level_too_high'), c.join(','));
  const r = read<FixtureResult>('go', 'fixture-result.json');
  // Same pack at L2 with one entry point missed on the fixture: L1 only.
  const missed: FixtureResult = { ...r, measurements: [{ ...r.measurements[0], mapped: { what: 'entry points', expected: 12, matched: 11, extra: 0 } }] };
  assert.ok(codes(goPack(), missed).includes('level_too_high'));
  const extra: FixtureResult = { ...r, measurements: [{ ...r.measurements[0], mapped: { what: 'entry points', expected: 12, matched: 12, extra: 1 } }] };
  assert.ok(codes(goPack(), extra).includes('level_too_high'));
  const unstable: FixtureResult = { ...r, measurements: [{ ...r.measurements[0], stability: { runs: 3, identical: false } }] };
  assert.ok(codes(goPack(), unstable).includes('level_too_high'));
  const notDetected: FixtureResult = { ...r, detect: { expected: ['go'], found: [] } };
  assert.ok(codes(goPack({ level: 'L1' }), notDetected).includes('level_too_high'));
});

test('an unknown detector, check or recipe is rejected; a Pro part is skipped only where the Pro folders are absent', () => {
  const m = goPack();
  assert.ok(codes({ ...m, parts: { ...m.parts, detectors: ['go', 'no-such-framework'] } }).includes('detector_unknown'));
  assert.ok(codes({ ...m, parts: { ...m.parts, checks: [...m.parts.checks!, { id: 'check.map.nothing' }] } }).includes('check_unknown'));
  const l4 = goPack({ level: 'L2', scopes: [{ where: 'Go with SQLite', level: 'L4' }], parts: { ...m.parts, start_recipe: { file: 'src/prove/recipe.ts', recipe: 'cobol' } } });
  assert.ok(codes(l4).includes('recipe_unknown'));
  const proCheck = { ...m, parts: { ...m.parts, checks: [...m.parts.checks!, { id: 'check.map.pro-only-thing', pro: true }] } };
  assert.ok(codes(proCheck, undefined, (e) => { e.hasPro = true; }).includes('check_unknown'), 'a Pro check that should be there is missing');
  assert.ok(!codes(proCheck, undefined, (e) => { e.hasPro = false; }).includes('check_unknown'), 'a Pro check is skipped in an edition without the Pro folders');
  const proFile = { ...m, parts: { ...m.parts, extractors: [...m.parts.extractors!, { file: 'pro-only/nothing.ts', pro: true }] } };
  assert.ok(codes(proFile, undefined, (e) => { e.hasPro = true; }).includes('file_missing'));
  assert.ok(!codes(proFile, undefined, (e) => { e.hasPro = false; }).includes('file_missing'));
});

test('the id must match the folder and be written as words joined with hyphens', () => {
  const s = sandbox();
  const dir = s.put('go', goPack({ id: 'Not Go' }));
  assert.ok(validatePack(dir, s.env).issues.some((i) => i.code === 'id'));
  const dir2 = s.put('other', goPack());
  assert.ok(validatePack(dir2, s.env).issues.some((i) => i.code === 'id' && /does not match the folder/.test(i.message)));
});

test('supportedLevel climbs one level at a time and stops at the first gap', () => {
  const base = read<FixtureResult>('node-ts', 'fixture-result.json');
  assert.equal(supportedLevel(base, null), 'L3');
  assert.equal(supportedLevel(base, 'Express with SQLite'), 'L4');
  assert.equal(supportedLevel(base, 'Fastify with Postgres'), 'L3', 'a scope with no proof stays at L3');
  const blind = base.measurements.find((m) => m.blind_key)!;
  assert.equal(supportedLevel({ ...base, measurements: [{ ...blind, blind_key: false }] }, null), 'L2', 'without a blind key, L2');
  assert.equal(supportedLevel({ ...base, measurements: [{ ...blind, flaws: { planted: 30, found: 14, false_findings: 0 } }] }, null), 'L2', 'recall under one half');
  assert.equal(supportedLevel({ ...base, measurements: [{ ...blind, flaws: { planted: 30, found: 15, false_findings: 0 } }] }, null), 'L3', 'recall of exactly one half');
  assert.equal(supportedLevel({ ...base, measurements: [{ ...blind, flaws: { planted: 30, found: 29, false_findings: 1 } }] }, null), 'L2', 'one false finding');
  assert.equal(supportedLevel({ ...base, proof: [{ ...base.proof[0], proven: 3 }] }, 'Express with SQLite'), 'L3', 'a flaw not proven');
  assert.equal(supportedLevel({ ...base, proof: [{ ...base.proof[0], false_proofs_fixed: 1 }] }, 'Express with SQLite'), 'L3', 'a proof on the fixed copy');
  assert.equal(supportedLevel({ ...base, proof: [{ ...base.proof[0], runs: 2 }] }, 'Express with SQLite'), 'L3', 'fewer than three runs');
  assert.equal(supportedLevel({ ...base, detect: { expected: ['express'], found: [] } }, null), 'L0');
  const real = { name: 'a real app', kind: 'third_party' as const, blind_key: true, source: 'test', flaws: null, stability: { runs: 3, identical: true } };
  assert.equal(supportedLevel({ ...base, measurements: [...base.measurements, { ...real, mapped: { what: 'entry points (sample)', expected: 25, matched: 23, extra: 0 } }] }, null), 'L3', '23 of 25 is 92 percent');
  assert.equal(supportedLevel({ ...base, measurements: [...base.measurements, { ...real, mapped: { what: 'entry points (sample)', expected: 25, matched: 22, extra: 0 } }] }, null), 'L1', 'a real app under 90 percent holds the pack at L1');
  assert.equal(supportedLevel({ ...base, measurements: [...base.measurements, { ...real, stability: { runs: 3, identical: false }, mapped: { what: 'entry points (sample)', expected: 25, matched: 25, extra: 0 } }] }, null), 'L1', 'a real app with unstable output');
});

test('first wave levels are the honest ones: Go, Rails, Laravel and Expo are L2, from synthetic fixtures plus a sample of one real app each', () => {
  const rows = new Map(coverageRows(validateAll(undefined, env)).map((r) => [r.id, r]));
  for (const id of ['go', 'rails', 'laravel', 'expo']) {
    assert.equal(rows.get(id)!.level, 'L2', id);
    assert.ok(!rows.get(id)!.onlySynthetic, id);
    assert.match(rows.get(id)!.fixture, /synthetic/, id);
    assert.match(rows.get(id)!.fixture, /no blind key/, id);
    assert.match(rows.get(id)!.fixture, /route sample on 1 real app/, id);
    assert.match(rows.get(id)!.limits.join(' '), /not measured on a real application/i, id);
  }
  assert.equal(rows.get('node-ts')!.level, 'L3');
  assert.deepEqual(rows.get('node-ts')!.scopes, [{ where: 'Express with SQLite', level: 'L4' }]);
  assert.equal(rows.get('firebase')!.level, 'L2', 'hosted, and no blind measurement');
  assert.equal(rows.get('supabase')!.level, 'L3');
});

test('the coverage table never shows a level above what the recorded result supports', () => {
  for (const r of coverageRows(validateAll(undefined, env))) {
    const rank = ['L0', 'L1', 'L2', 'L3', 'L4'];
    assert.ok(rank.indexOf(r.level) <= rank.indexOf(r.supported), `${r.id} shows ${r.level} and the result supports ${r.supported}`);
  }
  // And the validator is what stops a pack that tries: a table row cannot be made for a pack that fails.
  const s = sandbox();
  const dir = s.put('go', goPack({ level: 'L4', scopes: undefined }));
  assert.ok(validatePack(dir, s.env).issues.some((i) => i.code === 'level_too_high'));
});

test('the README coverage table is the generator output', () => {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
  const a = readme.indexOf(README_START);
  const b = readme.indexOf(README_END);
  assert.ok(a > 0 && b > a, 'markers present');
  assert.equal(readme.slice(a, b + README_END.length), readmeBlock(coverageRows(validateAll(undefined, env))), 'run: node scripts/sync-readme-coverage.mjs (in the working copy)');
});

test('the README table uses plain words: no dash punctuation and no claim without a level', () => {
  const md = coverageMarkdown(coverageRows(validateAll(undefined, env)));
  assert.doesNotMatch(md, new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]| - | -- `));
  for (const line of md.split('\n').slice(2)) assert.match(line, /\| L[0-4] /);
});

test('the report section lists the packs for the stacks found, and says L0 for the rest', () => {
  const fx = join(ROOT, 'test/fixtures/map-more/fail/go');
  const lines = reportSection(discover(fx), coverageRows(validateAll(undefined, env))).join('\n');
  assert.match(lines, /## Stack coverage/);
  assert.match(lines, /\| Go \| L2 Mapped \|/);
  assert.doesNotMatch(lines, /Measured on synthetic fixtures only: Go/);
  assert.match(lines, /Also checked on real applications, by a sample of their route registrations only .*: Go\./);
  const none = reportSection(discover(join(ROOT, 'test/fixtures/stacks/unknown-stack')), coverageRows(validateAll(undefined, env))).join('\n');
  assert.match(none, /No stack in this repository has a pack beyond L0/);
});

test('hullproof pack validate, list and table: exit codes and output', () => {
  const run = (...a: string[]) => spawnSync(process.execPath, [CLI, 'pack', ...a], { encoding: 'utf8', cwd: ROOT });
  const v = run('validate');
  assert.equal(v.status, 0, v.stdout + v.stderr);
  assert.match(v.stdout, /ok    node-ts L3/);
  assert.match(v.stdout, /\d+ of \d+ packs pass/);
  assert.match(run('list').stdout, /^go\tL2 Mapped\tGo$/m);
  assert.match(run('table').stdout, /\| Go \| L2 Mapped \|/);
  const s = sandbox();
  const dir = s.put('go', goPack({ level: 'L3' }));
  const bad = spawnSync(process.execPath, [CLI, 'pack', 'validate', dir, '--root', s.root], { encoding: 'utf8', cwd: ROOT });
  assert.equal(bad.status, 1, bad.stdout + bad.stderr);
  assert.match(bad.stdout, /FAIL  go/);
  assert.match(bad.stdout, /level_too_high/);
  assert.equal(run('nonsense').status, 2);
  assert.equal(run('validate', '/no/such/folder').status, 2);
  assert.equal(run('validate', '--bogus').status, 2);
});

test('the pack files carry no dash punctuation and no personal name', () => {
  for (const c of validateAll(undefined, env)) {
    const text = [join(c.dir, 'pack.json'), join(c.dir, 'fixture-result.json')].map((f) => readFileSync(f, 'utf8')).join('\n');
    assert.doesNotMatch(text, DASHES, c.dir);
    assert.doesNotMatch(text, new RegExp(['\\bJ' + 'T\\b', 'Jos' + 'hua', 'Theoph' + 'ilus'].join('|')), c.dir);
  }
  void cpSync;
});
