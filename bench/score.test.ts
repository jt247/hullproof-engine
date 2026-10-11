// node --test bench/score.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadClasses, markdownUnits, parseKey, parseOutput, resolvePath, score, stability, verdictOf } from './score.ts';

const KEY = `# Key

## Free edition findings

| # | Flaw | Where | Hullproof IDs (severity, edition) | Caught by |
|---|------|-------|------|------|
| F01 | SQL injection in search. | \`src/app/api/search/route.ts:10\` | SEC-API-017 (BLOCKER, free) | Free |
| F02 | Token logged at login. | \`src/app/api/auth/login/route.ts:24\` | SEC-LOG-001 (CRITICAL, free) | Free |

## Pro only findings

| # | Flaw | Where | Hullproof IDs (severity, edition) | Caught by |
|---|------|-------|------|------|
| P01 | No login rate limit. | \`src/app/api/auth/login/route.ts:17\`<br>\`src/middleware.ts:3\` | Pro edition requirements | Pro only |
`;
const CLASSES = loadClasses(JSON.stringify({
  flaws: { F01: { patterns: ['SQL'] }, F02: { patterns: ['token[^.\\n]{0,30}log'] }, P01: { patterns: ['rate[- ]limit'] } },
  not_planted: [{ id: 'NP1', label: 'hashing is fine', files: ['src/lib/auth.ts'], patterns: ['weak hash'] }],
}));
const FLAWS = parseKey(KEY, CLASSES);
const run = (text: string) => score('t', text, FLAWS, CLASSES.notPlanted);
const status = (text: string, id: string) => run(text).flaws.find((f) => f.id === id)!.status;

test('parseKey reads ids, sections, files, lines and SEC ids from the demo key format', () => {
  assert.deepEqual(FLAWS.map((f) => [f.id, f.section]), [['F01', 'free'], ['F02', 'free'], ['P01', 'pro']]);
  assert.deepEqual(FLAWS[2].files, ['src/app/api/auth/login/route.ts', 'src/middleware.ts']);
  assert.deepEqual(FLAWS[2].lines['src/middleware.ts'], [3]);
  assert.deepEqual(FLAWS[0].secIds, ['SEC-API-017']);
});

test('parseKey refuses a key with no flaw rows', () => {
  assert.throws(() => parseKey('# nothing here', CLASSES), /no flaw rows/);
});

test('resolvePath needs a unique suffix on a segment boundary', () => {
  const known = ['src/app/api/search/route.ts', 'src/app/api/auth/login/route.ts'];
  assert.equal(resolvePath('route.ts', known), null);
  assert.equal(resolvePath('search/route.ts', known), 'src/app/api/search/route.ts');
  assert.equal(resolvePath('h/route.ts', known), null);
  assert.equal(resolvePath('./src/app/api/search/route.ts', known), 'src/app/api/search/route.ts');
});

test('FOUND needs the flaw file and the defect class in the same finding', () => {
  assert.equal(status('- SQL injection in `api/search/route.ts:10`', 'F01'), 'FOUND');
  assert.equal(status('- SEC-API-017 at `src/app/api/search/route.ts:10`', 'F01'), 'FOUND');
  assert.equal(status('- The search route is slow at `api/search/route.ts:10`', 'F01'), 'MISSED');
});

test('the file and the class must sit in the same unit', () => {
  assert.equal(status('- Slow page at `api/search/route.ts:10`\n- SQL injection somewhere', 'F01'), 'PARTIAL');
});

test('PARTIAL is the class without any file the key names; a finding on another key file does not count', () => {
  assert.equal(status('- The session token is logged at login', 'F02'), 'PARTIAL');
  assert.equal(status('- The session token is logged in `src/app/login/page.tsx:3`', 'F02'), 'PARTIAL');
  assert.equal(status('- SQL text is built in `api/auth/login/route.ts:24`', 'F01'), 'MISSED');
});

test('a routed lead with file and class is PARTIAL, never FOUND', () => {
  assert.equal(status('- NEEDS DYNAMIC TEST | rate limit on `api/auth/login/route.ts:17`', 'P01'), 'PARTIAL');
  assert.equal(status('### Leads (routed, never rated)\n\n- rate limit missing at `src/middleware.ts:3`', 'P01'), 'PARTIAL');
});

test('settled rows and skipped sections are not findings', () => {
  assert.equal(status('- SEC-API-017 | NOT APPLICABLE | `api/search/route.ts`', 'F01'), 'MISSED');
  assert.equal(status('## PASSED CONTROLS\n\n- SQL injection guarded at `api/search/route.ts:10`', 'F01'), 'MISSED');
  assert.equal(status('**Fix order:**\n1. Fix SQL injection in `api/search/route.ts`', 'F01'), 'MISSED');
});

test('a heading that names a finding id makes one unit of its whole block', () => {
  const md = '# BLOCKERS\n\n### F-07: Search query\n\n- Requirement: SEC-API-017\n- Location: `src/app/api/search/route.ts:10`\n\n### F-08: Next\n';
  const units = markdownUnits(md, ['src/app/api/search/route.ts']);
  assert.equal(units.length, 2);
  assert.equal(status(md, 'F01'), 'FOUND');
});

test('fenced code is skipped', () => {
  assert.equal(status('```\nSQL injection api/search/route.ts\n```', 'F01'), 'MISSED');
});

test('a findings record is read from its block: fail is a finding, routed a lead, refuted ignored', () => {
  const rec = (kind: string, file: string, ids: string[], title: string) => ({ kind, sec_ids: ids, title, evidence: [{ file, line: 1, note: 'n' }] });
  const block = (records: object[]) => '# Findings record\n\n```hullproof-findings\n' + JSON.stringify({ schema_version: '1.0.0', records }) + '\n```\n';
  assert.equal(status(block([rec('fail', 'src/app/api/search/route.ts', ['SEC-API-017'], 'x')]), 'F01'), 'FOUND');
  assert.equal(status(block([rec('routed', 'src/app/api/search/route.ts', ['SEC-API-017'], 'x')]), 'F01'), 'PARTIAL');
  assert.equal(status(block([rec('refuted', 'src/app/api/search/route.ts', ['SEC-API-017'], 'x')]), 'F01'), 'MISSED');
  const asJson = block([rec('fail', 'src/app/api/search/route.ts', ['SEC-API-017'], 'x')]).replace('hullproof-findings', 'json');
  assert.equal(parseOutput(asJson, ['src/app/api/search/route.ts'])[0].kind, 'finding');
});

test('line_hit is true only within three lines of a key line', () => {
  assert.equal(run('- SQL injection `api/search/route.ts:12`').flaws[0].line_hit, true);
  assert.equal(run('- SQL injection `api/search/route.ts:40`').flaws[0].line_hit, false);
});

test('precision counts a finding that matches only a not planted item as a flagged false positive', () => {
  const s = run('- SQL injection at `api/search/route.ts:10`\n- weak hash in `src/lib/auth.ts:4`\n- something else at `src/lib/other.ts:1`');
  assert.equal(s.precision.true_positive_units, 1);
  assert.equal(s.precision.flagged_false_positive_units, 1);
  assert.equal(s.precision.unmatched_units, 1);
  assert.equal(s.precision.precision_flagged, 0.5);
  assert.deepEqual(s.precision.not_planted_hit, ['NP1']);
});

test('verdictOf reads the first verdict word', () => {
  assert.equal(verdictOf('Verdict: NOT READY'), 'NOT READY');
  assert.equal(verdictOf('nothing'), 'none');
});

test('stability counts flaws with one status in every run and checks the verdict', () => {
  const a = run('Verdict: NOT READY\n\n- SQL injection `api/search/route.ts:10`');
  const b = run('Verdict: NOT READY\n\n- SQL injection somewhere');
  const st = stability([a, b]);
  assert.equal(st.total_flaws, 3);
  assert.equal(st.stable_flaws, 2);
  assert.deepEqual(st.unstable, ['F01']);
  assert.equal(st.verdict_stable, true);
  assert.equal(stability([a, run('no verdict here')]).verdict_stable, false);
});

test('same input gives byte identical output', () => {
  const text = '- SQL injection `api/search/route.ts:10`\n- token is logged';
  assert.equal(JSON.stringify(run(text)), JSON.stringify(run(text)));
});
