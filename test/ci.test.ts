// hullproof ci: exit codes, the four output files, SARIF structure, byte identical output over three separate processes, and the
// refusals. The scan runs the real scanners (Semgrep, Gitleaks), so the tests that need them skip themselves when they are missing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { checkSarif } from '../src/ci/sarif-check.ts';
import { ciVerdict, COMMENT_MARKER, prComment } from '../src/ci/comment.ts';
import { buildSarif, uriOf } from '../src/ci/sarif.ts';
import { loadKit } from '../src/report/kit.ts';
import type { FailRecord, FindingsFile } from '../src/types/index.ts';
import { KIT, KIT_SKIP } from './helpers/kit.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const APP = fileURLToPath(new URL('./fixtures/scanners/app/', import.meta.url));
const have = (bin: string): boolean => spawnSync(bin, ['--version'], { encoding: 'utf8' }).status === 0;
const SKIP = KIT_SKIP || (have('semgrep') && have('gitleaks') ? false : 'semgrep or gitleaks not installed');
const G = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' };
const git = (d: string, ...a: string[]): void => { assert.equal(spawnSync('git', ['-C', d, ...a], { env: G }).status, 0, a.join(' ')); };
const ci = (...args: string[]) => spawnSync(process.execPath, [CLI, 'ci', ...args], { encoding: 'utf8', env: { ...process.env, HULLPROOF_KIT: KIT } });
const sha = (p: string): string => createHash('sha256').update(readFileSync(p)).digest('hex');
const FILES = ['findings.json', 'report.md', 'results.sarif', 'pr-comment.md'];

function repoWith(files: Record<string, string> | 'planted'): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-ci-'));
  if (files === 'planted') cpSync(APP, dir, { recursive: true });
  else for (const [n, c] of Object.entries(files)) { mkdirSync(join(dir, n, '..'), { recursive: true }); writeFileSync(join(dir, n), c); }
  git(dir, 'init', '-q'); git(dir, 'add', '-A'); git(dir, 'commit', '-q', '-m', 'init');
  return dir;
}

test('planted BLOCKER: exit 1, four files, valid SARIF, byte identical over three processes', { skip: SKIP }, () => {
  const repo = repoWith('planted');
  // Outputs go outside the repository: the scanners read untracked files in the working tree, so files left inside it would change the next scan.
  const outside = mkdtempSync(join(tmpdir(), 'hp-ci-out-'));
  const sums: string[][] = [];
  for (let i = 0; i < 3; i++) {
    const art = join(outside, `art${i}`);
    const r = ci(repo, '--artifacts', art, '--out', join(outside, 'hp'));
    assert.equal(r.status, 1, r.stderr + r.stdout);
    assert.match(r.stdout, /FAILED, a blocking finding is open/);
    sums.push(FILES.map((f) => sha(join(art, f))));
  }
  assert.deepEqual(sums[1], sums[0]);
  assert.deepEqual(sums[2], sums[0]);
  const art = join(outside, 'art0');
  const sarif = JSON.parse(readFileSync(join(art, 'results.sarif'), 'utf8'));
  assert.deepEqual(checkSarif(sarif), []);
  assert.ok(sarif.runs[0].results.some((x: { ruleId: string; level: string }) => x.ruleId === 'SEC-API-017' && x.level === 'error'));
  const findings = JSON.parse(readFileSync(join(art, 'findings.json'), 'utf8')) as FindingsFile;
  assert.equal(findings.schema_version, '1.1.0');
  assert.match(readFileSync(join(art, 'pr-comment.md'), 'utf8'), new RegExp(`^${COMMENT_MARKER}\\n## Hullproof: \\d+ blocking finding`));
  assert.match(readFileSync(join(art, 'report.md'), 'utf8'), /^# Hullproof report/);
  // The same files are in the commit folder of the scan.
  const commit = spawnSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8', env: G }).stdout.trim();
  for (const f of FILES) assert.equal(sha(join(outside, 'hp', commit, f)), sha(join(art, f)));
});

test('the default output folder inside the repository does not change the next run', { skip: SKIP }, () => {
  const repo = repoWith('planted');
  const sums: string[][] = [];
  for (let i = 0; i < 3; i++) {
    const r = ci(repo);
    assert.equal(r.status, 1, r.stderr);
    sums.push(FILES.map((f) => sha(join(repo, '.hullproof/ci', f))));
  }
  assert.deepEqual(sums[1], sums[0]);
  assert.deepEqual(sums[2], sums[0]);
});

test('--fail-on picks the level, none reports only; a clean repository exits 0', { skip: SKIP }, () => {
  const planted = repoWith('planted');
  assert.equal(ci(planted, '--fail-on', 'none').status, 0);
  assert.equal(ci(planted, '--fail-on', 'low').status, 1);
  const clean = repoWith({ 'README.md': '# hello\n', 'index.js': 'export const add = (a, b) => a + b;\n' });
  const r = ci(clean);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /PASSED/);
  assert.match(readFileSync(join(clean, '.hullproof/ci/pr-comment.md'), 'utf8'), /no blocking findings/);
  assert.deepEqual(checkSarif(JSON.parse(readFileSync(join(clean, '.hullproof/ci/results.sarif'), 'utf8'))), []);
});

test('bad input exits 2 and writes nothing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-ci-bad-'));
  for (const args of [[dir, '--fail-on', 'huge'], [dir, '--edition', 'gold'], [dir, '--stage', 'MOON'], [dir, '--bogus'], [dir, '--date', 'yesterday'], [dir]]) {
    const r = ci(...args);
    assert.equal(r.status, 2, args.join(' '));
    assert.match(r.stderr, /hullproof (ci|scan): /);
  }
  assert.equal(existsSync(join(dir, '.hullproof')), false);
});

test('--hunt is refused without the Pro edition, before anything runs', { skip: KIT_SKIP }, () => {
  const dir = repoWith({ 'README.md': 'x\n' });
  const r = ci(dir, '--hunt', '--edition', 'free');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--hunt/);
  assert.equal(existsSync(join(dir, '.hullproof')), false);
});

const fail = (sev: FailRecord['severity'], fp: string): FailRecord => ({
  fingerprint: fp, kind: 'fail', sec_ids: ['SEC-API-017'], title: 'Thing', class: 'finding', gap_in_standard: false, severity: sev, confidence: 'SUSPECTED', demonstrated: false,
  root_cause: 'r', raised_by: ['hullproof-engine'], impact_statement: 'Bad.', remediation: { strategy: 'Fix it.', confirm: 'Rerun.' }, evidence: [{ file: 'src/a b/x.ts', line: 4, note: 'n' }],
  machine_evidence: { tool: 'semgrep', rule_id: 'x', tool_version: '1', config_sha256: null },
});
const findingsOf = (...r: FailRecord[]): FindingsFile => ({ schema_version: '1.1.0', report: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), tree_clean: true, stage: 'LAUNCH', profile: 'standard', scope: 'full', run_status: 'incomplete', incomplete_reason: 'deterministic_only', agent_calls: 0, budget: null }, records: r });

test('the verdict counts fail records at or above the level and nothing else', () => {
  const f = findingsOf(fail('BLOCKER', 'SEC-API-017:a:x'), fail('CRITICAL', 'SEC-API-017:b:x'), fail('HIGH', 'SEC-API-017:c:x'));
  assert.equal(ciVerdict(f, 'blocker').blocking.length, 1);
  assert.equal(ciVerdict(f, 'critical').blocking.length, 2);
  assert.equal(ciVerdict(f, 'high').blocking.length, 3);
  assert.equal(ciVerdict(f, 'none').blocked, false);
  assert.equal(ciVerdict(findingsOf(), 'low').blocked, false);
  const c = prComment({ findings: f, verdict: ciVerdict(f, 'critical'), failOn: 'critical', edition: 'free', scanners: ['semgrep'] });
  assert.match(c, /2 blocking findings/);
  assert.equal(c, prComment({ findings: f, verdict: ciVerdict(f, 'critical'), failOn: 'critical', edition: 'free', scanners: ['semgrep'] }));
});

test('SARIF: paths become relative URIs, and the structural check rejects broken files', { skip: KIT_SKIP }, () => {
  assert.equal(uriOf('./src/a b/x.ts'), 'src/a%20b/x.ts');
  const kit = loadKit(KIT);
  const good = buildSarif(findingsOf(fail('BLOCKER', 'SEC-API-017:a:x')), kit, 'README.md') as { runs: { results: Record<string, unknown>[]; tool: { driver: Record<string, unknown> } }[] };
  assert.deepEqual(checkSarif(good), []);
  const clone = (): typeof good => JSON.parse(JSON.stringify(good));
  const loc = (d: typeof good): { physicalLocation: Record<string, Record<string, unknown>> } => (d.runs[0].results[0].locations as { physicalLocation: Record<string, Record<string, unknown>> }[])[0];
  const bad: [string, (d: typeof good) => void][] = [
    ['version', (d) => { (d as Record<string, unknown>).version = '2.0.0'; }],
    ['no runs', (d) => { (d as Record<string, unknown>).runs = []; }],
    ['no driver name', (d) => { delete d.runs[0].tool.driver.name; }],
    ['bad level', (d) => { d.runs[0].results[0].level = 'fatal'; }],
    ['rule index out of range', (d) => { d.runs[0].results[0].ruleIndex = 9; }],
    ['rule index to another rule', (d) => { d.runs[0].results[0].ruleId = 'SEC-API-018'; }],
    ['absolute uri', (d) => { loc(d).physicalLocation.artifactLocation.uri = '/etc/passwd'; }],
    ['uri with ..', (d) => { loc(d).physicalLocation.artifactLocation.uri = 'a/../../b'; }],
    ['file scheme uri', (d) => { loc(d).physicalLocation.artifactLocation.uri = 'file:///x'; }],
    ['line 0', (d) => { loc(d).physicalLocation.region.startLine = 0; }],
    ['no locations', (d) => { d.runs[0].results[0].locations = []; }],
    ['empty message', (d) => { d.runs[0].results[0].message = { text: '' }; }],
    ['unknown property', (d) => { d.runs[0].results[0].surprise = 1; }],
    ['bad severity score', (d) => { ((d.runs[0].tool.driver.rules as { properties: Record<string, unknown> }[])[0].properties)['security-severity'] = 'high'; }],
    ['fingerprint not a string', (d) => { d.runs[0].results[0].partialFingerprints = { a: 1 }; }],
  ];
  for (const [name, mutate] of bad) { const d = clone(); mutate(d); assert.notDeepEqual(checkSarif(d), [], name); }
  assert.notDeepEqual(checkSarif('x'), []);
});
