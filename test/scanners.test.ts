// Scanner adapters: live runs on a temporary copy of test/fixtures/scanners/app (skipped per tool when the tool is not
// installed), byte identical output over two runs, NOT RUN records, secret handling, the git index reader and the
// OSV parser and policy on a hand written report.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../src/discover/discover.ts';
import { ADAPTERS, runScanner, runScanners } from '../src/scanners/index.ts';
import { detectVersion, mask, parseIndex, readTracked, toolEnv } from '../src/scanners/common.ts';
import { parseOsv } from '../src/scanners/osv-scanner.ts';
import { readRules } from '../src/scanners/semgrep.ts';
import type { ScanOptions } from '../src/scanners/types.ts';
import type { ScannerId } from '../src/types/index.ts';
import { EXTRA_RULE_DIRS } from './helpers/packs.ts';
import { loadTable } from '../src/mapping/map.ts';
import { validate } from './helpers/schema.ts';
import { NEEDS_PRO_KIT } from './helpers/kit.ts';

const FIX = fileURLToPath(new URL('./fixtures/scanners/', import.meta.url));
const SCHEMAS = fileURLToPath(new URL('../schemas/', import.meta.url));
const schema = (n: string) => JSON.parse(readFileSync(join(SCHEMAS, n), 'utf8'));
const env = toolEnv(process.env, false);
const installed = (id: ScannerId): boolean => !!detectVersion(ADAPTERS.find((a) => a.id === id)!.versionCommand, env);
const skipUnless = (id: ScannerId) => (installed(id) ? false : `${id} is not installed`);

// Built from parts so this source file never holds a secret shaped value. Fixed, so both runs see the same bytes.
const FAKE_KEY = ['AK', 'IA', 'Q7RZ3MXP', '2VKD6WNB'].join('');

const git = (cwd: string, ...args: string[]) => {
  const r = spawnSync('git', ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', ...args],
    { cwd, env: { ...env, GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' }, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
};

// A temporary git repository: the fixture app plus a committed secret, an untracked secret and an untracked client file.
function makeRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hullproof-fixture-'));
  cpSync(join(FIX, 'app'), dir, { recursive: true });
  mkdirSync(join(dir, 'config'));
  writeFileSync(join(dir, 'config/settings.js'), `export const awsKeyId = "${FAKE_KEY}";\n`);
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'fixture');
  writeFileSync(join(dir, 'local-notes.js'), `const k = "${FAKE_KEY}";\n`);
  mkdirSync(join(dir, 'public'));
  writeFileSync(join(dir, 'public/app.js'), `window.k = "${FAKE_KEY}";\n`);
  return dir;
}

const opts = (repo: string, out: string, extra: Partial<ScanOptions> = {}): ScanOptions =>
  ({ repo, out, stack: discover(repo), allowNetwork: false, edition: 'pro', history: true, ...extra });

const repo = makeRepo();
process.on('exit', () => rmSync(repo, { recursive: true, force: true }));
const outs = [0, 1].map(() => mkdtempSync(join(tmpdir(), 'hullproof-out-')));
const runs = outs.map((out) => runScanners(opts(repo, out)));
const result = (id: ScannerId) => runs[0].find((s) => s.meta.tool === id)!;

test('two runs on the same commit give byte identical files for every tool', () => {
  const files = readdirSync(join(outs[0], 'scan')).filter((f) => f !== 'run.json').sort();
  assert.equal(files.length, ADAPTERS.length * 3);
  for (const f of files) assert.equal(readFileSync(join(outs[1], 'scan', f), 'utf8'), readFileSync(join(outs[0], 'scan', f), 'utf8'), f);
});

test('contract files match the shared schemas and hold no absolute path or secret', () => {
  for (const s of runs[0]) {
    assert.deepEqual(validate(schema('scan-hits.schema.json'), s.hits), [], `${s.meta.tool} hits`);
    assert.deepEqual(validate(schema('scan-meta.schema.json'), s.meta), [], `${s.meta.tool} meta`);
  }
  for (const f of readdirSync(join(outs[0], 'scan'))) {
    const text = readFileSync(join(outs[0], 'scan', f), 'utf8');
    assert.ok(!text.includes(FAKE_KEY), `${f} holds the secret`);
    assert.ok(!text.includes(repo) && !text.includes(tmpdir()), `${f} holds an absolute path`);
  }
});

test('semgrep: SQL built by concatenation maps to its rule metadata IDs', { skip: skipUnless('semgrep') }, () => {
  const s = result('semgrep');
  assert.equal(s.meta.status, 'ran');
  const h = s.detail.hits.find((x) => x.rule_id === 'hullproof-raw-sql-concat');
  assert.ok(h, 'raw sql hit');
  assert.equal(h.file, 'src/db.js');
  assert.equal(h.line, 3);
  assert.deepEqual(h.sec_ids, ['SEC-API-017']);
  assert.equal(h.mapped_by, 'rule metadata');
  assert.match(h.rule_version, /^sha256:[0-9a-f]{16}$/);
  assert.match(s.meta.config_sha256 ?? '', /^[0-9a-f]{64}$/);
  assert.equal(s.meta.files_tracked, readTracked(repo)!.size);
  assert.ok(s.detail.files.scanned_not_tracked === 0, 'semgrep reads tracked files only');
});

test('gitleaks: redacted, fingerprinted, tracked and history hits fail SEC-SECRETS-004; untracked ones do not', { skip: skipUnless('gitleaks') }, () => {
  const s = result('gitleaks');
  assert.equal(s.meta.status, 'ran');
  const at = (file: string, source: 'dir' | 'git') => s.detail.hits.find((h) => h.file === file && h.secret?.source === source);
  const tracked = at('config/settings.js', 'dir');
  assert.ok(tracked, 'tracked file hit');
  assert.deepEqual(tracked.sec_ids, ['SEC-SECRETS-004']);
  assert.equal(tracked.secret!.fingerprint, `config/settings.js:${tracked.rule_id}:1`);
  assert.ok(tracked.secret!.redacted.includes('REDACTED'));
  const hist = at('config/settings.js', 'git');
  assert.ok(hist, 'history hit');
  assert.match(hist.secret!.commit ?? '', /^[0-9a-f]{40}$/);
  const local = at('local-notes.js', 'dir');
  assert.ok(local && local.secret!.tracked === false && local.unmapped && local.sec_ids.length === 0, 'untracked file kept, unmapped');
  const pub = at('public/app.js', 'dir');
  assert.deepEqual(pub?.sec_ids, ['SEC-SECRETS-001'], 'untracked client file fails SEC-SECRETS-001 only');
  assert.ok(s.detail.files.scanned_not_tracked! >= 2);
});

test('gitleaks without history runs dir only', { skip: skipUnless('gitleaks') }, () => {
  const s = runScanner(ADAPTERS.find((a) => a.id === 'gitleaks')!, opts(repo, outs[0], { history: false }));
  assert.equal(s.detail.commands.length, 1);
  assert.ok(s.detail.hits.every((h) => h.secret?.source === 'dir'));
});

test('trivy: config scan maps cloud checks and keeps unmapped ones', { skip: skipUnless('trivy') || NEEDS_PRO_KIT }, () => {
  const s = result('trivy');
  assert.equal(s.meta.status, 'ran');
  const find = (id: string, file: string) => s.detail.hits.find((h) => h.rule_id === id && h.file === file);
  // The IDs come from the engine's Trivy table, which holds only the rows this edition of the engine maps.
  const rows = loadTable('trivy').rows;
  for (const [id, file] of [['AWS-0107', 'infra/main.tf'], ['AWS-0180', 'infra/main.tf'], ['GCP-0001', 'infra/gcp.tf'], ['DS-0031', 'Dockerfile']]) {
    const hit = find(id, file);
    assert.ok(hit, `${id} found`);
    assert.deepEqual(hit.sec_ids, rows.find((r) => r.rule_id === id)?.sec_ids ?? [], id);
  }
  assert.deepEqual(find('DS-0031', 'Dockerfile')?.sec_ids, ['SEC-CLOUD-016']);
  const unmapped = find('AWS-0089', 'infra/main.tf');
  assert.ok(unmapped && unmapped.unmapped && unmapped.sec_ids.length === 0, 'unmapped hit kept');
  assert.ok(s.hits.hits.some((h) => h.rule_id === 'AWS-0089'), 'unmapped hit is in the contract file too');
  assert.deepEqual(s.detail.sec_ids_not_in_controls.filter((id) => !/^SEC-CLOUD-0(4[6-9]|5[0-2])$/.test(id)), []);
  assert.ok(s.meta.files_scanned! >= 4);
});

test('osv-scanner without --allow-network is NOT RUN with the reason and the IDs left open', () => {
  const s = result('osv-scanner');
  assert.equal(s.meta.status, 'skipped: network not allowed');
  assert.match(s.detail.not_run_reason ?? '', /--allow-network/);
  assert.deepEqual(s.meta.not_assessed_sec_ids, ['SEC-SUPPLY-002']);
  assert.deepEqual(s.meta.argv, []);
});

test('a missing tool is NOT RUN: not installed, nothing installed, its IDs stay open', () => {
  for (const a of ADAPTERS) {
    const s = runScanner(a, opts(repo, outs[0], { env: { PATH: '/nonexistent' } }));
    assert.equal(s.meta.status, 'skipped: not installed', a.id);
    assert.match(s.detail.not_run_reason ?? '', /not installed/);
    assert.ok(s.meta.not_assessed_sec_ids.length > 0, `${a.id} lists open IDs`);
    assert.deepEqual(validate(schema('scan-meta.schema.json'), s.meta), []);
  }
});

test('a tool with nothing to read is NOT RUN: not applicable', () => {
  const empty = mkdtempSync(join(tmpdir(), 'hullproof-empty-'));
  writeFileSync(join(empty, 'notes.txt'), 'nothing here\n');
  const s = runScanner(ADAPTERS.find((a) => a.id === 'trivy')!, opts(empty, outs[0]));
  assert.equal(s.meta.status, installed('trivy') ? 'skipped: not applicable' : 'skipped: not installed');
  rmSync(empty, { recursive: true, force: true });
});

test('git index reader matches git ls-files for index versions 2 and 4', () => {
  const want = git(repo, 'ls-files').trim().split('\n').sort();
  assert.deepEqual([...readTracked(repo)!].sort(), want);
  const copy = mkdtempSync(join(tmpdir(), 'hullproof-v4-'));
  cpSync(repo, copy, { recursive: true });
  git(copy, 'update-index', '--index-version', '4');
  assert.equal(readFileSync(join(copy, '.git/index')).readUInt32BE(4), 4);
  assert.deepEqual([...parseIndex(readFileSync(join(copy, '.git/index')))].sort(), want);
  rmSync(copy, { recursive: true, force: true });
});

test('osv parser: severity class, fixed versions, aliases and the default policy', () => {
  const o = opts(repo, outs[0], { repo: '/REPO', asOf: '2026-10-10' });
  const { hits, scanned } = parseOsv(readFileSync(join(FIX, 'osv-output.json'), 'utf8'), { ...o, stack: discover(repo) }, '2026-10-10');
  assert.deepEqual(scanned, ['package-lock.json']);
  const by = Object.fromEntries(hits.map((h) => [h.rule_id, h]));
  const row = (id: string) => [by[id].advisory!.severity_class, by[id].advisory!.decision, by[id].sec_ids.join(',')];
  assert.deepEqual(row('TEST-2026-0001'), ['CRITICAL', 'fail', 'SEC-SUPPLY-002']);
  assert.deepEqual(row('TEST-2026-0002'), ['MEDIUM', 'report', '']);                // inside 90 days: reported, not failing
  assert.deepEqual(row('TEST-2026-0003'), ['MEDIUM', 'fail', 'SEC-SUPPLY-002']);    // past 90 days
  assert.deepEqual(row('TEST-2026-0004'), ['UNKNOWN', 'fail', 'SEC-SUPPLY-002']);   // no severity: treated as HIGH
  assert.deepEqual(row('TEST-2026-0005'), ['LOW', 'report', '']);
  assert.equal(by['TEST-2026-0002'].mapped_by, 'policy report only');
  assert.deepEqual(by['TEST-2026-0002'].advisory!.mapped_sec_ids, ['SEC-SUPPLY-002']);
  assert.deepEqual(by['TEST-2026-0002'].advisory!.aliases, ['TEST-ALIAS-0002']);
  assert.deepEqual(by['TEST-2026-0003'].advisory!.fixed_versions, ['2.1.0']);
  assert.equal(by['TEST-2026-0001'].advisory!.cvss_score, 9.8);
  assert.equal(by['TEST-2026-0001'].file, 'package-lock.json');
  assert.equal(by['TEST-2026-0001'].line, 0);
});

test('every Semgrep rule has an id and sec_ids (a taint rule may have none in an edition whose controls it does not map to)', () => {
  const rules = readRules(fileURLToPath(new URL('../rules/semgrep/', import.meta.url)), EXTRA_RULE_DIRS[0] ?? null);
  assert.ok(rules.length >= 40);
  for (const r of rules) assert.ok(r.sec_ids.length > 0 || r.id.startsWith('hullproof-taint-'), `${r.id} has no sec_ids`);
  assert.equal(new Set(rules.map((r) => r.id)).size, rules.length, 'rule ids are unique');
});

test('mask removes token shaped runs and keeps REDACTED', () => {
  assert.equal(mask(`key = "${FAKE_KEY}"`), 'key = "***"');
  assert.equal(mask('AWS_SECRET_ACCESS_KEY=REDACTED'), 'AWS_SECRET_ACCESS_KEY=REDACTED');
});
