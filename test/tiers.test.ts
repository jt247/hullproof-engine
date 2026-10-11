// Secrets always hold the gate, rule confidence tiers, and report and gate finding the kit the scan used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { separateTestCode, type BuildInput } from '../src/report/build.ts';
import { leadTier, loadTiers } from '../src/report/tiers.ts';
import { readRules } from '../src/scanners/semgrep.ts';
import { kitForRead } from '../src/commands/report-gate.ts';
import { KIT_LOCAL, scan } from '../src/commands/scan.ts';
import type { Hit, ToolMeta } from '../src/types/index.ts';
import { KIT, KIT_SKIP } from './helpers/kit.ts';
import { EXTRA_RULE_DIRS } from './helpers/packs.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const DIRS = [join(ROOT, 'rules/semgrep'), ...EXTRA_RULE_DIRS];
const hit = (tool: Hit['tool'], rule_id: string, file: string, sec_ids: string[]): Hit => ({ tool, rule_id, file, line: 3, sec_ids, severity_hint: null, message_key: `${tool}:${rule_id}` });
const input = (hits: Hit[]): BuildInput => ({ hits, rulesDirs: DIRS, checks: { schema_version: '1.0.0', commit: null, results: [], not_run: [] } } as unknown as BuildInput);

test('secrets in test files still hold the gate: Gitleaks hits and rules mapped to SEC-SECRETS', () => {
  const { input: out, test: t } = separateTestCode(input([
    hit('gitleaks', 'generic-api-key', 'test/api/user.test.ts', ['SEC-SECRETS-004']),
    hit('semgrep', 'hullproof-hardcoded-signing-secret', 'test/e2e/totp.spec.ts', ['SEC-SECRETS-003', 'SEC-SECRETS-004']),
    hit('semgrep', 'hullproof-raw-sql-concat', 'test/db.test.ts', ['SEC-API-017']),
  ]));
  assert.deepEqual(out.hits.map((h) => h.rule_id), ['generic-api-key', 'hullproof-hardcoded-signing-secret']);
  assert.deepEqual(out.hits[1].sec_ids, ['SEC-SECRETS-003', 'SEC-SECRETS-004'], 'every ID of a secret hit stays');
  assert.deepEqual(t.map((x) => [x.hit!.rule_id, x.kind]), [['hullproof-raw-sql-concat', 'test']]);
});

test('tier file: every rule listed, threshold 0.80, measured rules below it are leads, XSS and path traversal taint rules are leads', () => {
  const t = loadTiers(DIRS);
  assert.equal(t.threshold, 0.8);
  for (const r of readRules(DIRS[0], DIRS[1])) assert.ok(t.rules[r.id], `${r.id} has a tier`);
  for (const [id, e] of Object.entries(t.rules)) {
    if (e.judged >= Math.max(t.min_judged, e.needs_judged ?? 0) && e.precision !== null) assert.equal(e.tier, e.precision >= t.threshold ? 'gate' : 'lead', id);
    if (e.judged > 0) assert.ok(e.evidence && e.date, `${id} names its evidence and date`);
    if (e.judged < Math.max(t.min_judged, e.needs_judged ?? 0)) assert.equal(e.tier, id.startsWith('hullproof-taint-') || id.startsWith('check.map.') ? 'lead' : 'gate', `${id} keeps its default`);
  }
  for (const id of ['hullproof-taint-py-xss', 'hullproof-taint-py-path-traversal', 'hullproof-taint-js-path-traversal']) assert.equal(t.rules[id].tier, 'lead', id);
});

test('leadTier and separateTestCode: a lead rule hit is reported apart, kit rules and secrets stay gate, untested taint rules default to lead', () => {
  const t = loadTiers(DIRS);
  assert.ok(leadTier(hit('semgrep', 'hullproof-taint-py-xss', 'app.py', ['SEC-WEB-031']), t));
  assert.ok(leadTier(hit('semgrep', 'hullproof-taint-new-rule', 'app.py', ['SEC-API-017']), { ...t, rules: {} }), 'untested taint rule defaults to lead');
  assert.equal(leadTier(hit('semgrep', 'hullproof-raw-sql-concat', 'db.ts', ['SEC-API-017']), t), null);
  assert.equal(leadTier(hit('semgrep', 'hullproof-unknown-kit-rule', 'db.ts', ['SEC-API-017']), { ...t, rules: {} }), null, 'untested kit rule keeps gate');
  assert.equal(leadTier(hit('semgrep', 'hullproof-taint-py-xss', 'app.py', ['SEC-SECRETS-004']), t), null, 'a secret is never a lead');
  const { input: out, test: items } = separateTestCode(input([hit('semgrep', 'hullproof-taint-py-xss', 'app.py', ['SEC-WEB-031']), hit('semgrep', 'hullproof-raw-sql-concat', 'db.ts', ['SEC-API-017'])]));
  assert.deepEqual(out.hits.map((h) => h.rule_id), ['hullproof-raw-sql-concat']);
  assert.equal(items[0].kind, 'lead');
  assert.match(items[0].reason, /precision 0\.38 .*below 0\.80/);
});

test('kitForRead: --kit, then HULLPROOF_KIT, then the kit the scan recorded, then the usual search', () => {
  const env = process.env.HULLPROOF_KIT;
  delete process.env.HULLPROOF_KIT;
  try {
    const kit = mkdtempSync(join(tmpdir(), 'hp-kit-'));
    mkdirSync(join(kit, 'docs/hullproof'), { recursive: true });
    writeFileSync(join(kit, 'docs/hullproof/security-controls.json'), '{"controls":[]}');
    const other = mkdtempSync(join(tmpdir(), 'hp-kit2-'));
    mkdirSync(join(other, 'docs/hullproof'), { recursive: true });
    writeFileSync(join(other, 'docs/hullproof/security-controls.json'), '{"controls":[]}');
    const scanDir = mkdtempSync(join(tmpdir(), 'hp-scandir-'));
    const repo = mkdtempSync(join(tmpdir(), 'hp-repo-'));
    writeFileSync(join(scanDir, KIT_LOCAL), JSON.stringify({ kit_dir: kit, controls_sha256: 'x' }));
    assert.equal(kitForRead(repo, scanDir, null), kit);
    assert.equal(kitForRead(repo, scanDir, other), resolve(other));
    process.env.HULLPROOF_KIT = other;
    assert.equal(kitForRead(repo, scanDir, null), resolve(other));
    delete process.env.HULLPROOF_KIT;
    writeFileSync(join(scanDir, KIT_LOCAL), JSON.stringify({ kit_dir: join(kit, 'gone') }));
    assert.notEqual(kitForRead(repo, scanDir, null), join(kit, 'gone'), 'a recorded kit that no longer exists is not used');
  } finally {
    if (env === undefined) delete process.env.HULLPROOF_KIT; else process.env.HULLPROOF_KIT = env;
  }
});

const noKit = KIT_SKIP;
test('scan records the kit path and controls sha256 in kit.local.json', { skip: noKit }, async () => {
  const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' };
  const repo = mkdtempSync(join(tmpdir(), 'hp-kitrec-'));
  cpSync(join(ROOT, 'test/fixtures/checks/webhook-verified-before-use/fail'), repo, { recursive: true });
  for (const a of [['init', '-q'], ['add', '-A'], ['commit', '-q', '-m', 'init']]) assert.equal(spawnSync('git', ['-C', repo, ...a], { env: GIT_ENV }).status, 0);
  const out = mkdtempSync(join(tmpdir(), 'hp-kitrec-out-'));
  const meta: ToolMeta = { schema_version: '1.0.0', tool: 'semgrep', status: 'ran', version: '1.0.0', tested_version_range: '>=1', version_tested: true, argv: [], config_sha256: null, commit: null, files_scanned: 1, files_tracked: 1, exit_code: 0, db_date: null, not_assessed_sec_ids: [] };
  const code = await scan({ repo, out, kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: () => ({ hits: [], metas: [meta] }), log: () => {} });
  assert.equal(code, 0);
  const dir = join(out, readdirSync(out)[0]);
  const rec = JSON.parse(readFileSync(join(dir, KIT_LOCAL), 'utf8')) as { kit_dir: string; controls_sha256: string };
  assert.equal(rec.kit_dir, resolve(KIT));
  assert.equal(rec.controls_sha256, JSON.parse(readFileSync(join(dir, 'scan.json'), 'utf8')).kit.controls_sha256);
});
