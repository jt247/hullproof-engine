// hullproof scan, report and gate end to end on a small git repository, with stub scanners (the adapters have their
// own tests). Checks byte identical output over three runs, the kit validator, and the git safety refusal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/commands/scan.ts';
import { gate, report } from '../src/commands/report-gate.ts';
import { findingsJson } from '../src/report/build.ts';
import { stableJson as stableJsonText } from '../src/util.ts';
import type { Hit, ToolMeta } from '../src/types/index.ts';
import { KIT, KIT_SKIP } from './helpers/kit.ts';

const skip = KIT_SKIP;
const FIX = fileURLToPath(new URL('./fixtures/checks/', import.meta.url));
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid',
  GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' };
const git = (dir: string, ...args: string[]): void => { assert.equal(spawnSync('git', ['-C', dir, ...args], { env: GIT_ENV }).status, 0, args.join(' ')); };

function makeRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-scan-'));
  for (const f of ['webhook-verified-before-use', 'no-untrusted-event-in-run', 'cors-no-reflected-origin']) cpSync(join(FIX, f, 'fail'), dir, { recursive: true });
  git(dir, 'init', '-q');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'init');
  return dir;
}

const meta = (tool: ToolMeta['tool'], status: ToolMeta['status']): ToolMeta => ({ schema_version: '1.0.0', tool, status, version: status === 'ran' ? '1.0.0' : null,
  tested_version_range: '>=1', version_tested: status === 'ran', argv: [], config_sha256: null, commit: null, files_scanned: status === 'ran' ? 5 : null,
  files_tracked: 5, exit_code: 0, db_date: null, not_assessed_sec_ids: status === 'ran' ? [] : ['SEC-SECRETS-004'] });
const stub = () => ({
  hits: [{ tool: 'semgrep', rule_id: 'hullproof-cors-reflect-origin', file: 'src/app/api/webhooks/pay/route.ts', line: 3, sec_ids: ['SEC-WEB-022'], severity_hint: 'ERROR', message_key: 'semgrep:hullproof-cors-reflect-origin' },
    { tool: 'semgrep', rule_id: 'unmapped-rule', file: 'next.config.js', line: 1, sec_ids: [], severity_hint: null, message_key: 'semgrep:unmapped-rule' }] as Hit[],
  metas: [meta('semgrep', 'ran'), meta('gitleaks', 'skipped: not installed')],
});

function digest(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string): void => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (n !== 'run.json') out[relative(dir, p)] = createHash('sha256').update(readFileSync(p)).digest('hex');
    }
  };
  walk(dir);
  return out;
}

test('scan, report and gate: valid records, FAIL rows, NOT READY, and byte identical over three runs', { skip }, async () => {
  const repo = makeRepo();
  const out = mkdtempSync(join(tmpdir(), 'hp-scan-out-'));
  const runs: Record<string, string>[] = [];
  let commitDir = '';
  for (let i = 0; i < 3; i++) {
    const logs: string[] = [];
    assert.equal(await scan({ repo, out, kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: stub, log: (s) => logs.push(s) }), 0, logs.join('\n'));
    assert.equal(await report({ repo, out, kit: KIT, commit: null, owner: null, date: '2026-10-10', log: () => {} }), 0);
    commitDir = join(out, readdirSync(out)[0]);
    runs.push(digest(commitDir));
  }
  assert.deepEqual(runs[1], runs[0]);
  assert.deepEqual(runs[2], runs[0]);
  for (const f of ['stack.json', 'checks.json', 'results.json', 'report.findings.md', 'surface.json', 'scan.json', 'report.md']) assert.ok(runs[0][f], f);

  const results = JSON.parse(readFileSync(join(commitDir, 'results.json'), 'utf8')) as { id: string; result: string }[];
  const row = (id: string) => results.find((r) => r.id === id)?.result;
  assert.equal(row('SEC-API-101'), 'FAIL');
  assert.equal(row('SEC-WEB-022'), 'FAIL', 'a mapped rule hit fails its requirement');
  assert.equal(row('SEC-SUPPLY-032'), 'FAIL');
  assert.ok(results.every((r) => r.result === 'FAIL' || r.result === 'PASS (static)' || r.result.startsWith('NOT ASSESSED: ')));
  const findings = readFileSync(join(commitDir, 'report.findings.md'), 'utf8');
  assert.match(findings, /"kind": "observation"[\s\S]*unmapped-rule|unmapped-rule[\s\S]*"kind": "observation"/, 'an unmapped hit is an observation');
  assert.match(findings, /"incomplete_reason": "deterministic_only"/, "no verifier ran by design");
  assert.match(findings, /"run_status": "incomplete"/);
  assert.equal(JSON.parse(readFileSync(join(commitDir, 'scan.json'), 'utf8')).rule_pack, null);
  const md = readFileSync(join(commitDir, 'report.md'), 'utf8');
  assert.match(md, /## Verdict: NOT READY/);
  assert.match(md, /gitleaks \| skipped: not installed/);
  assert.doesNotMatch(md, /[\u2013\u2014]/, 'no en or em dashes');

  const prev = process.stdout.write.bind(process.stdout);
  let printed = '';
  process.stdout.write = ((s: string) => { printed += s; return true; }) as typeof process.stdout.write;
  try { assert.equal(await gate({ repo, out, kit: KIT, commit: null, owner: null, date: '2026-10-10', log: () => {} }), 1); }
  finally { process.stdout.write = prev; }
  assert.match(printed, /RESULT: NOT READY\n$/);
});

test('scan refuses a repository whose git configuration could run code', { skip }, async () => {
  const repo = makeRepo();
  appendFileSync(join(repo, '.git/config'), '[core]\n\tfsmonitor = ./evil.sh\n');
  const logs: string[] = [];
  assert.equal(await scan({ repo, out: mkdtempSync(join(tmpdir(), 'hp-x-')), kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: stub, log: (s) => logs.push(s) }), 2);
  assert.match(logs.join('\n'), /refused: a git command could run code/);
  writeFileSync(join(repo, 'unused'), '');
});

test('scan with a rule pack records it in scan.json and report.md; a missing pack is bad input', { skip }, async () => {
  const repo = makeRepo();
  const out = mkdtempSync(join(tmpdir(), 'hp-scan-pack-'));
  const pack = mkdtempSync(join(tmpdir(), 'hp-pack-'));
  writeFileSync(join(pack, 'extra.yaml'), 'rules:\n  - id: hullproof-test-pack-rule\n    languages: [javascript]\n    severity: WARNING\n    message: test rule\n    pattern: foo()\n    metadata:\n      sec_ids: [SEC-API-017]\n');
  const base = { repo, out, kit: KIT, edition: 'pro' as const, stage: null, allowNetwork: false, tools: null, scanners: stub, log: () => {} };
  assert.equal(await scan({ ...base, rulePack: join(pack, 'missing') }), 2);
  assert.equal(await scan({ ...base, rulePack: pack }), 0);
  assert.equal(await report({ repo, out, kit: KIT, commit: null, owner: null, date: '2026-10-10', log: () => {} }), 0);
  const dir = join(out, readdirSync(out)[0]);
  const info = JSON.parse(readFileSync(join(dir, 'scan.json'), 'utf8')) as { rule_pack: { name: string; files: string[]; sha256: string } };
  assert.equal(info.rule_pack.name, basename(pack));
  assert.equal(info.rule_pack.files.length, 1);
  assert.match(info.rule_pack.sha256, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(info).includes(pack), 'no absolute path in scan.json');
  assert.match(readFileSync(join(dir, 'report.md'), 'utf8'), new RegExp(`5\\. Semgrep rule pack: ${basename(pack)}, 1 rule files added`));
});

test('a findings block past the kit warning size is written as compact JSON, under it as indented JSON', () => {
  const rec = (i: number) => ({ fingerprint: `OBS:f${String(i).padStart(4, '0')}.ts:x`, kind: 'observation' as const, sec_ids: [], title: 't'.repeat(150), where: [{ file: `f${i}.ts`, line: 1, note: 'n'.repeat(250) }], note: 'n'.repeat(390), raised_by: ['hullproof-engine'] });
  const file = (n: number) => ({ schema_version: '1.1.0' as const, report: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), tree_clean: true, stage: 'LAUNCH' as const, profile: 'standard' as const, scope: 'full' as const, run_status: 'complete' as const, agent_calls: 0, budget: null }, records: Array.from({ length: n }, (_, i) => rec(i)) });
  const small = findingsJson(file(5));
  assert.ok(small.includes('\n  "records"'), 'indented');
  const big = findingsJson(file(200));
  assert.ok(big.length > 0 && big.length <= 200000 && !big.trimEnd().includes('\n'), 'one line, under the kit limit');
  assert.deepEqual(JSON.parse(big), JSON.parse(stableJsonText(file(200))));
});
