// hullproof hunt --replay and the report, end to end on a small git repository: the confirmation runs from saved answers, the
// result is byte identical three times, the report shows the hunt section, a rescan keeps the saved answers, and a lead never
// reaches the gate. The calls to a model are tested in pro-hunt.test.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/commands/scan.ts';
import { huntCommand } from '../src/commands/hunt.ts';
import { report } from '../src/commands/report-gate.ts';
import { huntDir, writeAnswer, writePlan } from '../src/confirm/store.ts';
import { loadKit } from '../src/report/kit.ts';
import type { ToolMeta } from '../src/types/index.ts';
import { answer, appCopy, boLead, DELETE_ID, planOf, proposal } from './helpers/hunt.ts';
import { KIT, KIT_SKIP } from './helpers/kit.ts';

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' };
const git = (dir: string, ...args: string[]): void => { assert.equal(spawnSync('git', ['-C', dir, ...args], { env: GIT_ENV }).status, 0, args.join(' ')); };
const meta = (tool: ToolMeta['tool']): ToolMeta => ({ schema_version: '1.0.0', tool, status: 'ran', version: '1', tested_version_range: '>=1', version_tested: true, argv: [], config_sha256: null, commit: null, files_scanned: 5, files_tracked: 5, exit_code: 0, db_date: null, not_assessed_sec_ids: [] });
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

test('hunt --replay with nothing saved is a clean refusal', () => {
  const { repo } = appCopy();
  git(repo, 'init', '-q'); git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'init');
  const r = spawnSync(process.execPath, [CLI, 'hunt', repo, '--replay', '--out', mkdtempSync(join(tmpdir(), 'hp-o-'))], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /no saved hunt outputs/);
  const bad = spawnSync(process.execPath, [CLI, 'hunt', repo, '--replay', '--dry-run'], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
});

test('replay three times is byte identical, the report shows the hunt, a rescan keeps the answers', { skip: KIT_SKIP }, async () => {
  const { repo, map } = appCopy();
  git(repo, 'init', '-q'); git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'init');
  const commit = spawnSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
  const out = mkdtempSync(join(tmpdir(), 'hp-hunt-out-'));
  const stub = () => ({ hits: [], metas: [meta('semgrep'), meta('gitleaks'), meta('osv-scanner')] });
  assert.equal(await scan({ repo, out, kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: stub, log: () => {} }), 0);
  const dir = join(out, commit);
  const kit = loadKit(KIT);
  const id = kit.controls.find((c) => c.edition === 'free' && c.stage === 'LAUNCH' && c.severity === 'CRITICAL')!.id;
  const hd = huntDir(dir);
  writePlan(hd, planOf(map, 3));
  for (const r of [1, 2, 3]) writeAnswer(hd, answer(r, DELETE_ID, [boLead({ requirement_ids: [id] }), boLead({ lead_id: 'lead2', requirement_ids: [id], path: [{ file: 'server.js', line: 29, note: 'reply' }], quoted_code: 'res.json({ ok: true });', evidence_proposal: proposal('none'), claim: 'The reply is sent with no log.' })]));
  const bytes: string[] = [];
  for (let i = 0; i < 3; i++) {
    assert.equal(await huntCommand({ repo, out, kit: KIT, commit: null, provider: null, model: null, runs: null, dryRun: false, resume: false, replay: true, log: () => {} }), 0);
    bytes.push(readFileSync(join(hd, 'result.json'), 'utf8'));
  }
  assert.equal(bytes[1], bytes[0]);
  assert.equal(bytes[2], bytes[0]);
  assert.equal(await report({ repo, out, kit: KIT, commit: null, owner: null, date: '2026-10-14', log: () => {} }), 0);
  const md = readFileSync(join(dir, 'report.md'), 'utf8');
  assert.match(md, /## Hunt: leads and confirmed findings/);
  assert.match(md, /Confirmed findings: 1\. Leads not confirmed: 1\./);
  assert.match(md, /Hallucinations .*: 0\./);
  assert.match(md, /### F-1 .*Confirmed lead/);
  // A rescan rewrites the scan files and leaves the saved answers alone.
  assert.equal(await scan({ repo, out, kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: stub, log: () => {} }), 0);
  assert.ok(existsSync(join(hd, 'run-1')) && readdirSync(join(hd, 'run-1')).length === 1);
});
