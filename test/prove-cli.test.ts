// hullproof prove on the command line, end to end on a small git repository with a fake container runtime and a fake app: the typed
// confirmation, the refusal of any address, hand written specs, the proof run, replay three times, the report and the gate, and a rescan
// that keeps the evidence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { proveCommand, type ProveOptions } from '../src/commands/prove.ts';
import { gate, report } from '../src/commands/report-gate.ts';
import { scan } from '../src/commands/scan.ts';
import { ContainerRunner } from '../src/prove/container.ts';
import { CONFIRM_PHRASE } from '../src/prove/safety.ts';
import { proveDir } from '../src/prove/store.ts';
import { loadKit } from '../src/report/kit.ts';
import type { Runner } from '../src/prove/runner.ts';
import type { ToolMeta } from '../src/types/index.ts';
import { KIT, KIT_SKIP } from './helpers/kit.ts';
import { FakeRuntime, fakeApp, idorSpec } from './helpers/prove.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' };
const git = (dir: string, ...args: string[]): void => { assert.equal(spawnSync('git', ['-C', dir, ...args], { env: GIT_ENV }).status, 0, args.join(' ')); };
const meta = (tool: ToolMeta['tool']): ToolMeta => ({ schema_version: '1.0.0', tool, status: 'ran', version: '1', tested_version_range: '>=1', version_tested: true, argv: [], config_sha256: null, commit: null, files_scanned: 5, files_tracked: 5, exit_code: 0, db_date: null, not_assessed_sec_ids: [] });
const stub = () => ({ hits: [], metas: [meta('semgrep'), meta('gitleaks'), meta('osv-scanner')] });

function appRepo(): { repo: string; commit: string } {
  const repo = mkdtempSync(join(tmpdir(), 'hp-pcli-'));
  mkdirSync(join(repo, 'node_modules/express'), { recursive: true });
  writeFileSync(join(repo, 'node_modules/express/index.js'), 'module.exports = () => ({});');
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'a', main: 'server.js' }));
  writeFileSync(join(repo, '.env'), 'JWT_SECRET=this-is-a-real-secret-value');
  writeFileSync(join(repo, 'server.js'), [
    "const express = require('express');", 'const app = express();', "app.get('/health', (req, res) => res.json({ ok: true }));",
    "app.post('/api/login', (req, res) => res.json({ token: 'x' }));",
    "app.get('/api/notes/:id', (req, res) => {", "  const n = db.get('SELECT * FROM notes WHERE id = ?', [req.params.id]);", '  res.json(n);', '});',
    'app.listen(process.env.PORT || 4321);', ''].join('\n'));
  git(repo, 'init', '-q'); git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'init');
  return { repo, commit: spawnSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim() };
}
const base = (repo: string, out: string, over: Partial<ProveOptions> = {}): ProveOptions => ({ repo, out, commit: null, allowRun: false, confirm: null, target: null, specs: [], gen: false, provider: null, model: null, replay: false, selfTest: false, runtime: null, log: () => undefined, ...over });
function counting(inner: Runner): Runner & { prepared: number; checked: number } {
  const r = { name: inner.name, prepared: 0, checked: 0, available: async () => { r.checked++; return inner.available(); }, prepare: async (q: Parameters<Runner['prepare']>[0]) => { r.prepared++; return inner.prepare(q); } };
  return r;
}
const specFile = (dir: string, over = {}): string => { const f = join(dir, 'spec.json'); writeFileSync(f, JSON.stringify({ ...idorSpec(), spec_id: 'idor_read', ...over })); return f; };

test('prove refuses an address, runs nothing without the flag and the typed phrase, and never reaches the runtime without them', async () => {
  const { repo } = appRepo();
  const out = mkdtempSync(join(tmpdir(), 'hp-po-'));
  const logs: string[] = [];
  const run = counting(new ContainerRunner(new FakeRuntime()));
  const o = (over: Partial<ProveOptions> = {}) => base(repo, out, { log: (s) => logs.push(s), ...over });
  assert.equal(await proveCommand(o({ target: 'https://staging.example.com', allowRun: true, confirm: CONFIRM_PHRASE }), { runner: run }), 2);
  assert.match(logs.join('\n'), /accepts no address/);
  assert.equal(await proveCommand(o(), { runner: run }), 2);
  assert.match(logs.join('\n'), /nothing to do/);
  assert.equal(await proveCommand(o({ allowRun: true }), { runner: run, interactive: false }), 2);
  assert.match(logs.join('\n'), /typed confirmation/);
  assert.equal(await proveCommand(o({ allowRun: true, confirm: 'yes' }), { runner: run }), 2);
  assert.equal(await proveCommand(o({ confirm: CONFIRM_PHRASE }), { runner: run }), 2, 'the phrase without the flag');
  assert.equal(await proveCommand(o({ allowRun: true }), { runner: run, interactive: true, ask: async () => 'no thanks' }), 2);
  assert.equal(run.checked + run.prepared, 0, 'the runtime was never touched');
  const bin = spawnSync(process.execPath, [CLI, 'prove', repo, '--target', 'http://127.0.0.1:3000'], { encoding: 'utf8' });
  assert.equal(bin.status, 2);
  assert.match(bin.stderr, /accepts no address/);
  const env = spawnSync(process.execPath, [CLI, 'prove', repo, '--allow-run', '--out', out], { encoding: 'utf8', env: { ...process.env, CI: 'true', HULLPROOF_CONFIRM: CONFIRM_PHRASE }, input: '' });
  assert.equal(env.status, 2, 'neither CI nor an environment variable confirms');
});

test('an unavailable runtime is a clear refusal with the commands to fix it', async () => {
  const { repo } = appRepo();
  const logs: string[] = [];
  const code = await proveCommand(base(repo, mkdtempSync(join(tmpdir(), 'hp-po-')), { allowRun: true, confirm: CONFIRM_PHRASE, log: (s) => logs.push(s) }), { runner: new ContainerRunner(new FakeRuntime({ infoOk: false })) });
  assert.equal(code, 2);
  assert.match(logs.join('\n'), /colima start/);
});

test('a bad spec file is refused with its reasons, and a good one is copied in', async () => {
  const { repo } = appRepo();
  const out = mkdtempSync(join(tmpdir(), 'hp-po-'));
  const dir = mkdtempSync(join(tmpdir(), 'hp-sp-'));
  const logs: string[] = [];
  const o = (specs: string[]) => base(repo, out, { specs, log: (s) => logs.push(s) });
  assert.equal(await proveCommand(o([specFile(dir, { steps: [] })])), 2);
  assert.match(logs.join('\n'), /is invalid: steps needs 2 to 24/);
  assert.equal(await proveCommand(o(['/nonexistent.json'])), 2);
  assert.equal(await proveCommand(o([specFile(dir)])), 2, 'copied, then nothing to do');
  const commit = spawnSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
  assert.ok(existsSync(join(proveDir(join(out, commit)), 'specs/idor_read.json')));
});

test('end to end: confirm, prove 3 of 3 in the fake sandbox, replay 3 times, report, gate, rescan', { skip: KIT_SKIP }, async () => {
  const { repo, commit } = appRepo();
  const out = mkdtempSync(join(tmpdir(), 'hp-pe-'));
  const kit = loadKit(KIT);
  const id = kit.controls.find((c) => c.edition === 'free' && c.stage === 'LAUNCH' && c.severity === 'CRITICAL')!.id;
  assert.equal(await scan({ repo, out, kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: stub, log: () => {} }), 0);
  const dir = join(out, commit);
  const readGate = async (): Promise<{ code: number; text: string }> => {
    const chunks: string[] = [];
    const orig = process.stdout.write.bind(process.stdout);
    (process.stdout as unknown as { write: (s: string) => boolean }).write = (s: string) => { chunks.push(String(s)); return true; };
    try { return { code: await gate({ repo, out, kit: KIT, commit: null, owner: null, date: '2026-10-14', log: () => {} }), text: chunks.join('') }; } finally { process.stdout.write = orig; }
  };
  const before = await readGate();
  const sdir = mkdtempSync(join(tmpdir(), 'hp-sp-'));
  const spec = { ...idorSpec(), spec_id: 'idor_read', requirement_ids: [id], target: { entry_point: 'server.js:5:http_route:GET:/api/notes/:id:-', file: 'server.js', line: 6 } };
  writeFileSync(join(sdir, 'spec.json'), JSON.stringify(spec));

  const app = await fakeApp('vulnerable');
  try {
    // Written for port 4321 in the repository; the fake runtime sends the executor to the fake app.
    const rt = new FakeRuntime({ appPort: app.port });
    const logs: string[] = [];
    const code = await proveCommand(base(repo, out, { allowRun: true, confirm: CONFIRM_PHRASE, specs: [join(sdir, 'spec.json')], log: (s) => logs.push(s) }), { runner: new ContainerRunner(rt, { sleepMs: 1 }) });
    assert.equal(code, 0, logs.join('\n'));
    assert.match(logs.join('\n'), /1 proven \(3 of 3 runs\)/);
    // The run command had every isolation flag, and the copy held no secret.
    for (const run of rt.find('run')) { assert.equal(run[run.indexOf('--network') + 1], 'none'); assert.ok(run.includes('--read-only')); assert.ok(!run.some((x) => x.includes('this-is-a-real-secret-value'))); }
    assert.equal(rt.find('run').length, 3, 'a fresh container for each of the 3 runs');
    assert.ok(rt.find('rm').length >= 3);
  } finally { await app.close(); }

  const pd = proveDir(dir);
  const live = readFileSync(join(pd, 'result.json'), 'utf8');
  for (let i = 0; i < 3; i++) {
    assert.equal(await proveCommand(base(repo, out, { replay: true })), 0);
    assert.equal(readFileSync(join(pd, 'result.json'), 'utf8'), live, `replay ${i + 1}`);
  }
  assert.equal(await report({ repo, out, kit: KIT, commit: null, owner: null, date: '2026-10-14', log: () => {} }), 0);
  const md = readFileSync(join(dir, 'report.md'), 'utf8');
  assert.match(md, /## Proof sandbox: findings proven by a test/);
  assert.match(md, /#### P-1 A signed in user can read the note of another user by id\./);
  assert.match(md, /Attack step other: bob sent GET \/api\/notes\/1 and got 200/);
  assert.match(md, /### F-\d+ .*Proven by test/);
  assert.doesNotMatch(md, /abcdef0123456789/, 'no token in the report');
  const after = await readGate();
  assert.notEqual(after.text, before.text, 'a proven finding changes the gate');
  assert.equal(after.code, 1);
  // A rescan rewrites the scan files and keeps the evidence.
  assert.equal(await scan({ repo, out, kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: stub, log: () => {} }), 0);
  assert.ok(existsSync(join(pd, 'result.json')) && existsSync(join(pd, 'runs/idor_read/run-3.json')));
  // Removing the evidence restores the earlier verdict bytes: nothing else carried the change.
  rmSync(pd, { recursive: true, force: true });
  assert.equal((await readGate()).text, before.text);
});

test('replay with nothing saved is a clean refusal', async () => {
  const { repo } = appRepo();
  const logs: string[] = [];
  assert.equal(await proveCommand(base(repo, mkdtempSync(join(tmpdir(), 'hp-po-')), { replay: true, log: (s) => logs.push(s) })), 2);
  assert.match(logs.join('\n'), /no saved proof run/);
  assert.equal(await proveCommand(base(repo, mkdtempSync(join(tmpdir(), 'hp-po-')), { replay: true, allowRun: true })), 2, '--replay takes no other option');
});

test('--allow-install-scripts prints a clear warning and is off unless given', async () => {
  const { repo } = appRepo();
  const run = async (flag: boolean): Promise<string> => {
    const logs: string[] = [];
    await proveCommand(base(repo, mkdtempSync(join(tmpdir(), 'hp-po-')), { allowRun: true, confirm: CONFIRM_PHRASE, allowInstallScripts: flag, log: (s) => logs.push(s) }), { runner: new ContainerRunner(new FakeRuntime({ infoOk: false })) });
    return logs.join('\n');
  };
  // The runtime is unavailable here, so the run stops before the warning: the warning is tied to a run that would start.
  assert.doesNotMatch(await run(false), /install scripts/i);
  const rt = new FakeRuntime();
  const logs: string[] = [];
  await proveCommand(base(repo, mkdtempSync(join(tmpdir(), 'hp-po-')), { allowRun: true, confirm: CONFIRM_PHRASE, allowInstallScripts: true, log: (s) => logs.push(s) }), { runner: new ContainerRunner(rt, { sleepMs: 1 }) });
  assert.match(logs.join('\n'), /WARNING: --allow-install-scripts is on\. Install scripts of every dependency run inside the build container/);
  const off: string[] = [];
  await proveCommand(base(repo, mkdtempSync(join(tmpdir(), 'hp-po-')), { allowRun: true, confirm: CONFIRM_PHRASE, log: (s) => off.push(s) }), { runner: new ContainerRunner(new FakeRuntime(), { sleepMs: 1 }) });
  assert.doesNotMatch(off.join('\n'), /allow-install-scripts is on/);
});
