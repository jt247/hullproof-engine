// The container backend against a fake runtime that records every command, and a fake HTTP app. The hardening of the run command is
// checked as text, the refusal of unsafe arguments is checked, and the whole path (build, start, health check, step executor, teardown)
// runs through the real code with only the docker binary replaced. A real container is exercised by test/prove-escape.test.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Recipe } from '../src/types/index.ts';
import { APP_USER, assertSafeRunArgs, buildArgs, ContainerRunner, dockerfile, EXEC_DIR, runArgs } from '../src/prove/container.ts';
import { DEFAULT_LIMITS } from '../src/prove/runner.ts';
import { FakeRuntime, fakeApp, idorSpec } from './helpers/prove.ts';

const recipe = (over: Partial<Recipe> = {}): Recipe => ({ schema_version: '1.0.0', stack: 'node-express', base_image: 'node:22-slim', install: null, vendored_modules: false, seed: 'node seed.js', start: 'node server.js', port: 3000, port_from_env: true, health_path: '/health', data_store: { kind: 'sqlite', env: ['DB_PATH'] }, env: { DB_PATH: '{DATA}/app.db', PORT: '3000', APP_NAME: 'dummy-app-name' }, notes: [], ...over });
const args = (over = {}) => runArgs({ name: 'hp-prove-x-1', runId: 'x', image: 'img', network: 'none', user: APP_USER, tmpfs: ['/tmp:rw'], env: { A: '1' }, limits: DEFAULT_LIMITS, cmd: ['sh', '-c', 'node server.js'], ...over });
const copyDir = (): string => { const d = mkdtempSync(join(tmpdir(), 'hp-cont-')); writeFileSync(join(d, 'server.js'), 'x'); return d; };

test('the run command carries every isolation flag', () => {
  const a = args();
  const at = (flag: string): string => a[a.indexOf(flag) + 1];
  assert.equal(at('--network'), 'none');
  assert.ok(a.includes('--read-only'));
  assert.equal(at('--user'), '10001:10001');
  assert.equal(at('--cap-drop'), 'ALL');
  assert.equal(a[a.indexOf('--security-opt') + 1], 'no-new-privileges');
  assert.equal(at('--pids-limit'), '128');
  assert.equal(at('--memory'), '512m');
  assert.equal(at('--memory-swap'), '512m');
  assert.equal(at('--cpus'), '1');
  for (const bad of ['--privileged', '-v', '--volume', '--mount', '-p', '--publish', '--device', '--cap-add', '--env-file']) assert.ok(!a.includes(bad), bad);
  assert.deepEqual(a.slice(-3), ['sh', '-c', 'node server.js']);
});

test('unsafe arguments are refused, each one on its own', () => {
  const head = args().slice(0, args().length - 4);
  const withFlag = (extra: string[]): string[] => [...head, ...extra];
  for (const extra of [['--privileged'], ['-v', 'hostdata:/host'], ['--volume', '/:/h'], ['--mount', 'type=bind,src=/,dst=/h'], ['-p', '3000:3000'], ['--publish', '3000'], ['--device', '/dev/sda'], ['--cap-add', 'SYS_ADMIN'], ['--pid', 'host'], ['--env-file', 'local.env'], ['--security-opt', 'seccomp=unconfined'], ['--add-host', 'x:1.1.1.1'], ['--userns', 'host']]) {
    assert.throws(() => assertSafeRunArgs(withFlag(extra), 'none'), /unsafe container arguments refused/, extra.join(' '));
  }
  const drop = (flag: string, n = 2): string[] => { const h = head.slice(); const i = h.indexOf(flag); h.splice(i, n); return h; };
  assert.throws(() => assertSafeRunArgs(head.filter((x) => x !== '--read-only'), 'none'), /--read-only/);
  assert.throws(() => assertSafeRunArgs(drop('--cap-drop'), 'none'), /capabilities/);
  assert.throws(() => assertSafeRunArgs(drop('--pids-limit'), 'none'), /--pids-limit/);
  assert.throws(() => assertSafeRunArgs(drop('--memory'), 'none'), /--memory/);
  assert.throws(() => assertSafeRunArgs(drop('--cpus'), 'none'), /--cpus/);
  assert.throws(() => assertSafeRunArgs(drop('--security-opt'), 'none'), /no-new-privileges/);
  assert.throws(() => args({ user: '0:0' }), /root/);
  assert.throws(() => args({ user: 'root' }), /root/);
  assert.throws(() => args({ network: 'host' }), /internal network/);
  assert.throws(() => args({ network: 'bridge' }), /network/);
  assert.throws(() => args({ network: 'some-other-net' }), /network/);
  assert.doesNotThrow(() => args({ network: 'hp-prove-net-x-1' }));
});

test('the build phase installs from the lockfile without install scripts; the run phase has no network', () => {
  const f = dockerfile(recipe({ install: ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/'] }));
  assert.match(f, /^FROM node:22-slim$/m);
  assert.match(f, /^RUN npm ci --ignore-scripts .*--registry=https:\/\/registry\.npmjs\.org\/$/m);
  assert.match(f, /^USER 10001:10001$/m);
  assert.doesNotMatch(dockerfile(recipe()), /RUN/);
  const b = buildArgs('t', 'run1', '/ctx');
  assert.deepEqual(b.slice(0, 3), ['build', '--label', 'hullproof.prove=run1']);
  assert.ok(!b.includes('--privileged') && !b.includes('--network') || b[b.indexOf('--network') + 1] !== 'host');
});

test('available: a missing or stopped runtime gives the command to fix it', async () => {
  assert.deepEqual(await new ContainerRunner(new FakeRuntime()).available(), { ok: true });
  const stopped = await new ContainerRunner(new FakeRuntime({ infoOk: false })).available();
  assert.ok(!stopped.ok && /colima start/.test(stopped.reason));
  const missing = new FakeRuntime();
  missing.run = async () => ({ code: null, stdout: '', stderr: 'docker: command not found', timedOut: false });
  const m = await new ContainerRunner(missing).available();
  assert.ok(!m.ok && /brew install colima docker/.test(m.reason));
});

test('prepare writes the executor and the Dockerfile into the copy, and a failed build is a reason, not a crash', async () => {
  const d = copyDir();
  const rt = new FakeRuntime();
  const p = await new ContainerRunner(rt).prepare({ recipe: recipe(), copyDir: d, sourceDir: d, limits: DEFAULT_LIMITS });
  assert.ok(p.ok);
  for (const f of ['spec.ts', 'executor.ts', 'exec-main.ts']) assert.ok(existsSync(join(d, '.hullproof-exec', f)), f);
  assert.match(readFileSync(join(d, 'Dockerfile.hullproof'), 'utf8'), /FROM node:22-slim/);
  assert.equal(rt.find('build').length, 1);
  const failed = await new ContainerRunner(new FakeRuntime({ buildOk: false })).prepare({ recipe: recipe(), copyDir: copyDir(), sourceDir: d, limits: DEFAULT_LIMITS });
  assert.ok(!failed.ok && failed.code === 'build_failed' && /npm ERR/.test(failed.reason));
});

test('start, health check, executor inside the sandbox, and teardown that leaves nothing', async () => {
  const app = await fakeApp('vulnerable');
  try {
    const rt = new FakeRuntime({ appPort: app.port, healthAfter: 2 });
    const runner = new ContainerRunner(rt, { sleepMs: 1 });
    const d = copyDir();
    const p = await runner.prepare({ recipe: recipe(), copyDir: d, sourceDir: d, limits: DEFAULT_LIMITS });
    assert.ok(p.ok);
    if (!p.ok) return;
    const s = await p.prepared.start();
    assert.ok(s.ok);
    if (!s.ok) return;
    const run = rt.find('run')[0];
    assert.equal(run[run.indexOf('--network') + 1], 'none');
    assert.ok(run.includes('--read-only') && run.includes('--tmpfs'));
    assert.ok(run.some((x) => x === 'DB_PATH=/data/app.db'), 'the data folder token is filled in');
    assert.ok(run.some((x) => x.startsWith('/data:rw')), 'a writable data folder is a tmpfs, not a host mount');
    assert.deepEqual(run.slice(-3), ['sh', '-c', 'node seed.js && exec node server.js']);
    assert.equal(rt.find('exec').filter((c) => c.some((a) => a.startsWith('fetch('))).length, 3, 'the health check retried until the app answered');
    const r = await s.instance.runSpec(idorSpec());
    assert.ok(r.ok && r.outcome === 'proven', JSON.stringify(r));
    const ex = rt.find('exec').find((c) => c.includes(`${EXEC_DIR}/exec-main.ts`))!;
    assert.deepEqual(ex.slice(0, 6), ['exec', '-i', 'hp-prove-' + run[run.indexOf('--name') + 1].slice(9), 'timeout', '-s', 'KILL']);
    assert.equal(ex[ex.length - 1], 'http://127.0.0.1:3000', 'the executor is given the sandbox loopback address only');
    const left = await s.instance.stop();
    assert.deepEqual(left.left_behind, []);
    assert.ok(rt.find('rm').some((c) => c.includes('-f')), 'the container is removed');
    const after = await s.instance.exec(['node', '-e', '1']);
    assert.match(after.stderr, /stopped/, 'a stopped instance runs nothing');
    const t = await p.prepared.dispose();
    assert.deepEqual(t.left_behind, []);
    assert.ok(rt.find('rmi').length >= 1, 'the image is removed');
    for (const kind of ['ps', 'images', 'network', 'volume']) assert.ok(rt.calls.some((c) => c[0] === kind && c.some((a) => a.startsWith('label=hullproof.prove='))), `${kind} was checked for leftovers`);
  } finally { await app.close(); }
});

test('teardown reports what is left behind', async () => {
  const rt = new FakeRuntime({ leftovers: { container: ['abc123'], network: ['net9'] } });
  const d = copyDir();
  const p = await new ContainerRunner(rt).prepare({ recipe: recipe(), copyDir: d, sourceDir: d, limits: DEFAULT_LIMITS });
  assert.ok(p.ok);
  if (p.ok) assert.deepEqual((await p.prepared.dispose()).left_behind, ['container abc123', 'network net9']);
});

test('a failed start and a health check that never passes are reasons, and the container is removed', async () => {
  const d = copyDir();
  for (const [script, code] of [[{ runOk: false }, 'start_failed'], [{ healthAfter: 999, notRunningAfterRun: false }, 'health_failed'], [{ healthAfter: 999, notRunningAfterRun: true }, 'start_failed']] as const) {
    const rt = new FakeRuntime(script);
    const p = await new ContainerRunner(rt, { sleepMs: 1 }).prepare({ recipe: recipe(), copyDir: d, sourceDir: d, limits: { ...DEFAULT_LIMITS, healthMs: 40 } });
    assert.ok(p.ok);
    if (!p.ok) continue;
    const s = await p.prepared.start();
    assert.ok(!s.ok && s.code === code, `${JSON.stringify(script)} gave ${JSON.stringify(s)}`);
    if (!s.ok) assert.match(s.reason, /EADDRINUSE|did not start|did not answer|stopped/);
    assert.ok(rt.find('rm').length >= 1, 'cleaned up');
  }
});

test('Postgres runs on an internal network with no route out, and the app joins it', async () => {
  const d = copyDir();
  mkdirSync(join(d, 'db/migrations'), { recursive: true });
  writeFileSync(join(d, 'db/migrations/001.sql'), 'create table t(id int);');
  writeFileSync(join(d, 'seed.sql'), 'insert into t values (1);');
  const app = await fakeApp();
  try {
    const rt = new FakeRuntime({ appPort: app.port });
    const r = recipe({ data_store: { kind: 'postgres', migrations: ['db/migrations/001.sql'], seed_sql: 'seed.sql' }, env: { DATABASE_URL: '{PGURL}' }, seed: null });
    const p = await new ContainerRunner(rt, { sleepMs: 1 }).prepare({ recipe: r, copyDir: d, sourceDir: d, limits: DEFAULT_LIMITS });
    assert.ok(p.ok);
    if (!p.ok) return;
    const s = await p.prepared.start();
    assert.ok(s.ok, s.ok ? '' : JSON.stringify(s));
    const net = rt.find('network')[0];
    assert.deepEqual(net.slice(0, 3), ['network', 'create', '--internal']);
    const runs = rt.find('run');
    assert.equal(runs.length, 2);
    for (const run of runs) { assert.equal(run[run.indexOf('--network') + 1], net[net.length - 1]); assert.ok(run.includes('--read-only')); assert.ok(run.includes('--cap-drop')); }
    assert.ok(runs[1].some((x) => /^DATABASE_URL=postgres:\/\/postgres:dummy@hp-prove-pg-/.test(x)), 'the app is pointed at the ephemeral database');
    assert.deepEqual(rt.inputs.slice(0, 2), ['create table t(id int);', 'insert into t values (1);'], 'migrations, then the seed, in that order');
    await s.instance.stop();
    assert.ok(rt.find('network').some((c) => c[1] === 'rm'), 'the network is removed');
    assert.ok(rt.find('rm').length >= 2, 'both containers are removed');
  } finally { await app.close(); }
});
