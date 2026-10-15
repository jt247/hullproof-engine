// The Postgres path against a REAL container runtime: an ephemeral Postgres on an internal network, migrations and seed applied with
// psql, the app container reaching the database by name, and neither container reaching the internet. Skipped (NOT RUN) without a runtime.
// This tests the sandbox plumbing with an app that has no database driver; a full Postgres fixture app would need a driver from the registry.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Recipe } from '../src/types/index.ts';
import { CliRuntime, ContainerRunner } from '../src/prove/container.ts';
import { DEFAULT_LIMITS } from '../src/prove/runner.ts';

const rt = new CliRuntime(process.env.HULLPROOF_CONTAINER_BIN ?? 'docker');
const runner = new ContainerRunner(rt);
const avail = await runner.available();
const skip = avail.ok ? false : `NOT RUN: no container runtime (${avail.reason})`;

test('REAL CONTAINER: Postgres on an internal network, migrations and seed applied, no route out, nothing left behind', { skip, timeout: 600_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-pg-'));
  mkdirSync(join(dir, 'db/migrations'), { recursive: true });
  writeFileSync(join(dir, 'db/migrations/001.sql'), 'create table t (id int primary key, note text);');
  writeFileSync(join(dir, 'seed.sql'), "insert into t values (1, 'CANARY-PG-1');");
  writeFileSync(join(dir, 'server.js'), "require('http').createServer((q,s)=>s.end('ok')).listen(3000);\n");
  const recipe: Recipe = { schema_version: '1.0.0', stack: 'node-express', base_image: 'node:22-slim', install: null, vendored_modules: false, seed: null, start: 'node server.js', port: 3000, port_from_env: false, health_path: '/', data_store: { kind: 'postgres', migrations: ['db/migrations/001.sql'], seed_sql: 'seed.sql' }, env: { DATABASE_URL: '{PGURL}' }, notes: [] };
  const p = await runner.prepare({ recipe, copyDir: dir, sourceDir: dir, limits: { ...DEFAULT_LIMITS, healthMs: 90_000 } });
  assert.ok(p.ok, p.ok ? '' : p.reason);
  if (!p.ok) return;
  try {
    const s = await p.prepared.start();
    assert.ok(s.ok, s.ok ? '' : s.reason);
    if (!s.ok) return;
    const probe = "const net=require('net');const u=new URL(process.env.DATABASE_URL);const c=(h,p)=>new Promise(r=>{const s=net.connect({host:h,port:p,timeout:3000});s.on('connect',()=>{s.destroy();r(true)});s.on('error',()=>r(false));s.on('timeout',()=>{s.destroy();r(false)})});(async()=>console.log(JSON.stringify({db:await c(u.hostname,5432),internet:await c('1.1.1.1',443)})))()";
    const r = await s.instance.exec(['node', '-e', probe], { timeoutMs: 30_000 });
    assert.deepEqual(JSON.parse(r.stdout.trim()), { db: true, internet: false }, 'the app reaches the database and not the internet');
    const names = (await rt.run(['ps', '-q', '--filter', 'label=hullproof.prove', '--format', '{{.Names}}'])).stdout.split('\n').filter(Boolean);
    const pg = (await rt.run(['ps', '--filter', 'label=hullproof.prove', '--format', '{{.Names}}'])).stdout.split('\n').find((n) => n.includes('-pg-'));
    assert.ok(pg && names.length >= 0, 'the database container is running');
    const q = await rt.run(['exec', pg!, 'psql', '-U', 'postgres', '-d', 'app', '-tA', '-c', 'select note from t where id = 1']);
    assert.equal(q.stdout.trim(), 'CANARY-PG-1', 'migrations then seed were applied');
    await s.instance.stop();
  } finally { assert.deepEqual((await p.prepared.dispose()).left_behind, []); }
  // Leftovers are checked per run through the label of this run (dispose above). A global listing would race with the other container tests.
});
