// Escape attempts against a REAL container: a network call, a host file read, a fork bomb, a long loop, a write to the root filesystem,
// running as root, and a memory bomb. They all have to fail contained. This file needs a container runtime. Without one every test is
// reported as skipped with the reason and the exact commands, and it must be read as NOT RUN, never as passed.
//   brew install colima docker && colima start
//   node --test test/prove-escape.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ContainerRunner, CliRuntime } from '../src/prove/container.ts';
import { runEscapeProbes, selfTestApp } from '../src/prove/probes.ts';
import { DEFAULT_LIMITS } from '../src/prove/runner.ts';

const rt = new CliRuntime(process.env.HULLPROOF_CONTAINER_BIN ?? 'docker');
const runner = new ContainerRunner(rt);
const avail = await runner.available();
const skip = avail.ok ? false : `NOT RUN: no container runtime (${avail.reason}). To run it: brew install colima docker; colima start; node --test test/prove-escape.test.ts`;

test('escape attempts are contained and teardown leaves nothing behind', { skip, timeout: 600_000 }, async () => {
  const app = selfTestApp();
  try {
    const p = await runner.prepare({ recipe: app.recipe, copyDir: app.dir, sourceDir: app.dir, limits: { ...DEFAULT_LIMITS, healthMs: 60_000 } });
    assert.ok(p.ok, p.ok ? '' : p.reason);
    if (!p.ok) return;
    const s = await p.prepared.start();
    assert.ok(s.ok, s.ok ? '' : s.reason);
    if (!s.ok) return;
    let results;
    try { results = await runEscapeProbes(s.instance, app.marker); } finally {
      const a = (await s.instance.stop()).left_behind;
      const b = (await p.prepared.dispose()).left_behind;
      assert.deepEqual([...a, ...b], [], 'teardown leaves nothing');
    }
    for (const r of results) assert.ok(r.ok, `${r.name} was NOT contained: ${r.detail}`);
    assert.equal(results.length, 6);
  } finally { app.cleanup(); }
});
