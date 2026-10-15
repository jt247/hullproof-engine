// Internal (the public export leaves this file out: it needs bench/packs-measure.ts and the internal fixture area). A fresh measurement of
// each pack on its fixture gives the figures recorded in packs/<id>/fixture-result.json, so a recorded result cannot go stale. A blind
// answer key that is kept outside the repository is used when it is on this machine and skipped, with the reason, when it is not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildResult, keyPaths, loadKeys, OUTSIDE_KEYS, ROOT } from '../bench/packs-measure.ts';
import type { FixtureResult, PackManifest } from '../src/packs/manifest.ts';
import { stableJson } from '../src/util.ts';

const ids = readdirSync(join(ROOT, 'packs')).sort();
const manifest = (id: string): PackManifest => JSON.parse(readFileSync(join(ROOT, 'packs', id, 'pack.json'), 'utf8')) as PackManifest;

for (const id of ids) {
  const m = manifest(id);
  for (const k of keyPaths(m)) {
    const skip = existsSync(k.path) ? false : `NOT RUN: the ${k.kind === 'outside_repo' ? 'blind answer key (kept outside the repository, local only)' : 'answer key'} is not at ${k.path}`;
    test(`${id}: a fresh measurement with the ${k.kind} key equals the recorded result`, { skip }, () => {
      const recorded = JSON.parse(readFileSync(join(ROOT, m.fixture.result), 'utf8')) as FixtureResult;
      const keys = loadKeys(m).filter((x) => x.kind === k.kind);
      const fresh = buildResult(m, keys, recorded.measured, recorded);
      const mine = fresh.result.measurements.filter((x) => x.source.includes(`key ${k.kind === 'in_repo' ? `packs/${id}/answer-key.json` : 'kept outside the repository'}`));
      assert.ok(mine.length === 1, 'one measurement per key');
      const was = recorded.measurements.find((x) => x.source === mine[0].source);
      assert.ok(was, `the recorded result has the measurement made with the ${k.kind} key`);
      assert.equal(stableJson(mine[0]), stableJson(was), `${id}: run node bench/packs-measure.ts --write ${id}`);
    });
  }
}

test('the blind answer keys are not in the repository', () => {
  for (const id of ids) assert.ok(!existsSync(join(ROOT, 'packs', id, 'blind-key.json')));
  assert.ok(!OUTSIDE_KEYS.startsWith(ROOT), 'the blind key folder is outside the engine tree');
});
