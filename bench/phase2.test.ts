// The Phase 2 bench helpers: the seeded sampler and the entry point comparison.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compare, parseHand, type MapEntry } from './compare-entrypoints.ts';
import { mulberry32, sample } from './sample.ts';

test('sample: same seed, same draw; a different seed draws differently; the draw is a subset without repeats', () => {
  const items = Array.from({ length: 200 }, (_, i) => `server.ts:${i + 1}`);
  const a = sample(items, 20261011, 25);
  assert.deepEqual(a, sample(items.slice().reverse(), 20261011, 25), 'input order does not matter');
  assert.notDeepEqual(a, sample(items, 20261012, 25));
  assert.equal(new Set(a).size, 25);
  assert.ok(a.every((x) => items.includes(x)));
  assert.deepEqual(sample(items, 20261011, 5, 25), sample(items, 20261011, 30).slice(25), 'skip continues the same draw');
});

test('mulberry32 is a pure function of its seed', () => {
  const r1 = mulberry32(1);
  const r2 = mulberry32(1);
  assert.deepEqual([r1(), r1(), r1()], [r2(), r2(), r2()]);
});

test('compare: a hand row matches the same file and line, or the handler location', () => {
  const md = '## 2. The demo\n\n| # | Method | File and line |\n|---|---|---|\n| 1 | GET /a | `src/a.ts:3` |\n| 2 | GET /b | `src/b.ts:5` |\n| 3 | GET /c | `src/c.ts:9` |\n\n## 3. Other\n\n| 1 | x | `skip.ts:1` |\n';
  const hand = parseHand(md, '2. The demo');
  assert.equal(hand.length, 3);
  const e = (file: string, line: number, handler: MapEntry['handler'] = null): MapEntry => ({ file, line, kind: 'http_route', method: 'GET', path: null, name: null, handler });
  const r = compare(hand, [e('src/a.ts', 3), e('server.ts', 40, { file: 'src/b.ts', line: 5 }), e('src/z.ts', 1)]);
  assert.equal(r.found.length, 2);
  assert.deepEqual(r.missing.map((h) => h.file), ['src/c.ts']);
  assert.deepEqual(r.extra.map((x) => x.file), ['src/z.ts']);
});
