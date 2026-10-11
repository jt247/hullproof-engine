// Executable checks: every check FAILs on its fail fixture and does not FAIL on its pass fixture, definitions match the
// schema, PASS (static) is used only for repo authority requirements, and two runs give the same bytes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../src/discover/discover.ts';
import { makeContext } from '../src/checks/context.ts';
import { releaseLine, supportTable } from '../src/checks/ops.ts';
import { loadChecks, runChecks } from '../src/checks/run.ts';
import { stableJson } from '../src/util.ts';
import { validate } from './helpers/schema.ts';
import { KIT_CONTROLS } from './helpers/kit.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
// Checks that read a kit file are given this folder as the kit; the checks shipped in every edition read none, so an
// edition without such a check has no fixture kit and gets an empty folder.
const FIXTURE_KIT = existsSync(ROOT + 'test/fixtures/checks/_kit') ? ROOT + 'test/fixtures/checks/_kit' : mkdtempSync(join(tmpdir(), 'hp-fixture-kit-'));
// Requirements written in a standard document that the controls file does not hold yet.
const PENDING_IDS = /^SEC-CLOUD-0(4[6-9]|5[0-2])$/;
const checks = loadChecks();

function runOn(dir: string, id: string) {
  const ctx = makeContext(ROOT + dir, discover(ROOT + dir), [], FIXTURE_KIT);
  const out = runChecks(ctx, checks.filter((c) => c.id === id));
  return { result: out.results[0], notRun: out.not_run[0] };
}

for (const c of checks) {
  test(`${c.id}: FAIL on its fail fixture, not FAIL on its pass fixture`, () => {
    assert.ok(existsSync(ROOT + c.fixtures.fail) && existsSync(ROOT + c.fixtures.pass), 'both fixtures exist');
    const fail = runOn(c.fixtures.fail, c.id);
    assert.equal(fail.result?.result, 'FAIL', JSON.stringify(fail));
    assert.ok(fail.result.evidence.length > 0, 'a FAIL carries evidence');
    for (const e of fail.result.evidence) assert.ok(e.file && (e.line ?? 0) >= 0 && !e.file.startsWith('/'), JSON.stringify(e));
    const pass = runOn(c.fixtures.pass, c.id);
    assert.equal(pass.result?.result, c.on_true, JSON.stringify(pass));
  });
}

test('a check whose files are absent goes to not_run as not applicable, never PASS', () => {
  const r = runOn('test/fixtures/checks/cors-no-reflected-origin/pass', 'check.db.rls-every-table');
  assert.equal(r.result, undefined);
  assert.match(r.notRun.reason, /^not applicable: /);
});

test('the framework check cannot run without the kit table and says why', { skip: checks.some((c) => c.id === 'check.supply.framework-supported') ? false : 'check not in this edition' }, () => {
  const dir = ROOT + 'test/fixtures/checks/framework-supported/fail';
  const out = runChecks(makeContext(dir, discover(dir), [], null), checks.filter((c) => c.id === 'check.supply.framework-supported'));
  assert.deepEqual(out.results, []);
  assert.match(out.not_run[0].reason, /^cannot run: the kit folder is not known/);
});

test('JSON check definitions match schemas/check.schema.json; ids are unique', () => {
  const schema = JSON.parse(readFileSync(ROOT + 'schemas/check.schema.json', 'utf8'));
  const ids = new Set<string>();
  for (const c of checks) {
    assert.ok(!ids.has(c.id), c.id);
    ids.add(c.id);
    if (c.op === 'code') continue;
    const { source: _s, ...def } = c;
    assert.deepEqual(validate(schema, def), [], c.id);
  }
});

test('every SEC id exists in the kit controls (or is pending); PASS (static) only for repo authority', { skip: existsSync(KIT_CONTROLS) ? false : 'kit not present' }, () => {
  const controls = new Map((JSON.parse(readFileSync(KIT_CONTROLS, 'utf8')).controls as { id: string; authority: string }[]).map((c) => [c.id, c]));
  for (const c of checks) {
    for (const id of c.sec_ids) assert.ok(controls.has(id) || PENDING_IDS.test(id), `${c.id} names unknown ${id}`);
    if (c.on_true === 'PASS (static)' || c.on_false === 'PASS (static)') {
      for (const id of c.sec_ids) assert.equal(controls.get(id)?.authority, 'repo', `${c.id}: PASS (static) on ${id}`);
    }
  }
});

test('checks.json is byte identical over two runs and matches its schema', () => {
  const dir = ROOT + 'test/fixtures/checks/webhook-verified-before-use/fail';
  const a = stableJson(runChecks(makeContext(dir, discover(dir), [], FIXTURE_KIT)));
  const b = stableJson(runChecks(makeContext(dir, discover(dir), [], FIXTURE_KIT)));
  assert.equal(a, b);
  const schema = JSON.parse(readFileSync(ROOT + 'schemas/check-results.schema.json', 'utf8'));
  assert.deepEqual(validate(schema, JSON.parse(a)), []);
});

test('releaseLine and supportTable', () => {
  assert.equal(releaseLine('13.4.0', 1), '13');
  assert.equal(releaseLine('^0.85.2', 2), '0.85');
  assert.equal(releaseLine('~=5.2.1', 2), '5.2');
  assert.equal(releaseLine('latest', 1), null);
  const table = '# Support table\n\n## Next.js\n\n| Release line | Released | Security fixes end | Status |\n|---|---|---|---|\n| 15 | 2024-10-21 | 2026-10-21 | Supported |\n| 13 | 2022-10-25 | 2024-12-21 | Ended |\n';
  const t = supportTable(table, 'Next.js');
  assert.equal(t?.get('13'), 'Ended');
  assert.equal(t?.get('15'), 'Supported');
  assert.equal(supportTable('# x', 'Next.js'), null);
});

test('ctx.tracked() lists committed files inside folders discovery skips, such as .vercel', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-tracked-'));
  mkdirSync(join(dir, '.vercel'));
  writeFileSync(join(dir, '.vercel/project.json'), '{"projectId":"x"}\n');
  writeFileSync(join(dir, 'index.js'), 'export {}\n');
  const env = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' };
  for (const args of [['init', '-q'], ['add', '-A']]) assert.equal(spawnSync('git', ['-C', dir, ...args], { env }).status, 0);
  const ctx = makeContext(dir, discover(dir), [], null);
  assert.ok(!ctx.files.includes('.vercel/project.json'), 'discovery skips .vercel');
  assert.deepEqual(ctx.tracked(), ['.vercel/project.json', 'index.js']);
  assert.equal(makeContext(FIXTURE_KIT, discover(FIXTURE_KIT), [], null).tracked(), null, 'null outside a git repository');
});
