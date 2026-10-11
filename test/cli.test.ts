// The hullproof command: subcommands, exit codes, and byte identical output across separate processes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ENGINE_VERSION } from '../src/version.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const FIX = fileURLToPath(new URL('./fixtures/stacks/', import.meta.url));
const run = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });

test('version and help', () => {
  assert.equal(run('version').stdout, `${ENGINE_VERSION}\n`);
  const h = run('help');
  assert.equal(h.status, 0);
  for (const c of ['discover', 'scan', 'report', 'gate', 'version', 'help']) assert.match(h.stdout, new RegExp(`\\n  ${c} `));
  assert.equal(run().status, 0);
});

test('scan refuses a folder that is not a git repository, and report and gate need a scan folder (exit 2)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-cli-nogit-'));
  for (const c of ['scan', 'report', 'gate']) {
    const r = run(c, dir, '--out', join(dir, 'out'));
    assert.equal(r.status, 2, c);
    assert.match(r.stderr, new RegExp(`hullproof ${c}: `));
  }
  assert.equal(run('scan', dir, '--edition', 'gold').status, 2);
  assert.equal(run('gate', dir, '--bogus').status, 2);
  rmSync(dir, { recursive: true, force: true });
});

test('bad input exits 2', () => {
  assert.equal(run('frobnicate').status, 2);
  assert.equal(run('discover', '--bogus').status, 2);
  assert.equal(run('discover', '--out').status, 2);
  assert.equal(run('discover', join(FIX, 'does-not-exist'), '--out', '-').status, 2);
});

test('discover writes stack.json, and two processes write the same bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-cli-'));
  try {
    for (const n of ['a', 'b']) {
      const r = run('discover', join(FIX, 'iac-clouds'), '--out', join(dir, n));
      assert.equal(r.status, 0, r.stderr);
    }
    const a = readFileSync(join(dir, 'a', 'stack.json'));
    assert.ok(a.equals(readFileSync(join(dir, 'b', 'stack.json'))));
    const piped = run('discover', join(FIX, 'iac-clouds'), '--out', '-');
    assert.equal(piped.stdout, a.toString('utf8'));
    assert.ok(a.toString('utf8').endsWith('}\n') && !a.includes('\r'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
