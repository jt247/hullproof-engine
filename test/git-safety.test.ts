// gitSafety reads .git/config and, when it exists, .git/config.worktree (newer checkouts write one), with the same three counts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gitSafety } from '../src/commands/git.ts';

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-gs-'));
  assert.equal(spawnSync('git', ['-C', dir, 'init', '-q']).status, 0);
  return dir;
}

test('a plain repository passes, and a benign config.worktree does not stop the scan', () => {
  const dir = repo();
  assert.equal(gitSafety(dir).ok, true);
  writeFileSync(join(dir, '.git/config.worktree'), '[core]\n\tsparseCheckout = false\n');
  assert.equal(gitSafety(dir).ok, true);
});

test('code running keys in config.worktree are refused like those in config', () => {
  const dir = repo();
  writeFileSync(join(dir, '.git/config.worktree'), '[core]\n\tfsmonitor = /tmp/x\n');
  const s = gitSafety(dir);
  assert.equal(s.ok, false);
  assert.match(s.message, /could run code/);
  const dir2 = repo();
  writeFileSync(join(dir2, '.git/config.worktree'), '[filter "x"]\n\tclean = cat\n');
  assert.equal(gitSafety(dir2).ok, false);
});
