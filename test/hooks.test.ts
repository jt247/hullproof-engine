// The pre-commit hook: installer modes, and the fast check run through real `git commit` calls. A planted secret must be blocked in
// under 5 seconds, a clean commit must pass, and `git commit --no-verify` must still work. The secret is built from parts so this
// file never holds a secret shaped value.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { installHooks, MARKER_BEGIN } from '../src/hooks/install.ts';
import { KIT, KIT_SKIP } from './helpers/kit.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const FAKE_KEY = ['AK', 'IA', 'Q7RZ3MXP', '2VKD6WNB'].join('');
const have = (bin: string): boolean => spawnSync(bin, ['--version'], { encoding: 'utf8' }).status === 0;
const SKIP = KIT_SKIP || (have('gitleaks') ? false : 'gitleaks not installed');
const SEMGREP_SKIP = SKIP || (have('semgrep') ? false : 'semgrep not installed');
const ID = ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false'];
const ENV = { ...process.env, HULLPROOF_KIT: KIT, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' };
const git = (d: string, ...a: string[]) => spawnSync('git', ['-C', d, ...ID, ...a], { encoding: 'utf8', env: ENV });
const must = (d: string, ...a: string[]): void => { const r = git(d, ...a); assert.equal(r.status, 0, `${a.join(' ')}: ${r.stderr}`); };

function repo(): string {
  const d = mkdtempSync(join(tmpdir(), 'hp-hook-'));
  must(d, 'init', '-q', '-b', 'main');
  writeFileSync(join(d, 'README.md'), '# fixture\n');
  writeFileSync(join(d, 'index.js'), 'export const add = (a, b) => a + b;\n');
  must(d, 'add', '-A'); must(d, 'commit', '-q', '-m', 'init');
  return d;
}
const hookFile = (d: string): string => join(d, '.git/hooks/pre-commit');

test('plain git: install writes one hook, a second install changes nothing, uninstall removes only our hook', () => {
  const d = repo();
  const r1 = installHooks({ repo: d, mode: null, dryRun: false, uninstall: false });
  assert.equal(r1.code, 0, r1.lines.join('\n'));
  const text = readFileSync(hookFile(d), 'utf8');
  assert.match(text, /^#!\/bin\/sh\n# hullproof pre-commit hook/);
  assert.match(text, /hooks run/);
  assert.equal(installHooks({ repo: d, mode: null, dryRun: false, uninstall: false }).code, 0);
  assert.equal(readFileSync(hookFile(d), 'utf8'), text);
  assert.equal(installHooks({ repo: d, mode: null, dryRun: false, uninstall: true }).code, 0);
  assert.equal(existsSync(hookFile(d)), false);
  // A hook of someone else is never overwritten or removed.
  writeFileSync(hookFile(d), '#!/bin/sh\necho mine\n');
  const refused = installHooks({ repo: d, mode: null, dryRun: false, uninstall: false });
  assert.equal(refused.code, 2);
  assert.equal(readFileSync(hookFile(d), 'utf8'), '#!/bin/sh\necho mine\n');
  assert.equal(installHooks({ repo: d, mode: null, dryRun: false, uninstall: true }).code, 2);
  assert.equal(readFileSync(hookFile(d), 'utf8'), '#!/bin/sh\necho mine\n');
});

test('dry run writes nothing', () => {
  const d = repo();
  const r = installHooks({ repo: d, mode: null, dryRun: true, uninstall: false });
  assert.equal(r.code, 0);
  assert.equal(existsSync(hookFile(d)), false);
  assert.ok(r.lines.some((l) => l.startsWith('would write')));
});

test('Husky is detected and its pre-commit file gets one marked block; the other lines stay', () => {
  const d = repo();
  mkdirSync(join(d, '.husky'));
  writeFileSync(join(d, '.husky/pre-commit'), 'npm test\n');
  const det = installHooks({ repo: d, mode: null, dryRun: false, uninstall: false });
  assert.equal(det.code, 0, det.lines.join('\n'));
  assert.match(det.lines[0], /mode husky/);
  const t = readFileSync(join(d, '.husky/pre-commit'), 'utf8');
  assert.ok(t.startsWith('npm test\n') && t.includes(MARKER_BEGIN));
  assert.equal(existsSync(hookFile(d)), false);
  installHooks({ repo: d, mode: null, dryRun: false, uninstall: false });
  assert.equal(readFileSync(join(d, '.husky/pre-commit'), 'utf8'), t);
  installHooks({ repo: d, mode: null, dryRun: false, uninstall: true });
  assert.equal(readFileSync(join(d, '.husky/pre-commit'), 'utf8').trim(), 'npm test');
});

test('the pre-commit framework gets a local hook appended under repos, and the file stays valid YAML', () => {
  const d = repo();
  writeFileSync(join(d, '.pre-commit-config.yaml'), 'repos:\n  - repo: https://example.invalid/hooks\n    rev: v1\n    hooks:\n      - id: a\n');
  const r = installHooks({ repo: d, mode: null, dryRun: false, uninstall: false });
  assert.equal(r.code, 0, r.lines.join('\n'));
  assert.match(r.lines[0], /mode pre-commit/);
  const t = readFileSync(join(d, '.pre-commit-config.yaml'), 'utf8');
  assert.ok(t.includes('id: hullproof') && t.includes('pass_filenames: false') && t.includes('always_run: true'));
  const y = spawnSync('python3', ['-c', 'import sys,yaml;d=yaml.safe_load(open(sys.argv[1]));print(len(d["repos"]), d["repos"][-1]["hooks"][0]["id"])', join(d, '.pre-commit-config.yaml')], { encoding: 'utf8' });
  if (y.status === 0) assert.equal(y.stdout.trim(), '2 hullproof');
  installHooks({ repo: d, mode: null, dryRun: false, uninstall: true });
  assert.ok(!readFileSync(join(d, '.pre-commit-config.yaml'), 'utf8').includes('hullproof'));
  // A file with a key after repos is not edited blindly: the snippet is printed instead.
  writeFileSync(join(d, '.pre-commit-config.yaml'), 'repos: []\nci:\n  autofix_prs: false\n');
  const printed = installHooks({ repo: d, mode: 'pre-commit', dryRun: false, uninstall: false });
  assert.equal(printed.code, 0);
  assert.equal(readFileSync(join(d, '.pre-commit-config.yaml'), 'utf8'), 'repos: []\nci:\n  autofix_prs: false\n');
  assert.ok(printed.lines.join('\n').includes('id: hullproof'));
});

test('a planted secret is blocked by git commit in under 5 seconds; --no-verify still commits', { skip: SKIP }, () => {
  const d = repo();
  // The hook is installed the way a user installs it, then called by git itself through the shell script.
  const inst = spawnSync(process.execPath, [CLI, 'hooks', 'install', d], { encoding: 'utf8', env: ENV });
  assert.equal(inst.status, 0, inst.stderr);
  writeFileSync(join(d, 'config.js'), `export const awsKeyId = "${FAKE_KEY}";\n`);
  must(d, 'add', 'config.js');
  const t0 = Date.now();
  const blocked = git(d, 'commit', '-q', '-m', 'add config');
  const seconds = (Date.now() - t0) / 1000;
  assert.equal(blocked.status, 1, blocked.stdout + blocked.stderr);
  assert.match(blocked.stderr, /BLOCKED/);
  assert.match(blocked.stderr, /config\.js:1/);
  assert.ok(!blocked.stderr.includes(FAKE_KEY), 'the secret is never printed');
  assert.ok(seconds < 5, `blocked in ${seconds}s`);
  process.stderr.write(`# planted secret blocked by git commit in ${seconds.toFixed(2)}s\n`);
  assert.equal(git(d, 'log', '--oneline').stdout.trim().split('\n').length, 1, 'no commit was made');
  const skipped = git(d, 'commit', '-q', '--no-verify', '-m', 'add config anyway');
  assert.equal(skipped.status, 0, skipped.stderr);
  assert.equal(git(d, 'log', '--oneline').stdout.trim().split('\n').length, 2);
});

test('a clean commit passes through the hook', { skip: SKIP }, () => {
  const d = repo();
  assert.equal(spawnSync(process.execPath, [CLI, 'hooks', 'install', d], { encoding: 'utf8', env: ENV }).status, 0);
  writeFileSync(join(d, 'util.js'), 'export const double = (n) => n * 2;\n');
  must(d, 'add', 'util.js');
  const t0 = Date.now();
  const ok = git(d, 'commit', '-q', '-m', 'add util');
  assert.equal(ok.status, 0, ok.stderr);
  process.stderr.write(`# clean commit through the hook in ${((Date.now() - t0) / 1000).toFixed(2)}s\n`);
  assert.equal(git(d, 'log', '--oneline').stdout.trim().split('\n').length, 2);
});

test('only staged files count: a secret in a file that is not staged does not block', { skip: SKIP }, () => {
  const d = repo();
  writeFileSync(join(d, 'old.js'), `export const k = "${FAKE_KEY}";\n`);
  must(d, 'add', 'old.js'); must(d, 'commit', '-q', '--no-verify', '-m', 'old secret already in history');
  writeFileSync(join(d, 'other.js'), 'export const one = 1;\n');
  must(d, 'add', 'other.js');
  const r = spawnSync(process.execPath, [CLI, 'hooks', 'run', d], { encoding: 'utf8', env: ENV });
  assert.equal(r.status, 0, r.stderr);
  // The staged content counts, not the working tree: a secret in the working tree only is not in the commit.
  writeFileSync(join(d, 'other.js'), `export const k = "${FAKE_KEY}";\n`);
  const r2 = spawnSync(process.execPath, [CLI, 'hooks', 'run', d], { encoding: 'utf8', env: ENV });
  assert.equal(r2.status, 0, 'the secret is not staged');
  must(d, 'add', 'other.js');
  assert.equal(spawnSync(process.execPath, [CLI, 'hooks', 'run', d], { encoding: 'utf8', env: ENV }).status, 1);
});

test('a BLOCKER finding in a staged source file blocks (Semgrep rule), and --no-semgrep skips it', { skip: SEMGREP_SKIP }, () => {
  const d = repo();
  writeFileSync(join(d, 'db.js'), 'export async function findUser(db, id) {\n  return db.query("SELECT * FROM users WHERE id = " + id);\n}\n');
  must(d, 'add', 'db.js');
  const r = spawnSync(process.execPath, [CLI, 'hooks', 'run', d], { encoding: 'utf8', env: ENV });
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /BLOCKER db\.js:2/);
  assert.match(r.stderr, /SEC-API-017/);
  assert.equal(spawnSync(process.execPath, [CLI, 'hooks', 'run', d, '--no-semgrep'], { encoding: 'utf8', env: ENV }).status, 0);
});

test('an engine error never blocks a commit, and a missing engine in the hook script lets the commit through', { skip: SKIP }, () => {
  const d = repo();
  writeFileSync(join(d, 'x.js'), 'export const x = 1;\n');
  must(d, 'add', 'x.js');
  const bad = spawnSync(process.execPath, [CLI, 'hooks', 'run', d, '--kit', join(d, 'no-such-kit')], { encoding: 'utf8', env: { ...ENV, HULLPROOF_KIT: '' } });
  assert.equal(bad.status, 0);
  // A hook script whose command does not exist exits 127 inside, and the script turns that into a pass.
  writeFileSync(hookFile(d), `#!/bin/sh\n# hullproof pre-commit hook. test\nno-such-hullproof-command hooks run\nstatus=$?\nif [ "$status" -eq 1 ]; then exit 1; fi\nexit 0\n`, { mode: 0o755 });
  assert.equal(git(d, 'commit', '-q', '-m', 'x').status, 0);
});
