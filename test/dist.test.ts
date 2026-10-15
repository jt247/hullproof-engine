// The compiled build (dist/) behaves exactly like the sources, and the package works when installed from a tarball into an empty
// folder. `npm pack` runs the build; nothing is published. The install runs offline: the engine has no runtime dependencies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { KIT, KIT_SKIP } from './helpers/kit.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const APP = fileURLToPath(new URL('./fixtures/scanners/app/', import.meta.url));
const have = (bin: string): boolean => spawnSync(bin, ['--version'], { encoding: 'utf8' }).status === 0;
const SKIP = KIT_SKIP || (have('semgrep') && have('gitleaks') ? false : 'semgrep or gitleaks not installed');
const G = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' };
const FILES = ['findings.json', 'report.md', 'results.sarif', 'pr-comment.md'];
const sha = (p: string): string => createHash('sha256').update(readFileSync(p)).digest('hex');

function plantedRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-dist-repo-'));
  cpSync(APP, dir, { recursive: true });
  for (const a of [['init', '-q'], ['add', '-A'], ['commit', '-q', '-m', 'init']]) assert.equal(spawnSync('git', ['-C', dir, ...a], { env: G }).status, 0);
  return dir;
}
const runCi = (entry: string[], repo: string, art: string) =>
  spawnSync(process.execPath, [...entry, 'ci', repo, '--artifacts', art, '--out', join(art, '..', 'hp')], { encoding: 'utf8', env: { ...process.env, HULLPROOF_KIT: KIT } });

test('build, then dist/cli.js gives the same four ci files as src/cli.ts', { skip: SKIP }, () => {
  const b = spawnSync(process.execPath, [join(ROOT, 'build.mjs')], { encoding: 'utf8' });
  assert.equal(b.status, 0, b.stderr + b.stdout);
  assert.ok(existsSync(join(ROOT, 'dist/cli.js')) && existsSync(join(ROOT, 'dist/mapping/maps/trivy.json')));
  assert.equal(spawnSync(process.execPath, [join(ROOT, 'dist/cli.js'), 'version'], { encoding: 'utf8' }).stdout, readFileSync(join(ROOT, 'src/version.ts'), 'utf8').match(/'([^']+)'/)![1] + '\n');
  const repo = plantedRepo();
  const out = mkdtempSync(join(tmpdir(), 'hp-dist-out-'));
  const a = runCi([join(ROOT, 'src/cli.ts')], repo, join(out, 'src'));
  const d = runCi([join(ROOT, 'dist/cli.js')], repo, join(out, 'dist'));
  assert.equal(a.status, 1, a.stderr);
  assert.equal(d.status, 1, d.stderr);
  for (const f of FILES) assert.equal(sha(join(out, 'dist', f)), sha(join(out, 'src', f)), f);
});

test('npm pack, install the tarball in an empty folder, run the bin from node_modules', { skip: SKIP, timeout: 240000 }, () => {
  const tmp = mkdtempSync(join(tmpdir(), 'hp-pack-'));
  const pack = spawnSync('npm', ['pack', '--pack-destination', tmp, '--json'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(pack.status, 0, pack.stderr);
  const info = JSON.parse(pack.stdout)[0] as { filename: string; files: { path: string }[] };
  // The tarball holds the build and the data the build reads, and nothing from the Pro folder, tests, benchmarks or scripts.
  const paths = info.files.map((f) => f.path);
  assert.ok(paths.includes('dist/cli.js') && paths.some((p) => p.startsWith('checks/') && p.endsWith('.json')) && paths.includes('package.json'));
  const proFolder = ['rules', 'pro'].join('-');
  assert.deepEqual(paths.filter((p) => p.startsWith(proFolder) || /^(test|bench|scripts|docs|public)\//.test(p) || /(^|\/)\.env/.test(p)), []);
  const dir = join(tmp, 'consumer');
  mkdirSync(dir);
  writeFileSync(join(dir, 'package.json'), '{"name":"consumer","version":"1.0.0","private":true}\n');
  const inst = spawnSync('npm', ['install', join(tmp, info.filename), '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: dir, encoding: 'utf8' });
  assert.equal(inst.status, 0, inst.stderr);
  const bin = join(dir, 'node_modules/.bin/hullproof');
  assert.ok(existsSync(bin));
  assert.deepEqual(readdirSync(join(dir, 'node_modules')).filter((n) => n !== '.bin' && n !== '.package-lock.json'), ['hullproof']);
  const v = spawnSync(bin, ['version'], { encoding: 'utf8' });
  assert.equal(v.status, 0, v.stderr);
  const repo = plantedRepo();
  const art = join(tmp, 'art');
  const r = spawnSync(bin, ['ci', repo, '--artifacts', art, '--out', join(tmp, 'hp')], { encoding: 'utf8', env: { ...process.env, HULLPROOF_KIT: KIT } });
  assert.equal(r.status, 1, r.stderr + r.stdout);
  // Same bytes as the sources produce, from inside node_modules. The working copy also loads the Pro map checks from the Pro folder, which
  // the tarball does not hold, so report.md (it lists every check, including those that did not apply) differs by exactly those.
  const ref = runCi([join(ROOT, 'src/cli.ts')], repo, join(tmp, 'ref'));
  assert.equal(ref.status, 1);
  for (const f of FILES.filter((x) => x !== 'report.md')) assert.equal(sha(join(art, f)), sha(join(tmp, 'ref', f)), f);
  const ours = readFileSync(join(art, 'report.md'), 'utf8');
  assert.match(ours, /^# Hullproof report/);
  assert.doesNotMatch(ours, /check\.map\.upload-without-limits/);
});
