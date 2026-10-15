// Unchanged kit files copied into a project are left out of the scan, because they hold planted samples. The list comes from the kit given to the run.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { kitOwnedFiles } from '../src/discover/kit-files.ts';
import { discover } from '../src/discover/discover.ts';
import { runScanner } from '../src/scanners/index.ts';
import { adapter as gitleaks } from '../src/scanners/gitleaks.ts';

const sha = (t: string): string => createHash('sha256').update(t).digest('hex');
const put = (root: string, files: Record<string, string>): void => { for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(root, f)), { recursive: true }); writeFileSync(join(root, f), t); } };
const KEY = ['AKIA', 'Z7Q2M5XN3KDW4PBT'].join('');
const SAMPLE = `const k = "${KEY}";\n`;

function setup(): { repo: string; kit: string } {
  const base = mkdtempSync(join(tmpdir(), 'hp-kitfiles-'));
  const kit = join(base, 'kit'); const repo = join(base, 'project');
  put(kit, { 'docs/hullproof/.kit-manifest': `${sha(SAMPLE)}  tools/hullproof/tests/sample.ts\n${sha('other')}  tools/hullproof/tests/changed.ts\n${sha('x')}  ../outside.ts\n` });
  put(repo, { 'tools/hullproof/tests/sample.ts': SAMPLE, 'tools/hullproof/tests/changed.ts': SAMPLE, 'src/app.ts': SAMPLE, 'package.json': '{"name":"p"}' });
  return { repo, kit };
}

test('a file is a kit file only when its bytes match the manifest of the kit that was given', () => {
  const { repo, kit } = setup();
  assert.deepEqual([...kitOwnedFiles(repo, kit)], ['tools/hullproof/tests/sample.ts']);
});

test('no kit, or a kit folder inside the project, or a manifest inside the project skips nothing', () => {
  const { repo, kit } = setup();
  assert.equal(kitOwnedFiles(repo, null).size, 0);
  // the project names its own file in a manifest of its own: not trusted
  put(repo, { 'docs/hullproof/.kit-manifest': `${sha(SAMPLE)}  src/app.ts\n` });
  assert.equal(kitOwnedFiles(repo, repo).size, 0);
  assert.equal(kitOwnedFiles(repo, join(repo, 'docs/..')).size, 0);
  assert.deepEqual([...kitOwnedFiles(repo, kit)], ['tools/hullproof/tests/sample.ts'], 'a manifest in the project does not add files');
});

test('discovery leaves unchanged kit files out and says so', () => {
  const { repo, kit } = setup();
  const skip = kitOwnedFiles(repo, kit);
  const stack = discover(repo, { skipFiles: skip });
  assert.ok(stack.skipped.some((s) => s.reason === 'unchanged kit files' && s.path === 'tools/hullproof/tests/'));
  const all = discover(repo);
  assert.ok(!all.skipped.some((s) => s.reason === 'unchanged kit files'));
});

test('Gitleaks hits in unchanged kit files are dropped, the same key in the project code and in a changed kit file is not', { skip: spawnSync('gitleaks', ['version']).status !== 0 }, () => {
  const { repo, kit } = setup();
  spawnSync('git', ['init', '-q'], { cwd: repo });
  const out = mkdtempSync(join(tmpdir(), 'hp-kitfiles-out-')); mkdirSync(join(out, 'scan'));
  const base = { repo, out, stack: {} as never, allowNetwork: false, edition: 'free' as const };
  const files = (skip?: ReadonlySet<string>): string[] => runScanner(gitleaks, { ...base, skipFiles: skip }).detail.hits.map((h) => h.file).sort();
  assert.deepEqual(files(), ['src/app.ts', 'tools/hullproof/tests/changed.ts', 'tools/hullproof/tests/sample.ts']);
  assert.deepEqual(files(kitOwnedFiles(repo, kit)), ['src/app.ts', 'tools/hullproof/tests/changed.ts']);
});
