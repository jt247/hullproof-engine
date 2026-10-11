// Measures the second wave extractors (Go, Rails, Laravel, Expo) on the synthetic fixtures in test/fixtures/map-more and, when the
// folder exists, checks that they invent no entry points in the stray Go, Ruby and PHP files of the local CVE subset.
//   node bench/second-wave.ts [--cve-subset DIR]
// Prints one markdown table. The fixtures were written together with the extractors, so the numbers are an upper estimate.
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeContext } from '../src/checks/context.ts';
import { loadChecks, runChecks } from '../src/checks/run.ts';
import { getMap } from '../src/checks/map/shared.ts';
import { discover } from '../src/discover/discover.ts';
import { stableJson } from '../src/util.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MORE = join(ROOT, 'test/fixtures/map-more');
const mapOf = (dir: string) => getMap(makeContext(dir, discover(dir)));

// Entry points counted by hand from the fixture sources before the extractors were run on them.
const HAND: Record<string, number> = { go: 9, gin: 3, rails: 9, laravel: 9, expo: 9 };
// Planted flaws, per stack, by the map check written for each. Only the checks loaded in this tree are counted: the four Pro
// checks (auth-endpoint-without-rate-limit, input-without-schema, page-size-from-request, upload-without-limits) are not in the open edition.
const ALL13 = ['admin-route-without-role', 'auth-endpoint-without-rate-limit', 'data-read-without-auth', 'input-without-schema', 'mutating-route-without-auth', 'page-size-from-request', 'privileged-action-without-audit', 'privileged-field-from-request', 'redirect-from-request', 'request-url-fetched', 'upload-without-limits', 'webhook-verify-before-use', 'write-by-id-without-owner'];
const PLANTED: Record<string, string[]> = {
  go: ALL13, rails: ALL13, laravel: ALL13,
  gin: ['input-without-schema', 'mutating-route-without-auth', 'privileged-field-from-request', 'write-by-id-without-owner'],
  expo: ['input-without-schema', 'mutating-route-without-auth'],
};

const rows: string[] = ['| Stack | Hand counted entry points | Found, fail copy | Found, pass copy | Planted flaws flagged | Flags in the pass copy |', '|---|---|---|---|---|---|'];
const checks = loadChecks().filter((c) => c.id.startsWith('check.map.') && !/supabase|firebase/.test(c.id));
const run = (side: string) => { const dir = join(MORE, side); return runChecks(makeContext(dir, discover(dir), [], null), checks); };
const fail = run('fail');
const pass = run('pass');
const loaded = new Set(checks.map((c) => c.id.slice('check.map.'.length)));
const flagged = (stack: string): number => fail.results.filter((r) => r.result === 'FAIL' && PLANTED[stack].includes(r.check_id.slice('check.map.'.length)) && r.evidence.some((e) => e.file.split('/')[0] === stack)).length;
const passFlags = (stack: string): number => pass.results.filter((r) => r.result === 'FAIL' && r.evidence.some((e) => e.file.split('/')[0] === stack)).length;
const count = (m: ReturnType<typeof mapOf>, stack: string): number => m.entry_points.filter((e) => e.file.startsWith(stack + '/')).length;
const mf = mapOf(join(MORE, 'fail'));
const mp = mapOf(join(MORE, 'pass'));
for (const stack of Object.keys(HAND)) rows.push(`| ${stack} | ${HAND[stack]} | ${count(mf, stack)} | ${count(mp, stack)} | ${flagged(stack)} of ${PLANTED[stack].filter((n) => loaded.has(n)).length} | ${passFlags(stack)} |`);
process.stdout.write(rows.join('\n') + '\n\n');

const hashes = [0, 1, 2].map(() => ['fail', 'pass'].map((s) => createHash('sha256').update(stableJson(mapOf(join(MORE, s)))).digest('hex').slice(0, 12)).join(' '));
process.stdout.write(`Three runs, codemap.json sha256 prefixes (fail pass): ${hashes.join(' | ')}; identical: ${new Set(hashes).size === 1}\n`);

// Negative control: the Go, Ruby and PHP files that happen to sit in third party JavaScript projects (test pages, a doc plugin, a push
// client). They are not web applications, so the map should list nothing in them. Only these files are copied to a scratch folder.
const i = process.argv.indexOf('--cve-subset');
const subset = i >= 0 ? process.argv[i + 1] : join(ROOT, '..', 'bench-targets', 'cve-subset');
if (existsSync(subset)) {
  const scratch = mkdtempSync(join(tmpdir(), 'hp-second-wave-'));
  let files = 0;
  const walk = (dir: string, rel: string): void => {
    for (const n of readdirSync(dir).sort()) {
      if (n === 'node_modules' || n === '.git') continue;
      const p = join(dir, n);
      if (statSync(p).isDirectory()) { walk(p, join(rel, n)); continue; }
      if (!/\.(?:go|rb|php)$/.test(n)) continue;
      mkdirSync(dirname(join(scratch, rel, n)), { recursive: true });
      copyFileSync(p, join(scratch, rel, n));
      files++;
    }
  };
  walk(subset, '');
  const m = mapOf(scratch);
  process.stdout.write(`CVE subset negative control: ${files} Go, Ruby and PHP files copied from ${readdirSync(subset).length} repositories, ${m.entry_points.length} entry points found in them\n`);
}
