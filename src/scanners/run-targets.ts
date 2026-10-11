// Development tool. Runs every adapter twice on each target folder, writing into two
// temporary output folders (never into the target), and prints per tool: status, version, hits, mapped and unmapped
// hits, files scanned and tracked, run time of each run, and whether both runs gave the same bytes.
// Usage: node src/scanners/run-targets.ts [--allow-network] [--history] DIR...
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { discover } from '../discover/discover.ts';
import { sha256 } from './common.ts';
import { runScanners } from './index.ts';

const args = process.argv.slice(2);
const allowNetwork = args.includes('--allow-network');
const history = args.includes('--history');
const rows: Record<string, unknown>[] = [];

for (const target of args.filter((a) => !a.startsWith('--')).map((a) => resolve(a))) {
  const stack = discover(target);
  const outs = [0, 1].map(() => mkdtempSync(join(tmpdir(), 'hullproof-runs-')));
  const runs = outs.map((out) => runScanners({ repo: target, out, stack, allowNetwork, edition: 'pro', history }));
  for (const [i, s] of runs[0].entries()) {
    const files = ['json', 'meta.json', 'detail.json'].map((ext) => `scan/${s.meta.tool}.${ext}`);
    const same = files.every((f) => sha256(readFileSync(join(outs[0], f))) === sha256(readFileSync(join(outs[1], f))));
    const hits = s.detail.hits;
    rows.push({
      target: basename(target), tool: s.meta.tool, status: s.meta.status, version: s.meta.version, reason: s.detail.not_run_reason,
      hits: s.hits.hits.length, detail_hits: hits.length, mapped: hits.filter((h) => h.sec_ids.length).length,
      unmapped: hits.filter((h) => h.unmapped).length, report_only: hits.filter((h) => h.mapped_by === 'policy report only').length,
      files: s.detail.files, tool_errors: s.detail.tool_errors.length, seconds: [runs[0][i].seconds, runs[1][i].seconds],
      identical: same, sha256: sha256(readFileSync(join(outs[0], files[0]))).slice(0, 12),
    });
  }
  for (const o of outs) rmSync(o, { recursive: true, force: true });
}
console.log(JSON.stringify(rows, null, 2));
