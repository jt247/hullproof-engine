// Reads a scan folder (<out>/<commit>/) back. The report and the gate read only these files, never the source.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { cmp } from '../util.ts';
import type { CheckResultsFile, FindingsFile, ResultRow, Stack, ToolMeta } from '../types/index.ts';
import type { ScanInfo } from '../commands/scan.ts';
import type { SurfaceFile } from './surface.ts';

export interface ScanFolder {
  dir: string; info: ScanInfo; stack: Stack; checks: CheckResultsFile; results: ResultRow[];
  findingsText: string; findings: FindingsFile; metas: ToolMeta[]; surface: SurfaceFile;
  reasons: Record<string, string | null>; // tool -> plain English reason it did not run, from scan/<tool>.detail.json
}

const json = <T>(p: string): T => JSON.parse(readFileSync(p, 'utf8')) as T;

export function loadScan(dir: string): ScanFolder {
  for (const f of ['scan.json', 'stack.json', 'checks.json', 'results.json', 'report.findings.md', 'surface.json']) {
    if (!existsSync(join(dir, f))) throw new Error(`${join(dir, f)} is missing. Run hullproof scan first.`);
  }
  const findingsText = readFileSync(join(dir, 'report.findings.md'), 'utf8');
  const block = /```hullproof-findings\n([\s\S]*?)\n```/.exec(findingsText);
  if (!block) throw new Error('report.findings.md holds no hullproof-findings block');
  const scanDir = join(dir, 'scan');
  const metas = existsSync(scanDir)
    ? readdirSync(scanDir).filter((n) => n.endsWith('.meta.json')).sort(cmp).map((n) => json<ToolMeta>(join(scanDir, n)))
    : [];
  const reasons: Record<string, string | null> = {};
  for (const m of metas) {
    const p = join(scanDir, `${m.tool}.detail.json`);
    reasons[m.tool] = existsSync(p) ? json<{ not_run_reason: string | null }>(p).not_run_reason : null;
  }
  return {
    reasons, dir, info: json(join(dir, 'scan.json')), stack: json(join(dir, 'stack.json')), checks: json(join(dir, 'checks.json')),
    results: json(join(dir, 'results.json')), findingsText, findings: JSON.parse(block[1]) as FindingsFile, metas,
    surface: json(join(dir, 'surface.json')),
  };
}
