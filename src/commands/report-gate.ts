// hullproof report and hullproof gate. Both read the scan folder of the current commit (or --commit) and the kit.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { readHeadCommit } from '../discover/git.ts';
import { evaluateGate, gateLines, loadKitGate, type GateOutcome, type OwnerFile } from '../gate/gate.ts';
import { loadKit, resolveKitDir, type Kit } from '../report/kit.ts';
import { loadScan, type ScanFolder } from '../report/load.ts';
import { renderReport } from '../report/report.ts';
import { mergeHunt, type Merged } from '../confirm/merge.ts';
import { KIT_LOCAL, outDirFor } from './scan.ts';

// The kit folder for report and gate: --kit, then HULLPROOF_KIT, then the kit the scan recorded in kit.local.json when
// that folder still holds a controls file, then the usual search (the repository, then the development kit).
export function kitForRead(repo: string, scanDir: string, flag: string | null): string | null {
  if (flag || process.env.HULLPROOF_KIT) return resolveKitDir(repo, flag);
  const p = join(scanDir, KIT_LOCAL);
  if (existsSync(p)) {
    try {
      const rec = JSON.parse(readFileSync(p, 'utf8')) as { kit_dir?: string };
      if (rec.kit_dir && existsSync(join(rec.kit_dir, 'docs/hullproof/security-controls.json'))) return rec.kit_dir;
    } catch { /* an unreadable record falls through to the usual search */ }
  }
  return resolveKitDir(repo, null);
}

export interface ReadOptions { repo: string; out: string | null; kit: string | null; commit: string | null; owner: string | null; date: string | null; log?: (s: string) => void }

const today = (): string => new Date().toISOString().slice(0, 10);

export type Prepared = { s: ScanFolder; kit: Kit; gate: GateOutcome; repo: string; merged: Merged | null };
export async function prepare(o: ReadOptions): Promise<Prepared | string> {
  const repo = resolve(o.repo);
  const commit = o.commit ?? readHeadCommit(repo);
  if (!commit) return `no commit found in ${repo}; pass --commit`;
  const dir = outDirFor(repo, o.out, commit);
  let s: ScanFolder;
  try { s = loadScan(dir); } catch (e) { return (e as Error).message; }
  const kitDir = kitForRead(repo, dir, o.kit);
  if (!kitDir) return 'no kit found. Pass --kit or set HULLPROOF_KIT.';
  const kit = loadKit(kitDir);
  if (kit.controlsSha256 !== s.info.kit.controls_sha256) return 'the kit controls file differs from the one the scan used. Run hullproof scan again.';
  let owner: OwnerFile | null = null;
  if (o.owner) {
    try { owner = JSON.parse(readFileSync(resolve(o.owner), 'utf8')) as OwnerFile; } catch (e) { return `cannot read the owner file: ${(e as Error).message}`; }
  }
  if (o.date && !/^\d{4}-\d{2}-\d{2}$/.test(o.date)) return '--date needs YYYY-MM-DD';
  // Confirmed hunt findings and findings proven by a test, and only those, join the rows and the findings record. Leads, unproven specs
  // and runs that were not provable here are never read here.
  const merged = s.hunt.result || s.prove?.result ? mergeHunt(s, kit, s.hunt.result, s.prove?.result ?? null) : null;
  if (merged) s = { ...s, results: merged.results, findings: merged.findings, findingsText: merged.findingsText };
  const gate = evaluateGate({
    kitGate: await loadKitGate(kitDir), controls: kit.controls, scope: { edition: s.info.edition, stage: s.info.stage, stageSource: s.info.stage_source },
    rows: s.results, findingsText: s.findingsText, metas: s.metas, owner, repo, commit, today: o.date ?? today(),
  });
  return { s, kit, gate, repo, merged };
}

export async function report(o: ReadOptions): Promise<number> {
  const log = o.log ?? ((x: string) => process.stderr.write(x + '\n'));
  const r = await prepare(o);
  if (typeof r === 'string') { log(`hullproof report: ${r}`); return 2; }
  const path = join(r.s.dir, 'report.md');
  writeFileSync(path, renderReport(r.s, r.kit, r.gate, r.merged));
  log(`hullproof report: wrote ${path}`);
  return 0;
}

export async function gate(o: ReadOptions): Promise<number> {
  const log = o.log ?? ((x: string) => process.stderr.write(x + '\n'));
  const r = await prepare(o);
  if (typeof r === 'string') { log(`hullproof gate: ${r}`); return 2; }
  for (const l of r.gate.problems) log(`hullproof gate: ${l}`);
  process.stdout.write(gateLines(r.gate).join('\n') + '\n');
  return r.gate.exit;
}
