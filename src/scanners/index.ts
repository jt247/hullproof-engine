// Runs the scanner adapters and writes, per tool, scan/<tool>.json (HitsFile), scan/<tool>.meta.json (ToolMeta) and
// scan/<tool>.detail.json (DetailFile). Nothing is installed. A missing tool, a tool that needs the network when the
// network is not allowed, a tool with nothing to read, and a tool that fails are each recorded with the reason.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Hit, HitsFile, ScannerId, ToolMeta } from '../types/index.ts';
import { cmp, stableJson } from '../util.ts';
import { readHeadCommit } from '../discover/git.ts';
import { loadControls, notInControls } from '../mapping/controls.ts';
import { detectVersion, exec, readTracked, RULES_DIR, toolEnv, versionTested } from './common.ts';
import { adapter as semgrep } from './semgrep.ts';
import { adapter as gitleaks } from './gitleaks.ts';
import { adapter as osv } from './osv-scanner.ts';
import { adapter as trivy } from './trivy.ts';
import type { Adapter, AdapterResult, DetailFile, DetailHit, Env, ScanOptions } from './types.ts';

export const ADAPTERS: Adapter[] = [semgrep, gitleaks, osv, trivy];

export interface ScanOutput { hits: HitsFile; meta: ToolMeta; detail: DetailFile; seconds: number }

const hitKey = (h: Hit): string[] => [h.file, String(h.line).padStart(9, '0'), h.tool, h.rule_id];
const byKey = (a: string[], b: string[]): number => { for (let i = 0; i < a.length; i++) { const c = cmp(a[i], b[i]); if (c) return c; } return 0; };

export function toContractHits(details: DetailHit[]): Hit[] {
  const seen = new Map<string, Hit>();
  for (const d of details) {
    const h: Hit = { tool: d.tool, rule_id: d.rule_id, file: d.file, line: d.line, sec_ids: d.sec_ids, severity_hint: d.severity_hint, message_key: d.message_key };
    const k = stableJson(h);
    if (!seen.has(k)) seen.set(k, h);
  }
  return [...seen.values()].sort((a, b) => byKey(hitKey(a), hitKey(b)) || cmp(stableJson(a), stableJson(b)));
}

const sortDetails = (xs: DetailHit[]): DetailHit[] =>
  xs.map((d) => [d, stableJson(d)] as const).sort((a, b) => byKey(hitKey(a[0]), hitKey(b[0])) || cmp(a[1], b[1])).map((x) => x[0]);

export function runScanner(a: Adapter, opts: ScanOptions): ScanOutput {
  const started = Date.now();
  const o: ScanOptions = { ...opts, rulesDir: opts.rulesDir ?? RULES_DIR };
  const env0 = toolEnv(o.env ?? process.env, o.allowNetwork);
  const controls = loadControls(o.controlsPath);
  const tracked = readTracked(o.repo);
  const version = detectVersion(a.versionCommand, env0);
  let status: ToolMeta['status'] = 'ran';
  let reason: string | null = null;
  let res: AdapterResult | null = null;

  if (!version) { status = 'skipped: not installed'; reason = `${a.tool} is not installed on this machine (not found on PATH). The engine does not install tools.`; }
  else if (a.needsNetwork && !o.allowNetwork) { status = 'skipped: network not allowed'; reason = `${a.tool} sends package names and versions to osv.dev and needs its advisory data. Run with --allow-network to include it.`; }
  else if (!a.applies(o.stack)) { status = 'skipped: not applicable'; reason = a.notApplicableReason(o); }
  else {
    const scratch = mkdtempSync(join(tmpdir(), 'hullproof-scan-'));
    const env: Env = {
      version, tracked, rulesDir: o.rulesDir!, scratch,
      run: (argv) => exec(argv, o.repo, env0),
    };
    try { res = a.execute(o, env); }
    catch (e) { status = 'failed'; reason = `${a.tool} did not finish: ${(e as Error).message}`; }
    finally { rmSync(scratch, { recursive: true, force: true }); }
  }

  const details = sortDetails(res?.hits ?? []);
  const scanned = res?.scanned ?? null;
  const scannedSet = new Set(scanned ?? []);
  const files: DetailFile['files'] = {
    scanned: scanned ? scanned.length : null,
    tracked: tracked ? tracked.size : null,
    scanned_not_tracked: scanned && tracked ? scanned.filter((f) => !tracked.has(f)).length : null,
    tracked_not_scanned: scanned && tracked ? [...tracked].filter((f) => !scannedSet.has(f)).length : null,
  };
  const ran = status === 'ran';
  const meta: ToolMeta = {
    schema_version: '1.0.0', tool: a.id, status, version, tested_version_range: a.testedVersions,
    version_tested: versionTested(version, a.testedVersions), argv: res?.commands[0] ?? [], config_sha256: res?.configSha256 ?? null,
    commit: readHeadCommit(o.repo), files_scanned: files.scanned, files_tracked: files.tracked, exit_code: res?.exitCode ?? null,
    db_date: res?.dbDate ?? null, not_assessed_sec_ids: ran ? [] : a.possibleSecIds(o),
  };
  const detail: DetailFile = {
    schema_version: '0.1.0', tool: a.id, status, not_run_reason: reason, tool_version: version, commands: res?.commands ?? [],
    files, as_of: res?.asOf ?? null, policy: res?.policy ?? null,
    sec_ids_not_in_controls: [...new Set(notInControls(details.flatMap((d) => [...d.sec_ids, ...(d.advisory?.mapped_sec_ids ?? [])]), controls))].sort(cmp),
    tool_errors: (res?.toolErrors ?? []).sort((x, y) => cmp(stableJson(x), stableJson(y))),
    hits: details,
  };
  return { hits: { schema_version: '1.0.0', tool: a.id, hits: toContractHits(details) }, meta, detail, seconds: (Date.now() - started) / 1000 };
}

export function writeScan(outDir: string, s: ScanOutput): void {
  const dir = join(outDir, 'scan');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${s.meta.tool}.json`), stableJson(s.hits));
  writeFileSync(join(dir, `${s.meta.tool}.meta.json`), stableJson(s.meta));
  writeFileSync(join(dir, `${s.meta.tool}.detail.json`), stableJson(s.detail));
}

// Runs every adapter (or the ones named) and writes their files. Run times go to scan/run.json, outside the contract.
export function runScanners(opts: ScanOptions, tools?: ScannerId[]): ScanOutput[] {
  const out = ADAPTERS.filter((a) => !tools || tools.includes(a.id)).map((a) => runScanner(a, opts));
  for (const s of out) writeScan(opts.out, s);
  writeFileSync(join(opts.out, 'scan', 'run.json'), JSON.stringify({ seconds: Object.fromEntries(out.map((s) => [s.meta.tool, s.seconds])) }, null, 2) + '\n');
  return out;
}
