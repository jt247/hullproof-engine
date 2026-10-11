// Trivy adapter: `trivy config` only, so misconfiguration checks on IaC, Kubernetes, Helm and Dockerfiles. No image is
// pulled. The checks are the ones built into the Trivy binary (--skip-check-update, an empty cache folder), so the rule
// set is fixed by the Trivy version, and network is blocked unless allowed (Terraform remote modules then do not load).
import { join } from 'node:path';
import { cmp, sortUnique } from '../util.ts';
import { isRegularFile, relPath, sourceLine } from './common.ts';
import { inEdition, loadControls } from '../mapping/controls.ts';
import { mapHit, tableSecIds } from '../mapping/map.ts';
import type { Adapter, DetailHit, ScanOptions } from './types.ts';

// Pinned so a Trivy update cannot add a scanner silently. The list is Trivy 0.75.0's default.
const MISCONFIG_SCANNERS = 'azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot,ansible';

interface Misconf { ID: string; Severity: string; Status: string; CauseMetadata?: { StartLine?: number; EndLine?: number } }
interface TrivyJson { Results?: { Target: string; Class: string; Misconfigurations?: Misconf[] }[] }

export const adapter: Adapter = {
  id: 'trivy',
  tool: 'trivy',
  versionCommand: ['trivy', '--version'],
  testedVersions: '0.75.x',
  needsNetwork: false,
  applies: (stack) => stack.iac.length > 0 || stack.containers.length > 0,
  notApplicableReason: (o) => (adapter.applies(o.stack) ? null : 'No infrastructure as code, Kubernetes, Helm or container file was found, so Trivy has nothing to check.'),
  configFiles: () => [],
  command: () => ['trivy', 'config', '--format', 'json', '--quiet', '--skip-check-update', '--skip-version-check',
    '--disable-telemetry', '--include-non-failures', '--misconfig-scanners', MISCONFIG_SCANNERS, '--cache-dir', '<empty-dir>', '.'],
  parse: (stdout, ctx) => parseTrivy(stdout, ctx as ScanOptions, 'unknown').hits,
  possibleSecIds: (o) => sortUnique(inEdition(tableSecIds('trivy'), o.edition, loadControls(o.controlsPath))),

  execute(o, env) {
    const argv = adapter.command(o).map((a) => (a === '<empty-dir>' ? env.scratch : a));
    const shown = adapter.command(o);
    const r = env.run(argv);
    if (r.status !== 0) throw new Error(`trivy exited with ${r.status ?? r.error}`);
    const out = parseTrivy(r.stdout, o, `trivy ${env.version} built in checks`, env.tracked);
    return { hits: out.hits, commands: [shown], configSha256: null, scanned: out.scanned, exitCode: r.status, toolErrors: [] };
  },
};

// Terraform results come per module folder as well as per file; a folder target stands for the tracked .tf files in it.
export function parseTrivy(stdout: string, o: ScanOptions, ruleVersion: string, tracked: Set<string> | null = null): { hits: DetailHit[]; scanned: string[] } {
  const controls = loadControls(o.controlsPath);
  const j = JSON.parse(stdout) as TrivyJson;
  const hits: DetailHit[] = [];
  const scanned = new Set<string>();
  for (const res of j.Results ?? []) {
    if (res.Class !== 'config') continue;
    const target = relPath(res.Target, o.repo);
    if (tracked && !isRegularFile(join(o.repo, target))) {
      const prefix = target === '.' ? '' : target + '/';
      for (const f of tracked) if (f.startsWith(prefix) && !f.slice(prefix.length).includes('/') && /\.tf(\.json)?$/.test(f)) scanned.add(f);
    } else scanned.add(target);
    for (const m of res.Misconfigurations ?? []) {
      if (m.Status !== 'FAIL') continue;
      const line = m.CauseMetadata?.StartLine ?? 0;
      const mapped = mapHit({ tool: 'trivy', rule_id: m.ID, file: target }, o.edition, controls);
      hits.push({
        tool: 'trivy', rule_id: m.ID, file: target, line, end_line: m.CauseMetadata?.EndLine ?? line, sec_ids: mapped.sec_ids,
        severity_hint: m.Severity ?? null, message_key: `trivy:${m.ID}`, rule_version: ruleVersion,
        evidence: sourceLine(o.repo, target, line), mapped_by: mapped.mapped_by, unmapped: !mapped.sec_ids.length,
      });
    }
  }
  return { hits, scanned: [...scanned].sort(cmp) };
}
