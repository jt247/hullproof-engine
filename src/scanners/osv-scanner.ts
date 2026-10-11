// OSV Scanner adapter. It sends package names and versions to osv.dev, so it runs only with --allow-network; without it
// the tool is NOT RUN with that reason. One hit per advisory group per package, with the advisory id, package, version,
// severity class, fixed versions and the dependency policy decision. The result is reproducible only for the same
// advisory data date, recorded as db_date.
import { cmp, sortUnique } from '../util.ts';
import { relPath } from './common.ts';
import { inEdition, loadControls } from '../mapping/controls.ts';
import { mapHit, tableSecIds } from '../mapping/map.ts';
import { classFromScore, classFromWord, decide, DEFAULT_POLICY, type SeverityClass } from '../mapping/dependency-policy.ts';
import type { Adapter, DetailHit, ScanOptions } from './types.ts';

interface Osv {
  id: string; published?: string; modified?: string;
  database_specific?: { severity?: string };
  affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { events?: { fixed?: string }[] }[] }[];
}
interface OsvJson {
  results?: { source: { path: string }; packages?: { package: { name: string; version?: string; commit?: string; ecosystem: string }; vulnerabilities?: Osv[]; groups?: { ids: string[]; aliases?: string[]; max_severity?: string }[] }[] }[];
}

const RANK: Record<SeverityClass, number> = { UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export const today = (): string => new Date().toISOString().slice(0, 10);

export const adapter: Adapter = {
  id: 'osv-scanner',
  tool: 'osv-scanner',
  versionCommand: ['osv-scanner', '--version'],
  testedVersions: '2.6.x',
  needsNetwork: true,
  applies: (stack) => stack.package_managers.length > 0,
  notApplicableReason: (o) => (adapter.applies(o.stack) ? null : 'No package manifest or lockfile was found, so there are no dependencies to check.'),
  configFiles: () => [],
  command: () => ['osv-scanner', 'scan', 'source', '--format', 'json', '--recursive', '.'],
  parse: (stdout, ctx) => parseOsv(stdout, ctx as ScanOptions, (ctx as ScanOptions).asOf ?? today()).hits,
  possibleSecIds: (o) => sortUnique(inEdition(tableSecIds('osv-scanner'), o.edition, loadControls(o.controlsPath))),

  execute(o, env) {
    const asOf = o.asOf ?? today();
    const argv = adapter.command(o);
    const r = env.run(argv);
    // 0: no advisories, 1: advisories found, 128: no packages found. Anything else is a failure.
    if (r.status !== 0 && r.status !== 1 && r.status !== 128) throw new Error(`osv-scanner exited with ${r.status ?? r.error}`);
    const out = r.status === 128 ? { hits: [], scanned: [] } : parseOsv(r.stdout, o, asOf);
    return { hits: out.hits, commands: [argv], configSha256: null, scanned: out.scanned, exitCode: r.status, toolErrors: [], dbDate: asOf, asOf, policy: o.policy ?? DEFAULT_POLICY };
  },
};

export function parseOsv(stdout: string, o: ScanOptions, asOf: string): { hits: DetailHit[]; scanned: string[] } {
  const controls = loadControls(o.controlsPath);
  const policy = o.policy ?? DEFAULT_POLICY;
  const j = JSON.parse(stdout) as OsvJson;
  const hits: DetailHit[] = [];
  const scanned = new Set<string>();
  for (const res of j.results ?? []) {
    const file = relPath(res.source.path, o.repo);
    scanned.add(file);
    for (const p of res.packages ?? []) {
      for (const g of p.groups ?? []) {
        const ids = [...g.ids].sort(cmp);
        const id = ids.find((x) => x.startsWith('GHSA-')) ?? ids[0];
        const vulns = (p.vulnerabilities ?? []).filter((v) => ids.includes(v.id));
        const score = Number.parseFloat(g.max_severity ?? '');
        const cls: SeverityClass = score > 0 ? classFromScore(score)
          : vulns.map((v) => classFromWord(v.database_specific?.severity)).reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'UNKNOWN');
        const dates = vulns.map((v) => v.published?.slice(0, 10)).filter((d): d is string => !!d).sort(cmp);
        const published = dates[0] ?? null;
        const fixed = sortUnique(vulns.flatMap((v) => (v.affected ?? [])
          .filter((a) => a.package?.name === p.package.name)
          .flatMap((a) => (a.ranges ?? []).flatMap((rg) => (rg.events ?? []).map((e) => e.fixed).filter((x): x is string => !!x)))));
        const d = decide(cls, published, asOf, policy);
        const version = p.package.version || p.package.commit || '';
        const mapped = mapHit({ tool: 'osv-scanner', rule_id: id, file }, o.edition, controls);
        const fails = d.decision === 'fail';
        const modified = vulns.map((v) => v.modified ?? '').sort(cmp).pop() || 'unknown';
        hits.push({
          tool: 'osv-scanner', rule_id: id, file, line: 0, end_line: 0, sec_ids: fails ? mapped.sec_ids : [],
          severity_hint: cls, message_key: `osv-scanner:${id}`, rule_version: `advisory modified ${modified}`,
          evidence: `${p.package.name}@${version} (${p.package.ecosystem})`,
          mapped_by: fails ? mapped.mapped_by : 'policy report only', unmapped: fails && !mapped.sec_ids.length,
          advisory: {
            id, aliases: sortUnique([...(g.aliases ?? []), ...ids].filter((x) => x !== id)), package: p.package.name,
            ecosystem: p.package.ecosystem, version, severity_class: cls, cvss_score: score > 0 ? score : null,
            fixed_versions: fixed, published, ...d, mapped_sec_ids: mapped.sec_ids,
          },
        });
      }
    }
  }
  return { hits, scanned: [...scanned].sort(cmp) };
}
