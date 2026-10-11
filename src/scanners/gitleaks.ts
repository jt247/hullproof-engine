// Gitleaks adapter. `gitleaks dir` over the working tree always; `gitleaks git` over history only when the caller says
// the git configuration was checked (opts.history), because it runs git. Both use the kit config in rules/gitleaks.toml,
// --redact, --ignore-gitleaks-allow and an empty ignore folder, so the scanned repository cannot hide its own findings.
// Kept per hit: rule id, file, line, the redacted match (masked again) and the Gitleaks fingerprint. Never the secret,
// the entropy, the author or the date.
import { join } from 'node:path';
import { sortUnique } from '../util.ts';
import { fileSha256, mask, relPath } from './common.ts';
import { inEdition, loadControls } from '../mapping/controls.ts';
import { mapHit, tableSecIds } from '../mapping/map.ts';
import type { Adapter, DetailHit, Env, Exec, ScanOptions } from './types.ts';

interface Finding { RuleID: string; StartLine: number; EndLine: number; Match: string; File: string; Commit: string; Fingerprint: string }

const flags = (config: string, ignoreDir: string): string[] => ['--redact', '--no-banner', '--no-color', '--config', config,
  '--ignore-gitleaks-allow', '--gitleaks-ignore-path', ignoreDir, '--report-format', 'json', '--report-path', '-', '--exit-code', '0'];

export const adapter: Adapter = {
  id: 'gitleaks',
  tool: 'gitleaks',
  versionCommand: ['gitleaks', 'version'],
  testedVersions: '8.30.x',
  needsNetwork: false,
  applies: () => true,
  notApplicableReason: () => null,
  configFiles: (ctx) => [join((ctx as ScanOptions).rulesDir ?? '', 'gitleaks.toml')],
  command: (ctx) => ['gitleaks', 'dir', '.', ...flags(join((ctx as ScanOptions).rulesDir ?? '', 'gitleaks.toml'), '<empty-dir>')],
  parse: (stdout, ctx) => parseGitleaks(stdout, ctx as ScanOptions, 'dir', null, '').hits,
  possibleSecIds: (o) => sortUnique(inEdition(tableSecIds('gitleaks'), o.edition, loadControls(o.controlsPath))),

  execute(o, env) {
    const config = join(env.rulesDir, 'gitleaks.toml');
    const configSha256 = fileSha256(config);
    const ruleVersion = `gitleaks ${env.version}, config sha256:${configSha256.slice(0, 16)}`;
    const show = (argv: string[]): string[] => argv.map((a) => (a === config ? '<engine>/rules/gitleaks.toml' : a === env.scratch ? '<empty-dir>' : a));
    const runOne = (mode: 'dir' | 'git'): Exec => {
      // Trace logging is the only place Gitleaks names each file it read. The log also prints skipped candidate values,
      // so stderr is read here for the file names only, never stored and never printed.
      const argv = ['gitleaks', mode, '.', ...flags(config, env.scratch), ...(mode === 'dir' ? ['--log-level', 'trace'] : [])];
      const r = env.run(argv);
      if (r.status !== 0) throw new Error(`gitleaks ${mode} exited with ${r.status ?? r.error}`);
      return r;
    };
    const dir = runOne('dir');
    const scanned = sortUnique([...dir.stderr.matchAll(/scanning path path=(.+)$/gm)].map((m) => relPath(m[1].trim(), o.repo)));
    const hits = parseGitleaks(dir.stdout, o, 'dir', env.tracked, ruleVersion).hits;
    const commands = [show(dir.argv)];
    if (o.history) {
      const git = runOne('git');
      hits.push(...parseGitleaks(git.stdout, o, 'git', env.tracked, ruleVersion).hits);
      commands.push(show(git.argv));
    }
    return { hits, commands, configSha256, scanned, exitCode: dir.status, toolErrors: [] };
  },
};

export function parseGitleaks(stdout: string, o: ScanOptions, source: 'dir' | 'git', tracked: Set<string> | null, ruleVersion: string): { hits: DetailHit[] } {
  const controls = loadControls(o.controlsPath);
  const list = (stdout.trim() ? JSON.parse(stdout) : []) as Finding[];
  return {
    hits: list.map((f): DetailHit => {
      const file = relPath(f.File, o.repo);
      const isTracked = source === 'git' || !tracked || tracked.has(file);
      const m = mapHit({ tool: 'gitleaks', rule_id: f.RuleID, file, tracked: isTracked }, o.edition, controls);
      const redacted = mask(f.Match);
      return {
        tool: 'gitleaks', rule_id: f.RuleID, file, line: f.StartLine, end_line: f.EndLine, sec_ids: m.sec_ids, severity_hint: null,
        message_key: `gitleaks:${f.RuleID}`, rule_version: ruleVersion, evidence: redacted, mapped_by: m.mapped_by, unmapped: !m.sec_ids.length,
        secret: { redacted, fingerprint: relFingerprint(f.Fingerprint, o.repo), source, commit: f.Commit || null, tracked: isTracked },
      };
    }),
  };
}

// The fingerprint is [commit:]file:rule:line; make its file part repository relative too.
const relFingerprint = (fp: string, repo: string): string => fp.includes(repo) ? fp.split(repo.replace(/\/$/, '') + '/').join('') : fp;
