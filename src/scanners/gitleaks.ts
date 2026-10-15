// Gitleaks adapter. `gitleaks dir` over the working tree always; `gitleaks git` over history only when the caller says
// the git configuration was checked (opts.history), because it runs git. Both use the kit config in rules/gitleaks.toml,
// --redact, --ignore-gitleaks-allow and an empty ignore folder, so the scanned repository cannot hide its own findings.
// Kept per hit: rule id, file, line, the redacted match (masked again) and the Gitleaks fingerprint. Never the secret,
// the entropy, the author or the date.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { secretNoise } from './secret-noise.ts';
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
    // The engine's own output folder is left out: it is written by this tool, so reading it would change the next run.
    const own = (f: string): boolean => f === '.hullproof' || f.startsWith('.hullproof/');
    const scanned = sortUnique([...dir.stderr.matchAll(/scanning path path=(.+)$/gm)].map((m) => relPath(m[1].trim(), o.repo))).filter((f) => !own(f));
    const hits = parseGitleaks(dir.stdout, o, 'dir', env.tracked, ruleVersion).hits.filter((h) => !own(h.file));
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
  // The source line is the only place a placeholder can be told from a key, because the scanner redacts the value. History hits
  // cannot be matched to the checked out files, so they get the path rules only.
  const lines = new Map<string, string[] | null>();
  const lineOf = (file: string, n: number): string | null => {
    if (source === 'git') return null;
    if (!lines.has(file)) { try { lines.set(file, readFileSync(join(o.repo, file), 'utf8').split('\n')); } catch { lines.set(file, null); } }
    return lines.get(file)?.[n - 1] ?? null;
  };
  return {
    hits: list.map((f): DetailHit => {
      const file = relPath(f.File, o.repo);
      const isTracked = source === 'git' || !tracked || tracked.has(file);
      const m = mapHit({ tool: 'gitleaks', rule_id: f.RuleID, file, tracked: isTracked }, o.edition, controls);
      const redacted = mask(f.Match);
      const noise = secretNoise(f.RuleID, file, lineOf(file, f.StartLine));
      return {
        tool: 'gitleaks', rule_id: f.RuleID, file, line: f.StartLine, end_line: f.EndLine, sec_ids: m.sec_ids, severity_hint: null,
        ...(noise ? { noise } : {}), message_key: `gitleaks:${f.RuleID}`, rule_version: ruleVersion, evidence: redacted, mapped_by: m.mapped_by, unmapped: !m.sec_ids.length,
        secret: { redacted, fingerprint: relFingerprint(f.Fingerprint, o.repo), source, commit: f.Commit || null, tracked: isTracked },
      };
    }),
  };
}

// The fingerprint is [commit:]file:rule:line; make its file part repository relative too.
const relFingerprint = (fp: string, repo: string): string => fp.includes(repo) ? fp.split(repo.replace(/\/$/, '') + '/').join('') : fp;
