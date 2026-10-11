// Semgrep adapter. Runs the Hullproof rules in rules/semgrep/, plus an optional external rule pack folder (for example a rule pack of your own),
// on the files git tracks, named one by one, with --no-git-ignore so Semgrep itself never calls git and the repository's
// own ignore files cannot hide a tracked file.
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { cmp, sortUnique } from '../util.ts';
import { dirSha256, fileSha256, isRegularFile, relPath, sha256, sourceLine } from './common.ts';
import { inEdition, loadControls } from '../mapping/controls.ts';
import { mapHit } from '../mapping/map.ts';
import type { Adapter, DetailHit, ScanOptions, ToolError } from './types.ts';

export interface RuleInfo { id: string; file: string; sec_ids: string[]; version: string }

const yamlIn = (dir: string): string[] => readdirSync(dir).filter((n) => /\.ya?ml$/.test(n)).sort(cmp);

// The rule files Semgrep runs, by file name: the engine's folder, then the pack. A pack file with the same name as an
// engine file replaces it, so a pack may be a whole kit rules folder (identical files change nothing) or only the
// files it adds. Throws when the pack folder is missing or holds no rule file.
export function ruleFiles(dir: string, pack: string | null = null): string[] {
  const byName = new Map<string, string>(yamlIn(dir).map((n) => [n, join(dir, n)]));
  if (pack) {
    if (!existsSync(pack)) throw new Error(`the rule pack folder ${basename(pack)} does not exist`);
    const names = yamlIn(pack);
    if (!names.length) throw new Error(`the rule pack folder ${basename(pack)} holds no .yaml rule file`);
    for (const n of names) byName.set(n, join(pack, n));
  }
  return [...byName.keys()].sort(cmp).map((n) => byName.get(n)!);
}

// Reads rule ids and metadata.sec_ids from the rule files. The kit writes `- id: x` and `sec_ids: [A, B]` on one line
// each; test/scanners.test.ts checks every rule has both.
export function readRules(dir: string, pack: string | null = null): RuleInfo[] {
  const out: RuleInfo[] = [];
  for (const path of ruleFiles(dir, pack)) {
    const f = basename(path);
    const version = 'sha256:' + fileSha256(path).slice(0, 16);
    let cur: RuleInfo | null = null;
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      const id = /^\s*-\s+id:\s*([\w.-]+)\s*$/.exec(line)?.[1];
      if (id) { cur = { id, file: f, sec_ids: [], version }; out.push(cur); continue; }
      const ids = /^\s*sec_ids:\s*\[(.*)\]\s*$/.exec(line)?.[1];
      if (ids !== undefined && cur) cur.sec_ids = sortUnique(ids.split(',').map((s) => s.trim()).filter(Boolean));
    }
  }
  return out;
}

const TIMEOUT_SECONDS = '30';
// Minified or generated files (a line longer than this) make Semgrep time out at random, which breaks byte identical
// output. They are left out by this fixed rule and listed as tool errors of type "skipped: minified".
const MAX_LINE = 1000;
const minified = (p: string): boolean => {
  try { return readFileSync(p, 'utf8').split('\n').some((l) => l.length > MAX_LINE); } catch { return false; }
};
const MAX_TARGET_BYTES = '1000000';

interface SemgrepJson {
  version: string;
  results: { check_id: string; path: string; start: { line: number }; end: { line: number }; extra: { severity?: string; metadata?: { sec_ids?: string[] } } }[];
  errors: { type?: unknown; path?: string; rule_id?: string }[];
  paths: { scanned: string[] };
}

export const adapter: Adapter = {
  id: 'semgrep',
  tool: 'semgrep',
  versionCommand: ['semgrep', '--version'],
  testedVersions: '1.176.x',
  needsNetwork: false,
  applies: (stack) => stack.languages.length > 0 || stack.ci.length > 0,
  notApplicableReason: (o) => (adapter.applies(o.stack) ? null : 'No source language or CI workflow was found, so there is nothing for the Semgrep rules to read.'),
  configFiles: (ctx) => [join((ctx as ScanOptions).rulesDir ?? '', 'semgrep')],
  command: (ctx) => ['semgrep', 'scan', '--config', join((ctx as ScanOptions).rulesDir ?? '', 'semgrep'), '--json', '--quiet',
    '--metrics=off', '--disable-version-check', '--no-git-ignore', '--timeout', TIMEOUT_SECONDS, '--timeout-threshold', '3',
    '--max-target-bytes', MAX_TARGET_BYTES],
  parse: (stdout, ctx) => parseSemgrep(stdout, ctx as ScanOptions, readRules(join((ctx as ScanOptions).rulesDir ?? '', 'semgrep'), (ctx as ScanOptions).rulePack ?? null)).hits,
  possibleSecIds: (o) => sortUnique(inEdition(readRules(join(o.rulesDir!, 'semgrep'), o.rulePack ?? null).flatMap((r) => r.sec_ids), o.edition, loadControls(o.controlsPath))),

  execute(o, env) {
    const engineRules = join(env.rulesDir, 'semgrep');
    const pack = o.rulePack ?? null;
    // With a pack, the merged rule files go into one folder in the scratch space, so Semgrep reads one --config folder
    // and the config sha256 covers exactly the rules that ran.
    let rulesDir = engineRules;
    if (pack) {
      const rules = readRules(engineRules, pack);
      const twice = rules.map((r) => r.id).filter((id, i, a) => a.indexOf(id) !== i);
      if (twice.length) throw new Error(`rule id ${twice[0]} is in two rule files once the pack is added`);
      rulesDir = join(env.scratch, 'rules');
      mkdirSync(rulesDir);
      for (const f of ruleFiles(engineRules, pack)) copyFileSync(f, join(rulesDir, basename(f)));
    }
    // ponytail: every tracked file goes on the command line; split into batches if a repository ever passes ARG_MAX.
    const files = env.tracked ? [...env.tracked].filter((f) => isRegularFile(join(o.repo, f))).sort(cmp) : [];
    const skipped = files.filter((f) => /\.(js|mjs|cjs|ts|jsx|tsx|json|ya?ml|html|py)$/.test(f) && minified(join(o.repo, f)));
    const targets = env.tracked ? files.filter((f) => !skipped.includes(f)) : ['.'];
    const base = adapter.command({ ...o, rulesDir: env.rulesDir } as ScanOptions);
    const shown = [...base.map((a) => (a === join(env.rulesDir, 'semgrep') ? (pack ? '<engine>/rules/semgrep + <rule-pack>' : '<engine>/rules/semgrep') : a)),
      env.tracked ? `<${targets.length} tracked files, list sha256 ${sha256(targets.join('\n')).slice(0, 16)}>` : '.'];
    const r = env.run([...base.map((a) => (a === join(env.rulesDir, 'semgrep') ? rulesDir : a)), ...targets]);
    let parsed: SemgrepJson;
    try { parsed = JSON.parse(r.stdout) as SemgrepJson; } catch { throw new Error(`semgrep printed no JSON (exit ${r.status})`); }
    const out = parseSemgrep(r.stdout, o, readRules(rulesDir));
    return {
      hits: out.hits, toolErrors: [...out.errors, ...skipped.map((file) => ({ type: 'skipped: minified', file, rule_id: '' }))], commands: [shown], configSha256: dirSha256(rulesDir),
      scanned: sortUnique(parsed.paths.scanned.map((p) => relPath(p, o.repo))), exitCode: r.status,
    };
  },
};

export function parseSemgrep(stdout: string, o: ScanOptions, rules: RuleInfo[]): { hits: DetailHit[]; errors: ToolError[] } {
  const j = JSON.parse(stdout) as SemgrepJson;
  const controls = loadControls(o.controlsPath);
  // check_id is prefixed with the rules folder written as a dotted path; the rule id is the known id it ends with.
  const ruleOf = (checkId: string): RuleInfo | undefined =>
    rules.find((r) => checkId === r.id || checkId.endsWith('.' + r.id));
  const hits = j.results.map((x): DetailHit => {
    const rule = ruleOf(x.check_id);
    const rule_id = rule?.id ?? x.check_id.split('.').pop()!;
    const file = relPath(x.path, o.repo);
    const meta = x.extra.metadata?.sec_ids ?? rule?.sec_ids ?? [];
    const m = mapHit({ tool: 'semgrep', rule_id, file, metadataSecIds: meta }, o.edition, controls);
    const secretRule = meta.some((id) => id.startsWith('SEC-SECRETS-'));
    return {
      tool: 'semgrep', rule_id, file, line: x.start.line, end_line: x.end.line, sec_ids: m.sec_ids,
      severity_hint: x.extra.severity ?? null, message_key: `semgrep:${rule_id}`, rule_version: rule?.version ?? 'unknown',
      evidence: secretRule ? null : sourceLine(o.repo, file, x.start.line), mapped_by: m.mapped_by, unmapped: m.sec_ids.length === 0,
    };
  });
  const errors = j.errors.map((e): ToolError => ({
    type: typeof e.type === 'string' ? e.type : Array.isArray(e.type) ? String(e.type[0]) : 'unknown',
    file: e.path ? relPath(e.path, o.repo) : '',
    rule_id: e.rule_id ? (ruleOf(e.rule_id)?.id ?? e.rule_id.split('.').pop()!) : '',
  }));
  return { hits, errors };
}
