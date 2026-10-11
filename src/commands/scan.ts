// hullproof scan: discover, scanner adapters, checks, then results.json, the findings record and surface.json, all under
// <out>/<commit>/. Every contract file is byte identical for the same commit, engine, kit files and tool versions.
// Run times go to run.json and scan/run.json only.
import { existsSync, mkdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { discover } from '../discover/discover.ts';
import { makeContext } from '../checks/context.ts';
import { getMap } from '../checks/map/shared.ts';
import { checkSha, loadChecks, runChecks } from '../checks/run.ts';
import { buildFindings, buildResults, findingsJson, findingsMarkdown, type Dropped } from '../report/build.ts';
import { loadKit, readStage, resolveKitDir, VALIDATOR_REL, type Edition, type Scope, type Stage } from '../report/kit.ts';
import { surface } from '../report/surface.ts';
import { runScanners } from '../scanners/index.ts';
import { dirSha256, RULES_DIR } from '../scanners/common.ts';
import { ruleFiles } from '../scanners/semgrep.ts';
import { stableJson } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import type { Hit, ScannerId, Stack, ToolMeta } from '../types/index.ts';
import { gitSafety, gitState } from './git.ts';

export interface ScanOptions {
  repo: string; out: string | null; kit: string | null; edition: Edition; stage: Stage | null;
  allowNetwork: boolean; tools: ScannerId[] | null;
  // An external Semgrep rule pack folder (for example a rule pack of your own). null: --rule-pack, else HULLPROOF_RULE_PACK, else none.
  rulePack?: string | null;
  // For tests: replaces the scanner adapters. Returns hits and metas for this run.
  scanners?: (stack: Stack, dir: string) => { hits: Hit[]; metas: ToolMeta[] };
  log?: (s: string) => void;
}

// scan.json: what the report and the gate need to read the folder the same way the scan wrote it.
export interface ScanInfo {
  schema_version: '1.0.0'; engine_version: string; commit: string; tree: string; tree_clean: boolean;
  edition: Edition; stage: Stage; stage_source: Scope['stageSource'];
  kit: { controls_sha256: string; standard_version: string; controls_found: boolean };
  scanners_available: boolean; tools: ScannerId[];
  // The external rule pack, if one was loaded: its folder name, file names and the sha256 of the folder. Never a path.
  rule_pack: { name: string; files: string[]; sha256: string } | null;
  checks: { total: number; ran: number; not_run: number };
  // The code map in this folder (codemap.json): how many entry points, and the languages it did not fully read.
  codemap: { entry_points: number; incomplete: { language: string; status: string }[] };
  dropped: Dropped[];
}

export const KIT_LOCAL = 'kit.local.json';
export const outDirFor = (repo: string, out: string | null, commit: string): string => join(resolve(out ?? join(repo, '.hullproof')), commit);

function defaultScanners(o: ScanOptions, stack: Stack, dir: string, controlsPath: string, kitDir: string, rulePack: string | null): { hits: Hit[]; metas: ToolMeta[] } {
  const outs = runScanners({ repo: o.repo, out: dir, stack, allowNetwork: o.allowNetwork, edition: o.edition, controlsPath, history: true, kit: kitDir, rulePack }, o.tools ?? undefined);
  return { hits: outs.flatMap((s) => s.hits.hits), metas: outs.map((s) => s.meta) };
}

// The rule pack folder from the option or HULLPROOF_RULE_PACK, checked before anything runs. A string is a bad input.
export function resolveRulePack(given: string | null | undefined): { path: string | null } | string {
  const raw = given ?? process.env.HULLPROOF_RULE_PACK ?? null;
  if (!raw) return { path: null };
  const path = resolve(raw);
  if (!existsSync(path) || !statSync(path).isDirectory()) return `the rule pack folder ${raw} does not exist`;
  try { ruleFiles(join(RULES_DIR, 'semgrep'), path); } catch (e) { return (e as Error).message; }
  return { path };
}

export async function scan(o: ScanOptions): Promise<number> {
  const log = o.log ?? ((s: string) => process.stderr.write(s + '\n'));
  const repo = resolve(o.repo);
  if (!existsSync(repo)) { log(`hullproof scan: ${repo} does not exist`); return 2; }
  const safety = gitSafety(repo);
  if (!safety.ok) { log(`hullproof scan: ${safety.message}`); return 2; }
  if (safety.credentialUrl) log('hullproof scan: note: a remote URL holds embedded credentials. Treat that credential as exposed and rotate it. The line is not printed.');
  const git = gitState(repo);
  if (!git) { log('hullproof scan: could not read the commit and tree with git (is there a commit?)'); return 2; }
  const kitDir = resolveKitDir(repo, o.kit);
  if (!kitDir) { log('hullproof scan: no kit found. Pass --kit <folder holding docs/hullproof/security-controls.json> or set HULLPROOF_KIT.'); return 2; }
  const kit = loadKit(kitDir);
  const pack = resolveRulePack(o.rulePack);
  if (typeof pack === 'string') { log(`hullproof scan: ${pack}`); return 2; }
  const st = o.stage ? { stage: o.stage, source: 'flag' as const } : readStage(repo);
  const scope: Scope = { edition: o.edition, stage: st.stage, stageSource: st.source };

  const started = Date.now();
  const dir = outDirFor(repo, o.out, git.commit);
  // Start from an empty folder so files from an earlier run with other tools never mix in.
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const stack = discover(repo);
  writeFileSync(join(dir, 'stack.json'), stableJson(stack));

  const controlsPath = join(kitDir, 'docs/hullproof/security-controls.json');
  const sc = o.scanners ? o.scanners(stack, dir) : defaultScanners(o, stack, dir, controlsPath, kitDir, pack.path);
  const hits = sc?.hits ?? [];
  const metas = (sc?.metas ?? []).slice().sort((a, b) => (a.tool < b.tool ? -1 : 1));
  if (o.scanners) {
    // Stub scanners (tests) do not write their files; write them here in the adapters' layout.
    mkdirSync(join(dir, 'scan'), { recursive: true });
    for (const m of metas) {
      writeFileSync(join(dir, 'scan', `${m.tool}.meta.json`), stableJson(m));
      writeFileSync(join(dir, 'scan', `${m.tool}.json`), stableJson({ schema_version: '1.0.0', tool: m.tool, hits: hits.filter((h) => h.tool === m.tool) }));
    }
  }

  const checkDefs = loadChecks();
  const ctx = makeContext(repo, stack, hits, kitDir);
  const checks = runChecks(ctx, checkDefs);
  writeFileSync(join(dir, 'checks.json'), stableJson(checks));
  const codemap = getMap(ctx);
  writeFileSync(join(dir, 'codemap.json'), stableJson(codemap));

  const input = { kit, scope, git, checks, hits, metas, checkShas: Object.fromEntries(checkDefs.map((c) => [c.id, checkSha(c)])), rulesDirs: [join(RULES_DIR, 'semgrep'), ...(pack.path ? [pack.path] : [])] };
  const results = buildResults(input);
  writeFileSync(join(dir, 'results.json'), stableJson(results));
  const { file: findings, dropped } = buildFindings(input);
  const findingsMd = findingsMarkdown(findings, findingsJson(findings));
  writeFileSync(join(dir, 'report.findings.md'), findingsMd);
  writeFileSync(join(dir, 'surface.json'), stableJson(surface(ctx)));
  const info: ScanInfo = {
    schema_version: '1.0.0', engine_version: ENGINE_VERSION, commit: git.commit, tree: git.tree, tree_clean: git.clean,
    edition: scope.edition, stage: scope.stage, stage_source: scope.stageSource,
    kit: { controls_sha256: kit.controlsSha256, standard_version: kit.standardVersion, controls_found: true },
    scanners_available: true, tools: metas.map((m) => m.tool),
    rule_pack: pack.path ? { name: basename(pack.path), files: ruleFiles(pack.path).map((f) => basename(f)), sha256: dirSha256(pack.path) } : null,
    checks: { total: checkDefs.length, ran: checks.results.length, not_run: checks.not_run.length },
    codemap: { entry_points: codemap.counts.entry_points, incomplete: codemap.coverage.filter((c) => c.status !== 'mapped').map((c) => ({ language: c.language, status: c.status })) },
    dropped,
  };
  writeFileSync(join(dir, 'scan.json'), stableJson(info));
  writeFileSync(join(dir, 'run.json'), JSON.stringify({ seconds: (Date.now() - started) / 1000 }) + '\n');
  // The kit this scan used, so report and gate find the same kit without --kit. A machine path, so it lives outside the
  // byte identical contract (like run.json); the controls sha256 in it is also in scan.json.
  writeFileSync(join(dir, KIT_LOCAL), JSON.stringify({ kit_dir: kitDir, controls_sha256: kit.controlsSha256 }) + '\n');

  // Self check with the kit's own validator: a record file the kit rejects is a bug, never a result.
  const problems = await validateWithKit(kitDir, findingsMd, kit.byId);
  if (problems.length) {
    for (const p of problems) log(`hullproof scan: findings record: ${p}`);
    return 2;
  }
  const fails = results.filter((r) => r.result === 'FAIL').length;
  const records = findings.records.filter((r) => r.kind === 'fail').length;
  log(`hullproof scan: wrote ${dir}`);
  log(`hullproof scan: requirements in scope ${results.length}, FAIL ${fails}, PASS (static) ${results.filter((r) => r.result === 'PASS (static)').length}, NOT ASSESSED ${results.filter((r) => r.result.startsWith('NOT ASSESSED')).length}; fail records ${records}; tools ran ${metas.filter((m) => m.status === 'ran').map((m) => m.tool).join(', ') || 'none'}`);
  return 0;
}

export async function validateWithKit(kitDir: string, text: string, byId: Map<string, { severity: string; authority: string }>): Promise<string[]> {
  const path = join(kitDir, VALIDATOR_REL);
  if (!existsSync(path)) return [];
  const v = await import(pathToFileURL(path).href) as { validateFindingsText: (t: string, o: { controls: Map<string, unknown> }) => { c: { errorCount: number; lines(): string[] } } };
  const res = v.validateFindingsText(text, { controls: byId });
  return res.c.errorCount ? res.c.lines() : [];
}
