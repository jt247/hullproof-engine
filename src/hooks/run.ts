// hullproof hooks run: the fast check the pre-commit hook calls. It looks at the staged files only, for two things: a secret, and a
// finding of the highest severity (BLOCKER) that a deterministic check or a mapped Semgrep rule raises in a staged file.
// Nothing leaves the machine: no network, no model, no upload. The staged content is exported from the index into a temporary
// folder, so the check sees what the commit will hold and not the working tree. Findings in files that are not staged never block.
// Exit 0 pass, 1 blocked. Any error is reported and lets the commit through (fail open), unless HULLPROOF_HOOK_STRICT=1.
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { makeContext } from '../checks/context.ts';
import { checkSha, loadChecks, runChecks } from '../checks/run.ts';
import { discover } from '../discover/discover.ts';
import { buildFindings, type BuildInput } from '../report/build.ts';
import { loadKit, readStage, resolveKitDir, type Edition } from '../report/kit.ts';
import { RULES_DIR } from '../scanners/common.ts';
import { runScanner } from '../scanners/index.ts';
import { adapter as gitleaks } from '../scanners/gitleaks.ts';
import { adapter as semgrep } from '../scanners/semgrep.ts';
import type { ScanOptions } from '../scanners/types.ts';
import { SEV_RANK } from '../report/kit.ts';
import type { CheckResultsFile, FailRecord, Hit, ToolMeta } from '../types/index.ts';

const SOURCE_FILES = /\.(js|mjs|cjs|ts|jsx|tsx|py|rb|php|go|java|kt|swift|yaml|yml|json|sql|tf|html)$/;

export interface HookRun { code: number; lines: string[] }
export interface HookOptions { repo: string; kit: string | null; semgrep: boolean; log?: (s: string) => void }

const git = (repo: string, args: string[], extra: NodeJS.ProcessEnv = {}): { ok: boolean; out: string } => {
  // --no-ext-diff and --no-textconv are given where they matter, so a driver named in the repository configuration cannot run.
  const r = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', ...extra } });
  return { ok: r.status === 0, out: r.stdout ?? '' };
};

export async function runHook(o: HookOptions): Promise<HookRun> {
  const started = Date.now();
  const top = git(o.repo, ['rev-parse', '--show-toplevel']);
  if (!top.ok) return { code: 2, lines: ['hullproof: not inside a git repository'] };
  const root = top.out.trim();
  const staged = git(root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '--no-ext-diff', '--no-textconv', '-z']).out.split('\0').filter(Boolean).sort();
  if (staged.length === 0) return { code: 0, lines: [] };
  const stagedSet = new Set(staged);

  const tmp = mkdtempSync(join(tmpdir(), 'hullproof-hook-'));
  try {
    const tree = join(tmp, 'tree');
    mkdirSync(tree);
    // The index as it will be committed, exported to a folder; its index file is copied so checks that ask which files git tracks
    // get the right answer.
    const exp = git(root, ['checkout-index', '-a', '-f', `--prefix=${tree}/`]);
    if (!exp.ok) throw new Error('could not read the staged files from the git index');
    const idxPath = resolve(root, git(root, ['rev-parse', '--git-path', 'index']).out.trim());
    mkdirSync(join(tree, '.git'));
    if (existsSync(idxPath)) copyFileSync(idxPath, join(tree, '.git/index'));
    writeFileSync(join(tree, '.git/HEAD'), 'ref: refs/heads/hook\n');

    const kitDir = resolveKitDir(root, o.kit);
    const kit = kitDir ? loadKit(kitDir) : null;
    const edition: Edition = kit?.controls.some((c) => c.edition === 'pro') ? 'pro' : 'free';
    const stack = discover(tree);
    const controlsPath = kitDir ? join(kitDir, 'docs/hullproof/security-controls.json') : undefined;
    const scanOpts = (extra: Partial<ScanOptions> = {}): ScanOptions => ({ repo: tree, out: join(tmp, 'out'), stack, allowNetwork: false, edition, history: false, kit: kitDir, controlsPath, ...extra });
    const metas: ToolMeta[] = [];
    const hits: Hit[] = [];
    const notes: string[] = [];
    const run = (a: typeof gitleaks, extra: Partial<ScanOptions> = {}): void => {
      const s = runScanner(a, scanOpts(extra));
      metas.push(s.meta);
      hits.push(...s.hits.hits);
      if (s.meta.status !== 'ran') notes.push(`${a.tool} did not run (${s.meta.status})`);
    };

    // 1. Secrets, which is the quick part: Gitleaks over the exported tree, kept to the staged files.
    run(gitleaks);
    const secretHits = hits.filter((h) => stagedSet.has(h.file));
    const secretsBlock = blockers(secretHits, EMPTY, kit, edition, tree, metas, stagedSet);
    if (secretsBlock.length || (secretHits.length && !kit)) {
      const lines = secretsBlock.length ? render(secretsBlock) : secretHits.map((h) => `  BLOCKER ${h.file}:${h.line}  a secret shaped value (rule ${h.rule_id})`);
      return done(1, lines, staged.length, started, notes);
    }
    if (!kit) return done(0, [], staged.length, started, [...notes, 'no kit was found (pass --kit or set HULLPROOF_KIT), so only secrets were checked']);

    // 2. Blocking findings from the deterministic checks and, when it is on, Semgrep on the staged source files.
    const sources = staged.filter((f) => SOURCE_FILES.test(f));
    if (o.semgrep && sources.length) run(semgrep, { targets: sources });
    const ctx = makeContext(tree, stack, hits, kitDir);
    const checkDefs = loadChecks();
    const checks = runChecks(ctx, checkDefs);
    const found = blockers(hits.filter((h) => stagedSet.has(h.file)), checks, kit, edition, tree, metas, stagedSet, checkDefs);
    return found.length ? done(1, render(found), staged.length, started, notes) : done(0, [], staged.length, started, notes);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

const EMPTY: CheckResultsFile = { schema_version: '1.0.0', commit: null, results: [], not_run: [] };
type Def = ReturnType<typeof loadChecks>;

// Fail records of BLOCKER severity that point at a staged file. The same record builder the scan uses, so a rule or a check gives
// the same title, requirement and fix here as in the report.
function blockers(hits: Hit[], checks: CheckResultsFile, kit: ReturnType<typeof loadKit> | null, edition: Edition, tree: string, metas: ToolMeta[], staged: Set<string>, defs: Def = []): FailRecord[] {
  if (!kit) return [];
  const input: BuildInput = {
    kit, scope: { edition, stage: readStage(tree).stage, stageSource: 'default' }, git: { commit: '0'.repeat(40), tree: '0'.repeat(40), clean: false },
    checks, hits, metas, checkShas: Object.fromEntries(defs.map((c) => [c.id, checkSha(c)])), rulesDirs: [join(RULES_DIR, 'semgrep')],
  };
  const { file } = buildFindings(input);
  return file.records.filter((r): r is FailRecord => r.kind === 'fail' && SEV_RANK[r.severity] >= SEV_RANK.BLOCKER && r.evidence.some((e) => staged.has(e.file)));
}

const render = (fs: FailRecord[]): string[] =>
  fs.flatMap((f) => {
    const e = f.evidence.find((x) => x.file) ?? f.evidence[0];
    return [`  ${f.severity} ${e ? `${e.file}:${e.line}` : ''}  ${f.title} (${f.sec_ids.join(', ')})`, `    Fix: ${f.remediation.strategy}`];
  });

function done(code: number, problems: string[], n: number, started: number, notes: string[]): HookRun {
  const secs = ((Date.now() - started) / 1000).toFixed(1);
  const lines = [...(code === 1 ? [`hullproof: BLOCKED, ${problems.filter((l) => l.startsWith('  ')&& !l.startsWith('    ')).length} problem(s) in the staged files`, ...problems] : []), ...notes.map((x) => `hullproof: note: ${x}`),
    `hullproof: checked ${n} staged file${n === 1 ? '' : 's'} in ${secs}s on this machine, nothing was sent anywhere.${code === 1 ? ' To commit anyway: git commit --no-verify' : ''}`];
  return { code, lines };
}
