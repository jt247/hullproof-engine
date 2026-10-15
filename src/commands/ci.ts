// hullproof ci: discover, scan, map, check and gate in one command, with no model and no container (hunt is the one option that
// calls a model, and only in the Pro edition). It writes four files for the commit and exits 0, 1 or 2:
//   findings.json   the findings record, schema 1.1.0
//   report.md       the plain English report
//   results.sarif   SARIF 2.1.0 for code scanning
//   pr-comment.md   the summary for a pull request
// The files are byte identical for the same commit, engine, kit and scanner versions. They go to <out>/<commit>/ and to the flat
// folder --artifacts (default <out>/ci), so a CI job, an AI tool and a person all read the same paths.
// Exit 0: nothing at or above --fail-on failed. Exit 1: something did. Exit 2: bad input, a refused run or a records problem.
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { readHeadCommit } from '../discover/git.ts';
import { loadHuntEnv } from '../env.ts';
import { checkSarif } from '../ci/sarif-check.ts';
import { buildSarif, sarifJson } from '../ci/sarif.ts';
import { ciVerdict, FAIL_ON_LEVELS, prComment, type FailOn } from '../ci/comment.ts';
import { gateLines } from '../gate/gate.ts';
import { loadKit, resolveKitDir, type Edition, type Stage } from '../report/kit.ts';
import { renderReport } from '../report/report.ts';
import { stableJson } from '../util.ts';
import type { ScannerId } from '../types/index.ts';
import { huntCommand } from './hunt.ts';
import { HUNT_PRO } from './hunt-pro.ts';
import { prepare } from './report-gate.ts';
import { scan } from './scan.ts';

export interface CiOptions {
  repo: string; out: string | null; kit: string | null; edition: Edition | null; stage: Stage | null; failOn: FailOn;
  artifacts: string | null; allowNetwork: boolean; tools: ScannerId[] | null; rulePack: string | null;
  owner: string | null; date: string | null;
  hunt: boolean; provider: string | null; model: string | null;
  log?: (s: string) => void; print?: (s: string) => void;
}

export const CI_FILES = ['findings.json', 'report.md', 'results.sarif', 'pr-comment.md'] as const;

export async function ciCommand(o: CiOptions): Promise<number> {
  const log = o.log ?? ((s: string) => process.stderr.write(s + '\n'));
  const print = o.print ?? ((s: string) => process.stdout.write(s + '\n'));
  const repo = resolve(o.repo);
  if (!FAIL_ON_LEVELS.includes(o.failOn)) { log(`hullproof ci: --fail-on takes ${FAIL_ON_LEVELS.join(', ')}`); return 2; }
  const kitDir = resolveKitDir(repo, o.kit);
  if (!kitDir) { log('hullproof ci: no kit found. Pass --kit <folder holding docs/hullproof/security-controls.json> or set HULLPROOF_KIT.'); return 2; }
  // The edition follows the kit unless it is named: a kit with Pro requirements runs the full set, the Free kit runs BLOCKER and CRITICAL.
  const edition: Edition = o.edition ?? (loadKit(kitDir).controls.some((c) => c.edition === 'pro') ? 'pro' : 'free');

  if (o.hunt) {
    if (!HUNT_PRO) { log('hullproof ci: --hunt calls a model and is part of the Pro edition. This edition runs the deterministic checks only.'); return 2; }
    if (edition !== 'pro') { log('hullproof ci: --hunt needs the Pro edition requirements (the kit has none, or --edition free was given)'); return 2; }
  }

  const code = await scan({
    repo, out: o.out, kit: kitDir, edition, stage: o.stage, allowNetwork: o.allowNetwork, tools: o.tools, rulePack: o.rulePack, log,
  });
  if (code !== 0) return 2;

  if (o.hunt) {
    // The key comes from the environment (a CI secret) or a .env.local file, never from a flag, and is never printed.
    // No .env.local is read in CI: the repository under test is untrusted and must not name the provider address.
    process.env.HULLPROOF_NO_ENV_FILE = '1';
    const { env } = loadHuntEnv(repo);
    if (!o.provider && !env.HULLPROOF_PROVIDER && !env.ANTHROPIC_API_KEY && !env.OPENAI_API_KEY && !env.GEMINI_API_KEY) {
      log('hullproof ci: --hunt needs a provider key in the environment (a CI secret). None is set, so no model was called.');
      return 2;
    }
    const h = await huntCommand({ repo, out: o.out, kit: kitDir, commit: null, provider: o.provider, model: o.model, runs: null, dryRun: false, resume: false, replay: false, log });
    if (h !== 0) return 2;
  }

  const r = await prepare({ repo, out: o.out, kit: kitDir, commit: null, owner: o.owner, date: o.date, log });
  if (typeof r === 'string') { log(`hullproof ci: ${r}`); return 2; }
  if (r.gate.problems.length) { for (const p of r.gate.problems) log(`hullproof ci: ${p}`); return 2; }

  const findings = r.s.findings;
  const verdict = ciVerdict(findings, o.failOn);
  // The SARIF result of a record with no evidence file points at a file that exists in every repository the engine can scan.
  const anchor = existsSync(join(repo, 'package.json')) ? 'package.json' : existsSync(join(repo, 'README.md')) ? 'README.md' : '.gitignore';
  const sarif = buildSarif(findings, r.kit, anchor);
  const bad = checkSarif(sarif);
  if (bad.length) { for (const b of bad) log(`hullproof ci: results.sarif: ${b}`); return 2; }

  const ran = r.s.metas.filter((m) => m.status === 'ran').map((m) => m.tool);
  const files: Record<(typeof CI_FILES)[number], string> = {
    'findings.json': stableJson(findings),
    'report.md': renderReport(r.s, r.kit, r.gate, r.merged),
    'results.sarif': sarifJson(sarif),
    'pr-comment.md': prComment({ findings, verdict, failOn: o.failOn, edition, scanners: ran }),
  };
  const commit = readHeadCommit(repo)!;
  const base = resolve(o.out ?? join(repo, '.hullproof'));
  const targets = [join(base, commit), resolve(o.artifacts ?? join(base, 'ci'))];
  for (const t of targets) {
    mkdirSync(t, { recursive: true });
    for (const n of CI_FILES) { rmSync(join(t, n), { force: true }); writeFileSync(join(t, n), files[n]); }
  }

  print(`hullproof ci: commit ${commit.slice(0, 12)}, ${edition} edition, stage ${findings.report.stage}, fails on ${o.failOn === 'none' ? 'nothing' : o.failOn.toUpperCase() + ' and above'}`);
  print(`hullproof ci: findings ${verdict.blocking.length + verdict.others.length}, blocking ${verdict.blocking.length}`);
  for (const f of verdict.blocking.slice(0, 20)) print(`  ${f.severity} ${f.sec_ids.join(',')} ${f.evidence[0] ? `${f.evidence[0].file}:${f.evidence[0].line}` : '-'} ${f.title}`);
  print(`hullproof ci: release gate for this commit (informational in CI): ${gateLines(r.gate).at(-1)}`);
  print(`hullproof ci: wrote ${CI_FILES.join(', ')} to ${targets[1]}`);
  print(`hullproof ci: ${verdict.blocked ? 'FAILED, a blocking finding is open' : 'PASSED'}`);
  return verdict.blocked ? 1 : 0;
}
