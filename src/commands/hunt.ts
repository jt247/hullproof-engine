// hullproof hunt. --replay (open) reruns the confirmation from the saved answers in <out>/<commit>/hunt/ and writes result.json.
// The other modes call a model through the hunt step that only the Pro edition has (src/commands/hunt-pro.ts).
import { resolve } from 'node:path';
import { makeContext, type CheckContext } from '../checks/context.ts';
import { getMap } from '../checks/map/shared.ts';
import { confirmHunt } from '../confirm/confirm.ts';
import { huntDir, readAnswers, readPlan, readSynthesis, writeResult, writeSynthesis } from '../confirm/store.ts';
import { summary } from '../confirm/summary.ts';
import { reguard } from '../confirm/synthesis.ts';
import { discover } from '../discover/discover.ts';
import { readHeadCommit } from '../discover/git.ts';
import { loadHuntEnv } from '../env.ts';
import { resolveKitDir } from '../report/kit.ts';
import type { CodeMap } from '../types/index.ts';
import { outDirFor } from './scan.ts';
import { HUNT_PRO } from './hunt-pro.ts';

export interface HuntOptions {
  repo: string; out: string | null; kit: string | null; commit: string | null; provider: string | null; model: string | null;
  runs: number | null; dryRun: boolean; resume: boolean; replay: boolean; log?: (s: string) => void;
}
export interface HuntRunOptions {
  repo: string; scanDir: string; huntDir: string; commit: string | null; map: CodeMap; ctx: CheckContext; kitDir: string;
  provider: string | null; model: string | null; runs: number; dryRun: boolean; resume: boolean;
  env: Record<string, string | undefined>; log: (s: string) => void;
}
export interface HuntPro { run(o: HuntRunOptions): Promise<number> }

export const DEFAULT_RUNS = 3;

export async function huntCommand(o: HuntOptions): Promise<number> {
  const log = o.log ?? ((s: string) => process.stderr.write(s + '\n'));
  const repo = resolve(o.repo);
  const commit = o.commit ?? readHeadCommit(repo);
  if (!commit) { log(`hullproof hunt: no commit found in ${repo}; pass --commit`); return 2; }
  if (o.replay && (o.dryRun || o.resume || o.provider || o.model || o.runs !== null)) { log('hullproof hunt: --replay takes no other hunt option'); return 2; }
  if (o.dryRun && o.resume) { log('hullproof hunt: --dry-run and --resume cannot be used together'); return 2; }
  const scanDir = outDirFor(repo, o.out, commit);
  const hd = huntDir(scanDir);
  let map: CodeMap;
  let ctx: CheckContext;
  try { ctx = makeContext(repo, discover(repo)); map = getMap(ctx); } catch (e) { log(`hullproof hunt: ${(e as Error).message}`); return 2; }

  if (o.replay) {
    let answers;
    let plan;
    try { answers = readAnswers(hd); plan = readPlan(hd); } catch (e) { log(`hullproof hunt: ${(e as Error).message}`); return 2; }
    if (!answers.length && !plan) { log(`hullproof hunt: no saved hunt outputs in ${hd}`); return 2; }
    const result = confirmHunt({ repo, map, answers, plan, commit });
    writeResult(hd, result);
    const syn = readSynthesis(hd);
    if (syn) writeSynthesis(hd, reguard(result, syn));
    for (const l of summary(result)) log(l);
    log(`hullproof hunt: replay wrote ${hd}/result.json`);
    return 0;
  }

  if (!HUNT_PRO) {
    log('hullproof hunt: the step that calls a model is not part of this edition. Use --replay to confirm saved outputs.');
    return 2;
  }
  const runs = o.runs ?? DEFAULT_RUNS;
  if (!Number.isInteger(runs) || runs < 1) { log('hullproof hunt: --runs needs a whole number of 1 or more'); return 2; }
  const kitDir = resolveKitDir(repo, o.kit);
  if (!kitDir) { log('hullproof hunt: no kit found. Pass --kit or set HULLPROOF_KIT.'); return 2; }
  const { env } = loadHuntEnv(repo);
  return HUNT_PRO.run({ repo, scanDir, huntDir: hd, commit, map, ctx, kitDir, provider: o.provider, model: o.model, runs, dryRun: o.dryRun, resume: o.resume, env, log });
}
