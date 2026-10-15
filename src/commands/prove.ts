// hullproof prove. Runs test specs against a local copy of the app in a sandbox and keeps the transcripts as evidence. The safety
// rules are enforced here before anything starts: an explicit flag, the owner's typed confirmation, no target address of any kind,
// and (inside the runner) no secrets, no network, no host mounts. --replay rebuilds the result from saved transcripts with no
// sandbox. --gen (Pro) writes specs from hunt leads. --self-test runs the escape attempts on this machine's container runtime.
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { basename, join, resolve } from 'node:path';
import { makeContext } from '../checks/context.ts';
import { getMap } from '../checks/map/shared.ts';
import { discover } from '../discover/discover.ts';
import { readHeadCommit } from '../discover/git.ts';
import { loadHuntEnv } from '../env.ts';
import { ContainerRunner, CliRuntime } from '../prove/container.ts';
import { runEscapeProbes, selfTestApp } from '../prove/probes.ts';
import { deriveRecipe } from '../prove/recipe.ts';
import { replayProve, runProve } from '../prove/run.ts';
import { DEFAULT_LIMITS, type Runner } from '../prove/runner.ts';
import { checkConfirmation, CONFIRM_PHRASE } from '../prove/safety.ts';
import { validateSpec } from '../prove/spec.ts';
import { proveDir, writeSpec } from '../prove/store.ts';
import { huntDir, readResult } from '../confirm/store.ts';
import type { CodeMap, HuntResult, ProveResult, Recipe } from '../types/index.ts';
import { outDirFor } from './scan.ts';
import { PROVE_PRO } from './prove-pro.ts';

export interface ProveOptions {
  repo: string; out: string | null; commit: string | null; allowRun: boolean; confirm: string | null; target: string | null;
  specs: string[]; allowInstallScripts?: boolean; gen: boolean; provider: string | null; model: string | null; replay: boolean; selfTest: boolean; runtime: string | null;
  log?: (s: string) => void;
}
// For tests: a runner in place of the container runtime, and a way to answer the typed confirmation.
export interface ProveDeps { runner?: Runner; ask?: (question: string) => Promise<string>; interactive?: boolean }

export interface GenOptions { repo: string; proveDir: string; hunt: HuntResult; map: CodeMap; recipe: Recipe | null; provider: string | null; model: string | null; env: Record<string, string | undefined>; log: (s: string) => void }
export interface ProvePro { generate(o: GenOptions): Promise<number> }

export function summaryLines(r: ProveResult): string[] {
  const c = r.counts;
  const lines = [`hullproof prove: ${c.proven} proven (3 of 3 runs), ${c.not_proven} not proven, ${c.invalid} invalid, ${c.unstable} unstable, ${c.error} error, ${c.not_provable} not provable here, ${c.dropped} spec file(s) dropped`];
  if (r.not_provable) lines.push(`hullproof prove: not provable here (${r.not_provable.code}): ${r.not_provable.reason}`);
  for (const s of r.specs) if (s.outcome !== 'proven' && s.outcome !== 'not_provable') lines.push(`hullproof prove: ${s.spec_id}: ${s.outcome}: ${s.reason}`);
  if (r.left_behind) lines.push(`hullproof prove: WARNING: ${r.left_behind} container, image or network item(s) were left behind`);
  return lines;
}

export async function proveCommand(o: ProveOptions, deps: ProveDeps = {}): Promise<number> {
  const log = o.log ?? ((s: string) => process.stderr.write(s + '\n'));
  if (o.target !== null) { log('hullproof prove: refused. prove runs a local copy of the app in a sandbox and accepts no address. It never sends a request to a staging, production or any other URL.'); return 2; }
  const repo = resolve(o.repo);
  const commit = o.commit ?? readHeadCommit(repo);
  if (!commit) { log(`hullproof prove: no commit found in ${repo}; pass --commit`); return 2; }
  const dir = proveDir(outDirFor(repo, o.out, commit));
  if (o.replay) {
    if (o.gen || o.selfTest || o.specs.length || o.allowRun || o.confirm !== null || o.provider || o.model) { log('hullproof prove: --replay takes no other option except --out and --commit'); return 2; }
    const r = replayProve(dir);
    if (typeof r === 'string') { log(`hullproof prove: ${r}`); return 2; }
    for (const l of summaryLines(r)) log(l);
    log(`hullproof prove: replay wrote ${join(dir, 'result.json')}`);
    return 0;
  }

  // Specs the owner or a person wrote are validated and copied into the prove folder. A bad file is a bad input, named with its reasons.
  for (const f of o.specs) {
    let raw: unknown;
    try { raw = JSON.parse(readFileSync(resolve(f), 'utf8')); } catch (e) { log(`hullproof prove: cannot read spec ${f}: ${(e as Error).message}`); return 2; }
    const v = validateSpec(raw);
    if (!v.ok) { log(`hullproof prove: spec ${basename(f)} is invalid: ${v.errors.join('; ')}`); return 2; }
    writeSpec(dir, v.spec);
  }

  let stack;
  let map: CodeMap;
  try { stack = discover(repo); map = getMap(makeContext(repo, stack)); } catch (e) { log(`hullproof prove: ${(e as Error).message}`); return 2; }

  if (o.gen) {
    if (!PROVE_PRO) { log('hullproof prove: spec generation from leads is a Pro feature and is not part of this edition. Write specs by hand (see docs/INTERFACES.md) and pass them with --spec.'); return 2; }
    const hunt = readResult(huntDir(outDirFor(repo, o.out, commit)));
    if (!hunt) { log('hullproof prove: --gen needs the result of a hunt for this commit. Run hullproof hunt first.'); return 2; }
    const rec = deriveRecipe(repo, stack, map);
    const { env } = loadHuntEnv(repo);
    const code = await PROVE_PRO.generate({ repo, proveDir: dir, hunt, map, recipe: rec.ok ? rec.recipe : null, provider: o.provider, model: o.model, env, log });
    if (code !== 0 || !o.allowRun) return code;
  }

  if (!o.allowRun && !o.selfTest) {
    log('hullproof prove: nothing to do. Use --allow-run to run specs, --replay to rebuild the result from saved transcripts, or --gen (Pro) to write specs from leads.');
    return 2;
  }
  // Safety rule 1: the flag and the typed phrase, every run. Asked here, before a runtime is even looked for.
  let typed = o.confirm;
  if (typed === null && (deps.interactive ?? process.stdin.isTTY)) {
    const ask = deps.ask ?? (async (q: string) => { const rl = createInterface({ input: process.stdin, output: process.stderr }); try { return await rl.question(q); } finally { rl.close(); } });
    log('hullproof prove will build and start a copy of this app in a container, with no secrets, no network and no access to your files. Only the owner of the app may approve that.');
    typed = await ask(`Type exactly "${CONFIRM_PHRASE}" to continue: `);
  }
  const c = checkConfirmation(o.allowRun || o.selfTest, typed);
  if (!c.ok) { log(`hullproof prove: ${c.reason}`); return 2; }

  const bin = o.runtime ?? process.env.HULLPROOF_CONTAINER_BIN ?? 'docker';
  if (!/^[a-z][a-z0-9._-]{0,30}$/.test(bin)) { log('hullproof prove: --runtime names a container command such as docker or podman'); return 2; }
  const runner = deps.runner ?? new ContainerRunner(new CliRuntime(bin));
  const av = await runner.available();
  if (!av.ok) { log(`hullproof prove: ${av.reason}`); return 2; }

  if (o.selfTest) return selfTest(runner, log);
  if (o.allowInstallScripts) log('hullproof prove: WARNING: --allow-install-scripts is on. Install scripts of every dependency run inside the build container, which can reach the package registry. They run with no secrets and no host mounts, but they are third party code. Use it only for an app you trust.');
  const result = await runProve({ repo, proveDir: dir, commit, stack, map, runner, limits: DEFAULT_LIMITS, allowInstallScripts: o.allowInstallScripts, log });
  for (const l of summaryLines(result)) log(l);
  log(`hullproof prove: wrote ${join(dir, 'result.json')}`);
  return result.left_behind > 0 || result.counts.error > 0 ? 1 : 0;
}

async function selfTest(runner: Runner, log: (s: string) => void): Promise<number> {
  const app = selfTestApp();
  try {
    const p = await runner.prepare({ recipe: app.recipe, copyDir: app.dir, sourceDir: app.dir, limits: DEFAULT_LIMITS });
    if (!p.ok) { log(`hullproof prove: self test could not prepare the sandbox: ${p.reason}`); return 1; }
    const s = await p.prepared.start();
    if (!s.ok) { log(`hullproof prove: self test could not start the sandbox: ${s.reason}`); await p.prepared.dispose(); return 1; }
    const results = await runEscapeProbes(s.instance, app.marker);
    for (const r of results) log(`hullproof prove: self test: ${r.ok ? 'contained' : 'NOT CONTAINED'}: ${r.name} (${r.detail})`);
    const left = (await s.instance.stop()).left_behind.length + (await p.prepared.dispose()).left_behind.length;
    log(`hullproof prove: self test: ${left === 0 ? 'nothing left behind' : `${left} item(s) left behind`}`);
    return results.every((r) => r.ok) && left === 0 ? 0 : 1;
  } finally { app.cleanup(); }
}
