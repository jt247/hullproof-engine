// The proof run: for each spec, start the app in a fresh sandbox, run the spec, tear down, three times; then build result.json from
// the saved run files. Building the result is one pure function, used by the live run and by the replay, so a replay of the saved
// transcripts gives the same bytes with no sandbox. Nothing here decides a verdict by itself: the verdict function is judge()
// in executor.ts and it reads only the stored transcript.
import type { CodeMap, NotProvable, ProveMeta, ProveResult, ProveRunSummary, ProveSpecResult, Recipe, RunOutcome, RunRecord, Spec, SpecOutcome, Stack } from '../types/index.ts';
import { ENGINE_VERSION } from '../version.ts';
import { cmp } from '../util.ts';
import { judge, runRecord } from './executor.ts';
import { deriveRecipe, recipeSha256 } from './recipe.ts';
import { makeSandboxCopy } from './safety.ts';
import { DEFAULT_LIMITS, type Limits, type Runner } from './runner.ts';
import { canon, sha256, specSha256 } from './spec.ts';
import { clearRuns, loadSpecs, readMeta, readRuns, writeMeta, writeProveResult, writeRecipe, writeRun } from './store.ts';

export const RUNS_REQUIRED = 3;

function verifyRun(spec: Spec, specSha: string, rr: RunRecord): ProveRunSummary {
  const bad = (detail: string): ProveRunSummary => ({ run: rr.run, outcome: 'error', transcript_sha256: rr.transcript_sha256, detail });
  if (rr.spec_sha256 !== specSha) return bad('the spec changed after this run, so its transcript no longer belongs to it');
  const { transcript_sha256: _h, ...body } = rr;
  if (sha256(canon(body)) !== rr.transcript_sha256) return bad('the stored transcript does not match its hash; it was changed after the run');
  if (!rr.steps.length) return rr.outcome === 'error' ? { run: rr.run, outcome: 'error', transcript_sha256: rr.transcript_sha256, detail: rr.detail } : bad('a run with no steps can only be an error');
  const j = judge(spec, rr.steps);
  if (!j.done || !j.outcome) return bad('the stored transcript stops before the spec reaches a verdict');
  if (j.outcome !== rr.outcome) return bad(`the stored outcome (${rr.outcome}) does not match what the transcript shows (${j.outcome})`);
  return { run: rr.run, outcome: j.outcome, transcript_sha256: rr.transcript_sha256, detail: j.detail };
}

function combine(runs: ProveRunSummary[], required: number): { outcome: SpecOutcome; reason: string } {
  if (runs.length < required) return { outcome: 'error', reason: `${runs.length} of ${required} runs finished, so nothing is proven` };
  const set = new Set<RunOutcome>(runs.map((r) => r.outcome));
  if (set.size > 1) return { outcome: 'unstable', reason: `the runs disagreed (${runs.map((r) => r.outcome).join(', ')}), so the lead stays a lead` };
  const o = runs[0].outcome;
  return { outcome: o, reason: o === 'proven' ? `${required} of ${required} runs: the positive control passed and the flaw showed` : runs[0].detail };
}

export function buildResult(meta: ProveMeta, specs: Spec[], dropped: { file: string; reason: string }[], runsOf: (id: string) => RunRecord[]): ProveResult {
  const out: ProveSpecResult[] = [];
  for (const s of specs.slice().sort((a, b) => cmp(a.spec_id, b.spec_id))) {
    const sha = specSha256(s);
    const base = { spec_id: s.spec_id, spec_sha256: sha, lead_key: s.lead_key, title: s.title, claim: s.claim, entry_point: s.target.entry_point, requirement_ids: s.requirement_ids, sink: { file: s.target.file, line: s.target.line } };
    if (meta.not_provable) { out.push({ ...base, outcome: 'not_provable', reason: `not provable here (${meta.not_provable.code}): ${meta.not_provable.reason}`, runs: [] }); continue; }
    const runs = runsOf(s.spec_id).map((r) => verifyRun(s, sha, r));
    out.push({ ...base, ...combine(runs, meta.runs_required), runs });
  }
  const n = (o: SpecOutcome): number => out.filter((x) => x.outcome === o).length;
  return {
    schema_version: '1.0.0', engine_version: ENGINE_VERSION, commit: meta.commit, runner: meta.runner, runs_required: meta.runs_required,
    recipe_sha256: meta.recipe_sha256, not_provable: meta.not_provable, specs: out, dropped, left_behind: meta.left_behind, copy_excluded: meta.copy_excluded,
    counts: { specs: out.length, proven: n('proven'), not_proven: n('not_proven'), invalid: n('invalid'), unstable: n('unstable'), error: n('error'), not_provable: n('not_provable'), dropped: dropped.length },
  };
}

export interface ProveInput {
  repo: string; proveDir: string; commit: string | null; stack: Stack; map: CodeMap; runner: Runner;
  runs?: number; limits?: Limits; allowInstallScripts?: boolean; log: (s: string) => void;
}

const finish = (i: ProveInput, meta: ProveMeta, specs: Spec[], dropped: { file: string; reason: string }[]): ProveResult => {
  writeMeta(i.proveDir, meta);
  const r = buildResult(meta, specs, dropped, (id) => readRuns(i.proveDir, id));
  writeProveResult(i.proveDir, r);
  return r;
};

export async function runProve(i: ProveInput): Promise<ProveResult> {
  const limits = i.limits ?? DEFAULT_LIMITS;
  const required = i.runs ?? RUNS_REQUIRED;
  const { specs, dropped } = loadSpecs(i.proveDir);
  clearRuns(i.proveDir);
  const meta: ProveMeta = { schema_version: '1.0.0', commit: i.commit, runner: i.runner.name, runs_required: required, recipe_sha256: null, not_provable: null, left_behind: 0, copy_excluded: [] };
  const stop = (np: NotProvable): ProveResult => finish(i, { ...meta, not_provable: np }, specs, dropped);
  if (!specs.length) { i.log('hullproof prove: no valid specs to run'); return finish(i, meta, specs, dropped); }

  const rec = deriveRecipe(i.repo, i.stack, i.map, { allowInstallScripts: i.allowInstallScripts });
  if (!rec.ok) return stop({ code: rec.code, reason: rec.reason });
  const recipe: Recipe = rec.recipe;
  meta.recipe_sha256 = recipeSha256(recipe);
  writeRecipe(i.proveDir, recipe);
  const av = await i.runner.available();
  if (!av.ok) return stop({ code: 'no_runtime', reason: av.reason });
  const copy = makeSandboxCopy(i.repo, { keepNodeModules: recipe.vendored_modules });
  if ('error' in copy) return stop({ code: 'too_large', reason: copy.error });
  meta.copy_excluded = copy.excluded;
  let notProvable: NotProvable | null = null;
  let leftBehind = 0;
  try {
    i.log(`hullproof prove: ${i.runner.name}, ${copy.files} files copied, ${copy.excluded.length} left out, preparing the image`);
    const prep = await i.runner.prepare({ recipe, copyDir: copy.dir, sourceDir: i.repo, limits });
    if (!prep.ok) { notProvable = { code: prep.code, reason: prep.reason }; }
    else {
      try {
        outer: for (const spec of specs) {
          const sha = specSha256(spec);
          for (let run = 1; run <= required; run++) {
            const st = await prep.prepared.start();
            if (!st.ok) { notProvable = { code: st.code, reason: st.reason }; break outer; }
            try {
              const r = await st.instance.runSpec(spec);
              const body = r.ok ? { outcome: r.outcome, detail: r.detail, steps: r.steps } : { outcome: 'error' as const, detail: r.reason, steps: [] };
              writeRun(i.proveDir, runRecord(spec, sha, run, body));
              i.log(`hullproof prove: ${spec.spec_id} run ${run}/${required}: ${body.outcome}`);
            } finally { leftBehind += (await st.instance.stop()).left_behind.length; }
          }
        }
      } finally {
        const t = await prep.prepared.dispose();
        leftBehind += t.left_behind.length;
        if (t.left_behind.length) i.log(`hullproof prove: WARNING: left behind after teardown: ${t.left_behind.join(', ')}`);
      }
    }
  } finally { copy.cleanup(); }
  return finish(i, { ...meta, not_provable: notProvable, left_behind: leftBehind }, specs, dropped);
}

// Rebuilds result.json from the saved specs and run files. No sandbox, no app, no model.
export function replayProve(proveDir: string): ProveResult | string {
  const meta = readMeta(proveDir);
  if (!meta) return `no saved proof run in ${proveDir}`;
  const { specs, dropped } = loadSpecs(proveDir);
  const r = buildResult(meta, specs, dropped, (id) => readRuns(proveDir, id));
  writeProveResult(proveDir, r);
  return r;
}
