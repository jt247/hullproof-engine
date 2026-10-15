// Where proof files live: <out>/<commit>/prove/. Specs go in, run transcripts and the result come out. Written through a temporary
// file and a rename, with the engine's one JSON writer, so the same value is the same bytes.
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ProveMeta, ProveResult, Recipe, RunRecord, Spec } from '../types/index.ts';
import { cmp, stableJson } from '../util.ts';
import { validateSpec } from './spec.ts';

export const proveDir = (scanDir: string): string => join(scanDir, 'prove');
const write = (p: string, text: string): void => { mkdirSync(join(p, '..'), { recursive: true }); writeFileSync(`${p}.tmp`, text); renameSync(`${p}.tmp`, p); };
const readJson = <T>(p: string): T => { try { return JSON.parse(readFileSync(p, 'utf8')) as T; } catch (e) { throw new Error(`${p} cannot be read: ${(e as Error).message}`); } };

export const specFile = (dir: string, id: string): string => join(dir, 'specs', `${id}.json`);
export const writeSpec = (dir: string, s: Spec): void => write(specFile(dir, s.spec_id), stableJson(s));
export const runFile = (dir: string, id: string, run: number): string => join(dir, 'runs', id, `run-${run}.json`);
export const writeRun = (dir: string, r: RunRecord): void => write(runFile(dir, r.spec_id, r.run), stableJson(r));
export const clearRuns = (dir: string): void => rmSync(join(dir, 'runs'), { recursive: true, force: true });
export const writeMeta = (dir: string, m: ProveMeta): void => write(join(dir, 'meta.json'), stableJson(m));
export const readMeta = (dir: string): ProveMeta | null => (existsSync(join(dir, 'meta.json')) ? readJson<ProveMeta>(join(dir, 'meta.json')) : null);
export const writeRecipe = (dir: string, r: Recipe): void => write(join(dir, 'recipe.json'), stableJson(r));
export const writeProveResult = (dir: string, r: ProveResult): void => write(join(dir, 'result.json'), stableJson(r));
export const readProveResult = (dir: string): ProveResult | null => (existsSync(join(dir, 'result.json')) ? readJson<ProveResult>(join(dir, 'result.json')) : null);

// Every spec file, validated. A file that fails validation is dropped and counted, with the reason.
export function loadSpecs(dir: string): { specs: Spec[]; dropped: { file: string; reason: string }[] } {
  const specs: Spec[] = [];
  const dropped: { file: string; reason: string }[] = [];
  const d = join(dir, 'specs');
  if (!existsSync(d)) return { specs, dropped };
  const seen = new Set<string>();
  for (const f of readdirSync(d).filter((n) => n.endsWith('.json')).sort(cmp)) {
    let raw: unknown;
    try { raw = JSON.parse(readFileSync(join(d, f), 'utf8')); } catch { dropped.push({ file: f, reason: 'not valid JSON' }); continue; }
    const v = validateSpec(raw);
    if (!v.ok) { dropped.push({ file: f, reason: v.errors.slice(0, 3).join('; ') }); continue; }
    if (`${v.spec.spec_id}.json` !== f) { dropped.push({ file: f, reason: `spec_id ${v.spec.spec_id} does not match the file name` }); continue; }
    if (seen.has(v.spec.spec_id)) { dropped.push({ file: f, reason: 'duplicate spec_id' }); continue; }
    seen.add(v.spec.spec_id);
    specs.push(v.spec);
  }
  return { specs, dropped };
}

export function readRuns(dir: string, id: string): RunRecord[] {
  const d = join(dir, 'runs', id);
  if (!existsSync(d)) return [];
  return readdirSync(d).filter((n) => /^run-\d+\.json$/.test(n)).sort(cmp).map((n) => readJson<RunRecord>(join(d, n))).sort((a, b) => a.run - b.run);
}
