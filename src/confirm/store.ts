// Where hunt files live and how they are read and written: <out>/<commit>/hunt/. Every answer is written the moment it arrives,
// through a temporary file and a rename, so an interrupted run leaves whole files only and can resume.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { HuntAnswer, HuntPlan, HuntResult, HuntSynthesis } from '../types/index.ts';
import { cmp, stableJson } from '../util.ts';

export const huntDir = (scanDir: string): string => join(scanDir, 'hunt');
const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'entry';
export const answerFile = (hunt: string, run: number, entryId: string): string =>
  join(hunt, `run-${run}`, `${slug(entryId)}-${createHash('sha256').update(entryId).digest('hex').slice(0, 8)}.json`);

function writeAtomic(path: string, text: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, text);
  renameSync(tmp, path);
}
const readJson = <T>(p: string): T => { try { return JSON.parse(readFileSync(p, 'utf8')) as T; } catch (e) { throw new Error(`${p} cannot be read: ${(e as Error).message}`); } };

export const writeAnswer = (hunt: string, a: HuntAnswer): void => writeAtomic(answerFile(hunt, a.run, a.entry_id), stableJson(a));
export const hasAnswer = (hunt: string, run: number, entryId: string): boolean => existsSync(answerFile(hunt, run, entryId));

export function readAnswers(hunt: string): HuntAnswer[] {
  if (!existsSync(hunt)) return [];
  const out: HuntAnswer[] = [];
  for (const d of readdirSync(hunt).filter((n) => /^run-\d+$/.test(n)).sort(cmp)) {
    for (const f of readdirSync(join(hunt, d)).filter((n) => n.endsWith('.json')).sort(cmp)) out.push(readJson<HuntAnswer>(join(hunt, d, f)));
  }
  return out.sort((a, b) => a.run - b.run || cmp(a.entry_id, b.entry_id));
}

export const writePlan = (hunt: string, p: HuntPlan): void => writeAtomic(join(hunt, 'plan.json'), stableJson(p));
export const readPlan = (hunt: string): HuntPlan | null => (existsSync(join(hunt, 'plan.json')) ? readJson<HuntPlan>(join(hunt, 'plan.json')) : null);
export const writeResult = (hunt: string, r: HuntResult): void => writeAtomic(join(hunt, 'result.json'), stableJson(r));
export const readResult = (hunt: string): HuntResult | null => (existsSync(join(hunt, 'result.json')) ? readJson<HuntResult>(join(hunt, 'result.json')) : null);
export const writeSynthesis = (hunt: string, s: HuntSynthesis): void => writeAtomic(join(hunt, 'synthesis.json'), stableJson(s));
export const readSynthesis = (hunt: string): HuntSynthesis | null => (existsSync(join(hunt, 'synthesis.json')) ? readJson<HuntSynthesis>(join(hunt, 'synthesis.json')) : null);
export const writeSkipped = (hunt: string, reason: string): void => writeAtomic(join(hunt, 'skipped.json'), stableJson({ schema_version: '1.0.0', reason }));
export const readSkipped = (hunt: string): string | null => (existsSync(join(hunt, 'skipped.json')) ? readJson<{ reason: string }>(join(hunt, 'skipped.json')).reason : null);
export const hasHuntFiles = (hunt: string): boolean => existsSync(hunt) && readdirSync(hunt).some((n) => /^run-\d+$/.test(n) || n === 'plan.json');
