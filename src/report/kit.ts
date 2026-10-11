// Finds the Hullproof kit (docs/hullproof and tools/hullproof) and reads the controls file, the source of truth for
// severity, authority, edition and stage. The engine never copies severities into its own code.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Severity } from '../types/index.ts';

export const CONTROLS_REL = 'docs/hullproof/security-controls.json';
export const GATE_REL = 'tools/hullproof/ci/hullproof-gate.mjs';
export const VALIDATOR_REL = 'tools/hullproof/ci/validate-findings.mjs';
// The Hullproof Free kit in a folder called hullproof-free next to this repository, used when nothing else names a kit
// (same default as src/mapping).
const SIBLING_KIT = fileURLToPath(new URL('../../../hullproof-free/kit/', import.meta.url));

export interface Control {
  id: string; title: string; severity: Severity; authority: 'repo' | 'dashboard' | 'runtime'; edition: 'free' | 'pro';
  stage: 'LAUNCH' | 'GROWTH' | 'SCALE'; prelaunch: boolean; status: string; domains: string[]; verification_method: string[];
}

export interface Kit { dir: string; controls: Control[]; byId: Map<string, Control>; controlsSha256: string; standardVersion: string }

// Order: --kit, HULLPROOF_KIT, the scanned repository when the kit is installed in it, then the kit next to this repository.
export function resolveKitDir(repo: string, flag: string | null): string | null {
  const tries = [flag, process.env.HULLPROOF_KIT ?? null, repo, SIBLING_KIT].filter((x): x is string => !!x).map((d) => resolve(d));
  return tries.find((d) => existsSync(join(d, CONTROLS_REL))) ?? null;
}

export function loadKit(dir: string): Kit {
  const raw = readFileSync(join(dir, CONTROLS_REL));
  const doc = JSON.parse(raw.toString('utf8')) as { standard_version?: string; controls: Control[] };
  const controls = doc.controls.filter((c) => c.status === 'active' || c.status === undefined);
  return {
    dir, controls, byId: new Map(controls.map((c) => [c.id, c])),
    controlsSha256: createHash('sha256').update(raw).digest('hex'), standardVersion: String(doc.standard_version ?? 'unknown'),
  };
}

export const STAGES = ['LAUNCH', 'GROWTH', 'SCALE'] as const;
export type Stage = typeof STAGES[number];
export type Edition = 'free' | 'pro';

export interface Scope { edition: Edition; stage: Stage; stageSource: 'flag' | 'STAGE.md' | 'default' }

// A requirement is in scope when its edition is in the run's edition and its stage is at or below the declared stage.
export function inScope(c: Control, s: Scope): boolean {
  return (s.edition === 'pro' || c.edition === 'free') && STAGES.indexOf(c.stage) <= STAGES.indexOf(s.stage);
}

// The stage from docs/security/STAGE.md ("Stage: GROWTH" or a heading or table cell naming one stage), else LAUNCH.
export function readStage(repo: string): { stage: Stage; source: 'STAGE.md' | 'default' } {
  const p = join(repo, 'docs/security/STAGE.md');
  if (!existsSync(p)) return { stage: 'LAUNCH', source: 'default' };
  const m = /\b(?:stage|declared stage)\b[^\n]{0,20}?\b(LAUNCH|GROWTH|SCALE)\b/i.exec(readFileSync(p, 'utf8'));
  return m ? { stage: m[1].toUpperCase() as Stage, source: 'STAGE.md' } : { stage: 'LAUNCH', source: 'default' };
}

export const SEV_RANK: Record<Severity, number> = { BLOCKER: 5, CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
export const highest = (sevs: Severity[]): Severity => sevs.reduce((a, b) => (SEV_RANK[b] > SEV_RANK[a] ? b : a), sevs[0]);
