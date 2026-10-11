// Reads the kit's security-controls.json, the source of truth for requirement IDs, edition and the tests each control
// ships. The engine never copies it. Path order: the explicit argument, HULLPROOF_CONTROLS, HULLPROOF_KIT, then the Hullproof Free kit
// in a folder called hullproof-free next to this repository.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_CONTROLS = fileURLToPath(
  new URL('../../../hullproof-free/kit/docs/hullproof/security-controls.json', import.meta.url));

export interface Control { id: string; edition: 'free' | 'pro'; status: string; tests: { id: string; kind: string; path: string }[] }

export interface Controls {
  path: string;
  byId: Map<string, Control>;
  ruleToIds: Map<string, string[]>;   // shipped test id (a Semgrep rule id) -> control ids that list it
}

const cache = new Map<string, Controls | null>();

const CONTROLS_REL = 'docs/hullproof/security-controls.json';
export const controlsPathFromEnv = (): string =>
  process.env.HULLPROOF_CONTROLS ?? (process.env.HULLPROOF_KIT ? join(process.env.HULLPROOF_KIT, CONTROLS_REL) : DEFAULT_CONTROLS);

export function loadControls(path = controlsPathFromEnv()): Controls | null {
  if (cache.has(path)) return cache.get(path)!;
  let out: Controls | null = null;
  if (existsSync(path)) {
    const doc = JSON.parse(readFileSync(path, 'utf8')) as { controls: Control[] };
    const byId = new Map(doc.controls.map((c) => [c.id, c]));
    const ruleToIds = new Map<string, string[]>();
    for (const c of doc.controls) for (const t of c.tests ?? []) ruleToIds.set(t.id, [...(ruleToIds.get(t.id) ?? []), c.id]);
    out = { path, byId, ruleToIds };
  }
  cache.set(path, out);
  return out;
}

// IDs in scope for an edition. Free keeps only IDs the controls file marks free; an ID the file does not list yet
// (one written in a standard document but not built into the file) is treated as Pro. Without a controls file nothing is filtered.
export function inEdition(ids: string[], edition: 'free' | 'pro', controls: Controls | null): string[] {
  if (edition === 'pro' || !controls) return ids;
  return ids.filter((id) => controls.byId.get(id)?.edition === 'free');
}

export const notInControls = (ids: Iterable<string>, controls: Controls | null): string[] =>
  controls ? [...ids].filter((id) => !controls.byId.has(id)) : [];
