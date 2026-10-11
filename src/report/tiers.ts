// Rule confidence tiers (rules/tiers.json). A Semgrep rule is "gate" or "lead". A gate rule's hit fails its requirements
// as before. A lead rule's hit is listed in the report as a lead and never fails a requirement or holds the gate.
// The tier comes from measurement: a rule whose measured precision is below the threshold in the file is a lead until a
// later measurement raises it. A rule not in the file keeps a default: engine taint rules (taint-*.yaml, rule ids
// hullproof-taint-*) are leads, every other rule is gate, which is how the kit rules with fixtures behaved before tiers.
// Gitleaks hits, Semgrep rules mapped to a SEC-SECRETS ID, engine checks, Trivy and OSV are always gate.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Hit } from '../types/index.ts';

export interface TierEntry { tier: 'gate' | 'lead'; precision: number | null; judged: number; evidence: string; date: string | null }
export interface TierFile { threshold: number; min_judged: number; rules: Record<string, TierEntry> }

// The tier file sits next to each Semgrep rule folder (rules/tiers.json, and a tier file next to a rule pack). Later folders (the rule
// pack) win for the same rule id; the threshold and minimum come from the first file found.
const DEFAULT: TierFile = { threshold: 0.8, min_judged: 3, rules: {} };
export function loadTiers(semgrepDirs: string[]): TierFile {
  const files = semgrepDirs.map((d) => join(dirname(d), 'tiers.json')).filter((p) => existsSync(p)).map((p) => JSON.parse(readFileSync(p, 'utf8')) as TierFile);
  if (!files.length) return DEFAULT;
  return { threshold: files[0].threshold, min_judged: files[0].min_judged, rules: Object.assign({}, ...files.map((f) => f.rules)) };
}

// A hit that is about a secret: a live key is a leak wherever it is committed, so it always holds the gate.
export const isSecretHit = (h: Hit): boolean => h.tool === 'gitleaks' || h.sec_ids.some((id) => id.startsWith('SEC-SECRETS-'));

// The tier entry for a hit, or null when the hit is gate.
export function leadTier(h: Hit, t: TierFile): TierEntry | null {
  if (h.tool !== 'semgrep' || isSecretHit(h)) return null;
  const e = t.rules[h.rule_id] ?? (h.rule_id.startsWith('hullproof-taint-')
    ? { tier: 'lead' as const, precision: null, judged: 0, evidence: 'not measured yet', date: null } : null);
  return e && e.tier === 'lead' ? e : null;
}

// Plain English reason for a lead record.
export function leadReason(e: TierEntry, t: TierFile): string {
  if (e.precision === null || e.judged === 0) return 'this rule has not been measured yet';
  const m = `precision ${e.precision.toFixed(2)} on ${e.judged} judged hits (${e.evidence}, ${e.date})`;
  return e.judged < t.min_judged ? `${m}, fewer than the ${t.min_judged} needed to change its default` : `${m}, below ${t.threshold.toFixed(2)}`;
}
