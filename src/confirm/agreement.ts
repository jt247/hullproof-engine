// Multi run agreement. A lead's identity is its entry point, its requirement and its cited sink. The number of runs that raised a
// lead only orders the list. Nothing here confirms anything.
import type { Lead } from '../types/index.ts';
import { cmp } from '../util.ts';

export const sinkOf = (l: Lead): { file: string; line: number } => { const s = l.path[l.path.length - 1]; return { file: s.file, line: s.line }; };
export const leadKey = (l: Lead): string => { const s = sinkOf(l); return `${l.entry_point}\u0000${l.requirement_ids.join('+')}\u0000${s.file}:${s.line}`; };
export const readableKey = (k: string): string => k.split('\u0000').join(' | ');

export interface Group { key: string; leads: { run: number; lead: Lead }[]; runs: number[] }

// Groups leads by identity. Within a group the leads are in run order, then lead_id order, so the first proposal tried is stable.
export function groupLeads(raised: { run: number; lead: Lead }[]): Group[] {
  const by = new Map<string, { run: number; lead: Lead }[]>();
  for (const r of raised) { const k = leadKey(r.lead); by.set(k, [...(by.get(k) ?? []), r]); }
  return [...by.entries()].map(([key, leads]) => {
    leads.sort((a, b) => a.run - b.run || cmp(a.lead.lead_id, b.lead.lead_id));
    return { key, leads, runs: [...new Set(leads.map((l) => l.run))] };
  });
}

// Most runs first, then by key. A pure ordering: no group is added or dropped.
export const byAgreement = <T extends { runs: number[]; key: string }>(xs: T[]): T[] => xs.slice().sort((a, b) => b.runs.length - a.runs.length || cmp(a.key, b.key));
