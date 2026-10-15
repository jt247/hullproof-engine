// The guard around the synthesis step. The synthesis call may explain the findings and leads that are already in result.json. It
// cannot add one, remove one or change one: this function keeps only a summary and one explanation per known key, and nothing
// else from the model's reply reaches any file the gate reads.
import type { HuntResult, HuntSynthesis } from '../types/index.ts';
import { cmp } from '../util.ts';
import { plain } from './lead.ts';

export const SYNTHESIS_LIMITS = { summary: 4000, explanation: 800, explanations: 60 } as const;

export function guardSynthesis(result: HuntResult, reply: unknown, meta: { provider: string; model: string; usage: { input_tokens: number; output_tokens: number } }): HuntSynthesis {
  const known = new Set([...result.confirmed, ...result.leads].map((l) => l.key));
  const o = reply && typeof reply === 'object' && !Array.isArray(reply) ? (reply as Record<string, unknown>) : {};
  const summary = typeof o.summary === 'string' ? plain(o.summary, SYNTHESIS_LIMITS.summary) : '';
  const seen = new Set<string>();
  const explanations: HuntSynthesis['explanations'] = [];
  if (Array.isArray(o.explanations)) {
    for (const x of o.explanations) {
      if (!x || typeof x !== 'object') continue;
      const { key, text } = x as { key?: unknown; text?: unknown };
      if (typeof key !== 'string' || typeof text !== 'string' || !known.has(key) || seen.has(key) || explanations.length >= SYNTHESIS_LIMITS.explanations) continue;
      seen.add(key);
      explanations.push({ key, text: plain(text, SYNTHESIS_LIMITS.explanation) });
    }
  }
  explanations.sort((a, b) => cmp(a.key, b.key));
  return { schema_version: '1.0.0', status: 'complete', stop: null, detail: null, provider: meta.provider, model: meta.model, summary, explanations, usage: meta.usage };
}

// A saved synthesis is applied again on replay against the result just computed: explanations for keys that no longer exist drop out.
export function reguard(result: HuntResult, s: HuntSynthesis): HuntSynthesis {
  const g = guardSynthesis(result, { summary: s.summary, explanations: s.explanations }, { provider: s.provider, model: s.model, usage: s.usage });
  return { ...g, status: s.status, stop: s.stop, detail: s.detail };
}
