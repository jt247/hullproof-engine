// The lead schema: what a model returns for one entry point, checked against the limits below. A lead that breaks a limit is
// malformed and is counted apart from a hallucination (a lead whose cited code is not there, see honesty.ts).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { EvidenceProposal, Lead } from '../types/index.ts';
import { parseQuery } from './query.ts';

export const LIMITS = { leadId: 80, claim: 500, note: 200, path: 12, requirements: 6, quote: 2000, leadsPerAnswer: 10, ruleYaml: 8000, controlCode: 20000, queryJson: 6000, minQuote: 8 } as const;
export const CONTROL_EXTENSIONS = ['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'go', 'rb', 'php', 'java'] as const;
// The schema handed to a provider as the structured output shape.
export const MODEL_OUTPUT_SCHEMA = JSON.parse(readFileSync(fileURLToPath(new URL('../../schemas/hunt-output.schema.json', import.meta.url)), 'utf8')) as Record<string, unknown>;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const SEC = /^SEC-[A-Z]+-\d{3}$/;
// One line of plain text: control characters removed, spaces collapsed, clipped.
export const plain = (s: string, max: number): string => {
  const t = s.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length <= max ? t : t.slice(0, max - 1).trimEnd() + '…';
};

function proposal(p: unknown): EvidenceProposal {
  if (!isObj(p) || typeof p.kind !== 'string') return { kind: 'none', rejected: 'no evidence proposal' };
  if (p.kind === 'generated_test') return { kind: 'generated_test' };
  if (p.kind === 'none') return { kind: 'none' };
  if (p.kind === 'map_query') {
    if (typeof p.query_json !== 'string' || !p.query_json.trim()) return { kind: 'none', rejected: 'map_query without query_json' };
    if (p.query_json.length > LIMITS.queryJson) return { kind: 'none', rejected: 'query_json is too long' };
    let v: unknown;
    try { v = JSON.parse(p.query_json); } catch { return { kind: 'none', rejected: 'query_json is not JSON' }; }
    const q = parseQuery(v);
    return q.ok ? { kind: 'map_query', query: q.query } : { kind: 'none', rejected: `query: ${q.reason}` };
  }
  if (p.kind === 'semgrep_rule') {
    const { rule_yaml: r, control_code: c, control_extension: e } = p;
    if (typeof r !== 'string' || !r.trim() || r.length > LIMITS.ruleYaml) return { kind: 'none', rejected: 'rule_yaml is missing or too long' };
    if (typeof c !== 'string' || !c.trim() || c.length > LIMITS.controlCode) return { kind: 'none', rejected: 'a rule needs control_code (the safe sample)' };
    const ext = typeof e === 'string' ? e.replace(/^\./, '') : '';
    if (!(CONTROL_EXTENSIONS as readonly string[]).includes(ext)) return { kind: 'none', rejected: 'control_extension is not one of the allowed extensions' };
    return { kind: 'semgrep_rule', rule_yaml: r, control_code: c, control_extension: ext };
  }
  return { kind: 'none', rejected: `unknown proposal kind` };
}

export interface Malformed { lead_id: string; reason: string }

// The leads of one saved output, for the entry point that was hunted. A lead that names another entry point is malformed.
export function parseOutput(raw: unknown, entryId: string): { leads: Lead[]; malformed: Malformed[] } {
  if (!isObj(raw) || !Array.isArray(raw.leads)) return { leads: [], malformed: [{ lead_id: '', reason: 'the output has no leads list' }] };
  const leads: Lead[] = [];
  const malformed: Malformed[] = [];
  raw.leads.forEach((x, i) => {
    const id = isObj(x) && typeof x.lead_id === 'string' ? plain(x.lead_id, LIMITS.leadId) : `#${i + 1}`;
    const bad = (reason: string): void => { malformed.push({ lead_id: id, reason }); };
    if (i >= LIMITS.leadsPerAnswer) return bad(`more than ${LIMITS.leadsPerAnswer} leads in one answer`);
    if (!isObj(x)) return bad('a lead must be an object');
    if (typeof x.lead_id !== 'string' || !x.lead_id.trim() || x.lead_id.length > LIMITS.leadId) return bad('lead_id is missing or too long');
    if (x.entry_point !== entryId) return bad('entry_point is not the entry point that was hunted');
    // An empty list is allowed: the lead names no requirement. It can still be confirmed, and then it is reported and stays out of the gate (merge.ts).
    if (!Array.isArray(x.requirement_ids) || x.requirement_ids.length > LIMITS.requirements || !x.requirement_ids.every((r) => typeof r === 'string' && SEC.test(r))) return bad('requirement_ids needs at most 6 ids written like SEC, an area and three digits');
    if (typeof x.claim !== 'string' || !x.claim.trim()) return bad('claim is missing');
    if (!Array.isArray(x.path) || x.path.length === 0 || x.path.length > LIMITS.path) return bad('path needs 1 to 12 steps');
    const path = [];
    for (const s of x.path) {
      if (!isObj(s) || typeof s.file !== 'string' || !s.file || !Number.isInteger(s.line) || (s.line as number) < 1 || typeof s.note !== 'string') return bad('a path step needs file, line and note');
      path.push({ file: s.file, line: s.line as number, note: plain(s.note, LIMITS.note) });
    }
    if (typeof x.quoted_code !== 'string' || x.quoted_code.length > LIMITS.quote) return bad('quoted_code is missing or too long');
    leads.push({
      lead_id: plain(x.lead_id, LIMITS.leadId), entry_point: entryId, requirement_ids: [...new Set(x.requirement_ids as string[])].sort(),
      claim: plain(x.claim, LIMITS.claim), path, quoted_code: x.quoted_code, evidence_proposal: proposal(x.evidence_proposal),
      // A claim over the limit is shortened and marked, not dropped. The mark is only written when true, so older results keep their bytes.
      ...(plain(x.claim, Infinity).length > LIMITS.claim ? { claim_truncated: true as const } : {}),
    });
  });
  return { leads, malformed };
}
