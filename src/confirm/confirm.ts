// The confirmation engine. From the saved answers of a hunt, the repository and the code map it decides, with no model and no
// clock, which leads are confirmed findings and which stay leads. The same inputs give the same result.json byte for byte.
// The result holds nothing a model wrote except the claim and the notes, which are plain text and never decide anything.
import { createHash } from 'node:crypto';
import type { CodeMap, Confirmation, HuntAnswer, HuntPlan, HuntResult, Lead, LeadOut } from '../types/index.ts';
import { cmp } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import { byAgreement, groupLeads, sinkOf, type Group } from './agreement.ts';
import { unknownProtections } from './chain.ts';
import { checkLead, FileCache } from './honesty.ts';
import { parseOutput } from './lead.ts';
import { runQuery } from './query.ts';
import { confirmRule, spawnSemgrep, type SemgrepRunner } from './rule.ts';

export interface ConfirmInput {
  repo: string; map: CodeMap; answers: HuntAnswer[]; plan: HuntPlan | null; commit: string | null; semgrep?: SemgrepRunner;
}

function tryGroup(g: Group, input: ConfirmInput, files: FileCache): Confirmation {
  let last: Confirmation = { status: 'not_confirmed', method: 'none', detail: 'the lead proposed no evidence the engine can check' };
  for (const { run, lead } of g.leads) {
    const p = lead.evidence_proposal;
    if (p.kind === 'map_query') {
      const o = runQuery(input.map, p.query, lead.entry_point, lead.path);
      if (o.confirmed) {
        // The map cannot vouch for a claim about input, ownership or protection when the route chain holds a helper it does not know.
        const ep = input.map.entry_points.find((e) => e.id === lead.entry_point);
        const unknown = ep ? unknownProtections(ep, input.map, files) : [];
        if (unknown.length) {
          last = { status: 'not_confirmed', method: 'map_query', reason: 'unknown_protection', helpers: unknown, detail: `unknown_protection: the route chain holds ${unknown.join(', ')}, which the code map does not recognise, so the map cannot say this claim is true` };
          continue;
        }
        const cfg = createHash('sha256').update(JSON.stringify(p.query)).digest('hex');
        return { status: 'confirmed', method: 'map_query', run, detail: o.detail, tool: 'hullproof-hunt', rule_id: `hunt.query.${cfg.slice(0, 12)}`, tool_version: ENGINE_VERSION, config_sha256: cfg };
      }
      last = { status: 'not_confirmed', method: 'map_query', detail: o.detail };
    } else if (p.kind === 'semgrep_rule') {
      const o = confirmRule(lead, input.repo, input.semgrep ?? spawnSemgrep);
      if (o.status === 'confirmed') return { status: 'confirmed', method: 'semgrep_rule', run, detail: o.detail, tool: 'semgrep', rule_id: o.rule_id, tool_version: o.tool_version, config_sha256: o.config_sha256 };
      last = o.status === 'not_run' ? { status: 'not_run', method: 'semgrep_rule', detail: o.detail } : { status: 'not_confirmed', method: 'semgrep_rule', detail: o.detail };
    } else if (p.kind === 'generated_test') {
      if (last.status === 'not_confirmed' && last.method === 'none') last = { status: 'not_confirmed', method: 'generated_test', detail: 'a generated test has to be written and run with hullproof prove; until it proves the flaw 3 of 3 the lead stays a lead' };
    } else if (p.kind === 'none' && p.rejected && last.status === 'not_confirmed' && last.method === 'none') {
      last = { status: 'not_confirmed', method: 'none', detail: `the proposal was not usable: ${p.rejected}` };
    }
  }
  return last;
}

export function confirmHunt(input: ConfirmInput): HuntResult {
  const files = new FileCache(input.repo);
  const incomplete: HuntResult['incomplete'] = [];
  const malformed: HuntResult['malformed']['items'] = [];
  const hallucinations: HuntResult['hallucinations']['items'] = [];
  const raised: { run: number; lead: Lead }[] = [];
  const usage = { calls: 0, input_tokens: 0, output_tokens: 0 };
  const seen = new Set<string>();
  let complete = 0;

  for (const a of input.answers) {
    seen.add(`${a.run}\u0000${a.entry_id}`);
    usage.calls++; usage.input_tokens += a.usage.input_tokens; usage.output_tokens += a.usage.output_tokens;
    if (a.status !== 'complete') { incomplete.push({ entry_id: a.entry_id, run: a.run, stop: a.stop ?? 'unknown', detail: a.detail ?? '' }); continue; }
    complete++;
    const p = parseOutput(a.output, a.entry_id);
    for (const m of p.malformed) malformed.push({ run: a.run, entry_id: a.entry_id, lead_id: m.lead_id, reason: m.reason });
    for (const lead of p.leads) {
      const h = checkLead(lead, files, input.map);
      if (h.ok) raised.push({ run: a.run, lead });
      else hallucinations.push({ run: a.run, entry_id: a.entry_id, lead_id: lead.lead_id, reason: h.reason });
    }
  }
  // Calls that were planned and never saved: the run was interrupted or not finished.
  let missing = 0;
  if (input.plan) {
    for (let r = 1; r <= input.plan.runs; r++) {
      for (const e of input.plan.entries) {
        if (seen.has(`${r}\u0000${e}`)) continue;
        missing++;
        incomplete.push({ entry_id: e, run: r, stop: 'not_run', detail: 'no answer was saved for this call' });
      }
    }
  }

  const out = (g: Group, c: Confirmation): LeadOut => {
    const first = g.leads[0].lead;
    return { key: g.key, ...(first.claim_truncated ? { claim_truncated: true as const } : {}), entry_point: first.entry_point, requirement_ids: first.requirement_ids, claim: first.claim, path: first.path, sink: sinkOf(first), runs_raised: g.runs.length, runs: g.runs, confirmation: c };
  };
  const groups = byAgreement(groupLeads(raised));
  const confirmed: LeadOut[] = [];
  const leads: LeadOut[] = [];
  for (const g of groups) {
    const c = tryGroup(g, input, files);
    (c.status === 'confirmed' ? confirmed : leads).push(out(g, c));
  }
  const by = (a: { entry_id: string; run: number }, b: { entry_id: string; run: number }): number => a.run - b.run || cmp(a.entry_id, b.entry_id);
  return {
    schema_version: '1.0.0', engine_version: ENGINE_VERSION, commit: input.commit,
    runs: Math.max(input.plan?.runs ?? 0, ...input.answers.map((a) => a.run), 0),
    entries_hunted: new Set(input.answers.map((a) => a.entry_id)).size,
    calls: { complete, incomplete: input.answers.length - complete, missing },
    incomplete: incomplete.sort(by),
    malformed: { count: malformed.length, items: malformed.sort((a, b) => a.run - b.run || cmp(a.entry_id, b.entry_id) || cmp(a.lead_id, b.lead_id)) },
    hallucinations: { count: hallucinations.length, items: hallucinations.sort((a, b) => a.run - b.run || cmp(a.entry_id, b.entry_id) || cmp(a.lead_id, b.lead_id)) },
    confirmed, leads, usage,
  };
}
