// The hunt part of report.md: confirmed findings with their evidence, leads, incomplete hunts and the hallucination count.
// Built from the hunt files only. Same files, same bytes.
import type { HuntResult, HuntSynthesis, LeadOut } from '../types/index.ts';
import type { Merged } from '../confirm/merge.ts';
import { readableKey } from '../confirm/agreement.ts';
import { cmp } from '../util.ts';

export interface HuntFiles { result: HuntResult | null; synthesis: HuntSynthesis | null; skipped: string | null }
const loc = (e: { file: string; line: number }): string => `\`${e.file}:${e.line}\``;
const METHOD: Record<string, string> = { map_query: 'a query over the code map', semgrep_rule: 'a generated Semgrep rule and a negative control', sandbox_test: 'a test run in a local sandbox, 3 of 3 runs' };

export function renderHunt(h: HuntFiles, merged: Merged | null): string[] {
  const out: string[] = [];
  const p = (...l: string[]): void => { out.push(...l); };
  if (!h.result) {
    if (h.skipped) p('## Hunt', '', `Hunt: not run, ${h.skipped}.`, '');
    return out;
  }
  const r = h.result;
  const syn = new Map((h.synthesis?.explanations ?? []).map((e) => [e.key, e.text]));
  const gateSet = new Set((merged?.inGate ?? []).map((c) => c.key));
  const provenSet = new Set((merged?.proven ?? []).map((c) => c.key));
  p('## Hunt: leads and confirmed findings', '');
  p('A model proposed these and the engine checked them. Only a lead that the engine confirmed with evidence a machine can re run is a finding. Every other lead is listed for a person to read and can never hold or release the gate. The number of runs that raised a lead only orders the list.', '');
  p(`1. Runs: ${r.runs}. Entry points hunted: ${r.entries_hunted}. Calls: ${r.calls.complete} complete, ${r.calls.incomplete} incomplete, ${r.calls.missing} never saved.`);
  p(`2. Confirmed findings: ${r.confirmed.length}. Leads not confirmed: ${r.leads.length}.`);
  p(`3. Hallucinations (leads that cited code that is not there, dropped): ${r.hallucinations.count}. Malformed leads (dropped): ${r.malformed.count}.`);
  p(`4. Tokens used, reported and not limited: ${r.usage.input_tokens} in, ${r.usage.output_tokens} out, over ${r.usage.calls} calls.`, '');
  if (h.synthesis) {
    p('### Summary of all runs', '');
    p(h.synthesis.status === 'complete' ? (h.synthesis.summary || 'The synthesis step returned no summary.') : `The synthesis step did not finish (${h.synthesis.stop ?? 'stopped'}). It only explains, so no finding is affected.`, '');
  }
  const conf = (c: LeadOut, i: number): void => {
    const e = c.confirmation;
    p(`#### H-${i + 1} ${c.claim}${c.claim_truncated ? ' (claim shortened to the limit)' : ''}`, '');
    p(`Where: ${c.path.map(loc).join(' to ')}. Requirements: ${c.requirement_ids.join(', ') || 'none named'}. Raised in ${c.runs_raised} of ${r.runs} runs.`);
    if (e.status === 'confirmed') p(`Evidence: confirmed by ${METHOD[e.method]} (${e.tool} ${e.tool_version}, ${e.rule_id}). ${e.detail}.`);
    if (provenSet.has(c.key)) p('Proven by a test in the sandbox: yes, see the proof sandbox section.');
    p(gateSet.has(c.key) ? 'Counts in the gate: yes, as a fail record with machine evidence.' : 'Counts in the gate: no, none of its requirements is in this run\'s scope (or it names none).');
    if (syn.has(c.key)) p(`Explanation: ${syn.get(c.key)}`);
    p('');
  };
  if (r.confirmed.length) { p('### Confirmed findings', ''); r.confirmed.forEach(conf); }
  if (r.leads.length) {
    p('### Leads (not confirmed, never in the gate)', '');
    p('| Raised in | Where | Requirements | Claim | Why not confirmed |', '|---|---|---|---|---|');
    for (const l of r.leads) {
      const why = provenSet.has(l.key) ? 'proven by a test in the sandbox, see the proof sandbox section' : l.confirmation.status === 'confirmed' ? '' : l.confirmation.detail;
      p(`| ${l.runs_raised} of ${r.runs} runs | ${loc(l.sink)} | ${l.requirement_ids.join(', ') || 'none named'} | ${l.claim_truncated ? '(claim shortened) ' : ''}${l.claim.replace(/\|/g, '\\|')}${syn.has(l.key) ? ' Explanation: ' + syn.get(l.key)!.replace(/\|/g, '\\|') : ''} | ${why.replace(/\|/g, '\\|')} |`);
    }
    p('');
  }
  if (r.incomplete.length) {
    p('### Incomplete hunts', '', 'These calls did not finish. A provider stop (a refusal, a safety stop, a rate limit, a timeout) is recorded and never retried around, so the entry point below was not fully hunted in that run.', '');
    p('| Run | Entry point | Why |', '|---|---|---|');
    for (const i of r.incomplete.slice().sort((a, b) => a.run - b.run || cmp(a.entry_id, b.entry_id))) p(`| ${i.run} | ${i.entry_id.replace(/\|/g, '\\|')} | ${i.stop}${i.detail ? ': ' + i.detail.replace(/\|/g, '\\|') : ''} |`);
    p('');
  }
  if (r.hallucinations.count) {
    p('### Dropped as hallucinations', '');
    for (const x of r.hallucinations.items.slice(0, 30)) p(`- Run ${x.run}, ${readableKey(x.entry_id)}: ${x.reason}.`);
    if (r.hallucinations.count > 30) p(`- and ${r.hallucinations.count - 30} more (all are in hunt/result.json).`);
    p('');
  }
  if (merged?.outOfScope.length) p(`${merged.outOfScope.length} confirmed finding(s) name no requirement in this run's scope, so they are shown above and are not in the gate.`, '');
  return out;
}
