// The proof sandbox part of report.md: what was proven by a test (with the redacted request and response of the attack and the hashes
// of the three transcripts), what was not proven and why, and what is not provable here. Built from the prove files only. Same files,
// same bytes. A scan folder with no prove folder gets no section, so earlier reports keep their bytes.
import { existsSync } from 'node:fs';
import type { Merged } from '../confirm/merge.ts';
import type { ProveResult, RunRecord, StepRecord } from '../types/index.ts';
import { proveDir, readProveResult, readRuns } from '../prove/store.ts';

export interface ProveFiles { result: ProveResult | null; first: Record<string, RunRecord> }

export function loadProveFiles(scanDir: string): ProveFiles {
  const dir = proveDir(scanDir);
  if (!existsSync(dir)) return { result: null, first: {} };
  const result = readProveResult(dir);
  const first: Record<string, RunRecord> = {};
  for (const s of result?.specs ?? []) if (s.outcome === 'proven') { const r = readRuns(dir, s.spec_id)[0]; if (r) first[s.spec_id] = r; }
  return { result, first };
}

const cell = (s: string): string => s.replace(/\|/g, '\\|').replace(/\s+/g, ' ');
const loc = (e: { file: string; line: number }): string => `\`${e.file}:${e.line}\``;
const clip = (s: string, n: number): string => (s.length <= n ? s : s.slice(0, n - 1) + '…');
const body = (r: NonNullable<StepRecord['response']>): string => clip(r.json !== undefined ? JSON.stringify(r.json) : (r.text ?? ''), 240);

export function renderProve(f: ProveFiles | undefined, merged: Merged | null): string[] {
  const r = f?.result;
  if (!f || !r) return [];
  const out: string[] = [];
  const p = (...l: string[]): void => { out.push(...l); };
  const c = r.counts;
  p('## Proof sandbox: findings proven by a test', '');
  p('A test written as data ran against a copy of the app inside a sandbox with no network, no secrets and no access to your files. A flaw counts as proven only when the positive control passed and the attack got through in 3 of 3 runs. Anything less stays a lead with its reason, and a lead never holds or releases the gate.', '');
  p(`1. Runner: ${r.runner}${r.runner === 'container' ? '' : ' (no isolation, for the engine\'s own fixtures only)'}. Specs: ${c.specs}. Proven: ${c.proven}. Not proven: ${c.not_proven}. Invalid: ${c.invalid}. Unstable: ${c.unstable}. Error: ${c.error}. Not provable here: ${c.not_provable}. Spec files dropped: ${c.dropped}.`);
  p(`2. Left behind after teardown: ${r.left_behind}. Left out of the copy that went into the sandbox: ${r.copy_excluded.length} item(s) such as environment files and keys.`, '');
  if (r.not_provable) p(`Not provable here (${r.not_provable.code}): ${r.not_provable.reason}`, '');
  const gate = new Set((merged?.inGate ?? []).map((l) => l.key));
  const provenSpecs = r.specs.filter((s) => s.outcome === 'proven');
  if (provenSpecs.length) {
    p('### Proven findings', '');
    provenSpecs.forEach((s, i) => {
      const key = s.lead_key ?? `spec:${s.spec_id}`;
      p(`#### P-${i + 1} ${s.claim}`, '');
      p(`Where: ${loc(s.sink)}. Requirements: ${s.requirement_ids.join(', ') || 'none named'}. Test: ${s.title} (${s.spec_id}).`);
      p(`Evidence: ${s.runs.length} of ${r.runs_required} runs proven. Transcript hashes: ${s.runs.map((x) => `run ${x.run} ${x.transcript_sha256.slice(0, 16)}`).join(', ')}. Files: \`prove/runs/${s.spec_id}/run-1.json\` to \`run-${r.runs_required}.json\`.`);
      const rec = f.first[s.spec_id];
      const attack = rec?.steps.filter((x) => x.phase === 'attack') ?? [];
      for (const st of attack) if (st.response) p(`Attack step ${st.id}: ${st.actor} sent ${st.request.method} ${st.request.path} and got ${st.response.status} ${body(st.response)}`);
      p(gate.has(key) ? 'Counts in the gate: yes, as a fail record with machine evidence (kind test).' : 'Counts in the gate: no, none of its requirements is in this run\'s scope (or it names none).', '');
    });
  }
  const rest = r.specs.filter((s) => s.outcome !== 'proven');
  if (rest.length) {
    p('### Not proven', '', 'These stay leads. None of them can hold or release the gate.', '', '| Spec | Where | Result | Why |', '|---|---|---|---|');
    for (const s of rest) p(`| ${cell(s.spec_id)} | ${loc(s.sink)} | ${s.outcome.replace('_', ' ')} | ${cell(s.reason)} |`);
    p('');
  }
  if (r.dropped.length) {
    p('### Spec files dropped', '', ...r.dropped.map((d) => `- ${d.file}: ${d.reason}`), '');
  }
  return out;
}
