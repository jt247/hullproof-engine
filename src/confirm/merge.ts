// Puts confirmed hunt findings, and findings proven by a test in the sandbox, into the rows and the findings record that the report and
// the gate read. Only the `confirmed` list of the hunt result and the specs the prove result marks `proven` (3 of 3 runs) are read. Leads (the `leads` list), their claims, their agreement counts and the synthesis never reach this code, so
// no lead can change a row, a record or the verdict. A confirmed finding becomes a fail record with machine_evidence, as findings
// schema 1.1.0 asks, and makes its requirement a FAIL row.
import { createHash } from 'node:crypto';
import type { FailRecord, FindingRecord, FindingsFile, HuntResult, LeadOut, ProveResult, ProveSpecResult, ResultRow, TraceStep } from '../types/index.ts';
import { cmp } from '../util.ts';
import { findingsJson, findingsMarkdown } from '../report/build.ts';
import { highest, inScope, type Kit, type Scope } from '../report/kit.ts';
import type { ScanFolder } from '../report/load.ts';

const clip = (s: string, n: number): string => (s.length <= n ? s : s.slice(0, n - 1).trimEnd() + '…');
const fpPath = (f: string): string => f.replace(/[\s:]/g, '_');
const slug = (s: string, max = 12): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').split('-').filter(Boolean).slice(0, max).join('-') || 'x';
const METHOD = { map_query: 'a query over the code map', semgrep_rule: 'a generated Semgrep rule with a negative control', sandbox_test: 'a test run in a local sandbox, 3 of 3 runs, with the transcripts kept' } as const;

// A spec the sandbox proved, as a confirmed finding. When it tests a hunt lead, the lead's own path and requirements are kept and the
// test replaces the weaker evidence: a test that fails the way the lead claims, 3 of 3 times, is the strongest confirmation there is.
function provenLead(sp: ProveSpecResult, p: ProveResult, base: LeadOut | undefined): LeadOut {
  const conf: LeadOut['confirmation'] = {
    status: 'confirmed', method: 'sandbox_test', run: p.runs_required, tool: 'hullproof-prove', rule_id: `prove.test.${sp.spec_sha256.slice(0, 12)}`,
    tool_version: p.engine_version, config_sha256: sp.spec_sha256,
    detail: `spec ${sp.spec_id} passed its positive control and showed the flaw in ${sp.runs.length} of ${p.runs_required} runs (transcripts ${sp.runs.map((r) => r.transcript_sha256.slice(0, 12)).join(', ')})`,
  };
  if (base) return { ...base, confirmation: conf };
  return { key: sp.lead_key ?? `spec:${sp.spec_id}`, entry_point: sp.entry_point, requirement_ids: sp.requirement_ids, claim: sp.claim, path: [{ file: sp.sink.file, line: sp.sink.line, note: `proven by test ${sp.spec_id}` }], sink: sp.sink, runs_raised: 0, runs: [], confirmation: conf };
}

export interface Merged { results: ResultRow[]; findings: FindingsFile; findingsText: string; inGate: LeadOut[]; outOfScope: LeadOut[]; proven: LeadOut[] }

// A lead that names no requirement can borrow the requirements of the engine's own map checks that flagged the same entry point (a FAIL in the
// same file). It only borrows when the scan folder carries the checks and the code map; the finding says so.
function borrowed(s: Partial<Pick<ScanFolder, 'checks' | 'codemap'>>, entryPoint: string): { ids: string[]; checks: string[] } {
  const e = s.codemap?.entry_points.find((x) => x.id === entryPoint);
  if (!e || !s.checks) return { ids: [], checks: [] };
  const hit = s.checks.results.filter((r) => r.result === 'FAIL' && r.check_id.startsWith('check.map.') && r.evidence.some((ev) => ev.file === e.file));
  return { ids: [...new Set(hit.flatMap((r) => r.sec_ids))].sort(cmp), checks: hit.map((r) => r.check_id).sort(cmp) };
}

export function mergeHunt(s: Pick<ScanFolder, 'results' | 'findings' | 'info'> & Partial<Pick<ScanFolder, 'checks' | 'codemap'>>, kit: Kit, hunt: HuntResult | null, prove: ProveResult | null = null): Merged {
  const scope: Scope = { edition: s.info.edition, stage: s.info.stage, stageSource: s.info.stage_source };
  const rows = new Map(s.results.map((r) => [r.id, r]));
  const records: FindingRecord[] = [...s.findings.records];
  const tails = new Set(records.filter((r) => r.kind === 'fail').map((r) => r.fingerprint.slice(r.fingerprint.indexOf(':') + 1)));
  const inGate: LeadOut[] = [];
  const outOfScope: LeadOut[] = [];

  const byKey = new Map([...(hunt?.confirmed ?? []), ...(hunt?.leads ?? [])].map((l) => [l.key, l]));
  const proven = (prove?.specs ?? []).filter((x) => x.outcome === 'proven' && x.runs.length >= prove!.runs_required && x.runs.every((r) => r.outcome === 'proven')).map((x) => provenLead(x, prove!, x.lead_key ? byKey.get(x.lead_key) : undefined));
  const provenKeys = new Set(proven.map((l) => l.key));
  const confirmed = [...(hunt?.confirmed ?? []).filter((l) => !provenKeys.has(l.key)), ...proven];
  for (const c of confirmed) {
    if (c.confirmation.status !== 'confirmed') continue;
    const lend = c.requirement_ids.length ? { ids: [], checks: [] as string[] } : borrowed(s, c.entry_point);
    const ids = (c.requirement_ids.length ? c.requirement_ids : lend.ids).filter((id) => { const k = kit.byId.get(id); return !!k && inScope(k, scope); }).sort(cmp);
    if (!ids.length) { outOfScope.push(c); continue; }
    const ev = c.confirmation;
    const first = kit.byId.get(ids[0])!;
    let tail = `${fpPath(c.sink.file)}:${slug(`${ev.method === 'sandbox_test' ? 'proven' : 'hunt'} ${c.entry_point} ${c.sink.line}`)}`;
    if (tails.has(tail)) tail = `${tail}-${createHash('sha256').update(c.key).digest('hex').slice(0, 6).replace(/[^a-z0-9]/g, 'a')}`;
    tails.add(tail);
    const trace: TraceStep[] = c.path.map((p, i) => ({ kind: i === c.path.length - 1 ? 'sink' : i === 0 ? 'entrypoint' : 'handoff', file: p.file, line: p.line, note: clip(p.note || 'step', 300) }));
    const rec: FailRecord = {
      fingerprint: `${ids[0]}:${tail}`, kind: 'fail', sec_ids: ids, title: clip(`${ev.method === 'sandbox_test' ? 'Proven by test' : 'Confirmed lead'}: ${c.claim}`, 160), class: 'finding', gap_in_standard: false,
      severity: highest(ids.map((id) => kit.byId.get(id)!.severity)), confidence: 'SUSPECTED', demonstrated: false,
      root_cause: clip(c.claim, 120), raised_by: [ev.method === 'sandbox_test' ? 'hullproof-prove' : 'hullproof-hunt'],
      impact_statement: clip(`${c.claim} ${ev.method === 'sandbox_test' ? 'The engine proved it with' : 'A model proposed this and the engine confirmed it with'} ${METHOD[ev.method]}: ${ev.detail}.${lend.checks.length && ids.length ? ` The lead named no requirement, so the requirement is taken from ${lend.checks.join(', ')}, which flagged this entry point.` : ''}`, 600),
      remediation: { strategy: clip(`Fix the code at ${c.sink.file}:${c.sink.line} so it meets ${ids.join(', ')}: ${first.title}.`, 800), confirm: ev.method === 'sandbox_test' ? 'Run hullproof prove again after the fix, then hullproof report. The finding is gone when the test no longer shows the flaw. Test the fixed request by hand as well.' : 'Run hullproof hunt with --replay and then hullproof report again. The finding is gone when the lead no longer confirms. Test the fixed request by hand as well.' },
      evidence: c.path.slice(0, 8).map((p) => ({ file: p.file, line: p.line, note: clip(p.note || 'step', 300) })),
      trace: trace.slice(0, 12),
      machine_evidence: { tool: ev.tool, rule_id: ev.rule_id, tool_version: ev.tool_version, config_sha256: ev.config_sha256 },
    };
    records.push(rec);
    inGate.push(c);
    for (const id of ids) {
      const old = rows.get(id);
      if (old?.result === 'FAIL') continue;
      rows.set(id, { id, result: 'FAIL', notes: clip(`Failed by ${ev.method === 'sandbox_test' ? 'a finding proven by test' : 'hunt lead confirmed by'} ${ev.rule_id} at ${c.sink.file}:${c.sink.line}.`, 600) });
    }
  }
  records.sort((a, b) => cmp(a.fingerprint, b.fingerprint));
  // A BLOCKER or CRITICAL record needs a verifier outcome in a complete run. No verifier ran, so such a run is recorded the way the
  // scan records it: incomplete, reason deterministic_only, with the agent calls of the kit's own audit at 0. The model calls of the
  // hunt are counted in hunt/result.json, not here.
  const needsVerifier = records.some((r) => r.kind === 'fail' && r.sec_ids.some((id) => { const v = kit.byId.get(id)?.severity; return v === 'BLOCKER' || v === 'CRITICAL'; }));
  const report = needsVerifier && s.findings.report.run_status === 'complete' ? { ...s.findings.report, run_status: 'incomplete' as const, incomplete_reason: 'deterministic_only' as const } : s.findings.report;
  const findings: FindingsFile = { ...s.findings, report, records };
  return { results: [...rows.values()].sort((a, b) => cmp(a.id, b.id)), findings, findingsText: findingsMarkdown(findings, findingsJson(findings)), inGate, outOfScope, proven };
}
