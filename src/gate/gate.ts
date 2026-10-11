// The release gate of STANDARD.md (G-1 to G-8 and the three outcomes), on top of the kit's own checklist gate.
// The checklist part (G-3 to G-5 on the results rows) and the record cross checks are the kit's functions from
// tools/hullproof/ci/hullproof-gate.mjs, imported, not copied. This file adds what the kit gate leaves out: G-1, G-2,
// G-6, G-7, G-8, written risk acceptance within the kit's limits, and the verdict.
// It blocks only on FAIL rows (from FAIL checks and mapped rule hits, never unmapped observations) and on requirements
// nothing settled, exactly as the kit gate counts them.
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { cmp } from '../util.ts';
import type { FindingsFile, ResultRow, Severity, ToolMeta } from '../types/index.ts';
import { GATE_REL, inScope, SEV_RANK, VALIDATOR_REL, type Control, type Scope } from '../report/kit.ts';

export interface KitGate {
  evaluate(controls: unknown[], rows: string[][], scope: string): { counts: Record<string, number>; ok: boolean };
  collapseRows(rows: string[][]): { got: Map<string, { state: string; raw: string; note: string }>; duplicates: number };
  crossChecks(controlMap: Map<string, unknown>, got: Map<string, unknown>, findings: unknown): { problems: string[] };
  isStaticPass(raw: string): boolean;
  validateFindingsText(text: string, o: { controls: Map<string, unknown> }): { c: { errorCount: number; lines(): string[] }; data: FindingsFile | null };
}

export async function loadKitGate(kitDir: string): Promise<KitGate> {
  const g = await import(pathToFileURL(join(kitDir, GATE_REL)).href);
  const v = await import(pathToFileURL(join(kitDir, VALIDATOR_REL)).href);
  return { evaluate: g.evaluate, collapseRows: g.collapseRows, crossChecks: g.crossChecks, isStaticPass: g.isStaticPass, validateFindingsText: v.validateFindingsText };
}

// What the owner supplies for the conditions no file in the repository can settle. Paths are relative to the repository.
export interface OwnerFile {
  audit_report?: string;        // G-2: an audit report in the AUDIT-REPORT format that names this commit
  rollback?: string;            // G-8: where the rollback path for this release is written down
  results?: OwnerRow[];         // rows settled with owner evidence (exports, staging tests); never overrides an engine FAIL
  acceptances?: Acceptance[];   // written risk acceptance, within the limits of STANDARD.md
}
// An owner row may say PASS, which the engine never writes: the owner holds the runtime evidence.
export type OwnerRow = Omit<ResultRow, 'result'> & { result: ResultRow['result'] | 'PASS' };
export interface Acceptance { id: string; owner: string; approver: string; compensating_control: string; effective: string; expires: string }

export interface GateInput {
  kitGate: KitGate; controls: Control[]; scope: Scope; rows: ResultRow[]; findingsText: string; metas: ToolMeta[];
  owner: OwnerFile | null; repo: string; commit: string; today: string;
}

export type Verdict = 'NOT READY' | 'READY WITH ACCEPTED RISK' | 'READY';
export interface Condition { id: string; met: boolean; why: string }
export interface GateOutcome {
  verdict: Verdict; label: string; exit: 0 | 1 | 2; problems: string[]; conditions: Condition[];
  counts: Record<string, number>; open: { id: string; severity: Severity; state: string; accepted: boolean }[];
  acceptancesUsed: string[]; acceptanceProblems: string[]; runSupportsReady: boolean; checklistLine: string;
}

// Hullproof policy (STANDARD.md, Protected classes): no acceptance for credentials and secrets, authentication,
// tenant isolation or payments. The class is read from the control's domains; authorization counts as tenant isolation.
const PROTECTED = new Set(['secrets', 'auth', 'authorization', 'tenancy', 'payments']);
const DAY = 86_400_000;
const days = (a: string, b: string): number => Math.round((Date.parse(b) - Date.parse(a)) / DAY);
const isDate = (s: unknown): s is string => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));

function currentAcceptances(list: Acceptance[], byId: Map<string, Control>, today: string): { ok: Map<string, Acceptance>; problems: string[] } {
  const ok = new Map<string, Acceptance>();
  const problems: string[] = [];
  let critical = 0;
  for (const a of [...list].sort((x, y) => cmp(x.id, y.id))) {
    const c = byId.get(a.id);
    const bad = (why: string): void => { problems.push(`${a.id}: acceptance not current (${why})`); };
    if (!c) { bad('not a requirement in scope'); continue; }
    if (c.severity === 'BLOCKER') { bad('a BLOCKER is never accepted'); continue; }
    if (c.severity !== 'CRITICAL' && c.severity !== 'HIGH') { bad('only CRITICAL and HIGH need acceptance'); continue; }
    if (c.domains.some((d) => PROTECTED.has(d))) { bad('protected class: secrets, authentication, tenant isolation or payments'); continue; }
    if (![a.owner, a.approver, a.compensating_control].every((s) => typeof s === 'string' && s.trim())) { bad('owner, approver and compensating control are all needed'); continue; }
    if (a.owner.trim().toLowerCase() === a.approver.trim().toLowerCase()) { bad('the approver must not be the risk owner'); continue; }
    if (!isDate(a.effective) || !isDate(a.expires)) { bad('effective and expires must be YYYY-MM-DD dates'); continue; }
    const limit = c.severity === 'CRITICAL' ? 90 : 180;
    if (days(a.effective, a.expires) > limit) { bad(`lasts more than ${limit} days`); continue; }
    if (a.effective > today || a.expires < today) { bad(a.expires < today ? 'expired' : 'not in effect yet'); continue; }
    if (c.severity === 'CRITICAL' && ++critical > 3) { bad('more than 3 CRITICAL acceptances for one release'); continue; }
    ok.set(a.id, a);
  }
  return { ok, problems };
}

const isGated = (c: Control): boolean => c.severity === 'BLOCKER' || c.severity === 'CRITICAL';

export function evaluateGate(g: GateInput): GateOutcome {
  const scoped = g.controls.filter((c) => inScope(c, g.scope));
  const byId = new Map(scoped.map((c) => [c.id, c]));
  const problems: string[] = [];

  // Rows: the engine's, then the owner's for anything the engine did not FAIL.
  const engine = new Map<string, OwnerRow>(g.rows.map((r) => [r.id, r]));
  for (const r of g.owner?.results ?? []) {
    if (engine.get(r.id)?.result === 'FAIL') continue;
    engine.set(r.id, r);
  }
  const rows = [...engine.values()].sort((a, b) => cmp(a.id, b.id)).map((r) => [r.id, r.result, r.notes]);

  // The kit's checklist gate on the in scope controls; scope 'all' because the stage filter is already applied.
  const { counts, ok } = g.kitGate.evaluate(scoped, rows, 'all');
  const checklistLine = `hullproof checklist (${g.scope.edition}, ${g.scope.stage}): checked ${counts.checked}, pass ${counts.pass}, not applicable ${counts.notApplicable}, fail ${counts.fail}, not assessed ${counts.notAssessed} (missing rows ${counts.missing}, PASS (static) rejected ${counts.passStaticRejected}, NOT APPLICABLE without a reason ${counts.naWithoutReason}), duplicate rows ${counts.duplicates}, unknown ids ${counts.unknownIds}`;

  // The findings record: validated by the kit, then cross checked against the rows by the kit.
  // Validation and cross checks see every known requirement: an observation may name one outside this run's scope.
  const all = new Map<string, unknown>(g.controls.map((c) => [c.id, c]));
  const v = g.kitGate.validateFindingsText(g.findingsText, { controls: all });
  if (v.c.errorCount) problems.push(...v.c.lines().map((l) => `findings ${l}`));
  const findings = v.data;
  const { got } = g.kitGate.collapseRows(rows);
  if (findings && !v.c.errorCount) problems.push(...g.kitGate.crossChecks(all, got, findings).problems);
  const runSupportsReady = !!findings && findings.report.run_status === 'complete' && findings.report.scope === 'full' && findings.report.profile !== 'quick';

  // Open gated items, the same way the kit's evaluate counts them.
  const open: GateOutcome['open'] = [];
  for (const c of scoped.filter(isGated)) {
    const r = got.get(c.id);
    const settled = r !== undefined && (
      (r.state === 'PASS' && !(g.kitGate.isStaticPass(r.raw) && c.authority !== 'repo')) || (r.state === 'NOT APPLICABLE' && r.note !== ''));
    if (!settled) open.push({ id: c.id, severity: c.severity, state: r?.raw ?? 'missing row', accepted: false });
  }
  if ((open.length === 0) !== ok) problems.push('internal: the open item list does not agree with the kit gate');

  const acc = currentAcceptances(g.owner?.acceptances ?? [], byId, g.today);
  for (const o of open) if (o.severity === 'CRITICAL' && acc.ok.has(o.id)) o.accepted = true;
  const highFails = (findings?.records ?? []).filter((r) => r.kind === 'fail' && r.severity === 'HIGH')
    .flatMap((r) => (r.kind === 'fail' ? r.sec_ids : [])).filter((id) => byId.get(id)?.severity === 'HIGH');
  const highOpen = [...new Set(highFails)].filter((id) => !acc.ok.has(id)).sort(cmp);
  const used = [...new Set([...open.filter((o) => o.accepted).map((o) => o.id), ...highFails.filter((id) => acc.ok.has(id))])].sort(cmp);

  const stagePath = join(g.repo, 'docs/security/STAGE.md');
  const inRepo = (p: string | undefined): string | null => { if (!p) return null; const abs = resolve(g.repo, p); return abs.startsWith(resolve(g.repo)) && existsSync(abs) ? abs : null; };
  const report = inRepo(g.owner?.audit_report);
  const rollback = inRepo(g.owner?.rollback);
  const ranOk = (t: string): boolean => g.metas.some((m) => m.tool === t && m.status === 'ran' && m.files_scanned !== 0);
  const g7missing = ['gitleaks', 'semgrep', 'osv-scanner'].filter((t) => !ranOk(t));
  const blockerOpen = open.filter((o) => o.severity === 'BLOCKER');
  const blockerFail = blockerOpen.filter((o) => o.state.toUpperCase().startsWith('FAIL'));
  const criticalOpen = open.filter((o) => o.severity === 'CRITICAL' && !o.accepted);

  const conditions: Condition[] = [
    { id: 'G-1', met: existsSync(stagePath) && g.scope.stageSource === 'STAGE.md', why: existsSync(stagePath) ? (g.scope.stageSource === 'STAGE.md' ? `stage ${g.scope.stage} recorded in docs/security/STAGE.md` : 'docs/security/STAGE.md names no stage') : 'docs/security/STAGE.md is missing' },
    { id: 'G-2', met: !!report && readFileSync(report, 'utf8').includes(g.commit), why: report ? (readFileSync(report, 'utf8').includes(g.commit) ? 'audit report names this commit' : 'the audit report does not name this commit') : 'no audit report supplied (owner file, audit_report)' },
    { id: 'G-3', met: blockerFail.length === 0, why: blockerFail.length ? `${blockerFail.length} BLOCKER requirement(s) FAIL` : 'no BLOCKER requirement FAILs' },
    { id: 'G-4', met: blockerOpen.length === 0, why: blockerOpen.length ? `${blockerOpen.length} BLOCKER requirement(s) open (FAIL or NOT ASSESSED)` : 'every BLOCKER requirement is settled' },
    { id: 'G-5', met: criticalOpen.length === 0, why: criticalOpen.length ? `${criticalOpen.length} CRITICAL requirement(s) open and not under a current acceptance` : 'every CRITICAL requirement is settled or accepted' },
    g.scope.edition === 'free'
      ? { id: 'G-6', met: true, why: 'outside the free scope' }
      : { id: 'G-6', met: highOpen.length === 0, why: highOpen.length ? `${highOpen.length} HIGH requirement(s) with a fail record and no current acceptance` : 'no open HIGH finding' },
    { id: 'G-7', met: g7missing.length === 0, why: g7missing.length ? `did not run on this commit: ${g7missing.join(', ')}` : 'gitleaks, semgrep and osv-scanner ran on this commit' },
    { id: 'G-8', met: !!rollback, why: rollback ? 'rollback path supplied' : 'no rollback path supplied (owner file, rollback)' },
  ];

  const allMet = conditions.every((c) => c.met) && runSupportsReady;
  const verdict: Verdict = !allMet ? 'NOT READY' : used.length ? 'READY WITH ACCEPTED RISK' : 'READY';
  const label = verdict !== 'NOT READY' && g.scope.edition === 'free' ? `${verdict} (FREE SCOPE)` : verdict;
  return {
    verdict, label, exit: problems.length ? 2 : verdict === 'NOT READY' ? 1 : 0, problems, conditions, counts,
    open: open.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.id, b.id)), acceptancesUsed: used, acceptanceProblems: acc.problems,
    runSupportsReady, checklistLine,
  };
}

export function gateLines(o: GateOutcome): string[] {
  const lines = [o.checklistLine];
  for (const c of o.conditions) lines.push(`${c.id}: ${c.met ? 'met' : 'not met'}, ${c.why}`);
  if (!o.runSupportsReady) lines.push('note: this run cannot support READY (the findings record says the run is incomplete, partial or quick)');
  for (const p of o.acceptanceProblems) lines.push(`note: ${p}`);
  if (o.problems.length) { lines.push('RESULT: stopped, the records or a cross check need attention (exit 2)'); return lines; }
  lines.push(`RESULT: ${o.label}`);
  return lines;
}
