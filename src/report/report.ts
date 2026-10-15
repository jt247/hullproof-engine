// report.md: the plain English report for people who build with AI tools. Built from the scan folder only.
// Same scan folder, same bytes: no clock, no absolute path, everything sorted.
import { cmp } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import type { FailRecord, ObservationRecord, RouteState } from '../types/index.ts';
import { OWNER_ACTION } from './build.ts';
import type { GateOutcome } from '../gate/gate.ts';
import { SEV_RANK, type Kit } from './kit.ts';
import type { ScanFolder } from './load.ts';
import { renderEntryPoints } from './entry-points.ts';
import { reportSection } from '../packs/coverage.ts';
import { renderHunt } from './hunt-section.ts';
import { renderProve } from './prove-section.ts';
import type { Merged } from '../confirm/merge.ts';

const cell = (s: string): string => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
const loc = (e: { file: string; line: number }): string => `\`${e.file}:${e.line}\``;
const STATE_ORDER: RouteState[] = ['NEEDS DYNAMIC TEST', 'NEEDS DASHBOARD', 'NEEDS BUILD', 'ASK OWNER', 'ATTESTATION', 'UNKNOWN'];
const STATE_MEANS: Record<RouteState, string> = {
  'NEEDS DYNAMIC TEST': 'Only a test of the running app (or a staging copy) can settle these.',
  'NEEDS DASHBOARD': 'Only a provider setting can settle these, shown by a dated export or screenshot.',
  'NEEDS BUILD': 'Only a production build from this commit can settle these.',
  'ASK OWNER': 'Only the owner can answer these.',
  'ATTESTATION': 'These need a signed, dated statement.',
  'UNKNOWN': 'These are settled by reading code, and no engine check or rule covers them yet. The engine has a code map and no model.',
};

export function renderReport(s: ScanFolder, kit: Kit, gate: GateOutcome, merged: Merged | null = null): string {
  const out: string[] = [];
  const p = (...l: string[]): void => { out.push(...l); };
  const fails = s.findings.records.filter((r): r is FailRecord => r.kind === 'fail')
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.fingerprint, b.fingerprint));
  const allObs = s.findings.records.filter((r): r is ObservationRecord => r.kind === 'observation');
  // Test code observations carry a fingerprint slug starting with test-code (src/report/build.ts).
  const slugOf = (o: ObservationRecord): string => o.fingerprint.split(':')[2];
  const isTest = (o: ObservationRecord): boolean => slugOf(o).startsWith('test-code-');
  const isLead = (o: ObservationRecord): boolean => slugOf(o).startsWith('lead-');
  const obs = allObs.filter((o) => !isTest(o) && !isLead(o));
  const testObs = allObs.filter(isTest);
  const leadObs = allObs.filter(isLead);
  const count = (w: string): number => s.results.filter((r) => r.result.startsWith(w)).length;
  const stageText = s.info.stage_source === 'STAGE.md' ? 'read from docs/security/STAGE.md' : s.info.stage_source === 'flag' ? 'set with --stage' : 'not declared, so LAUNCH is assumed';

  p('# Hullproof report', '');
  p(`Commit \`${s.info.commit}\`, tree \`${s.info.tree}\`, ${s.info.tree_clean ? 'no uncommitted changes to tracked files' : 'with uncommitted changes to tracked files (the report covers the files as they were, not the commit alone)'}. Hullproof Engine ${ENGINE_VERSION}, standard ${s.info.kit.standard_version}, ${s.info.edition} edition, stage ${s.info.stage} (${stageText}).`, '');
  p('This report comes from code and configuration only, with no model. Every finding is a pattern match that nobody has confirmed yet, so treat each one as likely and use its check step to confirm it. A requirement that nothing settled is listed as NOT ASSESSED. That is never a pass.', '');

  p(`## Verdict: ${gate.label}`, '');
  const notMet = gate.conditions.filter((c) => !c.met);
  if (gate.verdict === 'NOT READY') {
    p(`The release gate is not met. ${notMet.length} of ${gate.conditions.length} conditions are open${gate.runSupportsReady ? '' : ', and a run with unconfirmed BLOCKER or CRITICAL findings cannot support READY'}. A scan of files alone can never reach READY: most BLOCKER and CRITICAL requirements are settled by provider settings, a production build or a test of the running app, which the owner supplies.`, '');
  } else {
    p('Every condition of the release gate is met for this commit with the evidence supplied.', '');
  }
  p('| Condition | Met | Why |', '|---|---|---|');
  for (const c of gate.conditions) p(`| ${c.id} | ${c.met ? 'yes' : 'no'} | ${cell(c.why)} |`);
  p('');

  p('## Summary', '');
  const bySev = ['BLOCKER', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((v) => [v, fails.filter((f) => f.severity === v).length] as const).filter(([, n]) => n > 0);
  p(`1. Findings: ${fails.length}${bySev.length ? ` (${bySev.map(([v, n]) => `${n} ${v}`).join(', ')})` : ''}. In test code, reported apart and never in the gate: ${testObs.length}. Leads from rules still being measured, never in the gate: ${leadObs.length}.`);
  p(`2. Requirements in scope: ${s.results.length}. FAIL ${count('FAIL')}, PASS (static) ${count('PASS')}, NOT ASSESSED ${count('NOT ASSESSED')}.`);
  p(`3. Checks: ${s.info.checks.ran} ran, ${s.info.checks.not_run} did not run (listed below with the reason).`);
  const ran = s.metas.filter((m) => m.status === 'ran').map((m) => m.tool);
  p(`4. Scanners that ran: ${ran.length ? ran.join(', ') : 'none'}.${s.info.scanners_available ? '' : ' The scanner adapters were not available in this build, so no scanner ran.'}`);
  const pack = s.info.rule_pack;
  p(`5. Semgrep rule pack: ${pack ? `${pack.name}, ${pack.files.length} rule files added to the engine rules (sha256 ${pack.sha256.slice(0, 16)})` : 'none, the engine rules only'}.`, '');

  p('## Findings, most severe first', '');
  if (fails.length === 0) p('No check or mapped rule failed. That does not mean the requirements pass: see NOT ASSESSED below.', '');
  fails.forEach((f, i) => {
    const me = f.machine_evidence!;
    p(`### F-${i + 1} ${f.severity}: ${f.title}`, '');
    p(`Where: ${f.evidence.map(loc).join(', ')}`, '');
    p(`Requirements: ${f.sec_ids.map((id) => `${id} (${kit.byId.get(id)?.title ?? 'unknown'})`).join('; ')}`, '');
    p(`What could happen: ${f.impact_statement}`, '');
    p(`How to fix it: ${f.remediation.strategy}`, '');
    p(`How to check the fix: ${f.remediation.confirm}`, '');
    p(`Found by: ${me.tool === 'hullproof-check' ? `engine check ${me.rule_id}` : `${me.tool} ${me.tool_version}, rule ${me.rule_id}`}. Each line: ${f.evidence.map((e) => `${e.file}:${e.line} ${e.note}`).join('; ')}.`, '');
  });

  p(...renderHunt(s.hunt, merged));
  p(...renderProve(s.prove, merged));

  if (obs.length) {
    p('## Leads outside this run\'s scope', '');
    p('These were found but do not count in this run: their requirement is above the declared stage, outside the edition, or not mapped to a requirement. They never affect the gate.', '');
    for (const o of obs) p(`- ${o.title} at ${o.where.map(loc).join(', ')}. ${o.note}`);
    p('');
  }

  if (leadObs.length) {
    p('## Leads from rules still being measured', '');
    p('Each rule has a confidence tier from measurement on public benchmarks (rules/tiers.json). A rule whose measured precision is below the threshold, or that has not been measured yet, reports leads: read the code at each place. Leads never fail a requirement or affect the gate. Secret findings are never leads.', '');
    for (const o of leadObs) p(`- ${o.title} at ${o.where.map(loc).join(', ')}. ${o.note}`);
    p('');
  }

  if (testObs.length) {
    p('## Findings in test code', '');
    p('These are in test, fixture, spec, mock or example files, found by folder and file name conventions. They are kept so a person can read them, and they never fail a requirement or affect the gate. Secret findings are not in this list: a live key is a leak wherever it is committed, so they stay findings.', '');
    for (const o of testObs) p(`- ${o.title} at ${o.where.map(loc).join(', ')}. ${o.note}`);
    p('');
  }

  p('## What could not run, and why', '');
  p('| Scanner | Status | Why | Version | Requirements left NOT ASSESSED because of it |', '|---|---|---|---|---|');
  if (s.metas.length === 0) p('| all | no scanner adapter ran | | none | the requirements their rules cover |');
  for (const m of s.metas) p(`| ${m.tool} | ${m.status} | ${cell(s.reasons[m.tool] ?? '')} | ${m.version ?? 'none'}${m.version && !m.version_tested ? ' (not a tested version)' : ''} | ${m.not_assessed_sec_ids.join(', ') || 'none'} |`);
  p('');
  if (s.checks.not_run.length) {
    p('| Check | Why it did not run |', '|---|---|');
    for (const n of s.checks.not_run) p(`| ${n.check_id} | ${cell(n.reason)} |`);
    p('');
  }
  if (s.info.dropped.length) {
    p('Some checks name requirements that this kit\'s controls file does not hold yet, so those requirements are not in the results:', '');
    for (const d of s.info.dropped) p(`- ${d.source} at \`${d.where}\`: ${d.ids.join(', ')}`);
    p('');
  }
  p('Discovery reads files, not deployments. Anything set only in a provider dashboard is invisible to this scan.', '');

  p('## What the scan read', '');
  p(`${s.surface.files_listed} files were listed (dependency folders, build output, ignored files and the kit's own folders are left out).`, '');
  p('| Kind | Files |', '|---|---|');
  for (const k of s.surface.surfaces) p(`| ${k.kind} | ${k.count} |`);
  p('');

  if (s.codemap) p(...renderEntryPoints(s.codemap));
  p(...reportSection(s.stack));

  p('## Unverified controls (NOT ASSESSED)', '');
  p('Nothing in the files settled these. They are open, not passed. Each group says what settles it.', '');
  for (const st of STATE_ORDER) {
    const rows = s.results.filter((r) => r.result === `NOT ASSESSED: ${st}`);
    if (!rows.length) continue;
    p(`### NOT ASSESSED: ${st} (${rows.length})`, '', `${STATE_MEANS[st]} ${OWNER_ACTION[st]}`, '');
    p('| ID | Severity | Requirement |', '|---|---|---|');
    for (const r of rows.slice().sort((a, b) => SEV_RANK[kit.byId.get(b.id)!.severity] - SEV_RANK[kit.byId.get(a.id)!.severity] || cmp(a.id, b.id))) {
      const c = kit.byId.get(r.id)!;
      p(`| ${r.id} | ${c.severity} | ${cell(c.title)} |`);
    }
    p('');
  }
  const passes = s.results.filter((r) => r.result === 'PASS (static)');
  if (passes.length) {
    p('## PASS (static)', '', 'Settled by reading the repository. Only requirements whose authority is the repository can pass this way.', '');
    p('| ID | Requirement | How |', '|---|---|---|');
    for (const r of passes) p(`| ${r.id} | ${cell(kit.byId.get(r.id)?.title ?? '')} | ${cell(r.notes)} |`);
    p('');
  }

  p('## Reproducibility', '');
  p('The same commit, engine version, kit files and tool versions give the same bytes in every file of the scan folder except run.json and scan/run.json.', '');
  p('| Item | Value |', '|---|---|');
  p(`| Engine | ${ENGINE_VERSION} |`, `| Controls file sha256 | ${s.info.kit.controls_sha256} |`, `| Checks | ${s.info.checks.total} |`);
  for (const m of s.metas) p(`| ${m.tool} | ${m.version ?? 'not run'}, config sha256 ${m.config_sha256 ?? 'none'}, files scanned ${m.files_scanned ?? 'unknown'} of ${m.files_tracked ?? 'unknown'} tracked${m.db_date ? `, advisory data ${m.db_date}` : ''} |`);
  p('');
  return out.join('\n');
}
