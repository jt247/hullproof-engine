// Proven findings and the gate. The whole path runs: a proof result, the merge into rows and records, the kit gate. A spec proven 3 of 3
// enters the gate like any confirmed finding. Everything else the sandbox can say (not proven, invalid, unstable, error, not provable
// here, dropped files, a result edited to claim more than its runs show) leaves every byte of the gate output as it was.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { confirmHunt } from '../src/confirm/confirm.ts';
import { mergeHunt } from '../src/confirm/merge.ts';
import { evaluateGate, gateLines, loadKitGate } from '../src/gate/gate.ts';
import { findingsJson, findingsMarkdown } from '../src/report/build.ts';
import type { Control, Kit } from '../src/report/kit.ts';
import { renderProve } from '../src/report/prove-section.ts';
import type { FindingsFile, ProveResult, ProveSpecResult, ResultRow, RunOutcome, SpecOutcome, ToolMeta } from '../src/types/index.ts';
import { answer, appCopy, boLead, DELETE_ID, proposal } from './helpers/hunt.ts';
import { KIT } from './helpers/kit.ts';

const skip = existsSync(join(KIT, 'tools/hullproof/ci/hullproof-gate.mjs')) ? false : 'kit not present (set HULLPROOF_KIT)';
const C = (id: string, severity: Control['severity']): Control => ({ id, title: `Requirement ${id}`, severity, authority: 'runtime', edition: 'free', stage: 'LAUNCH', prelaunch: true, status: 'active', domains: ['api'], verification_method: [] });
const CONTROLS = [C('SEC-API-001', 'BLOCKER'), C('SEC-DB-007', 'CRITICAL'), C('SEC-XXX-000', 'HIGH')];
const KITOBJ: Kit = { dir: '', controls: CONTROLS, byId: new Map(CONTROLS.map((c) => [c.id, c])), controlsSha256: '0'.repeat(64), standardVersion: 'test' };
const COMMIT = 'a'.repeat(40);
const META = (tool: ToolMeta['tool']): ToolMeta => ({ schema_version: '1.0.0', tool, status: 'ran', version: '1', tested_version_range: '', version_tested: true, argv: [], config_sha256: null, commit: COMMIT, files_scanned: 10, files_tracked: 10, exit_code: 0, db_date: null, not_assessed_sec_ids: [] });
const BASE: FindingsFile = { schema_version: '1.1.0', report: { commit: COMMIT, tree: 'b'.repeat(40), tree_clean: true, stage: 'LAUNCH', profile: 'standard', scope: 'full', run_status: 'complete', agent_calls: 0, budget: null }, records: [] };
const ROWS: ResultRow[] = CONTROLS.map((c) => ({ id: c.id, result: 'NOT ASSESSED: NEEDS DYNAMIC TEST', notes: '' }));
const INFO = { edition: 'pro', stage: 'LAUNCH', stage_source: 'STAGE.md' } as never;
const { repo, map } = appCopy();
const gateDir = mkdtempSync(join(tmpdir(), 'hp-pg-'));
mkdirSync(join(gateDir, 'docs/security'), { recursive: true });
writeFileSync(join(gateDir, 'docs/security/STAGE.md'), '# Stage\n\nStage: LAUNCH\n');
writeFileSync(join(gateDir, 'docs/security/AUDIT.md'), `Audit of commit ${COMMIT}\n`);
writeFileSync(join(gateDir, 'docs/security/ROLLBACK.md'), 'Redeploy the previous build.\n');

const h = (n: number): string => n.toString(16).padStart(64, '0');
function spec(over: Partial<ProveSpecResult> = {}, outcome: SpecOutcome = 'proven', runOutcome: RunOutcome = 'proven'): ProveSpecResult {
  return { spec_id: 'note_delete', spec_sha256: h(1), lead_key: null, title: 'bob deletes the note of alice', claim: 'Any signed in user can delete any note by id.', entry_point: DELETE_ID, requirement_ids: ['SEC-XXX-000'], sink: { file: 'server.js', line: 28 }, outcome, reason: 'r', runs: [1, 2, 3].map((run) => ({ run, outcome: runOutcome, transcript_sha256: h(run + 10), detail: 'd' })), ...over };
}
function prove(specs: ProveSpecResult[], over: Partial<ProveResult> = {}): ProveResult {
  const n = (o: SpecOutcome): number => specs.filter((s) => s.outcome === o).length;
  return { schema_version: '1.0.0', engine_version: '0.5.0', commit: COMMIT, runner: 'container', runs_required: 3, recipe_sha256: h(9), not_provable: null, specs, dropped: [], left_behind: 0, copy_excluded: [], counts: { specs: specs.length, proven: n('proven'), not_proven: n('not_proven'), invalid: n('invalid'), unstable: n('unstable'), error: n('error'), not_provable: n('not_provable'), dropped: 0 }, ...over };
}

async function verdictFor(p: ProveResult | null, hunt = null as ReturnType<typeof confirmHunt> | null): Promise<{ lines: string; verdict: string; exit: number; inGate: number; problems: string[]; findings: FindingsFile; text: string }> {
  const m = mergeHunt({ results: ROWS, findings: BASE, info: INFO }, KITOBJ, hunt, p);
  const g = evaluateGate({
    kitGate: await loadKitGate(KIT), controls: CONTROLS, scope: { edition: 'pro', stage: 'LAUNCH', stageSource: 'STAGE.md' }, rows: m.results, findingsText: m.findingsText,
    metas: [META('gitleaks'), META('osv-scanner'), META('semgrep')], repo: gateDir, commit: COMMIT, today: '2026-10-14',
    owner: { audit_report: 'docs/security/AUDIT.md', rollback: 'docs/security/ROLLBACK.md', results: CONTROLS.map((c) => ({ id: c.id, result: 'PASS' as const, notes: 'staging test 2026-10-13' })) },
  });
  return { lines: gateLines(g).join('\n'), verdict: g.verdict, exit: g.exit, inGate: m.inGate.length, problems: g.problems, findings: m.findings, text: m.findingsText };
}

test('a spec proven 3 of 3 is a valid fail record with machine evidence of kind test, and makes its requirement FAIL', { skip }, async () => {
  const v = await verdictFor(prove([spec()]));
  assert.equal(v.inGate, 1);
  assert.deepEqual(v.problems, [], 'the kit validator accepts the merged record');
  const rec = v.findings.records[0];
  assert.equal(rec.kind, 'fail');
  if (rec.kind !== 'fail') return;
  assert.equal(rec.machine_evidence?.tool, 'hullproof-prove');
  assert.match(rec.machine_evidence!.rule_id, /^prove\.test\.[0-9a-f]{12}$/);
  assert.equal(rec.machine_evidence?.config_sha256, h(1), 'the hash of the spec');
  assert.deepEqual(rec.raised_by, ['hullproof-prove']);
  assert.match(rec.title, /^Proven by test: /);
  assert.match(rec.impact_statement, /proved it with a test run in a local sandbox/);
  assert.equal(rec.class, 'finding');
  assert.equal(rec.demonstrated, false);
  assert.equal(v.verdict, 'NOT READY');
  assert.equal(v.exit, 1);
});

test('everything but 3 of 3 proven leaves every byte of the gate output as it was', { skip }, async () => {
  const none = await verdictFor(null);
  assert.equal(none.verdict, 'READY', none.lines);
  const variants: [string, ProveResult][] = [
    ['not proven', prove([spec({}, 'not_proven', 'not_proven')])],
    ['invalid', prove([spec({}, 'invalid', 'invalid')])],
    ['unstable', prove([spec({}, 'unstable')])],
    ['error', prove([spec({}, 'error', 'error')])],
    ['not provable here', prove([spec({ runs: [] }, 'not_provable')], { not_provable: { code: 'hosted_service', reason: 'supabase' } })],
    ['dropped spec files', prove([], { dropped: [{ file: 'a.json', reason: 'x' }] })],
    ['a result edited to say proven with 2 runs', prove([spec({ runs: spec().runs.slice(0, 2) })])],
    ['a result edited to say proven with a run that was not', prove([spec({ runs: spec().runs.map((r, i) => (i === 2 ? { ...r, outcome: 'not_proven' as const } : r)) })])],
    ['a proven spec that names no requirement', prove([spec({ requirement_ids: [] })])],
  ];
  for (const [name, p] of variants) {
    const v = await verdictFor(p);
    assert.equal(v.inGate, 0, name);
    assert.equal(v.lines, none.lines, name);
    assert.equal(v.exit, none.exit, name);
  }
  // The same proof does change the verdict, so the test can fail.
  assert.notEqual((await verdictFor(prove([spec()]))).lines, none.lines);
});

test('a proof of a hunt lead replaces the weaker evidence and gives one record, not two', { skip }, async () => {
  const lead = boLead({ requirement_ids: ['SEC-XXX-000'] });
  const hunt = confirmHunt({ repo, map, answers: [answer(1, DELETE_ID, [lead])], plan: null, commit: COMMIT });
  assert.equal(hunt.confirmed.length, 1);
  const alone = await verdictFor(null, hunt);
  assert.match((alone.findings.records[0] as { machine_evidence: { tool: string } }).machine_evidence.tool, /hullproof-hunt/);
  const key = hunt.confirmed[0].key;
  const both = await verdictFor(prove([spec({ lead_key: key })]), hunt);
  assert.equal(both.findings.records.length, 1);
  assert.equal(both.inGate, 1);
  const rec = both.findings.records[0];
  assert.ok(rec.kind === 'fail' && rec.machine_evidence?.tool === 'hullproof-prove');
  assert.deepEqual(both.problems, []);
});

test('a hunt lead that waits for a test enters the gate when the test proves it, with the lead\'s own path and requirements', { skip }, async () => {
  const lead = boLead({ requirement_ids: ['SEC-XXX-000'], evidence_proposal: proposal('generated_test') });
  const hunt = confirmHunt({ repo, map, answers: [answer(1, DELETE_ID, [lead])], plan: null, commit: COMMIT });
  assert.equal(hunt.confirmed.length, 0);
  assert.equal(hunt.leads.length, 1);
  assert.equal(hunt.leads[0].confirmation.status, 'not_confirmed');
  const none = await verdictFor(null, hunt);
  assert.equal(none.verdict, 'READY', 'an unproven test lead never changes the verdict');
  const key = hunt.leads[0].key;
  const proven = await verdictFor(prove([spec({ lead_key: key, requirement_ids: [] })]), hunt);
  assert.equal(proven.inGate, 1);
  const rec = proven.findings.records[0];
  assert.ok(rec.kind === 'fail');
  if (rec.kind === 'fail') { assert.deepEqual(rec.sec_ids, ['SEC-XXX-000']); assert.equal(rec.trace?.length, 2, 'the lead path is kept'); assert.equal(rec.machine_evidence?.tool, 'hullproof-prove'); }
  assert.equal(proven.verdict, 'NOT READY');
});

test('the merged text is deterministic', { skip }, async () => {
  const a = await verdictFor(prove([spec()]));
  const b = await verdictFor(prove([spec()]));
  assert.equal(a.text, b.text);
  assert.equal(a.text, findingsMarkdown(a.findings, findingsJson(a.findings)));
});

test('the report marks proven findings with the attack request and response, and not provable runs with the reason', () => {
  assert.deepEqual(renderProve(undefined, null), [], 'a scan folder with no prove folder gets no section');
  assert.deepEqual(renderProve({ result: null, first: {} }, null), []);
  const m = mergeHunt({ results: ROWS, findings: BASE, info: INFO }, KITOBJ, null, prove([spec()]));
  const rec = { schema_version: '1.0.0' as const, spec_id: 'note_delete', spec_sha256: h(1), run: 1, outcome: 'proven' as const, detail: 'd', transcript_sha256: h(11), steps: [{ id: 'bob_deletes', phase: 'attack' as const, actor: 'bob', error: null, request: { method: 'DELETE' as const, path: '/api/notes/1', headers: {}, body: null }, response: { status: 200, headers: {}, json: { ok: true }, text: undefined, truncated: false }, captures: {}, assertions: [] }] };
  const text = renderProve({ result: prove([spec(), spec({ spec_id: 'other' }, 'not_proven', 'not_proven')]), first: { note_delete: rec } }, m).join('\n');
  assert.match(text, /## Proof sandbox: findings proven by a test/);
  assert.match(text, /#### P-1 Any signed in user can delete any note by id\./);
  assert.match(text, /Transcript hashes: run 1 [0-9a-f]{16}, run 2 [0-9a-f]{16}, run 3 [0-9a-f]{16}/);
  assert.match(text, /Attack step bob_deletes: bob sent DELETE \/api\/notes\/1 and got 200 \{"ok":true\}/);
  assert.match(text, /Counts in the gate: yes/);
  assert.match(text, /### Not proven[\s\S]*other/);
  const np = renderProve({ result: prove([spec({ runs: [] }, 'not_provable')], { not_provable: { code: 'hosted_service', reason: 'the app uses supabase' } }), first: {} }, null).join('\n');
  assert.match(np, /Not provable here \(hosted_service\): the app uses supabase/);
});
