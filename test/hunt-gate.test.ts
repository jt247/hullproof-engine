// Leads never change the gate. The whole path runs: saved answers, confirmation, merge into rows and records, the kit gate. The
// verdict is READY before any lead; adding, removing or changing leads that are not confirmed leaves every byte of the gate output
// as it was; a confirmed finding changes it, which shows the test can fail.
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
import type { FindingsFile, HuntAnswer, ResultRow, ToolMeta } from '../src/types/index.ts';
import { answer, appCopy, boLead, DELETE_ID, EXPORT_ID, proposal } from './helpers/hunt.ts';
import { KIT } from './helpers/kit.ts';

const skip = existsSync(join(KIT, 'tools/hullproof/ci/hullproof-gate.mjs')) ? false : 'kit not present (set HULLPROOF_KIT)';
const C = (id: string, severity: Control['severity'], domains: string[]): Control => ({ id, title: `Requirement ${id}`, severity, authority: 'runtime', edition: 'free', stage: 'LAUNCH', prelaunch: true, status: 'active', domains, verification_method: [] });
const CONTROLS = [C('SEC-API-001', 'BLOCKER', ['api']), C('SEC-DB-007', 'CRITICAL', ['database']), C('SEC-XXX-000', 'HIGH', ['web'])];
const KITOBJ: Kit = { dir: '', controls: CONTROLS, byId: new Map(CONTROLS.map((c) => [c.id, c])), controlsSha256: '0'.repeat(64), standardVersion: 'test' };
const COMMIT = 'a'.repeat(40);
const META = (tool: ToolMeta['tool']): ToolMeta => ({ schema_version: '1.0.0', tool, status: 'ran', version: '1', tested_version_range: '', version_tested: true, argv: [], config_sha256: null, commit: COMMIT, files_scanned: 10, files_tracked: 10, exit_code: 0, db_date: null, not_assessed_sec_ids: [] });
const BASE_FINDINGS: FindingsFile = { schema_version: '1.1.0', report: { commit: COMMIT, tree: 'b'.repeat(40), tree_clean: true, stage: 'LAUNCH', profile: 'standard', scope: 'full', run_status: 'complete', agent_calls: 0, budget: null }, records: [] };
const ROWS: ResultRow[] = CONTROLS.map((c) => ({ id: c.id, result: 'NOT ASSESSED: NEEDS DYNAMIC TEST', notes: '' }));
const INFO = { edition: 'pro', stage: 'LAUNCH', stage_source: 'STAGE.md' } as never;

function repoDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-hg-'));
  mkdirSync(join(dir, 'docs/security'), { recursive: true });
  writeFileSync(join(dir, 'docs/security/STAGE.md'), '# Stage\n\nStage: LAUNCH\n');
  writeFileSync(join(dir, 'docs/security/AUDIT.md'), `Audit of commit ${COMMIT}\n`);
  writeFileSync(join(dir, 'docs/security/ROLLBACK.md'), 'Redeploy the previous build.\n');
  return dir;
}
const { repo, map } = appCopy();
const gateDir = repoDir();

async function verdictFor(answers: HuntAnswer[]): Promise<{ lines: string; verdict: string; exit: number; confirmed: number; problems: string[] }> {
  const result = confirmHunt({ repo, map, answers, plan: null, commit: COMMIT });
  const m = mergeHunt({ results: ROWS, findings: BASE_FINDINGS, info: INFO }, KITOBJ, result);
  const g = evaluateGate({
    kitGate: await loadKitGate(KIT), controls: CONTROLS, scope: { edition: 'pro', stage: 'LAUNCH', stageSource: 'STAGE.md' }, rows: m.results, findingsText: m.findingsText,
    metas: [META('gitleaks'), META('osv-scanner'), META('semgrep')], repo: gateDir, commit: COMMIT, today: '2026-10-14',
    owner: { audit_report: 'docs/security/AUDIT.md', rollback: 'docs/security/ROLLBACK.md', results: CONTROLS.map((c) => ({ id: c.id, result: 'PASS' as const, notes: 'staging test 2026-10-13' })) },
  });
  return { lines: gateLines(g).join('\n'), verdict: g.verdict, exit: g.exit, confirmed: m.inGate.length, problems: g.problems };
}

const weak = (id: string, over = {}) => boLead({ lead_id: id, evidence_proposal: proposal('none'), ...over });
const exportLead = (over = {}) => boLead({ lead_id: 'E', entry_point: EXPORT_ID, requirement_ids: ['SEC-DB-007'], path: [{ file: 'server.js', line: 23, note: 'r' }, { file: 'server.js', line: 24, note: 'q' }], quoted_code: "res.json(db.all('SELECT id, email FROM users', []));", evidence_proposal: proposal('none'), ...over });

test('a confirmed finding is a valid fail record with machine evidence and makes its requirement FAIL', { skip }, async () => {
  const result = confirmHunt({ repo, map, answers: [answer(1, DELETE_ID, [boLead({ requirement_ids: ['SEC-XXX-000'] })])], plan: null, commit: COMMIT });
  const m = mergeHunt({ results: ROWS, findings: BASE_FINDINGS, info: INFO }, KITOBJ, result);
  assert.equal(m.inGate.length, 1);
  const rec = m.findings.records[0];
  assert.equal(rec.kind, 'fail');
  if (rec.kind === 'fail') {
    assert.equal(rec.machine_evidence?.tool, 'hullproof-hunt');
    assert.deepEqual(rec.raised_by, ['hullproof-hunt']);
    assert.equal(rec.trace?.[0].kind, 'entrypoint');
    assert.equal(rec.trace?.[rec.trace.length - 1].kind, 'sink');
  }
  assert.equal(m.results.find((r) => r.id === 'SEC-XXX-000')?.result, 'FAIL');
  const g = await verdictFor([answer(1, DELETE_ID, [boLead({ requirement_ids: ['SEC-XXX-000'] })])]);
  assert.deepEqual(g.problems, [], 'the kit validator and cross checks accept the merged record');
});

test('leads never change the verdict: add, remove and change leads, every gate byte stays the same', { skip }, async () => {
  const none = await verdictFor([]);
  assert.equal(none.verdict, 'READY', none.lines);
  const variants: [string, HuntAnswer[]][] = [
    ['one lead with no proposal', [answer(1, DELETE_ID, [weak('a')])]],
    ['the same lead in three runs', [1, 2, 3].map((r) => answer(r, DELETE_ID, [weak('a')]))],
    ['leads of every requirement severity', [answer(1, DELETE_ID, [weak('a', { requirement_ids: ['SEC-API-001'] }), weak('b', { requirement_ids: ['SEC-DB-007'] }), weak('c', { requirement_ids: ['SEC-XXX-000'] })])]],
    ['a changed claim and requirement', [answer(1, DELETE_ID, [weak('a', { claim: 'Everything is on fire.', requirement_ids: ['SEC-API-001', 'SEC-DB-007'] })])]],
    ['a fabricated lead', [answer(1, DELETE_ID, [weak('a', { path: [{ file: 'ghost.js', line: 1, note: 'x' }], quoted_code: 'nothing like this' })])]],
    ['a lead whose query does not hold', [answer(1, DELETE_ID, [boLead({ evidence_proposal: proposal('map_query', { query_json: JSON.stringify({ where: { field: 'kind', op: 'eq', value: 'webhook' } }) }) })])]],
    ['a lead whose rule cannot run', [answer(1, DELETE_ID, [boLead({ evidence_proposal: proposal('semgrep_rule', { rule_yaml: 'rules: []', control_code: 'x', control_extension: 'js' }) })])]],
    ['a generated test proposal', [answer(1, DELETE_ID, [weak('a', { evidence_proposal: proposal('generated_test') })])]],
    ['a malformed answer and a stopped call', [answer(1, DELETE_ID, [], { output: { leads: [5] } as never }), answer(2, DELETE_ID, [], { status: 'incomplete', stop: 'refusal', output: null })]],
    ['another entry point with a lead', [answer(1, EXPORT_ID, [exportLead()])]],
  ];
  for (const [name, a] of variants) {
    const v = await verdictFor(a);
    assert.equal(v.confirmed, 0, name);
    assert.equal(v.lines, none.lines, name);
    assert.equal(v.verdict, none.verdict, name);
    assert.equal(v.exit, none.exit, name);
  }
});

test('a confirmed finding does change the verdict, and removing it restores the verdict', { skip }, async () => {
  const none = await verdictFor([]);
  const withFinding = await verdictFor([answer(1, DELETE_ID, [boLead({ requirement_ids: ['SEC-XXX-000'] })])]);
  assert.equal(withFinding.confirmed, 1);
  assert.equal(withFinding.verdict, 'NOT READY', withFinding.lines);
  assert.notEqual(withFinding.lines, none.lines);
  // Three runs raising the same finding is one finding, and the verdict is the same as one run.
  const three = await verdictFor([1, 2, 3].map((r) => answer(r, DELETE_ID, [boLead({ requirement_ids: ['SEC-XXX-000'] })])));
  assert.equal(three.lines, withFinding.lines);
  assert.equal((await verdictFor([])).lines, none.lines);
});

test('the merged findings text is deterministic', () => {
  const result = confirmHunt({ repo, map, answers: [answer(1, DELETE_ID, [boLead({ requirement_ids: ['SEC-XXX-000'] })])], plan: null, commit: COMMIT });
  const a = mergeHunt({ results: ROWS, findings: BASE_FINDINGS, info: INFO }, KITOBJ, result);
  const b = mergeHunt({ results: ROWS, findings: BASE_FINDINGS, info: INFO }, KITOBJ, result);
  assert.equal(a.findingsText, b.findingsText);
  assert.equal(a.findingsText, findingsMarkdown(a.findings, findingsJson(a.findings)));
});

test('a confirmed finding under a BLOCKER or CRITICAL requirement keeps the records valid (the run is recorded as deterministic only)', { skip }, async () => {
  for (const id of ['SEC-API-001', 'SEC-DB-007']) {
    const v = await verdictFor([answer(1, DELETE_ID, [boLead({ requirement_ids: [id] })])]);
    assert.deepEqual(v.problems, [], id);
    assert.equal(v.verdict, 'NOT READY', id);
    assert.equal(v.exit, 1, id);
  }
});

test('a confirmed finding that names no requirement is reported and never enters the gate', { skip }, async () => {
  const none = await verdictFor([]);
  const a = [answer(1, DELETE_ID, [boLead({ requirement_ids: [] })])];
  const result = confirmHunt({ repo, map, answers: a, plan: null, commit: COMMIT });
  assert.equal(result.confirmed.length, 1);
  const m = mergeHunt({ results: ROWS, findings: BASE_FINDINGS, info: INFO }, KITOBJ, result);
  assert.equal(m.inGate.length, 0);
  assert.equal(m.outOfScope.length, 1);
  assert.equal((await verdictFor(a)).lines, none.lines);
});

test('a confirmed finding that names no requirement borrows the requirement of the map check that flagged the same entry point', () => {
  const entry = map.entry_points.find((e) => e.id === DELETE_ID)!;
  const checks = { schema_version: '1.0.0', commit: COMMIT, not_run: [], results: [
    { check_id: 'check.map.write-by-id-without-owner', sec_ids: ['SEC-XXX-000'], result: 'FAIL', evidence: [{ file: entry.file, line: entry.line, note: 'n' }], absence_search: null, message_key: 'x' },
    { check_id: 'check.map.other', sec_ids: ['SEC-API-001'], result: 'FAIL', evidence: [{ file: 'elsewhere.js', line: 1, note: 'n' }], absence_search: null, message_key: 'x' },
  ] } as never;
  const result = confirmHunt({ repo, map, answers: [answer(1, DELETE_ID, [boLead({ requirement_ids: [] })])], plan: null, commit: COMMIT });
  const withChecks = mergeHunt({ results: ROWS, findings: BASE_FINDINGS, info: INFO, checks, codemap: map }, KITOBJ, result);
  assert.equal(withChecks.inGate.length, 1);
  const rec = withChecks.findings.records.find((r) => r.kind === 'fail')!;
  assert.deepEqual(rec.sec_ids, ['SEC-XXX-000']);
  assert.match((rec as { impact_statement: string }).impact_statement, /named no requirement, so the requirement is taken from check\.map\.write-by-id-without-owner/);
  assert.equal(withChecks.results.find((r) => r.id === 'SEC-XXX-000')?.result, 'FAIL');
  assert.equal(withChecks.results.find((r) => r.id === 'SEC-API-001')?.result, 'NOT ASSESSED: NEEDS DYNAMIC TEST', 'a check on another file is not borrowed');
  // Without the checks the finding stays out of the gate, as before.
  assert.equal(mergeHunt({ results: ROWS, findings: BASE_FINDINGS, info: INFO }, KITOBJ, result).inGate.length, 0);
});
