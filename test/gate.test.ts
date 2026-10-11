// The release gate. Part 1: on the kit's own gate fixtures, the engine gate reaches the same counts, the same cross check
// outcome and the same exit as the kit's hullproof-gate.mjs. Part 2: G-1 to G-8, acceptances and the three verdicts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { evaluateGate, gateLines, loadKitGate, type GateInput, type KitGate, type OwnerRow } from '../src/gate/gate.ts';
import type { Control } from '../src/report/kit.ts';
import type { ResultRow, ToolMeta } from '../src/types/index.ts';
import { KIT } from './helpers/kit.ts';

const CI = join(KIT, 'tools/hullproof/ci');
const skip = existsSync(join(CI, 'hullproof-gate.mjs')) ? false : 'kit not present (set HULLPROOF_KIT)';
// The kit's own gate fixtures ship with some kits only.
const skipFixtures = existsSync(join(CI, 'fixtures/controls-mini.json')) ? skip : 'the kit has no gate fixtures';
const FX = (n: string): string => join(CI, 'fixtures', n);

test('same outcome as the kit gate on the kit fixtures', { skip: skipFixtures }, async () => {
  const kitGate = await loadKitGate(KIT);
  const kitMod = await import(pathToFileURL(join(CI, 'hullproof-gate.mjs')).href) as { loadResults(t: string): string[][] };
  const controls = JSON.parse(readFileSync(FX('controls-mini.json'), 'utf8')).controls as Control[];
  const cases: [string, string][] = [
    ['report-ok', 'findings-ok'], ['report-open', 'valid-all-kinds'], ['report-x1', 'findings-ok'], ['report-ok', 'valid-all-kinds'],
    ['report-ok', 'findings-x3'], ['report-x4', 'valid-all-kinds'], ['report-ok', 'findings-incomplete'], ['report-ok', 'findings-quick'],
    ['report-ok', 'findings-partial'],
  ];
  for (const [res, fin] of cases) {
    const resPath = FX(`gate/${res}.md`);
    const finPath = existsSync(FX(`gate/${fin}.md`)) ? FX(`gate/${fin}.md`) : FX(`findings/${fin}.md`);
    const kit = spawnSync(process.execPath, [join(CI, 'hullproof-gate.mjs'), '--controls', FX('controls-mini.json'), '--results', resPath, '--findings', finPath, '--scope', 'all'], { encoding: 'utf8' });
    const rows: ResultRow[] = kitMod.loadResults(readFileSync(resPath, 'utf8')).map(([id, result, notes]) => ({ id, result: result as ResultRow['result'], notes }));
    const o = evaluateGate({ kitGate, controls, scope: { edition: 'pro', stage: 'SCALE', stageSource: 'flag' }, rows, findingsText: readFileSync(finPath, 'utf8'),
      metas: [], owner: null, repo: tmpdir(), commit: 'x', today: '2026-10-10' });
    const mine = o.problems.length ? 2 : o.open.length || !o.runSupportsReady ? 1 : 0;
    assert.equal(mine, kit.status, `${res} + ${fin}\nkit: ${kit.stdout}${kit.stderr}\nmine: ${gateLines(o).join('\n')}\n${o.problems.join('\n')}`);
    const counts = /checked (\d+), pass (\d+), not applicable (\d+), fail (\d+), not assessed (\d+)/.exec(kit.stdout)!;
    assert.deepEqual([o.counts.checked, o.counts.pass, o.counts.notApplicable, o.counts.fail, o.counts.notAssessed].map(String), counts.slice(1), `${res} + ${fin}`);
    for (const m of kit.stderr.matchAll(/cross check (\d)/g)) assert.ok(o.problems.some((p) => p.includes(`cross check ${m[1]}`)), `${res} + ${fin}: cross check ${m[1]}`);
  }
});

// Part 2: a synthetic repository and controls.
const C = (id: string, severity: Control['severity'], domains: string[], authority: Control['authority'] = 'runtime'): Control =>
  ({ id, title: id, severity, authority, edition: 'free', stage: 'LAUNCH', prelaunch: true, status: 'active', domains, verification_method: [] });
const CONTROLS = [C('SEC-API-001', 'BLOCKER', ['api']), C('SEC-DB-007', 'CRITICAL', ['database']), C('SEC-AUTH-034', 'CRITICAL', ['auth'])];
const COMMIT = 'a'.repeat(40);
const FINDINGS = (status: 'complete' | 'incomplete'): string => '```hullproof-findings\n' + JSON.stringify({
  schema_version: '1.1.0', report: { commit: COMMIT, tree: 'b'.repeat(40), tree_clean: true, stage: 'LAUNCH', profile: 'standard', scope: 'full', run_status: status,
    ...(status === 'incomplete' ? { incomplete_reason: 'deterministic_only' } : {}), agent_calls: 0, budget: null }, records: [],
}) + '\n```\n';
const META = (tool: ToolMeta['tool']): ToolMeta => ({ schema_version: '1.0.0', tool, status: 'ran', version: '1', tested_version_range: '', version_tested: true, argv: [], config_sha256: null,
  commit: COMMIT, files_scanned: 10, files_tracked: 10, exit_code: 0, db_date: null, not_assessed_sec_ids: [] });

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-gate-'));
  mkdirSync(join(dir, 'docs/security'), { recursive: true });
  writeFileSync(join(dir, 'docs/security/STAGE.md'), '# Stage\n\nStage: LAUNCH\n');
  writeFileSync(join(dir, 'docs/security/AUDIT.md'), `Audit of commit ${COMMIT}\n`);
  writeFileSync(join(dir, 'docs/security/ROLLBACK.md'), 'Redeploy the previous build.\n');
  return dir;
}

const settled: ResultRow[] = [
  { id: 'SEC-API-001', result: 'NOT ASSESSED: NEEDS DYNAMIC TEST', notes: '' },
  { id: 'SEC-AUTH-034', result: 'NOT ASSESSED: NEEDS DYNAMIC TEST', notes: '' },
  { id: 'SEC-DB-007', result: 'NOT ASSESSED: NEEDS DASHBOARD', notes: '' },
];
const ownerRows: OwnerRow[] = settled.map((r) => ({ id: r.id, result: 'PASS', notes: 'staging test 2026-10-09' }));

async function base(kitGate: KitGate, over: Partial<GateInput> = {}): Promise<ReturnType<typeof evaluateGate>> {
  return evaluateGate({
    kitGate, controls: CONTROLS, scope: { edition: 'pro', stage: 'LAUNCH', stageSource: 'STAGE.md' }, rows: settled, findingsText: FINDINGS('complete'),
    metas: [META('gitleaks'), META('osv-scanner'), META('semgrep')], repo: repo(), commit: COMMIT, today: '2026-10-10',
    owner: { audit_report: 'docs/security/AUDIT.md', rollback: 'docs/security/ROLLBACK.md', results: ownerRows }, ...over,
  });
}

test('READY when every condition is met with owner evidence; NOT READY from a files only run', { skip }, async () => {
  const kitGate = await loadKitGate(KIT);
  const ready = await base(kitGate);
  assert.equal(ready.verdict, 'READY', gateLines(ready).join('\n'));
  assert.equal(ready.exit, 0);
  const filesOnly = await base(kitGate, { owner: null });
  assert.equal(filesOnly.verdict, 'NOT READY');
  assert.equal(filesOnly.exit, 1);
  assert.deepEqual(filesOnly.conditions.filter((c) => !c.met).map((c) => c.id), ['G-2', 'G-4', 'G-5', 'G-8']);
  const free = await base(kitGate, { scope: { edition: 'free', stage: 'LAUNCH', stageSource: 'STAGE.md' } });
  assert.equal(free.label, 'READY (FREE SCOPE)');
});

test('an owner row never overrides an engine FAIL; G-3 and G-7 and an incomplete run block READY', { skip }, async () => {
  const kitGate = await loadKitGate(KIT);
  const failRow = await base(kitGate, { rows: [{ ...settled[0], result: 'FAIL', notes: 'check' }, ...settled.slice(1)] });
  assert.equal(failRow.verdict, 'NOT READY');
  assert.ok(failRow.problems.some((p) => p.includes('cross check 1')), 'a FAIL with no fail record is a records problem, as in the kit');
  const noScan = await base(kitGate, { metas: [META('semgrep')] });
  assert.equal(noScan.conditions.find((c) => c.id === 'G-7')!.met, false);
  const incomplete = await base(kitGate, { findingsText: FINDINGS('incomplete') });
  assert.equal(incomplete.verdict, 'NOT READY');
  assert.equal(incomplete.runSupportsReady, false);
});

test('acceptance: a current CRITICAL acceptance outside the protected classes gives READY WITH ACCEPTED RISK; protected, expired or too long does not', { skip }, async () => {
  const kitGate = await loadKitGate(KIT);
  const rows = ownerRows.filter((r) => r.id !== 'SEC-DB-007');
  const accept = { id: 'SEC-DB-007', owner: 'Ada', approver: 'Grace', compensating_control: 'daily manual export', effective: '2026-10-01', expires: '2026-12-01' };
  const ok = await base(kitGate, { owner: { audit_report: 'docs/security/AUDIT.md', rollback: 'docs/security/ROLLBACK.md', results: rows, acceptances: [accept] } });
  assert.equal(ok.verdict, 'READY WITH ACCEPTED RISK', gateLines(ok).join('\n'));
  assert.deepEqual(ok.acceptancesUsed, ['SEC-DB-007']);
  const try1 = async (a: typeof accept, keep = 'SEC-DB-007'): Promise<string[]> => {
    const o = await base(kitGate, { owner: { audit_report: 'docs/security/AUDIT.md', rollback: 'docs/security/ROLLBACK.md', results: ownerRows.filter((r) => r.id !== keep), acceptances: [a] } });
    assert.equal(o.verdict, 'NOT READY');
    return o.acceptanceProblems;
  };
  assert.match((await try1({ ...accept, expires: '2026-10-05' }))[0], /expired/);
  assert.match((await try1({ ...accept, expires: '2027-03-01' }))[0], /more than 90 days/);
  assert.match((await try1({ ...accept, approver: 'ada' }))[0], /approver/);
  assert.match((await try1({ ...accept, id: 'SEC-AUTH-034' }, 'SEC-AUTH-034'))[0], /protected class/);
  assert.match((await try1({ ...accept, id: 'SEC-API-001' }, 'SEC-API-001'))[0], /BLOCKER is never accepted/);
});
