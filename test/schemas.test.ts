// The JSON schemas in schemas/ parse, accept a valid example, reject a broken one, and the findings schema matches the kit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CheckDefinition, CheckResultsFile, CodeCheckDefinition, FindingsFile, HitsFile, ResultsFile, ToolMeta } from '../src/types/index.ts';
import { validate } from './helpers/schema.ts';
import { KIT } from './helpers/kit.ts';

const DIR = fileURLToPath(new URL('../schemas/', import.meta.url));
const load = (n: string) => JSON.parse(readFileSync(DIR + n, 'utf8'));
const KIT_FINDINGS = process.env.HULLPROOF_KIT_FINDINGS_SCHEMA
  ?? join(KIT, 'docs/hullproof/findings.schema.json');

test('every schema file parses', () => {
  const names = readdirSync(DIR).filter((n) => n.endsWith('.schema.json'));
  assert.deepEqual(names.sort(), ['check-results.schema.json', 'check.schema.json', 'codemap.schema.json', 'findings.schema.json', 'results.schema.json', 'scan-hits.schema.json', 'scan-meta.schema.json', 'stack.schema.json']);
  for (const n of names) assert.doesNotThrow(() => load(n), n);
});

test('scan hits and meta examples', () => {
  const hits: HitsFile = { schema_version: '1.0.0', tool: 'semgrep', hits: [
    { tool: 'semgrep', rule_id: 'hullproof.sql-injection', file: 'src/db.ts', line: 12, sec_ids: ['SEC-DB-003'], severity_hint: 'ERROR', message_key: 'semgrep:hullproof.sql-injection' },
  ] };
  assert.deepEqual(validate(load('scan-hits.schema.json'), hits), []);
  assert.notDeepEqual(validate(load('scan-hits.schema.json'), { ...hits, hits: [{ ...hits.hits[0], file: '/abs/path.ts' }] }), []);
  const meta: ToolMeta = { schema_version: '1.0.0', tool: 'gitleaks', status: 'skipped: not installed', version: null, tested_version_range: '>=8.30 <9',
    version_tested: false, argv: [], config_sha256: null, commit: null, files_scanned: null, files_tracked: null, exit_code: null, db_date: null, not_assessed_sec_ids: ['SEC-SECRETS-004'] };
  assert.deepEqual(validate(load('scan-meta.schema.json'), meta), []);
});

test('check definition, check results and results examples', () => {
  const def: CheckDefinition = { id: 'check.supply.lockfile-committed', sec_ids: ['SEC-SUPPLY-002'], applies_when: { package_managers: '*' },
    op: 'file_exists_for_each', params: { for: 'package_managers' }, on_true: 'PASS (static)', on_false: 'FAIL',
    fixtures: { pass: 'test/fixtures/checks/lockfile/pass', fail: 'test/fixtures/checks/lockfile/fail' } };
  assert.deepEqual(validate(load('check.schema.json'), def), []);
  assert.notDeepEqual(validate(load('check.schema.json'), { ...def, on_false: 'NOT ASSESSED' }), [], 'NOT ASSESSED needs a sub state');
  const code: CodeCheckDefinition = { id: 'check.api.webhook-verified-before-use', sec_ids: ['SEC-API-101'], applies_when: {}, op: 'code', module: 'src/checks/code/webhook-verify.ts',
    on_true: 'NOT ASSESSED: NEEDS DYNAMIC TEST', on_false: 'FAIL', fixtures: { pass: 'test/fixtures/checks/webhook-verified-before-use/pass', fail: 'test/fixtures/checks/webhook-verified-before-use/fail' } };
  assert.deepEqual(validate(load('check.schema.json'), code), [], 'a code check names its module');
  const { module: _m, ...noModule } = code;
  assert.notDeepEqual(validate(load('check.schema.json'), noModule), [], 'a code check needs module');
  const { params: _p, ...noParams } = def;
  assert.notDeepEqual(validate(load('check.schema.json'), noParams), [], 'a declarative check needs params');
  const res: CheckResultsFile = { schema_version: '1.0.0', commit: null, not_run: [], results: [
    { check_id: def.id, sec_ids: def.sec_ids, result: 'FAIL', evidence: [{ file: 'package.json', key: 'dependencies', note: 'no lockfile next to this manifest' }],
      absence_search: { pattern: 'package-lock.json', files_searched: 40, file_globs: ['**/package-lock.json'], matches: 0 }, message_key: def.id },
  ] };
  assert.deepEqual(validate(load('check-results.schema.json'), res), []);
  const rows: ResultsFile = [{ id: 'SEC-SUPPLY-002', result: 'FAIL', notes: '' }, { id: 'SEC-WEB-022', result: 'NOT ASSESSED: NEEDS DYNAMIC TEST', notes: '' }];
  assert.deepEqual(validate(load('results.schema.json'), rows), []);
});

test('findings 1.1.0: a rule hit with machine_evidence is a finding without a trace', () => {
  const f: FindingsFile = {
    schema_version: '1.1.0',
    report: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), tree_clean: true, stage: 'LAUNCH', profile: 'standard', scope: 'full', run_status: 'complete', agent_calls: 0, budget: null },
    records: [{
      fingerprint: 'SEC-DB-003:src/db.ts:sql-built-from-input', kind: 'fail', sec_ids: ['SEC-DB-003'], title: 'SQL built from request input',
      class: 'finding', gap_in_standard: false, severity: 'CRITICAL', confidence: 'VERIFIED', demonstrated: false, root_cause: 'string concatenation into a query',
      raised_by: ['hullproof-engine'], impact_statement: 'A caller can read other rows.',
      remediation: { strategy: 'Use a parameterised query.', confirm: 'Rerun hullproof scan; the rule no longer fires.' },
      evidence: [{ file: 'src/db.ts', line: 12, note: 'query built with +' }],
      machine_evidence: { tool: 'semgrep', rule_id: 'hullproof.sql-injection', tool_version: '1.176.0', config_sha256: 'c'.repeat(64) },
    }],
  };
  assert.deepEqual(validate(load('findings.schema.json'), f), []);
});

test('schemas/findings.schema.json is the same as the kit file', { skip: existsSync(KIT_FINDINGS) ? false : 'kit not present' }, () => {
  assert.equal(readFileSync(DIR + 'findings.schema.json', 'utf8'), readFileSync(KIT_FINDINGS, 'utf8'),
    'copy the kit file again: cp <kit>/docs/hullproof/findings.schema.json schemas/');
});
