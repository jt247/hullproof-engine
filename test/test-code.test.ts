// Test code handling: path conventions, and that test code findings never fail a requirement unless the requirement is
// about shipped test material.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { testCodeReason } from '../src/report/test-code.ts';
import { separateTestCode, type BuildInput } from '../src/report/build.ts';
import { TEST_ARTIFACT_IDS } from '../src/report/test-code.ts';
import type { CheckResult, Hit } from '../src/types/index.ts';

test('testCodeReason: folders and file names per language', () => {
  for (const f of ['test/api/user.test.ts', 'src/__tests__/a.js', 'frontend/src/app/nav/nav.component.spec.ts', 'app/tests.py',
    'pkg/handler_test.go', 'src/test/java/com/x/UserService.java', 'src/main/java/com/x/UserServiceTest.java', 'tests/Feature/LoginTest.php',
    'spec/models/user_spec.rb', 'pkg/testdata/in.json', 'examples/basic/server.js', 'e2e/login.cy.ts', 'a/conftest.py', 'a/test_views.py',
    'src/__mocks__/fs.ts', 'lib/data.fixture.ts', 'Api.Tests/UserTests.cs']) {
    assert.ok(testCodeReason(f), f);
  }
  for (const f of ['src/app.ts', 'testcode/BenchmarkTest00001.py', 'src/main/java/BenchmarkTest00001.java', 'lib/testing/helpers.go',
    'routes/contest.ts', 'src/latest.py', 'app/attestation.php', 'src/protest_test_data_loader.ts']) {
    assert.equal(testCodeReason(f), null, f);
  }
});

const hit = (file: string, sec_ids: string[]): Hit => ({ tool: 'semgrep', rule_id: 'r', file, line: 3, sec_ids, severity_hint: null, message_key: 'semgrep:r' });
const fail = (files: string[], sec_ids = ['SEC-AUTH-034']): CheckResult => ({
  check_id: 'check.web.cors-no-reflected-origin', sec_ids, result: 'FAIL', evidence: files.map((file) => ({ file, line: 1, note: 'n' })), absence_search: null, message_key: 'x',
});
const input = (hits: Hit[], results: CheckResult[]): BuildInput =>
  ({ hits, checks: { schema_version: '1.0.0', commit: null, results, not_run: [] } } as unknown as BuildInput);

test('separateTestCode: test path hits leave the gate, shipped test material requirements stay', () => {
  const { input: out, test: t } = separateTestCode(input([
    hit('src/db.ts', ['SEC-API-017']),
    hit('test/db.test.ts', ['SEC-API-017']),
    hit('test/Dockerfile', []),
  ], []));
  assert.deepEqual(out.hits.map((h) => [h.file, h.sec_ids]), [['src/db.ts', ['SEC-API-017']]]);
  assert.deepEqual(t.map((x) => [x.hit!.file, x.ids]), [['test/db.test.ts', ['SEC-API-017']], ['test/Dockerfile', []]]);
});

// The IDs come from rules/test-artifact-ids.json, so an edition whose file lists none has nothing to keep.
test('separateTestCode: a requirement about shipped test material keeps failing in a test path', { skip: TEST_ARTIFACT_IDS.size ? false : 'this edition lists no such requirement' }, () => {
  const [art] = [...TEST_ARTIFACT_IDS];
  const { input: out, test: t } = separateTestCode(input([hit('test/seed.ts', [art, 'SEC-API-017'])], []));
  assert.deepEqual(out.hits.map((h) => [h.file, h.sec_ids]), [['test/seed.ts', [art]]]);
  assert.deepEqual(t.map((x) => [x.hit!.file, x.ids]), [['test/seed.ts', ['SEC-API-017']]]);
});

test('separateTestCode: a failed check keeps its shipped evidence and drops out when all evidence is test code', () => {
  const mixed = separateTestCode(input([], [fail(['lib/a.ts', 'test/a.spec.ts'])]));
  assert.deepEqual(mixed.input.checks.results[0].evidence.map((e) => e.file), ['lib/a.ts']);
  assert.deepEqual(mixed.test[0].check!.evidence.map((e) => e.file), ['test/a.spec.ts']);
  const onlyTest = separateTestCode(input([], [fail(['test/a.spec.ts'])]));
  assert.equal(onlyTest.input.checks.results.length, 0);
  const absence = separateTestCode(input([], [fail([])]));
  assert.equal(absence.input.checks.results.length, 1, 'a FAIL with no evidence still fails');
});
