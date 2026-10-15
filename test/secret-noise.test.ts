// Secret hits that are example values do not hold the gate; real looking secrets in source, config and test source files still do.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { secretNoise, valueNoise, pathNoise } from '../src/scanners/secret-noise.ts';
import { runScanner } from '../src/scanners/index.ts';
import { adapter as gitleaks } from '../src/scanners/gitleaks.ts';
import { spawnSync } from 'node:child_process';

const REAL = 'k3J9xQ2mV8pL5nR7tY1wZ4bC6dF0gH3a';
const b64 = (j: string): string => Buffer.from(j).toString('base64url');
const AKIA = ['AKIA', 'Z7Q2M5XN3KDW4PBT'].join('');

test('a shapeless rule in documentation, fixture data, an example env, a lockfile, vendored code or a migration is an example value', () => {
  const line = `apiKey = "${REAL}"`;
  for (const f of ['docs/setup.md', 'README.md', 'api-docs/api.yaml', 'tests/fixtures/a/data.json', 'spec/testdata/x.yml', '.env.example', 'config/app.env.sample', 'package-lock.json',
    'vendor/lib/x.js', 'web/static/plugins/editor/x.js', 'app/migrations/0001_init.py', 'db/migrate/20240101_x.rb', 'src/api.pb.go', 'tests/data/users.json']) {
    assert.ok(secretNoise('generic-api-key', f, line), f);
  }
});

test('a real looking secret in source, config and test source files still holds', () => {
  const line = `apiKey = "${REAL}"`;
  for (const f of ['src/client.ts', 'app/config.py', 'config/production.yml', 'server.js', 'tests/auth.test.ts', 'src/test/java/app/LoginTest.java', 'tests/Feature/LoginTest.php', 'docs/.vitepress/config.mts', '.env', 'dist/app.js', 'public/app.js']) {
    assert.equal(secretNoise('generic-api-key', f, line), null, f);
  }
});

test('a rule with a vendor shape holds in documents and fixtures too, because a real key there is still a leak', () => {
  for (const rule of ['aws-access-token', 'github-pat', 'stripe-access-token', 'private-key', 'hullproof-supabase-service-role']) {
    assert.equal(secretNoise(rule, 'docs/setup.md', `key = "${AKIA}"`), null, rule);
    assert.equal(secretNoise(rule, 'tests/fixtures/x.json', `key = "${AKIA}"`), null, rule);
  }
});

test('placeholder and published example values are not secrets in any file', () => {
  for (const l of [['curl --header "X-Api', '-Key: your-api-key" https://x'].join(''), 'const key = "AKIAIOSFODNN7EXAMPLE"', 'const token = "xxxxxxxxxxxxxxxxxxxxxxxx"', 'API_KEY=12345678-1234-1234-1234-123456789abc',
    'password: "<your-password-here>"', 'key: ${API_KEY_VALUE}', `var token = "${b64('{"alg":"HS256","typ":"JWT"}')}.${b64('{"sub":"1234567890","name":"John Doe","iat":1516239022}')}.signature-part"`]) {
    assert.ok(valueNoise(l), l);
    assert.ok(secretNoise('aws-access-token', 'src/config.js', l), l);
  }
  assert.equal(valueNoise(`apiKey = "${REAL}"`), null);
  assert.equal(valueNoise(`apiKey = "${REAL}" // example of the call`), null, 'a comment that says example does not hide a key on the same line');
  assert.equal(pathNoise('src/app.ts'), null);
});

const plant = (files: Record<string, string>): string => {
  const dir = mkdtempSync(join(tmpdir(), 'hp-noise-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  spawnSync('git', ['init', '-q'], { cwd: dir });
  return dir;
};

test('end to end with Gitleaks: planted keys in source and test files hold, the same shapes in docs and fixtures are marked as examples', { skip: spawnSync('gitleaks', ['version']).status !== 0 }, () => {
  const repo = plant({
    'src/client.ts': `const apiKey = "${REAL}";\n`,
    'src/aws.js': `const k = "${AKIA}";\n`,
    'tests/auth.test.ts': `const apiKey = "${REAL}";\n`,
    'docs/setup.md': `apiKey = "${REAL}"\n`,
    'docs/aws.md': `aws key ${AKIA}\n`,
    'tests/fixtures/data.json': `{"api_key": "${REAL}"}\n`,
    '.env.example': `SECRET_KEY="${REAL}"\n`,
  });
  const out = mkdtempSync(join(tmpdir(), 'hp-noise-out-'));
  mkdirSync(join(out, 'scan'));
  const res = runScanner(gitleaks, { repo, out, stack: {} as never, allowNetwork: false, edition: 'free' });
  const byFile = new Map(res.detail.hits.map((h) => [h.file, h]));
  for (const f of ['src/client.ts', 'src/aws.js', 'tests/auth.test.ts', 'docs/aws.md']) assert.ok(byFile.get(f), `${f} was found`), assert.equal(byFile.get(f)!.noise, undefined, `${f} holds`);
  for (const f of ['docs/setup.md', 'tests/fixtures/data.json', '.env.example']) {
    const h = byFile.get(f);
    if (h) assert.ok(h.noise, `${f} is an example value`);
  }
  assert.ok(byFile.get('docs/setup.md') || byFile.get('tests/fixtures/data.json') || byFile.get('.env.example'), 'at least one example file was found by the scanner, so the check above ran');
  assert.ok(res.hits.hits.filter((h) => h.noise).every((h) => /docs\/|fixtures\/|\.env\.example/.test(h.file)));
});

import { separateTestCode, type BuildInput } from '../src/report/build.ts';
import type { Hit } from '../src/types/index.ts';

test('separateTestCode: a secret stays in the gate, except one the scanner marked as an example value', () => {
  const g = (file: string, noise?: string): Hit => ({ tool: 'gitleaks', rule_id: 'generic-api-key', file, line: 3, sec_ids: ['SEC-SECRETS-004'], severity_hint: null, message_key: 'gitleaks:generic-api-key', ...(noise ? { noise } : {}) });
  const input = { hits: [g('src/a.ts'), g('tests/a.test.ts'), g('docs/a.md', 'documentation file')], checks: { schema_version: '1.0.0', commit: null, results: [], not_run: [] } } as unknown as BuildInput;
  const out = separateTestCode(input);
  assert.deepEqual(out.input.hits.map((h) => h.file), ['src/a.ts', 'tests/a.test.ts']);
  assert.deepEqual(out.test.map((t) => [t.hit!.file, t.reason]), [['docs/a.md', 'documentation file']]);
});

test('a short real password beside a variable named like an example still holds (TerraGoat regression)', () => {
  assert.equal(valueNoise('administrator_login_password = "Aa12345678"'), null);
  assert.equal(valueNoise('EXAMPLE_PASSWORD = "Aa12345678"'), null);
  assert.equal(secretNoise('hashicorp-tf-password', 'terraform/azure/sql.tf', 'administrator_login_password = "Aa12345678"'), null);
});
