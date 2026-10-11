// Rule test harness for the engine's own Semgrep rules (rules/semgrep/taint-*.yaml): every rule file has a fixture in
// test/fixtures/rules/ with the same name, every rule has "ruleid" and "ok" lines there, and semgrep --test passes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readRules } from '../src/scanners/semgrep.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const RULES = join(ROOT, 'rules/semgrep');
const FIXTURES = join(ROOT, 'test/fixtures/rules');
const own = readdirSync(RULES).filter((n) => /^taint-.*\.yaml$/.test(n)).sort();
const fixtures = readdirSync(FIXTURES).sort();
const semgrep = spawnSync('semgrep', ['--version'], { encoding: 'utf8' });
const noSemgrep = semgrep.status === 0 ? false : 'semgrep is not installed';

test('every engine rule has a CWE, a requirement ID list, and positive and negative fixture lines', () => {
  assert.ok(own.length >= 5, 'taint rule files present');
  for (const f of own) {
    const stem = f.replace(/\.yaml$/, '');
    const fx = fixtures.filter((n) => n.startsWith(stem + '.'));
    assert.ok(fx.length, `${f} has no fixture in test/fixtures/rules`);
    const text = fx.map((n) => readFileSync(join(FIXTURES, n), 'utf8')).join('\n');
    const yaml = readFileSync(join(RULES, f), 'utf8');
    assert.match(yaml, /^# SPDX-License-Identifier: Apache-2\.0$/m, `${f} licence header`);
    assert.doesNotMatch(yaml, /registry\.semgrep|semgrep-rules/, `${f} names a registry source`);
    for (const r of readRules(RULES).filter((x) => x.file === f)) {
      assert.match(text, new RegExp(`ruleid: ${r.id}\\b`), `${r.id} has a positive fixture line`);
      assert.match(text, new RegExp(`ok: ${r.id}\\b`), `${r.id} has a negative fixture line`);
    }
    // The list may be empty in an edition whose controls file lacks the requirements a rule maps to.
    assert.equal((yaml.match(/^\s+sec_ids: \[/gm) ?? []).length, readRules(RULES).filter((x) => x.file === f).length, `${f}: sec_ids listed for every rule`);
    assert.equal((yaml.match(/^\s+cwe: "CWE-\d+/gm) ?? []).length, readRules(RULES).filter((x) => x.file === f).length, `${f}: one CWE per rule`);
  }
});

test('semgrep --test passes on the engine rule fixtures', { skip: noSemgrep }, () => {
  const r = spawnSync('semgrep', ['--test', '--metrics=off', '--disable-version-check', '--config', RULES, FIXTURES], { encoding: 'utf8', cwd: ROOT });
  const out = `${r.stdout}\n${r.stderr}`;
  assert.equal(r.status, 0, out);
  assert.match(out, /All tests passed/, out);
});
