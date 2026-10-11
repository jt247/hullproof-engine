// A rule pack is loaded at run time by file name: it adds rule files and replaces an engine file with the same name.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readRules, ruleFiles } from '../src/scanners/semgrep.ts';
import { resolveRulePack } from '../src/commands/scan.ts';

const CORE = fileURLToPath(new URL('../rules/semgrep/', import.meta.url));
const makePack = (): string => {
  const pack = mkdtempSync(join(tmpdir(), 'hp-pack-'));
  writeFileSync(join(pack, 'added.yaml'), 'rules:\n  - id: added-rule\n    metadata:\n      sec_ids: [SEC-API-017]\n');
  return pack;
};

test('a rule pack adds files and replaces an engine file with the same name', () => {
  const core = ruleFiles(CORE);
  const pack = makePack();
  assert.equal(ruleFiles(CORE, pack).length, core.length + 1);
  const replaced = basename(core[0]);
  writeFileSync(join(pack, replaced), 'rules:\n  - id: replaced-rule\n    metadata:\n      sec_ids: [SEC-API-017]\n');
  const files = ruleFiles(CORE, pack);
  assert.equal(files.length, core.length + 1);
  assert.equal(files.find((f) => basename(f) === replaced), join(pack, replaced));
  const ids = readRules(CORE, pack).map((r) => r.id);
  assert.ok(ids.includes('replaced-rule') && ids.includes('added-rule'));
  assert.equal(new Set(ids).size, ids.length, 'rule ids stay unique');
});

test('resolveRulePack: none, a folder, a missing folder, a folder with no rule file', () => {
  const env = process.env.HULLPROOF_RULE_PACK;
  delete process.env.HULLPROOF_RULE_PACK;
  try {
    const pack = makePack();
    assert.deepEqual(resolveRulePack(null), { path: null });
    assert.deepEqual(resolveRulePack(pack), { path: pack });
    assert.match(resolveRulePack(join(pack, 'missing')) as string, /does not exist/);
    const empty = mkdtempSync(join(tmpdir(), 'hp-pack-empty-'));
    mkdirSync(join(empty, 'x'));
    assert.match(resolveRulePack(empty) as string, /holds no \.yaml rule file/);
    process.env.HULLPROOF_RULE_PACK = pack;
    assert.deepEqual(resolveRulePack(null), { path: pack });
  } finally {
    if (env === undefined) delete process.env.HULLPROOF_RULE_PACK; else process.env.HULLPROOF_RULE_PACK = env;
  }
});
