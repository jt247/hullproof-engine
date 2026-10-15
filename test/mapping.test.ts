// Mapping of scanner hits to requirement IDs, the dependency policy, and that the rules copy matches the kit.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONTROLS, inEdition, loadControls } from '../src/mapping/controls.ts';
import { loadTable, mapHit } from '../src/mapping/map.ts';
import { classFromScore, classFromWord, decide, DEFAULT_POLICY } from '../src/mapping/dependency-policy.ts';
import { readRules } from '../src/scanners/semgrep.ts';
import { sha256 } from '../src/scanners/common.ts';
import { KIT, NEEDS_PRO_KIT } from './helpers/kit.ts';
import { EXTRA_RULE_DIRS } from './helpers/packs.ts';

const controls = loadControls();
const noKit = controls ? false : `controls file not found at ${DEFAULT_CONTROLS}`;
const INFRA = join(KIT, 'docs/hullproof/INFRASTRUCTURE-SECURITY.md');
const RULES = fileURLToPath(new URL('../rules/', import.meta.url));
const NEW_CLOUD = /^SEC-CLOUD-0(4[6-9]|5[0-2])$/;

test('every ID in the mapping tables exists in the controls file, or is a new cloud ID written in INFRASTRUCTURE-SECURITY.md', { skip: noKit || NEEDS_PRO_KIT }, () => {
  const infra = existsSync(INFRA) ? readFileSync(INFRA, 'utf8') : '';
  for (const tool of ['gitleaks', 'osv-scanner', 'trivy'] as const) {
    const t = loadTable(tool);
    const ids = [...t.rows.flatMap((r) => r.sec_ids), ...(t.client_code_sec_ids ?? [])];
    for (const id of ids) {
      if (controls!.byId.has(id)) continue;
      assert.match(id, NEW_CLOUD, `${tool}: ${id} is in neither the controls file nor the new cloud range`);
      assert.ok(infra.includes(`### ${id}:`), `${id} has no heading in INFRASTRUCTURE-SECURITY.md`);
    }
  }
});

test('trivy table: rows sorted, ids unique and shaped like Trivy check ids', () => {
  const rows = loadTable('trivy').rows;
  assert.deepEqual(rows.map((r) => r.rule_id), [...rows.map((r) => r.rule_id)].sort());
  assert.equal(new Set(rows.map((r) => r.rule_id)).size, rows.length);
  for (const r of rows) assert.match(r.rule_id, /^(AWS|AZU|GCP|DS)-\d{4}$/);
});

test('every Semgrep rule sec_id exists in the controls file, and every kit Semgrep test id is a rule we ship', { skip: noKit || NEEDS_PRO_KIT }, () => {
  const rules = readRules(join(RULES, 'semgrep'), EXTRA_RULE_DIRS[0] ?? null);
  for (const r of rules) for (const id of r.sec_ids) assert.ok(controls!.byId.has(id), `${r.id}: ${id}`);
  // The kit lists a rule for some requirements. The rules this edition ships are a part of the kit's rule set, so the
  // second half only holds for a working copy that also has the other rule files.
  if (!EXTRA_RULE_DIRS.length) return;
  const ruleIds = new Set(rules.map((r) => r.id));
  for (const [testId] of controls!.ruleToIds) {
    const kinds = [...controls!.byId.values()].flatMap((c) => c.tests).filter((t) => t.id === testId).map((t) => t.kind);
    if (kinds.includes('semgrep')) assert.ok(ruleIds.has(testId), `controls name Semgrep rule ${testId}, which is not in the rule folders`);
  }
});

test('mapHit: metadata first, then table rule id, then default; unmapped stays empty', () => {
  assert.deepEqual(mapHit({ tool: 'semgrep', rule_id: 'x', file: 'a.ts', metadataSecIds: ['SEC-API-017'] }, 'pro', null),
    { sec_ids: ['SEC-API-017'], mapped_by: 'rule metadata' });
  const row = loadTable('trivy').rows.find((r) => r.rule_id === 'AWS-0107');
  assert.deepEqual(mapHit({ tool: 'trivy', rule_id: 'AWS-0107', file: 'main.tf' }, 'pro', null),
    row ? { sec_ids: row.sec_ids, mapped_by: 'map rule_id' } : { sec_ids: [], mapped_by: 'none' });
  assert.deepEqual(mapHit({ tool: 'trivy', rule_id: 'DS-0031', file: 'Dockerfile' }, 'pro', null), { sec_ids: ['SEC-CLOUD-016'], mapped_by: 'map rule_id' });
  assert.deepEqual(mapHit({ tool: 'trivy', rule_id: 'AWS-9999', file: 'main.tf' }, 'pro', null), { sec_ids: [], mapped_by: 'none' });
  assert.deepEqual(mapHit({ tool: 'osv-scanner', rule_id: 'GHSA-x', file: 'package-lock.json' }, 'pro', null), { sec_ids: ['SEC-SUPPLY-002'], mapped_by: 'map default' });
});

test('mapHit gitleaks: tracked, untracked and client code paths', () => {
  const g = (file: string, tracked: boolean) => mapHit({ tool: 'gitleaks', rule_id: 'aws-access-token', file, tracked }, 'pro', null).sec_ids;
  assert.deepEqual(g('src/config.ts', true), ['SEC-SECRETS-004']);
  assert.deepEqual(g('src/config.ts', false), []);
  assert.deepEqual(g('.next/static/chunks/app.js', false), ['SEC-SECRETS-001']);
  assert.deepEqual(g('public/app.js', true), ['SEC-SECRETS-001', 'SEC-SECRETS-004']);
  assert.deepEqual(g('web/dist/main.js.map', true), ['SEC-SECRETS-001', 'SEC-SECRETS-004']);
});

test('free edition keeps only free IDs; an ID the controls file does not list counts as Pro', { skip: noKit }, () => {
  const unlisted = ['SEC', 'ZZZ', '999'].join('-');
  assert.deepEqual(inEdition(['SEC-SECRETS-004', unlisted], 'free', controls), ['SEC-SECRETS-004']);
  const pro = [...controls!.byId.values()].find((c) => c.edition === 'pro');
  if (pro) assert.deepEqual(inEdition([pro.id, 'SEC-SECRETS-004'], 'free', controls), ['SEC-SECRETS-004']);
  assert.deepEqual(mapHit({ tool: 'trivy', rule_id: 'DS-0031', file: 'Dockerfile' }, 'free', controls).sec_ids, ['SEC-CLOUD-016']);
});

test('dependency policy: classes from score and word, deadlines, fail and report', () => {
  assert.deepEqual([9.8, 7, 6.9, 4, 3.9, 0].map(classFromScore), ['CRITICAL', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW', 'UNKNOWN']);
  assert.deepEqual(['critical', 'HIGH', 'MODERATE', 'LOW', ''].map(classFromWord), ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
  assert.equal(decide('HIGH', '2026-10-09', '2026-10-10').decision, 'fail');
  assert.deepEqual(decide('MEDIUM', '2026-07-12', '2026-10-10'), { deadline_days: 90, past_deadline: false, decision: 'report' }); // day 90
  assert.deepEqual(decide('MEDIUM', '2026-07-11', '2026-10-10'), { deadline_days: 90, past_deadline: true, decision: 'fail' });  // day 91
  assert.equal(decide('LOW', '2026-04-14', '2026-10-10').decision, 'report');
  assert.equal(decide('LOW', '2026-04-12', '2026-10-10').decision, 'fail');
  assert.equal(decide('MEDIUM', null, '2026-10-10').decision, 'fail');
  assert.equal(decide('MEDIUM', null, '2026-10-10', { ...DEFAULT_POLICY, unknown_published: 'report' }).decision, 'report');
  assert.equal(decide('HIGH', '2026-10-09', '2026-10-10', { ...DEFAULT_POLICY, fail_always: ['CRITICAL'] }).decision, 'report');
});

for (const dir of [RULES, ...EXTRA_RULE_DIRS.map((d) => join(d, '..'))]) test(`rules copy in ${dir.endsWith('rules/') || dir.endsWith('rules') ? 'rules' : 'the extra rule folder'} matches the kit it names in SOURCE.json`, { skip: existsSync(join(dir, 'SOURCE.json')) ? NEEDS_PRO_KIT : 'no SOURCE.json' }, () => {
  const src = JSON.parse(readFileSync(join(dir, 'SOURCE.json'), 'utf8')) as { files: { path: string; source: string; source_sha256: string }[] };
  const kit = join(KIT, '..');
  for (const f of src.files) {
    const copy = readFileSync(join(dir, f.path), 'utf8');
    assert.match(copy, /^# SPDX-License-Identifier: Apache-2\.0/, `${f.path} licence header`);
    const body = copy.slice(copy.indexOf('\n#\n') + 3);
    assert.equal(sha256(body), f.source_sha256, `${f.path} was edited after the copy`);
    const kitFile = join(kit, f.source);
    if (existsSync(kitFile)) assert.equal(sha256(readFileSync(kitFile)), f.source_sha256, `${f.source} changed in the kit: run node rules/refresh.ts`);
  }
});
