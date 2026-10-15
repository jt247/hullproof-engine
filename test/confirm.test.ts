// The confirmation engine (open): lead schema, honesty check, map query language, agreement, replay, the synthesis guard.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { confirmHunt } from '../src/confirm/confirm.ts';
import { groupLeads, leadKey } from '../src/confirm/agreement.ts';
import { checkLead, FileCache } from '../src/confirm/honesty.ts';
import { MODEL_OUTPUT_SCHEMA, parseOutput } from '../src/confirm/lead.ts';
import { parseQuery, runQuery } from '../src/confirm/query.ts';
import { guardSynthesis } from '../src/confirm/synthesis.ts';
import { stableJson } from '../src/util.ts';
import { readFileSync } from 'node:fs';
import { validate } from './helpers/schema.ts';
import { answer, appCopy, boLead, DELETE_ID, EXPORT_ID, incomplete, planOf, proposal } from './helpers/hunt.ts';

const { repo, map } = appCopy();
const confirm = (answers: ReturnType<typeof answer>[], plan = null as ReturnType<typeof planOf> | null) => confirmHunt({ repo, map, answers, plan, commit: 'c'.repeat(40) });

test('the model output schema is strict shaped: every property required, no extras', () => {
  const walk = (s: any): void => {
    if (s.type === 'object') { assert.equal(s.additionalProperties, false); assert.deepEqual([...s.required].sort(), Object.keys(s.properties).sort()); Object.values<any>(s.properties).forEach(walk); }
    if (s.items) walk(s.items);
  };
  walk(MODEL_OUTPUT_SCHEMA);
});

test('lead schema: a good lead parses; limits and a wrong entry point are malformed, not hallucinations', () => {
  const ok = parseOutput({ leads: [boLead()] }, DELETE_ID);
  assert.equal(ok.leads.length, 1);
  assert.equal(ok.leads[0].evidence_proposal.kind, 'map_query');
  const bad = parseOutput({ leads: [boLead({ entry_point: 'other' }), boLead({ requirement_ids: ['nope'] }), boLead({ claim: '' }), boLead({ path: [] }), 5] }, DELETE_ID);
  assert.equal(bad.leads.length, 0);
  assert.equal(bad.malformed.length, 5);
  assert.equal(parseOutput('text', DELETE_ID).malformed.length, 1);
  const noQuery = parseOutput({ leads: [boLead({ evidence_proposal: proposal('map_query', { query_json: '{not json' }) })] }, DELETE_ID);
  assert.equal(noQuery.leads[0].evidence_proposal.kind, 'none');
});

test('honesty: a lead that cites a missing file, a line past the end or code that is not there is dropped and counted', () => {
  const files = new FileCache(repo);
  const lead = (o: Parameters<typeof boLead>[0]) => parseOutput({ leads: [boLead(o)] }, DELETE_ID).leads[0];
  assert.deepEqual(checkLead(lead({}), files, map), { ok: true });
  const reasons = [
    checkLead(lead({ path: [{ file: 'nope.js', line: 1, note: 'x' }] }), files, map),
    checkLead(lead({ path: [{ file: 'server.js', line: 9999, note: 'x' }] }), files, map),
    checkLead(lead({ path: [{ file: '../etc/passwd', line: 1, note: 'x' }] }), files, map),
    checkLead(lead({ quoted_code: "db.run('DELETE FROM accounts WHERE id = ?', [id]);" }), files, map),
    checkLead(lead({ quoted_code: 'db.run(' }), files, map),
    checkLead(lead({ path: [{ file: 'server.js', line: 60, note: 'x' }] }), files, map),
  ];
  for (const r of reasons) assert.equal(r.ok, false);
  const out = confirm([answer(1, DELETE_ID, [boLead(), boLead({ lead_id: 'F1', path: [{ file: 'ghost.js', line: 3, note: 'x' }] }), boLead({ lead_id: 'F2', quoted_code: 'invented(code)()' })])]);
  assert.equal(out.hallucinations.count, 2);
  assert.equal(out.confirmed.length, 1);
});

test('map query: the planted flaw is confirmed, and the confirmed finding names the evidence', () => {
  const out = confirm([answer(1, DELETE_ID, [boLead()])]);
  assert.equal(out.confirmed.length, 1);
  const c = out.confirmed[0].confirmation;
  assert.equal(c.status, 'confirmed');
  if (c.status === 'confirmed') { assert.equal(c.method, 'map_query'); assert.equal(c.tool, 'hullproof-hunt'); assert.match(c.rule_id, /^hunt\.query\.[0-9a-f]{12}$/); assert.match(c.config_sha256, /^[0-9a-f]{64}$/); }
});

test('map query: a query that does not hold, matches everything or touches no cited line leaves a lead', () => {
  const q = (where: unknown) => JSON.stringify({ where });
  const lead = (where: unknown, o = {}) => boLead({ evidence_proposal: proposal('map_query', { query_json: q(where) }), ...o });
  const cases: [string, ReturnType<typeof boLead>][] = [
    ['does not match', lead({ field: 'kind', op: 'eq', value: 'webhook' })],
    ['all entry points', lead({ field: 'id', op: 'exists' })],
    ['no cited line', lead({ some: 'data', where: { field: 'op', op: 'eq', value: 'delete' } }, { path: [{ file: 'server.js', line: 34, note: 'reply of another route' }], quoted_code: 'res.json({ ok: true });' })],
    ['no fact at all', lead({ all: [{ field: 'kind', op: 'eq', value: 'http_route' }, { field: 'method', op: 'eq', value: 'DELETE' }] })],
    ['owner filter present on a different entry', lead({ some: 'protections', where: { field: 'kind', op: 'eq', value: 'owner_filter' } })],
  ];
  for (const [name, l] of cases) {
    const out = confirm([answer(1, DELETE_ID, [l])]);
    assert.equal(out.confirmed.length, 0, name);
    assert.equal(out.leads.length, 1, name);
    assert.equal(out.leads[0].confirmation.status, 'not_confirmed', name);
  }
});

test('query language: validation refuses regex like fields, deep nesting and unknown operators', () => {
  assert.equal(parseQuery({ where: { field: 'a', op: 'matches', value: 'x' } }).ok, false);
  assert.equal(parseQuery({ where: { field: '__proto__.x', op: 'eq', value: 1 } }).ok, false);
  assert.equal(parseQuery({ where: { all: [] } }).ok, false);
  let deep: any = { field: 'kind', op: 'eq', value: 'x' };
  for (let i = 0; i < 10; i++) deep = { not: deep };
  assert.equal(parseQuery({ where: deep }).ok, false);
  assert.equal(parseQuery({ where: { field: 'tags', op: 'contains', value: 'admin' } }).ok, true);
  const r = runQuery(map, { where: { field: 'tags', op: 'contains', value: 'state_changing' } }, DELETE_ID, []);
  assert.equal(r.confirmed, false);
});

test('agreement: identity is entry point, requirement and sink; the count only orders leads', () => {
  const a = parseOutput({ leads: [boLead()] }, DELETE_ID).leads[0];
  const sameSinkOtherId = parseOutput({ leads: [boLead({ lead_id: 'zzz', claim: 'other words' })] }, DELETE_ID).leads[0];
  const otherReq = parseOutput({ leads: [boLead({ requirement_ids: ['SEC-API-017'] })] }, DELETE_ID).leads[0];
  assert.equal(leadKey(a), leadKey(sameSinkOtherId));
  assert.notEqual(leadKey(a), leadKey(otherReq));
  const groups = groupLeads([{ run: 1, lead: a }, { run: 2, lead: sameSinkOtherId }, { run: 2, lead: a }, { run: 3, lead: otherReq }]);
  assert.deepEqual(groups.map((g) => g.runs.length).sort(), [1, 2]);
  // Agreement never confirms: three runs of an unconfirmable lead stay a lead.
  const weak = boLead({ evidence_proposal: proposal('none') });
  const out = confirm([1, 2, 3].map((r) => answer(r, DELETE_ID, [weak])));
  assert.equal(out.confirmed.length, 0);
  assert.equal(out.leads[0].runs_raised, 3);
  // And a confirmed lead raised once is as confirmed as one raised three times.
  assert.equal(confirm([answer(2, DELETE_ID, [boLead()])]).confirmed.length, 1);
  const mixed = confirm([answer(1, DELETE_ID, [weak]), answer(2, DELETE_ID, [weak]), answer(1, EXPORT_ID, [boLead({ entry_point: EXPORT_ID, lead_id: 'E', requirement_ids: ['SEC-API-018'], path: [{ file: 'server.js', line: 23, note: 'r' }, { file: 'server.js', line: 24, note: 'q' }], quoted_code: "res.json(db.all('SELECT id, email FROM users', []));", evidence_proposal: proposal('none') })])]);
  assert.deepEqual(mixed.leads.map((l) => l.runs_raised), [2, 1]);
});

test('incomplete calls and calls never saved are reported, and nothing is retried around them', () => {
  const plan = planOf(map, 2);
  const out = confirm([answer(1, DELETE_ID, [boLead()]), incomplete(2, DELETE_ID, 'rate_limit')], plan);
  assert.equal(out.calls.incomplete, 1);
  assert.equal(out.calls.missing, plan.entries.length * 2 - 2);
  assert.deepEqual(out.incomplete.find((i) => i.entry_id === DELETE_ID && i.run === 2), { entry_id: DELETE_ID, run: 2, stop: 'rate_limit', detail: 'stopped' });
});

test('replay: the same saved answers give byte identical results three times', () => {
  const answers = [1, 2, 3].map((r) => answer(r, DELETE_ID, [boLead(), boLead({ lead_id: 'H', quoted_code: 'made(up)()' })]));
  const runs = [0, 1, 2].map(() => stableJson(confirm(answers, planOf(map, 3))));
  assert.equal(runs[0], runs[1]);
  assert.equal(runs[1], runs[2]);
});

test('the synthesis guard keeps a summary and explanations of known keys, and nothing else', () => {
  const result = confirm([answer(1, DELETE_ID, [boLead()]), answer(1, EXPORT_ID, [boLead({ lead_id: 'w', entry_point: EXPORT_ID, path: [{ file: 'server.js', line: 24, note: 'q' }], quoted_code: "res.json(db.all('SELECT id, email FROM users', []));", evidence_proposal: proposal('none') })])]);
  const before = stableJson(result);
  const key = result.confirmed[0].key;
  const g = guardSynthesis(result, {
    summary: 'The delete route is open.', explanations: [{ key, text: 'It lacks an owner check.' }, { key: 'invented', text: 'a new finding' }],
    confirmed: [], leads: [], findings: [{ id: 'new' }], remove: [key], severity: 'LOW',
  }, { provider: 'mock', model: 'm', usage: { input_tokens: 1, output_tokens: 1 } });
  assert.equal(stableJson(result), before, 'the result is untouched');
  assert.deepEqual(g.explanations, [{ key, text: 'It lacks an owner check.' }]);
  assert.deepEqual(Object.keys(g).sort(), ['detail', 'explanations', 'model', 'provider', 'schema_version', 'status', 'stop', 'summary', 'usage']);
});

test('result.json and a model output follow their schemas', () => {
  const sch = (n: string) => JSON.parse(readFileSync(new URL(`../schemas/${n}`, import.meta.url), 'utf8'));
  const result = confirm([answer(1, DELETE_ID, [boLead(), boLead({ lead_id: 'h', quoted_code: 'made(up)()' })]), incomplete(2, DELETE_ID, 'refusal')], planOf(map, 2));
  assert.deepEqual(validate(sch('hunt-result.schema.json'), JSON.parse(stableJson(result))), []);
  assert.deepEqual(validate(sch('hunt-output.schema.json'), { leads: [boLead()] }), []);
  assert.notDeepEqual(validate(sch('hunt-output.schema.json'), { leads: [{ lead_id: 'x' }] }), []);
});

test('lead schema: an over long claim is shortened and marked, an empty requirement list is allowed', () => {
  const r = parseOutput({ leads: [boLead({ claim: 'x'.repeat(900) }), boLead({ claim: 'short' }), boLead({ requirement_ids: [] })] }, DELETE_ID);
  assert.equal(r.malformed.length, 0);
  assert.equal(r.leads.length, 3);
  assert.equal(r.leads[0].claim.length, 500);
  assert.equal(r.leads[0].claim_truncated, true);
  assert.ok(!('claim_truncated' in r.leads[1]));
  assert.deepEqual(r.leads[2].requirement_ids, []);
  // a list over six ids or an id that is not written like SEC-XXX-000 is still malformed
  const bad = parseOutput({ leads: [boLead({ requirement_ids: ['nope'] }), boLead({ requirement_ids: Array.from({ length: 7 }, () => 'SEC-XXX-000') })] }, DELETE_ID);
  assert.equal(bad.malformed.length, 2);
});

test('a truncated claim and an empty requirement list reach the result; a lead that names no requirement is still a lead', () => {
  const longLead = boLead({ claim: 'y'.repeat(700), requirement_ids: [] });
  const res = confirm([answer(1, DELETE_ID, [longLead])]);
  const all = [...res.confirmed, ...res.leads];
  assert.equal(all.length, 1);
  assert.equal(all[0].claim_truncated, true);
  assert.deepEqual(all[0].requirement_ids, []);
});
