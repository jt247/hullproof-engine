// The test spec language and the step executor: validation, the positive control rule, redaction, the verdicts, and the loopback only
// rule. These run against an in process fake app, so they need no container and no fixture folder.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { executeSpec, judge, loopbackBase, redactJson, redactText, runRecord } from '../src/prove/executor.ts';
import { canon, evalAssertion, fill, pathGet, specSha256, validateSpec } from '../src/prove/spec.ts';
import type { Spec, StepRecord } from '../src/types/index.ts';
import { asValid, fakeApp, idorSpec } from './helpers/prove.ts';

const bad = (s: unknown): string[] => { const v = validateSpec(s); assert.equal(v.ok, false, 'expected the spec to be rejected'); return v.ok ? [] : v.errors; };
const clone = (): Record<string, any> => JSON.parse(JSON.stringify(idorSpec()));

test('a good spec is accepted and unknown keys are dropped', () => {
  const raw = clone();
  raw.surprise = 'x';
  raw.steps[0].extra = 1;
  const v = validateSpec(raw);
  assert.equal(v.ok, true);
  if (v.ok) { assert.ok(!('surprise' in v.spec)); assert.ok(!('extra' in v.spec.steps[0])); }
});

test('the positive control rule: a spec without a passing control that comes first is invalid', () => {
  const noControl = clone(); noControl.steps = noControl.steps.filter((s: any) => s.phase !== 'control');
  assert.match(bad(noControl).join(' '), /positive control missing/);
  const late = clone(); late.steps = [late.steps[0], late.steps[1], late.steps[3], late.steps[2]];
  assert.match(bad(late).join(' '), /positive control missing/);
  const noSuccess = clone(); noSuccess.steps[2].assert = [{ kind: 'json', path: 'body', op: 'exists' }];
  assert.match(bad(noSuccess).join(' '), /2xx/);
  const emptyControl = clone(); emptyControl.steps[2].assert = [];
  assert.match(bad(emptyControl).join(' '), /at least one assertion/);
});

test('an attack that only asserts a denial proves nothing and is rejected', () => {
  const s = clone(); s.steps[3].assert = [{ kind: 'status', op: 'eq', value: 403 }];
  assert.match(bad(s).join(' '), /denial proves nothing/);
});

test('a path must be a path on the app: no host, no scheme, no protocol relative address, no dot dot', () => {
  for (const p of ['http://example.com/x', '//evil.test/x', 'api/notes', '/a/../b', '/a\\b', 'https://10.0.0.1/', '/x y']) {
    const s = clone(); s.steps[3].path = p;
    assert.ok(bad(s).some((e) => /path must start with one slash/.test(e)), p);
  }
});

test('headers: host and framing headers cannot be set, values are single lines', () => {
  for (const h of ['host', 'content-length', 'transfer-encoding', 'connection', 'x-forwarded-for', 'proxy-authorization']) {
    const s = clone(); s.steps[3].headers = { [h]: 'x' };
    assert.ok(bad(s).some((e) => /may not be set/.test(e)), h);
  }
  const s = clone(); s.steps[3].headers = { 'x-note': 'a\r\nb: c' };
  assert.ok(bad(s).some((e) => /single line/.test(e)));
});

test('payloads built to damage data or run code are rejected', () => {
  for (const v of ['1; DROP TABLE users', 'x; --', 'a union select b', '$(id)', '`id`', '../../etc/passwd', '<script>alert(1)</script>', 'rm -rf /', 'curl http://x']) {
    const s = clone(); s.steps[3].method = 'POST'; s.steps[3].body = { note: v };
    assert.ok(bad(s).some((e) => /payload_not_harmless/.test(e)), v);
  }
});

test('limits: steps, actors, body size, assertions per step', () => {
  const many = clone(); many.steps = Array.from({ length: 30 }, (_, i) => ({ ...many.steps[0], id: `s${i}` }));
  assert.match(bad(many).join(' '), /steps needs 2 to 24/);
  const big = clone(); big.steps[3].method = 'POST'; big.steps[3].body = { x: 'a'.repeat(5000) };
  assert.match(bad(big).join(' '), /small JSON object/);
  const asserts = clone(); asserts.steps[3].assert = Array.from({ length: 9 }, () => ({ kind: 'status', op: 'eq', value: 200 }));
  assert.match(bad(asserts).join(' '), /at most 8/);
});

test('variables must be captured before use, and an assertion cannot read or compare a secret', () => {
  const s = clone(); s.steps[2].path = '/api/notes/{{note_id}}';
  assert.match(bad(s).join(' '), /note_id.*before any step captures/);
  const t = clone(); t.steps[3].assert = [{ kind: 'status', op: 'eq', value: 200 }, { kind: 'json', path: 'user.password', op: 'exists' }];
  assert.match(bad(t).join(' '), /named like a secret/);
  const u = clone(); u.steps[3].assert = [{ kind: 'status', op: 'eq', value: 200 }, { kind: 'text', op: 'contains', value: '{{alice_token}}' }];
  assert.match(bad(u).join(' '), /secret that is redacted/);
});

test('setup steps come first, actors must be declared, methods are limited', () => {
  const a = clone(); a.steps[3].actor = 'mallory';
  assert.match(bad(a).join(' '), /actor is not declared/);
  const m = clone(); m.steps[3].method = 'TRACE';
  assert.match(bad(m).join(' '), /method must be one of/);
  const o = clone(); o.steps = [o.steps[0], o.steps[2], o.steps[1], o.steps[3]];
  assert.match(bad(o).join(' '), /setup steps come first/);
});

test('assertions: status, json paths, text, header', () => {
  const r = { status: 200, headers: { 'content-type': 'application/json' }, json: { a: { b: [{ c: 'x' }, 7] }, s: 'hello world' }, text: undefined, truncated: false };
  const ev = (a: any): boolean => evalAssertion(r, a, {}, new Set()).ok;
  assert.ok(ev({ kind: 'status', op: 'in', value: [200, 201] }));
  assert.ok(!ev({ kind: 'status', op: 'ne', value: 200 }));
  assert.ok(ev({ kind: 'json', path: 'a.b.0.c', op: 'eq', value: 'x' }));
  assert.ok(ev({ kind: 'json', path: 'a.b.1', op: 'eq', value: '7' }), 'a number equals its text form');
  assert.ok(ev({ kind: 'json', path: 's', op: 'contains', value: 'world' }));
  assert.ok(ev({ kind: 'json', path: 'a.zzz', op: 'absent' }));
  assert.ok(!ev({ kind: 'json', path: 'a.zzz', op: 'eq', value: 'x' }));
  assert.ok(ev({ kind: 'text', op: 'contains', value: 'hello' }));
  assert.ok(ev({ kind: 'header', name: 'content-type', op: 'contains', value: 'json' }));
  assert.equal(pathGet({ a: [1, 2] }, 'a.1'), 2);
  assert.equal(pathGet({ a: [1, 2] }, 'a.x'), undefined);
});

test('templates: unresolved variables fail, secrets show as redacted', () => {
  assert.throws(() => fill('/x/{{nope}}', {}, new Set(), false), /unresolved variable nope/);
  assert.equal(fill('Bearer {{t}}', { t: 'abc' }, new Set(['t']), true), 'Bearer [redacted]');
  assert.equal(fill('Bearer {{t}}', { t: 'abc' }, new Set(['t']), false), 'Bearer abc');
});

test('redaction: secret named fields, JWTs and long tokens never reach the transcript', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl';
  assert.equal(redactText(`token ${jwt} end`), 'token [redacted] end');
  assert.equal(redactText('key 0123456789abcdef0123456789abcdef01234567 end'), 'key [redacted] end');
  assert.equal(redactText('id 123e4567-e89b-12d3-a456-426614174000'), 'id 123e4567-e89b-12d3-a456-426614174000', 'a UUID is an id, not a secret');
  assert.deepEqual(redactJson({ password: 'hunter2', user: { api_key: 'k', name: 'alice' }, list: [{ session_id: 's1' }] }), { password: '[redacted]', user: { api_key: '[redacted]', name: 'alice' }, list: [{ session_id: '[redacted]' }] });
});

test('loopback only: anything but the sandbox own address is refused before a request is built', async () => {
  for (const u of ['http://example.com:80', 'https://127.0.0.1:3000', 'http://10.0.0.5:3000', 'http://127.0.0.1', 'http://user:pw@127.0.0.1:3000', 'http://127.0.0.1:3000/api', 'http://0.0.0.0:3000', 'not a url', 'http://169.254.169.254:80', 'http://[::1]:3000.evil.test']) {
    assert.throws(() => loopbackBase(u), /refused/, u);
  }
  assert.equal(loopbackBase('http://127.0.0.1:3000').port, '3000');
  const app = await fakeApp();
  try {
    let called = 0;
    await assert.rejects(executeSpec(idorSpec(), { baseUrl: 'https://prod.example.com:443', fetchFn: (async () => { called++; return new Response('x'); }) as typeof fetch }), /refused/);
    assert.equal(called, 0, 'no request was built');
    assert.equal(app.hits.length, 0);
  } finally { await app.close(); }
});

test('a path built from a captured value cannot leave the app', async () => {
  const app = await fakeApp();
  try {
    const s = asValid({ ...idorSpec(), actors: { anon: {} }, steps: [
      { id: 'login_alice', phase: 'setup', actor: 'anon', method: 'POST', path: '/api/login', body: { user: 'alice', password: 'alice-pass' }, captures: [{ name: 'who', from: 'json', path: 'user' }], assert: [{ kind: 'status', op: 'eq', value: 200 }] },
      { id: 'own', phase: 'control', actor: 'anon', method: 'GET', path: '/health', assert: [{ kind: 'status', op: 'eq', value: 200 }] },
      { id: 'x', phase: 'attack', actor: 'anon', method: 'GET', path: '/{{who}}', assert: [{ kind: 'status', op: 'eq', value: 200 }] }] });
    const r = await executeSpec(s, { baseUrl: `http://127.0.0.1:${app.port}` });
    assert.equal(r.outcome, 'not_proven');
    assert.ok(app.hits.every((h) => !h.startsWith('GET //')));
  } finally { await app.close(); }
});

test('verdicts: proven on a vulnerable app, not proven on a fixed one, invalid when the control fails, error when the app is down', async () => {
  const vuln = await fakeApp('vulnerable');
  const fixed = await fakeApp('fixed');
  try {
    const p = await executeSpec(idorSpec(), { baseUrl: `http://127.0.0.1:${vuln.port}` });
    assert.equal(p.outcome, 'proven', p.detail);
    const np = await executeSpec(idorSpec(), { baseUrl: `http://127.0.0.1:${fixed.port}` });
    assert.equal(np.outcome, 'not_proven', np.detail);
    assert.match(np.detail, /refused as it should/);
    const broken = idorSpec({ steps: idorSpec().steps.map((s) => (s.id === 'own' ? { ...s, path: '/api/notes/99' } : s)) });
    const inv = await executeSpec(broken, { baseUrl: `http://127.0.0.1:${vuln.port}` });
    assert.equal(inv.outcome, 'invalid');
    assert.match(inv.detail, /positive control failed/);
    const noLogin = idorSpec({ steps: idorSpec().steps.map((s) => (s.id === 'login_bob' ? { ...s, body: { user: 'bob', password: 'wrong' } } : s)) });
    assert.equal((await executeSpec(noLogin, { baseUrl: `http://127.0.0.1:${vuln.port}` })).outcome, 'invalid');
    await vuln.close();
    const down = await executeSpec(idorSpec(), { baseUrl: `http://127.0.0.1:${vuln.port}`, requestMs: 1500 });
    assert.equal(down.outcome, 'error');
  } finally { await fixed.close(); await vuln.close().catch(() => undefined); }
});

test('the transcript holds no token, header secret or password', async () => {
  const app = await fakeApp();
  try {
    const r = await executeSpec(idorSpec(), { baseUrl: `http://127.0.0.1:${app.port}` });
    const text = JSON.stringify(r.steps);
    assert.doesNotMatch(text, /abcdef0123456789/, 'the random token suffix');
    assert.doesNotMatch(text, /alice-pass|bob-pass/, 'no password');
    assert.match(text, /Bearer \{\{|\[redacted\]/);
    const login = r.steps[0];
    assert.equal(login.captures.alice_token, '[redacted]');
    assert.equal((login.request.body as Record<string, string>).password, '[redacted]');
  } finally { await app.close(); }
});

test('judge gives the live verdict from the stored records alone (this is what a replay does)', async () => {
  const app = await fakeApp();
  try {
    const spec = idorSpec();
    const live = await executeSpec(spec, { baseUrl: `http://127.0.0.1:${app.port}` });
    const stored = JSON.parse(JSON.stringify(live.steps)) as StepRecord[];
    const j = judge(spec, stored);
    assert.equal(j.outcome, live.outcome);
    // Tampering with a stored response changes the verdict, so a stored transcript cannot be edited into a proof.
    stored[stored.length - 1].response!.status = 403;
    assert.equal(judge(spec, stored).outcome, 'not_proven');
    const rec = runRecord(spec, specSha256(spec), 1, live);
    assert.match(rec.transcript_sha256, /^[0-9a-f]{64}$/);
    assert.equal(runRecord(spec, specSha256(spec), 1, live).transcript_sha256, rec.transcript_sha256);
  } finally { await app.close(); }
});

test('canon sorts keys and the spec hash does not depend on key order', () => {
  assert.equal(canon({ b: 1, a: { d: 1, c: 2 } }), '{"a":{"c":2,"d":1},"b":1}');
  const a = idorSpec();
  const b = JSON.parse(JSON.stringify(a), (_k, v) => v) as Spec;
  assert.equal(specSha256(a), specSha256({ ...b, steps: b.steps }));
});
