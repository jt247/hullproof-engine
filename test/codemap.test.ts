// The code map (Phase 2): entry points per stack on small synthetic apps, the checks that read the map on a fail and a pass
// copy of each app, honest degradation for languages with no extractor, determinism, the schema, and the CLI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../src/discover/discover.ts';
import { makeContext } from '../src/checks/context.ts';
import { loadChecks, runChecks } from '../src/checks/run.ts';
import { PRO_MAP_CHECKS } from '../src/checks/pro-map.ts';
import { getMap } from '../src/checks/map/shared.ts';
import { renderEntryPoints } from '../src/report/entry-points.ts';
import { separateTestCode, type BuildInput } from '../src/report/build.ts';
import { leadTierForCheck, loadTiers } from '../src/report/tiers.ts';
import { stableJson } from '../src/util.ts';
import type { CodeMap } from '../src/types/index.ts';
import { validate } from './helpers/schema.ts';
import { KIT, KIT_SKIP } from './helpers/kit.ts';
import { scan } from '../src/commands/scan.ts';
import { report } from '../src/commands/report-gate.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MAPS = join(ROOT, 'test/fixtures/map');
const schema = JSON.parse(readFileSync(join(ROOT, 'schemas/codemap.schema.json'), 'utf8'));
const CLI = join(ROOT, 'src/cli.ts');

const mapOf = (dir: string): CodeMap => { const ctx = makeContext(dir, discover(dir)); return getMap(ctx); };
const sig = (m: CodeMap, stack: string): string[] => m.entry_points.filter((e) => e.file.startsWith(stack + '/')).map((e) => `${e.kind} ${e.method ?? '-'} ${e.path ?? e.name}`).sort();

const EXPECTED: Record<string, string[]> = {
  nextapp: ['http_route DELETE /api/notes/:id', 'http_route GET /api/export', 'http_route GET /api/items', 'http_route POST /api/admin/users', 'http_route POST /api/import',
    'http_route POST /api/login', 'http_route POST /api/notes', 'http_route POST /api/upload', 'server_action POST updateProfile', 'webhook POST /api/webhooks/pay'],
  express: ['http_route DELETE /api/notes/:id', 'http_route GET /api/export', 'http_route GET /api/items', 'http_route POST /api/admin/users', 'http_route POST /api/import',
    'http_route POST /api/login', 'http_route POST /api/notes', 'http_route POST /api/upload', 'webhook POST /webhooks/pay'],
  nest: ['http_route DELETE /notes/:id', 'http_route GET /notes', 'http_route GET /notes/export', 'http_route POST /admin/users/role', 'http_route POST /notes', 'http_route POST /notes/upload', 'webhook POST /webhooks/pay'],
  flask: ['http_route DELETE /api/notes/:note_id', 'http_route GET /api/export', 'http_route GET /api/items', 'http_route POST /api/admin/users/:uid/role', 'http_route POST /api/import',
    'http_route POST /api/notes', 'http_route POST /api/upload', 'http_route POST /login', 'webhook POST /webhooks/pay'],
  fastapi: ['http_route DELETE /api/notes/:note_id', 'http_route GET /api/export', 'http_route GET /api/items', 'http_route POST /api/admin/role', 'http_route POST /api/import',
    'http_route POST /api/notes', 'http_route POST /api/upload', 'http_route POST /login', 'webhook POST /webhooks/pay'],
  django: ['http_route ANY /api/export', 'http_route ANY /api/items', 'http_route POST /api/admin/role', 'http_route POST /api/import', 'http_route POST /api/notes', 'http_route POST /api/notes/:pk/delete',
    'http_route POST /api/upload', 'http_route POST /login', 'webhook POST /webhooks/pay'],
};

for (const side of ['fail', 'pass']) {
  test(`entry points of every fixture stack (${side} copy)`, () => {
    const m = mapOf(join(MAPS, side));
    for (const [stack, want] of Object.entries(EXPECTED)) assert.deepEqual(sig(m, stack), want.slice().sort(), stack);
    assert.deepEqual(m.coverage.map((c) => [c.language, c.status]), [['javascript', 'mapped'], ['python', 'mapped'], ['typescript', 'mapped']]);
  });
}

// Which stacks the fail copy must be flagged in, per check. The pass copy must not be flagged by any of them.
const ALL = ['django', 'express', 'fastapi', 'flask', 'nest', 'nextapp'];
const OPEN_MATRIX: Record<string, string[]> = {
  'admin-route-without-role': ALL,
  'data-read-without-auth': ALL,
  'firebase-auth-only-rule': ['firebase'],
  'mutating-route-without-auth': ALL,
  'privileged-action-without-audit': ALL,
  'privileged-field-from-request': ALL,
  'redirect-from-request': ['django', 'express', 'fastapi', 'flask', 'nextapp'],
  'request-url-fetched': ['django', 'express', 'fastapi', 'flask', 'nextapp'],
  'supabase-open-table': ['supabase'],
  'supabase-policy-trusts-claims': ['supabase'],
  'supabase-privileged-column-grant': ['supabase'],
  'webhook-verify-before-use': ALL,
  'write-by-id-without-owner': ALL,
};
// The four map checks that settle only Pro requirements are loaded only in an edition that has them (src/checks/pro-map.ts).
const PRO_MATRIX: Record<string, string[]> = {
  'auth-endpoint-without-rate-limit': ['django', 'express', 'fastapi', 'flask', 'nextapp'],
  'input-without-schema': ALL,
  'page-size-from-request': ALL,
  'upload-without-limits': ALL,
};
const MATRIX: Record<string, string[]> = PRO_MAP_CHECKS.length > 0 ? { ...OPEN_MATRIX, ...PRO_MATRIX } : OPEN_MATRIX;

test('there are at least 10 checks that read the code map, each named in the matrix', () => {
  const ids = loadChecks().map((c) => c.id).filter((id) => id.startsWith('check.map.')).map((id) => id.slice('check.map.'.length)).sort();
  assert.ok(ids.length >= 10);
  assert.deepEqual(ids, Object.keys(MATRIX).sort());
});

test('each check flags the fail copy in every stack it applies to, and flags nothing in the pass copy', () => {
  const checks = loadChecks().filter((c) => c.id.startsWith('check.map.'));
  const run = (side: string) => { const dir = join(MAPS, side); return runChecks(makeContext(dir, discover(dir), [], null), checks); };
  const fail = run('fail');
  const pass = run('pass');
  for (const [name, stacks] of Object.entries(MATRIX)) {
    const id = `check.map.${name}`;
    const f = fail.results.find((r) => r.check_id === id);
    assert.equal(f?.result, 'FAIL', id);
    const seen = [...new Set(f!.evidence.map((e) => e.file.split('/')[0]))].sort();
    assert.deepEqual(seen, stacks.slice().sort(), `${id}: stacks flagged`);
    for (const e of f!.evidence) assert.ok(e.line && e.line >= 1 && e.note.length > 10, JSON.stringify(e));
    const p = pass.results.find((r) => r.check_id === id);
    assert.equal(p?.result, 'NOT ASSESSED: NEEDS DYNAMIC TEST', `${id}: pass copy ${JSON.stringify(p?.evidence)}`);
  }
});

test('a map check FAIL is a lead until it is measured: it never fails a requirement', () => {
  const t = loadTiers([join(ROOT, 'rules/semgrep')]);
  assert.ok(leadTierForCheck('check.map.mutating-route-without-auth', t));
  assert.equal(leadTierForCheck('check.api.webhook-verified-before-use', t), null, 'older engine checks stay gate');
  const input = { hits: [], rulesDirs: [join(ROOT, 'rules/semgrep')], checks: { schema_version: '1.0.0', commit: null, not_run: [], results: [
    { check_id: 'check.map.mutating-route-without-auth', sec_ids: ['SEC-API-001'], result: 'FAIL', evidence: [{ file: 'a.ts', line: 3, note: 'x' }, { file: 'b.ts', line: 4, note: 'y' }], absence_search: null, message_key: 'k' },
    { check_id: 'check.api.webhook-verified-before-use', sec_ids: ['SEC-API-101'], result: 'FAIL', evidence: [{ file: 'c.ts', line: 5, note: 'z' }], absence_search: null, message_key: 'k' },
  ] } } as unknown as BuildInput;
  const out = separateTestCode(input);
  assert.deepEqual(out.input.checks.results.map((r) => r.check_id), ['check.api.webhook-verified-before-use']);
  assert.deepEqual(out.test.map((x) => [x.kind, x.check!.evidence[0].file]), [['lead', 'a.ts'], ['lead', 'b.ts']], 'one lead per file');
});

test('a check with leads in more than 20 files gets one lead record that says how many places there are', () => {
  const evidence = Array.from({ length: 25 }, (_, i) => ({ file: `routes/r${i}.ts`, line: 3, note: 'x' }));
  const input = { hits: [], rulesDirs: [join(ROOT, 'rules/semgrep')], checks: { schema_version: '1.0.0', commit: null, not_run: [], results: [
    { check_id: 'check.map.mutating-route-without-auth', sec_ids: ['SEC-API-001'], result: 'FAIL', evidence, absence_search: null, message_key: 'k' }] } } as unknown as BuildInput;
  const out = separateTestCode(input);
  assert.equal(out.test.length, 1);
  assert.equal(out.test[0].total, 25);
});

test('codemap.json matches its schema, and two builds give the same bytes', () => {
  for (const side of ['fail', 'pass']) {
    const dir = join(MAPS, side);
    const a = stableJson(mapOf(dir));
    const b = stableJson(getMap(makeContext(dir, discover(dir))));
    assert.equal(a, b);
    assert.deepEqual(validate(schema, JSON.parse(a)), []);
    assert.ok(!a.includes(ROOT), 'no absolute path');
  }
});

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-map-'));
  for (const [f, t] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  return dir;
}

test('a language with no extractor is reported as not mapped, never silently empty', () => {
  const dir = project({
    'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\naxum = "0.7"\n',
    'src/main.rs': 'use axum::{routing::get, Router};\n\n#[tokio::main]\nasync fn main() {\n    let app = Router::new().route("/ping", get(|| async { "pong" }));\n}\n',
  });
  const m = mapOf(dir);
  assert.equal(m.counts.entry_points, 0);
  const rust = m.coverage.find((c) => c.language === 'rust')!;
  assert.equal(rust.status, 'not_mapped');
  assert.equal(rust.extractor, null);
  assert.match(rust.note, /No extractor for rust yet/);
  assert.match(rust.note, /axum/);
  const lines = renderEntryPoints(m).join('\n');
  assert.match(lines, /The code map is incomplete for rust/);
});

test('a framework the extractor does not read makes the language partly mapped', () => {
  const dir = project({
    'package.json': '{"name":"x","dependencies":{"@hapi/hapi":"^21.0.0"}}\n',
    'server.js': "const Hapi = require('@hapi/hapi');\nconst server = Hapi.server({ port: 3000 });\nserver.route({ method: 'GET', path: '/x', handler: () => 'ok' });\n",
  });
  const m = mapOf(dir);
  const js = m.coverage.find((c) => c.language === 'javascript')!;
  assert.equal(js.status, 'partial');
  assert.match(js.note, /hapi/);
});

test('the report section lists every entry point with what protects it, and says what it could not read', () => {
  const m = mapOf(join(MAPS, 'fail'));
  const text = renderEntryPoints(m).join('\n');
  assert.match(text, /## Entry points and what protects them/);
  assert.match(text, /\| POST \/api\/notes \| http route \| `nextapp\/app\/api\/notes\/route\.ts:4` \| no \|/);
  assert.match(text, /\| POST \/webhooks\/pay \| webhook \| `express\/server\.js:43` \| - \| - \| no \| ignored \|/);
  assert.match(text, /State changing entry points: \d+\. Without a session read the engine can see: \d+\./);
  assert.equal(text, renderEntryPoints(m).join('\n'), 'same map, same text');
});

test('hullproof map writes codemap.json, prints it with --out -, and refuses a missing folder', () => {
  const dir = project({ 'app.py': ['from flask import Flask', 'app = Flask(__name__)', '', "@app.route('/ping')", 'def ping():', "    return 'ok'", ''].join('\n') });
  const out = mkdtempSync(join(tmpdir(), 'hp-map-out-'));
  const r = spawnSync(process.execPath, [CLI, 'map', dir, '--out', out], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const written = JSON.parse(readFileSync(join(out, 'codemap.json'), 'utf8')) as CodeMap;
  assert.equal(written.counts.entry_points, 1);
  assert.equal(written.entry_points[0].path, '/ping');
  const piped = spawnSync(process.execPath, [CLI, 'map', dir, '--out', '-'], { encoding: 'utf8' });
  assert.equal(piped.stdout, readFileSync(join(out, 'codemap.json'), 'utf8'));
  assert.equal(spawnSync(process.execPath, [CLI, 'map', join(dir, 'nope')], { encoding: 'utf8' }).status, 2);
  assert.equal(spawnSync(process.execPath, [CLI, 'map', '--bogus'], { encoding: 'utf8' }).status, 2);
});

test('a router mounted under a prefix gives its routes the full path and the mount protections', () => {
  const dir = project({
    'package.json': '{"name":"x","dependencies":{"express":"^4.0.0"}}\n',
    'app.js': "const express = require('express');\nconst { requireUser } = require('./auth');\nconst items = require('./items');\nconst app = express();\napp.use('/api', requireUser, items);\n",
    'auth.js': "const jwt = require('jsonwebtoken');\nexports.requireUser = function requireUser(req, res, next) {\n  const user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET);\n  if (!user) return res.status(401).end();\n  next();\n};\n",
    'items.js': "const express = require('express');\nconst router = express.Router();\nrouter.get('/items/:id', (req, res) => res.json({}));\nmodule.exports = router;\n",
  });
  const m = mapOf(dir);
  const e = m.entry_points.find((x) => x.file === 'items.js')!;
  assert.equal(e.path, '/api/items/:id');
  assert.ok(e.protections.some((p) => p.kind === 'session_read' && p.scope === 'router'), JSON.stringify(e.protections));
});

test('test code entry points are listed but flagged, and the checks skip them', () => {
  const dir = project({
    'package.json': '{"name":"x","dependencies":{"express":"^4.0.0"}}\n',
    'tests/server.js': "const express = require('express');\nconst app = express();\napp.post('/api/things', (req, res) => res.json({}));\n",
  });
  const m = mapOf(dir);
  assert.equal(m.entry_points.length, 1);
  assert.equal(m.entry_points[0].test_code, true);
  const ctx = makeContext(dir, discover(dir));
  const out = runChecks(ctx, loadChecks().filter((c) => c.id === 'check.map.mutating-route-without-auth'));
  assert.deepEqual(out.results, []);
});

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid',
  GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid', GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' };

test('scan writes codemap.json next to the other contract files, lists the leads, and is byte identical over three runs', { skip: KIT_SKIP }, async () => {
  const repo = mkdtempSync(join(tmpdir(), 'hp-map-scan-'));
  cpSync(join(MAPS, 'fail', 'express'), repo, { recursive: true });
  for (const args of [['init', '-q'], ['add', '-A'], ['commit', '-q', '-m', 'init']]) assert.equal(spawnSync('git', ['-C', repo, ...args], { env: GIT_ENV }).status, 0);
  const out = mkdtempSync(join(tmpdir(), 'hp-map-scan-out-'));
  const hashes: string[] = [];
  let dir = '';
  for (let i = 0; i < 3; i++) {
    const log: string[] = [];
    const code = await scan({ repo, out, kit: KIT, edition: 'pro', stage: null, allowNetwork: false, tools: null, scanners: () => ({ hits: [], metas: [] }), log: (l) => log.push(l) });
    assert.equal(code, 0, log.join('\n'));
    assert.equal(await report({ repo, out, kit: KIT, commit: null, owner: null, date: '2026-01-01', log: (l) => log.push(l) }), 0, log.join('\n'));
    dir = join(out, readdirSync(out)[0]);
    const h = createHash('sha256');
    const walk = (d: string): void => { for (const n of readdirSync(d).sort()) { const p = join(d, n); if (statSync(p).isDirectory()) walk(p); else if (n !== 'run.json' && n !== 'kit.local.json') h.update(n).update(readFileSync(p)); } };
    walk(dir);
    hashes.push(h.digest('hex'));
  }
  assert.equal(new Set(hashes).size, 1, 'three runs, one set of bytes');
  const map = JSON.parse(readFileSync(join(dir, 'codemap.json'), 'utf8')) as CodeMap;
  assert.equal(map.counts.entry_points, 9);
  const info = JSON.parse(readFileSync(join(dir, 'scan.json'), 'utf8')) as { codemap: { entry_points: number; incomplete: unknown[] } };
  assert.deepEqual(info.codemap, { entry_points: 9, incomplete: [] });
  const md = readFileSync(join(dir, 'report.md'), 'utf8');
  assert.match(md, /## Entry points and what protects them/);
  assert.match(md, /Lead: Route that changes data has no sign in check/);
  const results = JSON.parse(readFileSync(join(dir, 'results.json'), 'utf8')) as { id: string; result: string }[];
  assert.notEqual(results.find((r) => r.id === 'SEC-API-001')?.result, 'FAIL', 'a lead never fails a requirement');
});
