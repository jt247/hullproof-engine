// The safety rules that do not need a container (typed confirmation, copy without secrets, dummy environment, loopback target)
// and the start recipes, on small repositories built in a temporary folder.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeContext } from '../src/checks/context.ts';
import { getMap } from '../src/checks/map/shared.ts';
import { discover } from '../src/discover/discover.ts';
import { deriveRecipe, detectPort } from '../src/prove/recipe.ts';
import { assertSandboxTarget, checkConfirmation, CONFIRM_PHRASE, dummyValue, envNames, isSecretFile, makeSandboxCopy } from '../src/prove/safety.ts';

function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'hp-safe-'));
  for (const [f, text] of Object.entries(files)) { mkdirSync(join(dir, f, '..'), { recursive: true }); writeFileSync(join(dir, f), text); }
  return dir;
}
const recipeOf = (files: Record<string, string>, opts: { allowInstallScripts?: boolean } = {}) => { const r = repo(files); const stack = discover(r); return deriveRecipe(r, stack, getMap(makeContext(r, stack)), opts); };
const SERVER = "const express = require('express');\nconst app = express();\napp.get('/health', (q, s) => s.json({ ok: true }));\napp.listen(process.env.PORT || 4100);\n";

test('typed confirmation: a flag and the exact phrase, nothing else counts', () => {
  assert.equal(checkConfirmation(false, CONFIRM_PHRASE).ok, false);
  assert.equal(checkConfirmation(true, null).ok, false);
  assert.equal(checkConfirmation(true, 'yes').ok, false);
  assert.equal(checkConfirmation(true, CONFIRM_PHRASE.toUpperCase()).ok, false);
  assert.equal(checkConfirmation(true, `  ${CONFIRM_PHRASE}  `).ok, true);
  const before = process.env.CI;
  process.env.CI = 'true';
  try { assert.equal(checkConfirmation(true, null).ok, false, 'a CI environment confirms nothing'); } finally { if (before === undefined) delete process.env.CI; else process.env.CI = before; }
});

test('target rule: only the sandbox own loopback on the recipe port', () => {
  assertSandboxTarget('http://127.0.0.1:3000', 3000);
  for (const [u, p] of [['http://127.0.0.1:3001', 3000], ['https://api.example.com:443', 443], ['http://localhost:3000', 3001], ['http://192.168.1.2:3000', 3000]] as const) assert.throws(() => assertSandboxTarget(u, p), /refused/, u);
});

test('the copy leaves out env files, keys, git history, links and (normally) node_modules', () => {
  const r = repo({ 'server.js': 'x', '.env': 'A=1', '.env.local': 'B=2', '.env.production': 'C=3', 'keys/server.pem': 'k', 'deploy.key': 'k', 'id_rsa': 'k', '.npmrc': '//registry:_authToken=abc', 'credentials.json': '{}', 'service-account-prod.json': '{}', '.git/config': 'x', 'node_modules/a/index.js': 'x', 'src/app.js': 'x', 'README.md': 'x' });
  symlinkSync('/etc/hosts', join(r, 'hosts-link'));
  const c = makeSandboxCopy(r, { keepNodeModules: false });
  assert.ok(!('error' in c));
  if ('error' in c) return;
  try {
    for (const f of ['server.js', 'src/app.js', 'README.md']) assert.ok(existsSync(join(c.dir, f)), f);
    for (const f of ['.env', '.env.local', '.env.production', 'keys/server.pem', 'deploy.key', 'id_rsa', '.npmrc', 'credentials.json', 'service-account-prod.json', '.git', 'node_modules', 'hosts-link']) assert.ok(!existsSync(join(c.dir, f)), `${f} must not be copied`);
    assert.ok(c.excluded.some((e) => e.startsWith('.env ')) && c.excluded.some((e) => e.startsWith('hosts-link')));
    const kept = makeSandboxCopy(r, { keepNodeModules: true });
    assert.ok(!('error' in kept) && existsSync(join((kept as { dir: string }).dir, 'node_modules/a/index.js')));
    (kept as { cleanup(): void }).cleanup();
  } finally { c.cleanup(); }
  assert.ok(!existsSync(c.dir), 'cleanup removes the copy');
  assert.ok(isSecretFile('.env.staging') && isSecretFile('x.p12') && !isSecretFile('env.js'));
});

test('the dummy environment holds names and made up values, never a real value, and is the same every time', () => {
  const r = repo({ 'a.js': "const k = process.env.STRIPE_KEY; const s = process.env['JWT_SECRET']; const p = process.env.PORT;", '.env': 'REAL_SECRET=hunter2-real-value', '.env.example': 'FROM_EXAMPLE=placeholder\nOTHER=\n' });
  const names = envNames(r);
  assert.deepEqual(names, ['FROM_EXAMPLE', 'JWT_SECRET', 'OTHER', 'PORT', 'STRIPE_KEY']);
  assert.ok(!names.includes('REAL_SECRET'), 'a real .env file is never opened');
  assert.equal(dummyValue('JWT_SECRET'), dummyValue('JWT_SECRET'));
  assert.notEqual(dummyValue('JWT_SECRET'), dummyValue('STRIPE_KEY'));
  assert.match(dummyValue('JWT_SECRET'), /^dummy-jwt-secret-[0-9a-f]{8}$/);
});

test('port detection', () => {
  assert.deepEqual(detectPort('app.listen(8080)'), { port: 8080, fromEnv: false });
  assert.deepEqual(detectPort('app.listen(process.env.PORT || 4100, () => {})'), { port: 4100, fromEnv: true });
  assert.deepEqual(detectPort('const PORT = process.env.PORT ?? 5000;\napp.listen(PORT);'), { port: 5000, fromEnv: true });
  assert.deepEqual(detectPort('app.listen(process.env.PORT)'), { port: 3000, fromEnv: true });
  assert.equal(detectPort('no server here'), null);
});

test('recipe: an Express app with a SQLite file, a vendored module folder and a seed step', () => {
  const r = recipeOf({
    'package.json': JSON.stringify({ name: 'a', main: 'server.js', scripts: { seed: 'node seed.js' } }), 'server.js': SERVER + "const { DatabaseSync } = require('node:sqlite'); new DatabaseSync(process.env.DB_PATH);\nprocess.env.SECRET_X;\n",
    'seed.js': 'x', 'node_modules/express/index.js': 'module.exports = () => {}',
  });
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.equal(r.recipe.install, null);
  assert.equal(r.recipe.vendored_modules, true);
  assert.equal(r.recipe.seed, 'npm run seed');
  assert.equal(r.recipe.start, 'node server.js');
  assert.equal(r.recipe.port, 4100);
  assert.equal(r.recipe.port_from_env, true);
  assert.equal(r.recipe.health_path, '/health');
  assert.deepEqual(r.recipe.data_store, { kind: 'sqlite', env: ['DB_PATH'] });
  assert.equal(r.recipe.env.DB_PATH, '{DATA}/app.db');
  assert.equal(r.recipe.env.PORT, '4100');
  assert.equal(r.recipe.env.SECRET_X, dummyValue('SECRET_X'));
});

test('recipe: a lockfile install without install scripts, only from the npm registry', () => {
  const r = recipeOf({ 'package.json': JSON.stringify({ dependencies: { express: '4.19.2' }, scripts: { start: 'node server.js' } }), 'package-lock.json': '{}', 'server.js': SERVER });
  assert.ok(r.ok);
  if (r.ok) assert.deepEqual(r.recipe.install, ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/']);
  if (r.ok) assert.equal(r.recipe.start, 'npm start');
});

test('not provable here, with the reason: no lockfile, native modules, other stacks, hosted services, hardcoded database path, no port', () => {
  const code = (files: Record<string, string>): string => { const r = recipeOf(files); assert.equal(r.ok, false); return r.ok ? '' : `${r.code}: ${r.reason}`; };
  assert.match(code({ 'package.json': JSON.stringify({ dependencies: { express: '4' } }), 'server.js': SERVER }), /^no_lockfile/);
  assert.match(code({ 'package.json': JSON.stringify({ dependencies: { express: '4', 'better-sqlite3': '9' } }), 'package-lock.json': '{}', 'server.js': SERVER }), /^needs_install_scripts: better-sqlite3/);
  assert.match(code({ 'requirements.txt': 'Django==5.0.6\n', 'manage.py': 'import django\n', 'app.py': 'from django.http import HttpResponse\n' }), /^unsupported_stack/);
  assert.match(code({ 'package.json': JSON.stringify({ dependencies: { express: '4', '@supabase/supabase-js': '2' } }), 'package-lock.json': '{}', 'server.js': SERVER + "require('@supabase/supabase-js');" }), /^hosted_service: .*supabase/);
  assert.match(code({ 'package.json': JSON.stringify({ dependencies: { express: '4', mongoose: '8' } }), 'package-lock.json': '{}', 'server.js': SERVER }), /^unsupported_datastore: .*mongodb/);
  assert.match(code({ 'package.json': JSON.stringify({}), 'server.js': "const express = require('express'); const app = express();\nconst { DatabaseSync } = require('node:sqlite'); new DatabaseSync('app.db');\napp.listen(3000);\n", 'node_modules/express/index.js': 'x' }), /^db_path_hardcoded/);
  assert.match(code({ 'package.json': JSON.stringify({}), 'server.js': "const express = require('express'); const app = express(); module.exports = app;\n", 'node_modules/express/index.js': 'x' }), /^port_unknown/);
  assert.match(code({ 'package.json': JSON.stringify({ dependencies: { express: '4', next: '14' } }), 'package-lock.json': '{}', 'server.js': SERVER, 'next.config.js': 'module.exports={}' }), /^unsupported_stack: .*Next\.js/);
});

test('recipe: Postgres needs DATABASE_URL and a migrations folder or seed.sql, and gets an internal network note', () => {
  const base = { 'package.json': JSON.stringify({ dependencies: { express: '4', pg: '8' } }), 'package-lock.json': '{}', 'server.js': SERVER + 'process.env.DATABASE_URL;' };
  const noSeed = recipeOf(base);
  assert.ok(!noSeed.ok && noSeed.code === 'no_seed');
  const ok = recipeOf({ ...base, 'db/migrations/001.sql': 'create table t(id int);', 'seed.sql': 'insert into t values (1);' });
  assert.ok(ok.ok);
  if (ok.ok) { assert.deepEqual(ok.recipe.data_store, { kind: 'postgres', migrations: ['db/migrations/001.sql'], seed_sql: 'seed.sql' }); assert.equal(ok.recipe.env.DATABASE_URL, '{PGURL}'); }
  const noUrl = recipeOf({ 'package.json': base['package.json'], 'package-lock.json': '{}', 'server.js': SERVER, 'seed.sql': 'x' });
  assert.ok(!noUrl.ok && noUrl.code === 'unsupported_datastore');
});

test('install scripts: off by default (native modules are refused), on only with the opt in flag, which says so in the recipe', () => {
  const files = { 'package.json': JSON.stringify({ dependencies: { express: '4', bcrypt: '5' } }), 'package-lock.json': '{}', 'server.js': SERVER };
  const off = recipeOf(files);
  assert.ok(!off.ok && off.code === 'needs_install_scripts' && /--allow-install-scripts/.test(off.reason));
  const plain = recipeOf({ ...files, 'package.json': JSON.stringify({ dependencies: { express: '4' } }) });
  assert.ok(plain.ok && plain.recipe.install?.includes('--ignore-scripts') && !plain.recipe.install_scripts);
  const on = recipeOf(files, { allowInstallScripts: true });
  assert.ok(on.ok);
  if (on.ok) { assert.ok(!on.recipe.install!.includes('--ignore-scripts')); assert.equal(on.recipe.install_scripts, true); assert.ok(on.recipe.notes.some((n) => /install scripts run inside the build container/.test(n))); assert.ok(on.recipe.install!.includes('--registry=https://registry.npmjs.org/')); }
});
