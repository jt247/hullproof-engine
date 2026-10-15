// Start recipes: how to build and start an app in the sandbox, read from stack.json and the code map and from the repository itself.
// Two recipes: a Node app on Express with a local SQLite file or an ephemeral Postgres, and (Phase 6d) a Python app on Flask with a
// local SQLite file. Anything else, or anything that needs a hosted service, comes back as "not provable here" with the reason. A
// recipe is never guessed.
import { existsSync, lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { CodeMap, Recipe, RecipeResult, Stack } from '../types/index.ts';
import { cmp } from '../util.ts';
import { dummyValue, envNames } from './safety.ts';
import { canon, sha256 } from './spec.ts';

export const BASE_IMAGE = 'node:22-slim';
export const PYTHON_IMAGE = 'python:3.12-slim';
const HOSTED_DATA = new Set(['supabase', 'firebase-realtime-database', 'firestore', 'dynamodb', 'azure-cosmos-db', 'neon', 'planetscale', 'turso', 'aws-rds', 'google-cloud-sql', 'azure-database-mysql', 'azure-database-postgres', 'azure-sql']);
const HOSTED_AUTH = new Set(['auth0', 'clerk', 'firebase-auth', 'supabase-auth', 'aws-cognito', 'kinde', 'workos', 'stytch', 'okta', 'microsoft-entra']);
const LOCAL_DATA = new Set(['sqlite', 'postgres']);
const NATIVE = ['better-sqlite3', 'sqlite3', 'bcrypt', 'sharp', 'canvas', 'argon2', 'node-sass', 'grpc', 'libsql'];
const DB_VARS = /^(?:DATABASE_URL|DB_PATH|DATABASE_PATH|SQLITE_PATH|SQLITE_FILE|DB_FILE|DATABASE_FILE)$/;
const HEALTH = ['/health', '/healthz', '/api/health', '/ping', '/status', '/'];
const nice = (id: string): string => id.replace(/-/g, ' ');

const no = (code: Extract<RecipeResult, { ok: false }>['code'], reason: string): RecipeResult => ({ ok: false, code, reason });
const ids = (xs: { id: string }[]): string[] => xs.map((x) => x.id);

function sourceFiles(repo: string, depth = 0, out: string[] = []): string[] {
  if (depth > 6) return out;
  for (const n of readdirSync(repo).sort(cmp)) {
    if (n === 'node_modules' || n === '.git' || n === '.hullproof') continue;
    const p = join(repo, n);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) sourceFiles(p, depth + 1, out);
    else if (/\.(?:[cm]?js|ts)$/.test(n) && st.size < 1_000_000) out.push(p);
  }
  return out;
}

// The port the app listens on: a number in listen(), or the number after process.env.PORT. Returns null when no listen() call is found.
export function detectPort(text: string): { port: number; fromEnv: boolean } | null {
  const m = /\.listen\(\s*([^,)\n]+)/.exec(text);
  if (!m) return null;
  let expr = m[1].trim();
  if (/^[A-Za-z_$][\w$]*$/.test(expr)) {
    const d = new RegExp(`(?:const|let|var)\\s+${expr}\\s*=\\s*([^;\\n]+)`).exec(text);
    if (d) expr = d[1];
  }
  const fromEnv = /process\.env\.PORT|process\.env\[\s*['"]PORT['"]\s*\]/.test(expr);
  const n = /\b(\d{2,5})\b/.exec(expr.replace(/process\.env\.PORT/g, ''));
  if (n && Number(n[1]) <= 65535) return { port: Number(n[1]), fromEnv };
  return fromEnv ? { port: 3000, fromEnv } : null;
}

export function deriveRecipe(repo: string, stack: Stack, map: CodeMap, opts: { allowInstallScripts?: boolean } = {}): RecipeResult {
  const hosted = [...stack.data_stores.filter((i) => HOSTED_DATA.has(i.id)), ...stack.auth.filter((i) => HOSTED_AUTH.has(i.id))];
  if (hosted.length) return no('hosted_service', `the app uses ${hosted.map((i) => nice(i.id)).join(' and ')}, a hosted service that cannot run locally and has no local stand in in this version. It is not faked.`);
  const otherData = stack.data_stores.filter((i) => !LOCAL_DATA.has(i.id));
  if (otherData.length) return no('unsupported_datastore', `the app uses ${otherData.map((i) => nice(i.id)).join(' and ')}. Only a local SQLite file and an ephemeral Postgres are supported.`);
  const fw = ids(stack.frameworks);
  if (!fw.includes('express') && fw.includes('flask')) return deriveFlask(repo, stack, map, opts);
  if (!fw.includes('express')) return no('unsupported_stack', `the proof sandbox has a recipe for Node on Express and for Python on Flask in this version${fw.length ? ` (found ${fw.slice(0, 4).join(', ')})` : ''}.`);
  if (fw.includes('nextjs')) return no('unsupported_stack', 'the app also uses Next.js, which needs a production build step that this version has no recipe for.');
  const pjPath = join(repo, 'package.json');
  if (!existsSync(pjPath)) return no('no_package_json', 'there is no package.json at the repository root.');
  let pj: { main?: string; scripts?: Record<string, string>; dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try { pj = JSON.parse(readFileSync(pjPath, 'utf8')); } catch { return no('no_package_json', 'package.json cannot be read as JSON.'); }
  const deps = { ...(pj.dependencies ?? {}), ...(pj.devDependencies ?? {}) };
  const notes: string[] = [];

  // Build phase: a lockfile install without install scripts, or nothing at all when the repository carries its own modules.
  const hasDeps = Object.keys(deps).length > 0;
  const native = NATIVE.filter((n) => n in deps);
  let install: string[] | null = null;
  let vendored = false;
  if (hasDeps) {
    if (native.length && !opts.allowInstallScripts) return no('needs_install_scripts', `${native.join(', ')} needs an install script to build or download a native part, and the sandbox installs without install scripts so none can run. Pass --allow-install-scripts to let them run in the build container.`);
    if (!existsSync(join(repo, 'package-lock.json'))) return no('no_lockfile', `there is no package-lock.json${existsSync(join(repo, 'yarn.lock')) || existsSync(join(repo, 'pnpm-lock.yaml')) ? ' (only npm lockfiles are installed in this version)' : ''}, and the sandbox installs from a lockfile only.`);
    install = ['npm', 'ci', ...(opts.allowInstallScripts ? [] : ['--ignore-scripts']), '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/'];
    if (opts.allowInstallScripts) notes.push('install scripts run inside the build container, which has network access to the package registry');
  } else if (existsSync(join(repo, 'node_modules'))) { vendored = true; notes.push('the repository carries its own node_modules and has no dependencies to install, so the build phase needs no network'); }

  const start = pj.scripts?.start ? 'npm start' : pj.main && existsSync(join(repo, pj.main)) ? `node ${pj.main}` : ['server.js', 'index.js', 'app.js', 'src/server.js', 'src/index.js'].find((f) => existsSync(join(repo, f))) ? `node ${['server.js', 'index.js', 'app.js', 'src/server.js', 'src/index.js'].find((f) => existsSync(join(repo, f)))}` : null;
  if (!start) return no('no_start_command', 'there is no start script, no main file and no server.js, index.js or app.js.');

  let port: { port: number; fromEnv: boolean } | null = null;
  for (const f of sourceFiles(repo)) { port = detectPort(readFileSync(f, 'utf8')); if (port) break; }
  if (!port) return no('port_unknown', 'no listen() call with a port was found in the source.');

  const names = envNames(repo);
  const env: Record<string, string> = {};
  if (port.fromEnv) env.PORT = String(port.port);
  const sqliteUsed = stack.data_stores.some((i) => i.id === 'sqlite') || sourceFiles(repo).some((f) => /node:sqlite|better-sqlite3|require\(['"]sqlite3['"]\)/.test(readFileSync(f, 'utf8')));
  const pgUsed = stack.data_stores.some((i) => i.id === 'postgres');
  let data: Recipe['data_store'] = { kind: 'none' };
  if (pgUsed && !sqliteUsed) {
    const url = names.find((n) => n === 'DATABASE_URL' || n === 'POSTGRES_URL');
    if (!url) return no('unsupported_datastore', 'the app uses Postgres but does not read DATABASE_URL or POSTGRES_URL, so the sandbox cannot point it at its own database.');
    const sqlIn = (d: string): string[] => (existsSync(join(repo, d)) ? readdirSync(join(repo, d)).filter((f) => f.endsWith('.sql')).sort(cmp).map((f) => `${d}/${f}`) : []);
    const migrations = [...sqlIn('migrations'), ...sqlIn('db/migrations')];
    const seedSql = ['seed.sql', 'db/seed.sql'].find((f) => existsSync(join(repo, f))) ?? null;
    if (!migrations.length && !seedSql) return no('no_seed', 'the app uses Postgres and the repository has no migrations folder or seed.sql to build the schema and data from.');
    data = { kind: 'postgres', migrations, seed_sql: seedSql };
    env[url] = '{PGURL}';
    notes.push('Postgres runs as a second container on an internal network with no route out');
  } else if (sqliteUsed) {
    const dbVars = names.filter((n) => DB_VARS.test(n));
    if (!dbVars.length) return no('db_path_hardcoded', 'the app uses SQLite but does not read its file path from an environment variable (DATABASE_URL, DB_PATH, SQLITE_PATH and similar). The sandbox root filesystem is read only, so a path written into the code cannot be redirected to a writable place.');
    for (const v of dbVars) env[v] = v.endsWith('_URL') ? 'file:{DATA}/app.db' : '{DATA}/app.db';
    data = { kind: 'sqlite', env: dbVars };
  }
  for (const n of names) if (!(n in env) && n !== 'PORT') env[n] = dummyValue(n);

  let seed: string | null = null;
  if (pj.scripts?.seed) seed = 'npm run seed';
  else {
    const f = ['seed.js', 'db/seed.js', 'scripts/seed.js', 'seed.mjs'].find((x) => existsSync(join(repo, x)));
    if (f) seed = `node ${f}`;
    else notes.push('no seed step found; the specs rely on data the app creates itself');
  }
  const gets = new Set(map.entry_points.filter((e) => e.kind === 'http_route' && e.method === 'GET' && e.path).map((e) => e.path!));
  const health = HEALTH.find((h) => gets.has(h)) ?? '/';
  if (health === '/' && !gets.has('/')) notes.push('no health route found; the app counts as up when it answers any request with a status below 500');

  return { ok: true, recipe: { schema_version: '1.0.0', stack: 'node-express', base_image: BASE_IMAGE, ...(opts.allowInstallScripts && install ? { install_scripts: true } : {}), install, vendored_modules: vendored, seed, start, port: port.port, port_from_env: port.fromEnv, health_path: health, data_store: data, env: Object.fromEntries(Object.entries(env).sort(([a], [b]) => cmp(a, b))), notes } };
}

// ---- Python on Flask (Phase 6d) ---------------------------------------------------------------------------------------------------------
function pyFiles(repo: string, depth = 0, out: string[] = []): string[] {
  if (depth > 6) return out;
  for (const n of readdirSync(repo).sort(cmp)) {
    if (['node_modules', '.git', '.hullproof', '__pycache__', '.venv', 'venv'].includes(n)) continue;
    const p = join(repo, n);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) pyFiles(p, depth + 1, out);
    else if (n.endsWith('.py') && st.size < 1_000_000) out.push(p);
  }
  return out;
}

// The port a Flask app listens on: app.run(port=...) with a number, or int(os.environ.get("PORT", "5000")). The flask command defaults to 5000.
export function detectPyPort(text: string): { port: number; fromEnv: boolean } | null {
  const run = /\.run\s*\(/.exec(text);
  if (!run) return null;
  // The text of the argument list, up to the bracket that closes it.
  let depth = 1;
  let i = run.index + run[0].length;
  const from = i;
  for (; i < text.length && depth > 0; i++) { if (text[i] === '(') depth++; else if (text[i] === ')') depth--; }
  const args = text.slice(from, i - 1);
  const at = /\bport\s*=\s*/.exec(args);
  if (!at) return { port: 5000, fromEnv: false };
  let d = 0;
  let k = at.index + at[0].length;
  const start = k;
  for (; k < args.length; k++) { if (args[k] === '(') d++; else if (args[k] === ')') d--; else if (args[k] === ',' && d === 0) break; }
  const expr = args.slice(start, k);
  const fromEnv = /os\.environ|getenv/.test(expr) && /PORT/.test(expr);
  const n = /(\d{2,5})/.exec(expr.replace(/PORT/g, ''));
  if (n && Number(n[1]) <= 65535) return { port: Number(n[1]), fromEnv };
  return fromEnv ? { port: 5000, fromEnv } : null;
}

function deriveFlask(repo: string, stack: Stack, map: CodeMap, opts: { allowInstallScripts?: boolean }): RecipeResult {
  const files = pyFiles(repo);
  const text = new Map(files.map((f) => [f, readFileSync(f, 'utf8')]));
  const notes: string[] = [];
  const reqPath = join(repo, 'requirements.txt');
  if (!existsSync(reqPath)) return no('no_lockfile', 'there is no requirements.txt, and the sandbox installs from pinned requirements only (Pipfile, Poetry and uv are not read in this version).');
  const lines = readFileSync(reqPath, 'utf8').split(/\r?\n/).map((l) => l.replace(/\s+#.*$/, '').trim()).filter((l) => l && !l.startsWith('#'));
  const loose = lines.filter((l) => !/^[A-Za-z0-9_.\[\]-]+\s*==\s*[\w.!+*-]+(?:\s*;.*)?(?:\s+--hash=.*)?$/.test(l) && !/^--hash=/.test(l));
  if (loose.length) return no('no_lockfile', `requirements.txt has lines that are not pinned with == (${loose.slice(0, 3).join(', ')}), and the sandbox installs from pinned requirements only.`);
  if (lines.some((l) => /^(?:-e|git\+|https?:|\.\/|\/|--(?:index-url|extra-index-url|find-links))/.test(l))) return no('no_lockfile', 'requirements.txt points at a source other than the package index, and the sandbox installs from the index only.');

  const sqlite = stack.data_stores.some((i) => i.id === 'sqlite') || [...text.values()].some((t) => /\bimport\s+(?:[\w.]+\s*,\s*)*sqlite3\b|\bfrom\s+sqlite3\b/.test(t));
  const otherDb = lines.some((l) => /^(?:psycopg2?|psycopg|pymysql|mysqlclient|pymongo|redis|sqlalchemy|django)\b/i.test(l));
  if (otherDb && !sqlite) return no('unsupported_datastore', 'the app uses a database package other than the built in sqlite3. Only a local SQLite file is supported for Python in this version.');
  const names = envNames(repo);
  const dbVars = names.filter((n) => DB_VARS.test(n));
  if (sqlite && !dbVars.length) return no('db_path_hardcoded', 'the app uses SQLite but does not read its file path from an environment variable (DATABASE_URL, DB_PATH, SQLITE_PATH and similar). The sandbox root filesystem is read only, so a path written into the code cannot be redirected to a writable place.');
  if (!sqlite) notes.push('no data store was found; the app starts with no database');

  const appFile = files.find((f) => /\bFlask\s*\(\s*__name__/.test(text.get(f)!));
  if (!appFile) return no('no_start_command', 'no file creates the app with Flask(__name__).');
  const rel = (f: string): string => f.slice(repo.length + 1);
  const runner = files.find((f) => /if\s+__name__\s*==\s*['"]__main__['"]/.test(text.get(f)!) && /\.run\s*\(/.test(text.get(f)!) && (f === appFile || /from\s+\w+\s+import|import\s+\w+/.test(text.get(f)!)));
  let start: string;
  let port: { port: number; fromEnv: boolean };
  if (runner) {
    const pt = detectPyPort(text.get(runner)!);
    if (!pt) return no('port_unknown', 'app.run() is called but its port could not be read.');
    port = pt;
    start = `python ${rel(runner)}`;
  } else {
    const mod = rel(appFile).replace(/\.py$/, '').replace(/\//g, '.');
    port = { port: 5000, fromEnv: false };
    start = `python -m flask --app ${mod} run --host 127.0.0.1 --port 5000`;
    notes.push('the app has no app.run() under __main__, so it starts with the flask command on port 5000');
  }
  const env: Record<string, string> = {};
  if (port.fromEnv) env.PORT = String(port.port);
  for (const v of dbVars) env[v] = v.endsWith('_URL') ? 'file:{DATA}/app.db' : '{DATA}/app.db';
  for (const n of names) if (!(n in env) && n !== 'PORT') env[n] = dummyValue(n);
  const seedFile = ['seed.py', 'db/seed.py', 'scripts/seed.py', 'init_db.py', 'db/init_db.py'].find((x) => existsSync(join(repo, x)));
  if (!seedFile) notes.push('no seed step found; the specs rely on data the app creates itself');
  const gets = new Set(map.entry_points.filter((e) => e.kind === 'http_route' && e.method === 'GET' && e.path).map((e) => e.path!));
  const health = HEALTH.find((h) => gets.has(h)) ?? '/';
  if (health === '/' && !gets.has('/')) notes.push('no health route found; the app counts as up when it answers any request with a status below 500');
  const install = ['pip', 'install', '--no-cache-dir', ...(opts.allowInstallScripts ? [] : ['--only-binary=:all:']), '--disable-pip-version-check', '-r', 'requirements.txt'];
  if (opts.allowInstallScripts) notes.push('a package with no wheel builds from source inside the build container, which has network access to the package index');
  else notes.push('packages install from wheels only, so no package build script runs; a package that has no wheel makes the app not provable here');
  notes.push('requirements are pinned by version; the sandbox does not check package hashes');
  return { ok: true, recipe: { schema_version: '1.0.0', stack: 'python-flask', base_image: PYTHON_IMAGE, ...(opts.allowInstallScripts ? { install_scripts: true } : {}), install, vendored_modules: false, seed: seedFile ? `python ${seedFile}` : null, start, port: port.port, port_from_env: port.fromEnv, health_path: health, data_store: sqlite ? { kind: 'sqlite', env: dbVars } : { kind: 'none' }, env: Object.fromEntries(Object.entries(env).sort(([a], [b]) => cmp(a, b))), notes } };
}

export const recipeSha256 = (r: Recipe): string => sha256(canon(r));
