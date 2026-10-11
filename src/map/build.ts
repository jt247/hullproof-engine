// Builds codemap.json: runs the extractors over every file, joins router mounts and gates, adds the Supabase and Firebase
// maps, and writes the per language coverage that says what the map did not read. Deterministic: sorted, no clock.
import type { CheckContext } from '../checks/context.ts';
import type { CodeMap, Coverage, EntryPoint, Gate, Protection } from '../types/index.ts';
import { cmp } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import { firebaseMap, supabaseMap } from './config.ts';
import { joinPath, type Extracted, type Mount } from './entry.ts';
import { extractExpress } from './js-express.ts';
import { extractAiTools, extractJobs, extractNest } from './js-misc.ts';
import { extractNext } from './js-next.ts';
import { extractExpo } from './expo.ts';
import { extractGoAll, goFiles } from './go.ts';
import { extractLaravelAll, laravelFiles } from './laravel.ts';
import { FnIndex } from './light-index.ts';
import { extractRailsAll, railsFiles } from './rails.ts';
import { authHelperCandidates } from './candidates.ts';
import { extractPython } from './py.ts';
import { extractDjango } from './py-django.ts';
import { langOf, Repo } from './repo.ts';

// Web frameworks a built extractor reads, and ones it does not, by language group (stack.json framework ids).
const READ_BY: Record<string, string[]> = { 'node-ts': ['nextjs', 'express', 'fastify', 'koa', 'hono', 'nestjs', 'trpc', 'react', 'expo'], python: ['flask', 'fastapi', 'django', 'quart', 'sanic', 'starlette'], go: ['chi', 'echo', 'fiber', 'gin', 'gorilla-mux'], ruby: ['rails'], php: ['laravel'] };
const UNREAD: Record<string, string[]> = {
  'node-ts': ['adonisjs', 'apollo-server', 'hapi', 'loopback', 'remix', 'sveltekit', 'nuxt', 'astro', 'socket.io', 'graphql'],
  python: ['aiohttp', 'bottle', 'falcon', 'litestar', 'pyramid', 'tornado', 'gradio', 'streamlit'],
  go: [], ruby: ['sinatra', 'grape', 'hanami', 'roda'],
  php: ['symfony', 'slim', 'codeigniter', 'cakephp', 'yii', 'drupal', 'wordpress'],
  java: ['spring', 'spring-boot', 'quarkus', 'micronaut', 'javalin', 'hibernate'], kotlin: ['ktor', 'spring', 'spring-boot'],
  csharp: ['aspnet-core', 'entity-framework'], rust: ['actix-web', 'axum', 'rocket', 'warp'], elixir: ['phoenix', 'ecto'],
  dart: ['dart-frog', 'shelf'], swift: ['vapor'],
};
const SERVER_LANGS = new Set(['java', 'kotlin', 'csharp', 'rust', 'scala', 'elixir', 'swift', 'dart', 'perl', 'c', 'cpp', 'lua', 'haskell', 'clojure', 'groovy', 'erlang', 'fsharp', 'ocaml', 'julia', 'r', 'visual-basic', 'zig', 'nim']);

const inPrefix = (path: string, prefix: string): boolean => prefix === '*' || prefix === '/' || path === prefix || path.startsWith(prefix.replace(/\/$/, '') + '/') || path.startsWith(prefix.replace(/\/$/, '') + '*');
const ROUTE_FW = new Set(['express', 'flask', 'fastapi', 'quart', 'sanic', 'flask-restful']);
const WEB_KINDS = new Set(['http_route', 'webhook', 'page']);

const confOf = (c: Protection['confidence'], cap: Protection['confidence']): Protection['confidence'] => (c === 'low' || cap === 'low' ? 'low' : c === 'medium' || cap === 'medium' ? 'medium' : 'high');

function addProtections(ep: EntryPoint, ps: Protection[]): void {
  const have = new Set(ep.protections.map((p) => `${p.kind}|${p.scope}|${p.file}|${p.line}|${p.via}`));
  for (const p of ps) { const k = `${p.kind}|${p.scope}|${p.file}|${p.line}|${p.via}`; if (!have.has(k)) { have.add(k); ep.protections.push(p); } }
  ep.protections.sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.kind, b.kind) || cmp(a.via, b.via) || cmp(a.scope, b.scope));
}

function prefixChain(mounts: Mount[]): Map<string, { prefix: string; protections: Protection[] }> {
  const byTarget = new Map<string, Mount[]>();
  for (const m of mounts) byTarget.set(m.target, [...(byTarget.get(m.target) ?? []), m]);
  const resolve = (file: string, depth: number): { prefix: string; protections: Protection[] } | null => {
    const ms = (byTarget.get(file) ?? []).slice().sort((a, b) => cmp(a.from, b.from) || a.line - b.line);
    if (!ms.length || depth > 5) return null;
    const m = ms[0];
    const up = resolve(m.from, depth + 1);
    return { prefix: joinPath(up?.prefix ?? '', m.prefix), protections: [...(up?.protections ?? []), ...m.protections] };
  };
  const out = new Map<string, { prefix: string; protections: Protection[] }>();
  for (const t of byTarget.keys()) { const r = resolve(t, 0); if (r) out.set(t, r); }
  return out;
}

export function buildCodeMap(ctx: CheckContext): CodeMap {
  const repo = new Repo(ctx);
  const all: Extracted = { entries: [], gates: [], mounts: [] };
  const merge = (x: Extracted): void => { all.entries.push(...x.entries); all.gates.push(...x.gates); all.mounts.push(...x.mounts); };
  // A file the extractor throws on is skipped and counted, so the coverage row can say so.
  const failed: { file: string; message: string }[] = [];
  const guard = (file: string, f: () => Extracted): void => { try { merge(f()); } catch (e) { failed.push({ file, message: (e as Error).message }); } };
  for (const file of ctx.files) {
    const lang = langOf(file);
    if (!lang) continue;
    const v = repo.view(file);
    if (!v) continue;
    if (lang === 'js') {
      if (repo.isClient(v)) { if (/(?:^|\/)page\.[cm]?[jt]sx?$/.test(file)) guard(file, () => extractNext(repo, v)); continue; }
      guard(file, () => extractNext(repo, v));
      guard(file, () => extractExpress(repo, v));
      guard(file, () => extractNest(repo, v));
      guard(file, () => extractJobs(repo, v));
      guard(file, () => extractAiTools(repo, v));
    } else if (lang === 'py') guard(file, () => extractPython(repo, v));
  }
  guard('(django url configuration)', () => extractDjango(repo));
  if (goFiles(repo).length) guard('(go routes)', () => extractGoAll(repo, new FnIndex(repo, 'go'), repo.local));
  if (railsFiles(repo).routes.length) guard('(rails routes)', () => extractRailsAll(repo, new FnIndex(repo, 'rb'), repo.local));
  if (laravelFiles(repo).length) guard('(laravel routes)', () => extractLaravelAll(repo, new FnIndex(repo, 'php'), repo.local));
  guard('(expo router)', () => extractExpo(repo));

  // Router mounts: routes registered in a mounted file live under the mount prefix and inherit its protections.
  const chains = prefixChain(all.mounts);
  for (const ep of all.entries) {
    const c = chains.get(ep.file);
    if (!c || !ROUTE_FW.has(ep.framework) || ep.path === null) continue;
    ep.path = joinPath(c.prefix, ep.path);
    if (ep.confidence === 'high') ep.confidence = 'medium';
    addProtections(ep, c.protections.map((p) => ({ ...p, scope: 'router' as const })));
  }

  // Gates: middleware and guards that cover an entry point by path, file order or framework.
  const gates: Gate[] = all.gates.slice().sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.id, b.id));
  for (const ep of all.entries) {
    if (!WEB_KINDS.has(ep.kind) && ep.kind !== 'server_action' && ep.kind !== 'graphql_resolver' && ep.kind !== 'rpc') continue;
    for (const g of gates) {
      if (g.framework === 'express' && (g.file !== ep.file || g.line > ep.line)) continue;
      if (g.framework === 'next-app' && !(ep.framework === 'next-app' || ep.framework === 'next-pages') || (g.framework === 'next-app' && ep.kind === 'server_action')) continue;
      if (g.framework === 'flask' && ep.framework !== 'flask' && ep.framework !== 'quart') continue;
      if (g.framework === 'nest' && ep.framework !== 'nest') continue;
      if (g.framework === 'django' && ep.framework !== 'django') continue;
      if (ep.path === null && !g.paths.includes('*')) continue;
      if (!g.paths.some((p) => ep.path === null ? p === '*' : inPrefix(ep.path!, p))) continue;
      const cap = g.paths.includes('*') || g.kind === 'guard' || g.kind === 'global_pipe' ? g.confidence : 'medium';
      addProtections(ep, g.protections.map((p) => ({ ...p, scope: g.kind === 'guard' || g.kind === 'global_pipe' ? 'global' as const : p.scope === 'router' ? 'router' as const : 'middleware' as const, confidence: confOf(p.confidence, cap) })));
    }
  }

  // Vercel cron paths: an entry point called by the platform scheduler.
  try {
    const vj = JSON.parse(ctx.text('vercel.json') || '{}') as { crons?: { path?: string }[] };
    for (const c of vj.crons ?? []) for (const ep of all.entries) if (c.path && ep.path && ep.path === joinPath('', c.path.split('?')[0])) ep.tags = [...new Set([...ep.tags, 'cron'])].sort();
  } catch { /* a vercel.json that does not parse adds no cron tags */ }

  const seen = new Map<string, EntryPoint>();
  for (const ep of all.entries) if (!seen.has(ep.id)) seen.set(ep.id, ep);
  const entries = [...seen.values()].sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.method ?? '', b.method ?? '') || cmp(a.path ?? '', b.path ?? '') || cmp(a.name ?? '', b.name ?? '') || cmp(a.kind, b.kind));

  const by = (key: (e: EntryPoint) => string): Record<string, number> => { const o: Record<string, number> = {}; for (const e of entries) o[key(e)] = (o[key(e)] ?? 0) + 1; return Object.fromEntries(Object.entries(o).sort(([a], [b]) => cmp(a, b))); };
  return {
    schema_version: '1.0.0', engine_version: ENGINE_VERSION, commit: ctx.stack.commit,
    coverage: coverage(ctx, entries, failed), entry_points: entries,
    gates: gates.map((g) => ({ ...g, protections: g.protections.slice().sort((a, b) => a.line - b.line || cmp(a.kind, b.kind) || cmp(a.via, b.via)) })),
    config: { supabase: supabaseMap(repo), firebase: firebaseMap(repo), local_vocab: { auth_helpers: repo.local.auth_helpers, role_helpers: repo.local.role_helpers }, auth_helper_candidates: authHelperCandidates(repo, entries) },
    counts: { entry_points: entries.length, by_kind: by((e) => e.kind), by_framework: by((e) => e.framework) },
  };
}

function coverage(ctx: CheckContext, entries: EntryPoint[], failed: { file: string; message: string }[]): Coverage[] {
  const frameworks = new Set([...ctx.stack.frameworks.map((f) => f.id), ...(ctx.stack.mobile ?? []).map((f) => f.id)]);
  const rows: Coverage[] = [];
  const nodeTotal = entries.filter((e) => /\.[cm]?[jt]sx?$/.test(e.file)).length;
  const count = (re: RegExp): number => entries.filter((e) => re.test(e.file)).length;
  for (const l of ctx.stack.languages) {
    const files = l.file_count ?? 0;
    if (l.id === 'javascript' || l.id === 'typescript') {
      const n = count(l.id === 'typescript' ? /\.[cm]?tsx?$/ : /\.[cm]?jsx?$/);
      const unread = UNREAD['node-ts'].filter((f) => frameworks.has(f));
      rows.push({ language: l.id, files, extractor: 'node-ts', status: unread.length ? 'partial' : 'mapped', entry_points: n, note: unread.length ? `Frameworks seen that this extractor does not read: ${unread.join(', ')}. Entry points they register may be missing.` : n === 0 && nodeTotal === 0 && READ_BY['node-ts'].some((f) => frameworks.has(f) && f !== 'react') ? 'A web framework was detected and no entry point was found. The routes may be registered in a way the extractor does not read.' : frameworks.has('expo') ? 'Next.js, Express family, NestJS, tRPC, Expo Router screens, API routes and deep links, jobs and AI tools are read.' : 'Next.js, Express family, NestJS, tRPC, jobs and AI tools are read.' });
    } else if (l.id === 'python') {
      const n = count(/\.py$/);
      const unread = UNREAD.python.filter((f) => frameworks.has(f));
      rows.push({ language: l.id, files, extractor: 'python', status: unread.length ? 'partial' : 'mapped', entry_points: n, note: unread.length ? `Frameworks seen that this extractor does not read: ${unread.join(', ')}. Entry points they register may be missing.` : n === 0 && READ_BY.python.some((f) => frameworks.has(f)) ? 'A web framework was detected and no entry point was found. The routes may be registered in a way the extractor does not read.' : 'Flask, FastAPI, Django and REST framework, Celery and scheduler jobs, and AI tools are read.' });
    } else if (l.id === 'go' || l.id === 'ruby' || l.id === 'php') {
      const ext = l.id === 'go' ? /\.go$/ : l.id === 'ruby' ? /\.rb$/ : /\.php$/;
      const n = count(ext);
      const unread = UNREAD[l.id].filter((f) => frameworks.has(f));
      const readSeen = READ_BY[l.id].filter((f) => frameworks.has(f));
      const name = l.id === 'go' ? 'go' : l.id === 'ruby' ? 'rails' : 'laravel';
      const what = l.id === 'go' ? 'net/http, chi, gin, echo, fiber and gorilla/mux routes' : l.id === 'ruby' ? 'Rails routes (config/routes.rb) and controller filters' : 'Laravel routes (routes/*.php) and controller middleware';
      let status: Coverage['status'] = unread.length ? 'partial' : 'mapped';
      let note = unread.length ? `Frameworks seen that this extractor does not read: ${unread.join(', ')}. Entry points they register may be missing.` : `${what[0].toUpperCase()}${what.slice(1)} are read.`;
      if (l.id !== 'go' && !readSeen.length && n === 0 && !unread.length) { status = 'partial'; note = `No ${l.id === 'ruby' ? 'Rails' : 'Laravel'} project was found, so no routes were read. Web code in ${l.id} files is not in this map.`; }
      else if (readSeen.length && n === 0) note = 'A web framework was detected and no entry point was found. The routes may be registered in a way the extractor does not read.';
      rows.push({ language: l.id, files, extractor: name, status, entry_points: n, note });
    } else if (SERVER_LANGS.has(l.id)) {
      const seen = (UNREAD[l.id] ?? []).filter((f) => frameworks.has(f));
      rows.push({ language: l.id, files, extractor: null, status: 'not_mapped', entry_points: 0, note: `No extractor for ${l.id} yet${seen.length ? ` (frameworks seen: ${seen.join(', ')})` : ''}. Entry points in ${l.id} files are not in this map.` });
    }
  }
  // Files an extractor threw on: the language they belong to is only partly mapped.
  const langOfFailed = (file: string): string => (/\.py$/.test(file) || /django/.test(file) ? 'python' : /\.go$|\(go /.test(file) ? 'go' : /\.rb$|\(rails /.test(file) ? 'ruby' : /\.php$|\(laravel /.test(file) ? 'php' : /\.tsx?$/.test(file) ? 'typescript' : 'javascript');
  for (const f of failed) {
    const lang = langOfFailed(f.file);
    const row = rows.find((r) => r.language === lang) ?? rows[0];
    if (row && !row.note.includes('could not be read')) { row.status = 'partial'; row.note += ` ${failed.filter((x) => langOfFailed(x.file) === lang).length} file(s) could not be read by the extractor, first: ${f.file}.`; }
  }
  return rows.sort((a, b) => cmp(a.language, b.language));
}
