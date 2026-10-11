// Entry points registered with a call, in the Express family: Express, Koa router, Fastify, Hono, restify and similar
// (app.get('/path', ...middleware, handler)), plus the app.use gates and router mounts around them.
import type { Confidence, Gate, Protection } from '../types/index.ts';
import { analyze, type FileView, type Spec } from './analyze.ts';
import { empty, joinPath, makeEntry, type Extracted } from './entry.ts';
import { closeOf, jsFunction, splitArgs } from './lex.ts';
import { paramsOf, resolveFunction } from './js-next.ts';
import type { Repo } from './repo.ts';

const FRAMEWORK = /\b(?:express|fastify|koa|hono|restify|polka|@hapi\/hapi|itty-router|elysia|@koa\/router|koa-router|connect|h3|@fastify\/\w+)\b/;
const CREATORS = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?(?:new\s+)?(?:express\s*\.\s*Router|express|Router|fastify|Fastify|Hono|Koa|Elysia|polka|createRouter|KoaRouter|restify\s*\.\s*createServer|\w*[rR]outer)\s*[(<]/g;
const VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all', 'options', 'head']);

const confMin = (cs: Confidence[]): Confidence => (cs.includes('low') ? 'low' : cs.includes('medium') ? 'medium' : 'high');

function literalPaths(v: FileView, a: { start: number; end: number } | undefined): string[] | null {
  if (!a) return null;
  const c = v.masked[a.start];
  if (c === '"' || c === "'" || c === '`') {
    const p = v.text.slice(a.start + 1, a.end - 1);
    return p.startsWith('/') || p === '*' || p === '' ? [p] : null;
  }
  if (c === '[') {
    const ps = [...v.text.slice(a.start, a.end).matchAll(/['"`]([^'"`]*)['"`]/g)].map((x) => x[1]).filter((p) => p.startsWith('/') || p === '*');
    return ps.length ? ps : null;
  }
  return null;
}

export function extractExpress(repo: Repo, v: FileView): Extracted {
  const out = empty();
  if (!FRAMEWORK.test(v.imports) && !/\bexpress\s*\(\s*\)|\bRouter\s*\(\s*\)/.test(v.masked)) return out;
  const names = new Set(['app', 'router', 'server', 'api', 'route', 'routes', 'fastify', 'instance']);
  for (const m of v.masked.matchAll(CREATORS)) names.add(m[1]);
  const recv = [...names].map((n) => n.replace(/\$/g, '\\$')).join('|');
  const call = new RegExp(`(?<![.\\w$])(?:${recv})\\s*\\.\\s*(get|post|put|patch|delete|all|options|head|use|route)\\s*\\(`, 'g');
  const imports = repo.importMap(v);
  const helpers = repo.helpers('js');

  const middlewareDeco = (args: { start: number; end: number }[]): NonNullable<Spec['decorators']> =>
    args.map((a) => ({ view: v, start: a.start, end: a.end, scope: 'wrapper' as const }));
  const calledNames = (args: { start: number; end: number }[]): string[] => {
    const set = new Set<string>();
    for (const a of args) for (const m of v.masked.slice(a.start, a.end).matchAll(/(?<![\w$])([A-Za-z_$][\w$]*)\s*(?:\(|,|$)/g)) set.add(m[1]);
    for (const a of args) { const t = v.masked.slice(a.start, a.end); const id = /^[A-Za-z_$][\w$.]*$/.exec(t); if (id) set.add(id[0].split('.').pop()!); }
    return [...set].sort();
  };

  const register = (verb: string, paths: string[], args: { start: number; end: number }[], at: number): void => {
    if (!args.length) return;
    const last = args[args.length - 1];
    const mws = args.slice(0, -1);
    const r = resolveFunction(repo, v, last.start, last.end);
    const line = v.lines.at(at);
    for (const p of paths) {
      const method = verb === 'all' ? 'ANY' : verb.toUpperCase();
      const handlerView = r?.view ?? v;
      const start = r?.start ?? last.start;
      const end = r?.end ?? last.end;
      const seeds = r ? (r.params.length ? [r.params[0]] : ['req']) : [];
      const deco = middlewareDeco(mws);
      if (r?.wrapper) deco.push({ view: v, start: r.wrapper.from, end: r.wrapper.to, scope: 'wrapper' });
      const extra = calledNames(mws).concat(r?.wrapper ? [r.wrapper.name.split('.').pop()!] : []);
      const e = makeEntry(repo, {
        kind: 'http_route', framework: 'express', file: v.file, line, method, path: joinPath('', p === '' ? '/' : p), name: r?.defName ?? nameOf(v, last),
        confidence: 'high', handlerView, spec: { start, end, seeds, decorators: deco, extraCalls: extra, returnsJson: true },
      });
      out.entries.push(e);
    }
  };

  for (const m of v.masked.matchAll(call)) {
    const verb = m[1];
    const open = m.index! + m[0].length - 1;
    const args = splitArgs(v.masked, open);
    if (verb === 'route') {
      const paths = literalPaths(v, args[0]);
      if (!paths) continue;
      // .route('/x').get(h).post(h): read the chain after the call.
      let i = closeOf(v.masked, open);
      if (i < 0) continue;
      for (let g = 0; g < 8; g++) {
        const nxt = /^\s*\.\s*(get|post|put|patch|delete|all|options|head)\s*\(/.exec(v.masked.slice(i, i + 60));
        if (!nxt) break;
        const o = i + nxt[0].length - 1;
        register(nxt[1], paths, splitArgs(v.masked, o), i + nxt[0].indexOf(nxt[1]));
        i = closeOf(v.masked, o);
        if (i < 0) break;
      }
      continue;
    }
    if (VERBS.has(verb)) {
      const paths = literalPaths(v, args[0]);
      if (!paths || args.length < 2) continue;
      register(verb, paths, args.slice(1), m.index!);
      continue;
    }
    // use(): a gate on a path, or a router mount.
    const paths = literalPaths(v, args[0]);
    const rest = paths ? args.slice(1) : args;
    const prefix = paths?.[0] ?? '*';
    const line = v.lines.at(m.index!);
    let target: string | null = null;
    for (const a of rest) {
      const id = /^[A-Za-z_$][\w$]*$/.exec(v.masked.slice(a.start, a.end));
      const spec = id ? imports.get(id[0]) : undefined;
      const file = spec ? repo.resolveImport(v.file, spec) : null;
      if (file && /\bRouter\s*\(|\bexpress\.Router\b|\bnew\s+Hono\b|\bfastify\b/.test(repo.ctx.text(file))) target = file;
    }
    const gateArgs = rest.filter((a) => { const id = /^[A-Za-z_$][\w$]*$/.exec(v.masked.slice(a.start, a.end)); return !(id && target && imports.get(id[0]) && repo.resolveImport(v.file, imports.get(id[0])!) === target); });
    const protections: Protection[] = [];
    for (const a of gateArgs) {
      const spec: Spec = { start: a.start, end: a.end, seeds: [], decorators: [], extraCalls: calledNames([a]), returnsJson: false, gate: true };
      const an = analyze(v, spec, helpers);
      for (const p of an.protections) if (p.kind !== 'owner_filter' && p.kind !== 'audit_log') protections.push({ ...p, scope: 'middleware' });
    }
    const joined = protections.length ? protections : [];
    if (target) out.mounts.push({ from: v.file, line, prefix: joinPath('', prefix === '*' ? '/' : prefix), target, protections: joined });
    else if (joined.length) {
      const gate: Gate = { id: `${v.file}:${line}:use:${prefix}`, kind: 'middleware', framework: 'express', file: v.file, line, paths: [prefix === '*' ? '*' : joinPath('', prefix)], methods: [], protections: joined, confidence: confMin(joined.map((p) => p.confidence)) === 'high' ? 'medium' : confMin(joined.map((p) => p.confidence)) };
      out.gates.push(gate);
    }
  }
  return out;
}

// A readable name for the handler argument: the function name, or the called factory, or null for an inline function.
function nameOf(v: FileView, a: { start: number; end: number }): string | null {
  const t = v.masked.slice(a.start, a.end);
  if (/^(?:async\b|function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.test(t)) return null;
  const m = /^([A-Za-z_$][\w$.]*)/.exec(t);
  return m ? m[1] : null;
}

export { paramsOf };
