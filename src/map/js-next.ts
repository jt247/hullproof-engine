// Entry points of Next.js (app router route handlers and pages, pages router API routes, server actions, middleware),
// Supabase edge functions and tRPC procedures.
import type { Gate, Protection } from '../types/index.ts';
import { analyze, type FileView, type Spec } from './analyze.ts';
import { empty, joinPath, makeEntry, normPath, paramNames, type Extracted } from './entry.ts';
import { closeOf, jsFunction, splitArgs, type Extent } from './lex.ts';
import type { Repo } from './repo.ts';
import { ADMIN_PATH } from './vocab.ts';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

// A function-valued expression starting at `at`: a function itself, a call that wraps one (withAuth(handler)), or a name.
export interface Resolved { view: FileView; start: number; end: number; wrapper: { name: string; from: number; to: number } | null; resolved: boolean; params: string[]; defName?: string }
export function resolveFunction(repo: Repo, v: FileView, at: number, limit: number): Resolved | null {
  const m = v.masked;
  const direct = jsFunction(m, at);
  if (direct && direct.end <= limit + 1) return { view: v, start: direct.start, end: direct.end, wrapper: null, resolved: false, params: paramsOf(m, direct) };
  const call = /^\s*([A-Za-z_$][\w$.]*)\s*(?:<[^>(]*>)?\s*\(/.exec(m.slice(at, limit));
  if (call) {
    const open = at + call[0].length - 1;
    const args = splitArgs(m, open);
    for (const a of args) {
      const f = jsFunction(m, a.start);
      if (f && f.end <= a.end + 1) return { view: v, start: f.start, end: f.end, wrapper: { name: call[1], from: at, to: a.start }, resolved: false, params: paramsOf(m, f) };
    }
    for (const a of args) {
      const id = /^([A-Za-z_$][\w$]*)(?:\s*\([\s\S]*\))?$/.exec(m.slice(a.start, a.end));
      if (id) { const r = repo.defs('js', id[1]).filter((d) => d.view.file === v.file).concat(repo.defs('js', id[1]))[0]; if (r) return { view: r.view, start: r.start, end: r.end, wrapper: { name: call[1], from: at, to: a.start }, resolved: true, params: paramsOf(r.view.masked, { start: r.start, end: r.end, bodyStart: r.start }), defName: id[1] }; }
    }
    return null;
  }
  const id = /^\s*([A-Za-z_$][\w$]*)\s*[;,)]?\s*$/.exec(m.slice(at, limit)) ?? /^\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)*([A-Za-z_$][\w$]*)\s*[;,)]?\s*$/.exec(m.slice(at, limit));
  if (id) {
    const defs = repo.defs('js', id[1]);
    const r = defs.find((d) => d.view.file === v.file) ?? (defs.length === 1 ? defs[0] : null);
    if (r) return { view: r.view, start: r.start, end: r.end, wrapper: null, resolved: true, params: paramsOf(r.view.masked, { start: r.start, end: r.end, bodyStart: r.start }), defName: id[1] };
  }
  return null;
}

export function paramsOf(masked: string, f: Extent): string[] {
  const head = masked.slice(f.start, f.bodyStart);
  const open = head.indexOf('(');
  if (open >= 0 && (head.indexOf('=>') < 0 || open < head.indexOf('=>'))) return paramNames(masked, f.start + open);
  const single = /^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/.exec(head);
  return single ? [single[1]] : [];
}

export const nextRoutePath = (file: string, strip: RegExp): string | null => {
  const m = /(?:^|\/)(?:src\/)?app\/(.*)$/.exec(file);
  if (!m) return null;
  const segs = m[1].replace(strip, '').split('/').filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith('@'));
  return normPath('/' + segs.join('/'));
};

// Exported names in a file with where their value starts: export function X, export const X = ..., export { a as X }.
export function exportedFunctions(repo: Repo, v: FileView): { exportName: string; r: Resolved; line: number; at: number }[] {
  const m = v.masked;
  const out: { exportName: string; r: Resolved; line: number; at: number }[] = [];
  for (const x of m.matchAll(/\bexport\s+(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/g)) {
    const at = x.index! + (/\bexport\s+(?:default\s+)?/.exec(x[0])![0].length);
    const f = jsFunction(m, at);
    if (f) out.push({ exportName: x[1], r: { view: v, start: f.start, end: f.end, wrapper: null, resolved: false, params: paramsOf(m, f) }, line: v.lines.at(x.index!), at });
  }
  for (const x of m.matchAll(/\bexport\s+const\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*/g)) {
    const at = x.index! + x[0].length;
    const limit = statementLimit(m, at);
    const r = resolveFunction(repo, v, at, limit);
    if (r) out.push({ exportName: x[1], r, line: v.lines.at(x.index!), at });
  }
  for (const x of m.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
    for (const part of x[1].split(',')) {
      const [local, alias] = part.trim().split(/\s+as\s+/);
      if (!local) continue;
      const defs = repo.defs('js', local);
      const d = defs.find((q) => q.view.file === v.file);
      if (d) out.push({ exportName: alias ?? local, r: { view: d.view, start: d.start, end: d.end, wrapper: null, resolved: false, params: paramsOf(d.view.masked, { start: d.start, end: d.end, bodyStart: d.start }) }, line: v.lines.at(x.index!), at: x.index! });
    }
  }
  return out;
}

function statementLimit(masked: string, from: number): number {
  let depth = 0;
  for (let i = from; i < masked.length; i++) {
    const c = masked[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { if (depth === 0) return i; depth--; }
    else if (c === ';' && depth === 0) return i;
    else if (c === '\n' && depth === 0 && /\n\s*(?:export|const|let|var|function|async|import|type|interface|\/\/)/.test(masked.slice(i, i + 40))) return i;
  }
  return masked.length;
}

function spec(r: Resolved, decorators: Spec['decorators'], seeds: string[], extra: string[] = []): Spec {
  const deco = decorators ?? [];
  return { start: r.start, end: r.end, seeds, decorators: deco, extraCalls: extra, returnsJson: true };
}

const wrapperDeco = (v: FileView, r: Resolved): NonNullable<Spec['decorators']> => (r.wrapper ? [{ view: v, start: r.wrapper.from, end: r.wrapper.to, scope: 'wrapper' }] : []);

export function extractNext(repo: Repo, v: FileView): Extracted {
  const out = empty();
  const file = v.file;
  const text = v.text;

  // App router route handlers.
  if (/(?:^|\/)(?:src\/)?app\/(?:.*\/)?route\.[cm]?[jt]sx?$/.test(file)) {
    const path = nextRoutePath(file, /\/?route\.[cm]?[jt]sx?$/);
    for (const e of exportedFunctions(repo, v)) {
      if (!METHODS.includes(e.exportName)) continue;
      const r = e.r;
      const seeds = r.params.length ? r.params : ['req', 'request', 'params'];
      out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'next-app', file, line: e.line, method: e.exportName, path, name: e.exportName, confidence: 'high', handlerView: r.view, spec: spec(r, wrapperDeco(v, r), [...seeds, 'params', 'searchParams'], r.wrapper ? [r.wrapper.name.split('.').pop()!] : []) }));
    }
  }

  // App router pages.
  if (/(?:^|\/)(?:src\/)?app\/(?:.*\/)?page\.[cm]?[jt]sx?$/.test(file)) {
    const path = nextRoutePath(file, /\/?page\.[cm]?[jt]sx?$/);
    const ex = defaultExport(repo, v);
    if (ex) {
      const r = ex.r;
      out.entries.push(makeEntry(repo, { kind: 'page', framework: 'next-app', file, line: v.lines.at(r.start), method: 'GET', path, name: ex.exportName, confidence: 'high', handlerView: r.view, spec: spec(r, [], ['params', 'searchParams', ...r.params]) }));
    }
  }

  // Pages router API routes.
  if (/(?:^|\/)(?:src\/)?pages\/api\/.+\.[cm]?[jt]sx?$/.test(file)) {
    const path = normPath('/api/' + (/pages\/api\/(.*)$/.exec(file)![1]).replace(/\.[cm]?[jt]sx?$/, '').replace(/\/?index$/, ''));
    const ex = defaultExport(repo, v);
    if (ex) {
      const r = ex.r;
      const methods = [...new Set([...v.text.slice(r.start, r.end).matchAll(/\bmethod\s*(?:===?|!==?)\s*['"](\w+)['"]|\bcase\s+['"](GET|POST|PUT|PATCH|DELETE)['"]/g)].map((x) => (x[1] ?? x[2]).toUpperCase()))].filter((x) => METHODS.includes(x)).sort();
      for (const method of methods.length ? methods : ['ANY']) {
        out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'next-pages', file, line: v.lines.at(r.start), method, path, name: ex.exportName, confidence: 'high', handlerView: r.view, spec: spec(r, wrapperDeco(v, r), r.params.length ? r.params : ['req'], r.wrapper ? [r.wrapper.name.split('.').pop()!] : []) }));
      }
    }
  }

  // Server actions: a "use server" file, or the directive inside a function.
  const fileDirective = /^\s*(?:\/\/[^\n]*\n\s*|\/\*[\s\S]*?\*\/\s*)*['"]use server['"]/.test(text);
  if (fileDirective) {
    for (const e of exportedFunctions(repo, v)) {
      const r = e.r;
      out.entries.push(makeEntry(repo, { kind: 'server_action', framework: 'next-app', file, line: v.lines.at(r.start), method: 'POST', path: null, name: e.exportName, confidence: 'high', handlerView: r.view, spec: spec(r, wrapperDeco(v, r), r.params, r.wrapper ? [r.wrapper.name.split('.').pop()!] : []) }));
    }
  } else if (/['"]use server['"]/.test(text)) {
    for (const x of v.masked.matchAll(/(?:\basync\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*async\s*\(/g)) {
      const at = x.index!;
      const f = jsFunction(v.masked, at);
      if (!f || !/^\s*\{\s*['"]use server['"]/.test(text.slice(f.bodyStart, f.bodyStart + 60))) continue;
      out.entries.push(makeEntry(repo, { kind: 'server_action', framework: 'next-app', file, line: v.lines.at(at), method: 'POST', path: null, name: x[1] ?? x[2], confidence: 'high', handlerView: v, spec: { start: f.start, end: f.end, seeds: paramsOf(v.masked, f), decorators: [], returnsJson: true } }));
    }
  }

  // Middleware (a gate, not an entry point).
  if (/(?:^|\/)(?:src\/)?(?:middleware|proxy)\.[cm]?[jt]s$/.test(file)) {
    const named = exportedFunctions(repo, v).find((e) => e.exportName === 'middleware' || e.exportName === 'proxy');
    const dflt = named ? null : defaultExport(repo, v);
    const fn = named ? { r: named.r } : dflt ? { r: dflt.r } : null;
    if (fn) {
      const a = analyze(v, spec(fn.r, wrapperDeco(v, fn.r), fn.r.params.length ? fn.r.params : ['req', 'request']), repo.helpers('js'));
      const matcher = /\bmatcher\s*:\s*(\[[^\]]*\]|['"][^'"]*['"])/.exec(text);
      const matcherPaths = matcher ? [...matcher[1].matchAll(/['"]([^'"]*)['"]/g)].map((x) => gatePrefix(x[1])) : [];
      // A check inside "if (pathname.startsWith('/admin'))" covers only those prefixes, not the whole matcher.
      const blocks = [...v.masked.slice(fn.r.start, fn.r.end).matchAll(/\bif\s*\(/g)].map((x) => {
        const open = fn.r.start + x.index! + x[0].length - 1;
        const condEnd = closeOf(v.masked, open);
        if (condEnd < 0) return null;
        const prefixes = [...text.slice(open, condEnd).matchAll(/startsWith\(\s*['"](\/[^'"]*)['"]/g)].map((y) => normPath(y[1].replace(/\/$/, '') || '/'));
        const b = v.masked.indexOf('{', condEnd);
        const bEnd = b < 0 ? -1 : closeOf(v.masked, b);
        return prefixes.length && b >= 0 && bEnd > 0 && /^\s*\{/.test(v.masked.slice(condEnd, b + 1)) ? { start: b, end: bEnd, prefixes } : null;
      }).filter((x): x is { start: number; end: number; prefixes: string[] } => x !== null);
      const groups = new Map<string, Protection[]>();
      const blockAt = (pos: number): { start: number; end: number; prefixes: string[] } | undefined => blocks.filter((b) => pos >= b.start && pos <= b.end).sort((x, y) => (x.end - x.start) - (y.end - y.start))[0];
      for (const p of a.protections.filter((q) => q.kind !== 'owner_filter')) {
        const at = v.lines.start(p.line);
        let prefixes = blockAt(at)?.prefixes ?? null;
        if (!prefixes) {
          // The value is stored in a variable and tested later: use the blocks that test it, when all of them are inside one.
          const lineText = text.slice(at, text.indexOf('\n', at) < 0 ? text.length : text.indexOf('\n', at));
          const name = /(?:const|let|var)\s+(\w+)\s*=/.exec(lineText)?.[1];
          if (name) {
            const uses = [...v.masked.slice(fn.r.start, fn.r.end).matchAll(new RegExp(`(?<![\\w$.])${name}\\b`, 'g'))].map((x) => fn.r.start + x.index!).filter((pos) => v.lines.at(pos) !== p.line);
            const inBlocks = uses.map((pos) => blockAt(pos));
            if (uses.length && inBlocks.every((b) => b)) prefixes = [...new Set(inBlocks.flatMap((b) => b!.prefixes))];
          }
        }
        const key = prefixes ? [...new Set(prefixes)].sort().join('\u0000') : '*';
        groups.set(key, [...(groups.get(key) ?? []), { ...p, scope: 'middleware' as const }]);
      }
      for (const [key, protections] of [...groups.entries()].sort()) {
        const paths = key === '*' ? (matcherPaths.length ? [...new Set(matcherPaths)].sort() : ['*']) : key.split('\u0000');
        const gate: Gate = {
          id: `${file}:${v.lines.at(fn.r.start)}:middleware:${key === '*' ? 'all' : paths.join(',')}`, kind: 'middleware', framework: 'next-app', file, line: v.lines.at(fn.r.start),
          paths, methods: [], protections, confidence: 'medium',
        };
        out.gates.push(gate);
      }
    }
  }

  // Supabase edge functions.
  const edge = /(?:^|\/)supabase\/functions\/([^/_][^/]*)\/index\.[cm]?[jt]sx?$/.exec(file);
  if (edge) {
    const serve = /\b(?:Deno\.)?serve\s*\(/.exec(v.masked);
    if (serve) {
      const open = serve.index + serve[0].length - 1;
      const args = splitArgs(v.masked, open);
      const fa = args.map((a) => ({ a, r: resolveFunction(repo, v, a.start, a.end) })).find((x) => x.r);
      if (fa?.r) {
        const e = makeEntry(repo, { kind: 'http_route', framework: 'supabase-edge', file, line: v.lines.at(serve.index), method: 'ANY', path: `/functions/v1/${edge[1]}`, name: edge[1], confidence: 'high', handlerView: fa.r.view, spec: spec(fa.r, [], fa.r.params.length ? fa.r.params : ['req', 'request']) });
        const cfg = repo.ctx.text('supabase/config.toml');
        const sec = new RegExp(`\\[functions\\.${edge[1].replace(/[-\\^$*+?.()|[\]{}]/g, '\\$&')}\\]([^\\[]*)`).exec(cfg);
        const off = sec ? /verify_jwt\s*=\s*false/.test(sec[1]) : false;
        if (!off) e.protections.push({ kind: 'session_read', scope: 'global', file: cfg ? 'supabase/config.toml' : file, line: 1, via: 'supabase verify_jwt (default on)', enforced: true, confidence: cfg ? 'high' : 'medium' });
        e.protections.sort((x, y) => x.line - y.line || (x.kind < y.kind ? -1 : 1));
        out.entries.push(e);
      }
    }
  }

  // tRPC procedures.
  if (/[pP]rocedure\b/.test(v.masked) && /trpc|Procedure/.test(v.imports + v.text.slice(0, 3000))) {
    for (const x of v.masked.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*[pP]rocedure)\b/g)) {
      let i = x.index! + x[0].length;
      let verb: string | null = null;
      let handler: Extent | null = null;
      const chain: string[] = [];
      for (let guard = 0; guard < 12; guard++) {
        while (/\s/.test(v.masked[i] ?? '')) i++;
        if (v.masked[i] !== '.') break;
        const call = /^\.\s*(\w+)\s*\(/.exec(v.masked.slice(i));
        if (!call) break;
        const open = i + call[0].length - 1;
        const close = closeOf(v.masked, open);
        if (close < 0) break;
        chain.push(call[1]);
        if (['query', 'mutation', 'subscription'].includes(call[1])) {
          verb = call[1];
          const a = splitArgs(v.masked, open)[0];
          handler = a ? jsFunction(v.masked, a.start) : null;
          i = close;
          break;
        }
        i = close;
      }
      if (!verb || !handler) continue;
      const procName = x[2];
      const deco: NonNullable<Spec['decorators']> = [{ view: v, start: x.index! + x[1].length, end: handler.start, scope: 'router' }];
      const e = makeEntry(repo, { kind: 'rpc', framework: 'trpc', file, line: v.lines.at(x.index!), method: verb.toUpperCase(), path: x[1], name: x[1], confidence: 'high', handlerView: v, spec: { start: handler.start, end: handler.end, seeds: ['input', 'ctx', ...paramsOf(v.masked, handler)], decorators: deco, returnsJson: true } });
      if (/protected|auth|private|member|user|admin|session|staff/i.test(procName)) e.protections.push({ kind: 'session_read', scope: 'router', file, line: e.line, via: `procedure ${procName}`, enforced: true, confidence: 'medium' });
      if (/admin|staff|owner/i.test(procName) || ADMIN_PATH.test(procName)) e.protections.push({ kind: 'role_check', scope: 'router', file, line: e.line, via: `procedure ${procName}`, enforced: true, confidence: 'medium' });
      if (chain.includes('input')) e.protections.push({ kind: 'input_validation', scope: 'router', file, line: e.line, via: 'trpc .input()', enforced: true, confidence: 'high' });
      e.protections.sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.via < b.via ? -1 : 1));
      out.entries.push(e);
    }
  }
  return out;
}

function defaultExport(repo: Repo, v: FileView): { exportName: string | null; r: Resolved } | null {
  const m = v.masked;
  const x = /\bexport\s+default\s+/.exec(m);
  if (!x) return null;
  const at = x.index + x[0].length;
  const limit = statementLimit(m, at);
  const direct = jsFunction(m, at);
  const named = /^(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/.exec(m.slice(at, at + 80));
  const r = direct ? { view: v, start: direct.start, end: direct.end, wrapper: null, resolved: false, params: paramsOf(m, direct) } : resolveFunction(repo, v, at, limit);
  return r ? { exportName: named?.[1] ?? null, r } : null;
}

// A middleware matcher such as "/admin/:path*" or "/api/(.*)" as the path prefix it covers.
function gatePrefix(matcher: string): string {
  const p = matcher.replace(/\/?(?::\w+\*?|\(\.\*\)|\*)$/g, '').replace(/\/\(\.\*\)$/, '');
  return normPath(p === '' ? '*' : p.startsWith('/') ? p : `/${p}`);
}

export { joinPath };
