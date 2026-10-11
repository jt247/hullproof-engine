// Go entry points: net/http (ServeMux, including the Go 1.22 "METHOD /path" patterns), chi, gin, echo, fiber and gorilla/mux.
// Router variables are followed in order inside a function (Group, Route, With, Use, PathPrefix), routers handed in as
// parameters are read at the prefix the file can see, and a Mount or a router returned by a function is followed to its
// definition. Pattern based, like the other extractors; every fact carries a confidence.
import type { EntryPoint, Scope } from '../types/index.ts';
import type { FileView } from './analyze.ts';
import { empty, joinPath, makeEntry, type Extracted } from './entry.ts';
import { goFunc, type FnIndex } from './light-index.ts';
import { analyzeLight, type LightDeco } from './light.ts';
import { closeOf, splitArgs } from './lex.ts';
import type { LocalVocab } from './local-vocab.ts';
import type { Repo } from './repo.ts';

interface Mw { view: FileView; start: number; end: number; scope: Scope; only: string | null }
interface Env { prefix: string; mws: Mw[]; fw: string; param: boolean }
interface FnRef { file: string; view: FileView; start: number; end: number; bodyStart: number; params: string; name: string }
interface MountCall { prefix: string; mws: Mw[]; fw: string; targets: string[]; from: string }

const ROUTER_TYPE = /\*?(?:gin\.(?:Engine|RouterGroup|IRouter|IRoutes)|chi\.(?:Router|Mux)|echo\.(?:Echo|Group)|fiber\.(?:App|Router)|mux\.Router|http\.ServeMux)\b/;
const FW_BY_IMPORT: [RegExp, string][] = [[/gin-gonic\/gin/, 'gin'], [/go-chi\/chi/, 'chi'], [/labstack\/echo/, 'echo'], [/gofiber\/fiber/, 'fiber'], [/gorilla\/mux/, 'gorilla-mux']];
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']);
const CREATE = /(?<![\w.])([A-Za-z_]\w*)\s*(?::=|=)\s*(?:chi\.NewRouter|chi\.NewMux|gin\.Default|gin\.New|echo\.New|fiber\.New|mux\.NewRouter|http\.NewServeMux|NewRouter|NewServeMux)\s*\(/g;
const ROUTE_CALLS = new Set(['Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'Any', 'All', 'Handle', 'HandleFunc', 'Method', 'MethodFunc', 'Match', 'Add', 'Connect', 'Trace', 'Mount', 'Use', 'Group', 'Route', 'With', 'PathPrefix', 'Subrouter', 'Static']);

const unq = (s: string): string | null => /^\s*(?:"((?:\\.|[^"\\])*)"|`([^`]*)`)\s*$/.exec(s)?.slice(1).find((x) => x !== undefined) ?? null;

export function goFiles(repo: Repo): string[] {
  return repo.filesOf('go').filter((f) => { const v = repo.view(f); return !!v && /net\/http|gin-gonic|go-chi|labstack\/echo|gofiber|gorilla\/mux/.test(v.imports); });
}

export function extractGoAll(repo: Repo, fn: FnIndex, local: LocalVocab | null): Extracted {
  const out = empty();
  const keyOf = (f: FnRef): string => `${f.file}#${f.start}`;
  const funcs: FnRef[] = [];
  for (const file of goFiles(repo)) {
    const v = repo.view(file)!;
    for (const x of v.masked.matchAll(/^func\s+(?:\(\s*\w*\s*\*?\s*[\w.[\]]+\s*\)\s*)?(\w+)\s*[([]/gm)) {
      const f = goFunc(v.masked, x.index!);
      if (f) funcs.push({ file, view: v, start: f.start, end: f.end, bodyStart: f.bodyStart, params: f.params, name: x[1] });
    }
    // Package level routing, outside any function: var mux = http.NewServeMux(); func init() is a function and is covered above.
  }
  const scanned = new Map<string, { entries: EntryPoint[]; mounts: MountCall[] }>();
  const mounted = new Map<string, Env>();
  const scan = (f: FnRef, base: Env | null): { entries: EntryPoint[]; mounts: MountCall[] } => {
    const r = scanFunction(repo, fn, local, f, base);
    return r;
  };
  for (const f of funcs) scanned.set(keyOf(f), scan(f, null));
  // Mounted routers: scan the function that builds them again at the mount prefix, and drop its standalone result.
  const queue: MountCall[] = [...scanned.values()].flatMap((s) => s.mounts);
  for (let depth = 0; depth < 4 && queue.length; depth++) {
    const next: MountCall[] = [];
    for (const m of queue.splice(0)) {
      for (const name of m.targets) {
        const t = fn.defs(name).filter((d) => d.view.lang === 'go' && funcs.some((f) => f.file === d.view.file && f.start === d.start))[0];
        if (!t) continue;
        const ref = funcs.find((f) => f.file === t.view.file && f.start === t.start)!;
        const key = keyOf(ref);
        if (mounted.has(key)) continue;
        const env: Env = { prefix: m.prefix, mws: m.mws, fw: m.fw, param: true };
        mounted.set(key, env);
        const res = scan(ref, env);
        scanned.set(key, res);
        next.push(...res.mounts);
      }
    }
    queue.push(...next);
  }
  for (const [, s] of [...scanned.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) out.entries.push(...s.entries);
  return out;
}

function scanFunction(repo: Repo, fn: FnIndex, local: LocalVocab | null, f: FnRef, base: Env | null): { entries: EntryPoint[]; mounts: MountCall[] } {
  const v = f.view;
  const fw0 = FW_BY_IMPORT.find(([re]) => re.test(v.imports))?.[1] ?? 'net-http';
  const entries: EntryPoint[] = [];
  const mounts: MountCall[] = [];
  const env = new Map<string, Env>();
  let baseUsed = false;
  const fresh = (): Env => { if (base && !baseUsed) { baseUsed = true; return { ...base, mws: base.mws.slice() }; } return { prefix: '', mws: [], fw: fw0, param: false }; };
  // Routers handed in as parameters.
  for (const part of f.params.split(',')) {
    const m = /^\s*(\w+)\s+(.+)$/.exec(part);
    if (m && ROUTER_TYPE.test(m[2])) env.set(m[1], base ? { ...base, mws: base.mws.slice() } : { prefix: '', mws: [], fw: fw0, param: true });
  }
  if (base && env.size) baseUsed = true;
  if (/"net\/http"/.test(v.imports)) env.set('http', { prefix: '', mws: [], fw: 'net-http', param: false });

  const text = v.text;
  const masked = v.masked;
  const mwOf = (a: { start: number; end: number }, scope: Scope, only: string | null = null): Mw => ({ view: v, start: a.start, end: a.end, scope, only });

  const route = (e: Env, recv: string, method: string, open: number, chained: Mw[], at: number, forced: string | null): void => {
    const args = splitArgs(masked, open);
    if (!args.length) return;
    let verb: string | null = forced;
    let pathIdx = 0;
    if (method === 'Handle' && args.length >= 3 && unq(text.slice(args[0].start, args[0].end)) && METHODS.has(unq(text.slice(args[0].start, args[0].end))!)) { verb = unq(text.slice(args[0].start, args[0].end))!; pathIdx = 1; }
    if (method === 'Add' && args.length >= 3) { verb = unq(text.slice(args[0].start, args[0].end)); pathIdx = 1; }
    if ((method === 'Method' || method === 'MethodFunc') && args.length >= 3) { verb = unq(text.slice(args[0].start, args[0].end))?.toUpperCase() ?? null; pathIdx = 1; }
    if (method === 'Match' && args.length >= 3) { verb = 'ANY'; pathIdx = 1; }
    if (!verb) verb = ROUTE_CALLS.has(method) && METHODS.has(method.toUpperCase()) ? method.toUpperCase() : 'ANY';
    let path = unq(text.slice(args[pathIdx].start, args[pathIdx].end));
    if (path === null) return;
    // Go 1.22 patterns: "GET /notes/{id}", and gorilla/chi style braces.
    const pm = /^([A-Z]+)\s+(\S.*)$/.exec(path);
    if (pm && METHODS.has(pm[1])) { verb = pm[1]; path = pm[2]; }
    path = path.replace(/\{(\w+)(?::[^}]*)?\}/g, ':$1').replace(/:(\w+)(?=\/|$)/g, ':$1').replace(/\*(\w*)/g, (_m, n) => `*${n || 'rest'}`).replace(/\{(\w+)\.\.\.\}/g, '*$1');
    const rest = args.slice(pathIdx + 1);
    if (!rest.length) return;
    const echo = e.fw === 'echo';
    const handlerArg = echo ? rest[0] : rest[rest.length - 1];
    const perRoute = (echo ? rest.slice(1) : rest.slice(0, -1)).map((a) => mwOf(a, 'wrapper'));
    const full = joinPath(e.prefix, path);
    const handlerText = text.slice(handlerArg.start, handlerArg.end);
    if (/\bFileServer\b|\bStripPrefix\b|\bStatic\b/.test(handlerText) && !/func\s*\(/.test(handlerText)) return;
    const resolved = resolveHandler(repo, fn, v, handlerArg);
    const decorators: LightDeco[] = [
      ...e.mws.filter((m) => m.only === null || full.startsWith(m.only)).map((m) => ({ view: m.view, start: m.start, end: m.end, scope: m.scope })),
      ...chained.map((m) => ({ view: m.view, start: m.start, end: m.end, scope: m.scope })),
      ...perRoute.map((m) => ({ view: m.view, start: m.start, end: m.end, scope: m.scope })),
      ...resolved.wrappers.map((w) => ({ view: v, start: w.start, end: w.end, scope: 'wrapper' as Scope })),
    ];
    const hv = resolved.view;
    const a = analyzeLight(hv, { start: resolved.start, end: resolved.end, seeds: [], decorators, lookup: fn.find, local });
    const line = v.lines.at(at);
    entries.push(makeEntry(repo, {
      kind: 'http_route', framework: e.fw, file: v.file, line, method: verb, path: full, name: resolved.name,
      confidence: e.param || !resolved.found ? 'medium' : 'high', handlerView: hv, spec: { start: resolved.start, end: resolved.end, seeds: [] }, analysis: a,
    }));
  };

  // Events in order: router creation, groups, middleware, routes, mounts.
  type Ev = { at: number; kind: 'create' | 'call'; m: RegExpExecArray };
  const evs: Ev[] = [];
  const body = [f.bodyStart, f.end] as const;
  CREATE.lastIndex = 0;
  for (const m of masked.slice(body[0], body[1]).matchAll(CREATE)) evs.push({ at: body[0] + m.index!, kind: 'create', m: m as RegExpExecArray });
  const callRe = /(?<![\w.])([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(/g;
  for (const m of masked.slice(body[0], body[1]).matchAll(callRe)) evs.push({ at: body[0] + m.index!, kind: 'call', m: m as RegExpExecArray });
  evs.sort((a, b) => a.at - b.at || (a.kind === 'create' ? -1 : 1));
  let skipTo = -1;
  const handleCall = (recv: string, method: string, at: number, open: number, e: Env, assignTo: string | null, within: Map<string, Env>): number => {
    const args = splitArgs(masked, open);
    const closeAt = closeOf(masked, open);
    if (method === 'Use') {
      let only: string | null = null;
      let list = args;
      if (e.fw === 'fiber' && args.length > 1 && unq(text.slice(args[0].start, args[0].end)) !== null) { only = unq(text.slice(args[0].start, args[0].end)); list = args.slice(1); }
      for (const a of list) e.mws.push(mwOf(a, 'router', only === null ? null : joinPath(e.prefix, only)));
      return closeAt;
    }
    if ((method === 'Group' || method === 'Route') && args.length) {
      // chi: r.Route("/p", func(r chi.Router) { ... }) and r.Group(func(r chi.Router) { ... })
      const lit = args.find((a) => /^func\s*\(/.test(masked.slice(a.start, a.end)));
      if (lit && /\bchi\b|Router/.test(masked.slice(lit.start, lit.start + 80))) {
        const g = goFunc(masked, lit.start);
        const pm = /^func\s*\(\s*(\w+)/.exec(masked.slice(lit.start));
        if (g && pm) {
          const p = method === 'Route' ? unq(text.slice(args[0].start, args[0].end)) ?? '' : '';
          const child: Env = { prefix: joinPath(e.prefix, p || '/'), mws: e.mws.slice(), fw: e.fw, param: e.param };
          const inner = new Map(within);
          inner.set(pm[1], child);
          walkRange(g.bodyStart + 1, g.end - 1, inner);
          return g.end;
        }
      }
      if (assignTo) {
        const p = unq(text.slice(args[0].start, args[0].end)) ?? '';
        const child: Env = { prefix: joinPath(e.prefix, p || '/'), mws: [...e.mws, ...args.slice(1).map((a) => mwOf(a, 'router'))], fw: e.fw, param: e.param };
        within.set(assignTo, child);
        return closeAt;
      }
      return closeAt;
    }
    if (method === 'PathPrefix' && assignTo) {
      const p = unq(text.slice(args[0]?.start ?? 0, args[0]?.end ?? 0)) ?? '';
      within.set(assignTo, { prefix: joinPath(e.prefix, p || '/'), mws: e.mws.slice(), fw: e.fw, param: e.param });
      return closeAt;
    }
    if (method === 'With') {
      const tail = /^\s*\.\s*([A-Za-z_]\w*)\s*\(/.exec(masked.slice(closeAt, closeAt + 60));
      if (tail) {
        const chained = args.map((a) => mwOf(a, 'wrapper'));
        const open2 = closeAt + tail[0].length - 1;
        route(e, recv, tail[1], open2, chained, at, null);
        return closeOf(masked, open2);
      }
      return closeAt;
    }
    if (method === 'Mount') {
      const p = unq(text.slice(args[0]?.start ?? 0, args[0]?.end ?? 0));
      const target = args[1] ? text.slice(args[1].start, args[1].end) : '';
      if (p !== null) {
        const names = [...target.matchAll(/(?<![\w.])(\w+)\s*\(/g)].map((x) => x[1]).concat(/^\s*\w+\s*$/.test(target) ? [target.trim()] : []);
        mounts.push({ prefix: joinPath(e.prefix, p), mws: e.mws.slice(), fw: e.fw, targets: names, from: v.file });
      }
      return closeAt;
    }
    if (method === 'Subrouter' || method === 'Static') return closeAt;
    if (ROUTE_CALLS.has(method) || METHODS.has(method.toUpperCase())) {
      // gorilla/mux: r.HandleFunc("/x", h).Methods("POST")
      let forced: string | null = null;
      const meth = /^\s*\.\s*Methods\s*\(([^)]*)\)/.exec(masked.slice(closeAt, closeAt + 80));
      if (meth) forced = [...text.slice(closeAt, closeAt + 120).matchAll(/"(\w+)"/g)].map((x) => x[1].toUpperCase())[0] ?? null;
      route(e, recv, method, open, [], at, forced);
      return meth ? closeAt + meth[0].length : closeAt;
    }
    return closeAt;
  };
  const walkRange = (from: number, to: number, scope: Map<string, Env>): void => {
    for (const ev of evs) {
      if (ev.at < from || ev.at >= to || ev.at < skipTo) continue;
      if (ev.kind === 'create') {
        scope.set(ev.m[1], fresh());
        continue;
      }
      const recv = ev.m[1];
      const method = ev.m[2];
      const e = scope.get(recv);
      if (!e) continue;
      const open = ev.at + ev.m[0].length - 1;
      const pre = masked.slice(Math.max(0, ev.at - 80), ev.at);
      const assign = /(?:^|\n)\s*(\w+)\s*:?=\s*$/.exec(pre)?.[1] ?? null;
      const end = handleCall(recv, method, ev.at, open, e, assign, scope);
      if (end > skipTo) skipTo = end;
    }
  };
  walkRange(body[0], body[1], env);
  return { entries, mounts };
}

interface Resolved { view: FileView; start: number; end: number; name: string | null; found: boolean; wrappers: { start: number; end: number }[] }

// A handler argument: a function literal, a name, a method value (h.CreateNote), or a call that wraps or builds a handler.
function resolveHandler(repo: Repo, fn: FnIndex, v: FileView, a: { start: number; end: number }, depth = 0): Resolved {
  const m = v.masked;
  const t = m.slice(a.start, a.end).trim();
  const miss: Resolved = { view: v, start: a.start, end: a.end, name: /^(?:\w+\.)*(\w+)$/.exec(t)?.[1] ?? null, found: false, wrappers: [] };
  if (depth > 4) return miss;
  if (/^func\s*\(/.test(t)) {
    const g = goFunc(m, a.start + (m.slice(a.start, a.end).length - m.slice(a.start, a.end).trimStart().length));
    if (g) return { view: v, start: g.start, end: g.end, name: null, found: true, wrappers: [] };
  }
  const call = /^((?:\w+\.)*\w+)\s*\(/.exec(t);
  if (call) {
    const at = a.start + (m.slice(a.start, a.end).length - m.slice(a.start, a.end).trimStart().length);
    const open = at + call[0].length - 1;
    const args = splitArgs(m, open);
    const head = call[1];
    const last = head.split('.').pop()!;
    if (/^HandlerFunc$/.test(last) && args.length === 1) return resolveHandler(repo, fn, v, args[0], depth + 1);
    for (const x of args) {
      const r = resolveHandler(repo, fn, v, x, depth + 1);
      if (r.found) return { ...r, wrappers: [{ start: at, end: x.start }, ...r.wrappers] };
    }
    // A handler factory: s.handleCreate() returns the handler, so read its body.
    const def = fn.find(last, v.file) ?? fn.defs(last)[0];
    if (def) return { view: def.view, start: def.start, end: def.end, name: last, found: true, wrappers: [] };
    return miss;
  }
  const nm = /^(?:\w+\.)*(\w+)$/.exec(t)?.[1];
  if (nm) {
    const defs = fn.defs(nm);
    const def = fn.find(nm, v.file) ?? defs.find((d) => d.view.file === v.file) ?? defs[0];
    if (def) return { view: def.view, start: def.start, end: def.end, name: nm, found: true, wrappers: [] };
  }
  return miss;
}

