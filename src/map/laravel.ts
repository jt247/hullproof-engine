// PHP and Laravel entry points: routes/*.php (Route::get and the other verbs, match, any, resource, apiResource, controller
// and middleware groups, prefix, closures and invokable controllers) joined to the controller methods they name, with the
// middleware each route runs (the group chain, the route chain, the controller constructor, HasMiddleware, attributes and
// authorizeResource) as its protections, and the api throttle group from bootstrap/app.php or the HTTP kernel.
import type { Protection } from '../types/index.ts';
import type { FileView } from './analyze.ts';
import { empty, joinPath, makeEntry, type Extracted } from './entry.ts';
import { phpFunc, type FnIndex } from './light-index.ts';
import { analyzeLight, type LightDeco } from './light.ts';
import { closeOf, splitArgs } from './lex.ts';
import type { LocalVocab } from './local-vocab.ts';
import type { Repo } from './repo.ts';

interface Mw { view: FileView; start: number; end: number }
interface Ctx { prefix: string; mws: Mw[]; controller: string | null; without: string[] }
interface Call { name: string; open: number; close: number }
interface CtrlFilter { view: FileView; start: number; end: number; only: string[] | null; except: string[] | null }

const VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'any']);
const singular = (s: string): string => (/ies$/.test(s) ? s.replace(/ies$/, 'y') : s.replace(/s$/, ''));
const phpPath = (p: string): string => p.replace(/\{(\w+)\??(?::[^}]*)?\}/g, ':$1');
const strs = (s: string): string[] => [...s.matchAll(/['"]([^'"]*)['"]/g)].map((m) => m[1]);

export function laravelFiles(repo: Repo): string[] {
  return repo.filesOf('php').filter((f) => /(?:^|\/)routes\/(?!console|channels)[\w.-]+\.php$/.test(f));
}

function chainAt(v: FileView, at: number): { calls: Call[]; end: number } {
  const m = v.masked;
  const calls: Call[] = [];
  let pos = at + 'Route::'.length;
  for (let guard = 0; guard < 24; guard++) {
    const id = /^\s*(\w+)\s*\(/.exec(m.slice(pos, pos + 800));
    if (!id) break;
    const open = pos + id[0].length - 1;
    const close = closeOf(m, open);
    if (close < 0) break;
    calls.push({ name: id[1], open, close });
    pos = close;
    const arrow = /^\s*->\s*/.exec(m.slice(pos, pos + 800)); // comments are blank in the masked copy and can be long
    if (!arrow) break;
    pos += arrow[0].length;
  }
  return { calls, end: pos };
}

export function extractLaravelAll(repo: Repo, fn: FnIndex, local: LocalVocab | null): Extracted {
  const out = empty();
  const files = laravelFiles(repo);
  if (!files.length) return out;

  // Classes by short name: controllers, models and middleware.
  const classes = new Map<string, FileView>();
  for (const f of repo.filesOf('php')) {
    if (/(?:^|\/)(?:vendor|node_modules)\//.test(f)) continue;
    const v = repo.view(f);
    if (!v) continue;
    const m = /^[ \t]*(?:final\s+|abstract\s+)?class\s+(\w+)/m.exec(v.masked);
    if (m && !classes.has(m[1])) classes.set(m[1], v);
  }
  const isModel = (cls: string): boolean => { const v = classes.get(cls); return !!v && (/\/Models\//.test(v.file) || /\bextends\s+(?:Model|Authenticatable|Pivot|\\?Illuminate\\Database\\Eloquent\\Model)\b/.test(v.masked)); };

  // Aliases of route middleware: 'admin' => EnsureUserIsAdmin::class.
  const aliases = new Map<string, string>();
  const bootText = ['bootstrap/app.php', 'app/Http/Kernel.php', 'app/Providers/RouteServiceProvider.php'].map((f) => ({ f, t: repo.ctx.text(f) }));
  for (const { t } of bootText) for (const m of t.matchAll(/['"]([\w.-]+)['"]\s*=>\s*\\?(?:[\w\\]*\\)?(\w+)::class/g)) aliases.set(m[1], m[2]);
  let apiThrottle: Protection | null = null;
  for (const { f, t } of bootText) {
    const m = /throttleApi\s*\(|['"]throttle:api['"]|['"]api['"]\s*=>\s*\[[^\]]*throttle/.exec(t);
    if (m && !apiThrottle) apiThrottle = { kind: 'rate_limit', scope: 'global', file: f, line: t.slice(0, m.index).split('\n').length, via: 'api middleware group throttle', enforced: true, confidence: 'medium' };
  }

  // Controller level middleware: constructor, HasMiddleware, attributes, authorizeResource.
  const ctrlFilters = (cls: string): { filters: CtrlFilter[]; policy: boolean } => {
    const v = classes.get(cls);
    const filters: CtrlFilter[] = [];
    let policy = false;
    if (!v) return { filters, policy };
    const m = v.masked;
    const lists = (text: string): { only: string[] | null; except: string[] | null } => ({
      only: /->\s*only\s*\(([^)]*)\)/.exec(text) ? strs(/->\s*only\s*\(([^)]*)\)/.exec(text)![1]) : null,
      except: /->\s*except\s*\(([^)]*)\)/.exec(text) ? strs(/->\s*except\s*\(([^)]*)\)/.exec(text)![1]) : null,
    });
    for (const x of m.matchAll(/\$this->middleware\s*\(/g)) {
      const open = x.index! + x[0].length - 1;
      const close = closeOf(m, open);
      if (close < 0) continue;
      const stmtEnd = m.indexOf(';', close);
      const tail = v.text.slice(close, stmtEnd < 0 ? close : stmtEnd);
      filters.push({ view: v, start: x.index!, end: Math.max(close, stmtEnd < 0 ? close : stmtEnd), ...lists(tail) });
    }
    for (const x of m.matchAll(/\$this->authorizeResource\s*\(/g)) {
      const open = x.index! + x[0].length - 1;
      const close = closeOf(m, open);
      policy = true;
      filters.push({ view: v, start: x.index!, end: close < 0 ? open : close, only: null, except: null });
    }
    const sm = /static\s+function\s+middleware\s*\(/.exec(m);
    if (sm) {
      const f = phpFunc(m, sm.index);
      if (f) {
        const body = v.text.slice(f.bodyStart, f.end);
        const bm = m.slice(f.bodyStart, f.end);
        let covered = 0;
        for (const x of bm.matchAll(/new\s+(?:\\?[\w\\]*\\)?Middleware\s*\(/g)) {
          const open = f.bodyStart + x.index! + x[0].length - 1;
          const close = closeOf(m, open);
          if (close < 0) continue;
          const t = v.text.slice(open, close);
          filters.push({ view: v, start: open, end: close, only: /only:\s*\[([^\]]*)\]/.exec(t) ? strs(/only:\s*\[([^\]]*)\]/.exec(t)![1]) : null, except: /except:\s*\[([^\]]*)\]/.exec(t) ? strs(/except:\s*\[([^\]]*)\]/.exec(t)![1]) : null });
          covered += close - open;
        }
        if (body.length) for (const x of body.matchAll(/(?<![\w(,]\s*)['"]([\w.:,-]+)['"]/g)) { void x; }
        if (!filters.some((fl) => fl.view === v && fl.start >= f.bodyStart && fl.end <= f.end)) filters.push({ view: v, start: f.bodyStart, end: f.end, only: null, except: null });
        void covered;
      }
    }
    const cm = /^[ \t]*(?:#\[[^\n]*\]\s*)+(?=(?:final\s+|abstract\s+)?class\b)/m.exec(m);
    if (cm) filters.push({ view: v, start: cm.index, end: cm.index + cm[0].length, only: null, except: null });
    return { filters, policy };
  };
  const methodAttrs = (v: FileView, fnStart: number): LightDeco | null => {
    const before = v.text.slice(Math.max(0, fnStart - 400), fnStart);
    const am = /((?:^|\n)[ \t]*#\[[^\n]*\][ \t]*\n[ \t]*)+(?:(?:public|protected|private|static)\s+)*$/.exec(before);
    return am ? { view: v, start: fnStart - am[0].length, end: fnStart, scope: 'router' } : null;
  };

  for (const rf of files) {
    const v = repo.view(rf);
    if (!v) continue;
    const m = v.masked;
    const isApi = /(?:^|\/)api\.php$/.test(rf);
    const base: Ctx = { prefix: isApi ? '/api' : '', mws: [], controller: null, without: [] };
    // Providers that load this file through a group: Route::prefix('api/v1')->middleware('api')->group(base_path('routes/api.php'))
    const name = /([\w-]+)\.php$/.exec(rf)![1];
    for (const { f, t } of bootText) {
      const pm = new RegExp(`Route::([^;]*?)->group\\s*\\(\\s*base_path\\s*\\(\\s*['"]routes/${name}\\.php['"]`).exec(t);
      if (pm) {
        const bv = repo.view(f);
        const pre = /prefix\s*\(\s*['"]([^'"]*)['"]/.exec(pm[1]);
        if (pre) base.prefix = joinPath('', pre[1]);
        if (bv && pm.index !== undefined) base.mws.push({ view: bv, start: pm.index, end: pm.index + pm[0].length });
      }
    }

    const handle = (calls: Call[], ctx: Ctx, at: number): void => {
      // Modifiers before the terminal call apply to everything under it; modifiers after it apply to the route.
      let c: Ctx = { ...ctx, mws: ctx.mws.slice(), without: ctx.without.slice() };
      const term = calls.findIndex((x) => VERBS.has(x.name) || ['match', 'resource', 'apiResource', 'resources', 'apiResources', 'singleton', 'group', 'webhooks'].includes(x.name));
      const route: Mw[] = [];
      const apply = (x: Call, into: Ctx, routeLevel: boolean): void => {
        const a = splitArgs(m, x.open);
        const range = { view: v, start: x.open - x.name.length - 2, end: x.close };
        if (x.name === 'prefix' && a[0]) into.prefix = joinPath(into.prefix, strs(v.text.slice(a[0].start, a[0].end))[0] ?? '');
        else if (x.name === 'middleware') (routeLevel ? route : into.mws).push(range);
        else if (x.name === 'can') (routeLevel ? route : into.mws).push(range);
        else if (x.name === 'withoutMiddleware') into.without.push(...strs(v.text.slice(x.open, x.close)));
        else if (x.name === 'controller' && a[0]) into.controller = /(\w+)::class/.exec(v.text.slice(a[0].start, a[0].end))?.[1] ?? null;
      };
      const mods = term < 0 ? calls : calls.slice(0, term);
      for (const x of mods) apply(x, c, false);
      if (term < 0) return;
      const t = calls[term];
      const after = calls.slice(term + 1);
      if (t.name === 'group') {
        const a = splitArgs(m, t.open);
        // Route::group(['prefix' => 'x', 'middleware' => ['auth']], function () { ... })
        if (a.length === 2) {
          const arr = v.text.slice(a[0].start, a[0].end);
          const px = /['"]prefix['"]\s*=>\s*['"]([^'"]*)['"]/.exec(arr);
          if (px) c.prefix = joinPath(c.prefix, px[1]);
          const mw = /['"]middleware['"]\s*=>/.exec(arr);
          if (mw) c.mws.push({ view: v, start: a[0].start + mw.index, end: a[0].end });
        }
        const closure = a.find((x) => /^(?:static\s+)?(?:function|fn)\b/.test(m.slice(x.start, x.end)));
        if (closure) {
          const body = /\{/.exec(m.slice(closure.start, closure.end));
          if (body) {
            const bs = closure.start + body.index;
            const be = closeOf(m, bs);
            for (const x of after) apply(x, c, false);
            walk(bs + 1, be < 0 ? closure.end : be - 1, c);
          } else if (/^(?:static\s+)?fn\b/.test(m.slice(closure.start, closure.end))) walk(closure.start, closure.end, c);
        }
        return;
      }
      for (const x of after) apply(x, c, true);
      const args = splitArgs(m, t.open);
      const line = v.lines.at(at);
      const text = (a: { start: number; end: number }): string => v.text.slice(a.start, a.end);
      const emit = (verb: string, path: string, handler: { start: number; end: number } | null, cls: string | null, method: string | null, extraName: string | null, ctrlOverride?: string | null): void => {
        const full = joinPath(c.prefix, phpPath(path));
        const cname = cls ?? ctrlOverride ?? null;
        const cv = cname ? classes.get(cname) : undefined;
        const fnDef = cv && method ? fn.defs(method).find((d) => d.view.file === cv.file) : undefined;
        const mws = [...c.mws.filter((x) => !c.without.some((w) => v.text.slice(x.start, x.end).includes(w))), ...route];
        const decos: LightDeco[] = [];
        const extra: Protection[] = [];
        for (const x of mws) {
          decos.push({ view: x.view, start: x.start, end: x.end, scope: x.view === v && route.includes(x) ? 'wrapper' : 'router' });
          // A middleware alias or class that lives in the repository: read the class.
          for (const nm of [...strs(x.view.text.slice(x.start, x.end)), ...[...x.view.text.slice(x.start, x.end).matchAll(/(\w+)::class/g)].map((y) => y[1])]) {
            const cls2 = aliases.get(nm.split(':')[0]) ?? nm;
            const mv = classes.get(cls2);
            if (mv && /Middleware\//.test(mv.file)) decos.push({ view: mv, start: 0, end: mv.text.length, scope: 'router' });
          }
        }
        let policy = false;
        let seeds: string[] = [];
        const bound: { name: string; target: string }[] = [];
        let hv: FileView = v;
        let start = m.lastIndexOf('\n', at) + 1;
        let end = t.close;
        let params = '';
        let found = false;
        if (handler) {
          const isClosure = /^(?:static\s+)?(?:function|fn)\b/.test(m.slice(handler.start, handler.end));
          if (isClosure) {
            const f = /^(?:static\s+)?function\b/.test(m.slice(handler.start, handler.end)) ? phpFunc(m, handler.start + m.slice(handler.start).indexOf('function')) : null;
            if (f) { start = f.start; end = f.end; params = f.params; found = true; } else { start = handler.start; end = handler.end; params = /\(([^)]*)\)/.exec(m.slice(handler.start, handler.end))?.[1] ?? ''; found = true; }
          }
        } else if (fnDef && cv) {
          hv = cv; start = fnDef.start; end = fnDef.end; found = true;
          const f = phpFunc(cv.masked, fnDef.start);
          params = f?.params ?? '';
          const { filters, policy: pol } = ctrlFilters(cname!);
          for (const fl of filters) {
            if (fl.only && (!method || !fl.only.includes(method))) continue;
            if (fl.except && method && fl.except.includes(method)) continue;
            decos.push({ view: fl.view, start: fl.start, end: fl.end, scope: 'router' });
          }
          policy = pol;
          const attr = methodAttrs(cv, fnDef.start);
          if (attr) decos.push(attr);
        }
        for (const part of params.split(/,(?![^(]*\))/)) {
          const pm = /^\s*(?:(?:public|protected|private|readonly)\s+)*(?:\??([\w\\]+)\s+)?(?:\.\.\.)?&?(\$\w+)/.exec(part);
          if (!pm) continue;
          const typ = pm[1]?.split('\\').pop() ?? null;
          if (typ && /Request$/.test(typ)) continue;
          if (typ && isModel(typ)) bound.push({ name: pm[2], target: typ });
          else if (!typ || /^(?:int|string|float|bool|mixed|array)$/.test(typ)) seeds.push(pm[2]);
        }
        if (apiThrottle && isApi) extra.push(apiThrottle);
        const a = analyzeLight(hv, { start, end, seeds, decorators: decos, extra, lookup: fn.find, local, policyScoped: policy, bound });
        out.entries.push(makeEntry(repo, {
          kind: 'http_route', framework: 'laravel', file: rf, line, method: verb, path: full || '/', name: extraName ?? (cname && method ? `${cname}@${method}` : null),
          confidence: found ? 'high' : 'low', handlerView: hv, spec: { start, end, seeds }, analysis: a,
        }));
      };
      const parseHandler = (a: { start: number; end: number } | undefined): { handler: { start: number; end: number } | null; cls: string | null; method: string | null } => {
        if (!a) return { handler: null, cls: c.controller, method: null };
        const t2 = text(a).trim();
        const arr = /^\[\s*\\?(?:[\w\\]*\\)?(\w+)::class\s*,\s*['"](\w+)['"]\s*\]$/.exec(t2);
        if (arr) return { handler: null, cls: arr[1], method: arr[2] };
        const str = /^['"](?:[\w\\]*\\)?(\w+)@(\w+)['"]$/.exec(t2);
        if (str) return { handler: null, cls: str[1], method: str[2] };
        const inv = /^\\?(?:[\w\\]*\\)?(\w+)::class$/.exec(t2);
        if (inv) return { handler: null, cls: inv[1], method: '__invoke' };
        const mt = /^['"](\w+)['"]$/.exec(t2);
        if (mt && c.controller) return { handler: null, cls: c.controller, method: mt[1] };
        if (/^(?:static\s+)?(?:function|fn)\b/.test(m.slice(a.start, a.end).trim())) return { handler: a, cls: null, method: null };
        return { handler: null, cls: null, method: null };
      };
      if (VERBS.has(t.name)) {
        const p = strs(text(args[0] ?? { start: 0, end: 0 }))[0];
        if (p === undefined) return;
        const h = parseHandler(args[1]);
        if (!h.handler && !h.cls && args[1] === undefined) return;
        emit(t.name === 'any' ? 'ANY' : t.name.toUpperCase(), p, h.handler, h.cls, h.method, null);
      } else if (t.name === 'match') {
        const verbs = strs(text(args[0] ?? { start: 0, end: 0 })).map((x) => x.toUpperCase());
        const p = strs(text(args[1] ?? { start: 0, end: 0 }))[0];
        if (p === undefined) return;
        const h = parseHandler(args[2]);
        for (const verb of verbs.length ? verbs : ['ANY']) emit(verb, p, h.handler, h.cls, h.method, null);
      } else if (t.name === 'resource' || t.name === 'apiResource' || t.name === 'singleton') {
        const nm = strs(text(args[0] ?? { start: 0, end: 0 }))[0];
        const cls = /(\w+)::class/.exec(text(args[1] ?? { start: 0, end: 0 }))?.[1] ?? null;
        if (!nm || !cls) return;
        const only = after.find((x) => x.name === 'only');
        const except = after.find((x) => x.name === 'except');
        const onlyL = only ? strs(v.text.slice(only.open, only.close)) : null;
        const exceptL = except ? strs(v.text.slice(except.open, except.close)) : null;
        const segs = nm.split('.');
        const prefix = segs.slice(0, -1).map((s) => `/${s}/:${singular(s)}`).join('');
        const last = segs[segs.length - 1];
        const param = singular(last);
        const acts: [string, string, string][] = t.name === 'singleton'
          ? [['show', 'GET', ''], ['update', 'PUT', ''], ['update', 'PATCH', '']]
          : [['index', 'GET', ''], ['create', 'GET', '/create'], ['store', 'POST', ''], ['show', 'GET', `/:${param}`], ['edit', 'GET', `/:${param}/edit`], ['update', 'PUT', `/:${param}`], ['update', 'PATCH', `/:${param}`], ['destroy', 'DELETE', `/:${param}`]];
        for (const [act, verb, sfx] of acts) {
          if (t.name === 'apiResource' && (act === 'create' || act === 'edit')) continue;
          if (onlyL && !onlyL.includes(act)) continue;
          if (exceptL && exceptL.includes(act)) continue;
          emit(verb, `${prefix}/${last}${sfx}`, null, cls, act, null);
        }
      } else if (t.name === 'resources' || t.name === 'apiResources') {
        for (const x of v.text.slice(t.open, t.close).matchAll(/['"]([\w.-]+)['"]\s*=>\s*(\w+)::class/g)) {
          const param = singular(x[1]);
          const acts: [string, string, string][] = [['index', 'GET', ''], ['store', 'POST', ''], ['show', 'GET', `/:${param}`], ['update', 'PUT', `/:${param}`], ['update', 'PATCH', `/:${param}`], ['destroy', 'DELETE', `/:${param}`]];
          for (const [act, verb, sfx] of acts) emit(verb, `/${x[1]}${sfx}`, null, x[2], act, null);
        }
      } else if (t.name === 'webhooks') {
        const p = strs(text(args[0] ?? { start: 0, end: 0 }))[0];
        if (p) emit('POST', p, null, null, null, 'webhook-client');
      }
      void c;
    };

    const walk = (from: number, to: number, ctx: Ctx): void => {
      let i = from;
      while (i < to) {
        const at = m.indexOf('Route::', i);
        if (at < 0 || at >= to) break;
        const prev = m.slice(Math.max(0, at - 1), at);
        if (/[\w$>]/.test(prev)) { i = at + 7; continue; }
        const ch = chainAt(v, at);
        if (!ch.calls.length) { i = at + 7; continue; }
        handle(ch.calls, ctx, at);
        i = Math.max(ch.end, at + 7);
      }
    };
    walk(0, m.length, base);
  }
  return out;
}
