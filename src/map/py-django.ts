// Django and Django REST framework entry points. Repository level: the URL configuration is read from the root down, so a
// view's full path includes the prefixes of every include() above it.
import type { Gate, Protection } from '../types/index.ts';
import type { FileView, Spec } from './analyze.ts';
import { empty, joinPath, makeEntry, normPath, type Extracted } from './entry.ts';
import { closeOf, pyBlock, splitArgs } from './lex.ts';
import { classDecos, decoratorGroups, pyParams, pyClassMethods, resolvePyModule } from './py.ts';
import type { Repo } from './repo.ts';

interface Pattern { route: string; viewText: string; line: number; includeFile: string | null; routerName: string | null; list: string | null; includeList: string | null }
interface UrlConf { file: string; view: FileView; patterns: Pattern[]; routers: Map<string, { prefix: string; viewset: string; line: number }[]> }

const GENERIC: Record<string, string[]> = {
  ListAPIView: ['GET'], CreateAPIView: ['POST'], RetrieveAPIView: ['GET'], UpdateAPIView: ['PUT', 'PATCH'], DestroyAPIView: ['DELETE'],
  ListCreateAPIView: ['GET', 'POST'], RetrieveUpdateAPIView: ['GET', 'PUT', 'PATCH'], RetrieveDestroyAPIView: ['GET', 'DELETE'],
  RetrieveUpdateDestroyAPIView: ['GET', 'PUT', 'PATCH', 'DELETE'], ModelViewSet: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  ReadOnlyModelViewSet: ['GET'], ListModelMixin: ['GET'], CreateModelMixin: ['POST'], DestroyModelMixin: ['DELETE'],
};

const routeText = (t: string): string | null => /^\s*[rRuU]?(['"])((?:\\.|(?!\1).)*)\1/.exec(t)?.[2] ?? null;
const cleanRoute = (r: string): string => normPath(r.replace(/^\^/, '').replace(/\$$/, '').replace(/\(\?P<(\w+)>[^)]*\)/g, ':$1').replace(/\\\//g, '/'));

function parseUrlConf(repo: Repo, v: FileView): UrlConf | null {
  if (!/\burlpatterns\b/.test(v.masked)) return null;
  const conf: UrlConf = { file: v.file, view: v, patterns: [], routers: new Map() };
  // Lists of patterns defined in this file (api_urls = [...]): a pattern belongs to the innermost list that holds it.
  const lists: { name: string; from: number; to: number }[] = [];
  for (const l of v.masked.matchAll(/^(\w+)\s*(?::[^=\n]+)?=\s*\[/gm)) { const open = l.index! + l[0].length - 1; const close = closeOf(v.masked, open); if (close > 0) lists.push({ name: l[1], from: open, to: close }); }
  for (const m of v.masked.matchAll(/(?<![\w.])(path|re_path|url)\s*\(/g)) {
    const open = m.index! + m[0].length - 1;
    const args = splitArgs(v.masked, open);
    if (args.length < 2) continue;
    const route = routeText(v.text.slice(args[0].start, args[0].end));
    if (route === null) continue;
    const viewText = v.text.slice(args[1].start, args[1].end);
    const inc = /^include\s*\(\s*([\s\S]*)\)\s*$/.exec(viewText);
    let includeFile: string | null = null;
    let routerName: string | null = null;
    let includeList: string | null = null;
    if (inc) {
      const lit = /^\(?\s*['"]([\w.]+)['"]/.exec(inc[1])?.[1];
      const rn = /^(\w+)\.urls/.exec(inc[1])?.[1];
      const own = /^\(?\s*(\w+)\s*\)?\s*$/.exec(inc[1])?.[1];
      if (own && lists.some((x) => x.name === own)) includeList = own;
      else if (lit) includeFile = resolvePyModule(repo, v.file, lit);
      else if (rn) routerName = rn;
      else { const id = /^\(?\s*(\w+)/.exec(inc[1])?.[1]; if (id) { const imp = [...v.text.matchAll(new RegExp(`from\\s+([\\w.]+)\\s+import\\s+[^\\n]*\\b${id}\\b`, 'g'))][0]; includeFile = resolvePyModule(repo, v.file, imp ? `${imp[1]}.${id}` : id) ?? (imp ? resolvePyModule(repo, v.file, imp[1]) : null); } }
    }
    const holder = lists.filter((x) => m.index! > x.from && m.index! < x.to).sort((a, b) => (a.to - a.from) - (b.to - b.from))[0];
    conf.patterns.push({ route: cleanRoute(route), viewText: inc ? '' : viewText, line: v.lines.at(m.index!), includeFile, routerName, list: holder?.name ?? null, includeList });
  }
  for (const m of v.masked.matchAll(/\b(\w+)\.register\s*\(/g)) {
    const open = m.index! + m[0].length - 1;
    const args = splitArgs(v.masked, open);
    if (args.length < 2) continue;
    const prefix = routeText(v.text.slice(args[0].start, args[0].end));
    const vs = /^[A-Za-z_][\w.]*/.exec(v.text.slice(args[1].start, args[1].end))?.[0];
    if (prefix === null || !vs) continue;
    const list = conf.routers.get(m[1]) ?? [];
    list.push({ prefix: cleanRoute(prefix), viewset: vs.split('.').pop()!, line: v.lines.at(m.index!) });
    conf.routers.set(m[1], list);
  }
  return conf;
}

// The function a url pattern names. A dotted reference (views.add) is followed through the import in the url file, a bare name through
// "from x import name", and otherwise a def of that name in a views module wins over one in a model, an admin class or a command.
function pickView(repo: Repo, urls: FileView, expr: string, fnName: string): ReturnType<Repo['defs']>[number] | undefined {
  const defs = repo.defs('py', fnName);
  if (defs.length <= 1) return defs[0];
  const ref = /^([\w.]+)/.exec(expr)?.[1] ?? fnName;
  const parts = ref.split('.');
  let file: string | null = null;
  if (parts.length > 1) {
    const mod = parts[parts.length - 2];
    const imp = new RegExp(`from\\s+([.\\w]+)\\s+import\\s+(?:[^\\n]*,\\s*)?${mod}\\b|import\\s+([.\\w]+)\\s+as\\s+${mod}\\b`).exec(urls.text);
    if (imp) file = imp[2] ? resolvePyModule(repo, urls.file, imp[2]) : (resolvePyModule(repo, urls.file, `${imp[1].replace(/\.$/, '')}.${mod}`) ?? resolvePyModule(repo, urls.file, imp[1]));
  } else {
    const imp = new RegExp(`from\\s+([.\\w]+)\\s+import\\s+[^\\n]*\\b${fnName}\\b`).exec(urls.text);
    if (imp) file = resolvePyModule(repo, urls.file, imp[1]);
  }
  const hit = file ? defs.filter((x) => x.view.file === file) : [];
  if (hit.length) return hit[0];
  const dir = urls.file.includes('/') ? urls.file.slice(0, urls.file.lastIndexOf('/') + 1) : '';
  const rank = (f: string): number => (/(?:^|\/)views?(?:\/|\.py$|_)/.test(f) ? 0 : f.startsWith(dir) ? 1 : 2) + (/(?:admin|models?|management|tests?)(?:\/|\.py$)/.test(f) ? 3 : 0);
  return defs.slice().sort((a, b) => rank(a.view.file) - rank(b.view.file))[0];
}

function findClass(repo: Repo, name: string, near: string): { view: FileView; at: number } | null {
  const files = [near, ...repo.filesOf('py').filter((f) => f !== near)];
  for (const f of files) {
    const view = repo.view(f);
    if (!view) continue;
    const m = new RegExp(`^class\\s+${name}\\b[^\\n]*:`, 'm').exec(view.masked);
    if (m) return { view, at: m.index };
  }
  return null;
}

export function extractDjango(repo: Repo): Extracted {
  const out = empty();
  const confs = new Map<string, UrlConf>();
  for (const f of repo.filesOf('py')) {
    if (!/urls?\.py$|urlconf|routing|routes/.test(f) && !/urlpatterns/.test(repo.ctx.text(f))) continue;
    const v = repo.view(f);
    const c = v ? parseUrlConf(repo, v) : null;
    if (c) confs.set(f, c);
  }
  if (!confs.size) return out;
  const included = new Set<string>();
  for (const c of confs.values()) for (const p of c.patterns) if (p.includeFile) included.add(p.includeFile);
  const roots = [...confs.keys()].filter((f) => !included.has(f)).sort();
  const emitted = new Set<string>();

  const emitView = (c: UrlConf, prefix: string, p: Pattern, viewExpr: string, route: string, depth: number): void => {
    void depth;
    const full = joinPath(prefix, route);
    const v = c.view;
    if (/admin\.site\.urls/.test(viewExpr)) {
      const e = makeEntry(repo, { kind: 'http_route', framework: 'django-admin', file: v.file, line: p.line, method: 'ANY', path: joinPath(full, '*'), name: 'django admin', confidence: 'medium', handlerView: v, spec: { start: 0, end: 0, seeds: [], decorators: [], returnsJson: false }, tags: ['admin'] });
      e.protections.push({ kind: 'session_read', scope: 'global', file: v.file, line: p.line, via: 'django admin site login', enforced: true, confidence: 'high' }, { kind: 'role_check', scope: 'global', file: v.file, line: p.line, via: 'django admin is_staff', enforced: true, confidence: 'high' });
      out.entries.push(e);
      return;
    }
    const asView = /^([\w.]+?)\.as_view\s*\(/.exec(viewExpr);
    if (asView) {
      const cls = asView[1].split('.').pop()!;
      const found = findClass(repo, cls, v.file);
      if (!found) return;
      emitClass(repo, found.view, found.at, cls, full, out);
      return;
    }
    const fnName = /^([\w.]+)\s*(?:,|$)/.exec(viewExpr.trim())?.[1]?.split('.').pop();
    if (!fnName) return;
    const d = pickView(repo, v, viewExpr.trim(), fnName);
    if (!d) return;
    const b = pyBlock(d.view.masked, d.view.lines, d.start);
    const g = decoratorGroups(d.view).find((x) => x.name === fnName && x.kind === 'def');
    const decoText = g ? g.decos.map((x) => d.view.text.slice(x.start, x.end)).join('\n') : '';
    const apiView = /@api_view\s*\(\s*\[([^\]]*)\]/.exec(decoText)?.[1];
    const reqMethods = /@require_http_methods\s*\(\s*[\[(]([^\])]*)[\])]/.exec(decoText)?.[1];
    const single = /@require_(GET|POST|safe)\b/.exec(decoText)?.[1];
    const ms = apiView || reqMethods ? [...(apiView ?? reqMethods)!.matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase()) : single ? (single === 'safe' ? ['GET', 'HEAD'] : [single]) : ['ANY'];
    const deco: NonNullable<Spec['decorators']> = g ? g.decos.map((x) => ({ view: d.view, start: x.start, end: x.end, scope: 'router' as const })) : [];
    for (const method of ms.length ? ms : ['ANY']) {
      out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'django', file: d.view.file, line: d.view.lines.at(d.start), method, path: full, name: fnName, confidence: 'medium', handlerView: d.view, spec: { start: d.start, end: b.end, seeds: [...pyParams(d.view.masked, d.start), 'request'], decorators: deco, returnsJson: true } }));
    }
  };

  const walk = (file: string, prefix: string, seen: string[], list: string | null = null): void => {
    const c = confs.get(file);
    if (!c || (list === null && seen.includes(file))) return;
    // The top level is urlpatterns, or every pattern outside a named helper list; a helper list is read where an include() names it.
    const named = new Set(c.patterns.filter((x) => x.includeList).map((x) => x.includeList));
    for (const p of c.patterns) {
      if (list === null ? (p.list !== null && p.list !== 'urlpatterns' && named.has(p.list)) : p.list !== list) continue;
      const joined = joinPath(prefix, p.route);
      if (p.includeList) { if (!seen.includes(`${file}#${p.includeList}`)) walk(file, joined, [...seen, `${file}#${p.includeList}`], p.includeList); continue; }
      if (p.includeFile) { walk(p.includeFile, joined, [...seen, file]); continue; }
      if (p.routerName) {
        for (const r of c.routers.get(p.routerName) ?? []) {
          const found = findClass(repo, r.viewset, file);
          if (!found) continue;
          const base = joinPath(joined, r.prefix);
          emitClass(repo, found.view, found.at, r.viewset, base, out, true);
        }
        continue;
      }
      if (!p.viewText) continue;
      const key = `${file}:${p.line}:${prefix}:${p.route}:${list ?? ''}`;
      if (emitted.has(key)) continue;
      emitted.add(key);
      emitView(c, prefix, p, p.viewText, p.route, seen.length);
    }
  };
  for (const r of roots.length ? roots : [...confs.keys()].sort()) walk(r, '', []);

  // REST framework settings that apply to every view.
  for (const f of repo.filesOf('py')) {
    if (!/settings/.test(f)) continue;
    const v = repo.view(f);
    const m = v && /REST_FRAMEWORK\s*=\s*\{/.exec(v.masked);
    if (!v || !m) continue;
    const open = v.masked.indexOf('{', m.index);
    const close = closeOf(v.masked, open);
    const body = v.text.slice(open, close);
    const line = v.lines.at(m.index);
    const protections: Protection[] = [];
    if (/DEFAULT_PERMISSION_CLASSES[^\]]*IsAuthenticated(?!OrReadOnly)/.test(body)) protections.push({ kind: 'session_read', scope: 'global', file: f, line, via: 'DEFAULT_PERMISSION_CLASSES IsAuthenticated', enforced: true, confidence: 'high' });
    if (/DEFAULT_PERMISSION_CLASSES[^\]]*IsAdminUser/.test(body)) protections.push({ kind: 'role_check', scope: 'global', file: f, line, via: 'DEFAULT_PERMISSION_CLASSES IsAdminUser', enforced: true, confidence: 'high' });
    if (/DEFAULT_THROTTLE_CLASSES/.test(body)) protections.push({ kind: 'rate_limit', scope: 'global', file: f, line, via: 'DEFAULT_THROTTLE_CLASSES', enforced: true, confidence: 'high' });
    if (protections.length) out.gates.push({ id: `${f}:${line}:REST_FRAMEWORK`, kind: 'guard', framework: 'django', file: f, line, paths: ['*'], methods: [], protections, confidence: 'high' } as Gate);
  }
  return out;
}

function emitClass(repo: Repo, view: FileView, at: number, cls: string, full: string, out: Extracted, viewset = false): void {
  const b = pyBlock(view.masked, view.lines, at);
  const header = view.masked.slice(at, b.bodyStart);
  const bases = (/\(([^)]*)\)/.exec(header)?.[1] ?? '').split(',').map((x) => x.trim().split('.').pop()!).filter(Boolean);
  const decos = classDecos(view, cls);
  const explicit = pyClassMethods(repo, view, cls);
  const implied = bases.flatMap((x) => GENERIC[x] ?? []);
  const seen = new Set<string>();
  const detail = joinPath(full, ':pk');
  for (const cm of explicit) {
    const path = viewset && /^(GET|PUT|PATCH|DELETE)$/.test(cm.method) && !/list/i.test(cm.method) ? full : full;
    out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'django', file: cm.view.file, line: cm.view.lines.at(cm.start), method: cm.method, path, name: `${cls}.${cm.method.toLowerCase()}`, confidence: 'medium', handlerView: cm.view, spec: { start: cm.start, end: cm.end, seeds: [...pyParams(cm.view.masked, cm.start), 'request'], decorators: decos, returnsJson: true } }));
    seen.add(cm.method);
  }
  // ViewSet actions (list, create, retrieve, update, partial_update, destroy) defined as methods.
  if (viewset) {
    const actions: [string, string, boolean][] = [['list', 'GET', false], ['create', 'POST', false], ['retrieve', 'GET', true], ['update', 'PUT', true], ['partial_update', 'PATCH', true], ['destroy', 'DELETE', true]];
    for (const x of view.masked.slice(b.bodyStart, b.end).matchAll(/^[ \t]+(?:async\s+)?def\s+(list|create|retrieve|update|partial_update|destroy)\s*\(/gm)) {
      const a = actions.find((y) => y[0] === x[1])!;
      const ls = view.masked.lastIndexOf('\n', b.bodyStart + x.index! + 1) + 1;
      const mb = pyBlock(view.masked, view.lines, ls);
      out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'django', file: view.file, line: view.lines.at(ls), method: a[1], path: a[2] ? detail : full, name: `${cls}.${x[1]}`, confidence: 'medium', handlerView: view, spec: { start: ls, end: mb.end, seeds: [...pyParams(view.masked, ls), 'request'], decorators: decos, returnsJson: true } }));
      seen.add(`${a[1]}:${a[2]}`);
    }
    for (const x of view.masked.slice(b.bodyStart, b.end).matchAll(/@action\s*\(([^)]*)\)\s*\n[ \t]*(?:async\s+)?def\s+(\w+)\s*\(/g)) {
      const ms = /methods\s*=\s*[\[(]([^\])]*)[\])]/.exec(view.text.slice(b.bodyStart + x.index!, b.bodyStart + x.index! + x[0].length))?.[1];
      const methods = ms ? [...ms.matchAll(/['"](\w+)['"]/g)].map((y) => y[1].toUpperCase()) : ['GET'];
      const ls = view.masked.lastIndexOf('\n', b.bodyStart + x.index! + x[0].length - 2) + 1;
      const mb = pyBlock(view.masked, view.lines, ls);
      const det = /detail\s*=\s*True/.test(view.text.slice(b.bodyStart + x.index!, b.bodyStart + x.index! + x[0].length));
      for (const method of methods) out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'django', file: view.file, line: view.lines.at(ls), method, path: joinPath(det ? detail : full, x[2]), name: `${cls}.${x[2]}`, confidence: 'medium', handlerView: view, spec: { start: ls, end: mb.end, seeds: [...pyParams(view.masked, ls), 'request'], decorators: decos, returnsJson: true } }));
    }
  }
  // Methods implied by a generic base class (ListCreateAPIView, ModelViewSet ...) that the class does not override.
  if (viewset && bases.some((x) => GENERIC[x])) {
    const have = (m: string, d: boolean): boolean => seen.has(`${m}:${d}`);
    const all: [string, boolean][] = bases.includes('ReadOnlyModelViewSet') ? [['GET', false], ['GET', true]] : [['GET', false], ['POST', false], ['GET', true], ['PUT', true], ['PATCH', true], ['DELETE', true]];
    const action = (method: string, det: boolean): string => (method === 'GET' ? (det ? 'retrieve' : 'list') : method === 'POST' ? 'create' : method === 'PUT' ? 'update' : method === 'PATCH' ? 'partial_update' : 'destroy');
    for (const [method, det] of all) if (!have(method, det)) out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'django', file: view.file, line: view.lines.at(at), method, path: det ? detail : full, name: `${cls}.${action(method, det)}`, confidence: 'medium', handlerView: view, spec: { start: at, end: b.end, seeds: ['request'], decorators: decos, returnsJson: true } }));
  } else if (!viewset) {
    for (const method of implied) if (!seen.has(method)) out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'django', file: view.file, line: view.lines.at(at), method, path: full, name: `${cls}.${method.toLowerCase()}`, confidence: 'medium', handlerView: view, spec: { start: at, end: b.end, seeds: ['request'], decorators: decos, returnsJson: true } }));
  }
}
