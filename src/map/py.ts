// Python entry points: Flask and FastAPI decorators, add_url_rule, Flask-RESTful resources, Celery and scheduler jobs, and
// tools handed to a model. Django is in py-django.ts. Pattern based, like the JavaScript extractors.
import type { Gate, Protection } from '../types/index.ts';
import { analyze, type FileView, type Spec } from './analyze.ts';
import { empty, joinPath, makeEntry, type Extracted } from './entry.ts';
import { closeOf, pyBlock, splitArgs } from './lex.ts';
import type { Repo } from './repo.ts';

export interface Deco { name: string; start: number; end: number; open: number }
export interface Group { decos: Deco[]; kind: 'def' | 'class'; name: string; lineStart: number; defStart: number }

// Decorator groups: each run of decorators followed by a def or class.
export function decoratorGroups(v: FileView): Group[] {
  const out: Group[] = [];
  const m = v.masked;
  const re = /^[ \t]*@/gm;
  let from = 0;
  for (let x = re.exec(m); x; x = re.exec(m)) {
    if (x.index < from) continue;
    const decos: Deco[] = [];
    let i = x.index;
    for (;;) {
      const at = m.indexOf('@', i);
      if (at < 0 || /\S/.test(m.slice(i, at))) break;
      const nm = /^@\s*([\w.]+)/.exec(m.slice(at));
      if (!nm) break;
      let end = at + nm[0].length;
      let open = -1;
      if (m[end] === '(') { open = end; const c = closeOf(m, end); if (c < 0) break; end = c; }
      decos.push({ name: nm[1], start: at, end, open });
      i = end;
      const nxt = /^\s*(?=@|(?:async\s+)?def\s|class\s)/.exec(m.slice(i, i + 400));
      if (!nxt) break;
      i += nxt[0].length;
      if (m[i] !== '@') break;
    }
    if (!decos.length) continue;
    const tail = /^\s*((?:async\s+)?def|class)\s+([A-Za-z_]\w*)/.exec(m.slice(decos[decos.length - 1].end, decos[decos.length - 1].end + 400));
    if (!tail) continue;
    const nameIdx = decos[decos.length - 1].end + tail[0].length - tail[2].length;
    const lineStart = m.lastIndexOf('\n', nameIdx) + 1;
    out.push({ decos, kind: tail[1] === 'class' ? 'class' : 'def', name: tail[2], lineStart, defStart: nameIdx });
    from = lineStart + 1;
  }
  return out;
}

export function pyParams(masked: string, from: number): string[] {
  const open = masked.indexOf('(', from);
  if (open < 0) return [];
  const close = closeOf(masked, open);
  const inner = masked.slice(open + 1, close - 1);
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  const flush = (): void => {
    const name = /^\s*\*{0,2}([A-Za-z_]\w*)/.exec(cur)?.[1];
    if (name && name !== 'self' && name !== 'cls' && !/Depends\s*\(|Security\s*\(/.test(cur)) out.push(name);
    cur = '';
  };
  for (const c of inner) { if ('([{'.includes(c)) depth++; else if (')]}'.includes(c)) depth--; if (c === ',' && depth === 0) flush(); else cur += c; }
  flush();
  return out;
}

export interface PyImport { module: string; attr: string | null }
export function pyImports(v: FileView): Map<string, PyImport> {
  const out = new Map<string, PyImport>();
  for (const m of v.text.matchAll(/^[ \t]*from\s+(\.*[\w.]*)\s+import\s+(\([^)]*\)|[^\n]+)/gm)) {
    for (const part of m[2].replace(/[()]/g, ' ').split(',')) {
      const [attr, alias] = part.trim().split(/\s+as\s+/);
      if (attr && /^[\w*]+$/.test(attr)) out.set(alias ?? attr, { module: m[1], attr });
    }
  }
  for (const m of v.text.matchAll(/^[ \t]*import\s+([\w.]+)(?:\s+as\s+(\w+))?/gm)) out.set(m[2] ?? m[1].split('.')[0], { module: m[1], attr: null });
  return out;
}

export function resolvePyModule(repo: Repo, from: string, dotted: string): string | null {
  let rel = 0;
  while (dotted[rel] === '.') rel++;
  const rest = dotted.slice(rel).replace(/\./g, '/');
  const candidates = (base: string): string[] => (base ? [`${base}.py`, `${base}/__init__.py`] : []);
  if (rel > 0) {
    const parts = from.split('/').slice(0, -1);
    for (let i = 1; i < rel; i++) parts.pop();
    const base = [...parts, ...(rest ? [rest] : [])].join('/');
    return candidates(base).find((c) => repo.fileSet.has(c)) ?? null;
  }
  if (!rest) return null;
  const exact = candidates(rest).find((c) => repo.fileSet.has(c));
  if (exact) return exact;
  const suffix = candidates(rest).flatMap((c) => repo.ctx.files.filter((f) => f.endsWith('/' + c)));
  return suffix.sort()[0] ?? null;
}

const strArg = (t: string): string | null => /^\s*(?:[rRuUbB]{0,2})(['"])((?:\\.|(?!\1).)*)\1/.exec(t)?.[2] ?? null;
const kwStr = (args: string, key: string): string | null => { const m = new RegExp(`(?:^|[,(\\s])${key}\\s*=\\s*[rRuU]?(['"])([^'"]*)\\1`).exec(args); return m ? m[2] : null; };

interface Receiver { name: string; prefix: string; deps: { start: number; end: number } | null; isApp: boolean }

export function extractPython(repo: Repo, v: FileView): Extracted {
  const out = empty();
  const { masked, text } = v;
  const flaskish = /\bflask\b|\bFlask\b|\bBlueprint\b|\bfastapi\b|\bFastAPI\b|\bAPIRouter\b|\bquart\b|\bsanic\b|\bstarlette\b|\bbottle\b|\bfalcon\b|\baiohttp\b|\blitestar\b|\bflask_restful\b|\bflask_restx\b|\bconnexion\b|\bceleryd?\b|\bshared_task\b|\bapscheduler\b|\bchalice\b|\bflask_smorest\b|\btool\b|\bmcp\b/.test(v.imports + text.slice(0, 2000));
  if (!flaskish) return out;
  const helpers = repo.helpers('py');
  const imps = pyImports(v);

  // Receivers: app = Flask(...), bp = Blueprint(...), router = APIRouter(...)
  const receivers = new Map<string, Receiver>();
  for (const m of masked.matchAll(/^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*(Flask|Blueprint|APIRouter|FastAPI|Quart|Sanic|Starlette|Router|Api|Namespace)\s*\(/gm)) {
    const open = m.index! + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close < 0) continue;
    const args = text.slice(open, close);
    const prefix = kwStr(args, 'url_prefix') ?? kwStr(args, 'prefix') ?? kwStr(args, 'path') ?? '';
    const hasDeps = /dependencies\s*=/.test(args);
    receivers.set(m[1], { name: m[1], prefix, deps: hasDeps ? { start: open, end: close } : null, isApp: /^(Flask|FastAPI|Quart|Sanic|Starlette)$/.test(m[2]) });
  }

  // before_request hooks: protections for every route of that receiver (app: for the whole app).
  const hookDecos = new Map<string, { start: number; end: number }[]>();
  const groups = decoratorGroups(v);
  for (const g of groups) {
    for (const d of g.decos) {
      const hook = /^(\w+)\.(before_request|before_app_request|middleware|before_first_request)$/.exec(d.name);
      if (!hook || g.kind !== 'def') continue;
      const b = pyBlock(masked, v.lines, g.lineStart);
      const rec = receivers.get(hook[1]);
      const spec: Spec = { start: g.lineStart, end: b.end, seeds: [], decorators: [], returnsJson: false };
      const a = analyze(v, spec, helpers);
      const protections: Protection[] = a.protections.filter((p) => p.kind !== 'owner_filter').map((p) => ({ ...p, scope: 'middleware' as const, enforced: p.enforced ?? true }));
      if (!protections.length) continue;
      if (rec?.isApp || hook[2] === 'middleware') {
        const gate: Gate = { id: `${v.file}:${v.lines.at(g.lineStart)}:${hook[2]}`, kind: 'middleware', framework: 'flask', file: v.file, line: v.lines.at(g.lineStart), paths: ['*'], methods: [], protections, confidence: 'medium' };
        out.gates.push(gate);
      } else {
        const list = hookDecos.get(hook[1]) ?? [];
        list.push({ start: g.lineStart, end: b.end });
        hookDecos.set(hook[1], list);
      }
    }
  }

  // Routes by decorator.
  const reg = /^(\w+)\.(route|get|post|put|patch|delete|head|options|api_route|websocket|websocket_route|on_event)$/;
  for (const g of groups) {
    if (g.kind !== 'def') continue;
    const rd = g.decos.find((d) => reg.test(d.name) && d.open >= 0);
    if (!rd) continue;
    const rm = reg.exec(rd.name)!;
    if (rm[2] === 'on_event') continue;
    const rec = receivers.get(rm[1]);
    if (!rec && !/^(app|bp|api|router|blueprint|server|v\d+|\w*router|\w*bp|\w*app)$/i.test(rm[1])) continue;
    const args = text.slice(rd.open, rd.end);
    const first = splitArgs(masked, rd.open)[0];
    const path = first ? strArg(text.slice(first.start, first.end)) ?? kwStr(args, 'path') : kwStr(args, 'path');
    if (path === null) continue;
    let methods: string[];
    if (rm[2] === 'route' || rm[2] === 'api_route') {
      const ml = /methods\s*=\s*[\[(]([^\])]*)[\])]/.exec(args);
      methods = ml ? [...ml[1].matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase()) : ['GET'];
      if (!methods.length) methods = ['GET'];
    } else methods = [rm[2].startsWith('websocket') ? 'WS' : rm[2].toUpperCase()];
    const b = pyBlock(masked, v.lines, g.lineStart);
    const decoSpecs: NonNullable<Spec['decorators']> = g.decos.map((d) => ({ view: v, start: d.start, end: d.end, scope: 'router' as const }));
    if (rec?.deps) decoSpecs.push({ view: v, start: rec.deps.start, end: rec.deps.end, scope: 'router' });
    for (const h of hookDecos.get(rm[1]) ?? []) decoSpecs.push({ view: v, start: h.start, end: h.end, scope: 'router' });
    const params = pyParams(masked, g.defStart);
    const framework = /fastapi|starlette|litestar/i.test(v.imports) ? 'fastapi' : /quart/i.test(v.imports) ? 'quart' : /sanic/i.test(v.imports) ? 'sanic' : 'flask';
    for (const method of methods) {
      const e = makeEntry(repo, { kind: 'http_route', framework, file: v.file, line: v.lines.at(rd.start), method, path: joinPath(rec?.prefix ?? '', path), name: g.name, confidence: 'high', handlerView: v, spec: { start: g.lineStart, end: b.end, seeds: [...params, 'request'], decorators: decoSpecs, returnsJson: true } });
      // FastAPI: a parameter typed with a pydantic model is validated; Form, File and Query parameters are reads.
      fastapiParams(repo, v, g, e);
      out.entries.push(e);
    }
  }

  // add_url_rule('/x', view_func=f, methods=[...]) and api.add_resource(Cls, '/x').
  for (const m of masked.matchAll(/\b(\w+)\.(add_url_rule|add_resource|add_api_route|add_route|add_websocket_route)\s*\(/g)) {
    const open = m.index! + m[0].length - 1;
    const args = splitArgs(masked, open);
    const argText = (i: number): string => (args[i] ? text.slice(args[i].start, args[i].end) : '');
    const rec = receivers.get(m[1]);
    if (m[2] === 'add_resource') {
      const cls = /^[A-Za-z_]\w*/.exec(argText(0))?.[0];
      const paths = args.slice(1).map((_, i) => strArg(argText(i + 1))).filter((x): x is string => !!x);
      if (cls && paths.length) pyClassMethods(repo, v, cls).forEach((cm) => { for (const p of paths) out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'flask-restful', file: cm.view.file, line: cm.view.lines.at(cm.start), method: cm.method, path: joinPath(rec?.prefix ?? '', p), name: `${cls}.${cm.method.toLowerCase()}`, confidence: 'medium', handlerView: cm.view, spec: { start: cm.start, end: cm.end, seeds: [...pyParams(cm.view.masked, cm.start), 'request'], decorators: classDecos(cm.view, cls), returnsJson: true } })); });
      continue;
    }
    const path = strArg(argText(0));
    if (path === null) continue;
    const viewFunc = /view_func\s*=\s*([\w.]+)|^\s*[\w"']+\s*,\s*([\w.]+)\s*[,)]/.exec(argText(1) ? text.slice(args[1].start, args[args.length - 1].end) : '')?.[1] ?? (args[1] ? /^[A-Za-z_][\w.]*/.exec(argText(1))?.[0] : null) ?? null;
    if (!viewFunc) continue;
    const fname = viewFunc.replace(/\.as_view$/, '').split('.')[0];
    const methods = /methods\s*=\s*[\[(]([^\])]*)[\])]/.exec(text.slice(open, closeOf(masked, open)))?.[1];
    const ms = methods ? [...methods.matchAll(/['"](\w+)['"]/g)].map((x) => x[1].toUpperCase()) : ['GET'];
    const fn = repo.defs('py', fname).sort((a, b) => (a.view.file === v.file ? -1 : 0) - (b.view.file === v.file ? -1 : 0))[0];
    if (/as_view/.test(argText(1)) || /as_view/.test(text.slice(open, closeOf(masked, open)))) {
      const cls = /(\w+)\.as_view/.exec(text.slice(open, closeOf(masked, open)))?.[1];
      if (!cls) continue;
      for (const cm of pyClassMethods(repo, v, cls)) out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'flask', file: cm.view.file, line: cm.view.lines.at(cm.start), method: cm.method, path: joinPath(rec?.prefix ?? '', path), name: `${cls}.${cm.method.toLowerCase()}`, confidence: 'medium', handlerView: cm.view, spec: { start: cm.start, end: cm.end, seeds: [...pyParams(cm.view.masked, cm.start), 'request'], decorators: classDecos(cm.view, cls), returnsJson: true } }));
      continue;
    }
    if (!fn) continue;
    const b = pyBlock(fn.view.masked, fn.view.lines, fn.start);
    const decos = decoratorsAbove(fn.view, fn.start);
    for (const method of ms) out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'flask', file: v.file, line: v.lines.at(m.index!), method, path: joinPath(rec?.prefix ?? '', path), name: fname, confidence: 'medium', handlerView: fn.view, spec: { start: fn.start, end: b.end, seeds: [...pyParams(fn.view.masked, fn.start), 'request'], decorators: decos, returnsJson: true } }));
  }

  // Mounts: app.register_blueprint(bp, url_prefix=...), app.include_router(mod.router, prefix=..., dependencies=[...]).
  for (const m of masked.matchAll(/\b(\w+)\.(register_blueprint|include_router|mount)\s*\(/g)) {
    const open = m.index! + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close < 0) continue;
    const args = splitArgs(masked, open);
    const first = args[0] ? text.slice(args[0].start, args[0].end) : '';
    const head = /^([A-Za-z_]\w*)/.exec(first)?.[1];
    const imp = head ? imps.get(head) : undefined;
    const callText = text.slice(open, close);
    const prefix = kwStr(callText, 'url_prefix') ?? kwStr(callText, 'prefix') ?? (m[2] === 'mount' ? strArg(first) ?? '' : '');
    let target: string | null = null;
    if (imp) {
      const modName = imp.attr && imp.module ? `${imp.module.replace(/\.$/, '')}${imp.module.endsWith('.') ? '' : '.'}${imp.attr}` : imp.module;
      target = (imp.attr ? resolvePyModule(repo, v.file, modName) : null) ?? resolvePyModule(repo, v.file, imp.module);
    }
    const protections: Protection[] = [];
    if (/dependencies\s*=/.test(callText)) {
      const a = analyze(v, { start: open, end: close, seeds: [], decorators: [], returnsJson: false }, helpers);
      for (const p of a.protections) if (p.kind !== 'owner_filter') protections.push({ ...p, scope: 'router' });
    }
    if (target && target !== v.file) out.mounts.push({ from: v.file, line: v.lines.at(m.index!), prefix: joinPath('', prefix || '/'), target, protections });
  }

  // Jobs: Celery tasks and scheduler jobs.
  for (const g of groups) {
    if (g.kind !== 'def') continue;
    const jd = g.decos.find((d) => /(^|\.)(task|shared_task|scheduled_job|periodic_task|job|actor)$/.test(d.name) && /celery|apscheduler|dramatiq|huey|rq|shared_task|schedul/i.test(v.imports + d.name));
    if (!jd) continue;
    const b = pyBlock(masked, v.lines, g.lineStart);
    out.entries.push(makeEntry(repo, { kind: 'job', framework: /celery|shared_task/i.test(v.imports + jd.name) ? 'celery' : 'scheduler', file: v.file, line: v.lines.at(jd.start), method: null, path: null, name: g.name, confidence: 'high', handlerView: v, spec: { start: g.lineStart, end: b.end, seeds: pyParams(masked, g.defStart), decorators: [], returnsJson: false } }));
  }
  for (const m of masked.matchAll(/\b\w+\.add_job\s*\(\s*([A-Za-z_]\w*)/g)) {
    const fn = repo.defs('py', m[1])[0];
    if (!fn) continue;
    const b = pyBlock(fn.view.masked, fn.view.lines, fn.start);
    out.entries.push(makeEntry(repo, { kind: 'job', framework: 'scheduler', file: fn.view.file, line: fn.view.lines.at(fn.start), method: null, path: null, name: m[1], confidence: 'medium', handlerView: fn.view, spec: { start: fn.start, end: b.end, seeds: pyParams(fn.view.masked, fn.start), decorators: [], returnsJson: false } }));
  }

  // AI tools: @tool (LangChain and others), @mcp.tool(), @function_tool.
  for (const g of groups) {
    if (g.kind !== 'def') continue;
    const td = g.decos.find((d) => /(^|\.)(tool|function_tool|register_tool)$/.test(d.name));
    if (!td) continue;
    const b = pyBlock(masked, v.lines, g.lineStart);
    out.entries.push(makeEntry(repo, { kind: 'ai_tool', framework: /mcp/i.test(td.name + v.imports) ? 'mcp' : 'ai-tools', file: v.file, line: v.lines.at(g.lineStart), method: null, path: null, name: g.name, confidence: 'medium', handlerView: v, spec: { start: g.lineStart, end: b.end, seeds: pyParams(masked, g.defStart), decorators: [], returnsJson: false } }));
  }
  return out;
}

// Decorators directly above the def that starts at `defStart` (an index at the start of the def line), as spec ranges.
export function decoratorsAbove(v: FileView, defStart: number): NonNullable<Spec['decorators']> {
  const g = decoratorGroups(v).find((x) => x.lineStart === defStart || v.masked.lastIndexOf('\n', x.defStart) + 1 === defStart);
  return g ? g.decos.map((d) => ({ view: v, start: d.start, end: d.end, scope: 'router' as const })) : [];
}

export function classDecos(v: FileView, cls: string): NonNullable<Spec['decorators']> {
  const m = new RegExp(`^class\\s+${cls}\\b[^\\n]*:`, 'm').exec(v.masked);
  if (!m) return [];
  const b = pyBlock(v.masked, v.lines, m.index);
  const body = v.masked.slice(b.bodyStart, b.end);
  const attrs = /\b(?:permission_classes|authentication_classes|throttle_classes|decorators|serializer_class|method_decorators)\s*=[^\n]*(?:\n[ \t]+[^\n]*)?/g;
  const out: NonNullable<Spec['decorators']> = [{ view: v, start: m.index, end: b.bodyStart, scope: 'router' }];
  for (const x of body.matchAll(attrs)) out.push({ view: v, start: b.bodyStart + x.index!, end: b.bodyStart + x.index! + x[0].length, scope: 'router' });
  return out;
}

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
// The HTTP methods a class defines (get, post ...), found in the class named `cls` in this file or elsewhere.
export function pyClassMethods(repo: Repo, v: FileView, cls: string): { view: FileView; method: string; start: number; end: number }[] {
  const files = [v.file, ...repo.filesOf('py').filter((f) => f !== v.file)];
  for (const f of files) {
    const view = f === v.file ? v : repo.view(f);
    if (!view) continue;
    const m = new RegExp(`^class\\s+${cls}\\b[^\\n]*:`, 'm').exec(view.masked);
    if (!m) continue;
    const b = pyBlock(view.masked, view.lines, m.index);
    const found: { view: FileView; method: string; start: number; end: number }[] = [];
    const body = view.masked.slice(b.bodyStart, b.end);
    for (const x of body.matchAll(/^[ \t]+(?:async\s+)?def\s+(\w+)\s*\(/gm)) {
      const name = x[1].toLowerCase();
      if (!HTTP_METHODS.includes(name)) continue;
      const at = b.bodyStart + x.index!;
      const ls = view.masked.lastIndexOf('\n', at + 1) + 1;
      const mb = pyBlock(view.masked, view.lines, ls);
      found.push({ view, method: name.toUpperCase(), start: ls, end: mb.end });
    }
    return found;
  }
  return [];
}

function fastapiParams(repo: Repo, v: FileView, g: Group, e: ReturnType<typeof makeEntry>): void {
  const open = v.masked.indexOf('(', g.defStart);
  if (open < 0) return;
  const close = closeOf(v.masked, open);
  const sig = v.text.slice(open, close);
  const line = v.lines.at(open);
  const add = (source: 'body' | 'query' | 'params' | 'file' | 'form' | 'headers'): void => { if (!e.reads.some((r) => r.source === source)) e.reads.push({ source, line }); };
  for (const m of sig.matchAll(/(\w+)\s*:\s*([A-Z]\w*)/g)) {
    const typ = m[2];
    if (typ === 'UploadFile') { add('file'); continue; }
    if (/^(?:Dict|List|Any|Mapping|Sequence)$/.test(typ)) { add('body'); continue; }
    if (['Request', 'Response', 'Depends', 'Session', 'BackgroundTasks', 'WebSocket'].includes(typ)) continue;
    const isModel = repo.filesOf('py').some((f) => { const t = repo.ctx.text(f); return new RegExp(`class\\s+${typ}\\s*\\([^)]*(?:BaseModel|SQLModel|Schema|BaseSchema)[^)]*\\)`).test(t); });
    if (isModel) { add('body'); e.protections.push({ kind: 'input_validation', scope: 'handler', file: v.file, line, via: `pydantic model ${typ}`, enforced: true, confidence: 'high' }); }
  }
  for (const m of sig.matchAll(/(\w+)\s*:\s*(?:dict|list|bytes|object)\b(?!\s*=\s*(?:Query|Header|Depends))/g)) { if (!(e.path ?? '').includes(`:${m[1]}`) && /^(POST|PUT|PATCH|DELETE)$/.test(e.method ?? '')) add('body'); }
  if (/\bFile\s*\(|UploadFile/.test(sig)) add('file');
  if (/\bForm\s*\(/.test(sig)) add('form');
  if (/\bQuery\s*\(/.test(sig)) add('query');
  if (/\bPath\s*\(/.test(sig)) add('params');
  if (/\bBody\s*\(/.test(sig)) add('body');
  if (/\bHeader\s*\(/.test(sig)) add('headers');
  if (e.path && /:\w+/.test(e.path)) add('params');
  e.reads.sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0));
  e.protections.sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.via < b.via ? -1 : a.via > b.via ? 1 : 0));
}
