// Ruby on Rails entry points: config/routes.rb (get, post, match, root, resources, resource, namespace, scope, member,
// collection, controller blocks, devise's authenticate blocks and mounted engines) joined to the controller actions they
// name, with the before_action filters each action runs (class level, inherited from parent controllers and from included
// concerns, minus skip_before_action) as its protections. Pattern based, like the other extractors.
import type { Protection } from '../types/index.ts';
import type { FileView } from './analyze.ts';
import { empty, joinPath, makeEntry, type Extracted } from './entry.ts';
import type { FnIndex } from './light-index.ts';
import { analyzeLight, type LightDeco } from './light.ts';
import type { LocalVocab } from './local-vocab.ts';
import type { Repo } from './repo.ts';

interface Frame { kind: string; path: string; module: string; resource: { name: string; singular: boolean } | null; auth: Protection[]; controller: string | null; only: string[] | null; except: string[] | null }
interface RouteDef { verb: string; path: string; controller: string; action: string; line: number; auth: Protection[]; decoLine: number; mount?: string }
interface Filter { name: string; line: number; view: FileView; start: number; end: number; only: string[] | null; except: string[] | null; kind: 'add' | 'skip'; text: string }

const CRUD: [string, string, string, boolean][] = [
  ['index', 'GET', '', false], ['create', 'POST', '', false], ['new', 'GET', '/new', false], ['show', 'GET', '/:id', true], ['edit', 'GET', '/:id/edit', true],
  ['update', 'PATCH', '/:id', true], ['update', 'PUT', '/:id', true], ['destroy', 'DELETE', '/:id', true],
];
const sym = (s: string): string[] => (/^%[iw]/.test(s) ? s.replace(/^%[iw]\[|\]$/g, '').split(/\s+/).filter(Boolean) : [...s.matchAll(/:(\w+)|['"](\w+)['"]/g)].map((m) => m[1] ?? m[2]));
const listOpt = (line: string, key: string): string[] | null => {
  const m = new RegExp(`\\b${key}:\\s*(%[iw]\\[[^\\]]*\\]|\\[[^\\]]*\\]|:\\w+|['"]\\w+['"])`).exec(line);
  return m ? sym(m[1]) : null;
};
const strOpt = (line: string, key: string): string | null => new RegExp(`\\b${key}:\\s*(?::(\\w+)|['"]([^'"]*)['"])`).exec(line)?.slice(1).find((x) => x !== undefined) ?? null;
const singular = (s: string): string => (/ies$/.test(s) ? s.replace(/ies$/, 'y') : /ses$/.test(s) ? s.replace(/es$/, '') : s.replace(/s$/, ''));

export function railsFiles(repo: Repo): { routes: string[]; controllers: string[] } {
  return {
    routes: repo.filesOf('rb').filter((f) => /(?:^|\/)config\/routes(?:\/[^/]+)?\.rb$/.test(f)),
    controllers: repo.filesOf('rb').filter((f) => /(?:^|\/)app\/controllers\/.*\.rb$|(?:^|\/)app\/controllers\/concerns\/.*\.rb$/.test(f)),
  };
}

function parseRoutes(v: FileView): RouteDef[] {
  const out: RouteDef[] = [];
  const lines = v.masked.split('\n');
  const orig = v.text.split('\n');
  const stack: Frame[] = [{ kind: 'root', path: '', module: '', resource: null, auth: [], controller: null, only: null, except: null }];
  const top = (): Frame => stack[stack.length - 1];
  const authFacts = (ln: number, text: string): Protection[] => (/\b(?:authenticate|authenticated)\b/.test(text) ? [{ kind: 'session_read', scope: 'router', file: v.file, line: ln, via: 'route authenticate block', enforced: true, confidence: 'high' }] : []);
  const roleFacts = (ln: number, text: string): Protection[] => (/\b(?:admin|role|staff|superuser|can\?)/i.test(text) ? [{ kind: 'role_check', scope: 'router', file: v.file, line: ln, via: 'route constraint', enforced: true, confidence: 'medium' }] : []);
  const push = (verb: string, path: string, controller: string, action: string, ln: number, f: Frame, mount?: string): void => {
    out.push({ verb, path: joinPath(f.path, path), controller, action, line: ln, auth: stack.flatMap((s) => s.auth), decoLine: ln, mount });
  };
  const ctrlOf = (f: Frame, name: string): string => (name.includes('/') ? name : `${f.module}${name}`);
  const nestedPrefix = (f: Frame, member: boolean): string => {
    const r = f.resource;
    if (!r) return '';
    return `/${r.name}${r.singular || !member ? '' : '/:id'}`;
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const l = raw.trim();
    if (!l) continue;
    const ln = i + 1;
    const o = orig[i] ?? '';
    const f = top();
    // Multi line route calls: join following lines while the line ends with a comma.
    let full = o.trim();
    let j = i;
    while (/,\s*$/.test(lines[j]) && j + 1 < lines.length && j < i + 6) { j++; full += ' ' + (orig[j] ?? '').trim(); }
    const opens = /\bdo(?:\s*\|[^|]*\|)?\s*$/.test(lines[j].trim());
    const blockHead = (kind: string, fr: Partial<Frame>): void => { stack.push({ ...f, kind, auth: [], only: null, except: null, ...fr }); };
    if (/^end\b/.test(l)) { if (stack.length > 1) stack.pop(); continue; }
    if (/^(?:if|unless|case|begin|while)\b/.test(l) && !/\bend\b/.test(l)) { stack.push({ ...f, kind: 'other', auth: [] }); continue; }
    if (/^else\b|^elsif\b|^when\b/.test(l)) continue;
    let m: RegExpExecArray | null;
    if ((m = /^namespace\s+(?::(\w+)|['"]([\w/]+)['"])/.exec(full))) {
      const n = m[1] ?? m[2];
      const p = strOpt(full, 'path');
      if (opens) blockHead('namespace', { path: joinPath(f.path, p ?? n), module: `${f.module}${n}/` });
      i = j; continue;
    }
    if ((m = /^scope\b(.*)$/.exec(full))) {
      const rest = m[1];
      const pos = /^\s*\(?\s*(?::(\w+)|['"]([^'"]*)['"])/.exec(rest);
      const p = strOpt(rest, 'path') ?? (pos ? pos[1] ?? pos[2] : null);
      const mod = strOpt(rest, 'module');
      if (opens) blockHead('scope', { path: p ? joinPath(f.path, p) : f.path, module: mod ? `${f.module}${mod}/` : f.module });
      i = j; continue;
    }
    if ((m = /^(authenticate|authenticated)\b(.*)$/.exec(full))) {
      if (opens) blockHead('authenticate', { auth: authFacts(ln, full) });
      i = j; continue;
    }
    if ((m = /^constraints\b(.*)$/.exec(full))) {
      if (opens) blockHead('constraints', { auth: [...authFacts(ln, full), ...roleFacts(ln, full)] });
      i = j; continue;
    }
    if ((m = /^controller\s+(?::(\w+)|['"]([\w/]+)['"])/.exec(full))) {
      if (opens) blockHead('controller', { controller: m[1] ?? m[2] });
      i = j; continue;
    }
    if ((m = /^(member|collection)\s+do\b/.exec(full))) { blockHead(m[1], {}); continue; }
    if (/^(?:concern|devise_scope|defaults|with_options|resources_for_api|direct|draw)\b/.test(l) && opens) { stack.push({ ...f, kind: 'concern', auth: [], controller: '\u0000skip' }); i = j; continue; }
    if ((m = /^(resources|resource)\s+(.*)$/.exec(full))) {
      const singularRes = m[1] === 'resource';
      const names = [...m[2].split(/\b(?:only|except|controller|path|param|as|module|shallow|constraints|defaults|format)\s*:/)[0].matchAll(/:(\w+)/g)].map((x) => x[1]);
      const only = listOpt(m[2], 'only');
      const except = listOpt(m[2], 'except');
      const ctrlOpt = strOpt(m[2], 'controller');
      const pathOpt = strOpt(m[2], 'path');
      for (const name of names) {
        const base = f.resource ? `${nestedPrefix(f, true).replace(/:id$/, `:${singular(f.resource.name)}_id`)}` : '';
        const urlName = pathOpt ?? name;
        const controller = ctrlOf(f, ctrlOpt ?? name);
        const acts = singularRes ? CRUD.filter(([a]) => a !== 'index') : CRUD;
        for (const [act, verb, suffix, member] of acts) {
          if (only && !only.includes(act)) continue;
          if (except && except.includes(act)) continue;
          const sfx = singularRes ? suffix.replace(/^\/:id/, '') : suffix;
          if (singularRes && act === 'index') continue;
          push(verb, `${base}/${urlName}${sfx}`, controller, act, ln, f);
        }
        if (opens) stack.push({ ...f, kind: 'resources', path: f.path, resource: { name: urlName, singular: singularRes }, auth: [], controller: controller });
      }
      if (opens && !names.length) stack.push({ ...f, kind: 'other', auth: [] });
      i = j; continue;
    }
    if ((m = /^(get|post|put|patch|delete|match)\s+(.*)$/.exec(full)) && !/^(?:get|post|put|patch|delete|match)\s*=/.test(full)) {
      const verbWord = m[1];
      const rest = m[2];
      const first = /^\(?\s*(?::(\w+)|['"]([^'"]*)['"])/.exec(rest);
      let target: string | null = strOpt(rest, 'to') ?? /=>\s*['"]([\w/]+#\w+)['"]/.exec(rest)?.[1] ?? null;
      if (/\bto:\s*(?:redirect|->|lambda|proc)\b|=>\s*redirect\b/.test(rest) || /\bto:\s*[A-Z]/.test(rest)) { if (opens) stack.push({ ...f, kind: 'other', auth: [] }); i = j; continue; }
      let action = strOpt(rest, 'action');
      let controller: string | null = null;
      if (target && target.includes('#')) { const [c, a] = target.split('#'); controller = ctrlOf(f, c); action = a; }
      else if (!target && first && /=>\s*['"]?[\w/]+#\w+/.test(rest)) { const t = /=>\s*['"]?([\w/]+)#(\w+)/.exec(rest)!; controller = ctrlOf(f, t[1]); action = t[2]; }
      let path: string | null = first ? (first[1] ?? first[2]) : null;
      if (!controller) {
        const ctrlName = f.controller && f.controller !== '\u0000skip' ? f.controller : null;
        if (ctrlName) controller = ctrlOf(f, ctrlName);
        if (!action && path) action = path.replace(/^\//, '').split('/')[0].replace(/\W+/g, '_');
        if (!controller && /^['"][\w/]+#\w+['"]$/.test(rest.split(',')[0].trim())) { const t = /['"]([\w/]+)#(\w+)['"]/.exec(rest)!; controller = ctrlOf(f, t[1]); action = t[2]; }
      }
      if (f.controller === '\u0000skip') { if (opens) stack.push({ ...f, kind: 'other', auth: [] }); i = j; continue; }
      if (!controller || !action || path === null) { if (opens) stack.push({ ...f, kind: 'other', auth: [] }); i = j; continue; }
      const on = strOpt(rest, 'on');
      const inMember = f.kind === 'member' || on === 'member';
      const inCollection = f.kind === 'collection' || on === 'collection';
      let prefix = '';
      if (f.resource && (inMember || inCollection)) prefix = nestedPrefix(f, inMember);
      else if (f.resource && f.kind === 'resources') prefix = nestedPrefix(f, true).replace(/:id$/, `:${singular(f.resource.name)}_id`);
      const verbs = verbWord === 'match' ? (listOpt(rest, 'via') ?? ['any']).map((x) => (x === 'all' || x === 'any' ? 'ANY' : x.toUpperCase())) : [verbWord.toUpperCase()];
      for (const verb of verbs) push(verb === 'ANY' ? 'ANY' : verb, `${prefix}/${path.replace(/^\//, '')}`.replace(/\(\.:format\)/g, ''), controller, action, ln, f);
      if (opens) stack.push({ ...f, kind: 'other', auth: [] });
      i = j; continue;
    }
    if ((m = /^root\s+(.*)$/.exec(full))) {
      const t = /['"]([\w/]+)#(\w+)['"]/.exec(m[1]);
      if (t) push('GET', '/', ctrlOf(f, t[1]), t[2], ln, f);
      i = j; continue;
    }
    if ((m = /^mount\s+(.*)$/.exec(full))) {
      const t = /^([\w:]+)\s*(?:=>|,\s*at:)\s*['"]([^'"]+)['"]/.exec(m[1]);
      if (t) push('ANY', t[2], t[1], '\u0000mount', ln, f, t[1]);
      i = j; continue;
    }
    if (opens) stack.push({ ...f, kind: 'other', auth: [] });
    i = j;
  }
  return out.filter((r) => r.path !== undefined);
}

interface ControllerInfo { key: string; name: string; file: string; view: FileView; parent: string | null; includes: string[]; filters: Filter[] }

const snakeCase = (s: string): string => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
// app/controllers/admin/users_controller.rb -> admin/users ; app/controllers/concerns/authentication.rb -> concerns/authentication
const keyOf = (file: string): string => (/app\/controllers\/(.*)\.rb$/.exec(file)?.[1] ?? file).replace(/_controller$/, '');

function parseControllers(repo: Repo, files: string[]): { ctrls: Map<string, ControllerInfo>; concerns: Map<string, ControllerInfo> } {
  const ctrls = new Map<string, ControllerInfo>();
  const concerns = new Map<string, ControllerInfo>();
  for (const file of files) {
    const v = repo.view(file);
    if (!v) continue;
    const isConcern = /\/concerns\//.test(file);
    const cl = /^[ \t]*class\s+([A-Z][\w:]*)(?:\s*<\s*([\w:]+))?/m.exec(v.masked);
    const head = isConcern ? /^[ \t]*module\s+([A-Z][\w:]*)/m.exec(v.masked) : cl;
    if (!head) continue;
    const info: ControllerInfo = { key: keyOf(file), name: head[1].split('::').pop()!, file, view: v, parent: !isConcern && cl?.[2] ? cl[2] : null, includes: [...v.masked.matchAll(/^[ \t]*include\s+([\w:]+)/gm)].map((x) => x[1].split('::').pop()!), filters: [] };
    const lines = v.masked.split('\n');
    const orig = v.text.split('\n');
    let defIndent = -1;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i].trim();
      const indent = /^[ \t]*/.exec(lines[i])![0].length;
      // A filter inside a method or a class_methods block is a macro definition, not a filter of this class.
      if (defIndent >= 0) { if (indent <= defIndent && /^end\b/.test(l)) defIndent = -1; continue; }
      if (/^(?:def\b|class_methods\b)/.test(l) && !/\bend\s*$/.test(l)) { defIndent = indent; continue; }
      const m = /^(before_action|before_filter|prepend_before_action|append_before_action|skip_before_action|skip_before_filter|skip_forgery_protection|load_and_authorize_resource|authorize_resource|load_resource|rate_limit|allow_unauthenticated_access|require_authentication)\b/.exec(l);
      if (!m) continue;
      let full = orig[i] ?? '';
      let j = i;
      while (/,\s*$/.test(lines[j]) && j + 1 < lines.length && j < i + 5) { j++; full += ' ' + (orig[j] ?? '').trim(); }
      const only = listOpt(full, 'only');
      const except = listOpt(full, 'except');
      const kw = m[1];
      const names = [...full.replace(/\b(?:only|except|if|unless|prepend|to|within|by|with)\s*:.*$/, '').matchAll(/:(\w+[?!]?)/g)].map((x) => x[1]);
      const start = v.lines.start(i + 1);
      let end = Math.min(v.lines.start(j + 2) - 1, v.text.length);
      // The options (only, except, if, unless) name actions and methods, not filters: leave them out of the text that is read.
      const cut = v.text.slice(start, end).search(/\b(?:only|except|if|unless)\s*:/);
      if (cut > 0) end = start + cut;
      const add = (name: string, kind: 'add' | 'skip'): void => { info.filters.push({ name, line: i + 1, view: v, start, end, only, except, kind, text: full }); };
      if (/^skip_/.test(kw)) for (const n of names) add(n, 'skip');
      else if (kw === 'allow_unauthenticated_access') add('require_authentication', 'skip');
      else if (/before_action|before_filter/.test(kw)) { if (names.length) for (const n of names) add(n, 'add'); else add('(block)', 'add'); }
      else add(kw, 'add');
      i = j;
    }
    if (isConcern) concerns.set(info.name, info); else ctrls.set(info.key, info);
  }
  return { ctrls, concerns };
}

export function extractRailsAll(repo: Repo, fn: FnIndex, local: LocalVocab | null): Extracted {
  const out = empty();
  const { routes, controllers } = railsFiles(repo);
  if (!routes.length) return out;
  const { ctrls, concerns } = parseControllers(repo, controllers);
  const parentOf = (c: ControllerInfo): ControllerInfo | undefined => {
    if (!c.parent) return undefined;
    const dir = c.key.includes('/') ? c.key.slice(0, c.key.lastIndexOf('/')) : '';
    const bare = c.parent.split('::').map(snakeCase).join('/').replace(/_controller$/, '');
    return ctrls.get(dir ? `${dir}/${bare}` : bare) ?? ctrls.get(bare);
  };
  for (const rf of routes) {
    const rv = repo.view(rf);
    if (!rv) continue;
    for (const r of parseRoutes(rv)) {
      if (r.action === '\u0000mount') {
        const a = analyzeLight(rv, { start: rv.lines.start(r.line), end: rv.lines.start(r.line + 1) - 1, seeds: [], decorators: [], extra: r.auth, local });
        out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'rails-mount', file: rf, line: r.line, method: 'ANY', path: r.path, name: r.mount ?? null, confidence: 'medium', handlerView: rv, spec: { start: rv.lines.start(r.line), end: rv.lines.start(r.line + 1) - 1, seeds: [] }, analysis: a }));
        continue;
      }
      const ci = ctrls.get(r.controller);
      const chain: ControllerInfo[] = [];
      for (let cur: ControllerInfo | undefined = ci, n = 0; cur && n < 8; n++) { chain.unshift(cur); cur = parentOf(cur); }
      // Filters in the order they run: each ancestor's included concerns, then its own lines.
      const active: Filter[] = [];
      const applies = (fl: Filter): boolean => (!fl.only || fl.only.includes(r.action)) && (!fl.except || !fl.except.includes(r.action));
      for (const c of chain) {
        const all = [...c.includes.flatMap((i) => concerns.get(i)?.filters ?? []), ...c.filters];
        for (const fl of all) {
          if (!applies(fl)) continue;
          if (fl.kind === 'skip') { for (let k = active.length - 1; k >= 0; k--) if (active[k].name === fl.name) active.splice(k, 1); continue; }
          active.push(fl);
        }
      }
      const decorators: LightDeco[] = active.map((fl) => ({ view: fl.view, start: fl.start, end: fl.end, scope: 'router' as const }));
      const policyScoped = active.some((fl) => /load_and_authorize_resource|authorize_resource/.test(fl.name));
      // The action itself.
      let hv: FileView = rv;
      let start = rv.lines.start(r.line);
      let end = rv.lines.start(r.line + 1) - 1;
      let found = false;
      if (ci) {
        const d = fn.defs(r.action).find((x) => x.view.file === ci.file);
        if (d) { hv = d.view; start = d.start; end = d.end; found = true; }
      }
      // A filter such as set_article loads the record before the action runs: @article = Article.find(params[:id]).
      const bound: { name: string; target: string; owner?: boolean }[] = [];
      for (const fl of active) {
        const d = fn.defs(fl.name).find((x) => chain.some((c) => c.file === x.view.file));
        if (!d) continue;
        const body = d.view.text.slice(d.start, d.end);
        for (const m of body.matchAll(/(@\w+)\s*=\s*(?:(@?current_\w+)\.(\w+)\.|([A-Z][\w:]*)\.)(?:find|find_by!?)\s*\(\s*(?:params\[\s*:\w+\s*\]|id:\s*params)/g)) bound.push({ name: m[1], target: m[4] ?? m[3], owner: m[2] !== undefined });
      }
      const a = analyzeLight(hv, { start, end, seeds: [], decorators, extra: r.auth.slice(), lookup: fn.find, local, policyScoped, bound });
      out.entries.push(makeEntry(repo, {
        kind: 'http_route', framework: 'rails', file: rf, line: r.line, method: r.verb, path: r.path.replace(/\(\.:format\)/g, '') || '/', name: `${r.controller}#${r.action}`,
        confidence: found ? 'high' : 'low', handlerView: hv, spec: { start, end, seeds: [] }, analysis: a,
      }));
    }
  }
  return out;
}

