// ASP.NET Core entry points (C#): controllers with [Route] and the [HttpGet] family, and minimal APIs (MapGet, MapPost and the others,
// with MapGroup prefixes). What protects each one: [Authorize] (with Roles or Policy), [AllowAnonymous], RequireAuthorization() on an
// endpoint or a group, a fallback policy that requires a sign in, and what the handler body does. [AllowAnonymous] anywhere on an
// endpoint turns the authorization attributes off, as it does in ASP.NET Core. Pattern based, like the other extractors.
import type { Protection } from '../types/index.ts';
import type { FileView } from './analyze.ts';
import { splitTop, strings } from './cblocks.ts';
import { empty, joinPath, makeEntry, normPath, type Extracted } from './entry.ts';
import { cMethod, type FnIndex } from './light-index.ts';
import { analyzeLight, type LightDeco } from './light.ts';
import { closeOf, splitArgs } from './lex.ts';
import type { LocalVocab } from './local-vocab.ts';
import type { Repo } from './repo.ts';

const HTTP: Record<string, string> = { HttpGet: 'GET', HttpPost: 'POST', HttpPut: 'PUT', HttpDelete: 'DELETE', HttpPatch: 'PATCH', HttpHead: 'HEAD', HttpOptions: 'OPTIONS' };
const SERVICE_TYPE = /^(?:I[A-Z]\w+|\w*(?:Db|DbContext|Context|Service|Repository|Logger|Options|Factory|Manager|Client|Provider|Handler)|CancellationToken|HttpContext|HttpRequest|HttpResponse|ClaimsPrincipal|IConfiguration|LinkGenerator|TokenService)\b/;
const AUTH_KINDS = new Set(['session_read', 'role_check']);

export function dotnetFiles(repo: Repo): string[] {
  return repo.filesOf('cs').filter((f) => { const v = repo.view(f); return !!v && (/Controller\b|\[ApiController\]/.test(v.masked) || /\.\s*Map(?:Get|Post|Put|Delete|Patch|Methods|Group)\s*\(/.test(v.masked)); });
}

interface Attr { name: string; start: number; end: number; args: string }
interface ABlock { attrs: Attr[]; start: number; end: number; declStart: number }

// Attribute lists ([A], [A, B(1)], [A][B]) that stand alone at brace depth 0 of [from, to): the first thing on their line, or right after another list.
function attributeBlocks(v: FileView, from: number, to: number): ABlock[] {
  const m = v.masked;
  const out: ABlock[] = [];
  let depth = 0;
  let cur: ABlock | null = null;
  for (let i = from; i < to; i++) {
    const c = m[i];
    if (c === '{' || c === '(') { depth++; continue; }
    if (c === '}' || c === ')') { depth--; continue; }
    if (c === '[' && depth === 0) {
      const lineStart = m.lastIndexOf('\n', i) + 1;
      const first = /^[ \t]*$/.test(m.slice(Math.max(lineStart, from), i));
      const chained = cur !== null && /^\s*$/.test(m.slice(cur.end, i));
      if (!first && !chained) { const e = closeOf(m, i); if (e > 0) i = e - 1; continue; }
      const close = closeOf(m, i);
      if (close < 0) continue;
      const attrs: Attr[] = splitTop(v.text.slice(i + 1, close - 1)).map((t) => {
        const nm = /^(?:\w+\s*:\s*)?([\w.]+)\s*(?:\(([\s\S]*)\))?$/.exec(t);
        const at = i + 1 + v.text.slice(i + 1, close - 1).indexOf(t);
        return { name: (nm?.[1] ?? t).replace(/^.*\./, '').replace(/Attribute$/, ''), start: at, end: at + t.length, args: nm?.[2] ?? '' };
      });
      if (chained && cur) { cur.attrs.push(...attrs); cur.end = close; }
      else { cur = { attrs, start: i, end: close, declStart: 0 }; out.push(cur); }
      i = close - 1;
    }
  }
  for (const b of out) { let d = b.end; while (/\s/.test(m[d] ?? '')) d++; b.declStart = d; }
  return out;
}

const tokens = (route: string, controller: string, action: string): string => route.replace(/\[controller\]/gi, controller.toLowerCase()).replace(/\[action\]/gi, action.toLowerCase()).replace(/\[area\]/gi, '');
const cleanPath = (p: string): string => normPath(p.replace(/\{(\w+)\?\}/g, '{$1}').replace(/\{\*{1,2}(\w+)\}/g, '{$1}'));

function seedsOf(paramsText: string): string[] {
  const seeds: string[] = [];
  for (const part of splitTop(paramsText)) {
    if (/\[FromServices\]/.test(part)) continue;
    const bare = part.replace(/\[[^\]]*\]\s*/g, '').replace(/\s*=\s*.*$/, '').trim();
    const mm = /^(?:this\s+)?(?:ref\s+|out\s+|in\s+)?([\w.<>?,\[\]]+)\s+(\w+)$/.exec(bare);
    if (!mm || SERVICE_TYPE.test(mm[1])) continue;
    seeds.push(mm[2]);
  }
  return seeds;
}

interface Group { prefix: string; chain: { start: number; end: number; view: FileView } | null; anonymous: boolean }

export function extractDotnet(repo: Repo, fn: FnIndex, local: LocalVocab | null): Extracted {
  const out = empty();
  // A fallback policy that needs a sign in, set anywhere in the project, covers every endpoint that is not [AllowAnonymous].
  let fallback: Protection | null = null;
  let controllersAuthorized: Protection | null = null;
  for (const file of repo.filesOf('cs')) {
    const v = repo.view(file);
    if (!v) continue;
    const fb = /\bFallbackPolicy\s*=/.exec(v.masked);
    if (fb && !fallback) fallback = { kind: 'session_read', scope: 'global', file, line: v.lines.at(fb.index), via: 'FallbackPolicy requires an authenticated user', enforced: true, confidence: 'high' };
    const mc = /\.\s*MapControllers\s*\(\s*\)\s*\.\s*RequireAuthorization\b/.exec(v.masked);
    if (mc && !controllersAuthorized) controllersAuthorized = { kind: 'session_read', scope: 'router', file, line: v.lines.at(mc.index), via: 'MapControllers().RequireAuthorization()', enforced: true, confidence: 'high' };
  }

  const analyse = (v: FileView, start: number, end: number, seeds: string[], decos: LightDeco[], extra: Protection[], anonymous: boolean) => {
    const a = analyzeLight(v, { start, end, seeds, decorators: decos, extra, lookup: fn.find, local });
    if (anonymous) a.protections = a.protections.filter((p) => !(AUTH_KINDS.has(p.kind) && (p.scope === 'router' || p.scope === 'wrapper' || p.scope === 'global' || p.scope === 'middleware')));
    return a;
  };

  for (const file of dotnetFiles(repo)) {
    const v = repo.view(file);
    if (!v) continue;
    const m = v.masked;

    // ---- controllers (a class is at the top of the file, or inside a block scoped namespace)
    const ranges: [number, number][] = [[0, m.length]];
    for (const ns of m.matchAll(/\bnamespace\s+[\w.]+\s*\{/g)) { const open = ns.index! + ns[0].length - 1; const close = closeOf(m, open); if (close > 0) ranges.push([open + 1, close - 1]); }
    for (const cls of ranges.flatMap(([a, b]) => attributeBlocks(v, a, b))) {
      const decl = /^(?:(?:public|internal|abstract|sealed|partial)\s+)*class\s+(\w+)\s*(?:\((?:[^()]|\([^()]*\))*\))?\s*(?::\s*([^{]+?))?\s*\{/.exec(m.slice(cls.declStart, cls.declStart + 500));
      if (!decl) continue;
      const names = cls.attrs.map((a) => a.name);
      if (!(names.includes('ApiController') || names.includes('Controller') || /\b(?:ControllerBase|Controller)\b/.test(decl[2] ?? '') || /\wController$/.test(decl[1]))) continue;
      const className = decl[1];
      const controller = className.replace(/Controller$/, '');
      const bodyOpen = cls.declStart + decl[0].length - 1;
      const bodyClose = closeOf(m, bodyOpen);
      if (bodyClose < 0) continue;
      const classRoute = cls.attrs.find((a) => a.name === 'Route');
      const classTemplate = classRoute ? strings(classRoute.args)[0] ?? '' : '';
      const classAnon = names.includes('AllowAnonymous');
      const classDeco: LightDeco = { view: v, start: cls.start, end: cls.end, scope: 'router' };
      for (const blk of attributeBlocks(v, bodyOpen + 1, bodyClose - 1)) {
        const verbs = blk.attrs.filter((a) => HTTP[a.name] || a.name === 'AcceptVerbs');
        const routeAttr = blk.attrs.find((a) => a.name === 'Route');
        if (!verbs.length && !routeAttr) continue;
        const nameAt = /(\w+)\s*(?:<[^>]*>)?\s*\(/.exec(m.slice(blk.declStart, blk.declStart + 400));
        if (!nameAt) continue;
        const f = cMethod(m, blk.declStart + nameAt.index);
        if (!f) continue;
        const action = nameAt[1];
        const anonymous = classAnon || blk.attrs.some((a) => a.name === 'AllowAnonymous');
        const decos: LightDeco[] = [{ view: v, start: blk.start, end: blk.end, scope: 'wrapper' }];
        if (cls.attrs.length) decos.push(classDeco);
        const extra: Protection[] = anonymous ? [] : [fallback, controllersAuthorized].filter((x): x is Protection => !!x);
        const seeds = seedsOf(f.params);
        const methodList = verbs.length ? verbs.flatMap((a) => (HTTP[a.name] ? [{ verb: HTTP[a.name], attr: a }] : [...a.args.matchAll(/"([A-Za-z]+)"/g)].map((x) => ({ verb: x[1].toUpperCase(), attr: a })))) : [{ verb: 'ANY', attr: routeAttr! }];
        for (const { verb, attr } of methodList) {
          const own = strings(attr.args)[0];
          const template = own === undefined && routeAttr && attr !== routeAttr ? strings(routeAttr.args)[0] : own;
          let full: string;
          const tpl = template === undefined ? undefined : tokens(template, controller, action);
          const ctpl = tokens(classTemplate, controller, action);
          if (tpl !== undefined && /^~?\//.test(tpl)) full = tpl.replace(/^~/, '');
          else full = joinPath(ctpl ? '/' + ctpl.replace(/^\//, '') : '', tpl ?? '') || '/';
          const path = cleanPath(full);
          const an = analyse(v, blk.declStart, f.end, seeds, decos, extra, anonymous);
          out.entries.push(makeEntry(repo, {
            kind: 'http_route', framework: 'aspnet', file, line: v.lines.at(attr.start), method: verb, path: path.startsWith('/') ? path : '/' + path, name: `${className}.${action}`,
            confidence: classTemplate || template !== undefined ? 'high' : 'medium', handlerView: v, spec: { start: blk.declStart, end: f.end, seeds }, analysis: an,
          }));
        }
      }
    }

    // ---- minimal APIs
    const groups = new Map<string, Group>();
    for (const g of m.matchAll(/\b(?:var|RouteGroupBuilder)\s+(\w+)\s*=\s*(\w+)\s*\.\s*MapGroup\s*\(/g)) {
      const open = g.index! + g[0].length - 1;
      const close = closeOf(m, open);
      if (close < 0) continue;
      const semi = m.indexOf(';', close);
      const parent = groups.get(g[2]);
      const lit = strings(v.text.slice(open, close))[0] ?? '';
      const chainText = m.slice(close, semi < 0 ? close : semi);
      groups.set(g[1], { prefix: joinPath(parent?.prefix ?? '', lit), chain: { start: close, end: semi < 0 ? close : semi, view: v }, anonymous: (parent?.anonymous ?? false) || /\.\s*AllowAnonymous\s*\(/.test(chainText) });
    }
    for (const mp of m.matchAll(/\b(\w+)\s*\.\s*Map(Get|Post|Put|Delete|Patch|Methods)\s*\(/g)) {
      const recv = mp[1];
      const grp = groups.get(recv);
      if (!grp && recv !== 'app' && recv !== 'endpoints' && recv !== 'builder') continue;
      const open = mp.index! + mp[0].length - 1;
      const close = closeOf(m, open);
      if (close < 0) continue;
      const args = splitArgs(m, open);
      if (!args.length) continue;
      const pathLit = strings(v.text.slice(args[0].start, args[0].end))[0];
      if (pathLit === undefined) continue;
      const semi = m.indexOf(';', close);
      const chain = { start: close, end: semi < 0 ? close : semi };
      const chainText = m.slice(chain.start, chain.end);
      const anonymous = /\.\s*AllowAnonymous\s*\(/.test(chainText) || !!grp?.anonymous;
      const verbs = mp[2] === 'Methods' ? [...v.text.slice(args[1]?.start ?? 0, args[1]?.end ?? 0).matchAll(/"([A-Za-z]+)"/g)].map((x) => x[1].toUpperCase()) : [mp[2].toUpperCase()];
      const handler = args[args.length - 1];
      if (!handler || args.length < 2) continue;
      const htext = m.slice(handler.start, handler.end);
      let seeds: string[] = [];
      let start = handler.start;
      let end = handler.end;
      let hv: FileView = v;
      const lam = /^(?:static\s+)?(?:async\s+)?\(([^)]*)\)\s*=>/.exec(htext) ?? /^(?:static\s+)?(?:async\s+)?(\w+)\s*=>/.exec(htext);
      if (lam) seeds = seedsOf(v.text.slice(handler.start + htext.indexOf(lam[1]), handler.start + htext.indexOf(lam[1]) + lam[1].length));
      else {
        const nm = /(\w+)\s*$/.exec(htext)?.[1];
        const ref = nm ? fn.find(nm, file) : null;
        if (ref) { hv = ref.view; start = ref.start; end = ref.end; const op = ref.view.masked.indexOf('(', ref.start); const pc = op >= 0 ? closeOf(ref.view.masked, op) : -1; if (pc > 0) seeds = seedsOf(ref.view.text.slice(op + 1, pc - 1)); }
      }
      const decos: LightDeco[] = [{ view: v, start: chain.start, end: chain.end, scope: 'wrapper' }];
      if (grp?.chain) decos.push({ view: grp.chain.view, start: grp.chain.start, end: grp.chain.end, scope: 'router' });
      const extra: Protection[] = anonymous ? [] : [fallback].filter((x): x is Protection => !!x);
      for (const verb of verbs) {
        const path = cleanPath(joinPath(grp?.prefix ?? '', pathLit));
        const an = analyse(hv, start, end, seeds, decos, extra, anonymous);
        out.entries.push(makeEntry(repo, {
          kind: 'http_route', framework: 'aspnet', file, line: v.lines.at(mp.index!), method: verb, path, name: null,
          confidence: 'high', handlerView: hv, spec: { start, end, seeds }, analysis: an,
        }));
      }
    }
  }
  return out;
}
