// NestJS controllers, resolvers and consumers; scheduled and queued jobs; functions handed to a model as tools.
import type { Gate, InputSource, Protection } from '../types/index.ts';
import type { FileView, Spec } from './analyze.ts';
import { empty, joinPath, makeEntry, paramNames, type Extracted } from './entry.ts';
import { closeOf, jsFunction, splitArgs } from './lex.ts';
import { paramsOf, resolveFunction } from './js-next.ts';
import type { Repo } from './repo.ts';

const NEST_VERBS = /@(Get|Post|Put|Patch|Delete|All|Options|Head)\s*\(/g;
const NEST_OTHER = /@(Query|Mutation|Subscription|ResolveField|MessagePattern|EventPattern|SubscribeMessage|Cron|Interval|Timeout|Process)\s*\(/g;
const PUBLIC_MARK = /@(?:Public|AllowAnonymous|SkipAuth|IsPublic|NoAuth|AllowUnauthenticated)\s*\(/;

const dtoCache = new WeakMap<Repo, Map<string, boolean>>();
// Whether a class of this name in the repository carries class-validator decorators.
function dtoValidated(repo: Repo, name: string): boolean {
  let cache = dtoCache.get(repo);
  if (!cache) { cache = new Map(); dtoCache.set(repo, cache); }
  const hit = cache.get(name);
  if (hit !== undefined) return hit;
  let ok = false;
  for (const f of repo.filesOf('js')) {
    const t = repo.ctx.text(f);
    const m = new RegExp(`class\\s+${name}\\b[^{]*\\{`).exec(t);
    if (!m) continue;
    const body = t.slice(m.index, m.index + 4000);
    if (/@(?:Is[A-Z]\w*|Min|Max|Length|MinLength|MaxLength|Matches|Validate\w*|Allow|ArrayMaxSize|ArrayMinSize|Contains|NotEquals|Equals|IsOptional)\s*\(/.test(body)) { ok = true; break; }
  }
  cache.set(name, ok);
  return ok;
}

export function extractNest(repo: Repo, v: FileView): Extracted {
  const out = empty();
  if (!/@(?:Controller|Resolver|Cron|Interval|Timeout|MessagePattern|EventPattern|SubscribeMessage|Process|Processor)\s*\(|APP_GUARD|useGlobalPipes|consumer\s*\.\s*apply\s*\(/.test(v.text)) return out;
  const { masked, text } = v;

  // Global guards and pipes become gates.
  for (const m of masked.matchAll(/provide\s*:\s*APP_GUARD/g)) {
    const seg = text.slice(m.index!, m.index! + 160);
    const cls = /useClass\s*:\s*([A-Za-z_$][\w$]*)/.exec(seg)?.[1] ?? 'APP_GUARD';
    const protections: Protection[] = [];
    const line = v.lines.at(m.index!);
    if (/auth|jwt|session|firebase|supabase/i.test(cls)) protections.push({ kind: 'session_read', scope: 'global', file: v.file, line, via: `APP_GUARD ${cls}`, enforced: true, confidence: 'medium' });
    if (/role|permission|admin|abac|casl/i.test(cls)) protections.push({ kind: 'role_check', scope: 'global', file: v.file, line, via: `APP_GUARD ${cls}`, enforced: true, confidence: 'medium' });
    if (/throttl|rate/i.test(cls)) protections.push({ kind: 'rate_limit', scope: 'global', file: v.file, line, via: `APP_GUARD ${cls}`, enforced: true, confidence: 'high' });
    if (protections.length) out.gates.push({ id: `${v.file}:${line}:APP_GUARD:${cls}`, kind: 'guard', framework: 'nest', file: v.file, line, paths: ['*'], methods: [], protections, confidence: 'medium' });
  }
  // Module middleware: consumer.apply(AuthMiddleware).forRoutes('path', { path: 'x', method: RequestMethod.GET }). One gate per route spec.
  for (const m of masked.matchAll(/\.\s*apply\s*\(([^)]*)\)/g)) {
    const statementEnd = masked.indexOf(';', m.index!);
    const chain = text.slice(m.index!, statementEnd < 0 ? m.index! + 600 : statementEnd);
    const fr = /\.\s*forRoutes\s*\(/.exec(chain);
    if (!fr) continue;
    const names = [...m[1].matchAll(/[A-Za-z_$][\w$]*/g)].map((x) => x[0]).filter((x) => !/^(?:new|function|req|res|next)$/.test(x));
    const line = v.lines.at(m.index!);
    const protections: Protection[] = [];
    for (const n of names) {
      if (/auth|jwt|session|firebase|supabase|login|token/i.test(n)) protections.push({ kind: 'session_read', scope: 'middleware', file: v.file, line, via: `module middleware ${n}`, enforced: null, confidence: 'medium' });
      if (/role|permission|admin|abac|casl/i.test(n)) protections.push({ kind: 'role_check', scope: 'middleware', file: v.file, line, via: `module middleware ${n}`, enforced: null, confidence: 'medium' });
      if (/throttl|rate/i.test(n)) protections.push({ kind: 'rate_limit', scope: 'middleware', file: v.file, line, via: `module middleware ${n}`, enforced: null, confidence: 'medium' });
    }
    if (!protections.length) continue;
    const open = m.index! + chain.indexOf('forRoutes') + 'forRoutes'.length;
    const args = text.slice(text.indexOf('(', open - 1) + 1, text.indexOf(')', open - 1 + chain.slice(chain.indexOf('forRoutes')).length)).trim();
    const specs: { path: string; methods: string[] }[] = [];
    for (const o of args.matchAll(/\{\s*path\s*:\s*['"`]([^'"`]*)['"`]\s*,\s*method\s*:\s*RequestMethod\.(\w+)\s*\}/g)) specs.push({ path: o[1], methods: o[2] === 'ALL' ? [] : [o[2]] });
    const rest = args.replace(/\{[^}]*\}/g, ' ');
    for (const sx of rest.matchAll(/['"`]([^'"`]*)['"`]/g)) specs.push({ path: sx[1], methods: [] });
    if (!specs.length && /^\s*\*\s*$|['"`]\*['"`]/.test(args)) specs.push({ path: '*', methods: [] });
    specs.forEach((sp, i) => {
      const star = sp.path.replace(/\/?\*.*$/, '');
      const gp = sp.path === '*' ? '*' : joinPath('/', star);
      out.gates.push({ id: `${v.file}:${line}:forRoutes:${i}`, kind: 'middleware', framework: 'nest', file: v.file, line, paths: [gp], methods: sp.methods, protections, confidence: 'medium' });
    });
  }
  for (const m of masked.matchAll(/useGlobalPipes\s*\(\s*new\s+ValidationPipe/g)) {
    const line = v.lines.at(m.index!);
    const g: Gate = { id: `${v.file}:${line}:ValidationPipe`, kind: 'global_pipe', framework: 'nest', file: v.file, line, paths: ['*'], methods: [], protections: [{ kind: 'input_validation', scope: 'global', file: v.file, line, via: 'global ValidationPipe', enforced: true, confidence: 'medium' }], confidence: 'medium' };
    out.gates.push(g);
  }

  for (const cm of masked.matchAll(/(?<![\w$])class\s+([A-Za-z_$][\w$]*)\b/g)) {
    const classKw = cm.index!;
    let ds = classKw;
    for (let k = classKw - 1; k >= 0 && classKw - k < 900; k--) { const c = masked[k]; if (c === '}' || c === ';') break; ds = k; }
    const classDeco = text.slice(ds, classKw);
    const bodyOpen = masked.indexOf('{', classKw);
    if (bodyOpen < 0) continue;
    const bodyClose = closeOf(masked, bodyOpen);
    if (bodyClose < 0) continue;
    const isController = /@Controller\s*\(/.test(classDeco);
    const isResolver = /@Resolver\s*\(/.test(classDeco);
    const prefix = isController ? (/@Controller\s*\(\s*(?:['"`]([^'"`]*)['"`]|\{[^}]*?path\s*:\s*['"`]([^'"`]*)['"`])/.exec(classDeco)?.slice(1).find((x) => x !== undefined) ?? '') : '';
    const body = masked.slice(bodyOpen, bodyClose);
    const verbRe = isController ? NEST_VERBS : NEST_OTHER;
    verbRe.lastIndex = 0;
    const hits = [...body.matchAll(isController ? NEST_VERBS : new RegExp(NEST_OTHER.source, 'g'))];
    if (!hits.length) continue;
    for (const h of hits) {
      const at = bodyOpen + h.index!;
      const decoOpen = at + h[0].length - 1;
      const decoClose = closeOf(masked, decoOpen);
      if (decoClose < 0) continue;
      // Skip further decorators, then read the method name and signature.
      let i = decoClose;
      for (;;) {
        const nxt = /^\s*@[\w$.]+\s*(?:\()?/.exec(masked.slice(i, i + 80));
        if (!nxt) break;
        const o = i + nxt[0].length - 1;
        if (masked[o] === '(') { const c = closeOf(masked, o); if (c < 0) break; i = c; } else i += nxt[0].length;
      }
      const sig = /^\s*(?:(?:public|private|protected|async|static|override)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(/.exec(masked.slice(i, i + 200));
      if (!sig) continue;
      const parenIdx = i + sig[0].length - 1;
      const f = jsFunction(masked, parenIdx, true);
      if (!f) continue;
      let ms = at;
      for (let k = at - 1; k > bodyOpen && at - k < 700; k--) { const c = masked[k]; if (c === '}' || c === ';' || c === '{') break; ms = k; }
      const methodDeco = text.slice(ms, at + (decoClose - at));
      const argText = text.slice(decoOpen + 1, decoClose - 1);
      const litPath = /^\s*['"`]([^'"`]*)['"`]/.exec(argText)?.[1] ?? '';
      const deco: NonNullable<Spec['decorators']> = [{ view: v, start: ds, end: classKw, scope: 'router' }, { view: v, start: ms, end: i, scope: 'handler' }];
      const name = sig[1];
      const params = paramNames(masked, parenIdx);
      let kind: 'http_route' | 'graphql_resolver' | 'message_consumer' | 'websocket' | 'job' = 'http_route';
      let method: string | null = h[1].toUpperCase();
      let path: string | null = null;
      if (isController) { method = h[1] === 'All' ? 'ANY' : h[1].toUpperCase(); path = joinPath('/' + prefix, litPath); if (path === '') path = '/'; }
      else if (/^(?:Query|Mutation|Subscription|ResolveField)$/.test(h[1])) { kind = 'graphql_resolver'; method = h[1] === 'ResolveField' ? 'FIELD' : h[1].toUpperCase(); path = name; }
      else if (/^(?:MessagePattern|EventPattern)$/.test(h[1])) { kind = 'message_consumer'; method = null; path = litPath || argText.trim().slice(0, 60) || name; }
      else if (h[1] === 'SubscribeMessage') { kind = 'websocket'; method = null; path = litPath || name; }
      else { kind = 'job'; method = null; path = litPath || (argText.trim().slice(0, 40) || name); }
      if (!isController && !isResolver && kind === 'graphql_resolver') continue;
      const e = makeEntry(repo, { kind, framework: 'nest', file: v.file, line: v.lines.at(at), method, path, name, confidence: 'high', handlerView: v, spec: { start: f.start, end: f.end, seeds: params, decorators: deco, extraCalls: [], returnsJson: true }, tags: PUBLIC_MARK.test(classDeco) || PUBLIC_MARK.test(methodDeco) ? ['public'] : [] });
      // Parameter decorators are request reads; a typed @Body() is checked against class-validator decorators on the DTO.
      const sigText = text.slice(parenIdx, f.bodyStart);
      const reads: [InputSource, RegExp][] = [['body', /@Body\s*\(/], ['query', /@Query\s*\(/], ['params', /@Param\s*\(/], ['headers', /@Headers?\s*\(/], ['file', /@(?:UploadedFiles?|UploadedFile)\s*\(/]];
      for (const [source, re] of reads) { const rm = re.exec(sigText); if (rm && !e.reads.some((r) => r.source === source)) e.reads.push({ source, line: v.lines.at(parenIdx + rm.index) }); }
      if (e.reads.some((r) => r.source === 'file') && !e.tags.includes('upload')) e.tags = [...e.tags, 'upload'].sort();
      if (/@(?:UseInterceptors\s*\(\s*(?:FileInterceptor|FilesInterceptor))/.test(methodDeco) && !e.reads.some((r) => r.source === 'file')) e.reads.push({ source: 'file', line: e.line });
      for (const dm of sigText.matchAll(/@Body\s*\([^)]*\)\s*[A-Za-z_$][\w$]*\s*:\s*([A-Z][\w$]*)/g)) {
        if (dtoValidated(repo, dm[1])) e.protections.push({ kind: 'input_validation', scope: 'handler', file: v.file, line: v.lines.at(parenIdx + dm.index!), via: `DTO ${dm[1]}`, enforced: null, confidence: 'medium' });
      }
      e.protections.sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.via < b.via ? -1 : a.via > b.via ? 1 : 0));
      e.reads.sort((a, b) => (a.source < b.source ? -1 : 1));
      out.entries.push(e);
    }
  }
  return out;
}

const JOB_CALL = /(?<![\w$])(cron\.schedule|schedule\.scheduleJob|scheduleJob|new\s+CronJob|agenda\.define|new\s+Worker|\w*[qQ]ueue\w*\.process|boss\.work|inngest\.createFunction|\w+\.addRepeatableJob|setInterval)\s*\(/g;

export function extractJobs(repo: Repo, v: FileView): Extracted {
  const out = empty();
  if (!/cron|schedule|agenda|Worker|[qQ]ueue|boss|inngest/.test(v.text)) return out;
  for (const m of v.masked.matchAll(JOB_CALL)) {
    if (m[1] === 'setInterval') continue;
    const open = m.index! + m[0].length - 1;
    const args = splitArgs(v.masked, open);
    const first = args[0];
    const lit = first && /^['"`]/.test(v.masked[first.start]) ? v.text.slice(first.start + 1, first.end - 1) : null;
    const fa = args.map((a) => ({ a, r: resolveFunction(repo, v, a.start, a.end) })).find((x) => x.r);
    if (!fa?.r) continue;
    const framework = /cron|schedule/i.test(m[1]) ? 'node-cron' : /Worker|process|work/.test(m[1]) ? 'queue' : m[1];
    out.entries.push(makeEntry(repo, { kind: 'job', framework, file: v.file, line: v.lines.at(m.index!), method: null, path: lit, name: lit && !/[\s*]/.test(lit) ? lit : null, confidence: 'high', handlerView: fa.r.view, spec: { start: fa.r.start, end: fa.r.end, seeds: fa.r.params, decorators: [], returnsJson: false } }));
  }
  return out;
}

const TOOL_OBJECT = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*\{/g;
const TOOLISH = /tool|function|handler|action|capabilit/i;

export function extractAiTools(repo: Repo, v: FileView): Extracted {
  const out = empty();
  if (!/tool|function_call|mcp|[aA]gent|llm|openai|anthropic|generateText|assistant/.test(v.text)) return out;
  const seen = new Set<number>();
  const push = (name: string | null, f: { start: number; end: number; bodyStart: number }, line: number, framework: string): void => {
    if (seen.has(f.start)) return;
    seen.add(f.start);
    out.entries.push(makeEntry(repo, { kind: 'ai_tool', framework, file: v.file, line, method: null, path: null, name, confidence: 'medium', handlerView: v, spec: { start: f.start, end: f.end, seeds: paramsOf(v.masked, f).slice(0, 1), decorators: [], returnsJson: false } }));
  };
  // 1. An object of functions named like tools: { read_note: (args) => ..., send: async (args) => ... }
  for (const m of v.masked.matchAll(TOOL_OBJECT)) {
    if (!TOOLISH.test(m[1]) || !/\b(?:tool|function|openai|anthropic|llm|assistant|agent|model)/i.test(v.text)) continue;
    const open = m.index! + m[0].length - 1;
    const close = closeOf(v.masked, open);
    if (close < 0) continue;
    for (const seg of splitArgs(v.masked, open)) {
      const head = /^(?:async\s+)?\[?['"]?([\w$-]+)['"]?\]?\s*(:|\()/.exec(v.text.slice(seg.start, seg.end).replace(/^async\s+/, 'async '));
      if (!head) continue;
      const name = head[1];
      let at = seg.start + head[0].length - 1;
      if (head[2] === ':') at = seg.start + head[0].length;
      const f = jsFunction(v.masked, head[2] === '(' ? at : at);
      if (f && f.end <= seg.end + 1) push(name, f, v.lines.at(seg.start), 'ai-tools');
    }
  }
  // 2. tool({ description, parameters, execute })
  for (const m of v.masked.matchAll(/(?<![\w$])tool\s*\(\s*\{/g)) {
    const open = v.masked.indexOf('{', m.index!);
    for (const seg of splitArgs(v.masked, open)) {
      const ex = /^execute\s*(:|\()/.exec(v.masked.slice(seg.start, seg.end));
      if (!ex) continue;
      const f = jsFunction(v.masked, seg.start + (ex[1] === ':' ? ex[0].length : ex[0].length - 1));
      if (!f) continue;
      const before = v.text.slice(Math.max(0, m.index! - 80), m.index!);
      const nm = /([A-Za-z_$][\w$]*)\s*(?::|=)\s*$/.exec(before)?.[1] ?? null;
      push(nm, f, v.lines.at(m.index!), 'ai-sdk');
    }
  }
  // 3. MCP: server.tool('name', schema, handler)
  for (const m of v.masked.matchAll(/\.\s*(?:tool|registerTool)\s*\(\s*(['"])/g)) {
    const open = v.masked.indexOf('(', m.index!);
    const args = splitArgs(v.masked, open);
    const nm = v.text.slice(args[0].start + 1, args[0].end - 1);
    const fa = args.map((a) => jsFunction(v.masked, a.start)).filter((x) => x).pop();
    if (fa) push(nm, fa, v.lines.at(m.index!), 'mcp');
  }
  return out;
}
