// Reads one handler (or one decorator and wrapper region) and returns its protections, request inputs, data touches and
// outbound calls. Pattern based; every fact carries a confidence. See docs/PHASE-2-DESIGN.md sections 2 and 6.
import type { Confidence, DataTouch, InputRead, InputSource, Outbound, Protection, ProtectionKind, Scope } from '../types/index.ts';
import { scanFile } from '../checks/code/webhook-verify.ts';
import { EXITS, ifBody } from '../checks/code/shared.ts';
import type { Lang, Lines } from './lex.ts';
import { dataTouches, outboundCalls, type Region } from './touches.ts';
import { taintOf, type Taint } from './taint.ts';
import type { LocalVocab } from './local-vocab.ts';
import {
  AUDIT, AUTH_PACKAGES, RATE, RATE_PACKAGES, ROLE_JS, ROLE_PY, SESSION_JS, SESSION_PY, SIGNATURE, VALIDATION_JS, VALIDATION_PY,
  type Pattern,
} from './vocab.ts';

export interface FileView { file: string; text: string; masked: string; lang: Lang; lines: Lines; imports: string }
export interface Spec {
  start: number; end: number;              // the handler, parameters included
  seeds: string[];                          // names that hold request data on entry
  decorators?: { view: FileView; start: number; end: number; scope: Scope }[]; // decorator, middleware or wrapper text outside the handler body
  extraCalls?: string[];                    // names to look into besides the calls in the body (the wrapper function, middleware names)
  gate?: boolean;                           // the region is a middleware or guard: a check that never rejects does not enforce anything
  returnsJson?: boolean;
}
export interface HelperRef { view: FileView; start: number; end: number }
export interface Helpers { find(name: string, fromFile?: string): HelperRef | null; local?: LocalVocab | null }

export interface Analysis {
  protections: Protection[]; reads: InputRead[]; data: DataTouch[]; outbound: Outbound[]; taint: Taint;
}

const usesText = (re: RegExp): boolean => /['"`]/.test(re.source);
const CONF_RANK: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };
const minConf = (a: Confidence, b: Confidence): Confidence => (CONF_RANK[a] >= CONF_RANK[b] ? a : b);

function facts(kind: ProtectionKind, pats: Pattern[], view: FileView, from: number, to: number, scope: Scope, upgrade: boolean, viaPrefix = ''): Protection[] {
  const out: Protection[] = [];
  const seen = new Set<string>();
  const masked = view.masked.slice(from, to);
  const text = view.text.slice(from, to);
  for (const p of pats) {
    p.re.lastIndex = 0;
    const m = p.re.exec(usesText(p.re) ? text : masked);
    if (!m || seen.has(p.via)) continue;
    const ln = view.lines.at(from + m.index);
    if (out.some((o) => o.line === ln)) continue;
    seen.add(p.via);
    const conf = upgrade && p.confidence === 'medium' ? 'high' : p.confidence;
    out.push({ kind, scope, file: view.file, line: ln, via: viaPrefix + p.via, enforced: null, confidence: viaPrefix ? minConf(conf, 'medium') : conf });
  }
  return out;
}

// Whether a failed check provably stops the request. true: the check sits in an if whose body exits, or it is a throwing
// guard (require..., a decorator). false: it is tested and the body does not exit. null: cannot tell.
function enforcedFor(view: FileView, at: number, via: string): boolean | null {
  const { text } = view;
  const lineStart = text.lastIndexOf('\n', at) + 1;
  const lineEnd = text.indexOf('\n', at) < 0 ? text.length : text.indexOf('\n', at);
  const before = text.slice(lineStart, at);
  if (/^@|decorator|Depends|permission_classes|login/.test(via) && /(^|\n)\s*@|Depends\s*\(|permission_classes/.test(text.slice(lineStart, lineEnd))) return true;
  const ifAt = /\b(?:if|unless|elif|assert)\b/.exec(before);
  if (ifAt) {
    const body = view.lang === 'py' ? text.slice(lineStart + ifAt.index, Math.min(text.length, lineEnd + 400)).split('\n').slice(0, 4).join('\n') : ifBody(text, lineStart + ifAt.index);
    return EXITS.test(body);
  }
  if ((/\b(?:require|ensure|assert)\w*/i.test(via) || /^local (?:auth|role) helper$/.test(via)) && !/=/.test(before)) return true;
  const lhs = /(?:\b(?:const|let|var|val)\s+)?(\{[^}]*(?:\{[^}]*\}[^}]*)*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?[\w.$]*\s*$/.exec(before);
  if (!lhs) return null;
  const names = [...lhs[1].matchAll(/[A-Za-z_$][\w$]*/g)].map((x) => x[0]).filter((n) => !['const', 'let', 'var', 'data', 'error', 'session'].includes(n) || lhs[1] === n);
  const rest = text.slice(lineEnd, Math.min(text.length, lineEnd + 1500));
  for (const n of names) {
    const guard = view.lang === 'py'
      ? new RegExp(`\\bif\\s+(?:not\\s+${n}\\b|${n}\\s+is\\s+None|${n}\\s*==\\s*None)`)
      : new RegExp(`\\bif\\s*\\(\\s*(?:!\\s*${n}\\b|${n}\\s*(?:===?|==)\\s*(?:null|undefined)\\b|!\\s*${n}\\s*\\|\\||!${n}\\?)`);
    const g = guard.exec(rest);
    if (!g) continue;
    const body = view.lang === 'py' ? rest.slice(g.index, g.index + 300).split('\n').slice(0, 4).join('\n') : ifBody(rest, g.index);
    return EXITS.test(body);
  }
  return null;
}

const READS: [InputSource, RegExp, boolean][] = [
  ['body', /\b(?:req|request|ctx\.request|c\.req)\s*\.\s*(?:body|json|get_json|data|text)\b|\bawait\s+\w+\.json\s*\(\)|\bJSON\.parse\s*\(\s*(?:raw|body|await)/, false],
  ['query', /\b(?:req|request)\.(?:query|args|GET|query_params|nextUrl)\b|\bsearchParams\b|\bc\.req\.query\b|\bctx\.query\b|\bparse_qs\b/, false],
  ['params', /\b(?:req|request|ctx|c\.req)\.params?\b|\bparams\s*[.\[]|\bc\.req\.param\b|\bview_args\b|\bkwargs\b|\bPath\s*\(/, false],
  ['headers', /\b(?:req|request)\.headers\b|\bheaders\s*\(\s*\)|\bc\.req\.header\b|\bgetHeader\s*\(|\brequest\.META\b/, false],
  ['cookies', /\b(?:req|request)\.cookies\b|\bcookies\s*\(\s*\)|\bgetCookie\s*\(|\bc\.req\.cookie\b/, false],
  ['form', /\bformData\b|\brequest\.form\b|\brequest\.POST\b|\bFormData\s*\(|\bmultipart\b/i, false],
  ['file', /\.get\s*\(\s*['"](?:file|files|upload|image|avatar|attachment|document|photo)s?['"]\s*\)|\bas\s+File\b|\bmulter\b|\breq\.files?\b|\brequest\.files\b|\bformidable\b|\bbusboy\b|\binstanceof\s+File\b|\bUploadFile\b|\brequest\.FILES\b|\.file\s*\(\s*['"]|\bupload\.(?:single|array|fields|any)\b|\bFileInterceptor\b|\bFilesInterceptor\b|\bgetAll\s*\(\s*['"]file/, false],
];
function readsOf(view: FileView, from: number, to: number): InputRead[] {
  const masked = view.masked.slice(from, to);
  const out: InputRead[] = [];
  for (const [source, re] of READS) {
    const m = re.exec(masked);
    if (m) out.push({ source, line: view.lines.at(from + m.index) });
  }
  return out;
}

const PARSE_CALL = /\bawait\s+\w+\.json\s*\(\)|\b(?:req|request)\.(?:json|get_json)\s*\(|\bJSON\.parse\s*\(|\bjson\.loads\s*\(|\.formData\s*\(\)|\brequest\.(?:json|form)\b/;

// A helper body that turns a request away: an error status, a throw, an abort or a redirect.
const REJECT = /\b(?:401|403|unauthori[sz]ed|forbidden)\b|\bthrow\b|\braise\b|\babort\s*\(|\bnext\s*\(\s*(?:new\s+)?\w*Error|\bcreateError\b|\bHTTPException\b|\bPermissionDenied\b|\bAuthenticationFailed\b|\bredirect\s*\(|\bstatus\s*\(\s*4\d\d|\bdenyAll\b/i;

const CALL = /(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g;
const SKIP_CALLS = new Set(['if', 'for', 'while', 'switch', 'function', 'return', 'catch', 'await', 'async', 'typeof', 'new', 'super', 'require', 'import', 'print', 'len', 'str', 'int', 'dict', 'list', 'set', 'tuple', 'range', 'isinstance', 'type', 'super', 'sorted', 'map', 'filter', 'json', 'Number', 'String', 'Boolean', 'Array', 'Object', 'Date', 'Promise', 'Error', 'parseInt', 'parseFloat', 'setTimeout', 'fetch', 'def', 'class', 'with', 'except', 'elif', 'lambda', 'not', 'and', 'or']);

export function analyze(view: FileView, spec: Spec, helpers: Helpers): Analysis {
  const lang = view.lang;
  const { start, end } = spec;
  const upgradeSession = AUTH_PACKAGES.test(view.imports);
  const upgradeRate = RATE_PACKAGES.test(view.imports);
  const local = helpers.local ?? null;
  const sessionPats = [...(lang === 'js' ? SESSION_JS : SESSION_PY), ...(local?.auth ? [local.auth] : [])];
  const rolePats = [...(lang === 'js' ? ROLE_JS : ROLE_PY), ...(local?.role ? [local.role] : [])];
  const valPats = lang === 'js' ? VALIDATION_JS : VALIDATION_PY;

  const prot: Protection[] = [];
  const own = (kind: ProtectionKind, pats: Pattern[], upgrade: boolean): void => {
    for (const f of facts(kind, pats, view, start, end, 'handler', upgrade)) {
      prot.push({ ...f, enforced: kind === 'session_read' || kind === 'role_check' ? enforcedFor(view, firstIndex(view, start, end, pats, f.via, start), f.via) : null });
    }
  };
  own('session_read', sessionPats, upgradeSession);
  own('role_check', rolePats, false);
  own('rate_limit', RATE, upgradeRate);
  own('input_validation', valPats, false);
  own('audit_log', AUDIT, false);

  // Signature checks: where it is, whether a failed check stops the request, and whether the body is parsed first.
  const sig = facts('signature_verify', SIGNATURE, view, start, end, 'handler', false);
  if (sig.length) {
    const region = view.text.slice(start, end);
    const bad = scanFile(view.file, region);
    const onlyMissing = bad.length > 0 && bad.every((b) => /^no call that checks/.test(b.note));
    const enforced = bad.length === 0 ? true : onlyMissing ? null : false;
    const first = sig.reduce((a, b) => (a.line <= b.line ? a : b));
    const parse = PARSE_CALL.exec(view.masked.slice(start, end));
    const parseLine = parse ? view.lines.at(start + parse.index) : null;
    for (const f of sig) prot.push({ ...f, enforced, after_parse: parseLine !== null && parseLine < first.line });
  }

  // Decorators, middleware and wrappers outside the handler body.
  const extra = new Set<string>(spec.extraCalls ?? []);
  for (const d of spec.decorators ?? []) {
    const dv = d.view;
    const dl = dv.lang;
    const keep = (kind: ProtectionKind, pats: Pattern[], up: boolean): void => { for (const f of facts(kind, pats, dv, d.start, d.end, d.scope, up)) prot.push({ ...f, enforced: kind === 'session_read' || kind === 'role_check' ? (f.confidence === 'high' ? true : null) : null }); };
    keep('session_read', [...(dl === 'js' ? SESSION_JS : SESSION_PY), ...(local?.auth ? [local.auth] : [])], AUTH_PACKAGES.test(dv.imports));
    keep('role_check', [...(dl === 'js' ? ROLE_JS : ROLE_PY), ...(local?.role ? [local.role] : [])], false);
    keep('rate_limit', RATE, RATE_PACKAGES.test(dv.imports));
    keep('input_validation', dl === 'js' ? VALIDATION_JS : VALIDATION_PY, false);
    keep('audit_log', AUDIT, false);
    for (const f of facts('signature_verify', SIGNATURE, dv, d.start, d.end, d.scope, false)) prot.push({ ...f, enforced: null });
    for (const m of dv.masked.slice(d.start, d.end).matchAll(CALL)) if (!SKIP_CALLS.has(m[1])) extra.add(m[1]);
  }

  // One hop into the repository's own helper functions the handler calls.
  const have = (k: ProtectionKind): boolean => prot.some((p) => p.kind === k);
  const names = new Set<string>();
  for (const m of view.masked.slice(start, end).matchAll(CALL)) if (!SKIP_CALLS.has(m[1])) names.add(m[1]);
  for (const n of extra) names.add(n);
  let hops = 0;
  for (const name of [...names].sort()) {
    if (hops >= 30) break;
    const h = helpers.find(name, view.file);
    if (!h) continue;
    hops++;
    const hv = h.view;
    const hf: [ProtectionKind, Pattern[], boolean][] = [
      ['session_read', [...(hv.lang === 'js' ? SESSION_JS : SESSION_PY), ...(local?.auth ? [local.auth] : [])], AUTH_PACKAGES.test(hv.imports)],
      ['role_check', [...(hv.lang === 'js' ? ROLE_JS : ROLE_PY), ...(local?.role ? [local.role] : [])], false], ['rate_limit', RATE, RATE_PACKAGES.test(hv.imports)],
      ['input_validation', hv.lang === 'js' ? VALIDATION_JS : VALIDATION_PY, false], ['audit_log', AUDIT, false],
    ];
    for (const [kind, pats, up] of hf) {
      if (kind === 'session_read' && have('session_read')) continue;
      if (have(kind) && kind !== 'audit_log') continue;
      const found = facts(kind, pats.filter((p) => p.confidence !== 'low'), hv, h.start, h.end, 'handler', up, `helper:${name} `);
      if (found.length) {
        const idx = view.masked.slice(start, end).search(new RegExp(`(?<![.\\w$])${name.replace(/\$/g, '\\$')}\\s*\\(`));
        const at = idx < 0 ? view.lines.at(start) : view.lines.at(start + idx);
        const rejects = REJECT.test(hv.text.slice(h.start, h.end));
        const enforced = rejects ? true : spec.gate && (kind === 'session_read' || kind === 'role_check') ? false : null;
        prot.push({ ...found[0], file: view.file, line: at, via: `helper:${name} ${found[0].via.replace(`helper:${name} `, '')}`, enforced });
      }
    }
  }

  // Taint, then data touches and outbound calls.
  const maskedBody = view.masked.slice(start, end);
  const textBody = view.text.slice(start, end);
  const taint = taintOf(maskedBody, textBody, spec.seeds, lang, local?.auth ? [local.auth] : []);
  const region: Region = { masked: maskedBody, text: textBody, base: start, line: (i) => view.lines.at(start + i) };
  const data = dataTouches(region, taint, lang);
  const outbound = outboundCalls(region, taint, lang, spec.returnsJson ?? true, view.imports);

  // owner_filter: a data touch that names an owner is a protection on that read or write.
  for (const d of data) if (d.owner_scoped && (d.by_id || d.request_derived || d.op !== 'read')) prot.push({ kind: 'owner_filter', scope: 'handler', file: view.file, line: d.line, via: `${d.store} ${d.target ?? ''}`.trim(), enforced: null, confidence: d.store === 'sql' ? 'medium' : 'medium' });

  prot.sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.via < b.via ? -1 : a.via > b.via ? 1 : 0));
  return { protections: dedupe(prot), reads: readsOf(view, start, end), data, outbound, taint };
}

function dedupe(ps: Protection[]): Protection[] {
  const seen = new Set<string>();
  return ps.filter((p) => { const k = `${p.kind}|${p.scope}|${p.line}|${p.via}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

// The character index of the first match of the pattern with this `via` inside [from, to), for enforcedFor.
function firstIndex(view: FileView, from: number, to: number, pats: Pattern[], via: string, fallback: number): number {
  const p = pats.find((x) => x.via === via);
  if (!p) return fallback;
  p.re.lastIndex = 0;
  const src = usesText(p.re) ? view.text.slice(from, to) : view.masked.slice(from, to);
  const m = p.re.exec(src);
  return m ? from + m.index : fallback;
}
