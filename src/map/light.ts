// Body analysis for Go, Ruby and PHP handlers: protections, request inputs, data touches and outbound calls, from the
// vocabulary in light-profiles.ts. Same output as analyze.ts for JavaScript and Python, and the same stated limits: pattern
// reading inside one function, one hop into the repository's own helpers, request taint by assignment. See
// docs/PHASE-2-DESIGN.md sections 2 and 6.
import type { Confidence, DataTouch, InputRead, Outbound, Protection, ProtectionKind, Scope } from '../types/index.ts';
import type { Analysis, FileView, HelperRef } from './analyze.ts';
import { PROFILES, type Profile } from './light-profiles.ts';
import { closeOf } from './lex.ts';
import type { MoreLang } from './lex-more.ts';
import type { LocalVocab } from './local-vocab.ts';
import { OWNER, PRIVILEGED, REDIRECT_GUARD, URL_GUARD, type Pattern } from './vocab.ts';

export interface LightDeco { view: FileView; start: number; end: number; scope: Scope }
export interface LightSpec {
  start: number; end: number;               // the handler, parameters included
  seeds: string[];                           // names that hold request data on entry
  decorators?: LightDeco[];                  // middleware, filters and attributes outside the handler body
  extra?: Protection[];                      // protections the extractor read itself (a before_action, a route middleware)
  lookup?: (name: string, fromFile: string) => HelperRef | null; // the repository's own functions, for the one hop
  local?: LocalVocab | null;
  policyScoped?: boolean;                    // a policy covers every record the handler loads (load_and_authorize_resource)
  bound?: { name: string; target: string; owner?: boolean }[]; // records loaded by id before the handler runs (Laravel route model binding, a Rails set_x filter)
}

const CONF_RANK: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };
const minConf = (a: Confidence, b: Confidence): Confidence => (CONF_RANK[a] >= CONF_RANK[b] ? a : b);
const usesText = (re: RegExp): boolean => /['"`]/.test(re.source);
const ID_COL = /(?:^|[^\w])(?:id|ID|Id|pk)(?![\w])|\w_id\b|\bid:|\buuid\s*(?::|=|\?)|\[:id\]|:id\b/;
const SQL_WORD = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i;
const OWNER_MORE: Record<MoreLang, RegExp> = {
  go: /UserID|OwnerID|userID|ownerID|TenantID|tenantID|AccountID|accountID|user_id|owner_id|tenant_id|team_id/,
  rb: /current_user|current_account|current_member/,
  php: /->user\b|\bAuth::(?:id|user)|auth\(\)->(?:id|user)|user_id|owner_id|tenant_id|team_id|account_id/,
  java: /findBy\w*(?:Owner|User|Tenant|Account)\w*|\bgetOwner\w*\b|\bownerId\b|\bOwnerId\b/,
  cs: /\bOwnerId\b|\bUserId\b|\bTenantId\b|\bAccountId\b/,
};
const ASSIGN: Record<MoreLang, RegExp> = {
  go: /^\s*(?:var\s+)?([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|=)(?!=)\s*/,
  rb: /^\s*((?:@{0,2}[A-Za-z_]\w*)(?:\s*,\s*@{0,2}[A-Za-z_]\w*)*)\s*(?:\|\|=|=)(?![=~>])\s*/,
  php: /^\s*(\$[A-Za-z_]\w*(?:\s*,\s*\$[A-Za-z_]\w*)*|list\([^)]*\)|\[[^\]]*\])\s*(?:\.=|\?\?=|=)(?![=>])\s*/,
  java: /^\s*(?:final\s+)?(?:[\w.]+(?:\s*<[^;=()]*>)?(?:\[\])*\s+)?([A-Za-z_]\w*)\s*=(?![=>])\s*/,
  cs: /^\s*(?:await\s+)?(?:(?:var|[\w.]+(?:\s*<[^;=()]*>)?[?]?(?:\[\])*)\s+)?([A-Za-z_]\w*)\s*=(?![=>])\s*/,
};
const KEYWORDS = new Set(['nil', 'null', 'true', 'false', 'self', 'this', 'new', 'return', 'if', 'else', 'unless', 'do', 'end', 'func', 'var', 'string', 'int', 'bool', 'err', 'ok', 'ctx', 'then', 'and', 'or', 'not', 'array', 'isset', 'empty']);

// Logical statements of the region: a line, joined with the lines that continue it.
export function statements(m: string, from: number, to: number, lang: MoreLang): [number, number][] {
  const out: [number, number][] = [];
  let i = from;
  while (i < to) {
    while (i < to && /\s/.test(m[i])) i++;
    if (i >= to) break;
    let j = i;
    let depth = 0;
    for (; j < to; j++) {
      const c = m[j];
      if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth = Math.max(0, depth - 1);
      else if (c === ';' && depth === 0 && lang !== 'rb') { j++; break; }
      else if ((c === '{' || c === '}') && depth === 0 && (lang === 'php' || lang === 'java' || lang === 'cs')) { j++; break; }
      else if (c === '\n' && depth === 0) {
        const prev = m.slice(i, j).trimEnd().slice(-1);
        const rest = m.slice(j + 1, j + 200);
        const nx = /\S/.exec(rest);
        const nxt = nx ? rest.slice(nx.index, nx.index + 2) : '';
        if (nx && (nxt[0] === '.' || nxt === '->' || nxt === '::' || nxt === '&&' || nxt === '||' || nxt[0] === '?' || (nxt[0] === ':' && lang !== 'rb' && nxt[1] !== ':'))) continue;
        if (',+&|\\.(=?:'.includes(prev) && prev !== '' && !(lang === 'go' && prev === ':')) continue;
        if (lang === 'rb' && /(?:^|\s)(?:and|or|not)$/.test(m.slice(i, j).trimEnd())) continue;
        break;
      }
    }
    out.push([i, Math.min(j, to)]);
    i = j + 1;
  }
  return out;
}

const idents = (p: Profile, expr: string): string[] => [...expr.matchAll(new RegExp(p.identRe.source, 'g'))].map((m) => m[1]).filter((x) => !KEYWORDS.has(x));

function pick(view: FileView, pats: Pattern[], from: number, to: number): { p: Pattern; index: number }[] {
  const out: { p: Pattern; index: number }[] = [];
  const seen = new Set<string>();
  for (const pt of pats) {
    pt.re.lastIndex = 0;
    const src = usesText(pt.re) ? view.text : view.masked;
    const g = new RegExp(pt.re.source, pt.re.flags.includes('g') ? pt.re.flags : pt.re.flags + 'g');
    g.lastIndex = from;
    for (let m = g.exec(src); m && m.index < to; m = g.exec(src)) {
      if (m[0] === '') { g.lastIndex++; continue; }
      const idx = m.index;
      // A match that starts inside a comment (blank in the masked copy) does not count.
      if (usesText(pt.re) && view.masked[idx] === ' ' && view.text[idx] !== ' ' && view.text[idx] !== '\n' && view.text[idx] !== '\t') continue;
      if (seen.has(pt.via)) break;
      seen.add(pt.via);
      out.push({ p: pt, index: idx });
      break;
    }
  }
  return out;
}

function protectionsIn(view: FileView, prof: Profile, local: LocalVocab | null, from: number, to: number, scope: Scope, viaPrefix = '', floor: Confidence | null = null, deco = false): Protection[] {
  const kinds: [ProtectionKind, Pattern[]][] = [
    ['session_read', [...prof.session, ...(deco ? prof.decoSession : []), ...(local?.auth ? [local.auth] : [])]],
    ['role_check', [...prof.role, ...(deco ? prof.decoRole : []), ...(local?.role ? [local.role] : [])]],
    ['rate_limit', prof.rate], ['input_validation', prof.validation], ['audit_log', prof.audit],
  ];
  const out: Protection[] = [];
  for (const [kind, pats] of kinds) {
    for (const { p, index } of pick(view, floor ? pats.filter((x) => x.confidence !== 'low') : pats, from, to)) {
      const conf = viaPrefix || floor ? minConf(p.confidence, 'medium') : p.confidence;
      out.push({ kind, scope, file: view.file, line: view.lines.at(index), via: viaPrefix + p.via, enforced: null, confidence: conf });
    }
  }
  return out;
}

// The lines after line `n` (1 based) up to the end of the block they belong to: a closing brace, end, else or elsif.
function afterBlock(lines: string[], n: number, max: number): string {
  const out: string[] = [];
  for (let i = n; i < Math.min(lines.length, n + max); i++) {
    if (/^\s*(?:\}|end\b|else\b|elsif\b|elseif\b)/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join('\n');
}

// Whether a failed check provably stops the request, from the text around the match.
function enforcedAt(view: FileView, prof: Profile, p: Protection): boolean | null {
  const lines = view.text.split('\n');
  const row = lines[p.line - 1] ?? '';
  const after = (n: number): string => afterBlock(lines, p.line, n);
  if (/^\s*(?:if|unless|elsif|elseif|when)\b/.test(row)) return prof.exits.test(row.replace(/^[^{]*\{/, '') + '\n' + after(4));
  const modifier = /\s(?:if|unless)\s/.exec(row);
  if (modifier && !ASSIGN[prof.lang].test(row)) return prof.exits.test(row.slice(0, modifier.index)); // statement if condition: the statement is the body
  if (/^\s*(?:before_action|prepend_before_action|\$this->middleware|->middleware|abort_(?:if|unless)|throw_(?:if|unless)|\$this->authorize|\$request->validate|Gate::authorize)/.test(row)) return true;
  const as = ASSIGN[prof.lang].exec(row);
  if (as) {
    const names = [...as[1].matchAll(/[@$]?[A-Za-z_]\w*/g)].map((m) => m[0]).concat(prof.guardVars);
    const rest = after(8);
    for (const n of new Set(names)) {
      const bare = n.replace(/^[@$]/, '');
      const guard = new RegExp(`\\b(?:if|unless)\\s*\\(?\\s*(?:!\\s*${n.replace('$', '\\$')}\\b|not\\s+${bare}\\b|${n.replace('$', '\\$')}\\s*(?:==|===)\\s*(?:nil|null)\\b|${n.replace('$', '\\$')}\\.nil\\?|${bare}\\s*!=\\s*nil|err\\s*!=\\s*nil|!ok\\b|!\\s*empty\\s*\\(\\s*${n.replace('$', '\\$')}\\s*\\)|${n.replace('$', '\\$')}\\s*===?\\s*false)`);
      const g = guard.exec(rest);
      if (g) return prof.exits.test(rest.slice(g.index, g.index + 320));
    }
  }
  return null;
}

export function readsOf(view: FileView, prof: Profile, from: number, to: number): InputRead[] {
  const out: InputRead[] = [];
  for (const [source, re] of prof.reads) {
    const g = new RegExp(re.source, re.flags.replace('g', ''));
    const src = usesText(re) ? view.text.slice(from, to) : view.masked.slice(from, to);
    const m = g.exec(src);
    if (m) out.push({ source, line: view.lines.at(from + m.index) });
  }
  return out;
}

interface Taint { names: Set<string>; validated: Set<string>; trusted: Set<string> }

function taintOf(prof: Profile, view: FileView, stmts: [number, number][], seeds: string[]): Taint {
  const names = new Set(seeds);
  const validated = new Set<string>();
  const trusted = new Set<string>();
  const tainted = (expr: string): boolean => {
    const e = expr.replace(new RegExp(prof.trusted.source, 'g'), ' ');
    return prof.sources.test(e) || idents(prof, e).some((i) => names.has(i) && !trusted.has(i));
  };
  const recs: { lhs: string[]; rhs: string; line: string }[] = [];
  for (const [s, e] of stmts) {
    const m = view.masked.slice(s, e);
    const a = ASSIGN[prof.lang].exec(m);
    if (a) recs.push({ lhs: [...a[1].matchAll(/[@$]?[A-Za-z_]\w*/g)].map((x) => x[0]).filter((x) => !KEYWORDS.has(x)), rhs: view.text.slice(s + a[0].length, e), line: m });
    if (prof.lang === 'go') {
      const b = /\.(?:Decode|ShouldBindJSON|ShouldBindQuery|BindJSON|ShouldBind|Bind|BodyParser|QueryParser|ParamsParser|Unmarshal|BindQuery)\s*\(\s*(?:[^,()]*,\s*)?&?(\w+)/.exec(m);
      if (b) { names.add(b[1]); if (/validator|Validate|binding:/.test(view.text.slice(s, e))) validated.add(b[1]); }
    } else {
      if (prof.lang === 'java' || prof.lang === 'cs') {
        const f = prof.lang === 'java' ? /\bfor\s*\(\s*(?:final\s+)?[\w.<>\[\],? ]+?\s+(\w+)\s*:\s*([^)]+)\)/.exec(m) : /\bforeach\s*\(\s*(?:var|[\w.<>\[\],?]+)\s+(\w+)\s+in\s+([^)]+)\)/.exec(m);
        if (f) recs.push({ lhs: [f[1]], rhs: f[2], line: m });
      } else {
        const f = prof.lang === 'php' ? /\bforeach\s*\(\s*(.+?)\s+as\s+(?:(\$\w+)\s*=>\s*)?(\$\w+)/.exec(m) : /([@\w.]+(?:\([^)]*\))?)\.each\s+do\s*\|\s*(\w+)/.exec(m);
        if (f) recs.push({ lhs: prof.lang === 'php' ? [f[3]] : [f[2]], rhs: f[1], line: m });
      }
    }
  }
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    for (const r of recs) {
      if (prof.trusted.test(r.rhs) && !/\bparams\b|\$request->(?:input|all|get)/.test(r.rhs)) { for (const l of r.lhs) if (!trusted.has(l)) { trusted.add(l); names.delete(l); changed = true; } continue; }
      if (!tainted(r.rhs)) continue;
      const schema = /->validated\s*\(|->safe\s*\(|\.permit\s*\(|\bValidator::make|->validate\s*\(/.test(r.rhs);
      for (const l of r.lhs) {
        if (!names.has(l)) { names.add(l); changed = true; }
        if (schema && !validated.has(l)) { validated.add(l); changed = true; }
      }
    }
    if (!changed) break;
  }
  return { names, validated, trusted };
}

// The model a GORM call works on: Model(&Note{}), Table("notes"), Find(&notes) where notes was declared as []Note.
function goTarget(stmt: string, fileText: string): string | null {
  const t = /\.Table\s*\(\s*"(\w+)"/.exec(stmt)?.[1];
  if (t) return t;
  const lit = /&(\w+)\s*\{/.exec(stmt)?.[1];
  if (lit) return lit;
  const v = /&(\w+)\b/.exec(stmt)?.[1];
  if (!v) return null;
  return new RegExp(`\\bvar\\s+${v}\\s+(?:\\[\\])?\\*?([A-Z]\\w*)`).exec(fileText)?.[1] ?? new RegExp(`\\b${v}\\s*:?=\\s*(?:\\[\\])?&?([A-Z]\\w*)\\s*\\{`).exec(fileText)?.[1] ?? new RegExp(`\\b${v}\\s+(?:\\[\\])?\\*?([A-Z]\\w*)\\b`).exec(fileText)?.[1] ?? null;
}

const snake = (s: string): string => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const clip = (s: string, n: number): string => { const t = s.replace(/\s+/g, ' ').trim(); return t.length > n ? t.slice(0, n - 1) + '…' : t; };

interface VarInfo { target: string | null; byId: boolean; owner: boolean }

export function analyzeLight(view: FileView, spec: LightSpec): Analysis {
  const prof = PROFILES[view.lang as MoreLang];
  const { start, end } = spec;
  const local = spec.local ?? null;
  const stmts = statements(view.masked, start, end, prof.lang);
  const t = taintOf(prof, view, stmts, spec.seeds);
  const taintedExpr = (expr: string): boolean => {
    const e = expr.replace(new RegExp(prof.trusted.source, 'g'), ' ');
    return prof.sources.test(e) || idents(prof, e).some((i) => t.names.has(i) && !t.trusted.has(i));
  };
  const hasSession = (expr: string): boolean => prof.trusted.test(expr) || idents(prof, expr).some((i) => t.trusted.has(i));

  // ---- protections
  const prot: Protection[] = [];
  for (const f of protectionsIn(view, prof, local, start, end, 'handler')) {
    prot.push({ ...f, enforced: f.kind === 'session_read' || f.kind === 'role_check' ? enforcedAt(view, prof, f) : null });
  }
  // Signature checks: where the check is, and whether a failed check stops the request.
  for (const { p, index } of pick(view, prof.signature, start, end)) {
    const line = view.lines.at(index);
    const bodyAt = prof.sources.exec(view.masked.slice(start, end));
    const parseLine = bodyAt ? view.lines.at(start + bodyAt.index) : null;
    const fact: Protection = { kind: 'signature_verify', scope: 'handler', file: view.file, line, via: p.via, enforced: null, confidence: p.confidence };
    let enforced = enforcedAt(view, prof, fact);
    if (enforced === null && /\bconstruct\w*Event|\bverify\w*Webhook|\bWebhook::construct/i.test(p.via + view.text.slice(index, index + 40))) enforced = true;
    prot.push({ ...fact, enforced, after_parse: parseLine !== null && parseLine < line && /\b(?:json|JSON\.parse|json_decode|Unmarshal|Decode|ShouldBindJSON|BindJSON)\b/.test(view.masked.slice(start, view.lines.start(line))) });
  }
  for (const d of spec.decorators ?? []) {
    for (const f of protectionsIn(d.view, prof, local, d.start, d.end, d.scope, '', null, true)) prot.push({ ...f, enforced: f.confidence === 'high' ? true : null });
    for (const { p, index } of pick(d.view, prof.signature, d.start, d.end)) prot.push({ kind: 'signature_verify', scope: d.scope, file: d.view.file, line: d.view.lines.at(index), via: p.via, enforced: null, confidence: p.confidence });
  }
  prot.push(...(spec.extra ?? []));

  // One hop into the repository's own functions the handler calls.
  const have = (k: ProtectionKind): boolean => prot.some((q) => q.kind === k);
  if (spec.lookup) {
    const names = new Set<string>();
    const body = view.masked.slice(start, end);
    for (const m of body.matchAll(prof.lang === 'rb' ? /(?<![.\w@:])([a-z_]\w*[?!]?)(?=[\s(]|$)/gm : prof.lang === 'php' ? /(?:\$this->|self::|static::|(?<![>:\w$]))([A-Za-z_]\w*)\s*\(/g : /(?<![\w])(?:\w+\.)?([A-Za-z_]\w*)\s*\(/g)) names.add(m[1]);
    for (const n of spec.decorators ?? []) for (const m of n.view.masked.slice(n.start, n.end).matchAll(/([A-Za-z_]\w*[?!]?)/g)) names.add(m[1]);
    let hops = 0;
    for (const name of [...names].sort()) {
      if (hops >= 30 || KEYWORDS.has(name)) continue;
      const h = spec.lookup(name, view.file);
      if (!h) continue;
      hops++;
      const rejects = prof.exits.test(h.view.text.slice(h.start, h.end)) && /\b(?:401|403|forbidden|unauthori[sz]ed|abort|raise|halt|redirect|head\s+:|status\(|Error)\b/i.test(h.view.text.slice(h.start, h.end));
      for (const f of protectionsIn(h.view, prof, local, h.start, h.end, 'handler', `helper:${name} `, 'medium')) {
        if (f.kind === 'session_read' && have('session_read')) continue;
        if (have(f.kind) && f.kind !== 'audit_log') continue;
        const idx = view.masked.slice(start, end).search(new RegExp(`(?<![\\w])${name.replace(/[$]/g, '\\$')}\\b`));
        prot.push({ ...f, file: view.file, line: idx < 0 ? view.lines.at(start) : view.lines.at(start + idx), via: f.via, enforced: rejects ? true : null });
      }
    }
  }

  // ---- data touches
  const data: DataTouch[] = [];
  const vars = new Map<string, VarInfo>();
  for (const b of spec.bound ?? []) vars.set(b.name, { target: b.target, byId: true, owner: b.owner ?? false });
  const sqlVars = new Map<string, Partial<DataTouch> & { raw: string }>();
  const policy = spec.policyScoped || /\bauthorize\b|\bauthorize!|\$this->authorize|\bGate::(?:authorize|allows)|\bpolicy\s*\(|\bpolicy_scope|->can\s*\(/.test(view.masked.slice(start, end));
  const ownerNear = (s: string): boolean => (OWNER.test(s) || OWNER_MORE[prof.lang].test(s)) && hasSession(s);

  for (const [s, e] of stmts) {
    const ms = view.masked.slice(s, e);
    const ts = view.text.slice(s, e);
    const line = (i: number): number => view.lines.at(s + i);
    const lhs = ASSIGN[prof.lang].exec(ms);
    const lhsNames = lhs ? [...lhs[1].matchAll(/[@$]?[A-Za-z_]\w*/g)].map((x) => x[0]).filter((x) => !KEYWORDS.has(x)) : [];
    const stmtTainted = taintedExpr(lhs ? ts.slice(lhs[0].length) : ts);
    const emitted: DataTouch[] = [];
    const lim = /(?:\.|->|\b)(?:limit|per|take|paginate|simplePaginate|forPage|Limit|per_page|PerPage|page_size|pageSize)\s*\(\s*([^)]*)\)|\b(?:per_page|limit|page_size|per):\s*([^,)\n]+)/i.exec(ts);
    const limitReq = !!lim && taintedExpr(lim[1] ?? lim[2] ?? '');

    // SQL text in a literal
    const sqlLit = SQL_WORD.exec(ts);
    if (sqlLit && /["'`]/.test(ms)) {
      const kw = sqlLit[1].toUpperCase();
      const op: DataTouch['op'] = kw.startsWith('SELECT') ? 'read' : kw.startsWith('DELETE') ? 'delete' : 'write';
      const table = /\b(?:FROM|INTO|UPDATE|JOIN)\s+[`"]?([\w.]+)/i.exec(ts)?.[1] ?? null;
      const args = ts.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, (q) => (SQL_WORD.test(q) || /WHERE|SET|VALUES|FROM/i.test(q) ? ' ' : q));
      const interp = (prof.lang === 'go' && (/\bfmt\.Sprintf\s*\(/.test(ts) || /["`]\s*\+\s*\w/.test(ts))) || (prof.lang === 'rb' && /#\{/.test(ts)) || (prof.lang === 'php' && (/\$\w+/.test(ts.replace(/'[^']*'/g, '')) && /"[^"]*\$\w+|\.\s*\$/.test(ts))) || (prof.lang === 'cs' && /\$@?"[^"]*\{/.test(ts)) || (prof.lang === 'java' && /\.formatted\s*\(|String\s*\.\s*format\s*\(/.test(ts)) || /["']\s*\.\s*\$|\+\s*[A-Za-z_]/.test(ts);
      const reqDerived = taintedExpr(args) || (interp && taintedExpr(ts));
      const sets = op === 'write' && /\bSET\b/i.test(ts) ? [...new Set([...ts.matchAll(/\b([a-z_]+)\s*=\s*(?:\?|\$\d+|:\w+|%s|['"]?\s*[#{$]|["']\s*\+|\+)/gi)].map((x) => x[1].toLowerCase()).filter((x) => PRIVILEGED.test(x)))].sort() : [];
      const whereAt = ts.search(/\bWHERE\b/i);
      const whereText = whereAt < 0 ? '' : ts.slice(whereAt);
      const info = { store: 'sql' as const, op, target: table, by_id: reqDerived && ID_COL.test(whereText), limit_from_request: /\bLIMIT\b/i.test(ts) && reqDerived, request_derived: reqDerived, owner_scoped: ownerNear(whereText + ' ' + ts), raw_sql: true, sets, mass_assign: false, confidence: 'medium' as Confidence };
      if (prof.sqlCall.test(ms) || prof.data.some((r) => r.store === 'sql' && new RegExp(r.re.source).test(ms))) emitted.push({ ...info, line: line(sqlLit.index) });
      else if (lhs) for (const n of lhsNames) sqlVars.set(n, { ...info, raw: ts });
    } else if (prof.sqlCall.test(ms)) {
      // The query text was built in an earlier statement.
      for (const n of idents(prof, ms)) {
        const prior = sqlVars.get(n);
        if (prior) { emitted.push({ ...(prior as DataTouch), request_derived: prior.request_derived || taintedExpr(ts), by_id: !!prior.by_id || (taintedExpr(ts) && ID_COL.test(prior.raw)), line: line(0) }); break; }
      }
    }
    if (!emitted.length) {
      const seen = new Set<number>();
      for (const rule of prof.data) {
        const g = new RegExp(rule.re.source, 'g');
        const hay = /['"`]/.test(rule.re.source) ? ts : ms; // a rule that reads a table name needs the string text
        for (let m = g.exec(hay); m; m = g.exec(hay)) {
          if (m[0] === '') { g.lastIndex++; continue; }
          if (hay !== ms && ms[m.index] === ' ' && ts[m.index] !== ' ') continue; // starts inside a comment
          if (seen.has(m.index)) continue;
          if (rule.store === 'sql' && sqlLit) continue;
          const verb = m[rule.verb] ?? '';
          if (/^(?:new|build)$/.test(verb)) { for (const n of lhsNames) vars.set(n, { target: rule.target ? m[rule.target] : null, byId: false, owner: false }); continue; }
          seen.add(m.index);
          const tail = ms.slice(m.index);
          const chain = [verb, ...[...tail.matchAll(/(?:\.|->|::)\s*([A-Za-z_]\w*[?!]?)/g)].map((x) => x[1])];
          const op: DataTouch['op'] = chain.some((c) => prof.verbs.del.test(c)) ? 'delete' : chain.some((c) => prof.verbs.write.test(c)) ? 'write' : chain.some((c) => prof.verbs.read.test(c)) ? 'read' : 'unknown';
          const open = m[0].endsWith('(') ? s + m.index + m[0].length - 1 : -1;
          const close = open >= 0 ? closeOf(view.masked, open) : -1;
          const args = open >= 0 && close > 0 ? view.text.slice(open + 1, close - 1) : view.text.slice(s + m.index + m[0].length, e);
          const ruleTarget: string | null = rule.target !== null ? ((m[rule.target] as string | undefined) ?? null) : null;
          const tgt0: string | null = ruleTarget ?? (prof.lang === 'go' && rule.store === 'orm' ? goTarget(ts.slice(m.index), view.text) : null);
          const tgt = tgt0 !== null && (prof.lang === 'java' || prof.lang === 'cs') ? tgt0.replace(/^_/, '').replace(/(?:Repository|Repo|Dao|DAO)$/, '') || tgt0 : tgt0;
          const reqDerived = taintedExpr(args) || (chain.length > 1 && taintedExpr(ts.slice(m.index)));
          const keyedVerb = /^(?:find|findOrFail|findMany|findOrNew|sole|findSole|destroy|FindOne|Get[A-Z]\w*|Show\w*|Load\w*)$/.test(verb);
          const createVerb = /^(?:create!?|insert\w*|Create|Save|forceCreate|build|new|insert_all|upsert\w*|updateOrCreate|firstOrCreate|firstOrNew|find_or_create_by|find_or_initialize_by)$/.test(verb);
          const byId = reqDerived && (keyedVerb || (!createVerb && rule.store !== 'filesystem' && ID_COL.test(ts.slice(m.index))));
          const ownerScoped = ownerNear(ts) && (OWNER.test(ts) || OWNER_MORE[prof.lang].test(ts));
          const writeArgs = lastWriteArgs(view, prof, s, ms, op) ?? args;
          const priv = privilegedIn(prof, ts, writeArgs, taintedExpr, t, view, tgt);
          const d: DataTouch = {
            store: rule.store, op, target: tgt ? clip(tgt, 60) : null, line: line(m.index), by_id: byId, limit_from_request: limitReq, request_derived: reqDerived,
            owner_scoped: ownerScoped, raw_sql: rule.store === 'sql' || /\b(?:find_by_sql|whereRaw|selectRaw|orderByRaw)\b/.test(ms), sets: op === 'write' ? priv.sets : [], mass_assign: op === 'write' && priv.mass, confidence: rule.conf,
          };
          // A write on a variable that an earlier statement loaded by id inherits what that load did.
          if (op === 'write' || op === 'delete') {
            for (const n of idents(prof, args)) {
              const v = vars.get(n);
              if (v) { d.by_id = d.by_id || v.byId; d.owner_scoped = d.owner_scoped || v.owner; d.target = d.target ?? v.target; }
            }
          }
          emitted.push(d);
          if (lhs) for (const n of lhsNames) if (n !== 'err' && n !== 'ok') vars.set(n, { target: tgt, byId, owner: ownerScoped });
        }
      }
      // Methods called on a record that an earlier statement loaded: @note.update(...), $note->delete(), note.destroy.
      const inst = prof.lang === 'rb' ? /(@?\w+)\.(update|update!|update_attributes|update_attribute|update_column|update_columns|destroy|destroy!|delete|save|save!|toggle!|increment!|decrement!|touch)\b/ : prof.lang === 'php' ? /(\$\w+)\s*->\s*(update|delete|save|fill|forceDelete|restore|increment|decrement|touch|push|forceFill)\s*\(/ : null;
      const im = inst ? inst.exec(ms) : null;
      if (im) {
        const v = vars.get(im[1]);
        if (v && !emitted.length) {
          const open = ms.indexOf('(', im.index);
          const close = open >= 0 ? closeOf(view.masked, s + open) : -1;
          const args = open >= 0 && close > 0 ? view.text.slice(s + open + 1, close - 1) : ts.slice(im.index + im[0].length);
          const op: DataTouch['op'] = prof.verbs.del.test(im[2]) ? 'delete' : 'write';
          const priv = privilegedIn(prof, ts, args, taintedExpr, t, view, v.target);
          emitted.push({ store: 'orm', op, target: v.target, line: line(im.index), by_id: v.byId, limit_from_request: false, request_derived: taintedExpr(args) || v.byId, owner_scoped: v.owner, raw_sql: false, sets: op === 'write' ? priv.sets : [], mass_assign: op === 'write' && priv.mass, confidence: 'medium' });
        }
      }
      // Assignments of a privileged field from request data: $user->role = $request->role; user.Role = req.Role
      const fa = prof.lang === 'php' ? /(\$\w+)\s*->\s*(\w+)\s*=\s*([^;]+)/.exec(ms) : prof.lang === 'rb' ? /(@?\w+)\.(\w+)\s*=\s*(.+)/.exec(ms) : prof.lang === 'java' ? /(\w+)\.set([A-Z]\w*)\s*\(([^;]+)\)/.exec(ms) : /(\w+)\.(\w+)\s*=\s*(.+)/.exec(ms);
      if (fa && PRIVILEGED.test(snake(fa[2])) && taintedExpr(fa[3]) && !emitted.length) {
        const v = vars.get(fa[1]);
        emitted.push({ store: 'orm', op: 'write', target: v?.target ?? null, line: line(fa.index), by_id: v?.byId ?? false, limit_from_request: false, request_derived: true, owner_scoped: v?.owner ?? false, raw_sql: false, sets: [snake(fa[2])], mass_assign: false, confidence: 'medium' });
      }
    }
    for (const d of emitted) {
      if (policy && d.by_id && !d.owner_scoped && d.op !== 'unknown') d.owner_scoped = true;
      if (d.op !== 'unknown' || d.sets.length || d.mass_assign) data.push(d);
    }
  }

  // ---- outbound
  const outbound: Outbound[] = [];
  const fnText = view.text.slice(start, end);
  const masked = view.masked.slice(start, end);
  for (const rule of prof.outbound) {
    const g = new RegExp(rule.re.source, 'g');
    for (let m = g.exec(masked); m; m = g.exec(masked)) {
      if (m[0] === '') { g.lastIndex++; continue; }
      const at = start + m.index;
      const open = m[0].endsWith('(') ? at + m[0].length - 1 : view.masked.indexOf('(', at);
      const lineEnd = view.masked.indexOf('\n', at);
      const hasParen = open >= 0 && open < (lineEnd < 0 ? view.masked.length : lineEnd);
      const close = hasParen ? closeOf(view.masked, open) : -1;
      const full = hasParen && close > 0 ? view.text.slice(open + 1, close - 1) : view.text.slice(at + m[0].length, lineEnd < 0 ? end : lineEnd);
      const parts = full.split(/,(?![^(]*\))/);
      const picked = rule.arg !== undefined && parts.length > rule.arg ? parts[rule.arg] : parts[0];
      const target = clip(picked || m[0], 120);
      const derived = taintedExpr(rule.arg !== undefined ? picked : full);
      outbound.push({ kind: rule.kind, line: view.lines.at(at), target, request_derived: derived, guarded: rule.guard === 'url' ? URL_GUARD.test(fnText) : rule.guard === 'redirect' ? REDIRECT_GUARD.test(fnText) : false, confidence: rule.conf });
    }
  }
  const seenO = new Set<string>();
  const out = outbound.filter((o) => { const k = `${o.kind}:${o.line}:${o.target}`; if (seenO.has(k)) return false; seenO.add(k); return true; })
    .sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.target < b.target ? -1 : a.target > b.target ? 1 : 0));

  for (const d of data) if (d.owner_scoped && (d.by_id || d.request_derived || d.op !== 'read')) prot.push({ kind: 'owner_filter', scope: 'handler', file: view.file, line: d.line, via: `${d.store} ${d.target ?? ''}`.trim(), enforced: null, confidence: 'medium' });
  if (policy) {
    const pf = pick(view, prof.role, start, end).find((x) => /authorize|policy|Gate|can/i.test(view.text.slice(x.index, x.index + 40)));
    if (pf && data.some((d) => d.by_id)) prot.push({ kind: 'owner_filter', scope: 'handler', file: view.file, line: view.lines.at(pf.index), via: 'policy authorize', enforced: null, confidence: 'medium' });
  }

  data.sort((a, b) => a.line - b.line || (a.store < b.store ? -1 : a.store > b.store ? 1 : 0) || ((a.target ?? '') < (b.target ?? '') ? -1 : 1));
  const seenD = new Set<string>();
  const dd = data.filter((d) => { const k = `${d.line}:${d.store}:${d.op}:${d.target}`; if (seenD.has(k)) return false; seenD.add(k); return true; });
  prot.sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.via < b.via ? -1 : a.via > b.via ? 1 : 0));
  const seenP = new Set<string>();
  const protections = prot.filter((q) => { const k = `${q.kind}|${q.scope}|${q.file}|${q.line}|${q.via}`; if (seenP.has(k)) return false; seenP.add(k); return true; });
  return { protections, reads: readsOf(view, prof, start, end), data: dd, outbound: out, taint: t };
}

// The arguments of the last call in the statement that writes or deletes, so find(params[:id]).update(role: x) reads update's.
function lastWriteArgs(view: FileView, prof: Profile, s: number, ms: string, op: DataTouch['op']): string | null {
  if (op !== 'write' && op !== 'delete') return null;
  const verbRe = op === 'write' ? prof.verbs.write : prof.verbs.del;
  let best: string | null = null;
  for (const m of ms.matchAll(/(?:\.|->|::)\s*([A-Za-z_]\w*[?!]?)\s*\(/g)) {
    if (!verbRe.test(m[1])) continue;
    const open = s + m.index! + m[0].length - 1;
    const close = closeOf(view.masked, open);
    if (close > 0) best = view.text.slice(open + 1, close - 1);
  }
  return best;
}

// Privileged columns a write sets from request data, and whether a whole request object goes into it.
function privilegedIn(prof: Profile, stmt: string, args: string, tainted: (e: string) => boolean, t: Taint, view: FileView, _target: string | null): { sets: string[]; mass: boolean } {
  const sets = new Set<string>();
  let mass = false;
  const pairs: [string, string][] = [];
  if (prof.lang === 'php') for (const m of args.matchAll(/['"](\w+)['"]\s*=>\s*([^,\]\n]+)/g)) pairs.push([m[1], m[2]]);
  else if (prof.lang === 'rb') { for (const m of args.matchAll(/(?:^|[(,\s])(\w+):\s*([^,)\n]+)/g)) pairs.push([m[1], m[2]]); for (const m of args.matchAll(/:(\w+)\s*=>\s*([^,)\n]+)/g)) pairs.push([m[1], m[2]]); for (const m of stmt.matchAll(/\.update_(?:column|attribute)s?\s*\(\s*:(\w+)\s*,\s*([^)]+)\)/g)) pairs.push([m[1], m[2]]); }
  else { for (const m of args.matchAll(/(?:^|[{,\s])["']?(\w+)["']?\s*:\s*([^,}\n]+)/g)) pairs.push([m[1], m[2]]); for (const m of stmt.matchAll(/\.Update(?:Column)?\s*\(\s*["'](\w+)["']\s*,\s*([^)]+)\)/g)) pairs.push([m[1], m[2]]); }
  for (const [k, v] of pairs) if (PRIVILEGED.test(snake(k)) && tainted(v)) sets.add(snake(k));
  if (prof.lang === 'rb') {
    // params.require(:user).permit(:email, :role) or a *_params method that holds the list
    const lists: string[] = [];
    for (const m of (args + ' ' + stmt).matchAll(/\b(\w+_params)\b/g)) {
      const def = new RegExp(`def\\s+${m[1]}\\b([\\s\\S]*?)\\n\\s*end\\b`).exec(view.text);
      if (def) lists.push(def[1]);
    }
    lists.push(args);
    for (const l of lists) {
      if (/\.permit!/.test(l)) mass = true;
      for (const pm of l.matchAll(/\.permit\s*\(([^)]*)\)/g)) for (const s of pm[1].matchAll(/:(\w+)/g)) if (PRIVILEGED.test(s[1])) sets.add(s[1]);
    }
    if (/^\s*params(?:\[\s*:\w+\s*\])?\s*$/.test(args) || /\bto_unsafe_h\b|\bparams\.to_h\b/.test(args)) mass = true;
  } else if (prof.lang === 'php') {
    if (/\$request->(?:all|input)\s*\(\s*\)|\$request->post\s*\(\s*\)|\$request->except\s*\(|\$_POST\b|\$_REQUEST\b|\$request->toArray\s*\(/.test(args) || /^\s*\$request\s*$/.test(args)) mass = true;
    for (const m of args.matchAll(/\$request->only\s*\(\s*\[([^\]]*)\]/g)) for (const s of m[1].matchAll(/['"](\w+)['"]/g)) if (PRIVILEGED.test(snake(s[1]))) sets.add(snake(s[1]));
    const v = /^\s*(\$\w+)\s*$/.exec(args)?.[1];
    if (v && t.names.has(v) && !t.validated.has(v) && !t.trusted.has(v)) mass = true;
  } else {
    // A decoded struct handed whole to a write: its fields decide.
    const v = /^\s*&?(\w+)\s*$/.exec(args.split(',').pop() ?? '')?.[1];
    if (v && t.names.has(v) && !t.trusted.has(v)) {
      const typ = new RegExp(`\\bvar\\s+${v}\\s+\\*?([A-Z]\\w*)|\\b${v}\\s*:?=\\s*&?([A-Z]\\w*)\\s*\\{|\\b${v}\\s+\\*?([A-Z]\\w*)\\b`).exec(view.text);
      const tn = typ ? typ[1] ?? typ[2] ?? typ[3] : null;
      const body = tn ? new RegExp(`type\\s+${tn}\\s+struct\\s*\\{([^}]*)\\}`).exec(view.text)?.[1] ?? null : null;
      if (body !== null) { for (const f of body.matchAll(/^\s*(\w+)\s+[\w.*[\]]+/gm)) if (PRIVILEGED.test(snake(f[1]))) sets.add(snake(f[1])); }
      else if (/map\[string\]/.test(view.text.slice(0, view.text.length)) && new RegExp(`\\b${v}\\s*:?=\\s*(?:make\\s*\\()?map\\[string\\]`).test(view.text)) mass = true;
      else if (!tn) mass = true;
    }
  }
  return { sets: [...sets].sort(), mass };
}
