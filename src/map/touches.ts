// Data store touches and outbound calls inside one handler body. SQL text is found by its string literal; ORM, Supabase and
// Firebase calls are found by their call shape. Everything is a pattern, so each touch carries a confidence.
import type { Confidence, DataTouch, Outbound, OutboundKind, StoreKind } from '../types/index.ts';
import type { Lang } from './lex.ts';
import { closeOf, splitArgs, statementEnd } from './lex.ts';
import type { Taint } from './taint.ts';
import { hasSessionValue, identifiers, isTainted } from './taint.ts';
import { OWNER, PRIVILEGED, REDIRECT_GUARD, URL_GUARD } from './vocab.ts';

export interface Region { masked: string; text: string; base: number; line(index: number): number }

const clip = (s: string, n: number): string => (s.length <= n ? s : s.slice(0, n - 1) + '…');
const oneLine = (s: string): string => s.replace(/\s+/g, ' ').trim();

interface Literal { open: number; start: number; end: number; quote: string; fString: boolean }
// String literals in a region, found from the quotes that mask() keeps.
function literals(masked: string, lang: Lang): Literal[] {
  const out: Literal[] = [];
  for (let i = 0; i < masked.length; i++) {
    const c = masked[i];
    if (c !== '"' && c !== "'" && c !== '`') continue;
    const triple = lang === 'py' && masked.startsWith(c.repeat(3), i);
    const close = triple ? masked.indexOf(c.repeat(3), i + 3) : masked.indexOf(c, i + 1);
    if (close < 0) break;
    const prefix = lang === 'py' ? masked.slice(Math.max(0, i - 2), i) : '';
    out.push({ open: i, start: i + (triple ? 3 : 1), end: close, quote: c, fString: /[fF]$/.test(prefix) || /[fF][rRbB]$/.test(prefix) || /[rRbB][fF]$/.test(prefix) });
    i = close + (triple ? 2 : 0);
  }
  return out;
}

const SQL_START = /^\s*\(?\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|WITH\s+\w+\s+AS)\b/i;
const SQL_ID = /(?:^|[\s(,.])(?:\w+\.)?(?:id|uuid|pk|_id)\s*=\s*(?:\?|\$\d+|:\w+|%s|@\w+|\$\{|\{|'\s*\+|"\s*\+|'\s*$|"\s*$|\s*$)/i;
const SQL_END = /\b(?:ORDER\s+BY|GROUP\s+BY|LIMIT|RETURNING|OFFSET|HAVING)\b|;/i;

function sqlTouch(lit: Literal, region: Region, t: Taint, lang: Lang): DataTouch | null {
  const sql = region.text.slice(lit.start, lit.end);
  const m = SQL_START.exec(sql);
  if (!m || sql.length < 12) return null;
  const word = m[1].toUpperCase();
  const op: DataTouch['op'] = word.startsWith('SELECT') || word.startsWith('WITH') ? 'read' : word.startsWith('DELETE') ? 'delete' : 'write';
  const target = (/\b(?:FROM|INTO|UPDATE)\s+(?:ONLY\s+)?([\w."]+)/i.exec(sql)?.[1] ?? null)?.replace(/"/g, '') ?? null;
  const w = /\bWHERE\b/i.exec(sql);
  let where = '';
  if (w) { const rest = sql.slice(w.index + 5); const e = SQL_END.exec(rest); where = e ? rest.slice(0, e.index) : rest; }
  const interpolated = lang === 'js' ? lit.quote === '`' && /\$\{/.test(sql) : lit.fString && /\{[^{}]+\}/.test(sql);
  const interpExprs = lang === 'js' ? [...sql.matchAll(/\$\{([^}]*)\}/g)].map((x) => x[1]) : lit.fString ? [...sql.matchAll(/\{([^{}]+)\}/g)].map((x) => x[1]) : [];
  // The statement around the literal: back to the previous ";", "{" or "}" and forward to the end of the statement.
  let begin = lit.open;
  for (let k = lit.open - 1; k >= 0 && lit.open - k < 700; k--) { const c = region.masked[k]; if (c === ';' || c === '{' || c === '}') { begin = k + 1; break; } begin = k; }
  while (begin < lit.open && /\s/.test(region.masked[begin])) begin++;
  const end = statementEnd(region.masked, begin);
  const around = region.masked.slice(begin, end);
  const concat = /^\s*(?:\+|%|\.format\s*\()/.test(region.masked.slice(lit.end + 1, lit.end + 14)) || /\+\s*$/.test(region.masked.slice(Math.max(0, lit.open - 6), lit.open));
  const requestDerived = interpExprs.some((e) => isTainted(t, e, lang)) || isTainted(t, around, lang);
  const rawSql = (interpolated && interpExprs.some((e) => isTainted(t, e, lang))) || (concat && isTainted(t, around, lang));
  const params = positionalArgs(region, lit, begin, end);
  const valueTainted = (expr: string, offset: number): boolean => {
    // The value of a column or limit: an interpolation in the text, or the parameter at its placeholder position.
    const inline = [...expr.matchAll(lang === 'js' ? /\$\{([^}]*)\}/g : /\{([^{}]+)\}/g)].map((x) => x[1]);
    if (inline.length) return inline.some((e) => isTainted(t, e, lang));
    const ph = /\?|%s|\$(\d+)/.exec(expr);
    if (!ph) return false;
    if (!params) return false;
    const before = sql.slice(0, offset + ph.index);
    const idx = ph[1] ? Number(ph[1]) - 1 : (before.match(/\?|%s/g) ?? []).length;
    return params[idx] !== undefined && isTainted(t, params[idx], lang);
  };
  const sets: string[] = [];
  if (op === 'write') {
    const set = /\bSET\b/i.exec(sql);
    if (set) {
      const wh = /\bWHERE\b/i.exec(sql.slice(set.index));
      const body = sql.slice(set.index + 3, wh ? set.index + wh.index : sql.length);
      for (const part of splitTopOffsets(body, set.index + 3)) {
        const cm = /^\s*(?:\w+\.)?"?(\w+)"?\s*=\s*([\s\S]*)$/.exec(part.text);
        if (cm && PRIVILEGED.test(cm[1]) && valueTainted(cm[2], part.offset + part.text.indexOf(cm[2]))) sets.push(cm[1]);
      }
    } else {
      const ins = /\(([^)]*)\)\s*VALUES\s*\(/i.exec(sql);
      if (ins) {
        const cols = ins[1].split(',').map((x) => x.trim().replace(/"/g, ''));
        const vopen = ins.index + ins[0].length - 1;
        const vclose = closeIn(sql, vopen);
        const vals = splitTopOffsets(sql.slice(vopen + 1, vclose), vopen + 1);
        cols.forEach((c, i) => { if (PRIVILEGED.test(c) && vals[i] && valueTainted(vals[i].text, vals[i].offset)) sets.push(c); });
      }
    }
  }
  // by_id: the id comparison itself takes a request value (not just any request value somewhere in the statement).
  let byId = false;
  if (w) {
    const idm = new RegExp(SQL_ID.source, 'i').exec(sql.slice(w.index + 5));
    if (idm) {
      const eq = idm.index + idm[0].indexOf('=') + 1;
      const offset = w.index + 5 + eq;
      byId = valueTainted(sql.slice(offset, offset + 30), offset) || (concat && requestDerived && /=\s*['"]?\s*$/.test(sql.slice(offset - 1, w.index + 5 + idm.index + idm[0].length + 1)));
    }
  }
  let limitFromRequest = false;
  const lm = /\bLIMIT\s+(\?|%s|\$\d+|:\w+|\$\{[^}]*\}|\{[^{}]*\})/i.exec(sql);
  if (lm) limitFromRequest = valueTainted(lm[1], lm.index + 6);
  return {
    store: 'sql', op, target, line: region.line(lit.open), by_id: byId, limit_from_request: limitFromRequest,
    request_derived: requestDerived, owner_scoped: OWNER.test(where) && hasSessionValue(t, `${around} ${interpExprs.join(' ')}`), raw_sql: rawSql, sets: [...new Set(sets)].sort(), mass_assign: false, confidence: 'high',
  };
}

function closeIn(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) { if (s[i] === '(') depth++; else if (s[i] === ')') { depth--; if (depth === 0) return i; } }
  return s.length;
}
function splitTopOffsets(s: string, base: number): { text: string; offset: number }[] {
  const out: { text: string; offset: number }[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i <= s.length; i++) {
    const c = s[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    if ((c === ',' && depth === 0) || i === s.length) { if (s.slice(from, i).trim()) out.push({ text: s.slice(from, i), offset: base + from }); from = i + 1; }
  }
  return out;
}

// The parameter expressions that go with a SQL string, in order: the array or tuple given to run, get, all, execute or query
// after it (JavaScript), or the second argument of the call that holds it (Python and others).
function positionalArgs(region: Region, lit: Literal, begin: number, end: number): string[] | null {
  const m = region.masked;
  const after = /^\s*,?\s*\)?\s*\.\s*(?:run|get|all|execute|query|exec|values|iterate|pluck|raw)\s*\(/.exec(m.slice(lit.end + 1, end));
  let open = -1;
  if (after) open = lit.end + 1 + after[0].length - 1;
  else {
    // The literal is an argument of a call: execute("...", (a, b)).
    for (let k = lit.open - 1; k >= begin; k--) { if (m[k] === '(') { open = k; break; } if (m[k] === ')' ) break; }
  }
  if (open < 0) return null;
  const args = splitArgs(m, open);
  let rest = args;
  if (!after) rest = args.filter((a) => a.start > lit.open);
  if (!rest.length) return null;
  const first = m.slice(rest[0].start, rest[0].end);
  if (/^[\[(]/.test(first) && (rest.length === 1 || !after)) {
    const inner = splitArgs(m, rest[0].start);
    if (inner.length || /^[\[(]\s*[\])]$/.test(first)) return inner.map((a) => region.text.slice(a.start, a.end));
  }
  return rest.map((a) => region.text.slice(a.start, a.end));
}

const NOT_MODEL = new Set(['Object', 'Array', 'Promise', 'Math', 'JSON', 'Number', 'String', 'Symbol', 'Buffer', 'Date', 'Map', 'Set', 'WeakMap', 'Reflect', 'Proxy', 'Intl', 'URL', 'Error', 'Response', 'NextResponse', 'Request', 'Headers', 'FormData', 'File', 'Blob', 'Boolean', 'RegExp', 'Uint8Array', 'process', 'console', 'React', 'Cache', 'Event', 'AbortController', 'URLSearchParams', 'TextEncoder', 'TextDecoder', 'Atomics', 'BigInt']);
const OP_WORDS: [RegExp, DataTouch['op']][] = [[/^(?:find|get|select|count|aggregate|exists|query|read|list|distinct|group|all|filter|exclude|values|first|last|only|defer|order_by|annotate|iterator|one)/i, 'read'], [/^(?:create|insert|update|upsert|save|set|add|bulk|replace|merge|increment|decrement)/i, 'write'], [/^(?:delete|destroy|remove|drop|truncate)/i, 'delete']];
const opOf = (name: string): DataTouch['op'] => OP_WORDS.find(([re]) => re.test(name))?.[1] ?? 'unknown';

function callArgs(region: Region, open: number): string {
  const c = closeOf(region.masked, open);
  return region.text.slice(open, c < 0 ? Math.min(region.text.length, open + 400) : c);
}

function ormTouch(store: StoreKind, name: string, target: string | null, args: string, at: number, region: Region, t: Taint, lang: Lang, confidence: Confidence, byIdName: boolean): DataTouch {
  const op = opOf(name);
  const derived = isTainted(t, args, lang);
  let byId = byIdName && derived;
  // key: value pairs of the argument object (JavaScript) or keyword arguments (Python); a shorthand key is its own value.
  const pairs: [string, string][] = [];
  if (lang === 'js') for (const m of args.matchAll(/(?:^|[{,\s])([A-Za-z_$][\w$]*)\s*(?::\s*([^,}\n]+)|(?=\s*[,}]))/g)) pairs.push([m[1], m[2] ?? m[1]]);
  else for (const m of args.matchAll(/(?:^|[(,\s])([A-Za-z_]\w*)\s*=\s*([^,)\n]+)/g)) pairs.push([m[1], m[2]]);
  // A shorthand key inside a nested object, as in { where: { id } }, is swallowed by the value of the outer key above.
  if (lang === 'js') for (const m of args.matchAll(/[{,]\s*([A-Za-z_$][\w$]*)\s*(?=[,}])/g)) pairs.push([m[1], m[1]]);
  for (const [k, v] of pairs) if (/^(?:id|_id|uuid|pk)$/.test(k) && isTainted(t, v, lang)) byId = true;
  const sets = op === 'write' ? pairs.filter(([k, v]) => PRIVILEGED.test(k) && isTainted(t, v, lang)).map(([k]) => k) : [];
  const limit = pairs.some(([k, v]) => /^(?:take|limit|first|pageSize|page_size|per_page|perPage|size|max|count)$/.test(k) && isTainted(t, v, lang)) || /\.\s*(?:limit|take|range|slice)\s*\(\s*[^)]*\)/.test(args) && [...args.matchAll(/\.\s*(?:limit|take|range|slice)\s*\(([^)]*)\)/g)].some((m) => isTainted(t, m[1], lang));
  const spread = /\.\.\.\s*([\w$.]+)|\*\*\s*([\w.]+)|data\s*:\s*([\w$.]+)\s*[,}]|\(\s*([\w$.]+)\s*\)\s*$/g;
  let mass = false;
  if (op === 'write') for (const m of args.matchAll(spread)) { const v = m[1] ?? m[2] ?? m[3] ?? m[4]; if (v && identifiers(v).some((i) => t.names.has(i) && !t.trusted.has(i) && !t.validated.has(i)) && !/^\s*(?:id|where)/.test(v)) mass = true; }
  return { store, op, target, line: region.line(at), by_id: byId, limit_from_request: limit, request_derived: derived, owner_scoped: OWNER.test(args) && hasSessionValue(t, args), raw_sql: false, sets: [...new Set(sets)].sort(), mass_assign: mass, confidence };
}

export function dataTouches(region: Region, t: Taint, lang: Lang): DataTouch[] {
  const out: DataTouch[] = [];
  const { masked } = region;
  for (const lit of literals(masked, lang)) { const d = sqlTouch(lit, region, t, lang); if (d) out.push(d); }
  const seen = new Set<number>();
  const add = (m: RegExpMatchArray, build: (open: number) => DataTouch | null): void => {
    const open = m.index! + m[0].length - 1;
    if (seen.has(open)) return;
    const d = build(open);
    if (d) { seen.add(open); out.push(d); }
  };
  if (lang === 'js') {
    for (const m of masked.matchAll(/\b(prisma|db|client|tx|trx|database|orm)\s*\.\s*([A-Za-z_]\w*)\s*\.\s*(findUnique|findFirst|findMany|findUniqueOrThrow|findFirstOrThrow|create|createMany|update|updateMany|upsert|delete|deleteMany|count|aggregate|groupBy)\s*\(/g))
      add(m, (open) => ormTouch('prisma', m[3], m[2], callArgs(region, open), m.index!, region, t, lang, 'high', false));
    for (const m of masked.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*(find|findOne|findById|findByPk|findAll|findAndCountAll|findOneOrFail|findOneBy|findBy|findById\w*|findOneAnd\w+|updateOne|updateMany|deleteOne|deleteMany|create|createMany|insertMany|insertOne|bulkCreate|countDocuments|count|aggregate|destroy|update|upsert|save|remove)\s*\(/g)) {
      const recv = m[1];
      const modelLike = (/^[A-Z]\w*$/.test(recv) && !NOT_MODEL.has(recv)) || /(?:Model|Collection|Repo|Repository)$/.test(recv);
      if (!modelLike) continue;
      add(m, (open) => ormTouch(/Collection$/.test(recv) || /^(?:findOneAnd|insertOne|insertMany|updateOne|deleteOne|countDocuments)/.test(m[2]) ? 'mongo' : 'orm', m[2], recv, callArgs(region, open), m.index!, region, t, lang, 'medium', /^findById|^findByPk/.test(m[2])));
    }
    for (const m of masked.matchAll(/\.\s*from\s*\(\s*(['"])/g)) {
      const quoteAt = m.index! + m[0].length - 1;
      const close = masked.indexOf(m[1], quoteAt + 1);
      const table = region.text.slice(quoteAt + 1, close);
      const end = statementEnd(masked, m.index!); // from the dot of .from(, so the whole chain is read
      const chain = region.text.slice(close, end);
      const verb = /\.\s*(select|insert|update|delete|upsert)\s*\(/.exec(chain);
      if (!verb) continue;
      const op: DataTouch['op'] = verb[1] === 'select' ? 'read' : verb[1] === 'delete' ? 'delete' : 'write';
      const eqs = [...chain.matchAll(/\.\s*(?:eq|match|in|filter)\s*\(\s*['"]([\w.]+)['"]\s*,\s*([^)]*)\)/g)];
      const byId = eqs.some((e) => /^(?:id|uuid|_id)$/.test(e[1]) && isTainted(t, e[2], lang));
      const sets: string[] = [];
      if (op === 'write') for (const c of chain.matchAll(/(?:^|[{,\s])([A-Za-z_]\w*)\s*:/g)) if (PRIVILEGED.test(c[1])) sets.push(c[1]);
      out.push({ store: /\.storage\s*\.\s*from/.test(masked.slice(Math.max(0, m.index! - 12), m.index! + 6)) ? 'object_storage' : 'supabase', op, target: table, line: region.line(m.index!), by_id: byId, limit_from_request: [...chain.matchAll(/\.\s*(?:limit|range)\s*\(([^)]*)\)/g)].some((x) => isTainted(t, x[1], lang)), request_derived: isTainted(t, chain, lang), owner_scoped: OWNER.test(chain.replace(/\.\s*(?:select|insert)\s*\([^)]*\)/g, '')) && hasSessionValue(t, chain), raw_sql: false, sets: [...new Set(sets)].sort(), mass_assign: op === 'write' && /\(\s*(?:body|req\.body|await\s+\w+\.json\(\))\s*\)/.test(chain), confidence: 'high' });
    }
    for (const m of masked.matchAll(/\b(?:redis|cache|kv)\s*\.\s*(get|set|del|hget|hset|hgetall|incr|expire|setex)\s*\(/g)) out.push({ store: 'redis', op: opOf(m[1]), target: null, line: region.line(m.index!), by_id: false, limit_from_request: false, request_derived: isTainted(t, callArgs(region, m.index! + m[0].length - 1), lang), owner_scoped: false, raw_sql: false, sets: [], mass_assign: false, confidence: 'medium' });
    for (const m of masked.matchAll(/\bfs(?:\.promises)?\s*\.\s*(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|unlink|unlinkSync|readdir|readdirSync|appendFile|rm|rmSync)\s*\(/g)) {
      const args = callArgs(region, m.index! + m[0].length - 1);
      out.push({ store: 'filesystem', op: /^(?:read|create.*Read)/.test(m[1]) ? 'read' : /unlink|rm/.test(m[1]) ? 'delete' : 'write', target: null, line: region.line(m.index!), by_id: false, limit_from_request: false, request_derived: isTainted(t, args, lang), owner_scoped: false, raw_sql: false, sets: [], mass_assign: false, confidence: 'high' });
    }
  } else {
    for (const m of masked.matchAll(/\b([A-Z]\w*)\s*\.\s*objects\s*\.\s*(get|filter|all|exclude|create|update|delete|get_or_create|update_or_create|bulk_create|values|first|last|count|exists|select_related|prefetch_related)\s*\(/g))
      add(m, (open) => {
        // The verb at the end of the chain decides the operation: Note.objects.filter(pk=pk).delete().
        const chain = region.masked.slice(open, statementEnd(region.masked, m.index!));
        const verb = /\)\s*\.\s*(delete|update|create|bulk_create|bulk_update|update_or_create|get_or_create)\s*\(/.exec(chain);
        const tail = verb ? region.text.slice(open, open + chain.length) : callArgs(region, open);
        const d = ormTouch('orm', verb ? verb[1] : m[2], m[1], verb ? tail : callArgs(region, open), m.index!, region, t, lang, 'high', false);
        // A slice such as [:limit] after the query is a limit; it counts when the bound is request data.
        const slice = [...chain.matchAll(/\[\s*(?:[^\]:]*:)\s*([^\]]+)\]/g)].some((x) => isTainted(t, region.text.slice(open + (x.index ?? 0), open + (x.index ?? 0) + x[0].length), lang));
        return slice ? { ...d, limit_from_request: true } : d;
      });
    for (const m of masked.matchAll(/\bget_object_or_404\s*\(/g)) add(m, (open) => ormTouch('orm', 'get', null, callArgs(region, open), m.index!, region, t, lang, 'high', false));
    for (const m of masked.matchAll(/\b([A-Z]\w*)\s*\.\s*query\s*\.\s*(get|get_or_404|filter|filter_by|all|first|first_or_404|delete|one|one_or_none|count)\s*\(/g))
      add(m, (open) => ormTouch('orm', m[2], m[1], callArgs(region, open), m.index!, region, t, lang, 'high', /^get/.test(m[2])));
    for (const m of masked.matchAll(/\b(?:db\.)?session\s*\.\s*(query|get|add|delete|merge|execute|scalar|scalars)\s*\(/g))
      add(m, (open) => ormTouch('orm', m[1] === 'query' ? 'select' : m[1], null, callArgs(region, open), m.index!, region, t, lang, 'medium', m[1] === 'get'));
    for (const m of masked.matchAll(/\b(\w*(?:collection|coll|db))\s*\.\s*(find|find_one|insert_one|insert_many|update_one|update_many|delete_one|delete_many|count_documents|aggregate|replace_one)\s*\(/g))
      add(m, (open) => ormTouch('mongo', m[2], m[1], callArgs(region, open), m.index!, region, t, lang, 'medium', false));
    for (const m of masked.matchAll(/\.\s*table\s*\(\s*['"]([\w.]+)['"]\s*\)/g)) out.push({ store: 'supabase', op: 'unknown', target: m[1], line: region.line(m.index!), by_id: false, limit_from_request: false, request_derived: false, owner_scoped: false, raw_sql: false, sets: [], mass_assign: false, confidence: 'medium' });
    for (const m of masked.matchAll(/\b(?:open|os\.remove|os\.unlink|shutil\.\w+|send_from_directory|send_file|Path)\s*\(/g)) {
      const args = callArgs(region, m.index! + m[0].length - 1);
      out.push({ store: 'filesystem', op: /remove|unlink|rmtree/.test(m[0]) ? 'delete' : 'read', target: null, line: region.line(m.index!), by_id: false, limit_from_request: false, request_derived: isTainted(t, args, lang), owner_scoped: false, raw_sql: false, sets: [], mass_assign: false, confidence: 'medium' });
    }
  }
  out.sort((a, b) => a.line - b.line || (a.store < b.store ? -1 : a.store > b.store ? 1 : 0) || ((a.target ?? '') < (b.target ?? '') ? -1 : 1));
  return out;
}


const HTTP_JS = /(?<![.\w$])(?:fetch|ofetch|\$fetch)\s*\(|\b(?:axios|got|ky|needle|superagent|undici|http|https)\s*(?:\.\s*(?:get|post|put|patch|delete|request|head|fetch|stream))?\s*\(|\bnew\s+(?:Request|XMLHttpRequest)\s*\(|\bhttps?\.(?:get|request)\s*\(/g;
const HTTP_PY = /\b(?:requests|httpx|aiohttp|urllib3?)\s*\.\s*(?:get|post|put|patch|delete|request|head|urlopen|fetch)\s*\(|\burlopen\s*\(|\burllib\.request\.\w+\s*\(|\bhttp\.client\.\w+\s*\(|\bpycurl\b/g;
// A client object from an HTTP library the file imports: async with httpx.AsyncClient() as client: client.get(url)
const HTTP_PY_CLIENT = /\b(?:client|session|async_client|http_client|http)\s*\.\s*(?:get|post|put|patch|delete|request|head)\s*\(/g;
const AI_RE = /\b(?:openai|anthropic|genai|ollama|cohere|mistral|groq|replicate)\s*\.\s*(?:chat\.completions\.create|completions\.create|messages\.create|responses\.create|generate_content|generateContent|chat|generate|invoke|stream|embeddings\.create|images\.generate)\s*\(|\b(?:generateText|streamText|generateObject|streamObject|embed|embedMany)\s*\(|\bChatCompletion\.create\s*\(/g;
const EMAIL_RE = /\b(?:sendMail|sendEmail|send_mail|send_email)\s*\(|\.emails\s*\.\s*send\s*\(|\bsgMail\s*\.\s*send\s*\(|\bresend\s*\.|\btransporter\s*\.\s*sendMail\s*\(|\bses\s*\.\s*send\w*\s*\(|\bmailgun\b|\bpostmark\b/g;
const SMS_RE = /\btwilio\b|\bsns\s*\.\s*publish\s*\(|\bsendSms\w*\s*\(|\bsend_sms\w*\s*\(|\bvonage\b/g;
const PAY_RE = /\bstripe\s*\.\s*\w+\s*\.\s*(?:create|retrieve|update|capture|refund|cancel)\s*\(|\bpaystack\w*\s*\.|\bpaddle\w*\s*\.\s*\w+|\bflutterwave\b|\bgateway\s*\.\s*charge\s*\(/g;
const PROC_JS = /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(|\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\(/g;
const PROC_PY = /\b(?:subprocess\s*\.\s*\w+|os\s*\.\s*(?:system|popen|exec\w*)|eval|exec|commands\.getoutput)\s*\(/g;
const REDIRECT = /(?<![.\w$])redirect\s*\(|\b(?:NextResponse|Response|res|reply|ctx|c)\s*\.\s*redirect\s*\(|\bHttpResponseRedirect\s*\(|\bRedirectResponse\s*\(|\bres\.(?:writeHead|status)\s*\(\s*30\d|\bhead\s*\(\s*['"]Location['"]|\bset(?:Header)?\s*\(\s*['"]Location['"]/g;
const REDIRECT_KEY = /(?:^|[{,\s])(redirect|redirectTo|redirect_to|redirectUrl|redirect_url|returnTo|return_to|next|nextUrl|callbackUrl|callback_url|location|url)\s*:\s*([^,}\n]+)/g;

function firstArg(region: Region, open: number): string {
  const a = splitArgs(region.masked, open);
  return a.length ? oneLine(region.text.slice(a[0].start, a[0].end)) : '';
}

export function outboundCalls(region: Region, t: Taint, lang: Lang, returnsJson: boolean, imports = ''): Outbound[] {
  const out: Outbound[] = [];
  const fnText = region.text;
  const add = (kind: OutboundKind, re: RegExp, guard: RegExp | null, confidence: Confidence): void => {
    re.lastIndex = 0;
    for (const m of region.masked.matchAll(re)) {
      const open = region.masked.indexOf('(', m.index!);
      const target = open < 0 ? '' : firstArg(region, open);
      const full = open < 0 ? '' : callArgs(region, open);
      out.push({ kind, line: region.line(m.index!), target: clip(target || oneLine(m[0]), 120), request_derived: kind === 'ai_model' || kind === 'email' || kind === 'sms' || kind === 'payment' ? isTainted(t, full, lang) : isTainted(t, target || full, lang), guarded: guard ? guard.test(fnText) : false, confidence });
    }
  };
  add('http', lang === 'js' ? HTTP_JS : HTTP_PY, URL_GUARD, 'high');
  if (lang === 'py' && /httpx|aiohttp|requests/.test(imports)) add('http', HTTP_PY_CLIENT, URL_GUARD, 'medium');
  add('ai_model', AI_RE, null, 'medium');
  add('email', EMAIL_RE, null, 'medium');
  add('sms', SMS_RE, null, 'medium');
  add('payment', PAY_RE, null, 'medium');
  add('process', lang === 'js' ? PROC_JS : PROC_PY, null, 'high');
  add('redirect', REDIRECT, REDIRECT_GUARD, 'high');
  if (returnsJson) {
    for (const m of fnText.matchAll(REDIRECT_KEY)) {
      if (m[1] === 'url' || m[1] === 'location') continue;
      out.push({ kind: 'redirect', line: region.line(m.index!), target: clip(oneLine(m[2]), 120), request_derived: isTainted(t, m[2], lang), guarded: REDIRECT_GUARD.test(fnText), confidence: 'medium' });
    }
  }
  const seen = new Set<string>();
  return out.filter((o) => { const k = `${o.kind}:${o.line}:${o.target}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.target < b.target ? -1 : a.target > b.target ? 1 : 0));
}
