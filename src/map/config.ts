// Configuration maps: Supabase tables from migration SQL (row level security, policies, grants, columns) and Firebase rules
// (Firestore, Storage and Realtime Database) as one record per match path.
import type { FirebaseRule, SupabaseTable } from '../types/index.ts';
import { cmp } from '../util.ts';
import { Lines } from './lex.ts';
import type { Repo } from './repo.ts';

interface Stmt { text: string; line: number }

// SQL statements with their start line. Comments are dropped, and ";" inside quotes, dollar quoted bodies and brackets does not split.
export function sqlStatements(sql: string): Stmt[] {
  const lines = new Lines(sql);
  const out: Stmt[] = [];
  let i = 0;
  let start = 0;
  let depth = 0;
  const n = sql.length;
  let buf = '';
  const flush = (end: number): void => {
    const t = buf.trim();
    if (t) out.push({ text: t, line: lines.at(start + (buf.length - buf.trimStart().length)) });
    buf = '';
    start = end;
  };
  while (i < n) {
    const c = sql[i];
    if (c === '-' && sql[i + 1] === '-') { while (i < n && sql[i] !== '\n') i++; continue; }
    if (c === '/' && sql[i + 1] === '*') { const e = sql.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === "'") { let j = i + 1; while (j < n && !(sql[j] === "'" && sql[j + 1] !== "'")) { if (sql[j] === "'" ) j++; j++; } buf += sql.slice(i, j + 1); i = j + 1; continue; }
    if (c === '$') {
      const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(i, i + 40));
      if (tag) { const e = sql.indexOf(tag[0], i + tag[0].length); const end = e < 0 ? n : e + tag[0].length; buf += sql.slice(i, end); i = end; continue; }
    }
    if (c === '(') depth++;
    else if (c === ')') depth--;
    if (c === ';' && depth <= 0) { i++; flush(i); depth = 0; continue; }
    buf += c;
    i++;
  }
  flush(n);
  return out;
}

const IDENT = String.raw`(?:"[^"]+"|[A-Za-z_][\w$]*)`;
const QNAME = String.raw`(${IDENT}(?:\s*\.\s*${IDENT})?)`;
const unq = (s: string): string => s.replace(/"/g, '').replace(/\s+/g, '').replace(/^public\./i, '');

function splitTop(s: string, sep = ','): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const c of s) {
    if (c === '(') depth++;
    else if (c === ')') depth--;
    if (c === sep && depth === 0) { out.push(cur); cur = ''; } else cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}
function parenBody(s: string, from: number): string | null {
  const open = s.indexOf('(', from);
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < s.length; i++) { if (s[i] === '(') depth++; else if (s[i] === ')') { depth--; if (depth === 0) return s.slice(open + 1, i); } }
  return null;
}

export function supabaseMap(repo: Repo): { tables: SupabaseTable[] } | null {
  const files = repo.ctx.files.filter((f) => /(?:^|\/)supabase\/(?:migrations\/.*|schema|seed)\.sql$|(?:^|\/)migrations\/.*\.sql$|(?:^|\/)schema\.sql$/i.test(f) && !/seed/i.test(f)).sort(cmp);
  if (!files.length) return null;
  const tables = new Map<string, SupabaseTable>();
  const get = (name: string, file: string, line: number): SupabaseTable => {
    let t = tables.get(name);
    if (!t) { t = { name, file, line, rls_enabled: null, columns: [], policies: [], grants: [] }; tables.set(name, t); }
    return t;
  };
  for (const file of files) {
    for (const st of sqlStatements(repo.ctx.text(file))) {
      const s = st.text;
      let m: RegExpExecArray | null;
      if ((m = new RegExp(String.raw`^create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${QNAME}`, 'i').exec(s))) {
        const name = unq(m[1]);
        const t = get(name, file, st.line);
        t.file = file; t.line = st.line; t.policies = []; t.grants = []; t.rls_enabled = null;
        const body = parenBody(s, m[0].length) ?? '';
        t.columns = splitTop(body).map((c) => c.trim()).filter((c) => c && !/^(?:primary\s+key|foreign\s+key|unique|constraint|check|like|exclude)\b/i.test(c)).map((c) => unq(/^(?:"[^"]+"|[A-Za-z_][\w$]*)/.exec(c)?.[0] ?? '')).filter(Boolean).sort();
      } else if ((m = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QNAME}\s+(enable|disable|force|no\s+force)\s+row\s+level\s+security`, 'i').exec(s))) {
        const t = get(unq(m[1]), file, st.line);
        const w = m[2].toLowerCase();
        if (w === 'enable') t.rls_enabled = true; else if (w === 'disable') t.rls_enabled = false;
      } else if ((m = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QNAME}\s+add\s+column\s+(?:if\s+not\s+exists\s+)?(${IDENT})`, 'i').exec(s))) {
        const t = get(unq(m[1]), file, st.line);
        t.columns = [...new Set([...t.columns, unq(m[2])])].sort();
      } else if ((m = new RegExp(String.raw`^create\s+policy\s+(${IDENT}|'[^']*')\s+on\s+${QNAME}`, 'i').exec(s))) {
        const t = get(unq(m[2]), file, st.line);
        const rest = s.slice(m[0].length);
        const op = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1]?.toLowerCase() ?? 'all';
        const rolesText = /\bto\s+([\w",\s]+?)(?=\s+(?:using|with)\b|$)/i.exec(rest)?.[1] ?? 'public';
        const roles = rolesText.split(',').map((r) => r.trim().replace(/"/g, '').toLowerCase()).filter(Boolean);
        const u = /\busing\s*\(/i.exec(rest);
        const c = /\bwith\s+check\s*\(/i.exec(rest);
        t.policies.push({
          name: m[1].replace(/["']/g, ''), op, roles: roles.sort(), using: u ? (parenBody(rest, u.index) ?? '').replace(/\s+/g, ' ').trim() : null,
          check: c ? (parenBody(rest, c.index) ?? '').replace(/\s+/g, ' ').trim() : null, line: st.line, permissive: !/\bas\s+restrictive\b/i.test(rest),
        });
      } else if ((m = new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?(${IDENT}|'[^']*')\s+on\s+${QNAME}`, 'i').exec(s))) {
        const t = tables.get(unq(m[2]));
        if (t) t.policies = t.policies.filter((p) => p.name !== m![1].replace(/["']/g, ''));
      } else if ((m = new RegExp(String.raw`^drop\s+table\s+(?:if\s+exists\s+)?${QNAME}`, 'i').exec(s))) {
        tables.delete(unq(m[1]));
      } else if ((m = /^grant\s+([\s\S]+?)\s+on\s+(?:table\s+)?([\s\S]+?)\s+to\s+([\s\S]+?)(?:\s+with\s+grant\s+option)?$/i.exec(s)) && !/^grant\s+\w+\s+to\s/i.test(s) && !/\bon\s+(?:function|sequence|schema|type|all\s+functions|all\s+sequences)/i.test(s)) {
        const all = /^all\s+tables\s+in\s+schema/i.test(m[2]);
        const targets = all ? ['*'] : splitTop(m[2]).map((x) => unq(x.trim().replace(/^table\s+/i, '')));
        const privs = splitTop(m[1]).map((p) => p.trim()).filter(Boolean).map((p) => {
          const pm = /^(all(?:\s+privileges)?|select|insert|update|delete|truncate|references|trigger)\s*(?:\(([^)]*)\))?$/i.exec(p);
          return pm ? { priv: pm[1].toLowerCase().replace(/\s+privileges/, ''), cols: pm[2] ? pm[2].split(',').map((c) => c.trim().replace(/"/g, '')).sort() : null } : null;
        }).filter((x): x is { priv: string; cols: string[] | null } => x !== null);
        const roles = splitTop(m[3]).map((r) => r.trim().replace(/"/g, '').toLowerCase());
        for (const tn of targets) {
          const t = get(tn, file, st.line);
          for (const role of roles) {
            for (const p of privs) t.grants.push({ role, privileges: [p.priv], columns: p.cols, line: st.line });
          }
        }
      } else if ((m = /^revoke\s+([\s\S]+?)\s+on\s+(?:table\s+)?([\s\S]+?)\s+from\s+([\s\S]+)$/i.exec(s))) {
        const targets = splitTop(m[2]).map((x) => unq(x.trim().replace(/^table\s+/i, '')));
        const roles = splitTop(m[3]).map((r) => r.trim().replace(/"/g, '').toLowerCase());
        const privs = splitTop(m[1]).map((p) => p.trim().toLowerCase().replace(/\s+privileges/, '').replace(/\s*\(.*\)/, ''));
        for (const tn of targets) {
          const t = tables.get(tn);
          if (!t) continue;
          t.grants = t.grants.filter((g) => !(roles.includes(g.role) && (privs.includes('all') || g.privileges.some((p) => privs.includes(p)))));
        }
      }
    }
  }
  // Default privileges and schema wide grants ("*") apply to every table.
  const star = tables.get('*');
  tables.delete('*');
  const list = [...tables.values()].filter((t) => t.name !== '').sort((a, b) => cmp(a.name, b.name));
  if (star) for (const t of list) t.grants = [...t.grants, ...star.grants.map((g) => ({ ...g }))];
  for (const t of list) {
    t.policies.sort((a, b) => a.line - b.line || cmp(a.name, b.name));
    t.grants.sort((a, b) => cmp(a.role, b.role) || cmp(a.privileges[0], b.privileges[0]) || a.line - b.line);
  }
  return { tables: list };
}

const OWNER_VAR = /uid|user_?id|owner|account|author|member|tenant/i;

export function firebaseMap(repo: Repo): { rules: FirebaseRule[] } | null {
  const files = repo.ctx.files.filter((f) => /(?:^|\/)[^/]*\.rules$|(?:^|\/)database\.rules\.json$|(?:^|\/)[^/]*\.rules\.json$/.test(f)).sort(cmp);
  if (!files.length) return null;
  const rules: FirebaseRule[] = [];
  for (const file of files) {
    const text = repo.ctx.text(file);
    if (/\.json$/.test(file)) { realtimeRules(file, text, rules); continue; }
    const service: FirebaseRule['service'] = /storage/i.test(file) || /service\s+firebase\.storage/.test(text) ? 'storage' : 'firestore';
    // Rules files have // and /* */ comments and paths with slashes, which the JavaScript masker would read as regular expressions.
    const masked = text.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));
    const lines = new Lines(text);
    const stack: { path: string; close: number }[] = [];
    const re = /\bmatch\s+((?:\/(?:\{[^}]*\}|[^\s{/])*)+)\s*\{|\ballow\s+([\w,\s]+?)\s*(?::\s*if\s+([^;]*?))?\s*;/g;
    for (let m = re.exec(masked); m; m = re.exec(masked)) {
      while (stack.length && m.index >= stack[stack.length - 1].close) stack.pop();
      if (m[1] !== undefined) {
        const open = m.index + m[0].length - 1;
        let depth = 0;
        let close = masked.length;
        for (let i = open; i < masked.length; i++) { if (masked[i] === '{') depth++; else if (masked[i] === '}') { depth--; if (depth === 0) { close = i; break; } } }
        stack.push({ path: m[1].trim(), close });
      } else {
        const ops = m[2].split(',').map((o) => o.trim()).filter(Boolean).sort();
        const cond = (text.slice(m.index, m.index + m[0].length).replace(/^allow\s+[\w,\s]+?\s*(?::\s*if\s+)?/, '').replace(/;$/, '')).replace(/\s+/g, ' ').trim();
        const fullPath = stack.map((s) => s.path).join('').replace(/\/+/g, '/');
        const wild = [...fullPath.matchAll(/\{(\w+)(?:=\*\*)?\}/g)].map((x) => x[1]);
        const uidWild = wild.filter((w) => OWNER_VAR.test(w));
        const ownerBound = new RegExp(`request\\.auth\\.uid\\s*==\\s*(?:${wild.join('|') || '@@'})\\b|\\b(?:${wild.join('|') || '@@'})\\s*==\\s*request\\.auth\\.uid|resource(?:\\.data)?\\.\\w+\\s*==\\s*request\\.auth\\.uid|request\\.resource\\.data\\.\\w+\\s*==\\s*request\\.auth\\.uid|request\\.auth\\.uid\\s+in\\s|\\b(?:isOwner|owns|isUser|isOwnerOf|belongsToUser)\\s*\\(`).test(cond)
          || (/\b[a-z]\w*\s*\(/i.test(cond) && !/request\.auth\s*!=\s*null|request\.auth\s*==\s*null/.test(cond) && /owner|isUser|uid/i.test(cond));
        const open = cond === '' || /^true$/.test(cond) || /^request\.time\s*<\s*timestamp\.date\(/.test(cond);
        rules.push({ service, file, line: lines.at(m.index), path: fullPath || '/', ops, condition: cond.slice(0, 200), uses_auth: /request\.auth/.test(cond), owner_bound: ownerBound, always_true: open, owner_wildcard: uidWild.length > 0 });
      }
    }
  }
  return { rules: rules.sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.ops.join(), b.ops.join())) };
}

function realtimeRules(file: string, text: string, out: FirebaseRule[]): void {
  let json: unknown;
  try { json = JSON.parse(text); } catch { return; }
  const lines = new Lines(text);
  let cursor = 0;
  const walkNode = (node: unknown, path: string[]): void => {
    if (!node || typeof node !== 'object') return;
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if ((k === '.read' || k === '.write') && (typeof v === 'string' || typeof v === 'boolean')) {
        const cond = String(v);
        const at = text.indexOf(`"${k}"`, cursor);
        if (at >= 0) cursor = at + 1;
        const wild = path.filter((p) => p.startsWith('$'));
        const ownerBound = /\$\w+\s*===?\s*auth\.uid|auth\.uid\s*===?\s*\$\w+|\.val\(\)\s*===?\s*auth\.uid|auth\.uid\s*===?\s*(?:data|newData)/.test(cond);
        out.push({ service: 'realtime', file, line: at >= 0 ? lines.at(at) : 1, path: '/' + path.join('/'), ops: [k.slice(1)], condition: cond.slice(0, 200), uses_auth: /\bauth\b/.test(cond), owner_bound: ownerBound, always_true: cond.trim() === 'true', owner_wildcard: wild.some((w) => OWNER_VAR.test(w)) });
      } else if (!k.startsWith('.')) walkNode(v, [...path, k]);
    }
  };
  walkNode((json as { rules?: unknown }).rules, []);
}
