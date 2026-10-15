// Rust (Phase 6f). Level L1 reads Cargo.toml into the code map: dependencies by source (registry, git, path), the release profile, the
// unsafe code lint, the edition, and whether a Cargo.lock is committed. Level L2 reads the routes of axum (Router::new() chains with
// route, nest, merge, layer and route_layer, followed in order) and actix web (the #[get] family of attribute macros), with what protects
// each one: layers whose function names a sign in or a role check, and extractor types in the handler signature. HANDLER BODIES ARE NOT
// READ: no data store, outbound call or input is recorded for a Rust handler, so the checks that need those facts stay silent for Rust.
// A signature check is looked for in the handler text only.
import type { CargoConfig, CargoDependency, CargoManifest, Protection, Scope } from '../types/index.ts';
import type { FileView } from './analyze.ts';
import { empty, joinPath, makeEntry, type Extracted } from './entry.ts';
import { closeOf, splitArgs } from './lex.ts';
import type { Repo } from './repo.ts';

// ---- Cargo.toml ----------------------------------------------------------------------------------------------------------------------
export function readCargo(file: string, text: string, hasLock: boolean, binary: boolean): CargoManifest {
  const lines = text.split('\n');
  const m: CargoManifest = { file, line: 1, name: null, edition: null, dependencies: [], release_debug: null, release_overflow_checks: null, unsafe_code_lint: null, has_lock: hasLock, binary };
  let section = '';
  let pending: { name: string; line: number; text: string; depth: number } | null = null;
  const addDep = (name: string, body: string, line: number): void => {
    const t = body.trim();
    let source: CargoDependency['source'] = 'registry';
    let version: string | null = null;
    if (t.startsWith('{')) {
      if (/\bgit\s*=/.test(t)) source = 'git'; else if (/\bpath\s*=/.test(t)) source = 'path';
      version = /\bversion\s*=\s*"([^"]*)"/.exec(t)?.[1] ?? null;
    } else version = /^"([^"]*)"/.exec(t)?.[1] ?? null;
    m.dependencies.push({ name, source, version, line });
  };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].replace(/(^|\s)#.*$/, '').trimEnd();
    const line = i + 1;
    if (pending) {
      pending.text += ' ' + raw.trim();
      pending.depth += (raw.match(/\{/g) ?? []).length - (raw.match(/\}/g) ?? []).length;
      if (pending.depth <= 0) { addDep(pending.name, pending.text, pending.line); pending = null; }
      continue;
    }
    const sec = /^\s*\[\[?([^\]]+)\]\]?\s*$/.exec(raw);
    if (sec) {
      section = sec[1].trim();
      const named = /^(?:workspace\.|target\.[^.]+\.)?(?:dependencies|build-dependencies)\.(.+)$/.exec(section);
      if (named) m.dependencies.push({ name: named[1], source: 'registry', version: null, line });
      continue;
    }
    const kv = /^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(raw);
    if (!kv) continue;
    if (section === 'package') { if (kv[1] === 'name') m.name = /"([^"]*)"/.exec(kv[2])?.[1] ?? null; if (kv[1] === 'edition') m.edition = /"([^"]*)"/.exec(kv[2])?.[1] ?? null; if (kv[1] === 'name') m.line = line; }
    else if (/^(?:workspace\.|target\.[^.]+\.)?(?:dependencies|build-dependencies)$/.test(section)) {
      const depth = (kv[2].match(/\{/g) ?? []).length - (kv[2].match(/\}/g) ?? []).length;
      if (depth > 0) pending = { name: kv[1], line, text: kv[2], depth }; else addDep(kv[1], kv[2], line);
    } else if (/^dependencies\./.test(section) || /^(?:workspace\.|target\.[^.]+\.)?(?:dependencies|build-dependencies)\.[^.]+$/.test(section)) {
      const dep = m.dependencies[m.dependencies.length - 1];
      if (dep && kv[1] === 'git') dep.source = 'git';
      else if (dep && kv[1] === 'path' && dep.source === 'registry') dep.source = 'path';
      else if (dep && kv[1] === 'version') dep.version = /"([^"]*)"/.exec(kv[2])?.[1] ?? null;
    } else if (section === 'profile.release') {
      if (kv[1] === 'debug') m.release_debug = /^(true|2|1|"full"|"limited")/.test(kv[2].trim()) ? true : /^(false|0)/.test(kv[2].trim()) ? false : null;
      if (kv[1] === 'overflow-checks') m.release_overflow_checks = /^true/.test(kv[2].trim()) ? true : /^false/.test(kv[2].trim()) ? false : null;
    } else if (section === 'lints.rust' || section === 'workspace.lints.rust') {
      if (kv[1] === 'unsafe_code') m.unsafe_code_lint = /"([^"]*)"/.exec(kv[2])?.[1] ?? /level\s*=\s*"([^"]*)"/.exec(kv[2])?.[1] ?? null;
    }
  }
  m.dependencies.sort((a, b) => a.line - b.line || (a.name < b.name ? -1 : 1));
  return m;
}

export function cargoConfig(repo: Repo): CargoConfig | null {
  const manifests = repo.ctx.files.filter((f) => /(?:^|\/)Cargo\.toml$/.test(f) && !/(?:^|\/)(?:target|node_modules|vendor)\//.test(f));
  if (!manifests.length) return null;
  const set = new Set(repo.ctx.files);
  return {
    manifests: manifests.map((f) => {
      const dir = f.includes('/') ? f.slice(0, f.lastIndexOf('/')) : '';
      const up = (name: string): boolean => { for (let d = dir; ; d = d.includes('/') ? d.slice(0, d.lastIndexOf('/')) : '') { if (set.has(d ? `${d}/${name}` : name)) return true; if (!d) return false; } };
      const text = repo.ctx.text(f);
      const binary = set.has(dir ? `${dir}/src/main.rs` : 'src/main.rs') || /^\s*\[\[bin\]\]/m.test(text);
      return readCargo(f, text, up('Cargo.lock'), binary);
    }),
  };
}

// ---- routes ---------------------------------------------------------------------------------------------------------------------------
interface FnDef { view: FileView; name: string; start: number; end: number; paramsText: string; bodyStart: number }
const AUTH_TYPE = /\b(?:AuthUser|CurrentUser|AuthenticatedUser|Authenticated|SessionUser|LoggedIn|UserClaims|Claims|Identity|BearerAuth|AuthBearer|Jwt|JwtClaims|Principal)\b|TypedHeader\s*<\s*Authorization|\bBearerAuth\b|\bUser\s*\(/;
const ADMIN_TYPE = /\b(?:AdminUser|Admin|RequireAdmin|StaffUser|SuperUser|OwnerUser)\b/;
const AUTH_NAME = /auth|login|session|jwt|token|bearer|identity|credential/i;
const ROLE_NAME = /admin|role|permission|staff|owner|authorize|superuser/i;
const SIGNATURE = /\b(?:verify_signature|verify_webhook|verify_slice|constant_time_eq|Webhook::construct_event|construct_event|validate_signature|verify_hmac|hmac_sha256_verify)\b|\bHmac\s*::\s*<|\bMac\s*::\s*verify/;
const RATE = /\bGovernorLayer\b|\bRateLimitLayer\b|\btower_governor\b|\bRateLimiter\b/;

function fnDefs(repo: Repo): Map<string, FnDef[]> {
  const out = new Map<string, FnDef[]>();
  for (const f of repo.filesOf('rs')) {
    const v = repo.view(f);
    if (!v) continue;
    const m = v.masked;
    for (const x of m.matchAll(/(?:^|\n)[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*(?:<[^>\n]*>)?\s*\(/g)) {
      const open = x.index! + x[0].length - 1;
      const pc = closeOf(m, open);
      if (pc < 0) continue;
      let j = pc;
      while (j < m.length && m[j] !== '{' && m[j] !== ';') j++;
      if (m[j] !== '{') continue;
      const e = closeOf(m, j);
      if (e < 0) continue;
      const def: FnDef = { view: v, name: x[1], start: x.index! + x[0].indexOf('fn'), end: e, paramsText: v.text.slice(open + 1, pc - 1), bodyStart: j };
      out.set(x[1], [...(out.get(x[1]) ?? []), def]);
    }
  }
  return out;
}

// What a layer or middleware function says, from its name and, when the function is in the project, what its body answers.
function layerProtections(defs: Map<string, FnDef[]>, view: FileView, at: number, expr: string): Protection[] {
  const out: Protection[] = [];
  const names = [...expr.matchAll(/\b(?:from_fn(?:_with_state)?|map_request|from_extractor|from_extractor_with_state)\s*(?:::\s*<[^>]*>)?\s*\(\s*(?:[^,()]*,\s*)?([A-Za-z_][\w:]*)/g)].map((x) => x[1].split('::').pop()!);
  const consts = [...expr.matchAll(/\b(\w*(?:Auth|Bearer|Jwt|Session)\w*Layer)\b/g)].map((x) => x[1]);
  const line = view.lines.at(at);
  const push = (kind: Protection['kind'], via: string, enforced: boolean | null, confidence: Protection['confidence']): void => { out.push({ kind, scope: 'middleware' as Scope, file: view.file, line, via, enforced, confidence }); };
  for (const n of [...names, ...consts]) {
    const d = defs.get(n)?.[0];
    const body = d ? d.view.text.slice(d.bodyStart, d.end) : '';
    const rejects = /StatusCode::(?:UNAUTHORIZED|FORBIDDEN)|Err\s*\(/.test(body);
    if (ROLE_NAME.test(n)) { push('role_check', `layer ${n}`, d ? (rejects ? true : null) : null, d && rejects ? 'high' : 'medium'); if (AUTH_NAME.test(n)) push('session_read', `layer ${n}`, d ? (rejects ? true : null) : null, d && rejects ? 'high' : 'medium'); }
    else if (AUTH_NAME.test(n)) push('session_read', `layer ${n}`, d ? (rejects ? true : null) : null, d && rejects ? 'high' : 'medium');
  }
  if (RATE.test(expr)) push('rate_limit', 'rate limit layer', null, 'medium');
  return out;
}

const handlerProtections = (d: FnDef | undefined, name: string): Protection[] => {
  if (!d) return [];
  const out: Protection[] = [];
  const line = d.view.lines.at(d.start);
  const p = d.paramsText;
  if (ADMIN_TYPE.test(p)) { out.push({ kind: 'role_check', scope: 'handler', file: d.view.file, line, via: `extractor ${ADMIN_TYPE.exec(p)![0]}`, enforced: true, confidence: 'medium' }); out.push({ kind: 'session_read', scope: 'handler', file: d.view.file, line, via: `extractor ${ADMIN_TYPE.exec(p)![0]}`, enforced: true, confidence: 'medium' }); }
  else if (AUTH_TYPE.test(p)) out.push({ kind: 'session_read', scope: 'handler', file: d.view.file, line, via: `extractor ${AUTH_TYPE.exec(p)![0].trim()}`, enforced: true, confidence: 'medium' });
  const body = d.view.text.slice(d.bodyStart, d.end);
  if (SIGNATURE.test(body)) out.push({ kind: 'signature_verify', scope: 'handler', file: d.view.file, line: d.view.lines.at(d.bodyStart + (SIGNATURE.exec(body)?.index ?? 0)), via: SIGNATURE.exec(body)![0], enforced: /if\s+!|return\s+(?:Err|StatusCode::UNAUTHORIZED)|\?;/.test(body) ? true : null, confidence: 'high' });
  void name;
  return out;
};

interface Route { method: string; path: string; handler: string; view: FileView; at: number; prot: Protection[] }
interface Chain { view: FileView; calls: { name: string; open: number; close: number }[] }

function chainAt(v: FileView, from: number): Chain {
  const m = v.masked;
  const calls: Chain['calls'] = [];
  let i = from + 'Router::new()'.length;
  for (;;) {
    const mm = /^\s*\.\s*(\w+)\s*(?:::\s*<[^>]*>)?\s*\(/.exec(m.slice(i, i + 400));
    if (!mm) break;
    const open = i + mm[0].length - 1;
    const close = closeOf(m, open);
    if (close < 0) break;
    calls.push({ name: mm[1], open, close });
    i = close;
  }
  return { view: v, calls };
}

export function rustFiles(repo: Repo): string[] {
  return repo.filesOf('rs').filter((f) => { const v = repo.view(f); return !!v && (/\bRouter\s*::\s*new\s*\(/.test(v.masked) || /#\s*\[\s*(?:get|post|put|delete|patch)\s*\(/.test(v.text)); });
}

export function extractRust(repo: Repo): Extracted {
  const out = empty();
  const defs = fnDefs(repo);
  const METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'any']);

  const handlerOf = (expr: string): { method: string; name: string; layers: string }[] => {
    // get(h).post(h2).layer(...) : the handler of each method, and the text of layers placed on the method router
    const res: { method: string; name: string; layers: string }[] = [];
    let layers = '';
    for (const x of expr.matchAll(/(?:^|\.|\b)(get|post|put|delete|patch|head|options|any|on|layer|route_layer)\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)/g)) {
      if (x[1] === 'layer' || x[1] === 'route_layer') { layers += ' ' + x[2]; continue; }
      if (!METHODS.has(x[1])) continue;
      const nm = /([A-Za-z_][\w:]*)\s*$/.exec(x[2].trim().replace(/\)\s*$/, ''))?.[1]?.split('::').pop();
      if (nm) res.push({ method: x[1].toUpperCase(), name: nm, layers: '' });
    }
    return res.map((r) => ({ ...r, layers }));
  };

  const build = (ch: Chain, vars: Map<string, Chain>, depth: number): Route[] => {
    let routes: Route[] = [];
    const v = ch.view;
    for (const c of ch.calls) {
      const args = splitArgs(v.masked, c.open);
      const txt = (k: number): string => (args[k] ? v.text.slice(args[k].start, args[k].end) : '');
      if (c.name === 'route' && args.length >= 2) {
        const path = /"([^"]*)"/.exec(txt(0))?.[1];
        if (path === undefined) continue;
        for (const h of handlerOf(txt(1))) routes.push({ method: h.method, path, handler: h.name, view: v, at: c.open, prot: h.layers ? layerProtections(defs, v, c.open, h.layers) : [] });
      } else if ((c.name === 'nest' || c.name === 'merge') && depth < 6) {
        const prefix = c.name === 'nest' ? /"([^"]*)"/.exec(txt(0))?.[1] ?? '' : '';
        const target = c.name === 'nest' ? txt(1).trim() : txt(0).trim();
        let sub: Chain | null = null;
        const inl = /Router\s*::\s*new\s*\(\s*\)/.exec(target);
        if (inl) { const start = args[c.name === 'nest' ? 1 : 0].start + inl.index; sub = chainAt(v, start); }
        else if (/^\w+$/.test(target)) sub = vars.get(target) ?? null;
        if (!sub) continue;
        for (const r of build(sub, vars, depth + 1)) routes.push({ ...r, path: prefix ? joinPath(prefix, r.path) : r.path });
      } else if (c.name === 'layer' || c.name === 'route_layer') {
        const ps = layerProtections(defs, v, c.open, txt(0));
        if (ps.length) routes = routes.map((r) => ({ ...r, prot: [...r.prot, ...ps] }));
      }
    }
    return routes;
  };

  for (const file of rustFiles(repo)) {
    const v = repo.view(file);
    if (!v) continue;
    const m = v.masked;
    // axum: chains, with `let name = Router::new()...;` variables resolved by name within the file
    const vars = new Map<string, Chain>();
    const chains: { name: string | null; chain: Chain }[] = [];
    for (const x of m.matchAll(/\bRouter\s*::\s*new\s*\(\s*\)/g)) {
      const before = m.slice(Math.max(0, x.index! - 120), x.index!);
      const prevCall = /\.\s*(?:nest|merge)\s*\(\s*(?:"[^"]*"\s*,\s*)?$/.test(before);
      if (prevCall) continue;
      const nm = /\blet\s+(?:mut\s+)?(\w+)(?:\s*:\s*[\w<>:, ]+)?\s*=\s*$/.exec(before)?.[1] ?? null;
      const ch = chainAt(v, x.index!);
      if (nm) vars.set(nm, ch);
      chains.push({ name: nm, chain: ch });
    }
    // Roots: chains that no other chain nests or merges by name.
    const used = new Set<string>();
    for (const { chain } of chains) for (const c of chain.calls) if (c.name === 'nest' || c.name === 'merge') { const t = splitArgs(v.masked, c.open).map((a) => v.text.slice(a.start, a.end).trim()); for (const a of t) if (/^\w+$/.test(a)) used.add(a); }
    const seen = new Set<string>();
    for (const { name, chain } of chains) {
      if (name && used.has(name)) continue;
      for (const r of build(chain, vars, 0)) {
        const key = `${r.method} ${r.path} ${r.handler} ${r.at}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const d = (defs.get(r.handler) ?? []).find((x) => x.view.file === file) ?? defs.get(r.handler)?.[0];
        const prot = [...r.prot, ...handlerProtections(d, r.handler)];
        const analysis = { protections: prot, reads: [], data: [], outbound: [], taint: { names: new Set<string>(), validated: new Set<string>(), trusted: new Set<string>() } };
        const hv = d?.view ?? v;
        out.entries.push(makeEntry(repo, {
          kind: 'http_route', framework: 'axum', file, line: v.lines.at(r.at), method: r.method, path: r.path === '' ? '/' : joinPath('', r.path), name: r.handler,
          confidence: d ? 'high' : 'medium', handlerView: hv, spec: { start: d?.start ?? r.at, end: d?.end ?? r.at, seeds: [] }, analysis,
        }));
      }
    }
    // actix web: #[get("/x")] above an async fn
    for (const x of v.text.matchAll(/#\s*\[\s*(get|post|put|delete|patch|head)\s*\(\s*"([^"]*)"[^\]]*\]\s*(?:\n\s*#\s*\[[^\]]*\]\s*)*\n?\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)/g)) {
      const d = (defs.get(x[3]) ?? []).find((y) => y.view.file === file);
      const analysis = { protections: handlerProtections(d, x[3]), reads: [], data: [], outbound: [], taint: { names: new Set<string>(), validated: new Set<string>(), trusted: new Set<string>() } };
      out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'actix-web', file, line: v.lines.at(x.index!), method: x[1].toUpperCase(), path: joinPath('', x[2]), name: x[3], confidence: 'medium', handlerView: v, spec: { start: d?.start ?? x.index!, end: d?.end ?? x.index!, seeds: [] }, analysis }));
    }
  }
  return out;
}
