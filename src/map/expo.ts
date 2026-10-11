// Expo and React Native entry points: Expo Router screens (the app/ folder), API routes (+api files), deep links declared
// in app.json or app.config (scheme, universal links, Android intent filters) and deep links handled in code (Linking
// listeners, useURL, a navigation linking config). The protections of a screen are the sign in guards in the layouts above
// it. A layout guard is a client side redirect: it keeps a signed out user from seeing a screen, it does not stop a request
// to your server, so a screen's own data calls still need a server side check (the report says "client side" in `via`).
import type { EntryPoint, Protection } from '../types/index.ts';
import { testCodeReason } from '../report/test-code.ts';
import type { FileView } from './analyze.ts';
import { empty, makeEntry, normPath, type Extracted } from './entry.ts';
import { splitArgs } from './lex.ts';
import { exportedFunctions, resolveFunction } from './js-next.ts';
import type { Repo } from './repo.ts';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const SOURCE_EXT = /\.[cm]?[jt]sx?$/;
// Session reads in mobile code: auth hooks and contexts, provider SDK calls, secure storage of a token.
const EXPO_SESSION: { re: RegExp; via: string; conf: 'high' | 'medium' }[] = [
  { re: /\b(?:useAuth|isSignedIn|useSession|useUser|useAuthContext|useAuthState|useSupabaseSession|useConvexAuth|useKindeAuth|useAuth0)\b/, via: 'auth hook', conf: 'medium' },
  { re: /\bsupabase\.auth\.(?:getSession|getUser|onAuthStateChange)\b|\bonAuthStateChanged\s*\(|\bgetAuth\s*\(|\bfirebase\.auth\(\)|\bauth\(\)\.currentUser|\bClerkProvider\b|\bSignedIn\b|\bSignedOut\b/, via: 'auth provider', conf: 'high' },
  { re: /\b(?:SecureStore|AsyncStorage|storage)\.(?:getItem|getItemAsync|get|getString)\s*\(\s*['"][\w.-]*(?:token|session|jwt|auth)[\w.-]*['"]/i, via: 'stored token', conf: 'medium' },
  { re: /\b(?:isAuthenticated|isLoggedIn|isAuthed|signedIn|loggedIn)\b/, via: 'signed in flag', conf: 'medium' },
];
const GUARD_REDIRECT = /<Redirect\b[^>]*\bhref\b|\brouter\.(?:replace|push|navigate)\s*\(|\bnavigation\.(?:replace|navigate|reset)\s*\(|\bProtected\b[^>]*\bguard\s*=|\bredirect\s*\(/;
const GUARD_CONDITION = /\bif\s*\(\s*!\s*\(?\s*\w*(?:session|user|token|signedIn|isSignedIn|isAuthenticated|isLoggedIn|authenticated|auth)\w*|\bguard\s*=\s*\{|[?&]{2}\s*<Redirect|:\s*<Redirect/i;
const PUBLIC_GROUP = /\((?:auth|public|login|sign-?in|sign-?up|onboarding|welcome|landing|guest|unauth\w*)\)/i;

function roots(repo: Repo): string[] {
  const out: string[] = [];
  for (const f of repo.ctx.files) {
    if (!/(?:^|\/)package\.json$/.test(f) || /node_modules\//.test(f)) continue;
    if (/"expo-router"|"expo"\s*:/.test(repo.ctx.text(f))) out.push(f.replace(/package\.json$/, ''));
  }
  return out.sort();
}

const routePath = (rel: string): string => {
  const segs = rel.replace(SOURCE_EXT, '').split('/').filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith('@'));
  if (segs[segs.length - 1] === 'index') segs.pop();
  return normPath('/' + segs.join('/').replace(/\[\.\.\.(\w+)\]/g, '*$1').replace(/\[(\w+)\]/g, ':$1'));
};

function layoutGuard(v: FileView): { line: number; enforced: boolean | null } | null {
  const session = EXPO_SESSION.some((s) => s.re.test(v.masked));
  const redirect = GUARD_REDIRECT.exec(v.masked);
  if (!session || !redirect) return null;
  const cond = GUARD_CONDITION.test(v.masked);
  if (!cond && !/\bProtected\b/.test(v.masked)) return null;
  return { line: v.lines.at(redirect.index), enforced: cond ? true : null };
}

export function extractExpo(repo: Repo): Extracted {
  const out = empty();
  for (const root of roots(repo)) {
    const appDir = [`${root}app/`, `${root}src/app/`].find((d) => repo.ctx.files.some((f) => f.startsWith(d)));
    const files = repo.ctx.files.filter((f) => f.startsWith(root) && !/node_modules\//.test(f) && SOURCE_EXT.test(f) && !/\.d\.ts$/.test(f));
    if (appDir) {
      // Layout guards, by directory.
      const guards: { dir: string; file: string; fact: { line: number; enforced: boolean | null }; text: string }[] = [];
      for (const f of files) {
        if (!f.startsWith(appDir) || !/(?:^|\/)_layout\.[cm]?[jt]sx?$/.test(f)) continue;
        const v = repo.view(f);
        const g = v ? layoutGuard(v) : null;
        if (v && g) guards.push({ dir: f.slice(0, f.lastIndexOf('/') + 1), file: f, fact: g, text: v.masked });
      }
      for (const f of files) {
        if (!f.startsWith(appDir)) continue;
        const rel = f.slice(appDir.length);
        const base = rel.split('/').pop()!;
        if (/^_layout\./.test(base) || /^\+(?:html|not-found|native-intent)\./.test(base)) continue;
        const v = repo.view(f);
        if (!v) continue;
        if (/\+api\.[cm]?[jt]sx?$/.test(f)) {
          const path = routePath(rel.replace(/\+api(\.[cm]?[jt]sx?)$/, '$1'));
          for (const e of exportedFunctions(repo, v)) {
            if (!METHODS.includes(e.exportName)) continue;
            const r = e.r;
            const seeds = [...(r.params.length ? r.params : ['request', 'req']), 'params'];
            out.entries.push(makeEntry(repo, { kind: 'http_route', framework: 'expo-api', file: f, line: e.line, method: e.exportName, path, name: e.exportName, confidence: 'high', handlerView: r.view, spec: { start: r.start, end: r.end, seeds, decorators: r.wrapper ? [{ view: v, start: r.wrapper.from, end: r.wrapper.to, scope: 'wrapper' }] : [], extraCalls: r.wrapper ? [r.wrapper.name] : [], returnsJson: true } }));
          }
          continue;
        }
        // A screen: the file under app/ with a default export that is not a layout.
        if (!/\bexport\s+default\b/.test(v.masked)) continue;
        const path = routePath(rel);
        const seeds = ['params', 'searchParams'];
        for (const m of v.masked.matchAll(/\b(?:const|let)\s+(\{[^}]*\}|\w+)\s*=\s*use(?:Local|Global)?SearchParams\b/g)) seeds.push(...[...m[1].matchAll(/\w+/g)].map((x) => x[0]));
        const dm = /\bexport\s+default\s+(?:async\s+)?function\s+(\w+)/.exec(v.masked);
        const ep = makeEntry(repo, { kind: 'page', framework: 'expo-router', file: f, line: v.lines.at(dm?.index ?? v.masked.search(/\bexport\s+default\b/)), method: null, path, name: dm?.[1] ?? null, confidence: 'high', handlerView: v, spec: { start: 0, end: v.text.length, seeds, returnsJson: false }, tags: ['mobile_screen'] });
        const extra: Protection[] = [];
        for (const s of EXPO_SESSION) {
          const m = s.re.exec(v.masked);
          if (m) { extra.push({ kind: 'session_read', scope: 'handler', file: f, line: v.lines.at(m.index), via: s.via, enforced: null, confidence: s.conf === 'high' ? 'medium' : 'medium' }); break; }
        }
        const publicGroup = PUBLIC_GROUP.test(f.slice(appDir.length));
        for (const g of guards) {
          if (!f.startsWith(g.dir) || publicGroup) continue;
          extra.push({ kind: 'session_read', scope: 'router', file: g.file, line: g.fact.line, via: 'expo layout guard (client side)', enforced: g.fact.enforced, confidence: 'medium' });
        }
        if (extra.length) {
          ep.protections = [...ep.protections, ...extra].sort((a, b) => a.line - b.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.via < b.via ? -1 : 1));
          if (guards.some((g) => f.startsWith(g.dir)) && !publicGroup) ep.tags = [...new Set([...ep.tags, 'guarded'])].sort();
        }
        if (publicGroup) ep.tags = [...new Set([...ep.tags, 'public'])].sort();
        out.entries.push(ep);
      }
    }

    // Deep links declared in the app config.
    for (const cfg of [`${root}app.json`, `${root}app.config.json`]) {
      const text = repo.ctx.text(cfg);
      if (!text) continue;
      let json: { expo?: Record<string, unknown> } | null = null;
      try { json = JSON.parse(text) as { expo?: Record<string, unknown> }; } catch { json = null; }
      const expo = (json?.expo ?? json ?? {}) as Record<string, unknown>;
      const lineOf = (needle: string): number => { const i = text.indexOf(needle); return i < 0 ? 1 : text.slice(0, i).split('\n').length; };
      const add = (path: string, name: string, needle: string, tags: string[]): void => {
        const line = lineOf(needle);
        out.entries.push(deepLink(cfg, line, path, name, 'high', tags));
      };
      const scheme = expo.scheme;
      for (const s of Array.isArray(scheme) ? scheme : scheme ? [scheme] : []) if (typeof s === 'string') add(`${s}://`, 'custom scheme', `"${s}"`, ['deep_link', 'custom_scheme']);
      const ios = (expo.ios ?? {}) as { associatedDomains?: unknown };
      for (const d of Array.isArray(ios.associatedDomains) ? ios.associatedDomains : []) if (typeof d === 'string' && d.startsWith('applinks:')) add(`https://${d.slice(9)}/`, 'universal link', `"${d}"`, ['deep_link', 'universal_link']);
      const android = (expo.android ?? {}) as { intentFilters?: { data?: { scheme?: string; host?: string; pathPrefix?: string }[]; autoVerify?: boolean }[] };
      for (const f of android.intentFilters ?? []) for (const d of f.data ?? []) if (d.scheme) add(`${d.scheme}://${d.host ?? ''}${d.pathPrefix ?? ''}`, f.autoVerify ? 'android app link' : 'android intent filter', `"${d.host ?? d.scheme}"`, ['deep_link', ...(f.autoVerify ? ['universal_link'] : ['custom_scheme'])]);
    }
    for (const cfg of [`${root}app.config.js`, `${root}app.config.ts`]) {
      const text = repo.ctx.text(cfg);
      if (!text) continue;
      for (const m of text.matchAll(/\bscheme\s*:\s*['"]([\w+.-]+)['"]/g)) out.entries.push(deepLink(cfg, text.slice(0, m.index).split('\n').length, `${m[1]}://`, 'custom scheme', 'high', ['deep_link', 'custom_scheme']));
    }

    // Deep links handled in code.
    for (const f of files) {
      const v = repo.view(f);
      if (!v || !/\bLinking\b|\buseURL\b|\bprefixes\s*:/.test(v.masked)) continue;
      for (const x of v.masked.matchAll(/\bLinking\.addEventListener\s*\(/g)) {
        const open = x.index! + x[0].length - 1;
        const args = splitArgs(v.masked, open);
        if (args.length < 2 || !/^['"]url['"]$/.test(v.text.slice(args[0].start, args[0].end).trim())) continue;
        const r = resolveFunction(repo, v, args[1].start, args[1].end);
        const spec = r ? { start: r.start, end: r.end, seeds: r.params.length ? r.params : ['event', 'url'], returnsJson: false } : { start: x.index!, end: args[args.length - 1].end, seeds: ['event', 'url'], returnsJson: false };
        out.entries.push(makeEntry(repo, { kind: 'deep_link', framework: 'react-native', file: f, line: v.lines.at(x.index!), method: null, path: null, name: 'Linking url listener', confidence: r ? 'high' : 'medium', handlerView: r?.view ?? v, spec, tags: ['deep_link'] }));
      }
      for (const x of v.masked.matchAll(/\b(?:Linking\.getInitialURL|useURL)\s*\(/g)) {
        const at = x.index!;
        const line = v.lines.at(at);
        const end = Math.min(v.text.length, v.lines.start(line + 12));
        out.entries.push(makeEntry(repo, { kind: 'deep_link', framework: 'react-native', file: f, line, method: null, path: null, name: x[0].replace(/\s*\($/, ''), confidence: 'medium', handlerView: v, spec: { start: at, end, seeds: ['url', 'initialUrl', 'event'], returnsJson: false }, tags: ['deep_link'] }));
      }
      for (const x of v.masked.matchAll(/\bprefixes\s*:\s*\[/g)) {
        const line = v.lines.at(x.index!);
        const prefixes = [...v.text.slice(x.index!, x.index! + 300).matchAll(/['"]([^'"]+:\/\/[^'"]*)['"]/g)].map((y) => y[1]);
        const end = Math.min(v.text.length, v.lines.start(line + 25));
        out.entries.push(makeEntry(repo, { kind: 'deep_link', framework: 'react-navigation', file: f, line, method: null, path: prefixes[0] ?? null, name: 'navigation linking config', confidence: 'medium', handlerView: v, spec: { start: x.index!, end, seeds: [], returnsJson: false }, tags: ['deep_link'] }));
      }
    }
  }
  return out;
}

function deepLink(file: string, line: number, path: string, name: string, confidence: EntryPoint['confidence'], tags: string[]): EntryPoint {
  return {
    id: `${file}:${line}:deep_link:-:${path}:${name}`, kind: 'deep_link', framework: 'expo', file, line, end_line: line, method: null, path, name, handler: null, confidence,
    test_code: testCodeReason(file) !== null, tags: [...tags].sort(), protections: [], reads: [{ source: 'params', line }], data: [], outbound: [],
  };
}

