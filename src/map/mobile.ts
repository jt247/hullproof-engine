// Native mobile configuration (Phase 6f): Android (Kotlin and Java apps) and iOS (Swift and Objective C apps). Level L1 reads the
// configuration files into the code map: AndroidManifest.xml (components, exported flags, permissions, backup, debuggable and cleartext
// flags), the network security configuration, Info.plist (App Transport Security, URL schemes, usage descriptions) and the entitlements
// (associated domains). Level L2 turns what other apps and websites can reach into entry points: exported Android components and deep
// links, iOS URL schemes and universal links. The Kotlin and Swift source is NOT read here: what a handler does with an incoming intent
// or URL is not analysed. Pattern based, no XML parser; every fact has the file and line it came from.
import type { AndroidComponent, AndroidConfig, AndroidFilter, AndroidManifest, ConfigSecret, IosConfig, IosPlist, NetworkSecurity, Protection } from '../types/index.ts';
import type { FileView } from './analyze.ts';
import { empty, makeEntry, type Extracted } from './entry.ts';
import { Lines } from './lex.ts';
import type { Repo } from './repo.ts';

export interface MobileFacts { android: AndroidConfig | null; ios: IosConfig | null; secrets: ConfigSecret[] }

// Names that say a value is a secret. A key that is public by design (a maps key, a Firebase web key, an analytics id) is not one.
const SECRET_NAME = /(?:secret|private[_.\- ]?key|passw(?:or)?d|passwd|signing[_.\- ]?key|service[_.\- ]?role|auth[_.\- ]?token|access[_.\- ]?token|refresh[_.\- ]?token)/i;
const PUBLIC_NAME = /(?:public|publishable|client[_.\- ]?id|maps|geo|analytics|sentry[_.\- ]?dsn)/i;
const PLACEHOLDER = /^(?:@|\$\(|\$\{|%|<|your[_\- ]|changeme|change[_\- ]me|todo|xxx|null|none|true|false|\s*$)/i;
export const isSecretValue = (name: string, value: string): boolean => SECRET_NAME.test(name) && !PUBLIC_NAME.test(name) && value.length >= 8 && !PLACEHOLDER.test(value.trim());

const blankComments = (t: string): string => t.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' '));
const view = (file: string, text: string): FileView => ({ file, text, masked: text, lang: 'kt', lines: new Lines(text), imports: '' });
const bool = (v: string | undefined): boolean | null => (v === 'true' ? true : v === 'false' ? false : null);

interface Tok { name: string; close: boolean; self: boolean; attrs: Record<string, string>; at: number; end: number }
function tokens(text: string): Tok[] {
  const out: Tok[] = [];
  for (const m of text.matchAll(/<(\/?)([A-Za-z_][\w.:-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>/g)) {
    const attrs: Record<string, string> = {};
    for (const a of m[3].matchAll(/([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attrs[a[1]] = a[2] ?? a[3] ?? '';
    out.push({ name: m[2], close: m[1] === '/', self: m[4] === '/', attrs, at: m.index!, end: m.index! + m[0].length });
  }
  return out;
}

const COMPONENTS = new Set(['activity', 'activity-alias', 'service', 'receiver', 'provider']);

export function readManifest(file: string, text: string, gradleTarget: number | null): { manifest: AndroidManifest; secrets: ConfigSecret[]; bounds: Map<AndroidComponent, [number, number]> } {
  const clean = blankComments(text);
  const lines = new Lines(text);
  const toks = tokens(clean);
  const secrets: ConfigSecret[] = [];
  const bounds = new Map<AndroidComponent, [number, number]>();
  const pkg = toks.find((t) => t.name === 'manifest')?.attrs.package ?? null;
  const sdk = toks.find((t) => t.name === 'uses-sdk');
  const targetRaw = sdk?.attrs['android:targetSdkVersion'];
  const target = targetRaw && /^\d+$/.test(targetRaw) ? Number(targetRaw) : gradleTarget;
  const app = toks.find((t) => t.name === 'application' && !t.close);
  const manifest: AndroidManifest = {
    file, package: pkg, line: lines.at(app?.at ?? 0), debuggable: bool(app?.attrs['android:debuggable']), allow_backup: bool(app?.attrs['android:allowBackup']),
    uses_cleartext_traffic: bool(app?.attrs['android:usesCleartextTraffic']), network_security_config: app?.attrs['android:networkSecurityConfig'] ?? null,
    target_sdk: target, permissions: toks.filter((t) => t.name === 'uses-permission' && !t.close).map((t) => t.attrs['android:name']).filter(Boolean).sort(), components: [],
  };
  let cur: AndroidComponent | null = null;
  let curStart = 0;
  let filter: AndroidFilter | null = null;
  let hasFilter = false;
  const finish = (endAt: number): void => {
    if (!cur) return;
    // A component with an intent filter and no explicit flag is exported before Android 12 (target SDK 31).
    if (!cur.exported_explicit) cur.exported = hasFilter && (target === null || target < 31);
    bounds.set(cur, [curStart, endAt]);
    manifest.components.push(cur);
    cur = null;
  };
  for (const t of toks) {
    if (t.name === 'meta-data' && !t.close) {
      const n = t.attrs['android:name'] ?? '';
      const v = t.attrs['android:value'] ?? '';
      if (isSecretValue(n, v)) secrets.push({ file, line: lines.at(t.at), key: n, where: 'android manifest' });
      continue;
    }
    if (COMPONENTS.has(t.name)) {
      if (t.close) { finish(t.end); continue; }
      finish(t.at);
      const nm = t.attrs['android:name'] ?? '';
      const full = nm.startsWith('.') ? `${pkg ?? ''}${nm}` : nm.includes('.') ? nm : `${pkg ?? ''}.${nm}`;
      const perm = t.attrs['android:permission'] ?? t.attrs['android:readPermission'] ?? t.attrs['android:writePermission'] ?? null;
      const ex = t.attrs['android:exported'];
      cur = { kind: t.name === 'activity-alias' ? 'activity' : (t.name as AndroidComponent['kind']), name: full, line: lines.at(t.at), exported: ex === 'true', exported_explicit: ex !== undefined, permission: perm, launcher: false, filters: [] };
      curStart = t.at;
      hasFilter = false;
      if (t.self) finish(t.end);
      continue;
    }
    if (!cur) continue;
    if (t.name === 'intent-filter') { if (t.close) { if (filter) cur.filters.push(filter); filter = null; } else { filter = { actions: [], categories: [], schemes: [], hosts: [], paths: [] }; hasFilter = true; } continue; }
    if (!filter || t.close) continue;
    if (t.name === 'action') filter.actions.push(t.attrs['android:name'] ?? '');
    else if (t.name === 'category') filter.categories.push(t.attrs['android:name'] ?? '');
    else if (t.name === 'data') {
      const a = t.attrs;
      if (a['android:scheme']) filter.schemes.push(a['android:scheme']);
      if (a['android:host']) filter.hosts.push(a['android:host']);
      const p = a['android:path'] ?? a['android:pathPrefix'] ?? a['android:pathPattern'] ?? a['android:pathAdvancedPattern'];
      if (p) filter.paths.push(p);
    }
  }
  finish(clean.length);
  for (const c of manifest.components) c.launcher = c.filters.length > 0 && c.filters.every((f) => f.actions.every((a) => a === 'android.intent.action.MAIN') && f.categories.includes('android.intent.category.LAUNCHER'));
  for (const c of manifest.components) { c.filters.forEach((f) => { f.actions.sort(); f.categories.sort(); f.schemes.sort(); f.hosts.sort(); f.paths.sort(); }); }
  manifest.components.sort((a, b) => a.line - b.line || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { manifest, secrets, bounds };
}

export function readNetworkSecurity(file: string, text: string): NetworkSecurity {
  const clean = blankComments(text);
  const lines = new Lines(text);
  const toks = tokens(clean);
  const base = toks.find((t) => t.name === 'base-config' && !t.close);
  const domains: string[] = [];
  let pins = 0;
  let inDomainConfig: Tok | null = null;
  let userCerts = false;
  let cleartextDomains: string[] = [];
  const pending: string[] = [];
  for (const t of toks) {
    if (t.name === 'domain-config') {
      if (t.close) { if (inDomainConfig?.attrs.cleartextTrafficPermitted === 'true') cleartextDomains = cleartextDomains.concat(pending); pending.length = 0; inDomainConfig = null; } else { inDomainConfig = t; pending.length = 0; }
    } else if (t.name === 'domain' && !t.close && inDomainConfig) { const d = clean.slice(t.end, clean.indexOf('<', t.end)).trim(); if (d) { domains.push(d); pending.push(d); } }
    else if (t.name === 'pin' && !t.close) pins++;
    else if (t.name === 'certificates' && t.attrs.src === 'user') userCerts = true;
  }
  return { file, line: lines.at(base?.at ?? 0), cleartext_base: bool(base?.attrs.cleartextTrafficPermitted), cleartext_domains: cleartextDomains.sort(), trusts_user_certs: userCerts, pinned_domains: pins };
}

// ---- Info.plist and entitlements -------------------------------------------------------------------------------------------------
type PVal = string | boolean | number | PVal[] | { [k: string]: PVal };
interface PlistRead { value: { [k: string]: PVal }; keyLines: Map<string, number> }
function readPlist(text: string): PlistRead | null {
  const lines = new Lines(text);
  const toks = [...blankComments(text).matchAll(/<(\/?)(dict|array|key|string|integer|real|true|false|data|date)\b[^>]*?(\/?)>/g)];
  let i = 0;
  const keyLines = new Map<string, number>();
  const textAfter = (m: RegExpMatchArray): string => text.slice(m.index! + m[0].length, text.indexOf('<', m.index! + m[0].length));
  const value = (): PVal => {
    const t = toks[i++];
    if (!t) return '';
    if (t[2] === 'true') return true;
    if (t[2] === 'false') return false;
    if (t[2] === 'string' || t[2] === 'data' || t[2] === 'date') { const v = t[3] === '/' ? '' : textAfter(t); if (t[3] !== '/') i++; return v; }
    if (t[2] === 'integer' || t[2] === 'real') { const v = Number(textAfter(t)); i++; return v; }
    if (t[2] === 'array') { const a: PVal[] = []; while (i < toks.length && !(toks[i][1] === '/' && toks[i][2] === 'array')) a.push(value()); i++; return a; }
    if (t[2] === 'dict') {
      const d: { [k: string]: PVal } = {};
      while (i < toks.length && !(toks[i][1] === '/' && toks[i][2] === 'dict')) {
        const k = toks[i];
        if (k[2] !== 'key' || k[1] === '/') { i++; continue; }
        const name = textAfter(k);
        keyLines.set(name, lines.at(k.index!));
        i += 2;
        d[name] = value();
      }
      i++;
      return d;
    }
    return '';
  };
  const start = toks.findIndex((t) => t[2] === 'dict' && t[1] !== '/');
  if (start < 0) return null;
  i = start;
  const v = value();
  return typeof v === 'object' && !Array.isArray(v) ? { value: v, keyLines } : null;
}

const strList = (v: PVal | undefined): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

export function readPlistFile(file: string, text: string): { plist: IosPlist; secrets: ConfigSecret[]; urlSchemes: { scheme: string; line: number }[]; domains: { domain: string; line: number }[] } | null {
  const r = readPlist(text);
  if (!r) return null;
  const d = r.value;
  const ats = typeof d.NSAppTransportSecurity === 'object' && !Array.isArray(d.NSAppTransportSecurity) ? (d.NSAppTransportSecurity as { [k: string]: PVal }) : null;
  const secrets: ConfigSecret[] = [];
  for (const [k, v] of Object.entries(d)) if (typeof v === 'string' && isSecretValue(k, v)) secrets.push({ file, line: r.keyLines.get(k) ?? 1, key: k, where: 'ios plist' });
  const types = Array.isArray(d.CFBundleURLTypes) ? d.CFBundleURLTypes : [];
  const schemes = types.flatMap((t) => (typeof t === 'object' && !Array.isArray(t) ? strList((t as { [k: string]: PVal }).CFBundleURLSchemes) : []));
  const line = r.keyLines.get('CFBundleURLTypes') ?? 1;
  const assoc = strList(d['com.apple.developer.associated-domains']).filter((x) => x.startsWith('applinks:')).map((x) => x.slice('applinks:'.length).replace(/\?.*$/, ''));
  return {
    plist: {
      file, ats_arbitrary_loads: ats && typeof ats.NSAllowsArbitraryLoads === 'boolean' ? (ats.NSAllowsArbitraryLoads as boolean) : null, ats_line: r.keyLines.get('NSAllowsArbitraryLoads') ?? null,
      url_schemes: schemes.slice().sort(), associated_domains: assoc.slice().sort(), usage_descriptions: Object.keys(d).filter((k) => /UsageDescription$/.test(k)).sort(),
    },
    secrets, urlSchemes: schemes.map((scheme) => ({ scheme, line })), domains: assoc.map((domain) => ({ domain, line: r.keyLines.get('com.apple.developer.associated-domains') ?? 1 })),
  };
}

const SKIP = /(?:^|\/)(?:Pods|Carthage|\.build|DerivedData|node_modules|build|intermediates)\//;

export function mobileFiles(repo: Repo): { manifests: string[]; plists: string[]; netsec: string[]; strings: string[] } {
  const f = repo.ctx.files.filter((x) => !SKIP.test(x));
  return {
    manifests: f.filter((x) => /(?:^|\/)AndroidManifest\.xml$/.test(x) && !/\/build\//.test(x)),
    netsec: f.filter((x) => /(?:^|\/)res\/xml\/[\w-]*network_security_config\w*\.xml$/.test(x)),
    strings: f.filter((x) => /(?:^|\/)res\/values[\w-]*\/strings\.xml$/.test(x)),
    plists: f.filter((x) => /(?:^|\/)Info\.plist$|\.entitlements$/.test(x)),
  };
}

const gradleTarget = (repo: Repo): number | null => {
  for (const f of repo.ctx.files.filter((x) => /(?:^|\/)build\.gradle(?:\.kts)?$/.test(x))) {
    const m = /\btargetSdk(?:Version)?\s*[= ]\s*(\d+)/.exec(repo.ctx.text(f));
    if (m) return Number(m[1]);
  }
  return null;
};

export function mobileFacts(repo: Repo): MobileFacts {
  const files = mobileFiles(repo);
  const secrets: ConfigSecret[] = [];
  let android: AndroidConfig | null = null;
  if (files.manifests.length || files.netsec.length) {
    const target = gradleTarget(repo);
    android = { manifests: [], network_security: files.netsec.map((f) => readNetworkSecurity(f, repo.ctx.text(f))) };
    for (const f of files.manifests) { const r = readManifest(f, repo.ctx.text(f), target); android.manifests.push(r.manifest); secrets.push(...r.secrets); }
    for (const f of files.strings) {
      const t = repo.ctx.text(f);
      const lines = new Lines(t);
      for (const m of blankComments(t).matchAll(/<string\s+name="([^"]+)"[^>]*>([^<]*)<\/string>/g)) if (isSecretValue(m[1], m[2])) secrets.push({ file: f, line: lines.at(m.index!), key: m[1], where: 'android strings' });
    }
  }
  let ios: IosConfig | null = null;
  const plists = files.plists.map((f) => ({ f, r: readPlistFile(f, repo.ctx.text(f)) })).filter((x) => x.r !== null);
  if (plists.length) { ios = { plists: plists.map((x) => x.r!.plist) }; for (const x of plists) secrets.push(...x.r!.secrets); }
  const sorted = secrets.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || (a.key < b.key ? -1 : 1));
  return { android, ios, secrets: sorted };
}

// ---- entry points -----------------------------------------------------------------------------------------------------------------
export function extractMobile(repo: Repo): Extracted {
  const out = empty();
  const files = mobileFiles(repo);
  const target = gradleTarget(repo);
  for (const f of files.manifests) {
    const text = repo.ctx.text(f);
    const v = view(f, text);
    const { manifest, bounds } = readManifest(f, text, target);
    for (const c of manifest.components) {
      if (!c.exported || c.launcher) continue;
      const [s, e] = bounds.get(c) ?? [0, 0];
      const prot: Protection[] = c.permission ? [{ kind: 'role_check', scope: 'handler', file: f, line: c.line, via: `android:permission ${c.permission}`, enforced: true, confidence: 'high' }] : [];
      const analysis = { protections: prot, reads: [], data: [], outbound: [], taint: { names: new Set<string>(), validated: new Set<string>(), trusted: new Set<string>() } };
      const links = c.filters.filter((x) => x.actions.includes('android.intent.action.VIEW') && x.categories.includes('android.intent.category.BROWSABLE') && x.schemes.length);
      if (c.kind === 'activity' && links.length) {
        const names = new Set<string>();
        for (const fl of links) for (const sc of fl.schemes) for (const h of fl.hosts.length ? fl.hosts : ['']) for (const p of fl.paths.length ? fl.paths : ['']) names.add(`${sc}://${h}${p}`);
        for (const n of [...names].sort()) out.entries.push(makeEntry(repo, { kind: 'deep_link', framework: 'android', file: f, line: c.line, method: null, path: null, name: n, confidence: 'high', handlerView: v, spec: { start: s, end: e, seeds: [] }, analysis, tags: ['public'] }));
        continue;
      }
      out.entries.push(makeEntry(repo, { kind: 'ipc', framework: 'android', file: f, line: c.line, method: null, path: null, name: c.name, confidence: c.exported_explicit ? 'high' : 'medium', handlerView: v, spec: { start: s, end: e, seeds: [] }, analysis }));
    }
  }
  for (const f of files.plists) {
    const text = repo.ctx.text(f);
    const r = readPlistFile(f, text);
    if (!r) continue;
    const v = view(f, text);
    const analysis = { protections: [] as Protection[], reads: [], data: [], outbound: [], taint: { names: new Set<string>(), validated: new Set<string>(), trusted: new Set<string>() } };
    for (const u of r.urlSchemes) out.entries.push(makeEntry(repo, { kind: 'deep_link', framework: 'ios', file: f, line: u.line, method: null, path: null, name: `${u.scheme}://`, confidence: 'high', handlerView: v, spec: { start: 0, end: 0, seeds: [] }, analysis, tags: ['public'] }));
    for (const d of r.domains) out.entries.push(makeEntry(repo, { kind: 'deep_link', framework: 'ios', file: f, line: d.line, method: null, path: null, name: `https://${d.domain}/`, confidence: 'high', handlerView: v, spec: { start: 0, end: 0, seeds: [] }, analysis, tags: ['public'] }));
  }
  return out;
}
