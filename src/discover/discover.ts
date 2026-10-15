// Stack discovery: deterministic, no model, no network, runs no program. Lists files, extracts facts, applies the detector
// rules, and builds stack.json. Same files and same detector files give the same bytes.
import { closeSync, openSync, readSync, fstatSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Confidence, Evidence, Stack, StackCategory, StackItem, Unknown } from '../types/stack.ts';
import { STACK_CATEGORIES } from '../types/stack.ts';
import { cmp, globToRegExp, sortUnique } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import { loadDetectors } from './detectors.ts';
import type { DetectorEntry, LoadedDetectors, Signal } from './detectors.ts';
import { IMPORT_LANGS, MANIFEST_NAMES, extractDeps, extractImports, importLangOf, nameMatches } from './extract.ts';
import type { DepFact, ImportFact } from './extract.ts';
import { readHeadCommit } from './git.ts';
import { walk } from './walk.ts';

export const LIMITS = { maxFiles: 200_000, maxBytesPerFile: 512 * 1024, maxImportFiles: 50_000, evidencePerItem: 5, languageSamples: 3 };

// Separator for prefix matching of package names per ecosystem; '' means exact names only (use "x*" for a prefix).
const DEP_SEP: Record<string, string> = {
  npm: '/', composer: '/', go: '/', maven: ':', nuget: '.', cocoapods: '/', swiftpm: '/',
  pypi: '', cargo: '', rubygems: '', pub: '', hex: '', terraform: '',
};

// Extensions that are data, docs, media or build artefacts: neither a language nor worth listing as unknown.
const NOT_CODE = new Set(('md markdown mdx txt rst adoc json jsonc json5 yaml yml toml xml csv tsv ini cfg conf lock log ' +
  'png jpg jpeg gif svg ico webp bmp tif tiff avif heic mp3 mp4 m4a wav ogg webm mov avi pdf zip gz tgz tar bz2 xz 7z rar jar war ' +
  'woff woff2 ttf otf eot map snap example sample template tpl j2 properties plist pbxproj xcconfig xcscheme xcworkspacedata ' +
  'storyboard xib entitlements strings pem crt cer key pub gitkeep keep sqlite sqlite3 db bin dat pkl pickle h5 npy ' +
  'sum mod tfvars tfstate hcl lockb editorconfig env patch diff po pot mo xlsx xls docx doc pptx odt license gradle bat cmd ' +
  'iml http rest bak orig tmp swp dockerignore gitignore gitattributes npmrc nvmrc prettierrc eslintrc babelrc ipynb').split(/\s+/));

const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|packages\.lock\.json|[^/]+\.lock)$/;
// Configuration files are looked for at the repository root and one level inside dot folders (.github, .do, .gitlab).
const CONFIG_EXT = /\.(ya?ml|toml|json|jsonc|ini|cfg|conf|hcl|properties)$/;
// Common tool configuration with no security meaning for discovery; not listed as unknown.
const KNOWN_TOOLING = /(^|\/)(\.?(eslint|prettier|stylelint|babel|jest|nyc|mocha|lint-staged|commitlint|markdownlint|yamllint|remark|cspell|renovate|codecov|release-it|semantic-release|browserslist|swcrc|postcss|tailwind|editorconfig|husky|c8|ava|vitest|karma|protractor|typedoc|tslint|lerna|nx|turbo|crowdin|codeclimate|mailmap|devcontainer|dependabot|pre-commit-config|gitpod|vscode|readthedocs|mkdocs|coveralls|sonar-project|cypress|playwright|stryker|snyk|zap|ncurc|npmpackagejsonlintrc|jsdoc|jsconfig|typos)(rc)?(\.[^/]*)?|tsconfig[^/]*|package-lock\.json|composer\.lock|\.?github\/[^/]*\.ya?ml|\.?github\/FUNDING\.yml|bower\.json|manifest\.json)$/i;
const TF_UTILITY = new Set(['random', 'null', 'local', 'tls', 'time', 'archive', 'template', 'external', 'http', 'terraform', 'cloudinit']);

const depConf = (e: DetectorEntry, eco: string): Confidence => {
  const c = e.deps_confidence;
  return (typeof c === 'object' ? c[eco] ?? c['*'] : c) ?? 'high';
};

const RANK: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };

interface Acc { evidence: Evidence[]; versions: Set<string>; lists: Map<string, Set<string>>; scalars: Record<string, string>; fileCount?: number }

function readHead(abs: string, max: number): { text: string; truncated: boolean } {
  const fd = openSync(abs, 'r');
  try {
    const size = fstatSync(fd).size;
    const buf = Buffer.alloc(Math.min(size, max));
    const n = readSync(fd, buf, 0, buf.length, 0);
    return { text: buf.subarray(0, n).toString('utf8'), truncated: size > max };
  } finally { closeSync(fd); }
}

const lineAt = (text: string, index: number): number => {
  let n = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
};

const extOf = (f: string): string => {
  const b = f.slice(f.lastIndexOf('/') + 1);
  const d = b.lastIndexOf('.');
  return d > 0 ? b.slice(d + 1).toLowerCase() : '';
};

export interface DiscoverOptions { detectors?: LoadedDetectors; skipFiles?: ReadonlySet<string> } // skipFiles: unchanged kit files (kit-files.ts)

export function discover(repo: string, opts: DiscoverOptions = {}): Stack {
  const root = resolve(repo);
  const det = opts.detectors ?? loadDetectors();
  const listing = walk(root, LIMITS.maxFiles, opts.skipFiles);
  const files = listing.files;

  const cache = new Map<string, string>();
  const truncated = new Set<string>();
  const text = (f: string): string => {
    let t = cache.get(f);
    if (t === undefined) {
      try {
        const r = readHead(join(root, f), LIMITS.maxBytesPerFile);
        t = r.text;
        if (r.truncated) truncated.add(f);
      } catch { t = ''; }
      cache.set(f, t);
    }
    return t;
  };

  // Facts.
  const deps: DepFact[] = [];
  for (const f of files) if (MANIFEST_NAMES.test(f)) deps.push(...extractDeps(f, text(f)));
  const importFiles = files.filter((f) => importLangOf(f) !== null);
  const scanned = importFiles.slice(0, LIMITS.maxImportFiles);
  const imports: ImportFact[] = [];
  for (const f of scanned) {
    imports.push(...extractImports(f, text(f)));
    cache.delete(f); // source text is not needed again unless a content signal asks for it
  }
  const depsByEco = Map.groupBy(deps, (d) => d.eco);
  const importsByLang = Map.groupBy(imports, (i) => i.lang);

  // Items.
  const items = new Map<string, Acc>();
  const usedFiles = new Set<string>();
  const matchedTf = new Set<string>();
  const acc = (cat: StackCategory, id: string): Acc => {
    const k = `${cat}\u0000${id}`;
    let a = items.get(k);
    if (!a) { a = { evidence: [], versions: new Set(), lists: new Map(), scalars: {} }; items.set(k, a); }
    return a;
  };
  const add = (a: Acc, ev: Evidence): void => { a.evidence.push(ev); usedFiles.add(ev.file); };
  const addList = (a: Acc, attrs: Record<string, string> | undefined, file: string): void => {
    for (const [k, v] of Object.entries(attrs ?? {})) {
      if (!a.lists.has(k)) a.lists.set(k, new Set());
      a.lists.get(k)!.add(v === '$file' ? file : v);
    }
  };
  const globCache = new Map<string, string[]>();
  const filesFor = (globs: string[]): string[] => {
    const key = globs.join('\n');
    let r = globCache.get(key);
    if (!r) { const res = globs.map(globToRegExp); r = files.filter((f) => res.some((re) => re.test(f))); globCache.set(key, r); }
    return r;
  };

  const runSignal = (cat: StackCategory, e: DetectorEntry, s: Signal, i: number): void => {
    const kind = s.regex ? 'content' : 'file';
    const rule = `${cat}.${e.id}.${kind}.${i + 1}`;
    const conf: Confidence = s.confidence ?? (s.regex ? 'medium' : 'high');
    const flags = 'm' + (s.ignore_case ? 'i' : '');
    const re = s.regex ? new RegExp(s.regex, flags) : null;
    const all = (s.all ?? []).map((r) => new RegExp(r, flags));
    for (const f of filesFor(s.files)) {
      if (re && LOCKFILE.test(f)) continue; // lockfiles are never templates or config; reading them only costs time
      if (!re) { const a = acc(cat, e.id); add(a, { file: f, key: '(present)', rule, confidence: conf }); addList(a, s.attrs, f); continue; }
      const t = text(f);
      const m = re.exec(t);
      if (!m || !all.every((r) => r.test(t))) continue;
      const a = acc(cat, e.id);
      add(a, { file: f, line: lineAt(t, m.index), rule, confidence: conf });
      addList(a, s.attrs, f);
    }
  };

  for (const df of det.files) {
    const cat = df.category;
    for (const e of df.entries) {
      for (const [eco, names] of Object.entries(e.deps ?? {})) {
        for (const d of depsByEco.get(eco) ?? []) {
          if (!names.some((n) => nameMatches(d.name, n, DEP_SEP[eco] ?? ''))) continue;
          if (eco === 'terraform') matchedTf.add(d.name);
          const a = acc(cat, e.id);
          add(a, { file: d.file, ...(d.line !== undefined ? { line: d.line } : { key: d.key }), rule: `${cat}.${e.id}.dep.${eco}`, confidence: depConf(e, eco) });
          if (d.version) a.versions.add(`${d.name}@${d.version}`);
        }
      }
      for (const [lang, mods] of Object.entries(e.imports ?? {})) {
        const sep = IMPORT_LANGS[lang]?.sep ?? '';
        for (const im of importsByLang.get(lang) ?? []) {
          if (!mods.some((m) => nameMatches(im.module, m, sep))) continue;
          add(acc(cat, e.id), { file: im.file, line: im.line, rule: `${cat}.${e.id}.import.${lang}`, confidence: e.imports_confidence ?? 'medium' });
        }
      }
      (e.signals ?? []).forEach((s, i) => runSignal(cat, e, s, i));
      if (e.extensions) {
        const exts = new Set(e.extensions);
        const hits = files.filter((f) => exts.has(extOf(f)));
        if (hits.length) {
          const a = acc(cat, e.id);
          a.fileCount = hits.length;
          for (const f of hits) a.evidence.push({ file: f, key: '(extension)', rule: `${cat}.${e.id}.extension`, confidence: 'high' });
        }
      }
      const a = items.get(`${cat}\u0000${e.id}`);
      if (a) Object.assign(a.scalars, e.attrs ?? {});
    }
  }

  // Unknowns: never guessed, only listed.
  const unknown: Unknown[] = [];
  const langExts = new Set(det.files.filter((f) => f.category === 'languages').flatMap((f) => f.entries.flatMap((e) => e.extensions ?? [])));
  const byExt = new Map<string, string[]>();
  for (const f of files) {
    const x = extOf(f);
    if (!x || langExts.has(x) || NOT_CODE.has(x)) continue;
    if (!byExt.has(x)) byExt.set(x, []);
    byExt.get(x)!.push(f);
  }
  for (const [x, fs] of byExt) unknown.push({ file: fs[0], note: `no detector for the file extension .${x} (${fs.length} file${fs.length === 1 ? '' : 's'})` });
  for (const f of files) {
    const parts = f.split('/');
    const configPlace = parts.length === 1 || (parts.length === 2 && parts[0].startsWith('.'));
    if (!configPlace || !CONFIG_EXT.test(f) || usedFiles.has(f) || KNOWN_TOOLING.test(f)) continue;
    unknown.push({ file: f, note: 'configuration file with no detector' });
  }
  const tfSeen = new Set<string>();
  for (const d of depsByEco.get('terraform') ?? []) {
    if (matchedTf.has(d.name) || TF_UTILITY.has(d.name) || tfSeen.has(d.name)) continue;
    tfSeen.add(d.name);
    unknown.push({ file: d.file, note: `Terraform provider "${d.name}" has no detector` });
  }
  const LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'];
  const fileSet = new Set(files);
  for (const f of files.filter((x) => x === 'package.json' || x.endsWith('/package.json'))) {
    const dir = f.slice(0, -'package.json'.length);
    if (LOCKS.some((l) => fileSet.has(dir + l) || fileSet.has(l))) continue;
    unknown.push({ file: f, note: 'package.json with no lockfile in its folder or the repository root: package manager not determined' });
  }

  // Assemble, sorted.
  const out = Object.fromEntries(STACK_CATEGORIES.map((c) => [c, [] as StackItem[]])) as Record<StackCategory, StackItem[]>;
  for (const [k, a] of items) {
    const [cat, id] = k.split('\u0000') as [StackCategory, string];
    const seen = new Set<string>();
    const ev = a.evidence
      .sort((x, y) => RANK[x.confidence] - RANK[y.confidence] || cmp(x.file, y.file) || (x.line ?? 0) - (y.line ?? 0) || cmp(x.key ?? '', y.key ?? '') || cmp(x.rule, y.rule))
      .filter((x) => { const s = `${x.file}|${x.line}|${x.key}|${x.rule}`; return seen.has(s) ? false : (seen.add(s), true); });
    const shown = cat === 'languages' && a.fileCount ? LIMITS.languageSamples : LIMITS.evidencePerItem;
    // The sample shows the best entry of each file first, so it spans files instead of repeating one file.
    const fileSeen = new Set<string>();
    const firsts = ev.filter((x) => !fileSeen.has(x.file) && !!fileSeen.add(x.file));
    const firstSet = new Set(firsts);
    const sample = [...firsts, ...ev.filter((x) => !firstSet.has(x))].slice(0, shown);
    const item: StackItem = { id, confidence: ev[0].confidence, evidence: sample, evidence_count: ev.length, ...a.scalars };
    if (a.versions.size) item.versions = sortUnique(a.versions);
    if (a.fileCount) item.file_count = a.fileCount;
    for (const [lk, set] of a.lists) (item as unknown as Record<string, string[]>)[lk] = sortUnique(set);
    out[cat].push(item);
  }
  for (const c of STACK_CATEGORIES) out[c].sort((x, y) => cmp(x.id, y.id));

  return {
    schema_version: '1.0.0',
    engine_version: ENGINE_VERSION,
    detectors_sha256: det.sha256,
    commit: readHeadCommit(root),
    confirmed_by_user: false,
    files: { listed: files.length, scanned_for_imports: scanned.length },
    limits: {
      max_files: LIMITS.maxFiles, max_bytes_per_file: LIMITS.maxBytesPerFile,
      file_cap_reached: listing.capReached || importFiles.length > scanned.length,
      truncated_files: sortUnique(truncated),
    },
    skipped: listing.skipped.slice().sort((x, y) => cmp(x.path, y.path)),
    ...out,
    unknown: unknown.sort((x, y) => cmp(x.file, y.file) || cmp(x.note, y.note)),
  };
}
