// Fact extractors: declared dependencies from manifests, and imports from source files. Small built in readers only,
// line based where the format allows, so every fact carries a file and a line (or a JSON key).

export interface DepFact { eco: string; name: string; version: string | null; file: string; line?: number; key?: string }
export interface ImportFact { lang: string; module: string; file: string; line: number }

const base = (f: string): string => f.slice(f.lastIndexOf('/') + 1);
const lines = (t: string): string[] => t.split(/\r?\n/);
const pyName = (n: string): string => n.toLowerCase().replace(/_/g, '-');

function jsonDeps(eco: string, file: string, text: string, sections: string[]): DepFact[] {
  let j: Record<string, unknown>;
  try { j = JSON.parse(text); } catch { return []; }
  const out: DepFact[] = [];
  for (const s of sections) {
    const deps = j?.[s];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, v] of Object.entries(deps as Record<string, unknown>)) {
      out.push({ eco, name, version: typeof v === 'string' ? v : null, file, key: `${s}.${name}` });
    }
  }
  return out;
}

function eachLine(text: string, fn: (line: string, n: number) => void): void {
  lines(text).forEach((l, i) => fn(l, i + 1));
}

function requirementString(s: string): { name: string; version: string | null } | null {
  const m = /^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*((?:===|[<>=!~]=?)[^;#,\s]*(?:\s*,\s*[<>=!~]=?[^;#,\s]*)*)?\s*(?:;.*)?$/.exec(s);
  return m ? { name: pyName(m[1]), version: m[2] ?? null } : null;
}

function requirementsTxt(file: string, text: string): DepFact[] {
  const out: DepFact[] = [];
  eachLine(text, (l, n) => {
    const t = l.replace(/\s+#.*$/, '').trim();
    if (!t || t.startsWith('#') || t.startsWith('-') || t.includes('://')) return;
    const r = requirementString(t);
    if (r) out.push({ eco: 'pypi', ...r, file, line: n });
  });
  return out;
}

function pyproject(file: string, text: string): DepFact[] {
  const out: DepFact[] = [];
  let section = '';
  let arrayKey: string | null = null;
  eachLine(text, (l, n) => {
    const sec = /^\s*\[{1,2}([^\]]+)\]{1,2}\s*$/.exec(l);
    if (sec) { section = sec[1].trim(); arrayKey = null; return; }
    let rest = l;
    if (arrayKey === null) {
      const a = /^\s*"?([A-Za-z0-9_.-]+)"?\s*=\s*\[(.*)$/.exec(l);
      if (a) { arrayKey = a[1]; rest = a[2]; }
      else if (/(^|\.)dependencies$/.test(section) && section !== 'project') {
        const p = /^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(l); // poetry style: name = "^1.0" or { version = "1.0" }
        if (p && p[1].toLowerCase() !== 'python') {
          const v = /^"([^"]*)"/.exec(p[2])?.[1] ?? /version\s*=\s*"([^"]*)"/.exec(p[2])?.[1] ?? null;
          out.push({ eco: 'pypi', name: pyName(p[1]), version: v, file, line: n });
        }
        return;
      } else return;
    }
    const depArray = (section === 'project' && arrayKey === 'dependencies') || section === 'project.optional-dependencies'
      || section === 'dependency-groups' || (section === 'build-system' && arrayKey === 'requires');
    if (depArray) {
      for (const m of rest.matchAll(/"([^"]+)"|'([^']+)'/g)) {
        const r = requirementString(m[1] ?? m[2]);
        if (r) out.push({ eco: 'pypi', ...r, file, line: n });
      }
    }
    if (rest.includes(']')) arrayKey = null;
  });
  return out;
}

function sectionKeyValues(eco: string, file: string, text: string, isDepSection: (s: string) => boolean, norm: (s: string) => string): DepFact[] {
  const out: DepFact[] = [];
  let section = '';
  eachLine(text, (l, n) => {
    const sec = /^\s*\[([^\]]+)\]\s*$/.exec(l);
    if (sec) { section = sec[1].trim(); return; }
    if (!isDepSection(section)) return;
    const p = /^\s*"?([A-Za-z0-9_.-]+)"?\s*=\s*(.*)$/.exec(l);
    if (!p) return;
    const v = /^"([^"]*)"/.exec(p[2])?.[1] ?? /version\s*=\s*"([^"]*)"/.exec(p[2])?.[1] ?? null;
    out.push({ eco, name: norm(p[1]), version: v, file, line: n });
  });
  return out;
}

function regexLines(eco: string, file: string, text: string, re: RegExp, nameOf: (m: RegExpExecArray) => string, verOf: (m: RegExpExecArray) => string | null): DepFact[] {
  const out: DepFact[] = [];
  eachLine(text, (l, n) => {
    const m = re.exec(l);
    if (m) out.push({ eco, name: nameOf(m), version: verOf(m), file, line: n });
  });
  return out;
}

function goMod(file: string, text: string): DepFact[] {
  const out: DepFact[] = [];
  let inBlock = false;
  eachLine(text, (l, n) => {
    if (/^\s*require\s*\(\s*$/.test(l)) { inBlock = true; return; }
    if (inBlock && /^\s*\)/.test(l)) { inBlock = false; return; }
    const m = inBlock ? /^\s*(\S+)\s+(v\S+)/.exec(l) : /^\s*require\s+(\S+)\s+(v\S+)/.exec(l);
    if (m) out.push({ eco: 'go', name: m[1], version: m[2], file, line: n });
  });
  return out;
}

function pomXml(file: string, text: string): DepFact[] {
  const out: DepFact[] = [];
  for (const m of text.matchAll(/<(dependency|parent|plugin)>([\s\S]*?)<\/\1>/g)) {
    const body = m[2];
    const g = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(body)?.[1] ?? '';
    const a = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(body);
    if (!a) continue;
    const v = /<version>\s*([^<\s]+)\s*<\/version>/.exec(body)?.[1] ?? null;
    const at = (m.index ?? 0) + m[0].indexOf(a[0]);
    out.push({ eco: 'maven', name: `${g}:${a[1]}`, version: v, file, line: text.slice(0, at).split('\n').length });
  }
  return out;
}

function pubspec(file: string, text: string): DepFact[] {
  const out: DepFact[] = [];
  let inDeps = false;
  eachLine(text, (l, n) => {
    if (/^\S/.test(l)) { inDeps = /^(dependencies|dev_dependencies|dependency_overrides):\s*$/.test(l); return; }
    if (!inDeps) return;
    const m = /^ {2}([A-Za-z0-9_]+):\s*(.*)$/.exec(l);
    if (m) out.push({ eco: 'pub', name: m[1], version: m[2].trim() || null, file, line: n });
  });
  return out;
}

function terraform(file: string, text: string): DepFact[] {
  const out: DepFact[] = [];
  eachLine(text, (l, n) => {
    // Provider blocks, and the provider prefix of resource and data types (aws_s3_bucket is provider aws).
    const p = /^\s*provider\s+"([a-z0-9_-]+)"/.exec(l) ?? /^\s*(?:resource|data)\s+"([a-z0-9]+)_/.exec(l);
    if (p) out.push({ eco: 'terraform', name: p[1], version: null, file, line: n });
  });
  return out;
}

// Every manifest format the engine reads, by file name.
export function extractDeps(file: string, text: string): DepFact[] {
  const b = base(file);
  if (b === 'package.json') return jsonDeps('npm', file, text, ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']);
  if (b === 'composer.json') return jsonDeps('composer', file, text, ['require', 'require-dev']);
  if (/^requirements.*\.(txt|in)$/.test(b) || /(^|\/)requirements\/[^/]+\.(txt|in)$/.test(file)) return requirementsTxt(file, text);
  if (b === 'pyproject.toml') return pyproject(file, text);
  if (b === 'Pipfile') return sectionKeyValues('pypi', file, text, (s) => s === 'packages' || s === 'dev-packages', pyName);
  if (b === 'setup.py') return regexLines('pypi', file, text, /^\s*['"]([A-Za-z][A-Za-z0-9_.-]*)(?:\[[^\]]*\])?\s*((?:[<>=!~]=?)[^'"]*)?['"],?\s*$/, (m) => pyName(m[1]), (m) => m[2] ?? null);
  if (b === 'go.mod') return goMod(file, text);
  if (b === 'Cargo.toml') return sectionKeyValues('cargo', file, text, (s) => /(^|\.)(dev-|build-)?dependencies$/.test(s), (s) => s);
  if (b === 'Gemfile') return regexLines('rubygems', file, text, /^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/, (m) => m[1], (m) => m[2] ?? null);
  if (b === 'pom.xml') return pomXml(file, text);
  if (b === 'build.gradle' || b === 'build.gradle.kts') {
    return regexLines('maven', file, text, /\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|androidTestImplementation|kapt|ksp|annotationProcessor|classpath|compile)\s*\(?\s*(?:platform\s*\(\s*)?['"]([^'":\s]+):([^'":\s]+)(?::([^'"\s]+))?['"]/, (m) => `${m[1]}:${m[2]}`, (m) => m[3] ?? null);
  }
  if (b === 'pubspec.yaml') return pubspec(file, text);
  if (/\.(cs|fs|vb)proj$/.test(b)) return regexLines('nuget', file, text, /<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?/i, (m) => m[1], (m) => m[2] ?? null);
  if (b === 'packages.config') return regexLines('nuget', file, text, /<package\s+id="([^"]+)"\s+version="([^"]+)"/i, (m) => m[1], (m) => m[2]);
  if (b === 'Package.swift') {
    return regexLines('swiftpm', file, text, /\.package\s*\([^)]*?url:\s*"(?:https?:\/\/|git@)?([^"]+?)(?:\.git)?"(?:[^)]*?(?:from|exact):\s*"([^"]+)")?/, (m) => m[1].replace(':', '/').toLowerCase(), (m) => m[2] ?? null);
  }
  if (b === 'Podfile') return regexLines('cocoapods', file, text, /^\s*pod\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/, (m) => m[1], (m) => m[2] ?? null);
  if (b === 'mix.exs') return regexLines('hex', file, text, /\{\s*:([a-z0-9_]+)\s*,\s*"([^"]+)"/, (m) => m[1], (m) => m[2]);
  if (b.endsWith('.tf')) return terraform(file, text);
  return [];
}

export const MANIFEST_NAMES = /(^|\/)(package\.json|composer\.json|requirements[^/]*\.(txt|in)|requirements\/[^/]+\.(txt|in)|pyproject\.toml|Pipfile|setup\.py|go\.mod|Cargo\.toml|Gemfile|pom\.xml|build\.gradle(\.kts)?|pubspec\.yaml|[^/]+\.(cs|fs|vb)proj|packages\.config|Package\.swift|Podfile|mix\.exs|[^/]+\.tf)$/;

// Import scan. Language key by extension, the line patterns, and the separator used for prefix matching in rules.
interface ImportLang { exts: string[]; res: RegExp[]; block?: { start: RegExp; end: RegExp; item: RegExp } }
export const IMPORT_LANGS: Record<string, ImportLang & { sep: string }> = {
  js: { exts: ['js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts', 'vue', 'svelte', 'astro'], sep: '/',
    res: [/(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)['"]([^'"\s]+)['"]/g] },
  python: { exts: ['py'], sep: '.', res: [/^\s*import\s+([A-Za-z_][\w.]*)/g, /^\s*from\s+([A-Za-z_][\w.]*)\s+import\b/g] },
  go: { exts: ['go'], sep: '/', res: [/^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"/g],
    block: { start: /^\s*import\s*\(\s*$/, end: /^\s*\)/, item: /^\s*(?:[\w.]+\s+)?"([^"]+)"/ } },
  ruby: { exts: ['rb'], sep: '/', res: [/^\s*require\s+['"]([^'"]+)['"]/g] },
  php: { exts: ['php'], sep: '\\', res: [/^\s*use\s+\\?([A-Za-z_][\w\\]*)/g] },
  jvm: { exts: ['java', 'kt', 'scala', 'groovy'], sep: '.', res: [/^\s*import\s+(?:static\s+)?([\w.]+)/g] },
  swift: { exts: ['swift'], sep: '.', res: [/^\s*(?:@testable\s+)?import\s+(?:(?:class|struct|enum|protocol|func|var|typealias)\s+)?(\w+)/g] },
  dart: { exts: ['dart'], sep: '/', res: [/^\s*import\s+['"](?:package:)?((?:dart:)?[^'"]+)['"]/g] },
  csharp: { exts: ['cs'], sep: '.', res: [/^\s*(?:global\s+)?using\s+(?:static\s+)?([A-Z][\w.]*)\s*;/g] },
  rust: { exts: ['rs'], sep: '::', res: [/^\s*(?:pub\s+)?use\s+([a-z_]\w*)::/g, /^\s*extern\s+crate\s+(\w+)/g] },
};
const LANG_BY_EXT = new Map<string, string>();
for (const [k, v] of Object.entries(IMPORT_LANGS)) for (const e of v.exts) LANG_BY_EXT.set(e, k);

export const importLangOf = (file: string): string | null => {
  const b = base(file);
  const dot = b.lastIndexOf('.');
  return dot > 0 ? LANG_BY_EXT.get(b.slice(dot + 1).toLowerCase()) ?? null : null;
};

// First line per module per file. Relative and alias imports (".", "/", "~", "@/", "#") are dropped.
export function extractImports(file: string, text: string): ImportFact[] {
  const lang = importLangOf(file);
  if (!lang) return [];
  const spec = IMPORT_LANGS[lang];
  const seen = new Map<string, number>();
  let inBlock = false;
  eachLine(text, (l, n) => {
    const found: string[] = [];
    if (spec.block) {
      if (!inBlock && spec.block.start.test(l)) { inBlock = true; return; }
      if (inBlock) {
        if (spec.block.end.test(l)) { inBlock = false; return; }
        const m = spec.block.item.exec(l);
        if (m) found.push(m[1]);
      }
    }
    for (const re of spec.res) for (const m of l.matchAll(re)) found.push(m[1]);
    for (const mod of found) {
      if (lang === 'js' && /^(\.|\/|~|@\/|#)/.test(mod)) continue;
      if (!seen.has(mod)) seen.set(mod, n);
    }
  });
  return [...seen].map(([module, line]) => ({ lang, module, file, line }));
}

// Does a fact name match a rule pattern? Exact, or a prefix on the separator, or "prefix*".
export function nameMatches(name: string, pattern: string, sep: string): boolean {
  if (pattern.endsWith('*')) return name.startsWith(pattern.slice(0, -1));
  return name === pattern || (sep !== '' && name.startsWith(pattern + sep));
}
