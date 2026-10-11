// A read only view of the repository for the extractors: file views (text, masked text, line index) and an index of the
// repository's own functions by name, used to follow a handler one hop into the helpers it calls.
import type { CheckContext } from '../checks/context.ts';
import { cmp } from '../util.ts';
import type { FileView, HelperRef, Helpers } from './analyze.ts';
import { jsFunction, Lines, mask, pyBlock, type Lang } from './lex.ts';
import { loadLocalVocab, type LocalVocab } from './local-vocab.ts';

export const JS_EXT = /\.(?:[cm]?[jt]sx?)$/;
export const PY_EXT = /\.py$/;
export const langOf = (file: string): Lang | null => (JS_EXT.test(file) && !/\.d\.ts$/.test(file) ? 'js' : PY_EXT.test(file) ? 'py' : /\.go$/.test(file) ? 'go' : /\.rb$/.test(file) ? 'rb' : /\.php$/.test(file) ? 'php' : null);

// The lines of a Go, Ruby or PHP file that name what it uses: import blocks, require lines, use statements.
const IMPORTS_MORE: Record<'go' | 'rb' | 'php', RegExp> = {
  go: /^[ \t]*import\s*(?:\([\s\S]*?\)|(?:\w+\s+)?"[^"]*")/gm,
  rb: /^[ \t]*(?:require(?:_relative)?|gem|include|extend)\s[^\n]*/gm,
  php: /^[ \t]*(?:use|namespace)\s+[^;\n]*;/gm,
};

// A file that is browser code or generated: no server entry points are looked for in it.
const CLIENT_FILE = /^\s*["']use client["']|@Component\s*\(|@NgModule\s*\(|from\s+["']@angular\/|\.min\.[cm]?js$/;

export class Repo {
  private views = new Map<string, FileView | null>();
  private indexes = new Map<Lang, Map<string, HelperRef[]>>();
  readonly fileSet: Set<string>;
  readonly ctx: CheckContext;
  readonly local: LocalVocab;
  constructor(ctx: CheckContext) { this.ctx = ctx; this.fileSet = new Set(ctx.files); this.local = loadLocalVocab(ctx.repo); }

  view(file: string): FileView | null {
    if (this.views.has(file)) return this.views.get(file)!;
    const lang = langOf(file);
    let v: FileView | null = null;
    if (lang) {
      const text = this.ctx.text(file);
      if (text) {
        const masked = mask(text, lang);
        const imports = lang === 'go' || lang === 'rb' || lang === 'php' ? (text.match(IMPORTS_MORE[lang]) ?? []).join('\n') : (text.match(/\bimport\s[^;]*?from\s+['"][^'"]+['"]|\bimport\s+['"][^'"]+['"]|\b(?:const|let|var)\s+[^=;\n]+=\s*require\(\s*['"][^'"]+['"]\s*\)|^[ \t]*(?:from\s+\S+\s+import\b[^\n]*|import\s+\S+[^\n]*)/gm) ?? []).join('\n');
        v = { file, text, masked, lang, lines: new Lines(text), imports };
      }
    }
    this.views.set(file, v);
    return v;
  }

  // Local name -> import specifier, for the default, named and namespace imports and require calls of a JavaScript file.
  importMap(v: FileView): Map<string, string> {
    const out = new Map<string, string>();
    for (const m of v.imports.matchAll(/\bimport\s+(?:type\s+)?([^'"]*?)\s+from\s+['"]([^'"]+)['"]/g)) {
      const clause = m[1];
      const named = /\{([^}]*)\}/.exec(clause)?.[1] ?? '';
      for (const part of named.split(',')) { const n = part.trim().split(/\s+as\s+/).pop()?.trim(); if (n) out.set(n, m[2]); }
      const def = clause.replace(/\{[^}]*\}/, '').replace(/\*\s+as\s+/, '').split(',').map((x) => x.trim()).filter(Boolean);
      for (const d of def) out.set(d, m[2]);
    }
    for (const m of v.imports.matchAll(/\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\(\s*['"]([^'"]+)['"]/g)) {
      if (m[1].startsWith('{')) { for (const part of m[1].slice(1, -1).split(',')) { const n = part.trim().split(/\s*:\s*/).pop()?.trim(); if (n) out.set(n, m[2]); } } else out.set(m[1], m[2]);
    }
    return out;
  }

  isClient(v: FileView): boolean { return CLIENT_FILE.test(v.text.slice(0, 4000)) || (v.lang === 'js' && /\.[jt]sx$/.test(v.file) && /<\w+[^>]*>/.test(v.masked.slice(0, 20000)) && /\buseState\b|\buseEffect\b/.test(v.masked)); }

  filesOf(lang: Lang): string[] { return this.ctx.files.filter((f) => langOf(f) === lang); }

  // Resolve a relative (or "@/" aliased) import specifier from a file to a repository file.
  resolveImport(from: string, spec: string): string | null {
    let base: string;
    if (spec.startsWith('.')) {
      const parts = from.split('/').slice(0, -1);
      for (const seg of spec.split('/')) { if (seg === '..') parts.pop(); else if (seg !== '.') parts.push(seg); }
      base = parts.join('/');
    } else if (spec.startsWith('@/') || spec.startsWith('~/')) {
      const rest = spec.slice(2);
      for (const root of ['src/', '']) { const r = this.tryFile(root + rest); if (r) return r; }
      return null;
    } else return null;
    return this.tryFile(base);
  }
  private tryFile(base: string): string | null {
    for (const ext of ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '/index.ts', '/index.js', '/index.mjs', '/__init__.py']) if (this.fileSet.has(base + ext)) return base + ext;
    return null;
  }

  private index(lang: Lang): Map<string, HelperRef[]> {
    let idx = this.indexes.get(lang);
    if (idx) return idx;
    idx = new Map();
    if (lang !== 'js' && lang !== 'py') { this.indexes.set(lang, idx); return idx; } // Go, Ruby and PHP keep their own indexes
    const put = (name: string, ref: HelperRef): void => { const l = idx!.get(name); if (l) l.push(ref); else idx!.set(name, [ref]); };
    for (const file of this.filesOf(lang)) {
      const v = this.view(file);
      if (!v || this.isClient(v)) continue;
      if (lang === 'js') {
        const m = v.masked;
        for (const x of m.matchAll(/(?<![.\w$])function\s*\*?\s*([A-Za-z_$][\w$]*)\s*[(<]/g)) {
          const at = /async\s+$/.test(m.slice(Math.max(0, x.index! - 7), x.index!)) ? x.index! - 6 : x.index!;
          const f = jsFunction(m, at);
          if (f) put(x[1], { view: v, start: f.start, end: f.end });
        }
        for (const x of m.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*/g)) {
          const f = jsFunction(m, x.index! + x[0].length);
          if (f) put(x[1], { view: v, start: f.start, end: f.end });
        }
        for (const x of m.matchAll(/\bexports\.([A-Za-z_$][\w$]*)\s*=\s*/g)) {
          const f = jsFunction(m, x.index! + x[0].length);
          if (f) put(x[1], { view: v, start: f.start, end: f.end });
        }
        for (const x of m.matchAll(/(?:^|[{,\n])\s*([A-Za-z_$][\w$]*)\s*:\s*(?=async\b|function\b|\(|[A-Za-z_$][\w$]*\s*=>)/g)) {
          const f = jsFunction(m, x.index! + x[0].length);
          if (f) put(x[1], { view: v, start: f.start, end: f.end });
        }
      } else {
        for (const x of v.masked.matchAll(/^([ \t]*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm)) {
          const b = pyBlock(v.masked, v.lines, x.index!);
          put(x[2], { view: v, start: x.index!, end: b.end });
        }
      }
    }
    this.indexes.set(lang, idx);
    return idx;
  }

  // Which repository file defines a function of this name: unique across the repository, else the one in the caller's file.
  helpers(lang: Lang): Helpers {
    return {
      local: this.local,
      find: (name, fromFile) => {
        const refs = this.index(lang).get(name);
        if (!refs) return null;
        if (refs.length === 1) return refs[0];
        const same = refs.filter((r) => r.view.file === fromFile);
        if (same.length === 1) return same[0];
        const sorted = refs.slice().sort((a, b) => cmp(a.view.file, b.view.file) || a.start - b.start);
        return fromFile === undefined ? sorted[0] : null;
      },
    };
  }

  // Function definitions of a name, all of them (for resolving a handler reference).
  defs(lang: Lang, name: string): HelperRef[] {
    return (this.index(lang).get(name) ?? []).slice().sort((a, b) => cmp(a.view.file, b.view.file) || a.start - b.start);
  }
}
