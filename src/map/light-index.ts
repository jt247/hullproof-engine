// An index of the repository's own functions by name for Go, Ruby and PHP: where a function starts and ends, so a handler
// can be followed to its definition and one hop into the helpers it calls. Built once per language and repository.
import { cmp } from '../util.ts';
import type { HelperRef } from './analyze.ts';
import { closeOf, statementEnd } from './lex.ts';
import type { MoreLang } from './lex-more.ts';
import type { Repo } from './repo.ts';

// The extent of a Go function whose "func" keyword is at `at`: [start, end) with the body inside braces.
export function goFunc(masked: string, at: number): { start: number; end: number; bodyStart: number; params: string } | null {
  let i = at + 4;
  while (/\s/.test(masked[i] ?? '')) i++;
  if (masked[i] === '(' && /^\(\s*\w*\s*\*?\s*[\w.[\]]+\s*\)\s*\w/.test(masked.slice(i, i + 120))) { const c = closeOf(masked, i); if (c < 0) return null; i = c; while (/\s/.test(masked[i] ?? '')) i++; }
  while (/[\w]/.test(masked[i] ?? '')) i++;
  while (/\s/.test(masked[i] ?? '')) i++;
  if (masked[i] === '[') { const c = closeOf(masked, i); if (c < 0) return null; i = c; }
  if (masked[i] !== '(') return null;
  const pc = closeOf(masked, i);
  if (pc < 0) return null;
  const params = masked.slice(i + 1, pc - 1);
  for (i = pc; i < masked.length; i++) {
    const c = masked[i];
    if (c === '{') {
      const before = masked.slice(Math.max(0, i - 12), i).trimEnd();
      if (/(?:interface|struct)$/.test(before)) { const e = closeOf(masked, i); if (e < 0) return null; i = e - 1; continue; }
      const e = closeOf(masked, i);
      return e < 0 ? null : { start: at, end: e, bodyStart: i, params };
    }
    if (c === ';' ) return null;
  }
  return null;
}

// A Ruby method: from "def" to the "end" at the same indentation.
export function rubyDef(masked: string, defAt: number): { start: number; end: number } {
  const ls = masked.lastIndexOf('\n', defAt) + 1;
  const indent = /^[ \t]*/.exec(masked.slice(ls))![0].length;
  const oneLine = /^[^\n]*\bdef\b[^\n]*=\s*\S/.exec(masked.slice(defAt, defAt + 200));
  const firstEnd = masked.indexOf('\n', defAt);
  if (oneLine && !/\bend\b/.test(masked.slice(defAt, firstEnd < 0 ? masked.length : firstEnd))) return { start: defAt, end: firstEnd < 0 ? masked.length : firstEnd };
  let pos = firstEnd < 0 ? masked.length : firstEnd + 1;
  while (pos < masked.length) {
    const e = masked.indexOf('\n', pos);
    const row = masked.slice(pos, e < 0 ? masked.length : e);
    const ind = /^[ \t]*/.exec(row)![0].length;
    if (row.trim() !== '' && ind <= indent && /^\s*end\b/.test(row)) return { start: defAt, end: pos + row.length };
    if (row.trim() !== '' && ind < indent) return { start: defAt, end: pos };
    if (e < 0) break;
    pos = e + 1;
  }
  return { start: defAt, end: masked.length };
}

// A PHP function or method: from "function" to the closing brace of its body.
export function phpFunc(masked: string, at: number): { start: number; end: number; bodyStart: number; params: string } | null {
  const open = masked.indexOf('(', at);
  if (open < 0) return null;
  const pc = closeOf(masked, open);
  if (pc < 0) return null;
  const params = masked.slice(open + 1, pc - 1);
  const m = /^[^{;]*\{/.exec(masked.slice(pc, pc + 300));
  if (!m) return null;
  const bodyStart = pc + m[0].length - 1;
  const e = closeOf(masked, bodyStart);
  return e < 0 ? null : { start: at, end: e, bodyStart, params };
}

// A Java or C# method whose name starts at `at`: the parameters, then a block body, or in C# an expression body after "=>". An abstract or
// interface method (ending in ";") has no body and gives null.
export function cMethod(masked: string, at: number): { start: number; end: number; bodyStart: number; params: string } | null {
  let i = at;
  while (/[\w$]/.test(masked[i] ?? '')) i++;
  while (/\s/.test(masked[i] ?? '')) i++;
  if (masked[i] === '<') { let d = 0; for (; i < masked.length; i++) { if (masked[i] === '<') d++; else if (masked[i] === '>' && --d === 0) { i++; break; } else if (masked[i] === '\n' && d > 4) return null; } while (/\s/.test(masked[i] ?? '')) i++; }
  if (masked[i] !== '(') return null;
  const pc = closeOf(masked, i);
  if (pc < 0) return null;
  const params = masked.slice(i + 1, pc - 1);
  for (let j = pc; j < masked.length; j++) {
    const c = masked[j];
    if (c === '{') { const e = closeOf(masked, j); return e < 0 ? null : { start: at, end: e, bodyStart: j, params }; }
    if (c === ';') return null;
    if (c === '=' && masked[j + 1] === '>') return { start: at, end: statementEnd(masked, j + 2), bodyStart: j + 2, params };
  }
  return null;
}

// Method declarations: at least one modifier, a type, a name and "(".
export const C_METHOD = /^[ \t]*(?:@\w+(?:\([^)\n]*\))?[ \t]*)*(?:(?:public|protected|private|internal|static|final|abstract|synchronized|async|override|virtual|sealed|partial|new|extern|unsafe|default)\s+)+[^;{}()=\n]*?\s(\w+)\s*(?:<[^>\n]*>)?\s*\(/gm;

export class FnIndex {
  private idx = new Map<string, HelperRef[]>();
  readonly repo: Repo;
  readonly lang: MoreLang;
  constructor(repo: Repo, lang: MoreLang) {
    this.repo = repo;
    this.lang = lang;
    const put = (name: string, ref: HelperRef): void => { const l = this.idx.get(name); if (l) l.push(ref); else this.idx.set(name, [ref]); };
    for (const file of repo.filesOf(lang)) {
      const v = repo.view(file);
      if (!v) continue;
      const m = v.masked;
      if (lang === 'go') {
        for (const x of m.matchAll(/^func\s+(?:\(\s*\w*\s*\*?\s*[\w.[\]]+\s*\)\s*)?(\w+)\s*[([]/gm)) {
          const f = goFunc(m, x.index!);
          if (f) put(x[1], { view: v, start: f.start, end: f.end });
        }
      } else if (lang === 'rb') {
        for (const x of m.matchAll(/^[ \t]*def\s+(?:self\.)?(\w+[?!=]?)/gm)) {
          const d = rubyDef(m, x.index! + x[0].indexOf('def'));
          put(x[1], { view: v, start: d.start, end: d.end });
        }
      } else if (lang === 'java' || lang === 'cs') {
        for (const x of m.matchAll(C_METHOD)) {
          const f = cMethod(m, x.index! + x[0].lastIndexOf(x[1]));
          if (f) put(x[1], { view: v, start: f.start, end: f.end });
        }
      } else {
        for (const x of m.matchAll(/\bfunction\s+&?\s*(\w+)\s*\(/g)) {
          const f = phpFunc(m, x.index!);
          if (f) put(x[1], { view: v, start: f.start, end: f.end });
        }
      }
    }
  }
  defs(name: string): HelperRef[] { return (this.idx.get(name) ?? []).slice().sort((a, b) => cmp(a.view.file, b.view.file) || a.start - b.start); }
  find = (name: string, fromFile: string): HelperRef | null => {
    const refs = this.idx.get(name);
    if (!refs) return null;
    if (refs.length === 1) return refs[0];
    const same = refs.filter((r) => r.view.file === fromFile);
    return same.length === 1 ? same[0] : null;
  };
}
