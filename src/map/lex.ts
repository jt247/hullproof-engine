// Text helpers for the extractors (approach (b) in docs/PHASE-2-DESIGN.md): blank out comments and string contents while
// keeping every position, match brackets, and cut function bodies. No parser, no dependency.

import { maskMore } from './lex-more.ts';

export type Lang = 'js' | 'py' | 'go' | 'rb' | 'php' | 'java' | 'cs' | 'kt' | 'swift' | 'rs';

const blank = (s: string): string => s.replace(/[^\n]/g, ' ');


// Whether a "/" at `i` starts a regular expression literal (and is not a division or a JSX closing tag), judged from the
// text before it.
function regexAllowed(text: string, i: number): boolean {
  let k = i - 1;
  while (k >= 0 && /\s/.test(text[k])) k--;
  if (k < 0) return true;
  if ('(,=:[!&|?{;+-*%~^'.includes(text[k])) return true;
  const m = /([A-Za-z_$][\w$]*)$/.exec(text.slice(Math.max(0, k - 12), k + 1));
  return !!m && /^(return|typeof|case|in|of|delete|void|throw|new|else|do|yield|await)$/.test(m[1]);
}

// A copy of `text` with the same length in which comments and the insides of string literals are spaces. Quote characters
// and newlines stay, so a regular expression run on the copy never matches inside a comment or a string, and a position in
// the copy is the same position in the original.
export function mask(text: string, lang: Lang): string {
  if (lang !== 'js' && lang !== 'py') return maskMore(text, lang);
  const n = text.length;
  const out: string[] = [];
  let i = 0;
  let prevSig = '';
  const put = (from: number, to: number): void => { out.push(blank(text.slice(from, to))); };
  const keep = (from: number, to: number): void => { out.push(text.slice(from, to)); };

  const skipTemplate = (start: number): number => { // start is the index of the opening backtick; returns the index after the closing one
    let j = start + 1;
    while (j < n) {
      const c = text[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '`') return j + 1;
      if (c === '$' && text[j + 1] === '{') {
        let depth = 1;
        j += 2;
        while (j < n && depth > 0) {
          const d = text[j];
          if (d === '`') { j = skipTemplate(j); continue; }
          if (d === '"' || d === "'") { j++; while (j < n && text[j] !== d && text[j] !== '\n') { if (text[j] === '\\') j++; j++; } j++; continue; }
          if (d === '{') depth++;
          else if (d === '}') depth--;
          j++;
        }
        continue;
      }
      j++;
    }
    return n;
  };

  while (i < n) {
    const c = text[i];
    const c2 = text[i + 1];
    if (lang === 'js') {
      if (c === '/' && c2 === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; put(i, end); i = end; continue; }
      if (c === '/' && c2 === '*') { const e = text.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; put(i, end); i = end; continue; }
      if (c === '`') { const end = skipTemplate(i); keep(i, i + 1); put(i + 1, Math.max(i + 1, end - 1)); if (end - 1 > i) keep(end - 1, end); i = end; prevSig = '`'; continue; }
      if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < n && text[j] !== c && text[j] !== '\n') { if (text[j] === '\\') j++; j++; }
        const close = j < n && text[j] === c ? j : -1;
        keep(i, i + 1);
        put(i + 1, close < 0 ? Math.min(j, n) : close);
        if (close >= 0) keep(close, close + 1);
        i = close < 0 ? Math.min(j, n) : close + 1;
        prevSig = c;
        continue;
      }
      if (c === '/' && regexAllowed(text, i)) {
        // regular expression literal
        let j = i + 1;
        let inClass = false;
        while (j < n && text[j] !== '\n') {
          if (text[j] === '\\') { j += 2; continue; }
          if (text[j] === '[') inClass = true;
          else if (text[j] === ']') inClass = false;
          else if (text[j] === '/' && !inClass) break;
          j++;
        }
        if (j < n && text[j] === '/') { keep(i, i + 1); put(i + 1, j); keep(j, j + 1); i = j + 1; prevSig = '/'; continue; }
      }
    } else {
      if (c === '#') { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; put(i, end); i = end; continue; }
      if (c === '"' || c === "'") {
        const triple = text[i + 1] === c && text[i + 2] === c;
        if (triple) {
          const e = text.indexOf(c.repeat(3), i + 3);
          const end = e < 0 ? n : e + 3;
          keep(i, i + 3); put(i + 3, Math.max(i + 3, end - 3)); if (e >= 0) keep(end - 3, end);
          i = end; prevSig = c; continue;
        }
        let j = i + 1;
        while (j < n && text[j] !== c && text[j] !== '\n') { if (text[j] === '\\') j++; j++; }
        const close = j < n && text[j] === c ? j : -1;
        keep(i, i + 1);
        put(i + 1, close < 0 ? Math.min(j, n) : close);
        if (close >= 0) keep(close, close + 1);
        i = close < 0 ? Math.min(j, n) : close + 1;
        prevSig = c;
        continue;
      }
    }
    keep(i, i + 1);
    if (!/\s/.test(c)) prevSig = c;
    i++;
  }
  return out.join('');
}

// Line numbers from character positions, by binary search over the line starts. Built once per file.
export class Lines {
  private starts: number[] = [0];
  constructor(text: string) { for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) this.starts.push(i + 1); }
  at(index: number): number {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (this.starts[mid] <= index) lo = mid; else hi = mid - 1; }
    return lo + 1;
  }
  start(line: number): number { return this.starts[Math.max(0, Math.min(this.starts.length - 1, line - 1))]; }
  get count(): number { return this.starts.length; }
}

const PAIR: Record<string, string> = { '(': ')', '{': '}', '[': ']' };

// The index just past the bracket that closes the one at `open`, in masked text, or -1.
export function closeOf(masked: string, open: number): number {
  const stack: string[] = [];
  for (let i = open; i < masked.length; i++) {
    const c = masked[i];
    if (PAIR[c]) stack.push(PAIR[c]);
    else if (c === ')' || c === '}' || c === ']') {
      if (c !== stack[stack.length - 1]) return -1;
      stack.pop();
      if (stack.length === 0) return i + 1;
    }
  }
  return -1;
}

// Top level argument ranges of the call whose "(" is at `open`: [{start, end}] with end exclusive, trimmed.
export function splitArgs(masked: string, open: number): { start: number; end: number }[] {
  const close = closeOf(masked, open);
  if (close < 0) return [];
  const args: { start: number; end: number }[] = [];
  let depth = 0;
  let from = open + 1;
  const push = (end: number): void => {
    let s = from;
    let e = end;
    while (s < e && /\s/.test(masked[s])) s++;
    while (e > s && /\s/.test(masked[e - 1])) e--;
    if (e > s) args.push({ start: s, end: e });
  };
  for (let i = open + 1; i < close - 1; i++) {
    const c = masked[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { push(i); from = i + 1; }
    else if (c === '=' && masked[i + 1] === '>' ) { /* arrow: the body follows; handled by depth of braces */ }
  }
  push(close - 1);
  return args;
}

// The end (exclusive) of the statement that starts at `from`: the first ";" at depth 0, or a newline at depth 0 after which
// the next code character does not continue the expression (a ".", "?", ":", operator or closing bracket).
export function statementEnd(masked: string, from: number): number {
  let depth = 0;
  for (let i = from; i < masked.length; i++) {
    const c = masked[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { if (depth === 0) return i; depth--; }
    else if (c === ';' && depth === 0) return i;
    else if (c === '\n' && depth === 0) {
      const rest = masked.slice(i + 1, i + 200);
      const next = /\S/.exec(rest);
      const prev = masked.slice(from, i).trimEnd().slice(-1);
      if (!next) return i;
      const nc = rest[next.index];
      if (nc === '.' || nc === '?' || nc === ':' || nc === '+' || nc === '|' || nc === '&' || nc === ',' || nc === ')' || nc === ']') continue;
      if (prev === ',' || prev === '+' || prev === '=' || prev === '?' || prev === ':' || prev === '|' || prev === '&' || prev === '(') continue;
      return i;
    }
  }
  return masked.length;
}

export interface Extent { start: number; end: number; bodyStart: number }

// The extent of the JavaScript or TypeScript function that begins at `from` (the index of "async", "function", "(" or a
// single parameter name before "=>"). bodyStart is the first index of the body text (the "{" or the first token of an
// expression body). Returns null when the text there is not a function.
// `method`: the text is a class method, so a "{" after the return type at bracket depth 0 is the body and never an object type.
export function jsFunction(masked: string, from: number, method = false): Extent | null {
  let i = from;
  const ws = (): void => { while (i < masked.length && /\s/.test(masked[i])) i++; };
  ws();
  if (masked.startsWith('async', i) && /\W/.test(masked[i + 5] ?? ' ')) { i += 5; ws(); }
  let isFunctionKeyword = false;
  if (masked.startsWith('function', i) && /\W/.test(masked[i + 8] ?? ' ')) { isFunctionKeyword = true; i += 8; ws(); if (masked[i] === '*') { i++; ws(); } while (/[\w$]/.test(masked[i] ?? '')) i++; ws(); if (masked[i] === '<') { let d = 0; for (; i < masked.length; i++) { if (masked[i] === '<') d++; else if (masked[i] === '>') { d--; if (d === 0) { i++; break; } } } ws(); } }
  if (masked[i] === '(') {
    const pc = closeOf(masked, i);
    if (pc < 0) return null;
    i = pc;
  } else if (!isFunctionKeyword && /[\w$]/.test(masked[i] ?? '')) {
    while (/[\w$]/.test(masked[i] ?? '')) i++;
    ws();
    if (!(masked[i] === '=' && masked[i + 1] === '>')) return null;
  } else return null;
  ws();
  // Optional return type annotation: scan to the "{" (function) or "=>" (arrow) at bracket depth 0.
  if (masked[i] === ':') {
    let depth = 0;
    for (i = i + 1; i < masked.length; i++) {
      const c = masked[i];
      if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (c === '<') depth++;
      else if (c === '>' && masked[i - 1] !== '=') depth--;
      else if (c === '{' && depth <= 0 && !isFunctionKeyword && !method) { depth++; }
      else if (c === '}' && depth > 0 && !isFunctionKeyword && !method) { depth--; }
      else if (c === '=' && masked[i + 1] === '>' && depth <= 0) break;
      else if (c === '{' && depth <= 0 && (isFunctionKeyword || method)) break;
    }
  }
  ws();
  if (masked[i] === '=' && masked[i + 1] === '>') {
    i += 2;
    ws();
    if (masked[i] === '{') { const e = closeOf(masked, i); return e < 0 ? null : { start: from, end: e, bodyStart: i }; }
    const e = statementEnd(masked, i);
    return { start: from, end: e, bodyStart: i };
  }
  if (masked[i] === '{') { const e = closeOf(masked, i); return e < 0 ? null : { start: from, end: e, bodyStart: i }; }
  return null;
}

// The Python block that belongs to the "def" or "class" line starting at `lineStart` (an index at the start of the line):
// the header (which may span several lines until the colon that ends it) and every following line indented deeper.
export function pyBlock(masked: string, lines: Lines, lineStart: number): Extent {
  const indentOf = (ls: number): number => { let k = ls; let w = 0; while (masked[k] === ' ' || masked[k] === '\t') { w += masked[k] === '\t' ? 8 : 1; k++; } return w; };
  const base = indentOf(lineStart);
  // header ends at the first ":" at bracket depth 0 followed by end of line
  let depth = 0;
  let i = lineStart;
  for (; i < masked.length; i++) {
    const c = masked[i];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ':' && depth === 0 && /^[ \t]*(\n|$)/.test(masked.slice(i + 1, i + 40))) break;
    else if (c === ':' && depth === 0 && /^[ \t]*\S/.test(masked.slice(i + 1, i + 40)) && /^\s*(def|class|async\s+def)\b/.test(masked.slice(lineStart, lineStart + 12))) { /* annotation colon, keep scanning */ }
  }
  const bodyStart = Math.min(masked.length, i + 1);
  let end = bodyStart;
  const total = lines.count;
  let ln = lines.at(bodyStart) + 1;
  for (; ln <= total; ln++) {
    const ls = lines.start(ln);
    const le = masked.indexOf('\n', ls);
    const row = masked.slice(ls, le < 0 ? masked.length : le);
    if (row.trim() === '') { continue; }
    if (indentOf(ls) <= base) break;
    end = le < 0 ? masked.length : le;
  }
  return { start: lineStart, end, bodyStart };
}
