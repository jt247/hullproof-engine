// Shared reading helpers for the annotation based languages (Java and Kotlin in Spring, C# attributes): split a class body into
// declaration blocks, each with the annotations in front of it, and read string literals out of annotation arguments. Works on masked
// text for structure and on the original text for the string values, which sit at the same positions.
import { closeOf } from './lex.ts';

export interface Anno { name: string; start: number; end: number; args: { start: number; end: number } | null }
export interface Block { annos: Anno[]; start: number; end: number; declStart: number }

// Annotations of the form @Name or @Name(...) at brace depth 0 of the range [from, to), grouped into blocks of consecutive annotations.
// `declStart` is the first character after the last annotation of the block (the declaration the annotations belong to).
export function annotationBlocks(masked: string, from: number, to: number): Block[] {
  const out: Block[] = [];
  let depth = 0;
  let cur: Block | null = null;
  for (let i = from; i < to; i++) {
    const c = masked[i];
    if (c === '{' || c === '(' || c === '[') { depth++; continue; }
    if (c === '}' || c === ')' || c === ']') { depth--; continue; }
    if (depth !== 0 || c !== '@') continue;
    const m = /^@([A-Za-z_][\w.]*)/.exec(masked.slice(i, i + 80));
    if (!m) continue;
    let end = i + m[0].length;
    let args: Anno['args'] = null;
    let k = end;
    while (/[ \t]/.test(masked[k] ?? '')) k++;
    if (masked[k] === '(') {
      const close = closeOf(masked, k);
      if (close > 0) { args = { start: k + 1, end: close - 1 }; end = close; }
    }
    const gap = cur ? masked.slice(cur.annos[cur.annos.length - 1].end, i) : '';
    if (cur && /^\s*$/.test(gap)) cur.annos.push({ name: m[1], start: i, end, args });
    else { cur = { annos: [{ name: m[1], start: i, end, args }], start: i, end: 0, declStart: 0 }; out.push(cur); }
    i = end - 1;
  }
  for (const b of out) { b.end = b.annos[b.annos.length - 1].end; let d = b.end; while (/\s/.test(masked[d] ?? '')) d++; b.declStart = d; }
  return out;
}

// All "string" literals in the text, with the escapes of a quoted string left as written.
export const strings = (text: string): string[] => [...text.matchAll(/"((?:[^"\\\n]|\\.)*)"/g)].map((m) => m[1]);

// Top level comma split of a parameter or argument list (commas inside (), [], {} and <> do not split).
export function splitTop(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '(' || c === '[' || c === '{' || c === '<') depth++;
    else if (c === ')' || c === ']' || c === '}' || (c === '>' && text[i - 1] !== '=' && text[i - 1] !== '-')) depth = Math.max(0, depth - 1);
    else if (c === ',' && depth === 0) { out.push(text.slice(from, i)); from = i + 1; }
  }
  if (text.slice(from).trim()) out.push(text.slice(from));
  return out.map((x) => x.trim()).filter(Boolean);
}
