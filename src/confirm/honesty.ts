// The honesty check. A lead is kept only when every file it cites exists in the repository, every cited line is inside its file,
// and the code it quotes is really there beside the sink (the last step of its path). A lead that fails is dropped and counted
// as a hallucination. Nothing here reads the lead's claim: it only asks whether the cited code exists.
import { lstatSync, readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import type { CodeMap, Lead } from '../types/index.ts';
import { LIMITS } from './lead.ts';

export const QUOTE_SLACK = 2;           // the quote may start or end this many lines from the cited sink line
const MAX_FILE_BYTES = 2_000_000;

const norm = (s: string): string => s.replace(/\s+/g, ' ').trim();

export class FileCache {
  private repo: string;
  private files = new Map<string, string | null>();
  constructor(repo: string) { this.repo = resolve(repo); }
  // The text of a repository file, or null: absolute paths, "..", links, folders and files over 2 MB are all null.
  read(file: string): string | null {
    if (this.files.has(file)) return this.files.get(file)!;
    let text: string | null = null;
    if (file && !file.startsWith('/') && !file.includes('\\') && !file.includes('\0') && !file.split('/').includes('..')) {
      const abs = resolve(this.repo, file);
      try {
        const st = lstatSync(abs);
        if (abs.startsWith(this.repo + sep) && st.isFile() && st.size <= MAX_FILE_BYTES) text = readFileSync(abs, 'utf8');
      } catch { text = null; }
    }
    this.files.set(file, text);
    return text;
  }
}

// Line ranges [start, end] (1 based) of every place the normalised quote occurs in the normalised file.
function occurrences(text: string, quote: string): [number, number][] {
  const starts: number[] = [];   // offset in the joined text where each original line begins
  let joined = '';
  text.split('\n').forEach((raw) => {
    const t = norm(raw);
    starts.push(joined.length);
    joined += t + ' ';
  });
  const lineAt = (off: number): number => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const m = (lo + hi + 1) >> 1; if (starts[m] <= off) lo = m; else hi = m - 1; }
    return lo + 1;
  };
  const out: [number, number][] = [];
  for (let at = joined.indexOf(quote); at >= 0; at = joined.indexOf(quote, at + 1)) out.push([lineAt(at), lineAt(at + quote.length - 1)]);
  return out;
}

export function checkLead(lead: Lead, files: FileCache, map: CodeMap): { ok: true } | { ok: false; reason: string } {
  if (!map.entry_points.some((e) => e.id === lead.entry_point)) return { ok: false, reason: 'the entry point is not in the code map' };
  for (const s of lead.path) {
    const t = files.read(s.file);
    if (t === null) return { ok: false, reason: `the cited file ${s.file} does not exist in the repository` };
    if (s.line > t.split('\n').length) return { ok: false, reason: `line ${s.line} is past the end of ${s.file}` };
  }
  const sink = lead.path[lead.path.length - 1];
  const quote = norm(lead.quoted_code);
  if (quote.length < LIMITS.minQuote || !/[A-Za-z0-9]/.test(quote)) return { ok: false, reason: 'the quoted code is too short to check' };
  const near = occurrences(files.read(sink.file)!, quote).some(([a, b]) => b >= sink.line - QUOTE_SLACK && a <= sink.line + QUOTE_SLACK);
  return near ? { ok: true } : { ok: false, reason: `the quoted code is not in ${sink.file} at line ${sink.line}` };
}
