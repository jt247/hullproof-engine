// The read only view of a repository that every check runs against: the file list, file text, stack.json and scan hits.
import { closeSync, openSync, readSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { LIMITS } from '../discover/discover.ts';
import { walk } from '../discover/walk.ts';
import { cmp, globToRegExp } from '../util.ts';
import { readTracked } from '../scanners/common.ts';
import type { CheckEvidence, Hit, Stack } from '../types/index.ts';

// Folders no check searches: engine output, the kit's own files and the project's security records. The kit folders hold
// text that names almost every term a check looks for (STANDARD.md, "What the searches leave out").
export const LEFT_OUT = ['.hullproof/', 'docs/hullproof/', 'tools/hullproof/', '.claude/', 'editors/', 'prompts/', 'docs/security/'];

export interface CheckContext {
  repo: string;                 // absolute path
  files: string[];              // repository relative POSIX paths, sorted, LEFT_OUT removed
  stack: Stack;
  hits: Hit[];
  kitDir: string | null;        // absolute path of the kit (docs/hullproof and tools/hullproof under it), when known
  text(file: string): string;   // '' when unreadable; at most LIMITS.maxBytesPerFile bytes
  select(globs: string[], exclude?: string[]): string[];
  // Every file in the git index, sorted, including files inside folders discovery skips (.vercel, .netlify, dist ...),
  // so a check can see a committed link or build file. null outside a git repository. Read once, on first use.
  tracked(): string[] | null;
}

function readHead(abs: string, max: number): string {
  const fd = openSync(abs, 'r');
  try {
    const buf = Buffer.alloc(max);
    const n = readSync(fd, buf, 0, max, 0);
    return buf.subarray(0, n).toString('utf8');
  } finally { closeSync(fd); }
}

export function makeContext(repo: string, stack: Stack, hits: Hit[] = [], kitDir: string | null = null): CheckContext {
  const root = resolve(repo);
  const files = walk(root, LIMITS.maxFiles).files.filter((f) => !LEFT_OUT.some((p) => f.startsWith(p)));
  const cache = new Map<string, string>();
  const text = (f: string): string => {
    let t = cache.get(f);
    if (t === undefined) {
      try { t = readHead(join(root, f), LIMITS.maxBytesPerFile); } catch { t = ''; }
      cache.set(f, t);
    }
    return t;
  };
  const select = (globs: string[], exclude: string[] = []): string[] => {
    const inc = globs.map(globToRegExp);
    const exc = exclude.map(globToRegExp);
    return files.filter((f) => inc.some((r) => r.test(f)) && !exc.some((r) => r.test(f)));
  };
  let trackedList: string[] | null | undefined;
  const tracked = (): string[] | null => {
    if (trackedList === undefined) { const t = readTracked(root); trackedList = t ? [...t].sort(cmp) : null; }
    return trackedList;
  };
  return { repo: root, files, stack, hits, kitDir, text, select, tracked };
}

// 1 based line of a character index.
export function lineOf(text: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

export const byFileLine = (a: CheckEvidence, b: CheckEvidence): number =>
  a.file < b.file ? -1 : a.file > b.file ? 1 : (a.line ?? 0) - (b.line ?? 0) || (a.note < b.note ? -1 : a.note > b.note ? 1 : 0);

// The most evidence entries one check result keeps. The count of all matches is kept in absence_search.
export const MAX_EVIDENCE = 25;
