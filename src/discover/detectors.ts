// Loads the detector rule files (detectors/*.json). Detectors are data; this file only reads and checks them.
// The format is documented in docs/INTERFACES.md, section "Detector rule files".
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { STACK_CATEGORIES } from '../types/stack.ts';
import type { Confidence, StackCategory } from '../types/stack.ts';
import { cmp } from '../util.ts';

export interface Signal {
  files: string[];                 // globs
  regex?: string;                  // when absent, the file being there is the signal
  all?: string[];                  // further patterns that must also match somewhere in the same file
  ignore_case?: boolean;
  confidence?: Confidence;         // default: high for a file signal, medium for a content signal
  attrs?: Record<string, string>;  // list fields to add to the item; "$file" is replaced by the file path
}

export interface DetectorEntry {
  id: string;
  attrs?: Record<string, string>;  // scalar fields of the item, for example {"kind": "cloud"}
  extensions?: string[];           // languages only
  deps?: Record<string, string[]>; // ecosystem to package names; "x*" is a prefix
  deps_confidence?: Confidence | Record<string, Confidence>; // default high; an object sets it per ecosystem, "*" for the rest
  imports?: Record<string, string[]>; // import language key to module names; "x*" is a prefix
  imports_confidence?: Confidence; // default medium
  signals?: Signal[];
}

export interface DetectorFile { category: StackCategory; entries: DetectorEntry[] }

export const DETECTORS_DIR = fileURLToPath(new URL('../../detectors/', import.meta.url));

const CONF = new Set(['high', 'medium', 'low']);

function check(name: string, f: DetectorFile): void {
  const bad = (msg: string): never => { throw new Error(`detectors/${name}: ${msg}`); };
  if (!STACK_CATEGORIES.includes(f.category)) bad(`unknown category ${f.category}`);
  const ids = new Set<string>();
  for (const e of f.entries ?? bad('no entries')) {
    if (!/^[a-z0-9][a-z0-9.-]*$/.test(e.id ?? '')) bad(`bad id ${e.id}`);
    if (ids.has(e.id)) bad(`duplicate id ${e.id}`);
    ids.add(e.id);
    if (!e.deps && !e.imports && !e.signals && !e.extensions) bad(`${e.id} has no signal`);
    const dc = typeof e.deps_confidence === 'object' ? Object.values(e.deps_confidence) : [e.deps_confidence];
    for (const c of [...dc, e.imports_confidence, ...(e.signals ?? []).map((s) => s.confidence)]) {
      if (c !== undefined && !CONF.has(c)) bad(`${e.id} bad confidence ${c}`);
    }
    for (const s of e.signals ?? []) {
      if (!Array.isArray(s.files) || s.files.length === 0) bad(`${e.id} signal without files`);
      for (const r of [s.regex, ...(s.all ?? [])]) if (r !== undefined) new RegExp(r); // throws on a bad pattern
    }
  }
}

export interface LoadedDetectors { files: DetectorFile[]; sha256: string }

export function loadDetectors(dir: string = DETECTORS_DIR): LoadedDetectors {
  const names = readdirSync(dir).filter((n) => n.endsWith('.json')).sort(cmp);
  const sums: string[] = [];
  const files: DetectorFile[] = [];
  for (const n of names) {
    const raw = readFileSync(join(dir, n));
    sums.push(`${createHash('sha256').update(raw).digest('hex')}  ${n}\n`);
    const f = JSON.parse(raw.toString('utf8')) as DetectorFile;
    check(n, f);
    files.push(f);
  }
  return { files, sha256: createHash('sha256').update(sums.join('')).digest('hex') };
}
