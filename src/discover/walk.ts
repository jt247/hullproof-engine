// File listing for discovery. Reads the folder tree directly and applies .gitignore files itself, so discovery never runs
// git (a repository's git config can make git run code). Dependency, build output and tool folders are skipped and reported.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Skipped } from '../types/stack.ts';
import { cmp, globBody } from '../util.ts';
import { kitFolders } from './kit-files.ts';

const SKIP_DIRS: Record<string, Skipped['reason']> = {
  node_modules: 'dependency folder', bower_components: 'dependency folder', jspm_packages: 'dependency folder',
  vendor: 'dependency folder', '.venv': 'dependency folder', venv: 'dependency folder', Pods: 'dependency folder',
  Carthage: 'dependency folder', '.bundle': 'dependency folder', '.pnpm-store': 'dependency folder', '.yarn': 'dependency folder',
  dist: 'build output', build: 'build output', out: 'build output', '.next': 'build output', '.nuxt': 'build output',
  '.svelte-kit': 'build output', '.output': 'build output', '.vercel': 'build output', '.netlify': 'build output',
  target: 'build output', '.gradle': 'build output', DerivedData: 'build output', coverage: 'build output',
  '__pycache__': 'build output', '.pytest_cache': 'build output', '.mypy_cache': 'build output', '.tox': 'build output',
  '.dart_tool': 'build output', '.expo': 'build output', '.turbo': 'build output', '.cache': 'build output',
  '.parcel-cache': 'build output', '.terraform': 'build output', '.serverless': 'build output', '.aws-sam': 'build output',
  'cdk.out': 'build output',
  '.git': 'tool folder', '.hg': 'tool folder', '.svn': 'tool folder', '.hullproof': 'tool folder', '.idea': 'tool folder',
};

interface IgnoreRule { base: string; re: RegExp; negate: boolean; dirOnly: boolean }

export function parseGitignore(text: string, base: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let p = raw.replace(/(?<!\\)\s+$/, '');
    if (!p || p.startsWith('#')) continue;
    const negate = p.startsWith('!');
    if (negate) p = p.slice(1);
    if (p.startsWith('\\')) p = p.slice(1);
    const dirOnly = p.endsWith('/');
    if (dirOnly) p = p.slice(0, -1);
    if (!p) continue;
    const anchored = p.includes('/');
    if (p.startsWith('/')) p = p.slice(1);
    const body = globBody(p); // ponytail: also reads {a,b} as alternation, which gitignore does not; rare in practice
    rules.push({ base, negate, dirOnly, re: new RegExp(anchored ? `^${body}$` : `^(?:.*/)?${body}$`) });
  }
  return rules;
}

function ignored(rel: string, isDir: boolean, rules: IgnoreRule[]): boolean {
  let out = false;
  for (const r of rules) {
    if (r.dirOnly && !isDir) continue;
    let sub: string;
    if (!r.base) sub = rel;
    else if (rel.startsWith(r.base + '/')) sub = rel.slice(r.base.length + 1);
    else continue;
    if (r.re.test(sub)) out = !r.negate;
  }
  return out;
}

export interface WalkResult { files: string[]; skipped: Skipped[]; capReached: boolean }

export function walk(root: string, maxFiles: number, skipFiles?: ReadonlySet<string>): WalkResult {
  const files: string[] = [];
  const skipped: Skipped[] = [];
  let capReached = false;
  const absRoot = resolve(root);

  const visit = (dirRel: string, inherited: IgnoreRule[]): void => {
    const abs = dirRel ? join(absRoot, dirRel) : absRoot;
    let rules = inherited;
    try { rules = inherited.concat(parseGitignore(readFileSync(join(abs, '.gitignore'), 'utf8'), dirRel)); } catch { /* no .gitignore here */ }
    const entries = readdirSync(abs, { withFileTypes: true }).sort((a, b) => cmp(a.name, b.name));
    for (const e of entries) {
      if (capReached) return;
      const rel = dirRel ? `${dirRel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { skipped.push({ path: rel, reason: 'symlink' }); continue; }
      const isDir = e.isDirectory();
      if (!isDir && !e.isFile()) continue;
      if (isDir && SKIP_DIRS[e.name]) { skipped.push({ path: rel + '/', reason: SKIP_DIRS[e.name] }); continue; }
      if (ignored(rel, isDir, rules)) { skipped.push({ path: isDir ? rel + '/' : rel, reason: 'gitignore' }); continue; }
      if (isDir) visit(rel, rules);
      else if (skipFiles?.has(rel)) continue;
      else if (files.length >= maxFiles) capReached = true;
      else files.push(rel);
    }
  };
  if (!statSync(absRoot).isDirectory()) throw new Error(`not a folder: ${root}`);
  visit('', []);
  if (skipFiles?.size) for (const d of kitFolders(skipFiles)) skipped.push({ path: d, reason: 'unchanged kit files' });
  return { files, skipped, capReached };
}
