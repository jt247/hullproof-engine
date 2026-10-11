// The declarative check operations. Each takes the op's params and the repository view and returns an outcome.
// Params per op are documented in src/checks/README.md. No op runs a program or uses the network.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { cmp } from '../util.ts';
import type { AbsenceSearch, CheckEvidence, CheckOp } from '../types/index.ts';
import { MAX_EVIDENCE, byFileLine, lineOf, type CheckContext } from './context.ts';

// value: true or false picks on_true or on_false. 'not_applicable' and 'cannot_run' put the check in not_run with reason.
export interface OpOutcome {
  value: boolean | 'not_applicable' | 'cannot_run';
  reason?: string;
  evidence: CheckEvidence[];
  absence: AbsenceSearch | null;
}

type P = Record<string, unknown>;
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : typeof v === 'string' ? [v] : []);
const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : d);
const cap = (ev: CheckEvidence[]): CheckEvidence[] => ev.sort(byFileLine).slice(0, MAX_EVIDENCE);
const na = (reason: string): OpOutcome => ({ value: 'not_applicable', reason, evidence: [], absence: null });
const cannot = (reason: string): OpOutcome => ({ value: 'cannot_run', reason, evidence: [], absence: null });

export function compile(pattern: string, ignoreCase: boolean): RegExp {
  return new RegExp(pattern, ignoreCase ? 'gim' : 'gm');
}

// Every match of re in text, as evidence.
export function matchesIn(file: string, text: string, re: RegExp, note: string): CheckEvidence[] {
  const out: CheckEvidence[] = [];
  re.lastIndex = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    out.push({ file, line: lineOf(text, m.index), note });
    if (m[0] === '') re.lastIndex++;
  }
  return out;
}

// Files the op reads: params.files minus params.exclude, kept only when they match params.only_if.
function selected(ctx: CheckContext, p: P): string[] {
  const files = ctx.select(strs(p.files), strs(p.exclude));
  if (typeof p.only_if !== 'string') return files;
  const re = compile(p.only_if, p.ignore_case === true);
  return files.filter((f) => { re.lastIndex = 0; return re.test(ctx.text(f)); });
}

// params.precondition {files, exclude?, pattern?}: when no file meets it the check does not apply. Returns the files that do.
function precondition(ctx: CheckContext, p: P): string[] | null {
  const pre = p.precondition as P | undefined;
  if (!pre) return null;
  const files = ctx.select(strs(pre.files), strs(pre.exclude));
  if (typeof pre.pattern !== 'string') return files;
  const re = compile(pre.pattern, pre.ignore_case === true);
  return files.filter((f) => { re.lastIndex = 0; return re.test(ctx.text(f)); });
}

function preEvidence(ctx: CheckContext, p: P, files: string[]): CheckEvidence[] {
  const pre = p.precondition as P;
  const note = str(p.precondition_note, 'searched here');
  if (typeof pre.pattern !== 'string') return files.map((file) => ({ file, line: 1, note }));
  const re = compile(pre.pattern, pre.ignore_case === true);
  return files.map((file) => ({ file, line: matchesIn(file, ctx.text(file), re, note)[0]?.line ?? 1, note }));
}

function regexOp(ctx: CheckContext, p: P, present: boolean): OpOutcome {
  const pre = precondition(ctx, p);
  if (pre && pre.length === 0) return na(str(p.not_applicable_reason, 'no file meets the precondition'));
  const files = selected(ctx, p);
  const pattern = str(p.pattern);
  if (!pattern) return cannot('params.pattern is missing');
  const absence = (matches: number): AbsenceSearch => ({ pattern, files_searched: files.length, file_globs: strs(p.files), matches });
  if (files.length === 0) {
    const w = str(p.when_no_files, 'not_applicable');
    if (w === 'not_applicable') return na(str(p.not_applicable_reason, 'no file to search'));
    const value = w === 'true';
    return { value, evidence: !value && pre ? cap(preEvidence(ctx, p, pre)) : [], absence: absence(0) };
  }
  const re = compile(pattern, p.ignore_case === true);
  const note = str(p.note, present ? 'matches the pattern' : 'matches the pattern this check forbids');
  const perFile = files.map((f) => ({ f, ev: matchesIn(f, ctx.text(f), re, note) }));
  const all = perFile.flatMap((x) => x.ev);
  if (!present) return { value: all.length === 0, evidence: cap(all), absence: absence(all.length) };
  if (p.each_file === true) {
    const missing = perFile.filter((x) => x.ev.length === 0).map((x) => x.f);
    const missNote = str(p.missing_note, 'the pattern is not in this file');
    return missing.length
      ? { value: false, evidence: cap(missing.map((file) => ({ file, line: 1, note: missNote }))), absence: absence(all.length) }
      : { value: true, evidence: cap(all), absence: absence(all.length) };
  }
  if (all.length) return { value: true, evidence: cap(all), absence: absence(all.length) };
  // Nothing found anywhere: point at the files where the thing is normally configured, when the check names them.
  return { value: false, evidence: pre ? cap(preEvidence(ctx, p, pre)) : [], absence: absence(0) };
}

function fileExists(ctx: CheckContext, p: P, wantPresent: boolean): OpOutcome {
  const found = ctx.select(strs(p.files), strs(p.exclude));
  const note = str(p.note, wantPresent ? 'file present' : 'file present that this check forbids');
  const evidence = cap(found.map((file) => ({ file, key: '(present)', note })));
  const absence: AbsenceSearch = { pattern: strs(p.files).join(' '), files_searched: ctx.files.length, file_globs: strs(p.files), matches: found.length };
  return { value: wantPresent ? found.length > 0 : found.length === 0, evidence, absence };
}

// params.manifests: manifest file name to the lockfile names that pin it. A lockfile in the same folder or any parent counts.
function fileExistsForEach(ctx: CheckContext, p: P): OpOutcome {
  const table = (p.manifests ?? {}) as Record<string, string[]>;
  const names = Object.keys(table);
  const have = new Set(ctx.files);
  const manifests = ctx.files.filter((f) => names.includes(f.slice(f.lastIndexOf('/') + 1)));
  if (manifests.length === 0) return na('no package manifest in the repository');
  const missing: CheckEvidence[] = [];
  for (const m of manifests) {
    const locks = table[m.slice(m.lastIndexOf('/') + 1)];
    const parts = m.split('/').slice(0, -1);
    let ok = false;
    for (let i = parts.length; i >= 0 && !ok; i--) {
      const dir = parts.slice(0, i).join('/');
      ok = locks.some((l) => have.has(dir ? `${dir}/${l}` : l));
    }
    if (!ok) missing.push({ file: m, line: 1, note: str(p.note, `no lockfile (${locks.join(', ')}) in this folder or above`) });
  }
  const absence: AbsenceSearch = { pattern: [...new Set(Object.values(table).flat())].sort(cmp).join(' '), files_searched: manifests.length, file_globs: names, matches: manifests.length - missing.length };
  return missing.length ? { value: false, evidence: cap(missing), absence } : { value: true, evidence: cap(manifests.map((file) => ({ file, line: 1, note: 'lockfile found' }))), absence };
}

// Strips SQL comments, keeping line breaks so line numbers stay right.
const stripSqlComments = (t: string): string => t.replace(/--[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
const tableName = (raw: string): { schema: string | null; name: string } => {
  const parts = raw.replace(/"/g, '').toLowerCase().split('.');
  return parts.length > 1 ? { schema: parts[0], name: parts[1] } : { schema: null, name: parts[0] };
};

// Every table created in an exposed schema has row level security enabled after it, reading files in name order.
function sqlEveryTableHas(ctx: CheckContext, p: P): OpOutcome {
  const files = ctx.select(strs(p.files), strs(p.exclude));
  if (files.length === 0) return na('no migration files');
  const schemas = strs(p.schemas).length ? strs(p.schemas) : ['public'];
  const ident = '((?:"[^"]+"|[\\w$]+)(?:\\.(?:"[^"]+"|[\\w$]+))?)';
  const re = new RegExp(`\\b(create\\s+(?:unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?${ident}|alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${ident}\\s+(enable|disable|force)\\s+row\\s+level\\s+security|drop\\s+table\\s+(?:if\\s+exists\\s+)?${ident})`, 'gi');
  const tables = new Map<string, { file: string; line: number; rls: boolean }>();
  const key = (raw: string): string | null => {
    const t = tableName(raw);
    const schema = t.schema ?? schemas[0];
    return schemas.includes(schema) ? `${schema}.${t.name}` : null;
  };
  for (const f of files) {
    const text = stripSqlComments(ctx.text(f));
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) {
      if (m[2]) { const k = key(m[2]); if (k) tables.set(k, { file: f, line: lineOf(text, m.index), rls: false }); }
      else if (m[3]) { const k = key(m[3]); const t = k ? tables.get(k) : undefined; if (t) t.rls = m[4].toLowerCase() !== 'disable'; }
      else if (m[5]) { const k = key(m[5]); if (k) tables.delete(k); }
    }
  }
  if (tables.size === 0) return na('no table created in an exposed schema');
  const without = [...tables.entries()].filter(([, t]) => !t.rls);
  const absence: AbsenceSearch = { pattern: 'alter table <name> enable row level security', files_searched: files.length, file_globs: strs(p.files), matches: tables.size - without.length };
  const evidence = without.map(([name, t]) => ({ file: t.file, line: t.line, note: `table ${name} is created and row level security is never enabled on it` }));
  return { value: without.length === 0, evidence: cap(evidence), absence };
}

function workflows(ctx: CheckContext, p: P): string[] {
  return ctx.select(strs(p.files).length ? strs(p.files) : ['.github/workflows/*.yml', '.github/workflows/*.yaml']);
}

// Every third party action is referenced by a full 40 character commit SHA.
function workflowUsesPinnedSha(ctx: CheckContext, p: P): OpOutcome {
  const files = workflows(ctx, p);
  if (files.length === 0) return na('no CI workflow files');
  const re = /^[ \t-]*uses:\s*["']?([^\s"'#]+)/gm;
  const bad: CheckEvidence[] = [];
  let total = 0;
  for (const f of files) {
    const text = ctx.text(f);
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) {
      const ref = m[1];
      if (ref.startsWith('./') || ref.startsWith('docker://')) continue;
      total++;
      const at = ref.lastIndexOf('@');
      if (at < 0 || !/^[0-9a-f]{40}$/.test(ref.slice(at + 1))) bad.push({ file: f, line: lineOf(text, m.index), note: `${ref} is not pinned to a full commit SHA` });
    }
  }
  if (total === 0) return na('no third party action is used');
  const absence: AbsenceSearch = { pattern: 'uses: <owner>/<repo>@<40 hex>', files_searched: files.length, file_globs: strs(p.files), matches: total - bad.length };
  return { value: bad.length === 0, evidence: cap(bad), absence };
}

// Every workflow declares token permissions (at the top or on every job) and none grants write-all.
function workflowPermissions(ctx: CheckContext, p: P): OpOutcome {
  const files = workflows(ctx, p);
  if (files.length === 0) return na('no CI workflow files');
  const bad: CheckEvidence[] = [];
  for (const f of files) {
    const text = ctx.text(f);
    for (const m of text.matchAll(/^[ \t]*permissions:[ \t]*write-all\b/gm)) bad.push({ file: f, line: lineOf(text, m.index), note: 'the token is granted write access to everything' });
    if (/^permissions:/m.test(text)) continue;
    const jobsAt = /^jobs:\s*$/m.exec(text);
    if (!jobsAt) continue;
    const body = text.slice(jobsAt.index);
    const jobs = [...body.matchAll(/^ {2}([\w-]+):\s*$/gm)];
    const withPerms = jobs.filter((j, i) => {
      const end = jobs[i + 1]?.index ?? body.length;
      return /^ {4}permissions:/m.test(body.slice(j.index, end));
    });
    if (jobs.length === 0 || withPerms.length < jobs.length) {
      bad.push({ file: f, line: lineOf(text, jobsAt.index), note: 'no permissions block for the workflow or for every job, so the token gets the repository default' });
    }
  }
  const absence: AbsenceSearch = { pattern: 'permissions: (top level or per job), write-all', files_searched: files.length, file_globs: strs(p.files), matches: bad.length };
  return { value: bad.length === 0, evidence: cap(bad), absence };
}

// Reads the kit's framework support table: per heading, release line to status.
export function supportTable(markdown: string, heading: string): Map<string, string> | null {
  const lines = markdown.split(/\r?\n/);
  const at = lines.findIndex((l) => l.trim() === `## ${heading}`);
  if (at < 0) return null;
  const rows = new Map<string, string>();
  for (let i = at + 1; i < lines.length && !lines[i].startsWith('## '); i++) {
    const l = lines[i].trim();
    if (!l.startsWith('|') || /^\|[\s|:-]+\|$/.test(l)) continue;
    const cells = l.slice(1, -1).split('|').map((c) => c.trim());
    if (cells[0] === 'Release line') continue;
    rows.set(cells[0], cells[cells.length - 1]);
  }
  return rows;
}

// The release line of a declared version: "13.4.0" -> "13", "^0.85.2" -> "0.85", "~=5.2.1" -> "5.2".
export function releaseLine(version: string, digits: number): string | null {
  const m = /(\d+)(?:\.(\d+))?/.exec(version);
  if (!m) return null;
  return digits === 2 ? (m[2] === undefined ? null : `${m[1]}.${m[2]}`) : m[1];
}

// params.table: kit relative path. params.frameworks: stack id to {heading, package, digits}.
function versionInTable(ctx: CheckContext, p: P): OpOutcome {
  if (!ctx.kitDir) return cannot('the kit folder is not known, so the framework support table cannot be read');
  let md: string;
  try { md = readFileSync(join(ctx.kitDir, str(p.table)), 'utf8'); } catch { return cannot(`cannot read ${str(p.table)} in the kit`); }
  const table = (p.frameworks ?? {}) as Record<string, { heading: string; package: string; digits?: number }>;
  const items = [...ctx.stack.frameworks, ...ctx.stack.mobile].filter((i) => table[i.id]);
  if (items.length === 0) return na('no framework from the support table is in stack.json');
  const bad: CheckEvidence[] = [];
  const good: CheckEvidence[] = [];
  const unknown: string[] = [];
  for (const item of items) {
    const row = table[item.id];
    const rows = supportTable(md, row.heading);
    const ev = item.evidence.find((e) => e.rule.includes('.dep.')) ?? item.evidence[0];
    const declared = (item.versions ?? []).filter((v) => v.startsWith(`${row.package}@`)).map((v) => v.slice(row.package.length + 1));
    if (!rows || declared.length === 0) { unknown.push(item.id); continue; }
    for (const v of declared) {
      const line = releaseLine(v, row.digits ?? 1);
      const status = line ? rows.get(line) : undefined;
      const where = { file: ev?.file ?? 'package.json', ...(ev?.line ? { line: ev.line } : { key: ev?.key ?? `(present)` }) };
      if (/canary|alpha|beta|rc|next|experimental|nightly/i.test(v)) bad.push({ ...where, note: `${row.package} ${v} is a prerelease or canary version` });
      else if (status === 'Supported') good.push({ ...where, note: `${row.package} ${v}: release line ${line} is supported in the kit table` });
      else if (status) bad.push({ ...where, note: `${row.package} ${v}: release line ${line} is ${status.toLowerCase()} in the kit's framework support table` });
      else unknown.push(`${item.id} ${v}`);
    }
  }
  const absence: AbsenceSearch = { pattern: `release lines in ${str(p.table)}`, files_searched: 1, file_globs: [str(p.table)], matches: good.length };
  if (bad.length) return { value: false, evidence: cap(bad), absence };
  if (unknown.length) return cannot(`no row in the framework support table for ${unknown.sort(cmp).join(', ')}`);
  return { value: true, evidence: cap(good), absence };
}

export const OPS: Partial<Record<CheckOp, (ctx: CheckContext, p: P) => OpOutcome>> = {
  file_exists: (c, p) => fileExists(c, p, true),
  file_absent: (c, p) => fileExists(c, p, false),
  file_exists_for_each: fileExistsForEach,
  regex_present: (c, p) => regexOp(c, p, true),
  regex_absent: (c, p) => regexOp(c, p, false),
  sql_every_table_has: sqlEveryTableHas,
  workflow_uses_pinned_sha: workflowUsesPinnedSha,
  workflow_permissions: workflowPermissions,
  version_in_table: versionInTable,
  // json_value is in the op list of the design and not built: no check needs it yet.
};
