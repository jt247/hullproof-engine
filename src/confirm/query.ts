// A small declarative query language over codemap.json, and its runner. A model proposes a query; the engine runs it. It has
// no regular expressions and no code, so a query cannot loop or run anything. See docs/INTERFACES.md, section 13.
import type { CodeMap, Cond, EntryPoint, Json, LeadStep, Query } from '../types/index.ts';

export const MAX_DEPTH = 8;
export const MAX_NODES = 60;
export const WITNESS_SLACK = 2;       // a fact counts when its line is within this many lines of a cited line
export const TOO_BROAD_MIN = 3;       // a query that matches every entry point of a map this large proves nothing
const OPS = new Set(['eq', 'ne', 'in', 'contains', 'startsWith', 'exists', 'gt', 'lt']);
const FIELD = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const BAD_SEG = new Set(['__proto__', 'constructor', 'prototype']);
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const goodField = (f: unknown): f is string => typeof f === 'string' && FIELD.test(f) && !f.split('.').some((s) => BAD_SEG.has(s));

export function parseQuery(v: unknown): { ok: true; query: Query } | { ok: false; reason: string } {
  if (!isObj(v) || !('where' in v)) return { ok: false, reason: 'a query is {"where": condition}' };
  let nodes = 0;
  const cond = (c: unknown, depth: number): Cond | string => {
    if (depth > MAX_DEPTH) return `nested deeper than ${MAX_DEPTH}`;
    if (++nodes > MAX_NODES) return `more than ${MAX_NODES} conditions`;
    if (!isObj(c)) return 'a condition must be an object';
    for (const k of ['all', 'any'] as const) {
      if (k in c) {
        if (!Array.isArray(c[k]) || c[k].length === 0) return `${k} needs a non empty list`;
        const out: Cond[] = [];
        for (const x of c[k] as unknown[]) { const r = cond(x, depth + 1); if (typeof r === 'string') return r; out.push(r); }
        return k === 'all' ? { all: out } : { any: out };
      }
    }
    if ('not' in c) { const r = cond(c.not, depth + 1); return typeof r === 'string' ? r : { not: r }; }
    for (const k of ['some', 'none'] as const) {
      if (k in c) {
        if (!goodField(c[k])) return `${k} needs a field name`;
        let where: Cond | undefined;
        if (c.where !== undefined) { const r = cond(c.where, depth + 1); if (typeof r === 'string') return r; where = r; }
        return k === 'some' ? { some: c.some as string, ...(where ? { where } : {}) } : { none: c.none as string, ...(where ? { where } : {}) };
      }
    }
    if ('field' in c) {
      if (!goodField(c.field)) return 'field is not a plain dotted name';
      if (typeof c.op !== 'string' || !OPS.has(c.op)) return `op is one of ${[...OPS].join(', ')}`;
      const val = c.value as Json | undefined;
      const scalar = (x: unknown): boolean => x === null || ['string', 'number', 'boolean'].includes(typeof x);
      if (c.op === 'in' ? !Array.isArray(val) || !val.every(scalar) || val.length > 20 : c.op === 'exists' ? val !== undefined && typeof val !== 'boolean' : !scalar(val)) return `value does not fit op ${c.op}`;
      if ((c.op === 'gt' || c.op === 'lt') && typeof val !== 'number') return `${c.op} needs a number`;
      if ((c.op === 'startsWith') && typeof val !== 'string') return 'startsWith needs a string';
      return { field: c.field, op: c.op as 'eq', ...(val !== undefined ? { value: val } : {}) };
    }
    return 'a condition is all, any, not, some, none or field';
  };
  const r = cond(v.where, 1);
  return typeof r === 'string' ? { ok: false, reason: r } : { ok: true, query: { where: r } };
}

export interface Witness { file: string; line: number }
interface Ev { ok: boolean; w: Witness[] }
const NO: Ev = { ok: false, w: [] };

function pick(node: unknown, path: string): unknown {
  let cur = node;
  for (const seg of path.split('.')) {
    if (!isObj(cur) || !Object.hasOwn(cur, seg)) return undefined;
    cur = cur[seg];
  }
  return cur;
}

function compare(c: Extract<Cond, { field: string }>, node: unknown): boolean {
  const got = pick(node, c.field);
  const want = c.value;
  switch (c.op) {
    case 'exists': return (got !== undefined && got !== null) === (want !== false);
    case 'eq': return got === want;
    case 'ne': return got !== want;
    case 'in': return Array.isArray(want) && (want as unknown[]).includes(got);
    case 'contains': return Array.isArray(got) ? got.includes(want) : typeof got === 'string' && typeof want === 'string' && got.includes(want);
    case 'startsWith': return typeof got === 'string' && typeof want === 'string' && got.startsWith(want);
    case 'gt': return typeof got === 'number' && typeof want === 'number' && got > want;
    case 'lt': return typeof got === 'number' && typeof want === 'number' && got < want;
  }
}

function run(c: Cond, node: unknown, file: string): Ev {
  if ('all' in c) {
    const rs = c.all.map((x) => run(x, node, file));
    return rs.every((r) => r.ok) ? { ok: true, w: rs.flatMap((r) => r.w) } : NO;
  }
  if ('any' in c) {
    const rs = c.any.map((x) => run(x, node, file)).filter((r) => r.ok);
    return rs.length ? { ok: true, w: rs.flatMap((r) => r.w) } : NO;
  }
  if ('not' in c) return run(c.not, node, file).ok ? NO : { ok: true, w: [] };
  if ('some' in c || 'none' in c) {
    const f = 'some' in c ? c.some : c.none;
    const arr = pick(node, f);
    const items = Array.isArray(arr) ? arr : [];
    const hits = items.filter((it) => !c.where || run(c.where, it, isObj(it) && typeof it.file === 'string' ? it.file : file).ok);
    if ('none' in c) return hits.length === 0 ? { ok: true, w: [] } : NO;
    if (!hits.length) return NO;
    const w: Witness[] = [];
    for (const it of hits) if (isObj(it) && typeof it.line === 'number') w.push({ file: typeof it.file === 'string' ? it.file : file, line: it.line });
    return { ok: true, w };
  }
  return compare(c, node) ? { ok: true, w: [] } : NO;
}

export interface QueryOutcome { confirmed: boolean; detail: string; witnesses: Witness[] }

// Runs the query on the lead's entry point. The lead is confirmed only when the entry point matches and at least one fact the
// query matched (a data touch, a protection, a read or an outbound call) sits on or beside a line the lead cites. A query that
// matches every entry point of a map of TOO_BROAD_MIN or more proves nothing and is not accepted.
export function runQuery(map: CodeMap, q: Query, entryId: string, cited: LeadStep[]): QueryOutcome {
  const ep = map.entry_points.find((e) => e.id === entryId);
  if (!ep) return { confirmed: false, detail: 'the entry point is not in the code map', witnesses: [] };
  const at = (e: EntryPoint): Ev => run(q.where, e, e.handler?.file ?? e.file);
  const mine = at(ep);
  if (!mine.ok) return { confirmed: false, detail: 'the query does not match this entry point', witnesses: [] };
  const matched = map.entry_points.filter((e) => at(e).ok).length;
  if (map.entry_points.length >= TOO_BROAD_MIN && matched === map.entry_points.length) {
    return { confirmed: false, detail: `the query matches all ${matched} entry points, so it proves nothing about this one`, witnesses: [] };
  }
  const near = mine.w.filter((w) => cited.some((s) => s.file === w.file && Math.abs(s.line - w.line) <= WITNESS_SLACK));
  if (!near.length) return { confirmed: false, detail: 'no fact the query matched sits on a line the lead cites', witnesses: [] };
  const uniq = [...new Map(near.map((w) => [`${w.file}:${w.line}`, w])).values()].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  return { confirmed: true, detail: `the query matches this entry point and ${matched - 1} other of ${map.entry_points.length}; matched facts at ${uniq.map((w) => `${w.file}:${w.line}`).join(', ')}`, witnesses: uniq };
}
