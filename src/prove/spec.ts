// The test spec language of the proof sandbox: validation, templates and assertions. A spec is data. The engine runs it; no model
// written code ever runs. This file has no imports beyond types, because the same file runs inside the sandbox (see exec-main.ts).
import { createHash } from 'node:crypto';
import type { Json } from '../types/hunt.ts';
import type { Assertion, Spec, SpecStep, StepRecord } from '../types/prove.ts';

export const SPEC_LIMITS = { steps: 24, actors: 6, assertions: 8, captures: 4, body: 4096, header: 512, text: 300, path: 300, idLen: 40 } as const;
const ID = /^[a-z][a-z0-9_]{0,39}$/;
const VAR = /\{\{([a-z][a-z0-9_]{0,39})\}\}/g;
// A path on the app itself: a slash first, no scheme, no host, no dot dot, no backslash. Templates are allowed.
const PATH = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/?#\-{}]*$/;
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];
const HEADER_DENY = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'expect', 'upgrade', 'te', 'trailer', 'keep-alive']);
const HEADER_DENY_PREFIX = ['proxy-', 'sec-', 'x-forwarded-', 'x-real-ip'];
// Strings that look built to damage data, read files or run code. A guard against a bad spec, not a boundary: the sandbox is the boundary.
const HARMFUL = /\b(?:drop|truncate|alter)\s+(?:table|database|schema)\b|\bdelete\s+from\b|\bunion\s+select\b|\brm\s+-|\bshutdown\b|;\s*--|\$\(|`|\.\.[\\/]|<script|\bexec\s*\(|\bcurl\s|\bwget\s/i;
export const SECRET_NAME = /(?:pass(?:word|wd)?|secret|token|api[_-]?key|authorization|cookie|session|bearer|jwt|credential|private)/i;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

// Sorted keys, no spaces: the form every hash in this phase is taken over.
export function canon(v: unknown): string {
  const sort = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(sort);
    if (isObj(x)) { const o: Record<string, unknown> = {}; for (const k of Object.keys(x).sort()) if (x[k] !== undefined) o[k] = sort(x[k]); return o; }
    return x;
  };
  return JSON.stringify(sort(v));
}
export const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex');
export const specSha256 = (s: Spec): string => sha256(canon(s));

export function varsIn(text: string): string[] { return [...text.matchAll(VAR)].map((m) => m[1]); }

function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => strings(x, out));
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) { out.push(k); strings(x, out); }
  return out;
}
function keysOf(v: unknown, out: string[] = []): string[] {
  if (Array.isArray(v)) v.forEach((x) => keysOf(x, out));
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) { out.push(k); keysOf(x, out); }
  return out;
}

export type SpecCheck = { ok: true; spec: Spec } | { ok: false; errors: string[] };

function checkHeaders(h: unknown, where: string, err: (m: string) => void): Record<string, string> | undefined {
  if (h === undefined) return undefined;
  if (!isObj(h)) { err(`${where}: headers must be an object`); return undefined; }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    const name = k.toLowerCase();
    if (!/^[a-z][a-z0-9-]{0,39}$/.test(name)) { err(`${where}: header name ${JSON.stringify(k).slice(0, 40)} is not allowed`); continue; }
    if (HEADER_DENY.has(name) || HEADER_DENY_PREFIX.some((p) => name.startsWith(p))) { err(`${where}: header ${name} may not be set`); continue; }
    if (typeof v !== 'string' || v.length > SPEC_LIMITS.header || /[\u0000-\u001f\u007f]/.test(v)) { err(`${where}: header ${name} must be a short single line string`); continue; }
    out[name] = v;
  }
  return out;
}

function checkAssertion(a: unknown, where: string, err: (m: string) => void): Assertion | null {
  if (!isObj(a) || typeof a.kind !== 'string') { err(`${where}: an assertion needs a kind`); return null; }
  const text = (x: unknown): x is string => typeof x === 'string' && x.length > 0 && x.length <= SPEC_LIMITS.text;
  if (a.kind === 'status') {
    const ok = (n: unknown): boolean => Number.isInteger(n) && (n as number) >= 100 && (n as number) <= 599;
    if (a.op === 'in' ? !(Array.isArray(a.value) && a.value.length > 0 && a.value.length <= 8 && a.value.every(ok)) : !((a.op === 'eq' || a.op === 'ne') && ok(a.value))) { err(`${where}: a status assertion needs op eq, ne or in and status codes`); return null; }
    return { kind: 'status', op: a.op as 'eq' | 'ne' | 'in', value: a.value as number | number[] };
  }
  if (a.kind === 'json') {
    if (typeof a.path !== 'string' || !/^[A-Za-z0-9_$-]+(?:\.[A-Za-z0-9_$-]+)*$/.test(a.path) || a.path.length > 120) { err(`${where}: a json assertion needs a dotted path such as items.0.owner`); return null; }
    if (SECRET_NAME.test(a.path)) { err(`${where}: an assertion may not read a field named like a secret (${a.path}); it is redacted in the transcript`); return null; }
    if (!['eq', 'ne', 'contains', 'exists', 'absent'].includes(String(a.op))) { err(`${where}: a json assertion needs op eq, ne, contains, exists or absent`); return null; }
    const needs = a.op === 'eq' || a.op === 'ne' || a.op === 'contains';
    const v = a.value;
    if (needs && !(typeof v === 'string' ? v.length <= SPEC_LIMITS.text : typeof v === 'number' || typeof v === 'boolean' || v === null)) { err(`${where}: a json ${a.op} assertion needs a value`); return null; }
    return { kind: 'json', path: a.path, op: a.op as 'eq', ...(needs ? { value: v as string } : {}) };
  }
  if (a.kind === 'text') {
    if ((a.op !== 'contains' && a.op !== 'absent') || !text(a.value)) { err(`${where}: a text assertion needs op contains or absent and a value`); return null; }
    return { kind: 'text', op: a.op, value: a.value };
  }
  if (a.kind === 'header') {
    if (typeof a.name !== 'string' || !/^[A-Za-z][A-Za-z0-9-]{0,39}$/.test(a.name) || SECRET_NAME.test(a.name)) { err(`${where}: a header assertion needs a plain header name that is not a secret`); return null; }
    if (!['eq', 'contains', 'exists', 'absent'].includes(String(a.op))) { err(`${where}: a header assertion needs op eq, contains, exists or absent`); return null; }
    const needs = a.op === 'eq' || a.op === 'contains';
    if (needs && !text(a.value)) { err(`${where}: a header ${a.op} assertion needs a value`); return null; }
    return { kind: 'header', name: a.name.toLowerCase(), op: a.op as 'eq', ...(needs ? { value: a.value as string } : {}) };
  }
  err(`${where}: unknown assertion kind`);
  return null;
}

// True when an attack assertion shows something got through: a 2xx status or a value that is there.
const exposes = (a: Assertion): boolean =>
  (a.kind === 'status' && (a.op === 'eq' || a.op === 'in') && [a.value].flat().every((n) => n >= 200 && n < 300)) ||
  (a.kind === 'json' && (a.op === 'eq' || a.op === 'contains' || a.op === 'exists')) || (a.kind === 'text' && a.op === 'contains');
const succeeds = (a: Assertion): boolean => a.kind === 'status' && (a.op === 'eq' || a.op === 'in') && [a.value].flat().every((n) => n >= 200 && n < 300);

// Validates a spec read from JSON. Returns a clean copy (unknown keys dropped) or every problem found. The positive control rule is
// here: a spec with no control step that must succeed, placed before the attack, is invalid.
export function validateSpec(raw: unknown): SpecCheck {
  const errors: string[] = [];
  const err = (m: string): void => { errors.push(m); };
  if (!isObj(raw)) return { ok: false, errors: ['the spec must be a JSON object'] };
  if (raw.schema_version !== '1.0.0') err('schema_version must be "1.0.0"');
  const str = (k: string, max: number): string => { const v = raw[k]; if (typeof v !== 'string' || !v.trim() || v.length > max) { err(`${k} is missing or too long`); return ''; } return v.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim(); };
  const spec_id = str('spec_id', SPEC_LIMITS.idLen);
  if (spec_id && !ID.test(spec_id)) err('spec_id must be lowercase letters, digits and underscores');
  const title = str('title', 160);
  const claim = str('claim', 500);
  const lead_key = raw.lead_key === null || raw.lead_key === undefined ? null : typeof raw.lead_key === 'string' && raw.lead_key.length <= 400 ? raw.lead_key : (err('lead_key must be a string or null'), null);
  const t = raw.target;
  let target = { entry_point: '', file: '', line: 1 };
  if (isObj(t) && typeof t.entry_point === 'string' && t.entry_point && t.entry_point.length <= 300 && typeof t.file === 'string' && t.file && t.file.length <= 300 && Number.isInteger(t.line) && (t.line as number) >= 1) target = { entry_point: t.entry_point, file: t.file, line: t.line as number };
  else err('target needs entry_point, file and line');
  const req = raw.requirement_ids;
  const requirement_ids = Array.isArray(req) && req.length <= 6 && req.every((r) => typeof r === 'string' && /^SEC-[A-Z]+-\d{3}$/.test(r)) ? [...new Set(req as string[])].sort() : (err('requirement_ids must be a list of at most 6 ids like SEC-API-001 (it may be empty)'), []);

  const actors: Spec['actors'] = {};
  if (!isObj(raw.actors) || !Object.keys(raw.actors).length || Object.keys(raw.actors).length > SPEC_LIMITS.actors) err(`actors needs 1 to ${SPEC_LIMITS.actors} entries`);
  else {
    for (const [name, a] of Object.entries(raw.actors)) {
      if (!ID.test(name)) { err(`actor name ${JSON.stringify(name).slice(0, 30)} is not allowed`); continue; }
      if (!isObj(a)) { err(`actor ${name} must be an object`); continue; }
      const h = checkHeaders(a.headers, `actor ${name}`, err);
      actors[name] = h ? { headers: h } : {};
    }
  }

  const steps: SpecStep[] = [];
  if (!Array.isArray(raw.steps) || raw.steps.length < 2 || raw.steps.length > SPEC_LIMITS.steps) err(`steps needs 2 to ${SPEC_LIMITS.steps} entries`);
  else {
    const ids = new Set<string>();
    raw.steps.forEach((s, i) => {
      const w = `step ${i + 1}`;
      if (!isObj(s)) return err(`${w}: must be an object`);
      if (typeof s.id !== 'string' || !ID.test(s.id) || ids.has(s.id)) return err(`${w}: id must be unique lowercase letters, digits and underscores`);
      ids.add(s.id);
      if (s.phase !== 'setup' && s.phase !== 'control' && s.phase !== 'attack') return err(`${w}: phase must be setup, control or attack`);
      if (typeof s.actor !== 'string' || !(s.actor in actors)) return err(`${w}: actor is not declared in actors`);
      if (typeof s.method !== 'string' || !METHODS.includes(s.method)) return err(`${w}: method must be one of ${METHODS.join(', ')}`);
      if (typeof s.path !== 'string' || s.path.length > SPEC_LIMITS.path || !PATH.test(s.path) || s.path.includes('..')) return err(`${w}: path must start with one slash and name a path on the app, never a host or address`);
      const headers = checkHeaders(s.headers, w, err);
      let body: SpecStep['body'] = null;
      if (s.body !== undefined && s.body !== null) {
        if (!isObj(s.body) || canon(s.body).length > SPEC_LIMITS.body) return err(`${w}: body must be a small JSON object`);
        body = s.body as { [k: string]: Json };
        if (s.method === 'GET' || s.method === 'HEAD') return err(`${w}: a ${s.method} request has no body`);
      }
      const captures: SpecStep['captures'] = [];
      if (s.captures !== undefined) {
        if (!Array.isArray(s.captures) || s.captures.length > SPEC_LIMITS.captures) return err(`${w}: captures needs at most ${SPEC_LIMITS.captures} entries`);
        for (const c of s.captures) {
          if (!isObj(c) || typeof c.name !== 'string' || !ID.test(c.name) || !['json', 'header', 'status'].includes(String(c.from))) return err(`${w}: a capture needs a name and from json, header or status`);
          if (c.from !== 'status' && (typeof c.path !== 'string' || !c.path || c.path.length > 120)) return err(`${w}: a ${String(c.from)} capture needs a path`);
          captures.push({ name: c.name, from: c.from as 'json', ...(c.from === 'status' ? {} : { path: c.path as string }) });
        }
      }
      if (!Array.isArray(s.assert) || s.assert.length > SPEC_LIMITS.assertions) return err(`${w}: assert needs a list of at most ${SPEC_LIMITS.assertions} assertions`);
      const assert = s.assert.map((a) => checkAssertion(a, w, err)).filter((a): a is Assertion => a !== null);
      steps.push({ id: s.id, phase: s.phase, actor: s.actor, method: s.method as SpecStep['method'], path: s.path, ...(headers ? { headers } : {}), ...(body ? { body } : {}), ...(captures.length ? { captures } : {}), assert });
    });
  }

  // Only words the spec can supply from an earlier capture: a variable must be captured before the step that uses it.
  const known = new Set<string>();
  const secretVars = new Set<string>();
  for (const s of steps) {
    const used = [...varsIn(s.path), ...Object.values(s.headers ?? {}).flatMap(varsIn), ...strings(s.body).flatMap(varsIn), ...s.assert.flatMap((a) => ('value' in a && typeof a.value === 'string' ? varsIn(a.value) : []))];
    for (const v of new Set(used)) if (!known.has(v)) errors.push(`step ${s.id}: {{${v}}} is used before any step captures it`);
    for (const a of s.assert) if ('value' in a && typeof a.value === 'string') for (const v of varsIn(a.value)) if (secretVars.has(v)) errors.push(`step ${s.id}: an assertion may not compare with {{${v}}}, a secret that is redacted in the transcript`);
    for (const c of s.captures ?? []) { known.add(c.name); if (SECRET_NAME.test(c.name) || SECRET_NAME.test(c.path ?? '')) secretVars.add(c.name); }
  }
  for (const [n, a] of Object.entries(actors)) for (const v of Object.values(a.headers ?? {}).flatMap(varsIn)) if (!steps.some((s) => s.captures?.some((c) => c.name === v))) errors.push(`actor ${n}: {{${v}}} is never captured`);

  // Harmless payloads only.
  for (const s of steps) {
    const all = [s.path, ...Object.values(s.headers ?? {}), ...strings(s.body), ...s.assert.flatMap((a) => ('value' in a && typeof a.value === 'string' ? [a.value] : []))];
    if (all.some((x) => HARMFUL.test(x))) errors.push(`step ${s.id}: payload_not_harmless: the request holds text built to damage data, read files or run code. Use canary strings and read style requests.`);
    for (const k of keysOf(s.body)) if (HARMFUL.test(k)) errors.push(`step ${s.id}: payload_not_harmless in a body key`);
  }

  // The positive control rule.
  const firstAttack = steps.findIndex((s) => s.phase === 'attack');
  const firstControl = steps.findIndex((s) => s.phase === 'control');
  if (steps.length && firstAttack < 0) errors.push('a spec needs at least one attack step');
  if (steps.length && (firstControl < 0 || (firstAttack >= 0 && firstControl > firstAttack))) errors.push('positive control missing: a control step that must succeed has to come before the first attack step');
  else if (!steps.some((s) => s.phase === 'control' && s.assert.some(succeeds))) errors.push('positive control missing: a control step needs a status assertion with a 2xx code, so a working harness is shown first');
  for (const s of steps) if ((s.phase === 'control' || s.phase === 'attack') && !s.assert.length) errors.push(`step ${s.id}: a ${s.phase} step needs at least one assertion`);
  if (steps.some((s) => s.phase === 'attack') && !steps.filter((s) => s.phase === 'attack').some((s) => s.assert.some(exposes))) errors.push('an attack step has to assert what got through (a 2xx status or a value that is there); asserting a denial proves nothing');
  if (steps.length && steps.some((s, i) => s.phase === 'setup' && steps.slice(0, i).some((p) => p.phase !== 'setup'))) errors.push('setup steps come first');
  if (!isObj(raw.expect) || raw.expect.outcome !== 'flaw_present') err('expect.outcome must be "flaw_present"');

  if (errors.length) return { ok: false, errors };
  return { ok: true, spec: { schema_version: '1.0.0', spec_id, title, claim, lead_key, target, requirement_ids, actors, steps, expect: { outcome: 'flaw_present' } } };
}

// ---- templates ---------------------------------------------------------------------------------------------------------------------
export type Vars = Record<string, Json>;
// Replaces {{name}} with the captured value. A name that is not captured is an error. With `redact`, a secret variable shows as [redacted].
export function fill(text: string, vars: Vars, secrets: ReadonlySet<string>, redact: boolean): string {
  return text.replace(VAR, (_m, n: string) => {
    if (!(n in vars)) throw new Error(`unresolved variable ${n}`);
    if (redact && secrets.has(n)) return '[redacted]';
    const v = vars[n];
    return typeof v === 'string' ? v : JSON.stringify(v);
  });
}
export function fillJson(v: Json, vars: Vars, secrets: ReadonlySet<string>, redact: boolean): Json {
  if (typeof v === 'string') return fill(v, vars, secrets, redact);
  if (Array.isArray(v)) return v.map((x) => fillJson(x, vars, secrets, redact));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fillJson(x, vars, secrets, redact)]));
  return v;
}

// ---- assertions, evaluated on the stored form of a response (so a replay gives the same answer) -------------------------------------
export function pathGet(v: Json | undefined, path: string): Json | undefined {
  let cur: Json | undefined = v;
  for (const part of path.split('.')) {
    if (cur === null || cur === undefined) return undefined;
    if (Array.isArray(cur)) { if (!/^\d+$/.test(part)) return undefined; cur = cur[Number(part)]; }
    else if (typeof cur === 'object') cur = Object.prototype.hasOwnProperty.call(cur, part) ? cur[part] : undefined;
    else return undefined;
  }
  return cur;
}
const same = (a: Json | undefined, b: Json): boolean => canon(a) === canon(b);

export function evalAssertion(r: NonNullable<StepRecord['response']>, a: Assertion, vars: Vars, secrets: ReadonlySet<string>): { ok: boolean; desc: string } {
  const want = (s: string): string => fill(s, vars, secrets, true);
  if (a.kind === 'status') {
    const ok = a.op === 'eq' ? r.status === a.value : a.op === 'ne' ? r.status !== a.value : (a.value as number[]).includes(r.status);
    return { ok, desc: `status ${a.op} ${JSON.stringify(a.value)}` };
  }
  if (a.kind === 'json') {
    const got = pathGet(r.json, a.path);
    const w = a.value === undefined ? undefined : typeof a.value === 'string' ? want(a.value) : a.value;
    const ok = a.op === 'exists' ? got !== undefined : a.op === 'absent' ? got === undefined
      : got === undefined ? a.op === 'ne' && r.json !== undefined
      : a.op === 'eq' ? same(got, w as Json) || (typeof got === 'number' && typeof w === 'string' && String(got) === w)
      : a.op === 'ne' ? !(same(got, w as Json) || (typeof got === 'number' && typeof w === 'string' && String(got) === w))
      : typeof got === 'string' ? got.includes(String(w)) : Array.isArray(got) && got.some((x) => same(x, w as Json));
    return { ok, desc: `json ${a.path} ${a.op}${w === undefined ? '' : ' ' + JSON.stringify(w)}` };
  }
  if (a.kind === 'text') {
    const hay = r.text ?? (r.json === undefined ? '' : canon(r.json));
    const has = hay.includes(want(a.value));
    return { ok: a.op === 'contains' ? has : !has, desc: `body text ${a.op} ${JSON.stringify(a.value)}` };
  }
  const got = r.headers[a.name];
  const w = a.value === undefined ? undefined : want(a.value);
  const ok = a.op === 'exists' ? got !== undefined : a.op === 'absent' ? got === undefined : got !== undefined && (a.op === 'eq' ? got === w : got.includes(w!));
  return { ok, desc: `header ${a.name} ${a.op}${w === undefined ? '' : ' ' + JSON.stringify(w)}` };
}
