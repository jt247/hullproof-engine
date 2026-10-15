// The step executor. It turns a validated spec into HTTP requests against one local address and records what came back. It runs
// inside the sandbox (through exec-main.ts), next to the app, so the request never leaves the sandbox network. Imports only
// node built ins and spec.ts. Responses are stored in redacted form and every assertion is judged on that stored form, so a replay
// from the stored transcript reaches the same verdict with no sandbox.
import type { Json } from '../types/hunt.ts';
import type { RunOutcome, Spec, SpecStep, StepRecord } from '../types/prove.ts';
import { canon, evalAssertion, fill, fillJson, pathGet, SECRET_NAME, sha256, type Vars } from './spec.ts';

export const LIMITS = { requestMs: 8000, bodyChars: 16384, textStore: 4096 } as const;
const HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

// The one place an address is accepted. Anything that is not the sandbox's own loopback is refused before a request is built.
export function loopbackBase(url: string): URL {
  let u: URL;
  try { u = new URL(url); } catch { throw new Error(`refused: ${JSON.stringify(url).slice(0, 80)} is not an address`); }
  if (u.protocol !== 'http:' || !HOSTS.has(u.hostname) || u.username || u.password || !u.port || u.pathname !== '/' || u.search || u.hash) {
    throw new Error(`refused: ${u.origin} is not a loopback address of the sandbox (http://127.0.0.1:PORT only)`);
  }
  return u;
}

const JWT = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
const LONG = /\b[A-Fa-f0-9]{40,}\b|\b[A-Za-z0-9_]{32,}\b/g;
export const redactText = (s: string): string => s.replace(JWT, '[redacted]').replace(LONG, '[redacted]');
export function redactJson(v: Json, key = ''): Json {
  if (SECRET_NAME.test(key) && v !== null && typeof v !== 'object') return '[redacted]';
  if (typeof v === 'string') return redactText(v);
  if (Array.isArray(v)) return v.map((x) => redactJson(x, key));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, redactJson(x, k)]));
  return v;
}

// What is kept of a response header: a short allow list. No cookie, no authorization, nothing that could hold a credential.
const KEEP = new Set(['content-type', 'location', 'cache-control', 'www-authenticate', 'access-control-allow-origin', 'x-content-type-options']);

function judgeStep(spec: Spec, s: SpecStep, rec: StepRecord, vars: Vars, secrets: ReadonlySet<string>): void {
  rec.assertions = rec.response ? s.assert.map((a) => evalAssertion(rec.response!, a, vars, secrets)) : [];
}

export interface Judgement { done: boolean; outcome: RunOutcome | null; detail: string }

// One verdict function for the live run and for a replay. Reads only the stored records.
export function judge(spec: Spec, recs: StepRecord[]): Judgement & { recs: StepRecord[] } {
  const vars: Vars = {};
  const secrets = new Set<string>();
  const out: StepRecord[] = [];
  for (let i = 0; i < recs.length; i++) {
    const s = spec.steps[i];
    const rec = recs[i];
    if (!s || rec.id !== s.id) return { done: true, outcome: 'error', detail: `the stored step ${i + 1} does not match the spec`, recs: out };
    for (const c of s.captures ?? []) if (SECRET_NAME.test(c.name) || SECRET_NAME.test(c.path ?? '')) secrets.add(c.name);
    const r = { ...rec, assertions: [...rec.assertions] };
    judgeStep(spec, s, r, vars, secrets);
    out.push(r);
    Object.assign(vars, rec.captures);
    const failed = r.assertions.find((a) => !a.ok);
    if (rec.error && !(failed && s.phase !== 'attack')) return { done: true, outcome: 'error', detail: `step ${s.id}: ${rec.error}`, recs: out };
    if (s.phase === 'setup' && failed) return { done: true, outcome: 'invalid', detail: `setup step ${s.id} did not hold (${failed.desc}), so the harness or the seed is not working`, recs: out };
    if (s.phase === 'control' && failed) return { done: true, outcome: 'invalid', detail: `positive control failed at step ${s.id} (${failed.desc}), so nothing can be said about the flaw`, recs: out };
    if (s.phase === 'attack' && failed) return { done: true, outcome: 'not_proven', detail: `the app refused as it should at step ${s.id} (${failed.desc} did not hold)`, recs: out };
  }
  if (recs.length === spec.steps.length) return { done: true, outcome: 'proven', detail: 'the positive control passed and every attack assertion held', recs: out };
  return { done: false, outcome: null, detail: '', recs: out };
}

const parseJson = (t: string): Json | undefined => { try { return JSON.parse(t) as Json; } catch { return undefined; } };

export interface ExecOptions { baseUrl: string; fetchFn?: typeof fetch; requestMs?: number }

// Runs the steps in order and stops as soon as the verdict is known. Returns the redacted records and the verdict.
export async function executeSpec(spec: Spec, o: ExecOptions): Promise<{ outcome: RunOutcome; detail: string; steps: StepRecord[] }> {
  const base = loopbackBase(o.baseUrl);
  const f = o.fetchFn ?? fetch;
  const vars: Vars = {};
  const secrets = new Set<string>();
  const recs: StepRecord[] = [];
  for (const s of spec.steps) {
    for (const c of s.captures ?? []) if (SECRET_NAME.test(c.name) || SECRET_NAME.test(c.path ?? '')) secrets.add(c.name);
    const rec: StepRecord = { id: s.id, phase: s.phase, actor: s.actor, error: null, request: { method: s.method, path: s.path, headers: {}, body: null }, response: null, captures: {}, assertions: [] };
    try {
      const path = fill(s.path, vars, secrets, false);
      if (!path.startsWith('/') || path.startsWith('//')) throw new Error('the path became something other than a path on the app');
      // The actor's headers apply once every variable in them has been captured (an actor that is not signed in yet sends none).
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(spec.actors[s.actor]?.headers ?? {})) { try { headers[k] = fill(v, vars, secrets, false); } catch { /* not signed in yet */ } }
      for (const [k, v] of Object.entries(s.headers ?? {})) headers[k] = fill(v, vars, secrets, false);
      const body = s.body ? fillJson(s.body, vars, secrets, false) : null;
      if (body && !headers['content-type']) headers['content-type'] = 'application/json';
      rec.request = {
        method: s.method, path: fill(s.path, vars, secrets, true),
        headers: Object.fromEntries(Object.entries({ ...(spec.actors[s.actor]?.headers ?? {}), ...(s.headers ?? {}) }).map(([k, v]) => [k, SECRET_NAME.test(k) ? '[redacted]' : v]).sort(([a], [b]) => (a < b ? -1 : 1))),
        body: s.body ? redactJson(fillJson(s.body, vars, secrets, true)) : null,
      };
      const res = await f(new URL(path, base), { method: s.method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual', signal: AbortSignal.timeout(o.requestMs ?? LIMITS.requestMs) });
      const full = (await res.text()).slice(0, LIMITS.bodyChars + 1);
      const truncated = full.length > LIMITS.bodyChars;
      const text = full.slice(0, LIMITS.bodyChars);
      const rawJson = truncated ? undefined : parseJson(text);
      const rh: Record<string, string> = {};
      res.headers.forEach((v, k) => { if (KEEP.has(k.toLowerCase())) rh[k.toLowerCase()] = redactText(v); });
      rec.response = {
        status: res.status, headers: rh, truncated,
        json: rawJson === undefined ? undefined : redactJson(rawJson),
        text: rawJson === undefined ? redactText(text).slice(0, LIMITS.textStore) : undefined,
      };
      // Captures read the raw response. What is stored is redacted. A capture that finds nothing is an error, but a failed assertion
      // on the same step is reported first (a failed sign in is an invalid setup, not a broken run).
      for (const c of s.captures ?? []) {
        const v: Json | undefined = c.from === 'status' ? res.status : c.from === 'header' ? (res.headers.get(c.path!) ?? undefined) : pathGet(rawJson, c.path!);
        if (v === undefined || (typeof v === 'object' && v !== null)) { rec.error ??= `capture ${c.name} found nothing at ${c.from} ${c.path ?? ''}`.trim(); continue; }
        vars[c.name] = v;
        rec.captures[c.name] = secrets.has(c.name) ? '[redacted]' : redactJson(v);
      }
    } catch (e) {
      rec.error = (e as Error).name === 'TimeoutError' ? 'the request timed out' : (e as Error).message.slice(0, 200);
    }
    recs.push(rec);
    const j = judge(spec, recs);
    recs[recs.length - 1] = j.recs[j.recs.length - 1];
    if (j.done) return { outcome: j.outcome!, detail: j.detail, steps: recs };
  }
  const j = judge(spec, recs);
  return { outcome: j.outcome ?? 'error', detail: j.detail, steps: recs };
}

// The record stored for one run. The hash covers every other field.
export function runRecord(spec: Spec, specSha: string, run: number, r: { outcome: RunOutcome; detail: string; steps: StepRecord[] }): import('../types/prove.ts').RunRecord {
  const body = { schema_version: '1.0.0' as const, spec_id: spec.spec_id, spec_sha256: specSha, run, outcome: r.outcome, detail: r.detail, steps: r.steps };
  return { ...body, transcript_sha256: sha256(canon(body)) };
}
