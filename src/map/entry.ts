// Builds one EntryPoint from a registration: runs the body analysis and adds the tags and the stable id.
import type { Confidence, EntryKind, EntryPoint } from '../types/index.ts';
import { testCodeReason } from '../report/test-code.ts';
import { analyze, type Analysis, type FileView, type Spec } from './analyze.ts';
import type { Repo } from './repo.ts';
import { ADMIN_PATH, AUTH_ENDPOINT, PUBLIC_PATH } from './vocab.ts';

export interface Seed {
  kind: EntryKind; framework: string;
  file: string; line: number;               // where the entry point is declared (the registration)
  method: string | null; path: string | null; name: string | null;
  confidence: Confidence;
  handlerView: FileView; spec: Spec;        // the handler body to read, and what to read it with
  tags?: string[];
  analysis?: Analysis;                      // the body already read (Go, Ruby and PHP use light.ts)
}

const STATE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const WEBHOOK_HEADER = /[xX]-[\w-]*[sS]ignature|stripe-signature|paystack-signature|svix-signature|webhook-signature|HTTP_X_\w*SIGNATURE|x-hub-signature/i;

// Path text with every parameter style written :name, and catch-alls written *name.
export function normPath(p: string): string {
  return p
    .replace(/\[\[?\.\.\.(\w+)\]?\]/g, '*$1').replace(/\[(\w+)\]/g, ':$1')
    .replace(/<(?:[\w.]+:)?(\w+)>/g, ':$1').replace(/\{(\w+)(?::[^}]*)?\}/g, ':$1')
    .replace(/\(\?P<(\w+)>[^)]*\)/g, ':$1')
    .replace(/\/{2,}/g, '/');
}
export function joinPath(prefix: string, path: string): string {
  const j = `${prefix.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
  return normPath(j === '/' ? '/' : j.replace(/\/+$/, '') || '/');
}

export function makeEntry(repo: Repo, s: Seed): EntryPoint {
  const hv = s.handlerView;
  const a = s.analysis ?? analyze(hv, s.spec, repo.helpers(hv.lang));
  const pathText = `${s.path ?? ''} ${s.name ?? ''}`;
  const handlerText = hv.text.slice(s.spec.start, s.spec.end);
  const hasSig = a.protections.some((p) => p.kind === 'signature_verify' && p.confidence === 'high' && /signature verify|hmac|svix/.test(p.via));
  const webhook = s.kind === 'webhook' || (s.kind === 'http_route' && (/webhook/i.test(pathText) || /(^|\/)webhooks?(\/|\.|$)/i.test(s.file) || WEBHOOK_HEADER.test(handlerText) || hasSig && /hook/i.test(`${s.file} ${pathText}`)));
  const kind: EntryKind = webhook ? 'webhook' : s.kind;
  const method = s.method;
  const tags = new Set<string>(s.tags ?? []);
  if (webhook) tags.add('webhook');
  const nameIsHandler = s.path === null || ['flask', 'fastapi', 'django', 'nest', 'quart', 'sanic', 'next-app', 'next-pages'].includes(s.framework);
  if (AUTH_ENDPOINT.test(s.path ?? '') || (nameIsHandler && s.framework !== 'next-app' && AUTH_ENDPOINT.test((s.name ?? '').replace(/([a-z])([A-Z])/g, '$1_$2')))) tags.add('auth_endpoint');
  if (ADMIN_PATH.test(s.path ?? '') || ADMIN_PATH.test(s.file)) tags.add('admin');
  if (PUBLIC_PATH.test(s.path ?? '')) tags.add('public');
  if (a.reads.some((r) => r.source === 'file')) tags.add('upload');
  const writes = a.data.some((d) => d.op === 'write' || d.op === 'delete');
  if (kind === 'server_action' || (method && STATE_METHODS.has(method)) || ((method === 'ANY' || method === null) && (writes || a.reads.some((r) => r.source === 'body' || r.source === 'form')) && (kind === 'http_route' || kind === 'webhook'))) tags.add('state_changing');
  const clientPage = s.kind === 'page' && /^\s*(?:\/\/[^\n]*\n\s*)*['"]use client['"]/.test(hv.text.slice(0, 400));
  if (clientPage) tags.add('client_component');
  const handler = hv.file === s.file && s.spec.start >= 0 && hv.lines.at(s.spec.start) === s.line ? null : { file: hv.file, line: hv.lines.at(s.spec.start) };
  return {
    id: `${s.file}:${s.line}:${kind}:${method ?? '-'}:${s.path ?? '-'}:${s.name ?? '-'}`,
    kind, framework: s.framework, file: s.file, line: s.line,
    end_line: hv.lines.at(Math.max(s.spec.start, s.spec.end - 1)),
    method, path: s.path, name: s.name, handler, confidence: s.confidence,
    test_code: testCodeReason(s.file) !== null, tags: [...tags].sort(),
    protections: clientPage ? [] : a.protections, reads: clientPage ? [] : a.reads, data: clientPage ? [] : a.data, outbound: clientPage ? [] : a.outbound,
  };
}

// Parameter names of the function whose "(" is at `open` in masked text: plain names and the names inside destructuring.
export function paramNames(masked: string, open: number): string[] {
  let depth = 0;
  let end = open;
  for (let i = open; i < masked.length; i++) { const c = masked[i]; if (c === '(') depth++; else if (c === ')') { depth--; if (depth === 0) { end = i; break; } } }
  const inner = masked.slice(open + 1, end).replace(/:[^,={}()]*(?:<[^>]*>)?/g, ' ').replace(/=[^,}]*/g, ' ');
  const out: string[] = [];
  for (const m of inner.matchAll(/(?<![.\w$@])([A-Za-z_$][\w$]*)/g)) if (!['async', 'this', 'self', 'cls'].includes(m[1])) out.push(m[1]);
  return out;
}

// What one extractor returns for one file. A mount says "routes registered in `target` live under `prefix`".
import type { Gate, Protection } from '../types/index.ts';
export interface Mount { from: string; line: number; prefix: string; target: string; protections: Protection[] }
export interface Extracted { entries: EntryPoint[]; gates: Gate[]; mounts: Mount[] }
export const empty = (): Extracted => ({ entries: [], gates: [], mounts: [] });
