// Helpers for the checks that read the code map (docs/PHASE-2-DESIGN.md section 4). The map is built once per context.
import type { CheckEvidence, CodeMap, EntryPoint, Protection, ProtectionKind } from '../../types/index.ts';
import { buildCodeMap } from '../../map/build.ts';
import type { CheckContext } from '../context.ts';
import type { OpOutcome } from '../ops.ts';
import type { CodeCheck } from '../types.ts';

const cache = new WeakMap<CheckContext, CodeMap>();
export function getMap(ctx: CheckContext): CodeMap {
  let m = cache.get(ctx);
  if (!m) { m = buildCodeMap(ctx); cache.set(ctx, m); }
  return m;
}

// A protection that counts: not a weak guess, and not one the code is known to ignore.
export const counts = (p: Protection): boolean => p.confidence !== 'low' && p.enforced !== false;
export const has = (ep: EntryPoint, kind: ProtectionKind): boolean => ep.protections.some((p) => p.kind === kind && counts(p));
export const hasAuth = (ep: EntryPoint): boolean => has(ep, 'session_read') || has(ep, 'signature_verify');
export const weakAuth = (ep: EntryPoint): Protection | undefined => ep.protections.find((p) => p.kind === 'session_read' && !counts(p));

export const HANDLER_KINDS = new Set(['http_route', 'server_action', 'graphql_resolver', 'rpc']);
// Entry points the checks judge: shipped code, a kind that handles requests.
export const judged = (ep: EntryPoint): boolean => !ep.test_code && HANDLER_KINDS.has(ep.kind) && ep.framework !== 'django-admin';
export const stateChanging = (ep: EntryPoint): boolean => ep.tags.includes('state_changing') || (ep.kind === 'graphql_resolver' && ep.method === 'MUTATION') || (ep.kind === 'rpc' && ep.method === 'MUTATION');

// Evidence in the entry point's own file at the registration line, or, for a line inside the handler body (a data touch, an outbound
// call), in the file that holds the handler: a route registered in one file can have its handler in another.
export const ev = (ep: EntryPoint, note: string): CheckEvidence => ({ file: ep.file, line: ep.line, note });
export const evAt = (ep: EntryPoint, note: string, line: number): CheckEvidence => ({ file: ep.handler?.file ?? ep.file, line, note });

export const where = (ep: EntryPoint): string => `${ep.method && ep.method !== 'ANY' ? ep.method + ' ' : ''}${ep.path ?? ep.name ?? ep.file}`.trim();

export interface MapCheckSpec {
  id: string; sec_ids: string[]; name: string; source: string;
  // The entry points or records the check looks at. Zero candidates makes the check not applicable.
  candidates(map: CodeMap): number;
  // Evidence for everything that fails.
  fails(map: CodeMap, ctx: CheckContext): CheckEvidence[];
  none: string;                    // reason when there is nothing to judge
  pattern: string;                 // what was searched, for the absence record
  fixtures?: { pass: string; fail: string }; // when the check reads facts the shared map fixtures do not hold
}

export function mapCheck(s: MapCheckSpec): CodeCheck {
  return {
    id: s.id, sec_ids: s.sec_ids, applies_when: {}, op: 'code', on_true: 'NOT ASSESSED: NEEDS DYNAMIC TEST', on_false: 'FAIL',
    fixtures: s.fixtures ?? { pass: 'test/fixtures/map/pass', fail: 'test/fixtures/map/fail' }, source: s.source,
    run: (ctx): OpOutcome => {
      const map = getMap(ctx);
      const n = s.candidates(map);
      if (n === 0) return { value: 'not_applicable', reason: s.none, evidence: [], absence: null };
      const bad = s.fails(map, ctx).sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || (a.line ?? 0) - (b.line ?? 0) || (a.note < b.note ? -1 : a.note > b.note ? 1 : 0));
      return { value: bad.length === 0, evidence: bad, absence: { pattern: s.pattern, files_searched: n, file_globs: ['codemap.json'], matches: bad.length } };
    },
  };
}

// The text of an entry point's handler, with `above` lines before it (decorators and route options sit above).
export function handlerText(ctx: CheckContext, ep: EntryPoint, above = 0): string {
  const file = ep.handler?.file ?? ep.file;
  const start = ep.handler?.line ?? ep.line;
  return ctx.text(file).split('\n').slice(Math.max(0, start - 1 - above), Math.max(start, ep.end_line)).join('\n');
}
