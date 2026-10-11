// Checks that read entry points from the code map: what protects each one and what it touches. All start as leads
// (src/report/tiers.ts) until a measurement raises them. Each is a pattern over map facts, so a FAIL is a place to look.
import { fileURLToPath } from 'node:url';
import type { EntryPoint } from '../../types/index.ts';
import type { CodeCheck } from '../types.ts';
import { ev, evAt, has, hasAuth, judged, mapCheck, stateChanging, weakAuth, where } from './shared.ts';

const source = fileURLToPath(import.meta.url);
const exempt = (ep: EntryPoint): boolean => ep.tags.includes('auth_endpoint') || ep.tags.includes('public') || ep.tags.includes('webhook');
const SENSITIVE = /user|account|profile|customer|member|order|payment|invoice|billing|card|address|email|message|note|file|upload|document|ticket|booking|patient|wallet|session|token|credential|subscription|contact|secret|key|transaction|history|log/i;

export const mutatingRouteWithoutAuth = mapCheck({
  id: 'check.map.mutating-route-without-auth', sec_ids: ['SEC-API-001'], name: 'mutating-route-without-auth', source,
  pattern: 'a state changing entry point with no session read on the handler, a wrapper, the router or a gate',
  none: 'the code map has no state changing entry point',
  candidates: (m) => m.entry_points.filter((e) => judged(e) && stateChanging(e)).length,
  fails: (m) => m.entry_points.filter((e) => judged(e) && stateChanging(e) && !exempt(e) && !hasAuth(e)).map((e) => {
    const weak = weakAuth(e);
    return ev(e, `${where(e)} changes state and no session read is reachable on it${weak ? ` (only a weak sign: ${weak.via} at ${weak.file}:${weak.line})` : ''}`);
  }),
});

export const dataReadWithoutAuth = mapCheck({
  id: 'check.map.data-read-without-auth', sec_ids: ['SEC-API-001', 'SEC-DATA-024'], name: 'data-read-without-auth', source,
  pattern: 'a GET entry point that reads a table with a personal data name and has no session read',
  none: 'the code map has no GET entry point that reads a data store',
  candidates: (m) => m.entry_points.filter((e) => judged(e) && e.kind === 'http_route' && e.method !== 'POST' && e.data.some((d) => d.op === 'read')).length,
  fails: (m) => m.entry_points.filter((e) => judged(e) && e.kind === 'http_route' && (e.method === 'GET' || e.method === 'HEAD' || e.method === 'ANY' || e.method === null) && !exempt(e) && !hasAuth(e)).flatMap((e) => {
    const d = e.data.find((x) => x.op === 'read' && x.target && SENSITIVE.test(x.target) && x.store !== 'filesystem');
    return d ? [evAt(e, `${where(e)} reads ${d.target} and no session read is reachable on it`, d.line)] : [];
  }),
});

export const writeByIdWithoutOwner = mapCheck({
  id: 'check.map.write-by-id-without-owner', sec_ids: ['SEC-AUTHZ-003'], name: 'write-by-id-without-owner', source,
  pattern: 'an update or delete filtered by an id from the request with no owner, user or tenant value from the session',
  none: 'the code map has no update or delete by id',
  candidates: (m) => m.entry_points.filter((e) => judged(e) && e.data.some((d) => (d.op === 'write' || d.op === 'delete') && d.by_id)).length,
  fails: (m) => m.entry_points.filter((e) => judged(e) && e.kind !== 'webhook' && !has(e, 'role_check')).flatMap((e) =>
    e.data.filter((d) => (d.op === 'write' || d.op === 'delete') && d.by_id && !d.owner_scoped).map((d) => evAt(e, `${where(e)} ${d.op === 'delete' ? 'deletes from' : 'updates'} ${d.target ?? 'a record'} by an id from the request and no owner value from the session is in the query`, d.line))),
});

export const adminRouteWithoutRole = mapCheck({
  id: 'check.map.admin-route-without-role', sec_ids: ['SEC-AUTHZ-020', 'SEC-AUTHZ-002'], name: 'admin-route-without-role', source,
  pattern: 'an entry point in an admin area with no role check on the handler, a wrapper, the router or a gate',
  none: 'the code map has no entry point in an admin area',
  candidates: (m) => m.entry_points.filter((e) => judged(e) && e.tags.includes('admin')).length,
  fails: (m) => m.entry_points.filter((e) => judged(e) && e.tags.includes('admin') && !has(e, 'role_check')).map((e) =>
    ev(e, `${where(e)} is in an admin area and no server side role check is reachable on it${has(e, 'session_read') ? ' (a session read is not a role check)' : ''}`)),
});

export const webhookVerifyBeforeUse = mapCheck({
  id: 'check.map.webhook-verify-before-use', sec_ids: ['SEC-API-101'], name: 'webhook-verify-before-use', source,
  pattern: 'a webhook entry point with no signature check, a check that does not stop the request, or a body parsed first',
  none: 'the code map has no webhook entry point',
  candidates: (m) => m.entry_points.filter((e) => !e.test_code && e.kind === 'webhook').length,
  fails: (m) => m.entry_points.filter((e) => !e.test_code && e.kind === 'webhook').flatMap((e) => {
    const sigs = e.protections.filter((p) => p.kind === 'signature_verify');
    if (!sigs.length) return [ev(e, `${where(e)} is a webhook and no signature check was found on it`)];
    if (sigs.every((p) => p.enforced === false)) return [{ file: sigs[0].file, line: sigs[0].line, note: `${where(e)} checks the signature but carries on when it fails` }];
    if (sigs.some((p) => p.after_parse) && !sigs.some((p) => !p.after_parse)) return [{ file: sigs[0].file, line: sigs[0].line, note: `${where(e)} parses the request body before it checks the signature` }];
    return [];
  }),
});

export const requestUrlFetched = mapCheck({
  id: 'check.map.request-url-fetched', sec_ids: ['SEC-API-035'], name: 'request-url-fetched', source,
  pattern: 'an outbound HTTP call whose target comes from the request, with no allowlist in the same function',
  none: 'the code map has no outbound HTTP call in an entry point',
  candidates: (m) => m.entry_points.filter((e) => !e.test_code && e.outbound.some((o) => o.kind === 'http')).length,
  fails: (m) => m.entry_points.filter((e) => !e.test_code).flatMap((e) => e.outbound.filter((o) => o.kind === 'http' && o.request_derived && !o.guarded).map((o) =>
    evAt(e, `${where(e)} fetches ${o.target}, which comes from the request, and no allowlist of hosts is checked`, o.line))),
});

export const privilegedFieldFromRequest = mapCheck({
  id: 'check.map.privileged-field-from-request', sec_ids: ['SEC-AUTHZ-004'], name: 'privileged-field-from-request', source,
  pattern: 'a write that sets role, plan, admin or similar columns from request data, or passes the whole request object to a create or update',
  none: 'the code map has no write in an entry point',
  candidates: (m) => m.entry_points.filter((e) => judged(e) && e.data.some((d) => d.op === 'write')).length,
  fails: (m) => m.entry_points.filter((e) => judged(e) && e.kind !== 'webhook' && !has(e, 'role_check')).flatMap((e) =>
    e.data.filter((d) => d.op === 'write' && (d.sets.length > 0 || d.mass_assign)).map((d) =>
      evAt(e, d.sets.length ? `${where(e)} sets ${d.sets.join(', ')} on ${d.target ?? 'a record'} from request data` : `${where(e)} passes the whole request object into a write on ${d.target ?? 'a record'}`, d.line))),
});

export const privilegedActionWithoutAudit = mapCheck({
  id: 'check.map.privileged-action-without-audit', sec_ids: ['SEC-LOG-003'], name: 'privileged-action-without-audit', source,
  pattern: 'a write or delete in an admin area with no audit record call',
  none: 'the code map has no write or delete in an admin area',
  candidates: (m) => m.entry_points.filter((e) => judged(e) && e.tags.includes('admin') && e.data.some((d) => d.op === 'write' || d.op === 'delete')).length,
  fails: (m) => m.entry_points.filter((e) => judged(e) && e.tags.includes('admin') && e.data.some((d) => d.op === 'write' || d.op === 'delete') && !e.protections.some((p) => p.kind === 'audit_log')).map((e) =>
    ev(e, `${where(e)} changes data in an admin area and writes no audit record`)),
});

export const redirectFromRequest = mapCheck({
  id: 'check.map.redirect-from-request', sec_ids: ['SEC-AUTH-030'], name: 'redirect-from-request', source,
  pattern: 'a redirect target taken from the request with no allowlist comparison in the same function',
  none: 'the code map has no redirect in an entry point',
  candidates: (m) => m.entry_points.filter((e) => !e.test_code && e.outbound.some((o) => o.kind === 'redirect')).length,
  fails: (m) => m.entry_points.filter((e) => !e.test_code).flatMap((e) => e.outbound.filter((o) => o.kind === 'redirect' && o.request_derived && !o.guarded).map((o) =>
    evAt(e, `${where(e)} sends the user to ${o.target}, which comes from the request, and no allowlist is checked`, o.line))),
});

export const ENTRY_CHECKS: CodeCheck[] = [
  mutatingRouteWithoutAuth, dataReadWithoutAuth, writeByIdWithoutOwner, adminRouteWithoutRole, webhookVerifyBeforeUse,
  requestUrlFetched, privilegedFieldFromRequest, privilegedActionWithoutAudit, redirectFromRequest,
];
