// The "Entry points and what protects them" section of report.md, built from codemap.json. Same map, same bytes.
import type { CodeMap, EntryPoint, Protection, ProtectionKind } from '../types/index.ts';
import { cmp } from '../util.ts';

export const MAX_TABLE_ROWS = 300;
const cell = (s: string): string => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');

const real = (ep: EntryPoint, kind: ProtectionKind): Protection[] => ep.protections.filter((p) => p.kind === kind);
// One cell for one protection kind: yes with its confidence, ignored (the code checks and carries on), weak, no.
export function protectionCell(ep: EntryPoint, kind: ProtectionKind): string {
  const ps = real(ep, kind);
  const good = ps.filter((p) => p.confidence !== 'low' && p.enforced !== false);
  if (good.length) {
    const best = good.some((p) => p.confidence === 'high') ? 'high' : 'medium';
    return `yes (${best})`;
  }
  if (ps.some((p) => p.enforced === false)) return 'ignored';
  if (ps.length) return 'weak';
  return 'no';
}

function rowFor(ep: EntryPoint): string[] {
  const state = ep.tags.includes('state_changing');
  const admin = ep.tags.includes('admin');
  const byId = ep.data.filter((d) => d.by_id);
  const owner = !byId.length ? '-' : byId.every((d) => d.owner_scoped) ? 'yes' : 'no';
  const isWebhook = ep.kind === 'webhook';
  const readsBody = ep.reads.some((r) => r.source === 'body' || r.source === 'form');
  const session = ep.kind === 'ai_tool' || ep.kind === 'job' || ep.kind === 'page' || isWebhook ? '-' : protectionCell(ep, 'session_read');
  return [
    session,
    admin ? protectionCell(ep, 'role_check') : '-',
    owner,
    isWebhook ? protectionCell(ep, 'signature_verify') : '-',
    ep.tags.includes('auth_endpoint') && state ? protectionCell(ep, 'rate_limit') : '-',
    state && readsBody ? protectionCell(ep, 'input_validation') : '-',
  ];
}

const label = (ep: EntryPoint): string => `${ep.method && ep.method !== 'ANY' ? ep.method + ' ' : ''}${ep.path ?? ep.name ?? ep.file}`.trim();

export function renderEntryPoints(map: CodeMap): string[] {
  const out: string[] = [];
  const p = (...l: string[]): void => { out.push(...l); };
  const eps = map.entry_points;
  const shipped = eps.filter((e) => !e.test_code);
  p('## Entry points and what protects them', '');
  p('The code map lists every entry point the engine could find by reading the code: HTTP routes, webhooks, server actions, jobs, AI tools and similar. It comes from pattern reading, not from running the app, so each cell below is a place to look and not a proof. "yes" means the engine found that protection on the entry point, with the confidence of the match. "ignored" means the code checks and then carries on. "weak" means only a sign such as a cookie being present. "-" means the column does not apply.', '');
  p('| Language | Files | Status | Entry points | Note |', '|---|---|---|---|---|');
  if (map.coverage.length === 0) p('| none | 0 | | 0 | No source language was found. |');
  for (const c of map.coverage) p(`| ${c.language} | ${c.files} | ${c.status === 'mapped' ? 'mapped' : c.status === 'partial' ? 'partly mapped' : 'not mapped'} | ${c.entry_points} | ${cell(c.note)} |`);
  p('');
  const incomplete = map.coverage.filter((c) => c.status !== 'mapped');
  if (incomplete.length) p(`The code map is incomplete for ${incomplete.map((c) => c.language).join(', ')}. Entry points in those files are not listed, and the checks that read the map did not look at them.`, '');

  const kinds = Object.entries(map.counts.by_kind).map(([k, n]) => `${n} ${k.replace(/_/g, ' ')}`).join(', ');
  const state = shipped.filter((e) => e.tags.includes('state_changing') && ['http_route', 'server_action', 'graphql_resolver', 'rpc'].includes(e.kind));
  const noSession = state.filter((e) => !e.tags.includes('auth_endpoint') && !e.tags.includes('public') && protectionCell(e, 'session_read') !== 'yes (high)' && protectionCell(e, 'session_read') !== 'yes (medium)');
  const admins = shipped.filter((e) => e.tags.includes('admin') && ['http_route', 'server_action', 'graphql_resolver', 'rpc'].includes(e.kind));
  const noRole = admins.filter((e) => !protectionCell(e, 'role_check').startsWith('yes'));
  const hooks = shipped.filter((e) => e.kind === 'webhook');
  const badHooks = hooks.filter((e) => !protectionCell(e, 'signature_verify').startsWith('yes'));
  p(`1. Entry points: ${map.counts.entry_points}${kinds ? ` (${kinds})` : ''}. In test code and left out of the checks: ${eps.length - shipped.length}.`);
  p(`2. State changing entry points: ${state.length}. Without a session read the engine can see: ${noSession.length}.`);
  p(`3. Entry points in an admin area: ${admins.length}. Without a role check the engine can see: ${noRole.length}.`);
  p(`4. Webhooks: ${hooks.length}. Without a signature check that stops the request: ${badHooks.length}.`);
  p('5. Gates (middleware, guards, router dependencies): ' + map.gates.length + '.', '');

  p('| Entry point | Kind | Where | Session | Role | Owner | Signature | Rate limit | Schema |', '|---|---|---|---|---|---|---|---|---|');
  const rows = eps.slice().sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.id, b.id)).slice(0, MAX_TABLE_ROWS);
  for (const ep of rows) {
    const r = rowFor(ep);
    p(`| ${cell(label(ep))}${ep.test_code ? ' (test code)' : ''} | ${ep.kind.replace(/_/g, ' ')} | \`${ep.file}:${ep.line}\` | ${r.join(' | ')} |`);
  }
  if (eps.length > rows.length) p('', `${eps.length - rows.length} more entry points are in codemap.json.`);
  p('');
  return out;
}
