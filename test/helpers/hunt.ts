// Shared by the hunt tests: a copy of the Express fixture app in a temp folder, its code map, and hand written model answers.
import { cpSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeContext } from '../../src/checks/context.ts';
import { getMap } from '../../src/checks/map/shared.ts';
import { discover } from '../../src/discover/discover.ts';
import type { CodeMap, HuntAnswer, HuntPlan, Json } from '../../src/types/index.ts';

const APP = fileURLToPath(new URL('../fixtures/map/fail/express/', import.meta.url));
export function appCopy(): { repo: string; map: CodeMap } {
  const repo = mkdtempSync(join(tmpdir(), 'hp-hunt-'));
  cpSync(APP, repo, { recursive: true });
  return { repo, map: getMap(makeContext(repo, discover(repo))) };
}

export const DELETE_ID = 'server.js:27:http_route:DELETE:/api/notes/:id:-';
export const EXPORT_ID = 'server.js:23:http_route:GET:/api/export:-';
export const DELETE_LINE = "  db.run('DELETE FROM notes WHERE id = ?', [req.params.id]);";
export const DELETE_QUERY = JSON.stringify({ where: { all: [
  { field: 'kind', op: 'eq', value: 'http_route' },
  { some: 'data', where: { all: [{ field: 'op', op: 'eq', value: 'delete' }, { field: 'by_id', op: 'eq', value: true }, { field: 'owner_scoped', op: 'eq', value: false }] } },
  { none: 'protections', where: { field: 'kind', op: 'eq', value: 'owner_filter' } },
] } });
export const DELETE_RULE = `rules:
  - id: delete-note-by-request-id
    languages: [javascript]
    severity: WARNING
    message: A note is deleted by an id from the request with no owner condition.
    pattern: db.run("DELETE FROM notes WHERE id = ?", [req.params.id])
`;
export const DELETE_CONTROL = "db.run('DELETE FROM notes WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id]);\n";

export interface RawLead { lead_id: string; entry_point: string; requirement_ids: string[]; claim: string; path: { file: string; line: number; note: string }[]; quoted_code: string; evidence_proposal: Record<string, Json> }
export const proposal = (kind: string, extra: Record<string, Json> = {}): Record<string, Json> => ({ kind, query_json: null, rule_yaml: null, control_code: null, control_extension: null, ...extra });

export function boLead(over: Partial<RawLead> = {}): RawLead {
  return {
    lead_id: 'L1', entry_point: DELETE_ID, requirement_ids: ['SEC-API-001'], claim: 'Any signed in user can delete any note by id because the delete has no owner condition.',
    path: [{ file: 'server.js', line: 27, note: 'route' }, { file: 'server.js', line: 28, note: 'delete by id from the request' }],
    quoted_code: "db.run('DELETE FROM notes WHERE id = ?', [req.params.id]);", evidence_proposal: proposal('map_query', { query_json: DELETE_QUERY }), ...over,
  };
}

export const answer = (run: number, entry: string, leads: RawLead[], over: Partial<HuntAnswer> = {}): HuntAnswer => ({
  schema_version: '1.0.0', run, entry_id: entry, status: 'complete', stop: null, detail: null, provider: 'mock', model: 'mock-1', context_sha256: 'a'.repeat(64),
  truncated: false, usage: { input_tokens: 100, output_tokens: 20 }, output: { leads } as unknown as Json, ...over,
});
export const incomplete = (run: number, entry: string, stop: string): HuntAnswer => answer(run, entry, [], { status: 'incomplete', stop, detail: 'stopped', output: null });
export const planOf = (map: CodeMap, runs: number): HuntPlan => ({ schema_version: '1.0.0', commit: null, runs, entries: map.entry_points.map((e) => e.id) });
