// Checks the protection facts of a demo code map against the hand table in bench/PHASE2-ENTRYPOINTS.md (section 2, "Hand count of
// protections"). The hand table was written by reading the handlers, before the extractors existed. Node 22.18 or later runs
// this file directly. No dependencies.
//
//   node bench/demo-protections.ts codemap.json
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import type { CodeMap, EntryPoint, ProtectionKind } from '../src/types/index.ts';

type Cell = 'yes' | 'no' | 'na';
// session, role, owner, signature, rate limit, schema
const HAND: Record<string, [Cell, Cell, Cell, Cell, Cell, Cell]> = {
  'GET /api/admin/users': ['yes', 'no', 'na', 'na', 'na', 'na'],
  'POST /api/admin/users': ['yes', 'no', 'na', 'na', 'na', 'yes'],
  'DELETE /api/admin/users': ['yes', 'no', 'na', 'na', 'na', 'yes'],
  'POST /api/ai/assistant': ['yes', 'na', 'yes', 'na', 'na', 'yes'],
  'POST /api/auth/login': ['no', 'na', 'na', 'na', 'no', 'yes'],
  'POST /api/auth/logout': ['no', 'na', 'na', 'na', 'no', 'no'],
  'POST /api/auth/signup': ['no', 'na', 'na', 'na', 'no', 'yes'],
  'GET /api/files/:id': ['yes', 'na', 'yes', 'na', 'na', 'na'],
  'POST /api/files': ['yes', 'na', 'na', 'na', 'na', 'no'],
  'GET /api/me': ['yes', 'na', 'na', 'na', 'na', 'na'],
  'GET /api/notes/:id': ['yes', 'na', 'no', 'na', 'na', 'na'],
  'PATCH /api/notes/:id': ['yes', 'na', 'yes', 'na', 'na', 'yes'],
  'DELETE /api/notes/:id': ['yes', 'na', 'yes', 'na', 'na', 'na'],
  'GET /api/notes/export': ['no', 'na', 'no', 'na', 'na', 'na'],
  'POST /api/notes/import-url': ['yes', 'na', 'na', 'na', 'na', 'yes'],
  'GET /api/notes': ['yes', 'na', 'yes', 'na', 'na', 'no'],
  'POST /api/notes': ['yes', 'na', 'na', 'na', 'na', 'yes'],
  'GET /api/search': ['yes', 'na', 'yes', 'na', 'na', 'no'],
  'POST /api/webhooks/payfake': ['na', 'na', 'na', 'no', 'na', 'yes'],
  'POST updateProfile': ['yes', 'na', 'yes', 'na', 'na', 'yes'],
};
const COLS = ['session', 'role', 'owner', 'signature', 'rate limit', 'schema'];

const good = (e: EntryPoint, k: ProtectionKind): boolean => e.protections.some((p) => p.kind === k && p.confidence !== 'low' && p.enforced !== false);

export function mapCells(e: EntryPoint): [Cell, Cell, Cell, Cell, Cell, Cell] {
  const owner: Cell = e.data.some((d) => d.owner_scoped) ? 'yes' : e.data.some((d) => d.by_id) ? 'no' : 'na';
  const isHook = e.kind === 'webhook';
  const admin = e.tags.includes('admin');
  const state = e.tags.includes('state_changing');
  const readsBody = e.reads.some((r) => r.source === 'body' || r.source === 'form');
  return [
    isHook ? 'na' : good(e, 'session_read') ? 'yes' : 'no',
    admin ? (good(e, 'role_check') ? 'yes' : 'no') : 'na',
    owner,
    isHook ? (good(e, 'signature_verify') ? 'yes' : 'no') : 'na',
    e.tags.includes('auth_endpoint') && state ? (good(e, 'rate_limit') ? 'yes' : 'no') : 'na',
    state && readsBody ? (good(e, 'input_validation') ? 'yes' : 'no') : 'na',
  ];
}

export function compareProtections(map: CodeMap): { cells: number; agree: number; noClaim: number; rows: number; diffs: string[] } {
  let cells = 0;
  let agree = 0;
  let noClaim = 0;
  const diffs: string[] = [];
  const byKey = new Map<string, EntryPoint>();
  for (const e of map.entry_points) byKey.set(e.kind === 'server_action' ? `POST ${e.name}` : `${e.method} ${e.path}`, e);
  for (const [key, hand] of Object.entries(HAND)) {
    const e = byKey.get(key);
    if (!e) { diffs.push(`${key}: no entry point in the map`); continue; }
    const got = mapCells(e);
    hand.forEach((h, i) => {
      if (h === 'na') return; // the hand table has no answer for this cell
      if (got[i] === 'na') { noClaim++; return; } // the map does not claim anything for this cell
      cells++;
      if (got[i] === h) agree++; else diffs.push(`${key} ${COLS[i]}: hand ${h}, map ${got[i]}`);
    });
  }
  return { cells, agree, noClaim, rows: Object.keys(HAND).length, diffs };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const map = JSON.parse(readFileSync(process.argv[2], 'utf8')) as CodeMap;
  const r = compareProtections(map);
  process.stdout.write(`rows ${r.rows}, cells both answered ${r.cells}, same answer ${r.agree}, hand answered and the map makes no claim ${r.noClaim}\n${r.diffs.join('\n')}${r.diffs.length ? '\n' : ''}`);
}
