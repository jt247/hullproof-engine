// Maps one scanner hit to requirement IDs. Order: the rule's own metadata (Semgrep sec_ids), then the controls file's
// tests[] entry for the rule id, then the tool's table in src/mapping/maps/<tool>.json (exact rule id, then "*").
// A hit with no mapping keeps sec_ids [] and is marked unmapped; it is never dropped.
import { readFileSync } from 'node:fs';
import type { ScannerId } from '../types/index.ts';
import { globToRegExp, sortUnique } from '../util.ts';
import { inEdition, type Controls } from './controls.ts';
import type { DetailHit } from '../scanners/types.ts';

export interface MapRow { rule_id: string; sec_ids: string[] }
export interface MapTable { tool: ScannerId; rows: MapRow[]; client_code_paths?: string[]; client_code_sec_ids?: string[] }

const tables = new Map<string, MapTable>();
export function loadTable(tool: ScannerId): MapTable {
  if (!tables.has(tool)) {
    tables.set(tool, JSON.parse(readFileSync(new URL(`./maps/${tool}.json`, import.meta.url), 'utf8')) as MapTable);
  }
  return tables.get(tool)!;
}

export interface MapInput {
  tool: ScannerId;
  rule_id: string;
  file: string;
  metadataSecIds?: string[];   // Semgrep rule metadata
  tracked?: boolean;           // Gitleaks: false for a file on disk that git does not track
}

export interface MapOutput { sec_ids: string[]; mapped_by: DetailHit['mapped_by'] }

export function mapHit(h: MapInput, edition: 'free' | 'pro', controls: Controls | null): MapOutput {
  const all = rawMap(h, controls);
  const sec_ids = sortUnique(inEdition(all.sec_ids, edition, controls));
  return sec_ids.length ? { sec_ids, mapped_by: all.mapped_by } : { sec_ids: [], mapped_by: 'none' };
}

function rawMap(h: MapInput, controls: Controls | null): MapOutput {
  if (h.metadataSecIds?.length) return { sec_ids: h.metadataSecIds, mapped_by: 'rule metadata' };
  const fromControls = controls?.ruleToIds.get(h.rule_id);
  if (fromControls?.length) return { sec_ids: fromControls, mapped_by: 'controls tests' };
  if (h.tool === 'semgrep') return { sec_ids: [], mapped_by: 'none' };
  const t = loadTable(h.tool);
  const exact = t.rows.find((r) => r.rule_id === h.rule_id);
  const any = t.rows.find((r) => r.rule_id === '*');
  let ids = exact?.sec_ids ?? any?.sec_ids ?? [];
  let by: MapOutput['mapped_by'] = exact ? 'map rule_id' : any ? 'map default' : 'none';
  if (h.tool === 'gitleaks') {
    const client = (t.client_code_paths ?? []).some((g) => globToRegExp(g).test(h.file));
    ids = [...(h.tracked === false ? [] : ids), ...(client ? t.client_code_sec_ids ?? [] : [])];
    if (!ids.length) by = 'none';
  }
  return { sec_ids: ids, mapped_by: by };
}

// Every ID a tool can produce through its table (used for not_assessed_sec_ids when the tool does not run).
export const tableSecIds = (tool: ScannerId): string[] => {
  const t = loadTable(tool);
  return sortUnique([...t.rows.flatMap((r) => r.sec_ids), ...(t.client_code_sec_ids ?? [])]);
};
