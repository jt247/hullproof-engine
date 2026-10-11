// hullproof map: discovery, then the code map. Needs no kit and no scanner. Writes <out>/codemap.json (default: .hullproof
// inside the repository), or prints it with --out -.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { makeContext } from '../checks/context.ts';
import { getMap } from '../checks/map/shared.ts';
import { discover } from '../discover/discover.ts';
import { stableJson } from '../util.ts';

export function mapCommand(repoArg: string, outArg: string | null, out: (s: string) => void, err: (s: string) => void): number {
  let json: string;
  let summary: string;
  try {
    const repo = resolve(repoArg);
    const ctx = makeContext(repo, discover(repo));
    const map = getMap(ctx);
    json = stableJson(map);
    const notMapped = map.coverage.filter((c) => c.status !== 'mapped');
    summary = `hullproof map: ${map.counts.entry_points} entry points${notMapped.length ? `; map incomplete for ${notMapped.map((c) => c.language).join(', ')}` : ''}`;
  } catch (e) { err(`hullproof map: ${(e as Error).message}\n`); return 2; }
  if (outArg === '-') { out(json); return 0; }
  const dir = resolve(outArg ?? join(repoArg, '.hullproof'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'codemap.json'), json);
  out(`${summary}\nhullproof map: wrote ${join(dir, 'codemap.json')}\n`);
  return 0;
}
