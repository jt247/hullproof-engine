// hullproof pack: validate the stack packs (packs/<id>), list them, or print the coverage table made from their recorded results.
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { coverageMarkdown, coverageRows, legendMarkdown } from '../packs/coverage.ts';
import { LEVEL_NAMES } from '../packs/manifest.ts';
import { defaultEnv, listPacks, PACKS_DIR, validatePack, type Checked } from '../packs/validate.ts';

export interface PackOptions { action: string; targets: string[]; root: string | null; out: (s: string) => void; err: (s: string) => void }

export function packCommand(o: PackOptions): number {
  const { out, err } = o;
  if (!['validate', 'list', 'table'].includes(o.action)) { err(`hullproof pack: use validate, list or table (got "${o.action}").\n`); return 2; }
  const root = o.root ? resolve(o.root) : undefined;
  if (root && !existsSync(root)) { err(`hullproof pack: --root ${root} does not exist.\n`); return 2; }
  const env = defaultEnv(root);
  const folders = o.targets.length ? o.targets.map((t) => resolve(t)) : listPacks(root ? resolve(root, 'packs') : PACKS_DIR);
  for (const f of folders) if (!existsSync(f)) { err(`hullproof pack: ${f} does not exist.\n`); return 2; }
  const checked: Checked[] = folders.map((f) => validatePack(f, env));

  if (o.action === 'table') { out(`${legendMarkdown()}\n\n${coverageMarkdown(coverageRows(checked))}\n`); return checked.some((c) => c.issues.length) ? 1 : 0; }
  if (o.action === 'list') {
    for (const c of checked) out(`${c.manifest?.id ?? c.dir}\t${c.manifest ? `${c.manifest.level} ${LEVEL_NAMES[c.manifest.level]}` : 'unreadable'}\t${c.manifest?.name ?? ''}\n`);
    return 0;
  }
  let failed = 0;
  for (const c of checked) {
    if (!c.issues.length) { out(`ok    ${c.manifest!.id} ${c.manifest!.level}${c.skipped.length ? ` (${c.skipped.length} Pro or internal part(s) not checked in this edition)` : ''}\n`); continue; }
    failed++;
    out(`FAIL  ${c.manifest?.id ?? c.dir}\n`);
    for (const i of c.issues) out(`      ${i.code}: ${i.message}\n`);
  }
  out(`hullproof pack validate: ${checked.length - failed} of ${checked.length} packs pass\n`);
  return failed ? 1 : 0;
}
