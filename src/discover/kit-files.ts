// Files of the Hullproof kit that were copied into the scanned project and are still byte for byte what the kit says.
// They hold planted samples on purpose (the kit's own test files, hook self tests), so scanning them reports the kit's samples as findings in the
// user's project. The list comes from the manifest of the kit the run was given (--kit), never from a manifest inside the scanned project, because a
// project could name its own files in a manifest of its own and hide them from the scan. A file that differs by one byte is not skipped.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

const MANIFEST_REL = 'docs/hullproof/.kit-manifest';
const LINE = /^([0-9a-f]{64})  (\S.*)$/;

export function kitOwnedFiles(repo: string, kitDir: string | null): Set<string> {
  const out = new Set<string>();
  if (!kitDir) return out;
  let manifest: string;
  try { manifest = readFileSync(join(kitDir, MANIFEST_REL), 'utf8'); } catch { return out; }
  // A kit folder inside the scanned project is the project's own content, so its manifest is not a trusted list.
  try {
    const rel = relative(realpathSync(resolve(repo)), realpathSync(resolve(kitDir)));
    if (rel === '' || (!rel.startsWith('..') && !rel.startsWith(sep) && rel.split(sep)[0] !== '..')) return out;
  } catch { return out; }
  for (const line of manifest.split('\n')) {
    const m = LINE.exec(line);
    if (!m || m[2].includes('..') || m[2].startsWith('/')) continue;
    const f = join(repo, m[2]);
    try {
      const st = lstatSync(f);
      if (!st.isFile()) continue;
      if (createHash('sha256').update(readFileSync(f)).digest('hex') === m[1]) out.add(m[2]);
    } catch { /* not in the project */ }
  }
  return out;
}

// The folders that hold the skipped kit files, collapsed to three levels, for the list of what discovery left out.
export const kitFolders = (files: Iterable<string>): string[] =>
  [...new Set([...files].map((f) => dirname(f).split('/').slice(0, 3).join('/') + '/'))].sort();
