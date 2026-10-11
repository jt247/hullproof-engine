// Reads the HEAD commit from the .git folder without running git.
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const SHA = /^[0-9a-f]{40}$/;
const read = (p: string): string | null => { try { return readFileSync(p, 'utf8'); } catch { return null; } };

export function readHeadCommit(root: string): string | null {
  let gitDir = join(root, '.git');
  if (!existsSync(gitDir)) return null;
  if (statSync(gitDir).isFile()) {
    const m = /^gitdir:\s*(.+)$/m.exec(read(gitDir) ?? '');
    if (!m) return null;
    gitDir = resolve(root, m[1].trim());
  }
  const head = (read(join(gitDir, 'HEAD')) ?? '').trim();
  if (SHA.test(head)) return head;
  const ref = /^ref:\s*(\S+)$/.exec(head)?.[1];
  if (!ref) return null;
  const common = read(join(gitDir, 'commondir'));
  const dirs = [gitDir, ...(common ? [resolve(gitDir, common.trim())] : [])];
  for (const d of dirs) {
    const loose = (read(join(d, ref)) ?? '').trim();
    if (SHA.test(loose)) return loose;
    for (const line of (read(join(d, 'packed-refs')) ?? '').split('\n')) {
      const [sha, name] = line.trim().split(' ');
      if (name === ref && SHA.test(sha)) return sha;
    }
  }
  return null;
}
