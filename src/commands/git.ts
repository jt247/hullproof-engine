// Git safety and state. Before any git command (ours or a scanner's), the repository's git configuration is checked
// with the same three counts as the kit's scan.sh, and the scan is refused when a git command could run code from it.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { GitState } from '../report/build.ts';

export interface Safety { ok: boolean; message: string; credentialUrl: boolean }

export function gitSafety(repo: string): Safety {
  const dotGit = join(repo, '.git');
  if (!existsSync(dotGit)) return { ok: false, message: `${repo} is not a git repository`, credentialUrl: false };
  let conf: string;
  if (statSync(dotGit).isDirectory()) {
    if (existsSync(join(dotGit, 'config.worktree'))) return { ok: false, message: 'refused: .git/config.worktree exists, its content cannot be checked here', credentialUrl: false };
    conf = join(dotGit, 'config');
  } else {
    const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotGit, 'utf8'));
    if (!m) return { ok: false, message: 'refused: GIT CONFIG: NOT CHECKED (cannot read the gitdir line)', credentialUrl: false };
    conf = join(dirname(dirname(resolve(repo, m[1].trim()))), 'config');
  }
  if (!existsSync(conf)) return { ok: false, message: 'refused: GIT CONFIG: NOT CHECKED (no config file at the expected place)', credentialUrl: false };
  const lines = readFileSync(conf, 'utf8').split('\n');
  const c1 = lines.filter((l) => /^[ \t]*(fsmonitor|sshCommand|hooksPath|textconv|pager|editor)[ \t]*=/i.test(l)).length;
  const c2 = lines.filter((l) => /^\[(diff|filter|credential)[ "]|^\[(diff|filter|credential)\]/i.test(l)).length;
  const c3 = lines.filter((l) => /:\/\/[^/ ]*@/.test(l)).length;
  if (c1 > 0 || c2 > 0) {
    return { ok: false, message: `refused: a git command could run code from this folder (code running keys ${c1}, driver and credential sections ${c2}). Remove the entries or scan a fresh clone.`, credentialUrl: c3 > 0 };
  }
  return { ok: true, message: `git config counts: code running keys 0, driver and credential sections 0, remote URLs with credentials ${c3}`, credentialUrl: c3 > 0 };
}

// git with the user and system configuration switched off, as scan.sh runs it. Call only after gitSafety passed.
export const GIT_ENV = { GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' };

function git(repo: string, args: string[]): string | null {
  const r = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8', env: { ...process.env, ...GIT_ENV } });
  return r.status === 0 ? r.stdout : null;
}

// The commit, its tree and whether tracked files differ from it. Untracked files are left out, so engine output written
// inside the repository does not change the answer between runs.
export function gitState(repo: string): GitState | null {
  const commit = git(repo, ['rev-parse', 'HEAD'])?.trim();
  const tree = git(repo, ['rev-parse', 'HEAD^{tree}'])?.trim();
  const status = git(repo, ['status', '--porcelain', '--untracked-files=no']);
  if (!commit || !tree || status === null || !/^[0-9a-f]{40}$/.test(commit) || !/^[0-9a-f]{40}$/.test(tree)) return null;
  return { commit, tree, clean: status.trim() === '' };
}
