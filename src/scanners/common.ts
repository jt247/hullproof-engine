// Helpers shared by the adapters: running a tool, reading the git index without git, hashing, masking, path rules.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cmp } from '../util.ts';
import type { Exec } from './types.ts';

export const ENGINE_ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const RULES_DIR = join(ENGINE_ROOT, 'rules');
const MAX_BUFFER = 512 * 1024 * 1024;

// An address nothing listens on. Go, Python and git clients send all HTTP and HTTPS traffic to it and fail,
// so a tool that tries the network while network is not allowed gets an error instead of a connection.
const BLACKHOLE = 'http://127.0.0.1:9';

export function toolEnv(base: NodeJS.ProcessEnv, allowNetwork: boolean): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...base,
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0', NO_COLOR: '1',
    SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0',
    // Set by the container entry point of the GitHub Action only (see src/commands/git.ts).
    ...(process.env.HULLPROOF_TRUST_REPO_OWNER === '1' ? { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'safe.directory', GIT_CONFIG_VALUE_0: '*' } : {}),
  };
  if (!allowNetwork) {
    for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) env[k] = BLACKHOLE;
    env.NO_PROXY = ''; env.no_proxy = '';
  }
  return env;
}

export function exec(argv: string[], cwd: string, env: NodeJS.ProcessEnv): Exec {
  const r = spawnSync(argv[0], argv.slice(1), { cwd, env, encoding: 'utf8', maxBuffer: MAX_BUFFER, shell: false });
  const error = r.error ? ((r.error as NodeJS.ErrnoException).code ?? r.error.message) : undefined;
  return { argv, stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status, error };
}

// First x.y.z in the version command's output. null when the tool is missing.
export function detectVersion(argv: string[], env: NodeJS.ProcessEnv): string | null {
  const r = exec(argv, process.cwd(), env);
  if (r.error) return null;
  return /(\d+\.\d+\.\d+)/.exec(r.stdout + '\n' + r.stderr)?.[1] ?? null;
}

// "1.176.x" style ranges: the installed version must have the same major and minor.
export function versionTested(version: string | null, range: string): boolean {
  if (!version) return false;
  const [maj, min] = range.split('.');
  const [vmaj, vmin] = version.split('.');
  return maj === vmaj && min === vmin;
}

export const sha256 = (data: string | Buffer): string => createHash('sha256').update(data).digest('hex');
export const fileSha256 = (p: string): string => sha256(readFileSync(p));

// The scan.sh method for a folder: sha256 over the per file sha256 lines, files in sorted path order.
export function dirSha256(dir: string): string {
  const files: string[] = [];
  const walk = (d: string): void => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p); else if (e.isFile()) files.push(relative(dir, p).split(sep).join('/'));
    }
  };
  walk(dir);
  return sha256(files.sort(cmp).map((f) => fileSha256(join(dir, f)) + '\n').join(''));
}

// Repository relative POSIX path. Absolute paths inside the repository lose the prefix; "./" is dropped.
export function relPath(p: string, repo: string): string {
  let out = p.replace(/\\/g, '/');
  if (isAbsolute(p)) {
    const r = relative(resolve(repo), p);
    out = r.startsWith('..') ? out : r.split(sep).join('/');
  }
  return out.replace(/^(\.\/)+/, '');
}

// Replaces long token shaped runs (keys, hashes, encoded blobs: 20 or more key characters with both a letter and a
// digit) so evidence text does not carry a secret value. Plain identifiers such as AWS_SECRET_ACCESS_KEY stay readable.
// ponytail: a secret with no digit passes; evidence for secret rules is the Gitleaks redacted form or null anyway.
const TOKEN = /[A-Za-z0-9+/_-]{20,}={0,2}/g;
export function mask(text: string, max = 160): string {
  const one = text.replace(/\s+/g, ' ').trim().replace(TOKEN, (m) => (/\d/.test(m) && /[A-Za-z]/.test(m) ? '***' : m));
  return one.length > max ? one.slice(0, max - 3) + '...' : one;
}

// One masked source line read from the repository, or null when the file or line is not there.
export function sourceLine(repo: string, file: string, line: number): string | null {
  if (line < 1) return null;
  try {
    const p = join(repo, file);
    if (!lstatSync(p).isFile() || statSync(p).size > 4 * 1024 * 1024) return null;
    const text = readFileSync(p, 'utf8').split('\n')[line - 1];
    return text === undefined ? null : mask(text);
  } catch { return null; }
}

// Paths tracked by git, read from .git/index (versions 2, 3 and 4) without running git. Stage 0 to 3 entries are one
// path; submodule entries (mode 160000) are left out. null when there is no index.
export function readTracked(repo: string): Set<string> | null {
  let gitDir = join(repo, '.git');
  if (!existsSync(gitDir)) return null;
  if (statSync(gitDir).isFile()) {
    const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(gitDir, 'utf8'));
    if (!m) return null;
    gitDir = resolve(repo, m[1].trim());
  }
  const idx = join(gitDir, 'index');
  if (!existsSync(idx)) return null;
  return parseIndex(readFileSync(idx));
}

export function parseIndex(buf: Buffer): Set<string> {
  if (buf.toString('latin1', 0, 4) !== 'DIRC') throw new Error('not a git index');
  const version = buf.readUInt32BE(4);
  if (version < 2 || version > 4) throw new Error(`git index version ${version} is not supported`);
  const count = buf.readUInt32BE(8);
  const out = new Set<string>();
  let off = 12;
  let prev: Buffer = Buffer.alloc(0);
  for (let i = 0; i < count; i++) {
    const start = off;
    const mode = buf.readUInt32BE(off + 24);
    const flags = buf.readUInt16BE(off + 60);
    off += 62;
    if (version >= 3 && flags & 0x4000) off += 2;
    let name: Buffer;
    if (version === 4) {
      let c = buf[off++];
      let strip = c & 127;
      while (c & 128) { c = buf[off++]; strip = ((strip + 1) << 7) | (c & 127); }
      const end = buf.indexOf(0, off);
      name = Buffer.concat([prev.subarray(0, prev.length - strip), buf.subarray(off, end)]);
      off = end + 1;
    } else {
      const end = buf.indexOf(0, off);
      name = buf.subarray(off, end);
      off = start + Math.floor((end - start + 8) / 8) * 8; // NUL padding to a multiple of 8
    }
    prev = name;
    if ((mode >>> 12) !== 0o16) out.add(name.toString('utf8')); // 0o160000 is a submodule
  }
  return out;
}

export const isRegularFile = (p: string): boolean => { try { return lstatSync(p).isFile(); } catch { return false; } };
