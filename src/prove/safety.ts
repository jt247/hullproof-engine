// The safety rules of the proof sandbox that do not depend on a container runtime: the typed confirmation, the loopback only
// target rule, the copy of the repository without secrets, and the dummy environment. Design: docs/PHASE-4-DESIGN.md, safety rules 1 to 3.
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, copyFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { loopbackBase } from './executor.ts';

export const CONFIRM_PHRASE = 'I own this app and approve running it';

// Rule 1: an explicit flag and the exact typed phrase. Nothing else counts: no environment variable, no default, no CI setting.
export function checkConfirmation(allowRun: boolean, typed: string | null): { ok: true } | { ok: false; reason: string } {
  if (!allowRun) return { ok: false, reason: 'hullproof prove runs the app, so it needs --allow-run' };
  if (typed === null) return { ok: false, reason: `hullproof prove needs the owner's typed confirmation: type "${CONFIRM_PHRASE}"` };
  if (typed.trim() !== CONFIRM_PHRASE) return { ok: false, reason: `the confirmation does not match. Type exactly: ${CONFIRM_PHRASE}` };
  return { ok: true };
}

// Rule 2: the only address a request may go to is the sandbox's own loopback on the recipe's port.
export function assertSandboxTarget(url: string, port: number): void {
  const u = loopbackBase(url);
  if (Number(u.port) !== port) throw new Error(`refused: ${u.origin} is not the sandbox app port ${port}`);
}

// Rule 3: names that never go into the copy. Environment files, keys, credentials, tool folders, git history.
const SECRET_FILE = /^(?:\.env(?:\..*)?|\.npmrc|\.netrc|\.pypirc|\.git-credentials|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|credentials(?:\..*)?|.*\.(?:pem|key|p12|pfx|jks|keystore|kdbx)|service-account.*\.json|.*secrets?\.(?:json|ya?ml|toml))$/i;
const SKIP_DIR = new Set(['.git', '.hullproof', '.DS_Store', '.next', '.cache', 'coverage']);
export const isSecretFile = (name: string): boolean => SECRET_FILE.test(name);
const MAX_FILE = 10 * 1024 * 1024;
const MAX_TOTAL = 200 * 1024 * 1024;

export interface SandboxCopy { dir: string; files: number; excluded: string[]; cleanup(): void }

// Copies the repository to a fresh temporary folder, leaving out secrets and (unless the repository vendors its modules) node_modules.
// Symbolic links are never followed or copied. Returns what was left out so the report can say so.
export function makeSandboxCopy(repo: string, o: { keepNodeModules: boolean }): SandboxCopy | { error: string } {
  const root = realpathSync(repo);
  const dir = mkdtempSync(join(tmpdir(), 'hp-prove-'));
  const excluded: string[] = [];
  let files = 0;
  let total = 0;
  const walk = (from: string): string | null => {
    for (const name of readdirSync(from).sort()) {
      const p = join(from, name);
      const rel = relative(root, p).split(sep).join('/');
      const st = lstatSync(p);
      if (st.isSymbolicLink()) { excluded.push(`${rel} (symbolic link)`); continue; }
      if (st.isDirectory()) {
        if (SKIP_DIR.has(name)) continue;
        if (name === 'node_modules' && !o.keepNodeModules) { excluded.push(`${rel}/ (dependencies are installed in the build phase)`); continue; }
        mkdirSync(join(dir, rel), { recursive: true });
        const e = walk(p);
        if (e) return e;
        continue;
      }
      if (!st.isFile()) continue;
      if (isSecretFile(name)) { excluded.push(`${rel} (secret file)`); continue; }
      if (st.size > MAX_FILE) { excluded.push(`${rel} (over 10 MB)`); continue; }
      total += st.size;
      if (total > MAX_TOTAL) return 'the repository is over 200 MB, which is too large to copy into a sandbox';
      mkdirSync(join(dir, rel, '..'), { recursive: true });
      copyFileSync(p, join(dir, rel));
      files++;
    }
    return null;
  };
  const err = walk(root);
  if (err) { rmSync(dir, { recursive: true, force: true }); return { error: err }; }
  return { dir, files, excluded: excluded.sort(), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// The environment variable names the repository reads: process.env.NAME and process.env['NAME'] in source files, and the names
// (not the values) in .env.example. A real .env file is never opened.
const SRC = /\.(?:[cm]?[jt]sx?)$/;
const PY_SRC = /\.py$/;
export function envNames(repo: string): string[] {
  const names = new Set<string>();
  const walk = (d: string, depth: number): void => {
    if (depth > 8) return;
    for (const n of readdirSync(d)) {
      if (n === 'node_modules' || n === '.git' || n === '.hullproof' || n === '.next' || n === '__pycache__' || n === '.venv' || n === 'venv') continue;
      const p = join(d, n);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) walk(p, depth + 1);
      else if (st.isFile() && st.size < 1_000_000) {
        if (SRC.test(n)) for (const m of readFileSync(p, 'utf8').matchAll(/process\.env(?:\.([A-Z][A-Z0-9_]*)|\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\])/g)) names.add(m[1] ?? m[2]);
        else if (PY_SRC.test(n)) for (const m of readFileSync(p, 'utf8').matchAll(/os\.(?:environ(?:\.get)?\s*[[(]\s*|getenv\s*\(\s*)['"]([A-Z][A-Z0-9_]*)['"]/g)) names.add(m[1]);
        else if (n === '.env.example') for (const l of readFileSync(p, 'utf8').split(/\r?\n/)) { const m = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=/.exec(l); if (m) names.add(m[1]); }
      }
    }
  };
  if (existsSync(repo)) walk(repo, 0);
  return [...names].sort();
}

// A fixed dummy value per name, so two runs get the same environment. It looks like what it stands for and opens nothing.
export const dummyValue = (name: string): string => `dummy-${name.toLowerCase().replace(/_/g, '-')}-${createHash('sha256').update(name).digest('hex').slice(0, 8)}`;
