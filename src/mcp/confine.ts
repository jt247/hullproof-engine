// Path confinement for the MCP server. Every file the server reads for a client goes through here. A path is accepted only when it is
// a repository relative path whose real location (symbolic links resolved) is inside the repository root. Files that usually hold
// secrets are refused even inside the root.
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

// Names that hold secrets or keys. An excerpt of one of these never goes to a client.
const SECRET_FILE = /(^|\/)(\.env($|\.)|\.npmrc$|\.netrc$|\.pgpass$|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|.*\.(pem|key|p12|pfx|jks|keystore)$|credentials(\.json)?$|\.aws\/|\.ssh\/|\.git\/)/i;

export interface Confined { ok: true; abs: string; rel: string }
export interface Refused { ok: false; why: string }

export function confine(root: string, given: unknown): Confined | Refused {
  if (typeof given !== 'string' || given.length === 0 || given.length > 1024) return { ok: false, why: 'not a usable path' };
  if (given.includes('\0')) return { ok: false, why: 'path holds a NUL character' };
  if (isAbsolute(given) || /^[A-Za-z]:[\\/]/.test(given)) return { ok: false, why: 'absolute paths are refused; use a path relative to the repository' };
  const real = realpathSync(root);
  const abs = resolve(real, given);
  const rel = relative(real, abs).split(sep).join('/');
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return { ok: false, why: 'the path is outside the repository' };
  if (SECRET_FILE.test(rel)) return { ok: false, why: 'files that usually hold secrets are not read' };
  let target: string;
  try { target = realpathSync(abs); } catch { return { ok: false, why: 'the file does not exist' }; }
  const back = relative(real, target);
  if (back.startsWith('..') || isAbsolute(back)) return { ok: false, why: 'the path leads outside the repository through a link' };
  if (SECRET_FILE.test(back.split(sep).join('/'))) return { ok: false, why: 'files that usually hold secrets are not read' };
  if (!lstatSync(target).isFile()) return { ok: false, why: 'not a regular file' };
  return { ok: true, abs: target, rel };
}

// A few lines around a line number, each clipped, as plain text with line numbers. null when the path is refused or unreadable.
export function excerpt(root: string, file: string, line: number, around = 2, maxLine = 200): string | null {
  const c = confine(root, file);
  if (!c.ok) return null;
  let text: string;
  try { text = readFileSync(c.abs, 'utf8'); } catch { return null; }
  if (text.length > 2_000_000 || text.includes('\0')) return null;
  const lines = text.split('\n');
  const from = Math.max(1, line - around);
  const to = Math.min(lines.length, line + around);
  const out: string[] = [];
  for (let n = from; n <= to; n++) out.push(`${String(n).padStart(5)}  ${lines[n - 1].slice(0, maxLine)}`);
  return out.join('\n');
}
