// Reads provider settings from a .env.local file without any dependency. Real environment variables always win. Only the names
// in HUNT_ENV_NAMES are read, and no value is ever logged or returned in a message: callers get the names that came from a file.
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HUNT_ENV_NAMES = [
  'HULLPROOF_PROVIDER', 'HULLPROOF_MODEL', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GEMINI_API_KEY',
  'HULLPROOF_OPENAI_COMPAT_BASE_URL', 'HULLPROOF_OPENAI_COMPAT_KEY',
] as const;
const ALLOWED = new Set<string>(HUNT_ENV_NAMES);
const ENGINE_ROOT = fileURLToPath(new URL('../', import.meta.url));
const MAX_BYTES = 64 * 1024;

// Parses KEY=VALUE lines: blank lines and # comments skipped, an optional "export " prefix, matching quotes removed.
export function parseEnvText(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m || !ALLOWED.has(m[1])) continue;
    let v = m[2].trim();
    const q = v[0] === '"' || v[0] === "'" ? v.indexOf(v[0], 1) : -1;
    if (q > 0) v = v.slice(1, q);
    else v = v.replace(/\s+#.*$/, '');
    if (v) out[m[1]] = v;
  }
  return out;
}

// The scanned repository's .env.local first, then the engine's. A name already set (and not empty) in `base` is never replaced.
export function loadHuntEnv(repo: string | null, base: NodeJS.ProcessEnv = process.env, engineRoot: string = ENGINE_ROOT): { env: Record<string, string | undefined>; fromFile: string[] } {
  const env: Record<string, string | undefined> = { ...base };
  const fromFile: string[] = [];
  // CI sets this: the scanned repository is untrusted there, so a .env.local inside it must not supply a provider address or key.
  if (base.HULLPROOF_NO_ENV_FILE === '1') return { env, fromFile };
  const roots = [...(repo ? [resolve(repo)] : []), resolve(engineRoot)];
  for (const root of roots) {
    const p = join(root, '.env.local');
    try {
      if (!existsSync(p) || statSync(p).size > MAX_BYTES) continue;
      for (const [k, v] of Object.entries(parseEnvText(readFileSync(p, 'utf8')))) {
        if (env[k]) continue;
        env[k] = v;
        fromFile.push(k);
      }
    } catch { /* an unreadable file is the same as no file */ }
  }
  return { env, fromFile: [...new Set(fromFile)].sort() };
}
