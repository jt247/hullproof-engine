// Names of sign in and role helpers that the built in vocabulary does not know, written by the project owner in
// <repository>/.hullproof/kit.local.json:
//
//   { "auth_helpers": ["requireMember", "Auth::member"], "role_helpers": ["isBillingAdmin"] }
//
// A call, decorator, middleware or filter with one of these names counts as a session read (or a role check) with medium
// confidence, in every language the map reads. The file is an input and the names are copied into codemap.json
// (`config.local_vocab`), so the same repository and the same file give the same bytes. A file that does not parse, or a
// name that is not a plain identifier, is ignored.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Pattern } from './vocab.ts';

export interface LocalVocab { auth_helpers: string[]; role_helpers: string[]; auth: Pattern | null; role: Pattern | null }

export const LOCAL_CONFIG = '.hullproof/kit.local.json';
const NAME = /^[A-Za-z_$][\w$]*(?:(?:::|\\|\.|->)[A-Za-z_$][\w$]*)*[!?]?$/;
const MAX_NAMES = 200;

const esc = (s: string): string => s.replace(/[\\^$.*+?()[\]{}|-]/g, '\\$&');
const names = (v: unknown): string[] => (Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === 'string' && x.length <= 80 && NAME.test(x)))].sort().slice(0, MAX_NAMES) : []);
const pattern = (list: string[], via: string): Pattern | null => (list.length ? { re: new RegExp(`(?<![\\w$])(?:${list.map(esc).join('|')})(?![\\w$])`), via, confidence: 'medium' } : null);

export function loadLocalVocab(repoAbs: string): LocalVocab {
  let raw: Record<string, unknown> = {};
  try { raw = JSON.parse(readFileSync(join(repoAbs, LOCAL_CONFIG), 'utf8')) as Record<string, unknown>; } catch { /* no file, or one that does not parse: no local names */ }
  const auth_helpers = names(raw?.auth_helpers);
  const role_helpers = names(raw?.role_helpers);
  return { auth_helpers, role_helpers, auth: pattern(auth_helpers, 'local auth helper'), role: pattern(role_helpers, 'local role helper') };
}
