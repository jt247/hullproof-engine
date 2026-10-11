// Small helpers shared by every module.

// Code unit order. Never localeCompare: its result depends on the machine's locale.
export const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export const sortUnique = (xs: Iterable<string>): string[] => [...new Set(xs)].sort(cmp);

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort(cmp)) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== undefined) out[k] = sortKeys(x);
    }
    return out;
  }
  return v;
}

// The engine's one JSON writer: sorted keys, two space indent, LF, final newline. Same value, same bytes.
export const stableJson = (v: unknown): string => JSON.stringify(sortKeys(v), null, 2) + '\n';
// The same sorted JSON on one line, for a block that must stay under a size limit.
export const stableJsonCompact = (v: unknown): string => JSON.stringify(sortKeys(v)) + '\n';

// Glob to RegExp. Supports *, **, ?, [...] and {a,b}. A pattern with no slash matches the file name at any depth;
// a pattern with a slash matches the whole repository relative path.
function globBody(p: string): string {
  let out = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*') {
      if (p[i + 1] === '*') {
        if (p[i + 2] === '/') { out += '(?:.*/)?'; i += 2; } else { out += '.*'; i += 1; }
      } else out += '[^/]*';
    } else if (c === '?') out += '[^/]';
    else if (c === '[' && p.indexOf(']', i + 1) > i + 1) {
      const j = p.indexOf(']', i + 1);
      const cls = p.slice(i + 1, j);
      out += '[' + (cls[0] === '!' ? '^' + cls.slice(1) : cls).replace(/\\/g, '\\\\') + ']';
      i = j;
    } else if (c === '{' && p.indexOf('}', i) > i) {
      const j = p.indexOf('}', i);
      out += '(?:' + p.slice(i + 1, j).split(',').map(globBody).join('|') + ')';
      i = j;
    } else if (c === '\\' && i + 1 < p.length) { out += escapeRe(p[i + 1]); i++; }
    else out += escapeRe(c);
  }
  return out;
}
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

export function globToRegExp(glob: string): RegExp {
  const anchored = glob.includes('/');
  const p = glob.startsWith('/') ? glob.slice(1) : glob;
  return new RegExp(anchored ? `^${globBody(p)}$` : `^(?:.*/)?${globBody(p)}$`);
}

export { globBody };
