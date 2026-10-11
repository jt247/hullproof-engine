// Taint inside one function: which names hold request data. Seeds are the handler parameters; a name becomes tainted when
// it is assigned from an expression that contains a tainted name or a request source. Followed to a fixed point. No calls
// are followed, so a value that passes through a helper function and comes back is not tracked (a stated limit).
import type { Lang } from './lex.ts';
import { statementEnd } from './lex.ts';
import { SESSION_JS, SESSION_PY, type Pattern } from './vocab.ts';

const KEYWORDS = new Set(['const', 'let', 'var', 'await', 'async', 'new', 'return', 'typeof', 'if', 'else', 'null', 'undefined', 'true', 'false', 'None', 'True', 'False', 'not', 'and', 'or', 'in', 'is', 'lambda', 'for', 'while', 'self', 'cls']);

// Identifiers in an expression that are values and not property names (not preceded by a dot).
export function identifiers(expr: string): string[] {
  const out: string[] = [];
  for (const m of expr.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)/g)) if (!KEYWORDS.has(m[1])) out.push(m[1]);
  return out;
}

const SOURCE_JS = /\b(?:req|request|ctx|event)\s*[.\[]|\bsearchParams\b|\bformData\b|\bnextUrl\b|\bc\.req\b|\bawait\s+\w+\.(?:json|formData|text)\s*\(\)|\bURL\s*\(\s*(?:req|request)\.url/;
const SOURCE_PY = /\brequest\s*[.\[]|\brequest\b\.|\bflask\.request\b|\binput\s*\(|\bsys\.argv\b/;

// Values that come from the session and not from the request: req.user, current_user, session[...] and the like.
export const TRUSTED_CHAIN = /\b(?:req|request|ctx|event)\s*\.\s*(?:user|session|auth|locals\s*\.\s*user|state\s*\.\s*user)\b|\bcurrent_user\b|\bg\.user\b|\bsession\s*[\[.]|\bc\.get\(\s*['"]user/g;

export interface Taint { names: Set<string>; validated: Set<string>; trusted: Set<string> }

// `seeds`: names that hold request data on entry. `validated` collects names assigned from a schema parse, which are
// still request data but are shaped by a schema (so passing one whole into a create is not a free for all).
export function taintOf(masked: string, original: string, seeds: string[], lang: Lang, extraSession: Pattern[] = []): Taint {
  const names = new Set(seeds);
  const validated = new Set<string>();
  const trusted = new Set<string>();
  const isSource = lang === 'js' ? SOURCE_JS : SOURCE_PY;
  const sessionPats = [...(lang === 'js' ? SESSION_JS : SESSION_PY), ...extraSession].filter((p) => p.confidence !== 'low');
  const fromSession = (expr: string): boolean => sessionPats.some((p) => { p.re.lastIndex = 0; return p.re.test(expr); });
  const tainted = (expr: string): boolean => { const e = expr.replace(TRUSTED_CHAIN, ' '); return isSource.test(e) || identifiers(e).some((i) => names.has(i) && !trusted.has(i)); };
  const parsed = (expr: string): boolean => /\.(?:safeParse|parse|parseAsync|safeParseAsync|model_validate|parse_obj|load|validate)\s*\(/.test(expr) || /\bvalidated|\.data\b/.test(expr) && identifiers(expr).some((i) => validated.has(i));
  const assignments: { lhs: string[]; rhs: string }[] = [];
  if (lang === 'js') {
    for (const m of masked.matchAll(/\b(?:const|let|var)\s+(?:(\w+)|\{([^}]*(?:\{[^}]*\}[^}]*)*)\}|\[([^\]]*)\])\s*(?::[^=\n]+)?=(?!=)/g)) {
      const rhsStart = m.index! + m[0].length;
      const rhsEnd = statementEnd(masked, rhsStart);
      const lhs = m[1] ? [m[1]] : identifiers((m[2] ?? m[3] ?? '').replace(/(\w+)\s*:/g, ' ')).concat(identifiers((m[2] ?? '')));
      assignments.push({ lhs, rhs: original.slice(rhsStart, rhsEnd) });
    }
    for (const m of masked.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*=(?![=>])/g)) {
      const rhsStart = m.index! + m[0].length;
      assignments.push({ lhs: [m[1]], rhs: original.slice(rhsStart, statementEnd(masked, rhsStart)) });
    }
  } else {
    for (const m of masked.matchAll(/^[ \t]*([A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::[^=\n]+)?=(?!=)/gm)) {
      const rhsStart = m.index! + m[0].length;
      assignments.push({ lhs: m[1].split(',').map((s) => s.trim()), rhs: original.slice(rhsStart, statementEnd(masked, rhsStart)) });
    }
    for (const m of masked.matchAll(/\bfor\s+([A-Za-z_]\w*)\s+in\s+([^\n:]+):/g)) assignments.push({ lhs: [m[1]], rhs: m[2] });
  }
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    for (const a of assignments) {
      if (fromSession(a.rhs)) { for (const l of a.lhs) if (!trusted.has(l)) { trusted.add(l); names.delete(l); changed = true; } continue; }
      if (!tainted(a.rhs)) continue;
      const fromSchema = parsed(a.rhs);
      for (const l of a.lhs) {
        if (!names.has(l)) { names.add(l); changed = true; }
        if (fromSchema && !validated.has(l)) { validated.add(l); changed = true; }
      }
    }
    if (!changed) break;
  }
  return { names, validated, trusted };
}

export const isTainted = (t: Taint, expr: string, lang: Lang): boolean => {
  const e = expr.replace(TRUSTED_CHAIN, ' ');
  return (lang === 'js' ? SOURCE_JS : SOURCE_PY).test(e) || identifiers(e).some((i) => t.names.has(i) && !t.trusted.has(i));
};

// Whether a session derived value reaches this text: a trusted name, a chain such as req.user or current_user, or a field of
// a context object that the framework hands in (ctx.userId, auth.uid, session.user.id).
export const hasSessionValue = (t: Taint, expr: string): boolean => {
  TRUSTED_CHAIN.lastIndex = 0;
  if (TRUSTED_CHAIN.test(expr) || identifiers(expr).some((i) => t.trusted.has(i))) return true;
  for (const m of expr.matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)((?:\s*\??\.\s*[\w$]+)+)/g)) {
    if (t.names.has(m[1]) && !t.trusted.has(m[1])) continue;
    if (/^(?:ctx|context|auth|session|principal|identity|viewer|currentUser|me|actor|caller|user|usr|account|current)$/i.test(m[1]) && /user|id|uid|sub|account|tenant|org|owner/i.test(m[2])) return true;
  }
  return false;
};
