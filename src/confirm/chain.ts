// The names on a route's own chain (the middleware and helper calls written between the path and the handler) that the code map
// cannot classify. A map query talks about input, ownership and protections as the map knows them. When the chain holds a call
// whose name looks like it checks, binds or filters the caller or the request (security.appendUserId() is the example from Juice
// Shop) and the map has no protection for that name, the map cannot say the claim is true, so a query must not confirm it.
import type { CodeMap, EntryPoint } from '../types/index.ts';
import type { FileCache } from './honesty.ts';

const MAX_LINES = 8;
// Names that plausibly act on the caller or the request. A wrapper such as withErrors or asyncHandler does not match.
const RELEVANT = /(auth|user|owner|session|token|guard|verify|check|permission|role|tenant|account|csrf|protect|secure|policy|allow|deny|require|login|acl|admin|scope|bind|append|limit|throttle|sanit|validate|can[A-Z]|is[A-Z])/;
const REGISTER = /^(app|router|server|api|[A-Za-z_$][\w$]*Router)\.(get|post|put|patch|delete|all|options|head|use|route)$/;

// Top level arguments of the first call that opens in `text`, as strings.
function firstCallArgs(text: string): string[] {
  const open = text.indexOf('(');
  if (open < 0) return [];
  const args: string[] = [];
  let depth = 0, cur = '', quote = '';
  for (let i = open + 1; i < text.length; i++) {
    const c = text[i];
    if (quote) { cur += c; if (c === quote && text[i - 1] !== '\\') quote = ''; continue; }
    if (c === '"' || c === "'" || c === '`') { quote = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    if (c === ')' || c === ']' || c === '}') { if (depth === 0) { args.push(cur.trim()); return args; } depth--; }
    if (c === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  return args;
}

const callName = (arg: string): string | null => /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/.exec(arg)?.[1] ?? null;

// Calls on the chain, in order. Express style: every argument between the path and the last argument (the handler). Wrapper style
// (`export const POST = withX(...)`): the wrapper name. Decorator style (Flask): every decorator that is not the route.
export function chainCalls(text: string, line: number): string[] {
  const lines = text.split('\n').slice(line - 1, line - 1 + MAX_LINES);
  const first = lines.join('\n');
  const out: string[] = [];
  const reg = /^\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/.exec(first);
  if (reg && REGISTER.test(reg[1])) {
    const args = firstCallArgs(first);
    for (const a of args.slice(1, -1)) { const n = callName(a); if (n) out.push(n); }
    return out;
  }
  const wrap = /^\s*(?:export\s+)?(?:const|let)\s+\w+\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*\(/.exec(first);
  if (wrap) out.push(wrap[1]);
  for (const l of lines) {
    const d = /^\s*@([A-Za-z_][\w.]*)/.exec(l);
    if (d && !/\.route$|\.(get|post|put|delete|patch)$/.test(d[1])) out.push(d[1]);
    if (/^\s*(async\s+)?def\s/.test(l)) break;
  }
  return out;
}

const known = (name: string, ep: EntryPoint, map: CodeMap): boolean => {
  const last = name.split('.').pop()!.toLowerCase();
  const vias = [...ep.protections, ...map.gates.flatMap((g) => g.protections)].map((p) => p.via.toLowerCase());
  const vocab = [...map.config.local_vocab.auth_helpers, ...map.config.local_vocab.role_helpers].map((v) => v.toLowerCase());
  return vias.some((v) => v.includes(last)) || vocab.includes(last);
};

// Names on the chain of `ep` that look like they act on the caller or the request and that the map does not know.
export function unknownProtections(ep: EntryPoint, map: CodeMap, files: FileCache): string[] {
  const text = files.read(ep.file);
  if (!text) return [];
  return [...new Set(chainCalls(text, ep.line).filter((n) => RELEVANT.test(n.split('.').pop()!) && !known(n, ep, map)))].sort();
}
