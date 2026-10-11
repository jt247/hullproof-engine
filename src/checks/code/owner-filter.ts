// Two checks from one detector: a record read by an id that came from the request (or from a model's tool arguments)
// must also be filtered by its owner. check.authz.owner-filter-on-id-read covers request handlers (SEC-AUTHZ-003);
// check.ai.tool-owner-filter covers functions handed to a model as tools (SEC-AI-021).
// Detected read forms: SQL text (any driver), Prisma and Drizzle style where objects, Supabase .eq('id'), Mongoose
// findById, Django .get(pk=) and get_object_or_404, Rails .find(params[:id]), Laravel ::find / findOrFail.
// It reads code, so it can FAIL those runtime requirements for the part a file settles and never PASS them.
import { fileURLToPath } from 'node:url';
import type { CheckEvidence } from '../../types/index.ts';
import { byFileLine, lineOf, type CheckContext } from '../context.ts';
import type { OpOutcome } from '../ops.ts';
import type { CodeCheck } from '../types.ts';
import { handlerFiles, NOT_HANDLER } from './shared.ts';

const READS: { re: RegExp; what: string }[] = [
  { re: /\bSELECT\b[^;"'`]*?\bWHERE\s+(?:\w+\.)?(?:id|pk|uuid)\s*=\s*(?:\?|\$\d+|:\w+|%s|@\w+|\$\{)/gi, what: 'SQL read by id' },
  { re: /\.(?:findUnique|findFirst|findOne|findOneBy|findOneOrFail)\(\s*\{\s*where:\s*\{\s*id\s*[:,}]/g, what: 'ORM read by id' },
  { re: /\.(?:findById|findByPk|findOneById)\(/g, what: 'ORM read by id' },
  { re: /\.eq\(\s*["'](?:id|uuid)["']\s*,/g, what: 'Supabase read by id' },
  { re: /\.objects\.get\(\s*(?:id|pk)\s*=|get_object_or_404\(\s*\w+\s*,\s*(?:id|pk)\s*=/g, what: 'Django read by id' },
  { re: /\.find\(\s*params\[:id\]\s*\)|::(?:find|findOrFail)\(\s*\$(?:id|request)/g, what: 'Rails or Laravel read by id' },
];
// Words that show the read is scoped to the caller.
const OWNER = /owner|user_?id|userId|tenant|account_?id|accountId|org_?id|orgId|organization|workspace|created_by|createdBy|author|auth\.uid|current_?user|request\.user|session\.user|\.user\.id|ctx\.user|scope|policy/i;
// Words that show the id came from the request or from model arguments.
const INPUT = /params|args|arguments|req\.|request\.|query|body|input|searchParams|\$_(GET|POST|REQUEST)|kwargs/;
const WRITE = /\b(UPDATE|DELETE|INSERT)\b/i;

// The statement around a match: from the match to the first semicolon or blank line, at most 6 lines.
function statement(text: string, at: number): string {
  const lines = text.slice(at).split('\n').slice(0, 6);
  const out: string[] = [];
  for (const l of lines) { if (out.length && l.trim() === '') break; out.push(l); if (/;\s*$/.test(l)) break; }
  return out.join('\n');
}

function scan(files: string[], ctx: CheckContext): CheckEvidence[] {
  const bad: CheckEvidence[] = [];
  for (const file of files) {
    const text = ctx.text(file);
    for (const { re, what } of READS) {
      re.lastIndex = 0;
      for (let m = re.exec(text); m; m = re.exec(text)) {
        // For SQL, judge only the WHERE clause onward: an owner column in the select list filters nothing.
        const where = m[0].search(/\bWHERE\b/i);
        const stmt = statement(text, m.index + Math.max(0, where));
        if (WRITE.test(m[0]) || OWNER.test(stmt) || !INPUT.test(stmt)) continue;
        bad.push({ file, line: lineOf(text, m.index), note: `${what} with an id from the request and no owner filter` });
      }
    }
  }
  return bad.sort(byFileLine);
}

const AI_TOOL_GLOBS = ['**/{ai,llm,agent,agents,mcp,tools}/**/*.{ts,js,mjs,py}', '**/*tool*.{ts,js,mjs,py}'];
const aiToolFiles = (ctx: CheckContext): string[] =>
  ctx.select(AI_TOOL_GLOBS, NOT_HANDLER).filter((f) => /\btools?\b|tool_call|function_call|bind_tools|@tool\b/.test(ctx.text(f)));

function outcome(files: string[], ctx: CheckContext, none: string): OpOutcome {
  if (files.length === 0) return { value: 'not_applicable', reason: none, evidence: [], absence: null };
  const bad = scan(files, ctx);
  return {
    value: bad.length === 0,
    evidence: bad,
    absence: { pattern: 'reads by id (SQL, ORM, Supabase, Django, Rails, Laravel) with no owner, user or tenant term in the statement', files_searched: files.length, file_globs: [], matches: bad.length },
  };
}

const source = fileURLToPath(import.meta.url);

export const ownerFilter: CodeCheck = {
  id: 'check.authz.owner-filter-on-id-read',
  sec_ids: ['SEC-AUTHZ-003'],
  applies_when: {},
  op: 'code',
  on_true: 'NOT ASSESSED: NEEDS DYNAMIC TEST',
  on_false: 'FAIL',
  fixtures: { pass: 'test/fixtures/checks/owner-filter-on-id-read/pass', fail: 'test/fixtures/checks/owner-filter-on-id-read/fail' },
  source,
  run: (ctx) => {
    const ai = new Set(aiToolFiles(ctx));
    return outcome(handlerFiles(ctx).filter((f) => !ai.has(f)), ctx, 'no request handler found');
  },
};

export const toolOwnerFilter: CodeCheck = {
  id: 'check.ai.tool-owner-filter',
  sec_ids: ['SEC-AI-021'],
  applies_when: {},
  op: 'code',
  on_true: 'NOT ASSESSED: NEEDS DYNAMIC TEST',
  on_false: 'FAIL',
  fixtures: { pass: 'test/fixtures/checks/tool-owner-filter/pass', fail: 'test/fixtures/checks/tool-owner-filter/fail' },
  source,
  run: (ctx) => outcome(aiToolFiles(ctx), ctx, 'no file that defines tools for a model was found'),
};
