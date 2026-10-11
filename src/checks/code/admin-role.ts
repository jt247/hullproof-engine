// check.authz.admin-role-check: every server handler under an admin path checks an admin role on the server.
// A session check alone (any signed in user) is not a role check. Middleware or a shared guard that checks the role for
// the whole admin path is not followed in Phase 1; such a project sees this FAIL and the report says how to confirm it.
import { fileURLToPath } from 'node:url';
import type { CheckEvidence } from '../../types/index.ts';
import { byFileLine, lineOf, type CheckContext } from '../context.ts';
import type { OpOutcome } from '../ops.ts';
import type { CodeCheck } from '../types.ts';
import { handlerFiles } from './shared.ts';

const ADMIN_PATH = /(^|\/)(admin|backoffice|staff|superuser)(\/|\.|$)/i;
const ROLE_CHECK = new RegExp([
  String.raw`\brole\s*(?:===?|!==?|==)\s*["'\x60](?:admin|owner|superadmin|staff)`,
  String.raw`["'\x60](?:admin|owner|superadmin|staff)["'\x60]\s*(?:===?|!==?)\s*[\w.?]*role`,
  String.raw`\b(?:is_?admin|isAdmin|requireAdmin|require_admin|assertAdmin|ensureAdmin|adminOnly|admin_required|requireRole|require_role|checkRole|withRole|hasRole|has_role|hasPermission|has_perm|is_staff|is_superuser|authorize)\b`,
  String.raw`@(?:PreAuthorize|Secured|RolesAllowed|Roles|staff_member_required|user_passes_test|permission_required)`,
  String.raw`\bcurrent_user\.admin\?|\buser\.admin\b|roles?\.includes\(\s*["']admin`,
].join('|'));
const HANDLER = /export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|default|handler)\b|@(?:app|router|api_view|\w+)\.(?:get|post|put|patch|delete|route)\(|\bdef\s+(?:get|post|put|patch|delete|index|show|create|update|destroy)\b|\b(?:router|app)\.(?:get|post|put|patch|delete)\(/g;

export function run(ctx: CheckContext): OpOutcome {
  const files = handlerFiles(ctx).filter((f) => ADMIN_PATH.test(f));
  if (files.length === 0) return { value: 'not_applicable', reason: 'no server handler under an admin path', evidence: [], absence: null };
  const bad: CheckEvidence[] = [];
  for (const file of files) {
    const text = ctx.text(file);
    if (ROLE_CHECK.test(text)) continue;
    const handlers = [...text.matchAll(HANDLER)];
    const lines = handlers.length ? handlers.map((h) => lineOf(text, h.index!)) : [1];
    for (const line of lines) bad.push({ file, line, note: 'admin handler with no server side admin role check' });
  }
  return {
    value: bad.length === 0,
    evidence: bad.sort(byFileLine),
    absence: { pattern: ROLE_CHECK.source, files_searched: files.length, file_globs: ['handler files under an admin path'], matches: files.length - new Set(bad.map((b) => b.file)).size },
  };
}

export const check: CodeCheck = {
  id: 'check.authz.admin-role-check',
  sec_ids: ['SEC-AUTHZ-020'],
  applies_when: {},
  op: 'code',
  on_true: 'NOT ASSESSED: NEEDS DYNAMIC TEST',
  on_false: 'FAIL',
  fixtures: { pass: 'test/fixtures/checks/admin-role-check/pass', fail: 'test/fixtures/checks/admin-role-check/fail' },
  source: fileURLToPath(import.meta.url),
  run,
};
