// Loads every check (checks/*.json and the TypeScript checks in src/checks/code/), runs the ones that apply, and returns
// checks.json. Deterministic: files and checks are sorted, no clock, no network, no program is run.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cmp } from '../util.ts';
import type { CheckDefinition, CheckResult, CheckResultsFile, Stack } from '../types/index.ts';
import type { CheckContext } from './context.ts';
import { OPS, type OpOutcome } from './ops.ts';
import type { AnyCheck, CodeCheck } from './types.ts';
import { check as webhookVerify } from './code/webhook-verify.ts';
import { ownerFilter, toolOwnerFilter } from './code/owner-filter.ts';
import { check as adminRole } from './code/admin-role.ts';

export const CHECKS_DIR = fileURLToPath(new URL('../../checks/', import.meta.url));
export const CODE_CHECKS: CodeCheck[] = [webhookVerify, ownerFilter, toolOwnerFilter, adminRole];

export function loadChecks(dir: string = CHECKS_DIR): AnyCheck[] {
  const json = readdirSync(dir).filter((n) => n.endsWith('.json')).sort(cmp)
    .map((n) => ({ ...(JSON.parse(readFileSync(join(dir, n), 'utf8')) as CheckDefinition), source: join(dir, n) }));
  return [...json, ...CODE_CHECKS].sort((a, b) => cmp(a.id, b.id));
}

// sha256 of the check's own file: a JSON definition or the TypeScript module. Goes into machine_evidence.config_sha256.
const shaCache = new Map<string, string>();
export function checkSha(c: AnyCheck): string {
  let s = shaCache.get(c.source);
  if (!s) { s = createHash('sha256').update(readFileSync(c.source)).digest('hex'); shaCache.set(c.source, s); }
  return s;
}

// The check applies when every category it names has an item whose id it lists (or any item for "*").
export function appliesTo(c: AnyCheck, stack: Stack): string | null {
  for (const [cat, want] of Object.entries(c.applies_when)) {
    const items = (stack[cat as keyof Stack] as { id: string }[] | undefined) ?? [];
    const ok = want === '*' ? items.length > 0 : items.some((i) => (want as string[]).includes(i.id));
    if (!ok) return `not applicable: stack.json has no ${cat} item${want === '*' ? '' : ` of ${(want as string[]).join(', ')}`}`;
  }
  return null;
}

export function runOne(c: AnyCheck, ctx: CheckContext): OpOutcome {
  if (c.op === 'code') return (c as CodeCheck).run(ctx);
  const op = OPS[c.op];
  if (!op) return { value: 'cannot_run', reason: `the op ${c.op} is not built in this engine version`, evidence: [], absence: null };
  return op(ctx, (c as CheckDefinition).params);
}

export function runChecks(ctx: CheckContext, checks: AnyCheck[] = loadChecks()): CheckResultsFile {
  const results: CheckResult[] = [];
  const notRun: { check_id: string; reason: string }[] = [];
  for (const c of checks) {
    const skip = appliesTo(c, ctx.stack);
    if (skip) { notRun.push({ check_id: c.id, reason: skip }); continue; }
    let o: OpOutcome;
    try { o = runOne(c, ctx); } catch (e) { o = { value: 'cannot_run', reason: `the check failed: ${(e as Error).message}`, evidence: [], absence: null }; }
    if (o.value === 'not_applicable') { notRun.push({ check_id: c.id, reason: `not applicable: ${o.reason ?? ''}`.trim() }); continue; }
    if (o.value === 'cannot_run') { notRun.push({ check_id: c.id, reason: `cannot run: ${o.reason ?? ''}`.trim() }); continue; }
    results.push({
      check_id: c.id,
      sec_ids: [...c.sec_ids].sort(cmp),
      result: o.value ? c.on_true : c.on_false,
      evidence: o.evidence,
      absence_search: o.absence,
      message_key: c.id,
    });
  }
  return { schema_version: '1.0.0', commit: ctx.stack.commit, results, not_run: notRun };
}
