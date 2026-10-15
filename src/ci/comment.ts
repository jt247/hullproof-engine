// pr-comment.md: the summary posted on a pull request. Same findings, same bytes: no clock, no link to a run.
// The first line is a marker so the Action can find and update its own comment instead of adding a new one each push.
import { cmp } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import type { FailRecord, FindingsFile, Severity } from '../types/index.ts';
import { SEV_RANK } from '../report/kit.ts';

export const COMMENT_MARKER = '<!-- hullproof-ci -->';
export const FAIL_ON_LEVELS = ['blocker', 'critical', 'high', 'medium', 'low', 'none'] as const;
export type FailOn = typeof FAIL_ON_LEVELS[number];
const MAX_ROWS = 15;

export interface CiVerdict { blocked: boolean; blocking: FailRecord[]; others: FailRecord[] }

// The CI verdict. A fail record blocks when its severity is at or above the chosen level. Only fail records count: observations,
// leads and routed items never do, as in the release gate. "none" never blocks.
export function ciVerdict(f: FindingsFile, failOn: FailOn): CiVerdict {
  const fails = f.records.filter((r): r is FailRecord => r.kind === 'fail')
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || cmp(a.fingerprint, b.fingerprint));
  const min = failOn === 'none' ? 99 : SEV_RANK[failOn.toUpperCase() as Severity];
  const blocking = fails.filter((r) => SEV_RANK[r.severity] >= min);
  return { blocked: blocking.length > 0, blocking, others: fails.filter((r) => !blocking.includes(r)) };
}

const cell = (s: string): string => s.replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
const where = (r: FailRecord): string => (r.evidence[0] ? `\`${r.evidence[0].file}:${r.evidence[0].line}\`` : 'repository');

export interface CommentInput {
  findings: FindingsFile; verdict: CiVerdict; failOn: FailOn; edition: 'free' | 'pro'; scanners: string[];
}

export function prComment(i: CommentInput): string {
  const { findings, verdict, failOn } = i;
  const out: string[] = [COMMENT_MARKER];
  const p = (...l: string[]): void => { out.push(...l); };
  const n = verdict.blocking.length;
  p(`## Hullproof: ${verdict.blocked ? `${n} blocking finding${n === 1 ? '' : 's'}` : 'no blocking findings'}`, '');
  p(`Commit \`${findings.report.commit.slice(0, 12)}\`. Hullproof Engine ${ENGINE_VERSION}, ${i.edition} edition, stage ${findings.report.stage}. This check fails on ${failOn === 'none' ? 'nothing (report only)' : `${failOn.toUpperCase()} and above`}. Scanners that ran: ${i.scanners.length ? i.scanners.join(', ') : 'none'}.`, '');
  if (verdict.blocked) {
    p('| Severity | Where | Finding | Requirement |', '|---|---|---|---|');
    for (const r of verdict.blocking.slice(0, MAX_ROWS)) p(`| ${r.severity} | ${where(r)} | ${cell(r.title)} | ${r.sec_ids.join(', ')} |`);
    if (n > MAX_ROWS) p('', `${n - MAX_ROWS} more blocking findings are in report.md.`);
    p('', '### How to fix the first one', '');
    const first = verdict.blocking[0];
    p(cell(first.impact_statement), '', cell(first.remediation.strategy), '', `To check the fix: ${cell(first.remediation.confirm)}`);
  } else {
    p('Nothing at or above the chosen level failed a check or a mapped rule. That does not mean the requirements pass: most are settled by provider settings or a test of the running app, and report.md lists what nothing settled.');
  }
  if (verdict.others.length) p('', `Other findings below the blocking level: ${verdict.others.length} (see report.md).`);
  p('', 'This comment comes from code and configuration only, with no model. The full report and results.sarif are in the workflow artifacts.', '');
  return out.join('\n');
}
