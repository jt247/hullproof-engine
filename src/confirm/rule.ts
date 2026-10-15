// Confirmation by a generated Semgrep rule. The rule must match the lines the lead cites in the real file, and it must not match a
// negative control: a safe sample of the same kind of code that the model supplies. Both runs must really scan their file, so a rule
// for another language cannot pass by matching nothing. Semgrep runs offline with metrics off. If Semgrep is not installed the
// outcome is "not run" and the lead stays a lead.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Lead } from '../types/index.ts';

export interface SemgrepRun { status: number | null; stdout: string; missing?: boolean }
export type SemgrepRunner = (args: string[]) => SemgrepRun;
const TIMEOUT_MS = 120_000;
const SLACK = 1;

export const spawnSemgrep: SemgrepRunner = (args) => {
  const r = spawnSync('semgrep', args, { encoding: 'utf8', timeout: TIMEOUT_MS, maxBuffer: 32 * 1024 * 1024, env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' } });
  if ((r.error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT') return { status: null, stdout: '', missing: true };
  return { status: r.status, stdout: r.stdout ?? '' };
};

export type RuleOutcome =
  | { status: 'confirmed'; detail: string; rule_id: string; tool_version: string; config_sha256: string }
  | { status: 'not_confirmed'; detail: string }
  | { status: 'not_run'; detail: string };

interface Out { results: { start: { line: number }; end: { line: number } }[]; errors: unknown[]; paths?: { scanned?: string[] } }
const BANNED = /pattern-where-python|pattern-sources:\s*\n\s*-\s*exact|\binclude:|r2c-internal/;

function scanFile(run: SemgrepRunner, rule: string, target: string): { out: Out } | { fail: string } | { missing: true } {
  const r = run(['scan', '--config', rule, '--json', '--quiet', '--metrics=off', '--disable-version-check', '--no-git-ignore', '--timeout', '10', target]);
  if (r.missing) return { missing: true };
  let out: Out;
  try { out = JSON.parse(r.stdout) as Out; } catch { return { fail: 'semgrep printed no JSON for this rule' }; }
  if (!Array.isArray(out.results)) return { fail: 'semgrep printed no results list' };
  if (Array.isArray(out.errors) && out.errors.length) return { fail: 'semgrep reported an error for the rule or the file' };
  if (!(out.paths?.scanned ?? []).some((p) => resolve(p) === resolve(target))) return { fail: 'semgrep did not scan the file (the rule does not cover its language)' };
  return { out };
}

export function confirmRule(lead: Lead, repo: string, run: SemgrepRunner = spawnSemgrep): RuleOutcome {
  const p = lead.evidence_proposal;
  if (p.kind !== 'semgrep_rule') return { status: 'not_confirmed', detail: 'no rule was proposed' };
  const ids = [...p.rule_yaml.matchAll(/^\s*-\s*id:\s*([^\s#]+)/gm)].map((m) => m[1]);
  if (!/^\s*rules:/m.test(p.rule_yaml) || ids.length !== 1) return { status: 'not_confirmed', detail: 'the rule file must hold exactly one rule' };
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(ids[0])) return { status: 'not_confirmed', detail: 'the rule id has characters outside letters, digits, dot, underscore and hyphen' };
  if (BANNED.test(p.rule_yaml)) return { status: 'not_confirmed', detail: 'the rule uses a feature the engine does not accept' };
  const norm = (s: string): string => s.replace(/\s+/g, ' ').trim();
  if (norm(p.control_code).includes(norm(lead.quoted_code))) return { status: 'not_confirmed', detail: 'the negative control still holds the quoted code, so it is not a control' };

  const sink = lead.path[lead.path.length - 1];
  const dir = mkdtempSync(join(tmpdir(), 'hp-rule-'));
  try {
    const ruleFile = join(dir, 'rule.yaml');
    const controlFile = join(dir, `control.${p.control_extension}`);
    writeFileSync(ruleFile, p.rule_yaml);
    writeFileSync(controlFile, p.control_code);
    const ver = run(['--version']);
    if (ver.missing) return { status: 'not_run', detail: 'Semgrep is not installed' };
    const hit = scanFile(run, ruleFile, join(resolve(repo), sink.file));
    if ('missing' in hit) return { status: 'not_run', detail: 'Semgrep is not installed' };
    if ('fail' in hit) return { status: 'not_confirmed', detail: hit.fail };
    const onSink = hit.out.results.some((r) => r.end.line >= sink.line - SLACK && r.start.line <= sink.line + SLACK);
    if (!onSink) return { status: 'not_confirmed', detail: `the rule does not match the cited lines (${sink.file}:${sink.line})` };
    const ctl = scanFile(run, ruleFile, controlFile);
    if ('missing' in ctl) return { status: 'not_run', detail: 'Semgrep is not installed' };
    if ('fail' in ctl) return { status: 'not_confirmed', detail: `negative control: ${ctl.fail}` };
    if (ctl.out.results.length) return { status: 'not_confirmed', detail: 'the rule also matches the negative control, so it does not tell the flaw from safe code' };
    return {
      status: 'confirmed', detail: `the rule matches ${sink.file}:${sink.line} and does not match the negative control`, rule_id: `hunt.${ids[0]}`.slice(0, 190),
      tool_version: (/^\d+\.\d+[\w.+-]*/m.exec(ver.stdout)?.[0] ?? 'unknown').replace(/[^A-Za-z0-9._+-]/g, '-').slice(0, 59) || 'unknown',
      config_sha256: createHash('sha256').update(p.rule_yaml).digest('hex'),
    };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
