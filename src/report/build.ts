// Builds results.json (one row per requirement in scope) and the findings record (schema 1.1.0) from the check results
// and scanner hits. FAIL comes only from a FAIL check or a mapped rule hit; PASS (static) only from a check on a repo
// authority requirement; every other requirement in scope is NOT ASSESSED with the sub state that closes it.
import { createHash } from 'node:crypto';
import { cmp, stableJson, stableJsonCompact } from '../util.ts';
import { ENGINE_VERSION } from '../version.ts';
import type {
  CheckResult, CheckResultsFile, FailRecord, FileLineNote, FindingsFile, FindingRecord, Hit, ObservationRecord, ResultRow,
  ResultWord, RouteState, Severity, ToolMeta,
} from '../types/index.ts';
import { checkMessage, ruleMessage } from './messages.ts';
import { highest, inScope, type Control, type Kit, type Scope } from './kit.ts';
import { TEST_ARTIFACT_IDS, testCodeReason } from './test-code.ts';
import { isSecretHit, leadReason, leadTier, loadTiers } from './tiers.ts';

export interface GitState { commit: string; tree: string; clean: boolean }
export interface BuildInput {
  kit: Kit; scope: Scope; git: GitState; checks: CheckResultsFile; hits: Hit[]; metas: ToolMeta[];
  checkShas: Record<string, string>;  // check id -> sha256 of its definition file
  rulesDirs: string[];               // Semgrep rule folders (engine, then the rule pack), for the plain English text
}

const MAX_NOTE = 600;
// Checks whose FAIL means a control is missing everywhere searched (class missing_control, with the search recorded).
const ABSENCE_CHECKS = new Set(['check.web.security-headers-configured', 'check.auth.login-rate-limit', 'check.supply.lockfile-committed']);
// A fingerprint path has no spaces or colons.
const fpPath = (f: string): string => f.replace(/[\s:]/g, '_');
const clip = (s: string, n: number): string => (s.length <= n ? s : s.slice(0, n - 1).trimEnd() + '…');
const slug = (s: string, max = 12): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').split('-').filter(Boolean).slice(0, max).join('-') || 'x';
const where = (e: { file: string; line?: number }): string => (e.line ? `${e.file}:${e.line}` : e.file);

// The sub state for a requirement nothing settled, from its authority and how it is verified.
export function routeFor(c: Control): RouteState {
  if (c.authority === 'dashboard') return 'NEEDS DASHBOARD';
  if (c.authority === 'runtime') return 'NEEDS DYNAMIC TEST';
  return 'UNKNOWN';
}

export const OWNER_ACTION: Record<RouteState, string> = {
  'NEEDS DASHBOARD': 'Export the provider setting (screenshot or export, dated, naming the project) and record it.',
  'NEEDS BUILD': 'Run a production build from this commit and scan the output.',
  'NEEDS DYNAMIC TEST': 'Test the running app or a staging copy and record the requests and responses.',
  'ASK OWNER': 'Answer the question in writing.',
  'ATTESTATION': 'Sign and date a statement.',
  'UNKNOWN': 'No engine check or rule settles this from the files. A code review (a person, or the Hullproof audit) must read the code and record the result.',
};

interface Fail { source: string; sec_ids: string[]; evidence: { file: string; line?: number; note: string }[] }

// A finding kept for the report and never in results.json or the gate: test code (src/report/test-code.ts), or a lead
// from a rule whose confidence tier is lead (src/report/tiers.ts).
interface TestItem { hit?: Hit; check?: CheckResult; ids: string[]; reason: string; kind: 'test' | 'lead' }

// Splits hits and failed checks into what can fail a requirement and what is only reported. In order:
// 1. A secret (a Gitleaks hit or a rule mapped to a SEC-SECRETS ID) always stays: a live key is a leak wherever it is.
// 2. In a test path, a requirement about shipped test material (TEST_ARTIFACT_IDS) keeps failing; every other ID moves
//    to a test code item.
// 3. A hit of a rule whose tier is lead moves to a lead item.
export function separateTestCode(input: BuildInput): { input: BuildInput; test: TestItem[] } {
  const test: TestItem[] = [];
  const hits: Hit[] = [];
  const tiers = loadTiers(input.rulesDirs ?? []);
  for (const h of input.hits) {
    const reason = isSecretHit(h) ? null : testCodeReason(h.file);
    if (reason) {
      const keep = h.sec_ids.filter((id) => TEST_ARTIFACT_IDS.has(id));
      if (keep.length) hits.push({ ...h, sec_ids: keep });
      if (keep.length < h.sec_ids.length || !h.sec_ids.length) test.push({ hit: h, ids: h.sec_ids.filter((id) => !TEST_ARTIFACT_IDS.has(id)), reason, kind: 'test' });
      continue;
    }
    const lead = leadTier(h, tiers);
    if (lead) { test.push({ hit: h, ids: h.sec_ids, reason: leadReason(lead, tiers), kind: 'lead' }); continue; }
    hits.push(h);
  }
  const results: CheckResult[] = [];
  for (const r of input.checks.results) {
    const secret = r.sec_ids.some((id) => id.startsWith('SEC-SECRETS-'));
    const inTest = r.result === 'FAIL' && !secret && !r.sec_ids.some((id) => TEST_ARTIFACT_IDS.has(id)) ? r.evidence.filter((e) => testCodeReason(e.file)) : [];
    const shipped = r.evidence.filter((e) => !inTest.includes(e));
    if (inTest.length) test.push({ check: { ...r, evidence: inTest }, ids: r.sec_ids, reason: testCodeReason(inTest[0].file)!, kind: 'test' });
    // A FAIL whose evidence is all in test code no longer fails; one with no evidence (an absence check) still does.
    if (!inTest.length || shipped.length) results.push(inTest.length ? { ...r, evidence: shipped } : r);
  }
  return { input: { ...input, hits, checks: { ...input.checks, results } }, test };
}

function failsFor(input: BuildInput): Fail[] {
  const out: Fail[] = [];
  for (const r of input.checks.results) if (r.result === 'FAIL') out.push({ source: r.check_id, sec_ids: r.sec_ids, evidence: r.evidence });
  for (const h of input.hits) if (h.sec_ids.length) out.push({ source: `${h.tool} rule ${h.rule_id}`, sec_ids: h.sec_ids, evidence: [{ file: h.file, line: h.line || undefined, note: h.rule_id }] });
  return out;
}

export function buildResults(all: BuildInput): ResultRow[] {
  const input = separateTestCode(all).input;
  const { kit, scope } = input;
  const fails = failsFor(input);
  const checkWords = new Map<string, CheckResult[]>();
  for (const r of input.checks.results) for (const id of r.sec_ids) checkWords.set(id, [...(checkWords.get(id) ?? []), r]);
  const skippedBy = new Map<string, string[]>();
  for (const m of input.metas) if (m.status !== 'ran') for (const id of m.not_assessed_sec_ids) skippedBy.set(id, [...(skippedBy.get(id) ?? []), `${m.tool} (${m.status})`]);

  const rows: ResultRow[] = [];
  for (const c of kit.controls.filter((x) => inScope(x, scope)).sort((a, b) => cmp(a.id, b.id))) {
    const mine = fails.filter((f) => f.sec_ids.includes(c.id));
    if (mine.length) {
      const where1 = mine.flatMap((f) => f.evidence.slice(0, 3).map((e) => `${f.source} at ${where(e)}`));
      rows.push({ id: c.id, result: 'FAIL', notes: clip(`Failed by ${[...new Set(where1)].join('; ')}.`, MAX_NOTE) });
      continue;
    }
    const words = checkWords.get(c.id) ?? [];
    const pass = words.find((w) => w.result === 'PASS (static)');
    if (pass && c.authority === 'repo') {
      rows.push({ id: c.id, result: 'PASS (static)', notes: clip(`Settled by ${pass.check_id} on the files of this commit.`, MAX_NOTE) });
      continue;
    }
    // A check that ran and found nothing wrong names the sub state that would settle the rest.
    const routed = words.map((w) => w.result).find((w) => w.startsWith('NOT ASSESSED: ')) as ResultWord | undefined;
    const state = (routed ? routed.slice('NOT ASSESSED: '.length) : routeFor(c)) as RouteState;
    const parts = [routed ? `${words.map((w) => w.check_id).join(', ')} found nothing wrong in the files; that cannot settle it.` : '', OWNER_ACTION[state]];
    const skipped = skippedBy.get(c.id);
    if (skipped) parts.push(`Not run: ${skipped.join(', ')}.`);
    rows.push({ id: c.id, result: `NOT ASSESSED: ${state}`, notes: clip(parts.filter(Boolean).join(' '), MAX_NOTE) });
  }
  return rows;
}

// Requirement IDs of a fail split into those in scope (they make a fail record) and the rest.
function split(ids: string[], input: BuildInput): { scoped: string[]; known: string[]; unknown: string[] } {
  const known = ids.filter((id) => input.kit.byId.has(id));
  return {
    scoped: known.filter((id) => inScope(input.kit.byId.get(id)!, input.scope)).sort(cmp),
    known: known.sort(cmp),
    unknown: ids.filter((id) => !input.kit.byId.has(id)).sort(cmp),
  };
}

const refs = (ev: { file: string; line?: number; note: string }[]): FileLineNote[] =>
  ev.slice(0, 8).map((e) => ({ file: e.file, line: e.line && e.line > 0 ? e.line : 1, note: clip(e.note, 300) }));

export interface Dropped { source: string; ids: string[]; where: string }

// Past the kit's size warning even on one line, a rule that matched more than COLLAPSE_FILES files gets one record for
// all its files instead of one per file; every hit stays in scan/<tool>.json, and the record says how many files.
// ponytail: fixed file count per rule; lower it or group per folder if a repository still passes the kit limit.
const COLLAPSE_FILES = 20;
export function buildFindings(all: BuildInput): { file: FindingsFile; dropped: Dropped[] } {
  const first = buildFindingsWith(all, null);
  return stableJsonCompact(first.file).length <= KIT_WARN_BLOCK_CHARS ? first : buildFindingsWith(all, COLLAPSE_FILES);
}

function buildFindingsWith(all: BuildInput, collapse: number | null): { file: FindingsFile; dropped: Dropped[] } {
  const { input, test } = separateTestCode(all);
  // tool and rule -> files it matched, in shipped code and in test code apart.
  const filesOf = new Map<string, Set<string>>();
  const note = (k: string, f: string): void => { filesOf.set(k, (filesOf.get(k) ?? new Set()).add(f)); };
  for (const h of input.hits) note(`${h.tool}\u0000${h.rule_id}`, h.file);
  for (const t of test) if (t.hit) note(`${t.kind}\u0000${t.hit.tool}\u0000${t.hit.rule_id}`, t.hit.file);
  const many = (k: string): number => (collapse !== null && (filesOf.get(k)?.size ?? 0) > collapse ? filesOf.get(k)!.size : 0);
  const records: FindingRecord[] = [];
  const dropped: Dropped[] = [];
  const add = (o: {
    source: string; ruleId: string; tool: string; toolVersion: string; configSha: string | null; ids: string[];
    evidence: { file: string; line?: number; note: string }[]; msg: ReturnType<typeof checkMessage>; absence: CheckResult['absence_search']; line?: number;
  }): void => {
    const s = split(o.ids, input);
    const file0 = fpPath(o.evidence[0]?.file ?? '-');
    if (s.unknown.length) dropped.push({ source: o.source, ids: s.unknown, where: where(o.evidence[0] ?? { file: '-' }) });
    if (s.scoped.length === 0) {
      // Outside this run's edition or stage, or unmapped: shown as an observation, never in the gate.
      const obs: ObservationRecord = {
        fingerprint: `OBS:${file0}:${slug(`${o.ruleId} ${o.line ?? ''}`)}`, kind: 'observation', sec_ids: s.known, title: clip(o.msg.title, 160),
        where: refs(o.evidence).slice(0, 4),
        note: clip(s.known.length ? `Outside this run's scope (${input.scope.edition} edition, ${input.scope.stage} stage): ${s.known.join(', ')}. ${o.msg.fix}` : `No requirement is mapped to ${o.source}${s.unknown.length ? ` in this kit (named: ${s.unknown.join(', ')})` : ''}. ${o.msg.fix}`, 400),
        raised_by: ['hullproof-engine'],
      };
      records.push(obs);
      return;
    }
    const sev: Severity = highest(s.scoped.map((id) => input.kit.byId.get(id)!.severity));
    const rec: FailRecord = {
      fingerprint: `${s.scoped[0]}:${file0}:${slug(`${o.ruleId} ${o.line ?? ''}`)}`,
      kind: 'fail', sec_ids: s.scoped, title: clip(o.msg.title, 160),
      class: o.tool === 'hullproof-check' && ABSENCE_CHECKS.has(o.ruleId) && o.absence ? 'missing_control' : 'finding',
      gap_in_standard: false, severity: sev, confidence: 'SUSPECTED', demonstrated: false,
      root_cause: clip(o.msg.root, 120), raised_by: ['hullproof-engine'], impact_statement: clip(o.msg.impact, 600),
      remediation: { strategy: clip(o.msg.fix, 800), confirm: clip(o.msg.confirm, 400) },
      evidence: refs(o.evidence),
      machine_evidence: { tool: o.tool, rule_id: o.ruleId, tool_version: o.toolVersion.replace(/[^A-Za-z0-9._+-]/g, '-') || 'unknown', config_sha256: o.configSha },
    };
    if (rec.class === 'missing_control') {
      rec.absence_search = { command: clip(`${o.ruleId}: ${o.absence!.pattern} over ${o.absence!.file_globs.join(' ') || 'the selected files'}`, 300), files_searched: o.absence!.files_searched, count: o.absence!.matches, practice: 'present_unsafe' };
    }
    records.push(rec);
  };

  for (const r of input.checks.results) {
    if (r.result !== 'FAIL') continue;
    add({ source: r.check_id, ruleId: r.check_id, tool: 'hullproof-check', toolVersion: ENGINE_VERSION, configSha: input.checkShas[r.check_id] ?? null,
      ids: r.sec_ids, evidence: r.evidence, msg: checkMessage(r.check_id), absence: r.absence_search });
  }
  // Scanner hits: one record per tool, rule and file, with up to 8 lines.
  const groups = new Map<string, Hit[]>();
  for (const h of input.hits) {
    const k = `${h.tool}\u0000${h.rule_id}\u0000${many(`${h.tool}\u0000${h.rule_id}`) ? '*' : h.file}`;
    groups.set(k, [...(groups.get(k) ?? []), h]);
  }
  for (const k of [...groups.keys()].sort(cmp)) {
    const hs = groups.get(k)!;
    const h = hs[0];
    const n = many(`${h.tool}\u0000${h.rule_id}`);
    const meta = input.metas.find((m) => m.tool === h.tool);
    const label = n ? `${h.tool} rule ${h.rule_id}, which matched ${n} files (all in scan/${h.tool}.json)` : `${h.tool} rule ${h.rule_id}`;
    add({ source: `${h.tool} rule ${h.rule_id}`, ruleId: h.rule_id, tool: h.tool, toolVersion: meta?.version ?? 'unknown', configSha: meta?.config_sha256 ?? null,
      ids: [...new Set(hs.flatMap((x) => x.sec_ids))], evidence: hs.map((x) => ({ file: x.file, line: x.line || undefined, note: clip(label, 300) })),
      msg: ruleMessage(h.tool, h.rule_id, input.rulesDirs), absence: null, line: n ? undefined : h.line });
  }

  // Test code and leads: one observation per tool, rule and file, marked by a fingerprint slug that starts with
  // test-code or lead.
  const testGroups = new Map<string, TestItem[]>();
  for (const t of test) {
    const k = t.hit
      ? `${t.kind}\u0000${t.hit.tool}\u0000${t.hit.rule_id}\u0000${many(`${t.kind}\u0000${t.hit.tool}\u0000${t.hit.rule_id}`) ? '*' : t.hit.file}`
      : `${t.kind}\u0000hullproof-check\u0000${t.check!.check_id}\u0000${t.check!.evidence[0].file}`;
    testGroups.set(k, [...(testGroups.get(k) ?? []), t]);
  }
  for (const k of [...testGroups.keys()].sort(cmp)) {
    const ts = testGroups.get(k)!;
    const [kind, tool, ruleId, key] = k.split('\u0000');
    const file = key === '*' ? ts[0].hit!.file : key;
    const msg = ts[0].hit ? ruleMessage(tool, ruleId, input.rulesDirs) : checkMessage(ruleId);
    const ev = ts.flatMap((t) => (t.hit ? [{ file: t.hit.file, line: t.hit.line || undefined, note: `${tool} rule ${ruleId}` }] : t.check!.evidence));
    const ids = [...new Set(ts.flatMap((t) => t.ids))].filter((id) => input.kit.byId.has(id)).sort(cmp);
    const isLead = kind === 'lead';
    records.push({
      fingerprint: `OBS:${fpPath(file)}:${slug(`${isLead ? 'lead' : 'test code'} ${ruleId} ${ts[0].hit?.line ?? ''}`, 14)}`, kind: 'observation', sec_ids: ids,
      title: clip(`${isLead ? 'Lead' : 'Test code'}: ${msg.title}`, 160), where: refs(ev).slice(0, 4),
      note: clip(isLead
        ? `Lead from rule ${ruleId}, whose confidence tier is lead: ${ts[0].reason}. Read the code; it never holds the gate.${ids.length ? ` If real it fails ${ids.join(', ')}.` : ''}`
        : `Test code (${ts[0].reason}): kept as a lead, never in the gate.${ids.length ? ` In shipped code it would fail ${ids.join(', ')}.` : ''} ${msg.fix}`, 400),
      raised_by: ['hullproof-engine'],
    });
  }

  // Fingerprints are unique: a second record with the same tail gets a short hash of its source.
  const seen = new Set<string>();
  for (const r of records) {
    let fp = r.fingerprint;
    const tail = fp.slice(fp.indexOf(':') + 1);
    if (seen.has(tail)) fp = `${fp}-${createHash('sha256').update(JSON.stringify(r)).digest('hex').slice(0, 6).replace(/[^a-z0-9]/g, 'a')}`;
    seen.add(fp.slice(fp.indexOf(':') + 1));
    r.fingerprint = fp;
  }
  records.sort((a, b) => cmp(a.fingerprint, b.fingerprint));
  const needsVerifier = records.some((r) => r.kind === 'fail' && (r.severity === 'BLOCKER' || r.severity === 'CRITICAL' || r.sec_ids.some((id) => ['BLOCKER', 'CRITICAL'].includes(input.kit.byId.get(id)!.severity))));
  const file: FindingsFile = {
    schema_version: '1.1.0',
    report: {
      commit: input.git.commit, tree: input.git.tree, tree_clean: input.git.clean, stage: input.scope.stage, profile: 'standard', scope: 'full',
      // No model and no verifier run in Phase 1. A BLOCKER or CRITICAL record needs a verifier outcome in a complete run,
      // so such a run is recorded incomplete with the kit's reason for exactly this: deterministic_only (schema 1.1.0).
      run_status: needsVerifier ? 'incomplete' : 'complete',
      ...(needsVerifier ? { incomplete_reason: 'deterministic_only' as const } : {}),
      agent_calls: 0, budget: null,
    },
    records,
  };
  return { file, dropped: dropped.sort((a, b) => cmp(a.source + a.where, b.source + b.where)) };
}

// The kit validator warns on a findings block over 150000 characters and rejects one over 200000 (rule F3). Indented JSON
// is written while it stays under the warning size; past it the same sorted JSON goes on one line, which is about 40
// percent shorter on the targets measured (juice-shop with a large rule pack: 207103 indented).
// ponytail: compact JSON only raises the ceiling; group records per rule instead of per file if a repository passes it.
export const KIT_WARN_BLOCK_CHARS = 150000;
export function findingsJson(f: FindingsFile): string {
  const pretty = stableJson(f);
  return pretty.length <= KIT_WARN_BLOCK_CHARS ? pretty : stableJsonCompact(f);
}

export function findingsMarkdown(f: FindingsFile, json: string): string {
  return [
    '# Findings record', '',
    `Written by the Hullproof Engine ${ENGINE_VERSION} for commit ${f.report.commit}. Every record comes from a check or a scanner rule, with no model. Validate it with tools/hullproof/ci/validate-findings.mjs from the kit.`, '',
    '```hullproof-findings', json.trimEnd(), '```', '',
  ].join('\n');
}
