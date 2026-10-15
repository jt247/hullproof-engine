// Confirmation by a generated Semgrep rule with a negative control. The logic is tested with a stubbed runner; one more test runs
// the real Semgrep when it is installed and says so when it is not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { confirmHunt } from '../src/confirm/confirm.ts';
import { parseOutput } from '../src/confirm/lead.ts';
import { confirmRule, type SemgrepRunner } from '../src/confirm/rule.ts';
import { answer, appCopy, boLead, DELETE_CONTROL, DELETE_ID, DELETE_RULE, proposal } from './helpers/hunt.ts';

const { repo, map } = appCopy();
const ruleLead = (over: Record<string, string> = {}) => parseOutput({ leads: [boLead({ evidence_proposal: proposal('semgrep_rule', { rule_yaml: DELETE_RULE, control_code: DELETE_CONTROL, control_extension: 'js', ...over }) })] }, DELETE_ID).leads[0];

// A stub that answers like Semgrep: the sink file matches at the given lines, the control matches when asked.
const stub = (o: { sinkLines?: number[]; controlMatches?: boolean; missing?: boolean; scanned?: boolean; errors?: boolean }): SemgrepRunner => (args) => {
  if (o.missing) return { status: null, stdout: '', missing: true };
  if (args[0] === '--version') return { status: 0, stdout: '1.176.0\n' };
  const target = args[args.length - 1];
  const isControl = /control\.js$/.test(target);
  const lines = isControl ? (o.controlMatches ? [1] : []) : (o.sinkLines ?? []);
  return { status: 0, stdout: JSON.stringify({ results: lines.map((l) => ({ start: { line: l }, end: { line: l } })), errors: o.errors ? [{ type: 'x' }] : [], paths: { scanned: o.scanned === false ? [] : [target] } }) };
};

test('rule: matches the cited lines and not the control, so it is confirmed', () => {
  const r = confirmRule(ruleLead(), repo, stub({ sinkLines: [28] }));
  assert.equal(r.status, 'confirmed');
  if (r.status === 'confirmed') { assert.equal(r.rule_id, 'hunt.delete-note-by-request-id'); assert.equal(r.tool_version, '1.176.0'); assert.match(r.config_sha256, /^[0-9a-f]{64}$/); }
});

test('rule: not confirmed when it misses the cited lines, matches the control, or did not scan a file', () => {
  assert.equal(confirmRule(ruleLead(), repo, stub({ sinkLines: [5] })).status, 'not_confirmed');
  assert.equal(confirmRule(ruleLead(), repo, stub({ sinkLines: [28], controlMatches: true })).status, 'not_confirmed');
  assert.equal(confirmRule(ruleLead(), repo, stub({ sinkLines: [28], scanned: false })).status, 'not_confirmed');
  assert.equal(confirmRule(ruleLead(), repo, stub({ sinkLines: [28], errors: true })).status, 'not_confirmed');
});

test('rule: refused before running when it is not one rule, uses a banned feature, or the control is the flaw itself', () => {
  const never: SemgrepRunner = () => { throw new Error('semgrep must not run'); };
  assert.equal(confirmRule(ruleLead({ rule_yaml: 'rules: []' }), repo, never).status, 'not_confirmed');
  assert.equal(confirmRule(ruleLead({ rule_yaml: DELETE_RULE + '    pattern-where-python: "1"\n' }), repo, never).status, 'not_confirmed');
  assert.equal(confirmRule(ruleLead({ rule_yaml: DELETE_RULE + '  - id: second\n    languages: [javascript]\n    severity: INFO\n    message: m\n    pattern: x\n' }), repo, never).status, 'not_confirmed');
  assert.equal(confirmRule(ruleLead({ control_code: "db.run('DELETE FROM notes WHERE id = ?', [req.params.id]);" }), repo, never).status, 'not_confirmed');
});

test('rule: without Semgrep the outcome is not run and the lead stays a lead', () => {
  assert.equal(confirmRule(ruleLead(), repo, stub({ missing: true })).status, 'not_run');
  const out = confirmHunt({ repo, map, answers: [answer(1, DELETE_ID, [boLead({ evidence_proposal: proposal('semgrep_rule', { rule_yaml: DELETE_RULE, control_code: DELETE_CONTROL, control_extension: 'js' }) })])], plan: null, commit: null, semgrep: stub({ missing: true }) });
  assert.equal(out.confirmed.length, 0);
  assert.equal(out.leads[0].confirmation.status, 'not_run');
});

const hasSemgrep = spawnSync('semgrep', ['--version'], { encoding: 'utf8' }).status === 0;
test('rule: the real Semgrep confirms the planted flaw and does not confirm a safe sample', { skip: hasSemgrep ? false : 'semgrep is not installed: not run, logic covered by the stubbed tests above' }, () => {
  const good = confirmRule(ruleLead(), repo);
  assert.equal(good.status, 'confirmed', JSON.stringify(good));
  // A rule that is too general also matches the control, so the control rejects it.
  const wide = ruleLead({ rule_yaml: DELETE_RULE.replace('db.run("DELETE FROM notes WHERE id = ?", [req.params.id])', 'db.run(...)') });
  assert.equal(confirmRule(wide, repo).status, 'not_confirmed');
  // A rule that matches only safe code does not match the cited lines.
  const safeOnly = ruleLead({ rule_yaml: DELETE_RULE.replace('[req.params.id])', '[req.params.id, req.user.id])') });
  assert.equal(confirmRule(safeOnly, repo).status, 'not_confirmed');
  // A rule for another language never scans the files.
  assert.equal(confirmRule(ruleLead({ rule_yaml: DELETE_RULE.replace('javascript', 'python') }), repo).status, 'not_confirmed');
});
