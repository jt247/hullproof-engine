// check.api.webhook-verified-before-use: a webhook handler checks the sender's signature, and a failed check stops the
// request before the event is used. Works on any stack whose handlers are found by handlerFiles() (JS, TS, Python, Go,
// PHP, Ruby). It reads code, so it can FAIL SEC-API-101 for the part a file settles and never PASS it.
import { fileURLToPath } from 'node:url';
import type { CheckEvidence } from '../../types/index.ts';
import { byFileLine, lineOf, type CheckContext } from '../context.ts';
import type { OpOutcome } from '../ops.ts';
import type { CodeCheck } from '../types.ts';
import { EXITS, handlerFiles, ifBody } from './shared.ts';

// A file is a webhook handler when its path says webhook or it reads a provider signature header.
const WEBHOOK_PATH = /webhook/i;
const SIGNATURE_HEADER = /\b[xX]-[a-zA-Z-]*[sS]ignature\b|stripe-signature|paystack-signature|svix-signature|webhook-signature|HTTP_X_[A-Z_]*SIGNATURE/;
// Calls that check a signature and return a result the caller must act on.
const VERIFY_CALL = /\b((?:\w+\.)?(?:verify\w*|validate\w*[sS]ignature\w*|check\w*[sS]ignature\w*|is\w*[vV]alid\w*[sS]ignature\w*|compare_digest|hash_equals|secure_compare|timingSafeEqual|hmac\.Equal|ValidatePayload))\s*\(/g;
// Calls documented by their providers to throw (or raise) on a bad signature, so code after them runs only when valid.
const THROWING = /constructEvent|construct_event|webhooks\.verify|wh\.verify|Webhook\.construct|unwrap\(|constructEventAsync|validateRequest/;

function scanFile(file: string, text: string): CheckEvidence[] {
  const bad: CheckEvidence[] = [];
  let calls = 0;
  VERIFY_CALL.lastIndex = 0;
  for (let m = VERIFY_CALL.exec(text); m; m = VERIFY_CALL.exec(text)) {
    if (/function\s+$|def\s+$|func\s+(\([^)]*\)\s*)?$/.test(text.slice(Math.max(0, m.index - 30), m.index))) continue; // a definition, not a call
    calls++;
    const lineStart = text.lastIndexOf('\n', m.index) + 1;
    const lineText = text.slice(lineStart, text.indexOf('\n', m.index) < 0 ? text.length : text.indexOf('\n', m.index));
    if (THROWING.test(m[1]) || THROWING.test(lineText)) continue;
    // The call sits in an if condition: `if (!verify(...)) return ...` or `if not verify(...): raise ...`.
    const ifAt = /\bif\b/.exec(lineText);
    if (ifAt && lineStart + ifAt.index < m.index) {
      const body = ifBody(text, lineStart + ifAt.index);
      if (!EXITS.test(body.slice(body.indexOf(m[0]) + m[0].length))) bad.push({ file, line: lineOf(text, m.index), note: 'a failed signature check does not stop the request' });
      continue;
    }
    // The result is stored: `const ok = verify(...)`, `ok := verify(...)`, `ok = verify(...)`.
    const assigned = /(?:const|let|var|val)?\s*([A-Za-z_$][\w$]*)\s*(?::=|=)\s*(?:await\s+)?[\w.$]*$/.exec(text.slice(lineStart, m.index));
    if (!assigned) continue; // a bare call: its result is not used as a gate, and most such helpers throw
    const name = assigned[1];
    const after = text.slice(m.index);
    const guard = new RegExp(`\\bif\\s*\\(?\\s*(?:!\\s*${name}\\b|not\\s+${name}\\b|${name}\\s*(?:===?|is)\\s*(?:false|False|nil|None)|${name}\\s*!==?\\s*true)`, 'g');
    const guards = [...after.matchAll(guard)];
    if (guards.length === 0) { bad.push({ file, line: lineOf(text, m.index), note: `the result ${name} of the signature check is never used to stop the request` }); continue; }
    const stops = guards.some((g) => EXITS.test(ifBody(text, m!.index + g.index!)));
    if (!stops) bad.push({ file, line: lineOf(text, m.index + guards[0].index!), note: `when ${name} is false the handler carries on and uses the event` });
  }
  if (calls === 0 && !THROWING.test(text)) {
    const handler = /export\s+(?:async\s+)?(?:function|const)\s+(?:POST|PUT|handler|default)\b|@(?:app|router)\.post|\bdef\s+\w*webhook\w*|func\s+\w*[Ww]ebhook\w*/.exec(text);
    bad.push({ file, line: handler ? lineOf(text, handler.index) : 1, note: 'no call that checks the sender signature was found in this webhook handler' });
  }
  return bad;
}

export function run(ctx: CheckContext): OpOutcome {
  const files = handlerFiles(ctx).filter((f) => WEBHOOK_PATH.test(f) || SIGNATURE_HEADER.test(ctx.text(f)));
  if (files.length === 0) return { value: 'not_applicable', reason: 'no webhook handler found', evidence: [], absence: null };
  const bad = files.flatMap((f) => scanFile(f, ctx.text(f))).sort(byFileLine);
  return {
    value: bad.length === 0,
    evidence: bad.length ? bad : files.map((file) => ({ file, line: 1, note: 'signature check found and a failure stops the request' })),
    absence: { pattern: `${VERIFY_CALL.source} followed by a guard that returns or throws`, files_searched: files.length, file_globs: ['handler files whose path says webhook or that read a signature header'], matches: files.length - new Set(bad.map((b) => b.file)).size },
  };
}

export const check: CodeCheck = {
  id: 'check.api.webhook-verified-before-use',
  sec_ids: ['SEC-API-101', 'SEC-API-126'],
  applies_when: {},
  op: 'code',
  on_true: 'NOT ASSESSED: NEEDS DYNAMIC TEST',
  on_false: 'FAIL',
  fixtures: { pass: 'test/fixtures/checks/webhook-verified-before-use/pass', fail: 'test/fixtures/checks/webhook-verified-before-use/fail' },
  source: fileURLToPath(import.meta.url),
  run,
};
