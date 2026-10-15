// A map query must not confirm a claim when the route chain holds a protection like helper the map does not know.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeContext } from '../src/checks/context.ts';
import { getMap } from '../src/checks/map/shared.ts';
import { chainCalls } from '../src/confirm/chain.ts';
import { confirmHunt } from '../src/confirm/confirm.ts';
import { discover } from '../src/discover/discover.ts';
import { answer, boLead, DELETE_ID } from './helpers/hunt.ts';

const APP = fileURLToPath(new URL('./fixtures/map/fail/express/', import.meta.url));
function withLine27(registration: string) {
  const repo = mkdtempSync(join(tmpdir(), 'hp-chain-'));
  cpSync(APP, repo, { recursive: true });
  const lines = readFileSync(join(repo, 'server.js'), 'utf8').split('\n');
  assert.ok(lines[26].startsWith("app.delete('/api/notes/:id'"));
  lines[26] = registration;
  writeFileSync(join(repo, 'server.js'), lines.join('\n'));
  return { repo, map: getMap(makeContext(repo, discover(repo))) };
}
const run = (x: { repo: string; map: ReturnType<typeof getMap> }) => {
  const r = confirmHunt({ repo: x.repo, map: x.map, answers: [answer(1, DELETE_ID, [boLead()])], plan: null, commit: 'c'.repeat(40) });
  return [...r.confirmed, ...r.leads][0];
};

test('an unknown helper on the chain (security.appendUserId) keeps the lead a lead and names the helper', () => {
  const l = run(withLine27("app.delete('/api/notes/:id', security.appendUserId(), (req, res) => {"));
  assert.equal(l.confirmation.status, 'not_confirmed');
  if (l.confirmation.status === 'not_confirmed') {
    assert.equal(l.confirmation.reason, 'unknown_protection');
    assert.deepEqual(l.confirmation.helpers, ['security.appendUserId']);
    assert.match(l.confirmation.detail, /^unknown_protection:/);
  }
});

test('a recognised protection on the chain still confirms', () => {
  assert.equal(run(withLine27("app.delete('/api/notes/:id', requireUser, (req, res) => {")).confirmation.status, 'confirmed');
});

test('a chain with no protection like helper still confirms; a wrapper is not a protection', () => {
  assert.equal(run(withLine27("app.delete('/api/notes/:id', (req, res) => {")).confirmation.status, 'confirmed');
});

test('chainCalls reads Express chains, wrappers and decorators', () => {
  assert.deepEqual(chainCalls("  app.post('/a', security.appendUserId(), utils.asyncHandler(verifyImageCaptcha()))\n", 1), ['security.appendUserId']);
  assert.deepEqual(chainCalls("app.get('/a', trackOrder())\n", 1), []);
  assert.deepEqual(chainCalls("app.get('/a', utils.asyncHandler(h()))\n", 1), []);
  assert.deepEqual(chainCalls('export const POST = withErrors(async (req) => {\n', 1), ['withErrors']);
  assert.deepEqual(chainCalls("@app.route('/x', methods=['GET'])\n@login_required\ndef f():\n  pass\n", 1), ['login_required']);
});
