// The .env.local loader: real environment variables win, only the provider names are read, and no value is ever returned in a message.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadHuntEnv, parseEnvText } from '../src/env.ts';

test('parse: comments, export, quotes and unknown names', () => {
  const t = parseEnvText('# note\nHULLPROOF_PROVIDER=openai\nexport HULLPROOF_MODEL="gpt-x"\nOPENAI_API_KEY=\'abc-12345678\'  # trailing\nEMPTY=\nPATH=/evil\nGEMINI_API_KEY=\n');
  assert.deepEqual(t, { HULLPROOF_PROVIDER: 'openai', HULLPROOF_MODEL: 'gpt-x', OPENAI_API_KEY: ['abc', '12345678'].join('-') });
});

test('load: the repository file fills only names that are not set, and a real variable always wins', () => {
  const repo = mkdtempSync(join(tmpdir(), 'hp-env-'));
  writeFileSync(join(repo, '.env.local'), 'HULLPROOF_MODEL=from-file\nOPENAI_API_KEY=file-key-0000\nGEMINI_API_KEY=gem-file-key-0000\n');
  const none = mkdtempSync(join(tmpdir(), 'hp-env-engine-'));
  const r = loadHuntEnv(repo, { OPENAI_API_KEY: 'real-key-1111', PATH: '/bin' }, none);
  assert.equal(r.env.OPENAI_API_KEY, 'real-key-1111');
  assert.equal(r.env.GEMINI_API_KEY, 'gem-file-key-0000');
  assert.equal(r.env.HULLPROOF_MODEL, 'from-file');
  assert.deepEqual(r.fromFile, ['GEMINI_API_KEY', 'HULLPROOF_MODEL']);
  assert.ok(!JSON.stringify(r.fromFile).includes('key-0000'), 'names only');
  assert.equal(r.env.PATH, '/bin');
  // An empty real variable does not block the file.
  assert.equal(loadHuntEnv(repo, { OPENAI_API_KEY: '' }, none).env.OPENAI_API_KEY, 'file-key-0000');
});

test('load: no file is no change', () => {
  const r = loadHuntEnv(mkdtempSync(join(tmpdir(), 'hp-env-')), { HULLPROOF_MODEL: 'x' }, mkdtempSync(join(tmpdir(), 'hp-env-')));
  assert.equal(r.env.HULLPROOF_MODEL, 'x');
});

test('load: the engine folder file is the second place, and the repository file wins over it', () => {
  const repo = mkdtempSync(join(tmpdir(), 'hp-env-'));
  const engine = mkdtempSync(join(tmpdir(), 'hp-env-engine-'));
  writeFileSync(join(repo, '.env.local'), 'HULLPROOF_MODEL=repo-model\n');
  writeFileSync(join(engine, '.env.local'), 'HULLPROOF_MODEL=engine-model\nHULLPROOF_PROVIDER=local\n');
  const r = loadHuntEnv(repo, {}, engine);
  assert.deepEqual([r.env.HULLPROOF_MODEL, r.env.HULLPROOF_PROVIDER], ['repo-model', 'local']);
});
