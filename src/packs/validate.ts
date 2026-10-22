// hullproof pack validate: reads packs/<id>/pack.json and fixture-result.json and rejects a pack that is missing a part, lists a rule
// without a test, has no fixture result, uses a bad level, or claims a level its recorded fixture result does not support.
// Reads files only. Runs no scanner, no model and no network.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadChecks } from '../checks/run.ts';
import { PRO_MAP_CHECKS } from '../checks/pro-map.ts';
import { DETECTORS_DIR } from '../discover/detectors.ts';
import { cmp } from '../util.ts';
import { claims, isLevel, LEVELS, rank, supportedLevel, topLevel, type FileRef, type FixtureResult, type Level, type PackManifest } from './manifest.ts';

export const ENGINE_ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const PACKS_DIR = join(ENGINE_ROOT, 'packs');

export interface Issue { pack: string; code: string; message: string }
export interface Checked { dir: string; manifest: PackManifest | null; result: FixtureResult | null; issues: Issue[]; skipped: string[] }

// What a part must have at each level. L0 needs nothing but the manifest and a fixture result; every pack needs the fixture result.
const NEEDS: Record<string, Level> = { detectors: 'L1', extractors: 'L2', auth_patterns: 'L2', checks: 'L3', mapping: 'L3', start_recipe: 'L4' };

export interface Env {
  root: string;
  detectorIds: Set<string>;
  checkIds: Set<string>;
  recipes: Set<string>;
  hasPro: boolean;              // this is the Pro edition: the Pro only checks are loaded
}

export function defaultEnv(root: string = ENGINE_ROOT): Env {
  const detectorIds = new Set<string>();
  for (const n of readdirSync(DETECTORS_DIR).filter((f) => f.endsWith('.json'))) {
    for (const e of (JSON.parse(readFileSync(join(DETECTORS_DIR, n), 'utf8')) as { entries: { id: string }[] }).entries) detectorIds.add(e.id);
  }
  return { root, detectorIds, checkIds: new Set(loadChecks().map((c) => c.id)), recipes: RECIPES, hasPro: PRO_MAP_CHECKS.length > 0 };
}

// Start recipes the proof sandbox builds (src/prove/recipe.ts). A pack at L4 names one of these.
export const RECIPES = new Set(['node-express', 'python-flask']);

const SEC_ID = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

export function readJson<T>(file: string): T | string {
  try { return JSON.parse(readFileSync(file, 'utf8')) as T; } catch (e) { return (e as Error).message; }
}

// The Semgrep rule ids in a rule file, read without YAML parsing: lines of the form "  - id: name".
export const ruleIds = (text: string): string[] => [...text.matchAll(/^\s*-\s+id:\s*([A-Za-z0-9._-]+)\s*$/gm)].map((m) => m[1]);

export function validatePack(folder: string, env: Env): Checked {
  const id = folder.split('/').filter(Boolean).pop() ?? folder;
  const issues: Issue[] = [];
  const skipped: string[] = [];
  const bad = (code: string, message: string): void => { issues.push({ pack: id, code, message }); };
  const out = (manifest: PackManifest | null, result: FixtureResult | null): Checked => ({ dir: folder, manifest, result, issues: issues.sort((a, b) => cmp(a.code, b.code) || cmp(a.message, b.message)), skipped });

  const mf = join(folder, 'pack.json');
  if (!existsSync(mf)) { bad('manifest_missing', 'there is no pack.json'); return out(null, null); }
  const raw = readJson<PackManifest>(mf);
  if (typeof raw === 'string') { bad('manifest_unreadable', `pack.json is not valid JSON: ${raw}`); return out(null, null); }
  const m = raw;

  // ---- identity and levels
  if (m.schema !== 1) bad('schema', 'schema must be 1');
  if (typeof m.id !== 'string' || !SEC_ID.test(m.id)) bad('id', 'id must be lower case words joined with hyphens');
  else if (m.id !== id) bad('id', `id "${m.id}" does not match the folder name "${id}"`);
  for (const k of ['name', 'summary'] as const) if (typeof m[k] !== 'string' || !m[k].trim()) bad('field', `${k} is missing`);
  if (m.edition !== 'free' && m.edition !== 'pro') bad('field', 'edition must be free or pro');
  for (const k of ['languages', 'frameworks'] as const) if (!Array.isArray(m[k]) || m[k].length === 0 || m[k].some((x) => typeof x !== 'string')) bad('field', `${k} must list at least one stack id`);
  if (!isLevel(m.level)) bad('level', `level "${String(m.level)}" is not one of ${LEVELS.join(', ')}`);
  for (const s of m.scopes ?? []) {
    if (typeof s.where !== 'string' || !s.where.trim()) bad('level', 'a scope has no "where"');
    else if (!isLevel(s.level)) bad('level', `scope "${s.where}" has level "${String(s.level)}", which is not one of ${LEVELS.join(', ')}`);
    else if (isLevel(m.level) && rank(s.level) <= rank(m.level)) bad('level', `scope "${s.where}" is L${rank(s.level)}, which is not higher than the pack level; a scope exists only to reach a higher level`);
  }
  if (m.limits !== undefined && (!Array.isArray(m.limits) || m.limits.some((x) => typeof x !== 'string' || !x.trim()))) bad('field', 'limits must be a list of sentences');
  const levelsOk = isLevel(m.level) && (m.scopes ?? []).every((s) => isLevel(s.level));
  const parts = m.parts ?? {};
  if (!m.parts || typeof m.parts !== 'object') bad('parts_missing', 'parts is missing');

  // ---- every part the declared level needs must be there
  if (levelsOk) {
    const top = topLevel(m);
    for (const [part, at] of Object.entries(NEEDS)) {
      const have = (parts as Record<string, unknown>)[part];
      const present = Array.isArray(have) ? have.length > 0 : have !== undefined && have !== null;
      if (rank(top) >= rank(at) && !present) bad('part_missing', `the pack declares ${top}, which needs "${part}" (from ${at}), and the manifest has none`);
    }
  }

  // ---- files named by a part must exist (a Pro part is skipped when the Pro folders are not in this tree)
  const here = (rel: string): boolean => existsSync(join(env.root, rel));
  const fileRef = (part: string, r: FileRef): void => {
    if (!r || typeof r.file !== 'string') { bad('file', `${part}: an entry has no file`); return; }
    if (here(r.file)) return;
    if (r.pro && !env.hasPro) { skipped.push(`${part}: ${r.file} (Pro, not in this edition)`); return; }
    bad('file_missing', `${part}: ${r.file} does not exist`);
  };
  for (const part of ['extractors', 'auth_patterns', 'sources_sinks', 'mapping'] as const) for (const r of parts[part] ?? []) fileRef(part, r);

  for (const d of parts.detectors ?? []) if (!env.detectorIds.has(d)) bad('detector_unknown', `detectors: "${d}" is not an id in detectors/*.json`);
  for (const f of m.frameworks ?? []) if (!env.detectorIds.has(f)) bad('detector_unknown', `frameworks: "${f}" is not an id in detectors/*.json`);

  // ---- rules need tests: every rule id in the file has a "ruleid" line and an "ok" line in the test files
  for (const r of parts.rules ?? []) {
    if (!r || typeof r.file !== 'string') { bad('file', 'rules: an entry has no file'); continue; }
    if (!here(r.file)) { if (r.pro && !env.hasPro) skipped.push(`rules: ${r.file} (Pro, not in this edition)`); else bad('file_missing', `rules: ${r.file} does not exist`); continue; }
    if (!Array.isArray(r.tests) || r.tests.length === 0) { bad('rule_without_test', `rules: ${r.file} has no test files`); continue; }
    // An npm install carries the rules but not the test folder, so the rule tests cannot be read there.
    if (!existsSync(join(env.root, 'test/fixtures'))) { skipped.push(`rules: tests for ${r.file} (no fixture folder in this tree)`); continue; }
    const missing = r.tests.filter((t) => !here(t));
    for (const t of missing) bad('file_missing', `rules: test file ${t} for ${r.file} does not exist`);
    if (missing.length) continue;
    const testText = r.tests.map((t) => readFileSync(join(env.root, t), 'utf8')).join('\n');
    for (const rid of ruleIds(readFileSync(join(env.root, r.file), 'utf8'))) {
      if (!new RegExp(`ruleid: ${rid}\\b`).test(testText)) bad('rule_without_test', `rules: ${rid} in ${r.file} has no "ruleid: ${rid}" line in its test files`);
      if (!new RegExp(`ok: ${rid}\\b`).test(testText)) bad('rule_without_test', `rules: ${rid} in ${r.file} has no "ok: ${rid}" line in its test files`);
    }
  }

  // ---- checks must exist in this engine (a Pro check is skipped when the Pro folders are absent)
  for (const c of parts.checks ?? []) {
    if (!c || typeof c.id !== 'string') { bad('check_unknown', 'checks: an entry has no id'); continue; }
    if (env.checkIds.has(c.id)) continue;
    if (c.pro && !env.hasPro) skipped.push(`checks: ${c.id} (Pro, not in this edition)`); else bad('check_unknown', `checks: ${c.id} is not a check this engine loads`);
  }

  // ---- start recipe
  const rc = parts.start_recipe;
  if (rc) {
    if (!env.recipes.has(rc.recipe)) bad('recipe_unknown', `start_recipe: "${rc.recipe}" is not a recipe the proof sandbox builds (${[...env.recipes].sort(cmp).join(', ')})`);
    fileRef('start_recipe', rc);
  }

  // ---- fixture and its recorded result
  const fx = m.fixture;
  let result: FixtureResult | null = null;
  if (!fx || typeof fx !== 'object') bad('fixture_missing', 'fixture is missing');
  else {
    for (const k of ['dir', 'fixed_dir', 'result'] as const) if (typeof fx[k] !== 'string' || !fx[k]) bad('fixture_missing', `fixture.${k} is missing`);
    if (!Array.isArray(fx.answer_keys) || fx.answer_keys.length === 0 || fx.answer_keys.some((k) => !['in_repo', 'outside_repo', 'independent'].includes(k))) bad('fixture_missing', 'fixture.answer_keys must list in_repo, outside_repo or independent');
    // Fixtures marked internal are in neither edition. Their folders are checked only in a tree that has the internal fixture area.
    const internalArea = here('test/fixtures/packs');
    for (const k of ['dir', 'fixed_dir'] as const) if (typeof fx[k] === 'string' && fx[k] && !here(fx[k])) {
      if (fx.internal && !internalArea) skipped.push(`fixture.${k}: ${fx[k]} (internal fixture, not in this edition)`);
      else if (fx.internal !== true && !existsSync(join(env.root, 'test/fixtures'))) skipped.push(`fixture.${k}: ${fx[k]} (no fixture folder in this tree)`);
      else bad('fixture_missing', `fixture.${k}: ${fx[k]} does not exist`);
    }
    const rf = typeof fx.result === 'string' ? join(env.root, fx.result) : '';
    if (!rf || !existsSync(rf)) bad('fixture_result_missing', `there is no fixture result (${fx.result ?? 'no path'}); a pack with no recorded result on its fixture is not listed`);
    else {
      const r = readJson<FixtureResult>(rf);
      if (typeof r === 'string') bad('fixture_result_invalid', `${fx.result} is not valid JSON: ${r}`);
      else {
        const why = checkResult(r, m.id);
        if (why.length) for (const w of why) bad('fixture_result_invalid', `${fx.result}: ${w}`);
        else result = r;
      }
    }
  }

  // ---- the declared levels against what the result supports
  if (levelsOk && result) {
    for (const [scope, lv] of claims(m)) {
      const sup = supportedLevel(result, scope);
      if (rank(lv) > rank(sup)) bad('level_too_high', `${scope ? `scope "${scope}"` : 'the pack'} declares ${lv}, and the recorded fixture result supports ${sup}`);
    }
  }
  return out(m, result);
}

function checkResult(r: FixtureResult, id: string): string[] {
  const w: string[] = [];
  if (r.schema !== 1) w.push('schema must be 1');
  if (r.pack !== id) w.push(`pack is "${String(r.pack)}", not "${id}"`);
  if (typeof r.measured !== 'string' || !DATE.test(r.measured)) w.push('measured must be a date, YYYY-MM-DD');
  if (!r.detect || !Array.isArray(r.detect.expected) || !Array.isArray(r.detect.found)) w.push('detect.expected and detect.found are required');
  if (!Array.isArray(r.measurements) || r.measurements.length === 0) w.push('measurements is empty; a pack with no measurement on a fixture is not listed');
  const nums = (o: object | null, keys: string[], name: string): void => { if (o && keys.some((k) => !Number.isInteger((o as Record<string, unknown>)[k]) || (o as Record<string, number>)[k] < 0)) w.push(`${name} needs whole numbers for ${keys.join(', ')}`); };
  for (const m of Array.isArray(r.measurements) ? r.measurements : []) {
    const n = `measurement "${String(m?.name)}"`;
    if (!m || typeof m.name !== 'string' || !['synthetic', 'demo', 'third_party'].includes(m.kind) || typeof m.blind_key !== 'boolean') { w.push(`${n} needs name, kind and blind_key`); continue; }
    if (typeof m.source !== 'string' || !m.source.trim()) w.push(`${n}: source says nothing about how the numbers were made`);
    nums(m.mapped, ['expected', 'matched', 'extra'], `${n} mapped`);
    if (m.mapped && (typeof m.mapped.what !== 'string' || !m.mapped.what)) w.push(`${n}: mapped.what is missing`);
    nums(m.flaws, ['planted', 'found', 'false_findings'], `${n} flaws`);
    if (!m.stability || !Number.isInteger(m.stability.runs) || typeof m.stability.identical !== 'boolean') w.push(`${n}: stability.runs and stability.identical are required`);
    if (m.mapped && m.mapped.matched > m.mapped.expected) w.push(`${n}: matched is more than expected`);
    if (m.flaws && m.flaws.found > m.flaws.planted) w.push(`${n}: flaws.found is more than planted`);
  }
  if (!Array.isArray(r.proof)) w.push('proof must be a list (empty when no proof was run)');
  else for (const p of r.proof) nums(p, ['planted', 'proven', 'runs', 'false_proofs_fixed'], 'proof');
  return w;
}

export function listPacks(dir: string = PACKS_DIR): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => join(dir, d.name)).sort(cmp);
}

export function validateAll(dir: string = PACKS_DIR, env: Env = defaultEnv()): Checked[] {
  return listPacks(dir).map((p) => validatePack(p, env));
}
