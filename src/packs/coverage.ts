// The coverage table: one row per stack pack, from the levels the packs declare and the results recorded on their fixtures. Nothing
// here is typed by hand. The table is printed by `hullproof pack table`, shown in the README between two markers (a test keeps the two
// equal), and shown in the report for the stacks found in the repository. Plain words only: no dash punctuation.
import type { Stack } from '../types/index.ts';
import { cmp } from '../util.ts';
import { flawsFrom, LEVEL_NAMES, mappedFrom, rank, supportedLevel, topLevel, type FixtureResult, type Level, type Measurement, type PackManifest } from './manifest.ts';
import { defaultEnv, validateAll, type Checked, type Env } from './validate.ts';

export interface Row {
  id: string; name: string; level: Level; scopes: { where: string; level: Level }[]; supported: Level;
  onlySynthetic: boolean; limits: string[]; entry: string; flaws: string; falseFindings: string; stable: string; fixture: string; languages: string[]; frameworks: string[];
}

const KIND: Record<Measurement['kind'], string> = { synthetic: 'synthetic app', demo: 'demo app', third_party: 'third party app' };
const of = (a: number, b: number): string => `${a} of ${b}`;

const kindText = (m: Measurement): string => `${m.kind === 'demo' ? 'demo app, counted over all its stacks' : KIND[m.kind]}${m.blind_key ? ' with a blind answer key' : ''}`;

export function rowOf(m: PackManifest, r: FixtureResult): Row {
  const mp = mappedFrom(r);
  const fl = flawsFrom(r);
  const real = r.measurements.filter((x) => x.kind === 'third_party' && x.mapped);
  const realText = real.length ? `route sample on ${real.length} real ${real.length === 1 ? 'app' : 'apps'}` : '';
  const fixture = [fl ? `flaws on a ${kindText(fl)}` : '', mp && mp !== fl ? `map on a ${kindText(mp)}` : fl && !fl.blind_key ? 'no blind key' : '', realText].filter(Boolean).join(', ') || 'none';
  return {
    id: m.id, name: m.name, level: m.level, scopes: m.scopes ?? [], supported: supportedLevel(r, null),
    entry: mp?.mapped ? `${of(mp.mapped.matched, mp.mapped.expected)} ${mp.mapped.what}` : 'not measured',
    flaws: fl?.flaws ? of(fl.flaws.found, fl.flaws.planted) : 'not measured',
    falseFindings: fl?.flaws ? String(fl.flaws.false_findings) : 'not measured',
    stable: mp ? (mp.stability.identical ? `${mp.stability.runs} of ${mp.stability.runs} identical` : 'not identical') : 'not measured',
    fixture,
    onlySynthetic: r.measurements.every((x) => x.kind === 'synthetic'), limits: m.limits ?? [], languages: m.languages, frameworks: m.frameworks,
  };
}

export function coverageRows(checked: Checked[]): Row[] {
  return checked.filter((c): c is Checked & { manifest: PackManifest; result: FixtureResult } => !!c.manifest && !!c.result)
    .map((c) => rowOf(c.manifest, c.result))
    .sort((a, b) => rank(b.level) - rank(a.level) || cmp(a.name, b.name));
}

export const LEVEL_LEGEND: [Level, string][] = [
  ['L0', 'Secrets, dependencies, infrastructure and cloud configuration, and the generic rules. Runs on any stack.'],
  ['L1', 'The stack is recognised and its configuration files are checked.'],
  ['L2', 'Entry points and what protects them are written to the code map.'],
  ['L3', 'Executable checks and stack rules, measured on a fixture with a blind answer key.'],
  ['L4', 'A start recipe, so the proof sandbox can run the app and prove a flaw.'],
];

const scopeText = (r: Row): string => (r.scopes.length ? r.scopes.map((s) => `${s.level} for ${s.where}`).join('; ') : 'none');

// The Markdown table with the measured figures. Everything in it comes from the rows, so it cannot say more than the recorded results support.
export function coverageMarkdown(rows: Row[]): string {
  const head = '| Stack | Level | Higher level for | Mapped on the fixture | Planted flaws found | False findings | Fixture | Not covered |';
  const sep = '|---|---|---|---|---|---|---|---|';
  const body = rows.map((r) => `| ${r.name} | ${r.level} ${LEVEL_NAMES[r.level]} | ${scopeText(r)} | ${r.entry} | ${r.flaws} | ${r.falseFindings} | ${r.fixture} | ${r.limits.join(' ') || 'nothing recorded'} |`);
  return [head, sep, ...body].join('\n');
}

// The README table states levels and what each was measured on, with no figures: the README makes no detection claim.
export function levelsMarkdown(rows: Row[]): string {
  const head = '| Stack | Level | Higher level for | Measured on | Not covered |';
  const sep = '|---|---|---|---|---|';
  return [head, sep, ...rows.map((r) => `| ${r.name} | ${r.level} ${LEVEL_NAMES[r.level]} | ${scopeText(r)} | ${r.fixture} | ${r.limits.join(' ') || 'nothing recorded'} |`)].join('\n');
}

export const legendMarkdown = (): string => ['| Level | What it means |', '|---|---|', ...LEVEL_LEGEND.map(([l, t]) => `| ${l} ${LEVEL_NAMES[l]} | ${t} |`)].join('\n');

export const README_START = '<!-- pack-coverage:start -->';
export const README_END = '<!-- pack-coverage:end -->';

// The block that goes between the README markers.
export function readmeBlock(rows: Row[]): string {
  return `${README_START}\n${legendMarkdown()}\n\n${levelsMarkdown(rows)}\n${README_END}`;
}

export function currentRows(env: Env = defaultEnv()): Row[] { return coverageRows(validateAll(undefined, env)); }

// Packs that apply to a repository, judged from stack.json: a pack applies when any of its frameworks or languages was found.
export function rowsForStack(stack: Stack, rows: Row[] = currentRows()): Row[] {
  const ids = new Set<string>([...stack.languages, ...stack.frameworks, ...stack.mobile, ...stack.data_stores, ...stack.auth].map((i) => i.id));
  return rows.filter((r) => r.frameworks.some((f) => ids.has(f)) || r.languages.some((l) => ids.has(l)));
}

// The report section: levels for the stacks found here, and the plain statement that everything else is level 0.
export function reportSection(stack: Stack, rows: Row[] = currentRows()): string[] {
  const hit = rowsForStack(stack, rows);
  const out = ['## Stack coverage', '', 'Every stack gets the generic checks (level L0). The deeper levels below are what the engine has for the stacks found in this repository, as measured on its own fixtures. A level is a statement about depth, not about how many flaws exist in your app.', ''];
  if (!hit.length) { out.push('No stack in this repository has a pack beyond L0. Secrets, dependencies, infrastructure files and the generic rules were checked.', ''); return out; }
  out.push('| Stack | Level | Higher level for | Not covered |', '|---|---|---|---|', ...hit.map((r) => `| ${r.name} | ${r.level} ${LEVEL_NAMES[r.level]} | ${scopeText(r)} | ${r.limits.join(' ') || 'nothing recorded'} |`), '');
  const synthetic = hit.filter((r) => r.onlySynthetic);
  if (synthetic.length) out.push(`Measured on synthetic fixtures only: ${synthetic.map((r) => r.name).join(', ')}. No real application has been measured for them yet.`, '');
  const sampled = hit.filter((r) => !r.onlySynthetic && /route sample on/.test(r.fixture));
  if (sampled.length) out.push(`Also checked on real applications, by a sample of their route registrations only (planted flaws were not measured there): ${sampled.map((r) => r.name).join(', ')}.`, '');
  return out;
}

export { topLevel };
