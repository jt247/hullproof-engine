// Hullproof Phase 0 benchmark scorer. Node 22.18 or later runs this file directly (type stripping). No dependencies, no model.
//
//   node bench/score.ts --key DEMO-ANSWER-KEY.md --classes bench/keys/demo-classes.json [--scope all|free] [--format md|json] [LABEL=]OUTPUT...
//
// OUTPUT is an audit output: a findings record file (a fenced hullproof-findings block, or a json block holding "records"),
// a Markdown report, or plain text. Two or more outputs of the same commit also get a stability block.
// The matching method is written in docs/SCORING.md. Same inputs, same bytes out.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export type Status = 'FOUND' | 'PARTIAL' | 'MISSED';
export interface Flaw { id: string; title: string; section: 'free' | 'pro'; files: string[]; lines: Record<string, number[]>; secIds: string[]; patterns: RegExp[] }
export interface NotPlanted { id: string; label: string; files: string[]; patterns: RegExp[] }
export interface Unit { kind: 'finding' | 'lead'; text: string; files: string[]; secIds: string[]; at: number }
export interface FlawResult { id: string; status: Status; line_hit: boolean; matched_at: number[] }
export interface Score {
  output: string; units: number; finding_units: number; lead_units: number; verdict: string;
  totals: Record<Status, number>; flaws: FlawResult[];
  precision: { true_positive_units: number; flagged_false_positive_units: number; unmatched_units: number; precision_flagged: number | null; not_planted_hit: string[] };
}

const SEC_RE = /SEC-[A-Z]+-\d{3}/g;
const EXT = 'tsx?|jsx?|mjs|cjs|sql|ya?ml|json|py|go|rb|php|java|kt|swift|cs|tf|toml|lock|md|html|env';
const PATH_RE = new RegExp(`(?<![A-Za-z0-9_\\-./\\[\\]@])((?:[A-Za-z0-9_\\-.@]+|\\[[A-Za-z0-9_.]+\\])(?:/(?:[A-Za-z0-9_\\-.@]+|\\[[A-Za-z0-9_.]+\\]))*\\.(?:${EXT}))(?::(\\d+))?(?![A-Za-z0-9_])`, 'g');
const ROUTED_RE = /NOT ASSESSED|NEEDS DYNAMIC TEST|NEEDS DASHBOARD|NEEDS BUILD|ASK OWNER|\bUNKNOWN\b/;
const SETTLED_RE = /PASS \(static\)|NOT APPLICABLE|\bREFUTED\b/;
// Sections whose items are not findings shown to the owner. Matched against every heading above a unit and the paragraph that leads it.
const SKIP_CONTEXT = /passed|coverage ledger|refuted|dropped|next actions|fix order|recommended|limits|tool output|provenance|strength|scorecard|evidence hash|raised by|merge record|disagreement|discovery|owner question|surface coverage|header|system profile|\bgates?\b|applicability|verifier outcome|to get the files/i;
const LEAD_CONTEXT = /\blead|routed|unverified/i;

const uniq = <T>(xs: T[]): T[] => [...new Set(xs)];
const sortU = (xs: string[]): string[] => uniq(xs).sort();

export function parseKey(md: string, classes: { flaws: Record<string, { patterns: string[] }> }): Flaw[] {
  const flaws: Flaw[] = [];
  let section: 'free' | 'pro' | null = null;
  for (const line of md.split(/\r?\n/)) {
    if (/^#{1,6}\s/.test(line)) section = /free edition/i.test(line) ? 'free' : /pro only/i.test(line) ? 'pro' : null;
    const m = /^\|\s*([A-Z]\d{2,3})\s*\|(.*)\|\s*$/.exec(line);
    if (!m || !section) continue;
    const cells = m[2].split('|').map((c) => c.trim());
    const where = cells[1] ?? '';
    const lines: Record<string, number[]> = {};
    for (const [, f, l] of where.matchAll(/`([^`:]+):(\d+)`/g)) (lines[f] ??= []).push(Number(l));
    const pats = classes.flaws[m[1]]?.patterns ?? [];
    flaws.push({ id: m[1], title: cells[0] ?? '', section, files: Object.keys(lines).sort(), lines, secIds: sortU(cells[2]?.match(SEC_RE) ?? []), patterns: pats.map((p) => new RegExp(p, 'i')) });
  }
  if (flaws.length === 0) throw new Error('no flaw rows found in the key (expected tables under a "Free edition" and a "Pro only" heading)');
  return flaws;
}

// A cited path token resolves to a known file when it equals that file or is a suffix of it on a path segment boundary,
// and it resolves to exactly one known file. "route.ts" alone is ambiguous and resolves to nothing.
export function resolvePath(token: string, known: string[]): string | null {
  const t = token.replace(/^\.\//, '');
  const hits = known.filter((k) => k === t || k.endsWith('/' + t));
  return hits.length === 1 ? hits[0] : null;
}

function extract(text: string, known: string[]): { files: string[]; secIds: string[] } {
  const files: string[] = [];
  for (const m of text.matchAll(PATH_RE)) { const r = resolvePath(m[1], known); if (r) files.push(r); }
  return { files: sortU(files), secIds: sortU(text.match(SEC_RE) ?? []) };
}

interface Rec { kind?: string; sec_ids?: string[]; [k: string]: unknown }
function recordUnits(records: Rec[], known: string[]): Unit[] {
  const units: Unit[] = [];
  records.forEach((r, i) => {
    if (r.kind === 'refuted') return;
    const refs: string[] = [];
    for (const key of ['evidence', 'trace', 'where', 'preventing_layer']) {
      const v = r[key];
      if (Array.isArray(v)) for (const e of v) if (e && typeof e === 'object' && typeof (e as { file?: unknown }).file === 'string') refs.push((e as { file: string }).file);
    }
    const text = JSON.stringify(r);
    const ex = extract(text, known);
    const files = sortU([...ex.files, ...refs.map((f) => resolvePath(f, known)).filter((f): f is string => f !== null)]);
    units.push({ kind: r.kind === 'fail' ? 'finding' : 'lead', text, files, secIds: sortU([...(r.sec_ids ?? []), ...ex.secIds]), at: i + 1 });
  });
  return units;
}

// Markdown or plain text to units. A heading that names a finding id (F-12) makes one unit of everything up to the next heading.
// Otherwise each list item, each table row and each paragraph is one unit. Fenced code is skipped.
export function markdownUnits(text: string, known: string[]): Unit[] {
  const lines = text.split(/\r?\n/);
  const units: Unit[] = [];
  const heads: string[] = [];
  let lead = '';
  let cur: { lines: string[]; at: number; ctx: string } | null = null;
  let block = false;
  let fence = false;
  const close = () => {
    if (!cur) return;
    const body = cur.lines.join('\n');
    const ctx = cur.ctx;
    const at = cur.at;
    cur = null;
    if (SKIP_CONTEXT.test(ctx) || SETTLED_RE.test(body)) return;
    const ex = extract(body, known);
    const kind = ROUTED_RE.test(body) || LEAD_CONTEXT.test(ctx) ? 'lead' : 'finding';
    units.push({ kind, text: body, files: ex.files, secIds: ex.secIds, at });
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*(```|~~~)/.test(line)) { fence = !fence; if (!block) close(); continue; }
    if (fence) continue;
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      close();
      heads.length = h[1].length - 1;
      heads[h[1].length - 1] = h[2];
      lead = '';
      block = /\bF-\d+\b/.test(h[2]);
      if (block) cur = { lines: [line], at: i + 1, ctx: heads.slice(0, -1).join(' / ') };
      continue;
    }
    if (block) { cur?.lines.push(line); continue; }
    const ctx = [...heads.filter(Boolean), lead].join(' / ');
    if (line.trim() === '') { close(); continue; }
    const isItem = /^(\s{0,3})([-*+]|\d+[.)])\s+/.test(line) && !/^\s{4,}/.test(line);
    const isRow = /^\s*\|/.test(line);
    if (isRow) {
      close();
      if (/^\s*\|[\s:|-]+\|\s*$/.test(line)) continue;
      cur = { lines: [line], at: i + 1, ctx };
      close();
      continue;
    }
    if (isItem) { close(); cur = { lines: [line], at: i + 1, ctx }; continue; }
    if (cur) { cur.lines.push(line); continue; }
    lead = line;
    cur = { lines: [line], at: i + 1, ctx: heads.filter(Boolean).join(' / ') };
  }
  close();
  return units;
}

export function parseOutput(text: string, known: string[]): Unit[] {
  for (const m of text.matchAll(/^```[ \t]*(hullproof-findings|json)[ \t]*\r?\n([\s\S]*?)^```[ \t]*$/gm)) {
    try {
      const j = JSON.parse(m[2]);
      if (j && Array.isArray(j.records)) return recordUnits(j.records, known);
    } catch { /* not a findings block, keep looking */ }
  }
  return markdownUnits(text, known);
}

const classMatch = (u: Unit, ids: string[], pats: RegExp[]) => u.secIds.some((s) => ids.includes(s)) || pats.some((p) => p.test(u.text));

function lineHit(u: Unit, f: Flaw): boolean {
  for (const m of u.text.matchAll(PATH_RE)) {
    const r = resolvePath(m[1], f.files);
    if (r && m[2] && f.lines[r].some((l) => Math.abs(l - Number(m[2])) <= 3)) return true;
  }
  return false;
}

export function verdictOf(text: string): string {
  const m = /\b(NOT READY|READY WITH CONDITIONS|READY)\b/.exec(text);
  return m ? m[1] : 'none';
}

export function score(name: string, text: string, flaws: Flaw[], notPlanted: NotPlanted[]): Score {
  const known = sortU([...flaws.flatMap((f) => f.files), ...notPlanted.flatMap((n) => n.files)]);
  const units = parseOutput(text, known);
  const results: FlawResult[] = flaws.map((f) => {
    const own = (u: Unit) => u.files.some((x) => f.files.includes(x));
    const cm = (u: Unit) => classMatch(u, f.secIds, f.patterns);
    const found = units.filter((u) => u.kind === 'finding' && own(u) && cm(u));
    const partial = units.filter((u) => cm(u) && ((u.kind === 'finding' && u.files.length === 0) || (u.kind === 'lead' && own(u))));
    const hit = found.length ? found : partial;
    return { id: f.id, status: found.length ? 'FOUND' : partial.length ? 'PARTIAL' : 'MISSED', line_hit: found.some((u) => lineHit(u, f)), matched_at: hit.map((u) => u.at) };
  });
  const findingUnits = units.filter((u) => u.kind === 'finding');
  let tp = 0, fp = 0, other = 0;
  const npHit = new Set<string>();
  for (const u of findingUnits) {
    const isTp = flaws.some((f) => classMatch(u, f.secIds, f.patterns) && (u.files.some((x) => f.files.includes(x)) || u.files.length === 0));
    const np = notPlanted.filter((n) => u.files.some((x) => n.files.includes(x)) && n.patterns.some((p) => p.test(u.text)));
    if (isTp) tp++;
    else if (np.length) { fp++; np.forEach((n) => npHit.add(n.id)); }
    else other++;
  }
  const totals = { FOUND: 0, PARTIAL: 0, MISSED: 0 } as Record<Status, number>;
  for (const r of results) totals[r.status]++;
  return {
    output: name, units: units.length, finding_units: findingUnits.length, lead_units: units.length - findingUnits.length,
    verdict: verdictOf(text), totals, flaws: results,
    precision: { true_positive_units: tp, flagged_false_positive_units: fp, unmatched_units: other, precision_flagged: tp + fp ? Math.round((tp / (tp + fp)) * 1000) / 1000 : null, not_planted_hit: [...npHit].sort() },
  };
}

export function stability(scores: Score[]): { runs: number; stable_flaws: number; total_flaws: number; share: number; verdicts: string[]; verdict_stable: boolean; unstable: string[] } {
  const ids = scores[0].flaws.map((f) => f.id);
  const unstable = ids.filter((id) => new Set(scores.map((s) => s.flaws.find((f) => f.id === id)!.status)).size > 1);
  const verdicts = scores.map((s) => s.verdict);
  return {
    runs: scores.length, stable_flaws: ids.length - unstable.length, total_flaws: ids.length,
    share: Math.round(((ids.length - unstable.length) / ids.length) * 1000) / 1000,
    verdicts, verdict_stable: new Set(verdicts).size === 1 && verdicts[0] !== 'none', unstable,
  };
}

export function loadClasses(text: string): { flaws: Record<string, { patterns: string[] }>; notPlanted: NotPlanted[] } {
  const j = JSON.parse(text);
  return { flaws: j.flaws ?? {}, notPlanted: (j.not_planted ?? []).map((n: { id: string; label: string; files: string[]; patterns: string[] }) => ({ id: n.id, label: n.label, files: n.files, patterns: n.patterns.map((p) => new RegExp(p, 'i')) })) };
}

function toMarkdown(scores: Score[], flaws: Flaw[], st: ReturnType<typeof stability> | null): string {
  const out: string[] = [];
  out.push(`| Flaw | ${scores.map((s) => s.output).join(' | ')} |`, `|---|${scores.map(() => '---').join('|')}|`);
  for (const f of flaws) out.push(`| ${f.id} | ${scores.map((s) => s.flaws.find((x) => x.id === f.id)!.status).join(' | ')} |`);
  out.push('', '| Output | Found | Partial | Missed | Verdict | Finding units | Lead units | Flagged false positive units | Precision (flagged) |', '|---|---|---|---|---|---|---|---|---|');
  for (const s of scores) out.push(`| ${s.output} | ${s.totals.FOUND} | ${s.totals.PARTIAL} | ${s.totals.MISSED} | ${s.verdict} | ${s.finding_units} | ${s.lead_units} | ${s.precision.flagged_false_positive_units}${s.precision.not_planted_hit.length ? ' (' + s.precision.not_planted_hit.join(', ') + ')' : ''} | ${s.precision.precision_flagged ?? 'n/a'} |`);
  if (st) out.push('', `Stability over ${st.runs} outputs: ${st.stable_flaws} of ${st.total_flaws} flaws have the same status in every output (share ${st.share}). Verdicts: ${st.verdicts.join(', ')}; verdict stable: ${st.verdict_stable ? 'yes' : 'no'}. Unstable: ${st.unstable.join(', ') || 'none'}.`);
  return out.join('\n') + '\n';
}

function main(argv: string[]): number {
  const arg = (n: string) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  const keyPath = arg('--key'), classPath = arg('--classes');
  const scope = arg('--scope') ?? 'all', format = arg('--format') ?? 'md';
  const flagged = new Set(['--key', '--classes', '--scope', '--format']);
  const outputs = argv.filter((a, i) => !flagged.has(a) && !flagged.has(argv[i - 1] ?? ''));
  if (!keyPath || !classPath || outputs.length === 0 || !['all', 'free'].includes(scope) || !['md', 'json'].includes(format)) {
    console.error('usage: node bench/score.ts --key KEY.md --classes CLASSES.json [--scope all|free] [--format md|json] OUTPUT...');
    return 2;
  }
  const classes = loadClasses(readFileSync(classPath, 'utf8'));
  const flaws = parseKey(readFileSync(keyPath, 'utf8'), classes).filter((f) => scope === 'all' || f.section === 'free');
  // An output may be given as LABEL=PATH so the tables carry a short name.
  const scores = outputs.map((o) => {
    const eq = o.indexOf('=');
    const [label, path] = eq > 0 && !o.slice(0, eq).includes('/') ? [o.slice(0, eq), o.slice(eq + 1)] : [o.split('/').slice(-2).join('/'), o];
    return score(label, readFileSync(path, 'utf8'), flaws, classes.notPlanted);
  });
  const st = scores.length > 1 ? stability(scores) : null;
  process.stdout.write(format === 'json' ? JSON.stringify({ scope, scores, stability: st }, null, 2) + '\n' : toMarkdown(scores, flaws, st));
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
