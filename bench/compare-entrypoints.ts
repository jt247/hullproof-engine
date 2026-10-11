// Compares a hand made list of entry points with a codemap.json. Node 22.18 or later runs this file directly. No dependencies.
//
//   node bench/compare-entrypoints.ts --hand bench/PHASE2-ENTRYPOINTS.md --section "2. The demo" codemap.json
//
// The hand list is every table row of the chosen section that holds a `file:line` in backticks. An entry point of the map
// matches a hand row when it has the same file and the same line, or when its handler (the function body, when it is
// registered by reference) is at that file and line. Prints the found, missing and extra entry points, and a count.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export interface Hand { file: string; line: number; text: string }
export interface MapEntry { file: string; line: number; kind: string; method: string | null; path: string | null; name: string | null; handler: { file: string; line: number } | null; test_code?: boolean }

export function parseHand(md: string, section: string): Hand[] {
  const out: Hand[] = [];
  let inside = false;
  for (const line of md.split(/\r?\n/)) {
    if (/^## /.test(line)) inside = line.includes(section);
    if (!inside) continue;
    const m = /`([^`:]+):(\d+)`/.exec(line);
    if (m && line.startsWith('|')) out.push({ file: m[1], line: Number(m[2]), text: line.split('|').slice(1, 3).map((c) => c.trim()).join(' ') });
  }
  return out;
}

export function compare(hand: Hand[], entries: MapEntry[]): { found: Hand[]; missing: Hand[]; extra: MapEntry[] } {
  const used = new Set<MapEntry>();
  const found: Hand[] = [];
  const missing: Hand[] = [];
  for (const h of hand) {
    const e = entries.find((x) => !used.has(x) && ((x.file === h.file && x.line === h.line) || (x.handler?.file === h.file && x.handler.line === h.line)));
    if (e) { used.add(e); found.push(h); } else missing.push(h);
  }
  return { found, missing, extra: entries.filter((e) => !used.has(e)) };
}

function main(argv: string[]): number {
  const get = (f: string): string | undefined => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : undefined; };
  const handFile = get('--hand');
  const section = get('--section');
  const mapFile = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--hand' && argv[i - 1] !== '--section').pop();
  if (!handFile || !section || !mapFile) { process.stderr.write('usage: compare-entrypoints.ts --hand FILE --section TEXT codemap.json\n'); return 2; }
  const hand = parseHand(readFileSync(handFile, 'utf8'), section);
  const map = JSON.parse(readFileSync(mapFile, 'utf8')) as { entry_points: MapEntry[] };
  const r = compare(hand, map.entry_points);
  process.stdout.write(`hand ${hand.length}, found ${r.found.length}, missing ${r.missing.length}, extra in the map ${r.extra.length}\n`);
  for (const h of r.missing) process.stdout.write(`missing ${h.file}:${h.line} ${h.text}\n`);
  for (const e of r.extra) process.stdout.write(`extra ${e.file}:${e.line} ${e.kind} ${e.method ?? ''} ${e.path ?? e.name ?? ''}\n`);
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exitCode = main(process.argv.slice(2));
