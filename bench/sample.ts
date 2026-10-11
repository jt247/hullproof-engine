// Seeded random sample of lines, so a hand check can be repeated. Node 22.18 or later runs this file directly. No dependencies.
//
//   node bench/sample.ts --seed 20261011 --n 25 [--skip K] LINES.txt
//
// LINES.txt holds one candidate per line. The candidates are sorted in code unit order, shuffled with Fisher-Yates driven by
// mulberry32 seeded with --seed, and the first N after --skip are printed, one per line, in the order drawn.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// mulberry32: a small 32 bit generator. Same seed, same sequence, on every machine.
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function sample(items: string[], seed: number, n: number, skip = 0): string[] {
  const xs = items.slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const rnd = mulberry32(seed);
  for (let i = xs.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [xs[i], xs[j]] = [xs[j], xs[i]]; }
  return xs.slice(skip, skip + n);
}

function main(argv: string[]): number {
  const get = (f: string, d: string): string => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
  const file = argv.filter((a, i) => !a.startsWith('--') && !['--seed', '--n', '--skip'].includes(argv[i - 1])).pop();
  if (!file) { process.stderr.write('usage: sample.ts --seed N --n N [--skip K] LINES.txt\n'); return 2; }
  const items = readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
  process.stdout.write(sample(items, Number(get('--seed', '20261011')), Number(get('--n', '25')), Number(get('--skip', '0'))).join('\n') + '\n');
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) process.exitCode = main(process.argv.slice(2));
