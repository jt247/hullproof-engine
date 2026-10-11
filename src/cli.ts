#!/usr/bin/env node
// hullproof: the engine command line. Node 22.18 or later runs this TypeScript file directly. No dependencies.
import { mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { discover } from './discover/discover.ts';
import { scan } from './commands/scan.ts';
import { gate, report } from './commands/report-gate.ts';
import type { ScannerId } from './types/index.ts';
import { stableJson } from './util.ts';
import { ENGINE_VERSION } from './version.ts';

// Exit codes. 0, 1 and 2 match the kit gate; 3 is reserved for a command that exists but is not built yet (none today).
export const EXIT = { ok: 0, open: 1, badInput: 2, notImplemented: 3 } as const;

const HELP = `hullproof ${ENGINE_VERSION}

Usage: hullproof <command> [repository] [options]

Commands:
  discover   Detect the stack of a repository and write stack.json
  scan       Run discovery, the scanners and the checks; write <out>/<commit>/
  report     Write report.md from a scan folder
  gate       Apply the release gate to a scan folder and exit with its code
  version    Print the engine version
  help       Print this help

Options for discover:
  --out DIR  Folder for stack.json (default: .hullproof inside the repository). Use --out - to print to standard output.

Options for scan, report and gate:
  --out DIR         Base folder (default: .hullproof inside the repository). Files go to DIR/<commit>/.
  --kit DIR         The kit folder holding docs/hullproof/security-controls.json (default: HULLPROOF_KIT, the
                    repository itself when the kit is installed there, then a folder called hullproof-free/kit next to the engine)
scan only:
  --edition free|pro  Which requirements are in scope (default pro)
  --stage LAUNCH|GROWTH|SCALE  Default: docs/security/STAGE.md, else LAUNCH
  --allow-network   Let OSV Scanner reach osv.dev (off by default)
  --tools a,b       Limit the scanners (semgrep, gitleaks, osv-scanner, trivy)
  --rule-pack DIR   Add the Semgrep rule files in DIR (for example a rule pack of your own) to the engine rules; a file with
                    the same name as an engine rule file replaces it (default: HULLPROOF_RULE_PACK, else none)
report and gate:
  --commit SHA      Read the scan folder of this commit (default: HEAD)
  --owner FILE      Owner evidence: audit_report, rollback, results rows, acceptances (see README)
  --date YYYY-MM-DD The day acceptances are judged on (default: today, UTC)

Exit codes: 0 done (gate: READY or READY WITH ACCEPTED RISK), 1 open items (gate: NOT READY),
2 bad input, a refused run or a records problem.
`;

const TOOLS: ScannerId[] = ['semgrep', 'osv-scanner', 'gitleaks', 'trivy', 'checkov'];

interface Parsed { repo: string; flags: Map<string, string | true> }
const VALUE_FLAGS = new Set(['--out', '--kit', '--edition', '--stage', '--tools', '--commit', '--owner', '--date', '--rule-pack']);
const BOOL_FLAGS = new Set(['--allow-network']);

function parse(cmd: string, rest: string[], allowed: string[]): Parsed | string {
  const flags = new Map<string, string | true>();
  let repo = '.';
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith('-')) { repo = a; continue; }
    if (!allowed.includes(a)) return `unknown option ${a}`;
    if (BOOL_FLAGS.has(a)) { flags.set(a, true); continue; }
    const v = rest[++i];
    if (v === undefined || (VALUE_FLAGS.has(a) && v.startsWith('--'))) return `${a} needs a value`;
    flags.set(a, v);
  }
  return { repo, flags };
}

function discoverCmd(rest: string[], out: (s: string) => void, err: (s: string) => void): number {
  const p = parse('discover', rest, ['--out']);
  if (typeof p === 'string') { err(`hullproof discover: ${p}${p.startsWith('--out') ? ', or - for standard output' : ''}.\n`); return EXIT.badInput; }
  const outDir = (p.flags.get('--out') as string | undefined) ?? null;
  let json: string;
  try { json = stableJson(discover(p.repo)); } catch (e) {
    err(`hullproof discover: ${(e as Error).message}\n`);
    return EXIT.badInput;
  }
  if (outDir === '-') { out(json); return EXIT.ok; }
  const dir = resolve(outDir ?? join(p.repo, '.hullproof'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'stack.json'), json);
  out(`hullproof discover: wrote ${join(dir, 'stack.json')}\n`);
  return EXIT.ok;
}

async function scanCmd(rest: string[], err: (s: string) => void): Promise<number> {
  const p = parse('scan', rest, ['--out', '--kit', '--edition', '--stage', '--allow-network', '--tools', '--rule-pack']);
  if (typeof p === 'string') { err(`hullproof scan: ${p}\n`); return EXIT.badInput; }
  const edition = (p.flags.get('--edition') as string | undefined) ?? 'pro';
  const stage = (p.flags.get('--stage') as string | undefined) ?? null;
  const tools = p.flags.has('--tools') ? String(p.flags.get('--tools')).split(',').map((t) => t.trim()) : null;
  if (edition !== 'free' && edition !== 'pro') { err('hullproof scan: --edition is free or pro\n'); return EXIT.badInput; }
  if (stage && !['LAUNCH', 'GROWTH', 'SCALE'].includes(stage)) { err('hullproof scan: --stage is LAUNCH, GROWTH or SCALE\n'); return EXIT.badInput; }
  if (tools && tools.some((t) => !TOOLS.includes(t as ScannerId))) { err(`hullproof scan: --tools takes ${TOOLS.join(', ')}\n`); return EXIT.badInput; }
  return scan({
    repo: p.repo, out: (p.flags.get('--out') as string | undefined) ?? null, kit: (p.flags.get('--kit') as string | undefined) ?? null,
    edition, stage: stage as 'LAUNCH' | 'GROWTH' | 'SCALE' | null, allowNetwork: p.flags.has('--allow-network'), tools: tools as ScannerId[] | null,
    rulePack: (p.flags.get('--rule-pack') as string | undefined) ?? null, log: (s) => err(s + '\n'),
  });
}

async function readCmd(cmd: 'report' | 'gate', rest: string[], err: (s: string) => void): Promise<number> {
  const p = parse(cmd, rest, ['--out', '--kit', '--commit', '--owner', '--date']);
  if (typeof p === 'string') { err(`hullproof ${cmd}: ${p}\n`); return EXIT.badInput; }
  const get = (f: string): string | null => (p.flags.get(f) as string | undefined) ?? null;
  const o = { repo: p.repo, out: get('--out'), kit: get('--kit'), commit: get('--commit'), owner: get('--owner'), date: get('--date'), log: (s: string) => err(s + '\n') };
  return cmd === 'report' ? report(o) : gate(o);
}

export function main(argv: string[]): number | Promise<number> {
  const [cmd, ...rest] = argv;
  const out = (s: string): void => { process.stdout.write(s); };
  const err = (s: string): void => { process.stderr.write(s); };

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') { out(HELP); return EXIT.ok; }
  if (cmd === 'version' || cmd === '--version') { out(`${ENGINE_VERSION}\n`); return EXIT.ok; }
  if (cmd === 'discover') return discoverCmd(rest, out, err);
  if (cmd === 'scan') return scanCmd(rest, err);
  if (cmd === 'report' || cmd === 'gate') return readCmd(cmd, rest, err);
  err(`hullproof: unknown command "${cmd}". Run hullproof help.\n`);
  return EXIT.badInput;
}

const invokedAs = (): string => { try { return pathToFileURL(realpathSync(process.argv[1] ?? '')).href; } catch { return ''; } };
if (import.meta.url === invokedAs()) process.exitCode = await main(process.argv.slice(2));
