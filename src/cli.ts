#!/usr/bin/env node
// hullproof: the engine command line. Node 22.18 or later runs this TypeScript file directly. No dependencies.
import { mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { discover } from './discover/discover.ts';
import { mapCommand } from './commands/map.ts';
import { scan } from './commands/scan.ts';
import { huntCommand } from './commands/hunt.ts';
import { ciCommand } from './commands/ci.ts';
import { hooksCommand } from './commands/hooks.ts';
import { mcpCommand } from './commands/mcp.ts';
import { FAIL_ON_LEVELS, type FailOn } from './ci/comment.ts';
import { proveCommand } from './commands/prove.ts';
import { packCommand } from './commands/pack.ts';
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
  map        Build the code map of a repository (entry points and what protects them) and write codemap.json
  scan       Run discovery, the scanners and the checks; write <out>/<commit>/
  ci         One command for CI: scan, map, check, gate; write findings.json, report.md, results.sarif, pr-comment.md
  hooks      Install or remove the git pre-commit hook (install, uninstall), or run its fast check (run)
  mcp        Serve the scan results to an AI tool over MCP on stdio (read only; run_scan with --allow-run)
  hunt       Hunt for leads with a model, confirm them with evidence, or replay saved outputs (--replay)
  prove      Run test specs against a local copy of the app in a sandbox and keep the transcripts as evidence
  pack       Validate the stack packs (validate), list them (list), or print the coverage table from their recorded results (table)
  report     Write report.md from a scan folder
  gate       Apply the release gate to a scan folder and exit with its code
  version    Print the engine version
  help       Print this help

Options for discover:
  --out DIR  Folder for stack.json (default: .hullproof inside the repository). Use --out - to print to standard output.

Options for map:
  --out DIR  Folder for codemap.json (default: .hullproof inside the repository). Use --out - to print to standard output.

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

Options for ci (also --out, --kit, --edition, --stage, --allow-network, --tools, --rule-pack as for scan; --owner, --date as for gate):
  --fail-on LEVEL   blocker, critical, high, medium, low or none (default blocker). Exit 1 when a finding at or above LEVEL failed.
  --artifacts DIR   Flat folder for the four output files (default: ci inside the --out folder)
  --hunt            Pro only: run the model hunt first. Needs a provider key in the environment (a CI secret); fork pull requests get none.
  --provider, --model as for hunt
  ci runs no model and no container unless --hunt is given. The same commit gives the same four files, byte for byte.

Options for hooks (hullproof hooks install|uninstall|run [repository]):
  --mode git|husky|pre-commit  Where the hook goes (default: Husky if the repository uses it, else the pre-commit framework if it has a config, else plain git)
  --dry-run         install and uninstall: say what would change and change nothing
  --kit DIR         run: the kit folder (as for scan)
  --no-semgrep      run: check secrets and the deterministic checks only (also: HULLPROOF_HOOK_SEMGREP=0)
  run looks at the staged files only, blocks (exit 1) on a secret or a BLOCKER finding in them, and sends nothing anywhere. An error never blocks a commit.

Options for mcp (hullproof mcp [repository]):
  --kit DIR         The kit folder (as for scan)
  --edition free|pro  Which requirements are served (default: the kit decides)
  --allow-run       Also offer run_scan, which runs hullproof ci and writes only under .hullproof/. Off by default.
  mcp makes no network call, runs no model, and never leaves the repository folder. It writes nothing but JSON-RPC to standard output.

Options for hunt:
  --provider NAME   anthropic, openai, gemini or local (default: HULLPROOF_PROVIDER, else the one provider whose key is set)
  --model NAME      The model to call (default: HULLPROOF_MODEL). Keys come from the environment or a .env.local file, never from a flag.
  --runs N          Hunting runs per entry point (default 3), then one synthesis call
  --dry-run         List the entry points and calls and make no model call
  --resume          Continue an interrupted hunt from the answers already saved
  --replay          Rerun the confirmation from the saved answers; no model, same bytes every time
  --out, --kit, --commit as for report

Options for prove:
  --allow-run       Required to run the app. The owner must also type the confirmation (asked on a terminal, or pass --confirm).
  --confirm TEXT    The confirmation phrase, for a run with no terminal. Nothing else (no variable, no CI setting) can stand in for it.
  --spec FILE[,FILE] Test specs written by hand (see docs/INTERFACES.md); they are checked and copied into the scan folder.
  --allow-install-scripts  Let dependency install scripts run in the build container (default off). Needed for native modules such
                    as better-sqlite3, bcrypt and sharp. Third party code runs with network access to the package registry.
  --gen             Write specs from hunt leads with a model (Pro). Runs nothing unless --allow-run is also given.
  --replay          Rebuild result.json from the saved specs and transcripts. No sandbox, no app, same bytes every time.
  --self-test       Run the escape attempts (network call, host file read, fork bomb, long loop) against this machine's container runtime.
  --runtime NAME    The container command: docker (Colima and Docker Desktop) or podman (default: HULLPROOF_CONTAINER_BIN, else docker)
  --provider, --model, --out, --commit as for hunt
  prove accepts no address. It only ever runs a copy of the app inside the sandbox, and refuses --target.

Options for pack (hullproof pack validate|list|table [pack folder ...]):
  --root DIR        The engine checkout the packs name their files in (default: this engine). Folders given by name are validated in place.
  validate rejects a pack that is missing a part for its level, lists a rule without a test, has no fixture result, uses a bad level or claims
  a level its recorded fixture result does not support. It reads files only. Exit 1 when a pack fails.

Exit codes: 0 done (gate: READY or READY WITH ACCEPTED RISK), 1 open items (gate: NOT READY),
2 bad input, a refused run or a records problem.
`;

const TOOLS: ScannerId[] = ['semgrep', 'osv-scanner', 'gitleaks', 'trivy', 'checkov'];

interface Parsed { repo: string; flags: Map<string, string | true> }
const VALUE_FLAGS = new Set(['--mode', '--fail-on', '--artifacts', '--provider', '--model', '--runs', '--out', '--kit', '--edition', '--stage', '--tools', '--commit', '--owner', '--date', '--rule-pack', '--confirm', '--spec', '--runtime', '--target']);
const BOOL_FLAGS = new Set(['--no-semgrep', '--hunt', '--allow-network', '--dry-run', '--resume', '--replay', '--allow-run', '--gen', '--self-test', '--allow-install-scripts']);

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

function mapCmd(rest: string[], out: (s: string) => void, err: (s: string) => void): number {
  const p = parse('map', rest, ['--out']);
  if (typeof p === 'string') { err(`hullproof map: ${p}${p.startsWith('--out') ? ', or - for standard output' : ''}.\n`); return EXIT.badInput; }
  return mapCommand(p.repo, (p.flags.get('--out') as string | undefined) ?? null, out, err);
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

async function ciCmd(rest: string[], out: (s: string) => void, err: (s: string) => void): Promise<number> {
  const p = parse('ci', rest, ['--out', '--kit', '--edition', '--stage', '--allow-network', '--tools', '--rule-pack', '--owner', '--date', '--fail-on', '--artifacts', '--hunt', '--provider', '--model']);
  if (typeof p === 'string') { err(`hullproof ci: ${p}\n`); return EXIT.badInput; }
  const get = (f: string): string | null => (p.flags.get(f) as string | undefined) ?? null;
  const edition = get('--edition');
  const stage = get('--stage');
  const failOn = (get('--fail-on') ?? 'blocker').toLowerCase();
  const tools = get('--tools') ? String(get('--tools')).split(',').map((t) => t.trim()) : null;
  if (edition && edition !== 'free' && edition !== 'pro') { err('hullproof ci: --edition is free or pro\n'); return EXIT.badInput; }
  if (stage && !['LAUNCH', 'GROWTH', 'SCALE'].includes(stage)) { err('hullproof ci: --stage is LAUNCH, GROWTH or SCALE\n'); return EXIT.badInput; }
  if (!(FAIL_ON_LEVELS as readonly string[]).includes(failOn)) { err(`hullproof ci: --fail-on takes ${FAIL_ON_LEVELS.join(', ')}\n`); return EXIT.badInput; }
  if (tools && tools.some((t) => !TOOLS.includes(t as ScannerId))) { err(`hullproof ci: --tools takes ${TOOLS.join(', ')}\n`); return EXIT.badInput; }
  if (get('--date') && !/^\d{4}-\d{2}-\d{2}$/.test(get('--date')!)) { err('hullproof ci: --date needs YYYY-MM-DD\n'); return EXIT.badInput; }
  return ciCommand({
    repo: p.repo, out: get('--out'), kit: get('--kit'), edition: edition as 'free' | 'pro' | null, stage: stage as 'LAUNCH' | 'GROWTH' | 'SCALE' | null,
    failOn: failOn as FailOn, artifacts: get('--artifacts'), allowNetwork: p.flags.has('--allow-network'), tools: tools as ScannerId[] | null,
    rulePack: get('--rule-pack'), owner: get('--owner'), date: get('--date'), hunt: p.flags.has('--hunt'), provider: get('--provider'), model: get('--model'),
    log: (s) => err(s + '\n'), print: (s) => out(s + '\n'),
  });
}

async function hooksCmd(rest: string[], err: (s: string) => void): Promise<number> {
  const [action, ...more] = rest;
  const p = parse('hooks', more, ['--mode', '--dry-run', '--kit', '--no-semgrep']);
  if (typeof p === 'string') { err(`hullproof hooks: ${p}\n`); return EXIT.badInput; }
  const get = (f: string): string | null => (p.flags.get(f) as string | undefined) ?? null;
  return hooksCommand({ action: action ?? '', repo: p.repo, mode: get('--mode'), dryRun: p.flags.has('--dry-run'), kit: get('--kit'), noSemgrep: p.flags.has('--no-semgrep'), log: (s) => err(s + '\n') });
}

async function mcpCmd(rest: string[], err: (s: string) => void): Promise<number> {
  const p = parse('mcp', rest, ['--kit', '--edition', '--allow-run']);
  if (typeof p === 'string') { err(`hullproof mcp: ${p}\n`); return EXIT.badInput; }
  const get = (f: string): string | null => (p.flags.get(f) as string | undefined) ?? null;
  const edition = get('--edition');
  if (edition && edition !== 'free' && edition !== 'pro') { err('hullproof mcp: --edition is free or pro\n'); return EXIT.badInput; }
  return mcpCommand({ repo: p.repo, kit: get('--kit'), edition: edition as 'free' | 'pro' | null, allowRun: p.flags.has('--allow-run'), log: (s) => err(s + '\n') });
}

async function readCmd(cmd: 'report' | 'gate', rest: string[], err: (s: string) => void): Promise<number> {
  const p = parse(cmd, rest, ['--out', '--kit', '--commit', '--owner', '--date']);
  if (typeof p === 'string') { err(`hullproof ${cmd}: ${p}\n`); return EXIT.badInput; }
  const get = (f: string): string | null => (p.flags.get(f) as string | undefined) ?? null;
  const o = { repo: p.repo, out: get('--out'), kit: get('--kit'), commit: get('--commit'), owner: get('--owner'), date: get('--date'), log: (s: string) => err(s + '\n') };
  return cmd === 'report' ? report(o) : gate(o);
}

async function huntCmd(rest: string[], err: (s: string) => void): Promise<number> {
  const p = parse('hunt', rest, ['--out', '--kit', '--commit', '--provider', '--model', '--runs', '--dry-run', '--resume', '--replay']);
  if (typeof p === 'string') { err(`hullproof hunt: ${p}\n`); return EXIT.badInput; }
  const get = (f: string): string | null => (p.flags.get(f) as string | undefined) ?? null;
  const runsRaw = get('--runs');
  if (runsRaw !== null && !/^[1-9]\d*$/.test(runsRaw)) { err('hullproof hunt: --runs needs a whole number of 1 or more\n'); return EXIT.badInput; }
  return huntCommand({ repo: p.repo, out: get('--out'), kit: get('--kit'), commit: get('--commit'), provider: get('--provider'), model: get('--model'),
    runs: runsRaw === null ? null : Number(runsRaw), dryRun: p.flags.has('--dry-run'), resume: p.flags.has('--resume'), replay: p.flags.has('--replay'), log: (s) => err(s + '\n') });
}

function packCmd(rest: string[], out: (s: string) => void, err: (s: string) => void): number {
  const [action, ...more] = rest;
  const targets: string[] = [];
  let root: string | null = null;
  for (let i = 0; i < more.length; i++) {
    if (more[i] === '--root') { root = more[++i] ?? null; if (!root) { err('hullproof pack: --root needs a folder.\n'); return EXIT.badInput; } } else if (more[i].startsWith('-')) { err(`hullproof pack: unknown option ${more[i]}.\n`); return EXIT.badInput; } else targets.push(more[i]);
  }
  return packCommand({ action: action ?? '', targets, root, out, err });
}

async function proveCmd(rest: string[], err: (s: string) => void): Promise<number> {
  const p = parse('prove', rest, ['--out', '--commit', '--allow-run', '--confirm', '--target', '--spec', '--allow-install-scripts', '--gen', '--provider', '--model', '--replay', '--self-test', '--runtime']);
  if (typeof p === 'string') { err(`hullproof prove: ${p}\n`); return EXIT.badInput; }
  const get = (f: string): string | null => (p.flags.get(f) as string | undefined) ?? null;
  return proveCommand({ repo: p.repo, out: get('--out'), commit: get('--commit'), allowRun: p.flags.has('--allow-run'), allowInstallScripts: p.flags.has('--allow-install-scripts'), confirm: get('--confirm'), target: get('--target'),
    specs: (get('--spec') ?? '').split(',').map((x) => x.trim()).filter(Boolean), gen: p.flags.has('--gen'), provider: get('--provider'), model: get('--model'),
    replay: p.flags.has('--replay'), selfTest: p.flags.has('--self-test'), runtime: get('--runtime'), log: (s) => err(s + '\n') });
}

export function main(argv: string[]): number | Promise<number> {
  const [cmd, ...rest] = argv;
  const out = (s: string): void => { process.stdout.write(s); };
  const err = (s: string): void => { process.stderr.write(s); };

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') { out(HELP); return EXIT.ok; }
  if (cmd === 'version' || cmd === '--version') { out(`${ENGINE_VERSION}\n`); return EXIT.ok; }
  if (cmd === 'discover') return discoverCmd(rest, out, err);
  if (cmd === 'map') return mapCmd(rest, out, err);
  if (cmd === 'scan') return scanCmd(rest, err);
  if (cmd === 'ci') return ciCmd(rest, out, err);
  if (cmd === 'hooks') return hooksCmd(rest, err);
  if (cmd === 'mcp') return mcpCmd(rest, err);
  if (cmd === 'hunt') return huntCmd(rest, err);
  if (cmd === 'prove') return proveCmd(rest, err);
  if (cmd === 'pack') return packCmd(rest, out, err);
  if (cmd === 'report' || cmd === 'gate') return readCmd(cmd, rest, err);
  err(`hullproof: unknown command "${cmd}". Run hullproof help.\n`);
  return EXIT.badInput;
}

const invokedAs = (): string => { try { return pathToFileURL(realpathSync(process.argv[1] ?? '')).href; } catch { return ''; } };
if (import.meta.url === invokedAs()) process.exitCode = await main(process.argv.slice(2));
