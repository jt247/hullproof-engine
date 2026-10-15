// hullproof hooks install and uninstall: a git pre-commit hook for plain git, a Husky entry, or a pre-commit framework entry.
// The hook only calls `hullproof hooks run` (src/hooks/run.ts). Only exit code 1 from it blocks a commit; a missing command or an
// engine error lets the commit through, because the hook must never be the reason a team cannot work. `git commit --no-verify` skips it.
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

export type HookMode = 'git' | 'husky' | 'pre-commit';
export const MARKER_BEGIN = '# >>> hullproof >>>';
export const MARKER_END = '# <<< hullproof <<<';
const HOOK_TAG = '# hullproof pre-commit hook';

const sh = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;
const git = (repo: string, ...a: string[]): string | null => {
  const r = spawnSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
};

export interface Detected { root: string; mode: HookMode; husky: boolean; framework: boolean; hooksPath: string | null; huskyV8: boolean }

export function detect(repo: string): Detected | string {
  const root = git(repo, 'rev-parse', '--show-toplevel');
  if (!root) return `${resolve(repo)} is not inside a git repository`;
  const hooksPath = git(root, 'config', '--get', 'core.hooksPath');
  let pkgHusky = false;
  try {
    const p = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>;
    pkgHusky = !!(p.devDependencies?.husky || p.dependencies?.husky);
  } catch { /* no package.json */ }
  const husky = existsSync(join(root, '.husky')) || pkgHusky || (hooksPath ?? '').replace(/^\.\//, '').startsWith('.husky');
  const framework = existsSync(join(root, '.pre-commit-config.yaml'));
  return { root, husky, framework, hooksPath, huskyV8: existsSync(join(root, '.husky/_/husky.sh')), mode: husky ? 'husky' : framework ? 'pre-commit' : 'git' };
}

// How the hook calls the engine: `hullproof` when it is on PATH now, else this very engine through node, by absolute path.
export function runner(): string {
  const onPath = spawnSync('sh', ['-c', 'command -v hullproof'], { encoding: 'utf8' });
  if (onPath.status === 0 && onPath.stdout.trim()) return 'hullproof';
  let cli = process.argv[1] ?? '';
  try { cli = realpathSync(cli); } catch { /* keep as given */ }
  return `${sh(process.execPath)} ${sh(cli)}`;
}

const callLines = (cmd: string): string[] => [
  `${cmd} hooks run`,
  'status=$?',
  // Only a block (1) stops the commit. 127 (command not found) and any other code let it through.
  'if [ "$status" -eq 1 ]; then exit 1; fi',
];

export const plainHook = (cmd: string): string => ['#!/bin/sh', `${HOOK_TAG}. Installed by hullproof hooks install, removed by hullproof hooks uninstall.`, '# Skip it once with: git commit --no-verify', ...callLines(cmd), 'exit 0', ''].join('\n');
export const huskyBlock = (cmd: string): string => [MARKER_BEGIN, ...callLines(cmd), MARKER_END, ''].join('\n');
export const frameworkBlock = (cmd: string): string => [
  `  ${MARKER_BEGIN}`,
  '  - repo: local',
  '    hooks:',
  '      - id: hullproof',
  '        name: hullproof (secrets and blocking findings in staged files)',
  `        entry: ${cmd} hooks run`,
  '        language: system',
  '        pass_filenames: false',
  '        always_run: true',
  `  ${MARKER_END}`, '',
].join('\n');

export interface InstallResult { code: number; lines: string[] }
export interface InstallOptions { repo: string; mode: HookMode | null; dryRun: boolean; uninstall: boolean }

const stripBlock = (text: string): string => {
  const re = new RegExp(`\\n?[ \\t]*${MARKER_BEGIN.replace(/[>]/g, '\\>')}[\\s\\S]*?${MARKER_END.replace(/[<]/g, '\\<')}\\n?`, 'g');
  return text.replace(re, '\n').replace(/\n{3,}/g, '\n\n');
};

export function installHooks(o: InstallOptions): InstallResult {
  const d = detect(o.repo);
  if (typeof d === 'string') return { code: 2, lines: [`hullproof hooks: ${d}`] };
  const mode = o.mode ?? d.mode;
  const lines: string[] = [`hullproof hooks: mode ${mode}${o.mode ? '' : ` (detected: Husky ${d.husky ? 'yes' : 'no'}, pre-commit framework ${d.framework ? 'yes' : 'no'})`}`];
  const cmd = runner();
  const write = (path: string, text: string, exec = false): void => {
    if (o.dryRun) { lines.push(`would write ${path}`); return; }
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
    if (exec) chmodSync(path, 0o755);
    lines.push(`wrote ${path}`);
  };

  if (mode === 'git') {
    const hooksDir = git(d.root, 'rev-parse', '--git-path', 'hooks');
    if (!hooksDir) return { code: 2, lines: [...lines, 'hullproof hooks: could not find the git hooks folder'] };
    const path = resolve(d.root, hooksDir, 'pre-commit');
    const current = existsSync(path) ? readFileSync(path, 'utf8') : null;
    if (o.uninstall) {
      if (current === null) lines.push('no pre-commit hook to remove');
      else if (!current.includes(HOOK_TAG)) return { code: 2, lines: [...lines, `${path} is not a Hullproof hook, so it was left alone`] };
      else if (o.dryRun) lines.push(`would remove ${path}`);
      else { rmSync(path); lines.push(`removed ${path}`); }
      return { code: 0, lines };
    }
    if (current !== null && !current.includes(HOOK_TAG)) {
      return { code: 2, lines: [...lines, `${path} already exists and is not a Hullproof hook. It was not changed.`, 'Add this to it, or use the Husky or pre-commit framework mode:', ...callLines(cmd)] };
    }
    write(path, plainHook(cmd), true);
    return { code: 0, lines };
  }

  if (mode === 'husky') {
    const path = join(d.root, '.husky/pre-commit');
    const current = existsSync(path) ? readFileSync(path, 'utf8') : null;
    if (o.uninstall) {
      if (current === null || !current.includes(MARKER_BEGIN)) lines.push('no Hullproof entry in .husky/pre-commit');
      else write(path, stripBlock(current));
      return { code: 0, lines };
    }
    if (current?.includes(MARKER_BEGIN)) { lines.push('.husky/pre-commit already has the Hullproof entry'); return { code: 0, lines }; }
    const head = current ?? `#!/usr/bin/env sh\n${d.huskyV8 ? '. "$(dirname -- "$0")/_/husky.sh"\n' : ''}`;
    write(path, `${head.replace(/\n*$/, '\n')}${huskyBlock(cmd)}`, true);
    return { code: 0, lines };
  }

  // pre-commit framework
  const path = join(d.root, '.pre-commit-config.yaml');
  const current = existsSync(path) ? readFileSync(path, 'utf8') : null;
  if (o.uninstall) {
    if (current === null || !current.includes(MARKER_BEGIN)) lines.push('no Hullproof entry in .pre-commit-config.yaml');
    else write(path, stripBlock(current));
    return { code: 0, lines };
  }
  if (current?.includes(MARKER_BEGIN)) { lines.push('.pre-commit-config.yaml already has the Hullproof entry'); return { code: 0, lines }; }
  const block = frameworkBlock(cmd);
  // The entry is appended at the end of the file, which is only right when `repos:` is the last top level key and a block list.
  const topKeys = (current ?? '').split('\n').filter((l) => /^[A-Za-z_][\w-]*\s*:/.test(l));
  const last = topKeys.at(-1) ?? '';
  const appendable = current === null || (/^repos\s*:\s*$/.test(last) && last === topKeys.find((k) => k.startsWith('repos')));
  if (!appendable) {
    return { code: 0, lines: [...lines, 'could not add the entry safely (the file has keys after `repos:` or a flow style list). Add this under `repos:` yourself:', '', block.replace(/^ {2}# .*\n/gm, '')] };
  }
  const base = current ?? 'repos:\n';
  write(path, `${base.replace(/\n*$/, '\n')}${block}`);
  lines.push('run `pre-commit install` once so the framework runs it on each commit');
  return { code: 0, lines };
}
