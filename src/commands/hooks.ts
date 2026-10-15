// hullproof hooks install | uninstall | run. `run` is what the git hook calls (src/hooks/run.ts).
import { installHooks, type HookMode } from '../hooks/install.ts';
import { runHook } from '../hooks/run.ts';

export interface HooksOptions { action: string; repo: string; mode: string | null; dryRun: boolean; kit: string | null; noSemgrep: boolean; log?: (s: string) => void }

export async function hooksCommand(o: HooksOptions): Promise<number> {
  const log = o.log ?? ((s: string) => process.stderr.write(s + '\n'));
  if (o.action === 'install' || o.action === 'uninstall') {
    if (o.mode && !['git', 'husky', 'pre-commit'].includes(o.mode)) { log('hullproof hooks: --mode is git, husky or pre-commit'); return 2; }
    const r = installHooks({ repo: o.repo, mode: o.mode as HookMode | null, dryRun: o.dryRun, uninstall: o.action === 'uninstall' });
    for (const l of r.lines) log(l);
    return r.code;
  }
  if (o.action === 'run') {
    try {
      const r = await runHook({ repo: o.repo, kit: o.kit, semgrep: !o.noSemgrep && process.env.HULLPROOF_HOOK_SEMGREP !== '0' });
      for (const l of r.lines) log(l);
      return r.code === 1 ? 1 : r.code === 2 ? 0 : r.code;
    } catch (e) {
      log(`hullproof: the pre-commit check could not run (${(e as Error).message}). The commit was not blocked.`);
      return process.env.HULLPROOF_HOOK_STRICT === '1' ? 1 : 0;
    }
  }
  log('hullproof hooks: use install, uninstall or run');
  return 2;
}
