// UNSAFE. A plain local process backend, for the engine's own fixture apps in CI and nothing else. There is no isolation here: the
// app runs as the current user on the host. For that reason this runner refuses any repository that is not inside a fixture folder of
// this engine, and the command line never offers it. It is labelled unsafe in its name, in the result file and in the report.
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeSpec } from './executor.ts';
import { assertSandboxTarget } from './safety.ts';
import { validateSpec } from './spec.ts';
import type { Exec, Instance, PrepareRequest, PrepareResult, Prepared, Runner, SpecRun, StartResult, Teardown } from './runner.ts';

const ENGINE = fileURLToPath(new URL('../../', import.meta.url));
export const FIXTURE_ROOTS = [join(ENGINE, 'test/fixtures/prove'), join(ENGINE, 'bench/fixtures')];
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const freePort = (): Promise<number> => new Promise((res, rej) => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const p = (s.address() as { port: number }).port; s.close(() => res(p)); }); s.on('error', rej); });
const inside = (p: string, root: string): boolean => p === root || p.startsWith(root + sep);

export class LocalProcessRunner implements Runner {
  readonly name = 'local-process-unsafe';
  private readonly roots: string[];
  constructor(o: { acknowledgeUnsafe: true; fixtureRoots?: string[] }) {
    if (o.acknowledgeUnsafe !== true) throw new Error('the local process runner is unsafe and must be created with acknowledgeUnsafe: true');
    this.roots = (o.fixtureRoots ?? FIXTURE_ROOTS).map((r) => { try { return realpathSync(r); } catch { return r; } });
  }
  async available(): Promise<{ ok: true }> { return { ok: true }; }

  async prepare(req: PrepareRequest): Promise<PrepareResult> {
    let src: string;
    try { src = realpathSync(req.sourceDir); } catch { return { ok: false, code: 'refused_unsafe_backend', reason: 'the source folder does not exist' }; }
    if (!this.roots.some((r) => inside(src, r))) return { ok: false, code: 'refused_unsafe_backend', reason: 'the local process backend has no isolation, so it only runs the fixture apps of this engine and refuses any other folder' };
    if (req.recipe.install) return { ok: false, code: 'refused_unsafe_backend', reason: 'the local process backend installs nothing' };
    if (req.recipe.data_store.kind === 'postgres') return { ok: false, code: 'refused_unsafe_backend', reason: 'the local process backend has no Postgres' };
    return { ok: true, prepared: new LocalPrepared(req) };
  }
}

class LocalPrepared implements Prepared {
  private readonly req: PrepareRequest;
  private readonly live = new Set<LocalInstance>();
  constructor(req: PrepareRequest) { this.req = req; }

  // A free port is chosen first and the app binds it a moment later, so another process can take it in between. Start again on a new
  // port, twice at most, when the app exits before it answers.
  async start(): Promise<StartResult> {
    let last = await this.startOnce();
    for (let i = 0; i < 2 && !last.ok && last.code === 'start_failed' && this.req.recipe.port_from_env; i++) last = await this.startOnce();
    return last;
  }

  private async startOnce(): Promise<StartResult> {
    const { recipe, copyDir, limits } = this.req;
    const data = mkdtempSync(join(tmpdir(), 'hp-local-data-'));
    const port = recipe.port_from_env ? await freePort() : recipe.port;
    const env: Record<string, string> = { PATH: process.env.PATH ?? '', HOME: data, TMPDIR: data };
    for (const [k, v] of Object.entries(recipe.env)) env[k] = v.replace(/\{DATA\}/g, data);
    if (recipe.port_from_env) env.PORT = String(port);
    let log = '';
    const child = spawn('sh', ['-c', `${recipe.seed ? recipe.seed + ' && ' : ''}exec ${recipe.start}`], { cwd: copyDir, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (d: Buffer) => { log = (log + d.toString()).slice(-2000); });
    child.stderr.on('data', (d: Buffer) => { log = (log + d.toString()).slice(-2000); });
    let exited = false;
    child.on('exit', () => { exited = true; });
    const inst = new LocalInstance(child, data, port);
    this.live.add(inst);
    const deadline = Date.now() + limits.healthMs;
    while (Date.now() < deadline && !exited) {
      try { const r = await fetch(`http://127.0.0.1:${port}${recipe.health_path}`, { signal: AbortSignal.timeout(1500) }); if (r.status < 500) return { ok: true, instance: inst }; } catch { /* not up yet */ }
      await sleep(100);
    }
    await inst.stop();
    return { ok: false, code: exited ? 'start_failed' : 'health_failed', reason: `${exited ? 'the app exited before it answered' : 'the app did not answer in time'}: ${log.trim().replace(/\s+/g, ' ').slice(-300)}` };
  }
  async dispose(): Promise<Teardown> { for (const i of this.live) await i.stop(); return { left_behind: [...this.live].flatMap((i) => i.alive() ? [`process ${i.pid}`] : []) }; }
}

class LocalInstance implements Instance {
  readonly baseUrl: string;
  readonly pid: number;
  private readonly child: ChildProcess;
  private readonly data: string;
  private readonly port: number;
  constructor(child: ChildProcess, data: string, port: number) { this.child = child; this.data = data; this.port = port; this.pid = child.pid ?? 0; this.baseUrl = `http://127.0.0.1:${port}`; }
  alive(): boolean { try { process.kill(this.pid, 0); return true; } catch { return false; } }
  async exec(): Promise<Exec> { return { code: null, stdout: '', stderr: 'the local process backend does not run commands', timedOut: false }; }
  async runSpec(spec: import('../types/index.ts').Spec): Promise<SpecRun> {
    const v = validateSpec(spec);
    if (!v.ok) return { ok: false, reason: `invalid spec: ${v.errors.join('; ')}` };
    try { assertSandboxTarget(this.baseUrl, this.port); return { ok: true, ...(await executeSpec(v.spec, { baseUrl: this.baseUrl })) }; } catch (e) { return { ok: false, reason: (e as Error).message }; }
  }
  async stop(): Promise<Teardown> {
    try { process.kill(-this.pid, 'SIGKILL'); } catch { /* already gone */ }
    for (let i = 0; i < 20 && this.alive(); i++) await sleep(25);
    rmSync(this.data, { recursive: true, force: true });
    return { left_behind: this.alive() ? [`process ${this.pid}`] : [] };
  }
}
