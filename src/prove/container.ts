// The container backend. It speaks the docker command line, so Colima, Docker Desktop and Podman work through the same commands.
// Safety rules 4 and 6 of the design are built into runArgs() and checked again by assertSafeRunArgs() before any container starts:
// non root, read only root filesystem, no host mounts (the copy goes in at build time, nothing is mounted), no capabilities, no
// privilege escalation, memory, cpu, process and time limits, and no network while tests run. The build phase may reach the package
// registry (lockfile install, no install scripts). A Postgres store runs on an internal network that has no route out.
import { spawn } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Recipe } from '../types/index.ts';
import { assertSandboxTarget } from './safety.ts';
import type { Exec, Instance, Limits, PrepareRequest, PrepareResult, Prepared, Runner, SpecRun, StartResult, Teardown } from './runner.ts';

export interface ContainerRuntime { readonly bin: string; run(args: string[], o?: { input?: string; timeoutMs?: number }): Promise<Exec> }

const MAX_OUT = 4 * 1024 * 1024;
export class CliRuntime implements ContainerRuntime {
  readonly bin: string;
  constructor(bin: string = 'docker') { this.bin = bin; }
  run(args: string[], o: { input?: string; timeoutMs?: number } = {}): Promise<Exec> {
    return new Promise((resolve) => {
      let out = ''; let err = ''; let timedOut = false; let done = false;
      const fin = (e: Exec): void => { if (!done) { done = true; resolve(e); } };
      let child;
      try { child = spawn(this.bin, args, { stdio: ['pipe', 'pipe', 'pipe'] }); } catch (e) { return fin({ code: null, stdout: '', stderr: (e as Error).message, timedOut: false }); }
      const timer = o.timeoutMs ? setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, o.timeoutMs) : null;
      child.stdout.on('data', (d: Buffer) => { if (out.length < MAX_OUT) out += d.toString('utf8'); });
      child.stderr.on('data', (d: Buffer) => { if (err.length < MAX_OUT) err += d.toString('utf8'); });
      child.on('error', (e: Error) => { if (timer) clearTimeout(timer); fin({ code: null, stdout: out, stderr: (e as NodeJS.ErrnoException).code === 'ENOENT' ? `${this.bin}: command not found` : e.message, timedOut }); });
      child.on('close', (code: number | null) => { if (timer) clearTimeout(timer); fin({ code, stdout: out, stderr: err, timedOut }); });
      child.stdin.on('error', () => undefined);
      child.stdin.end(o.input ?? '');
    });
  }
}

export const LABEL = 'hullproof.prove';
export const APP_USER = '10001:10001';
export const EXEC_DIR = '/app/.hullproof-exec';
const EXEC_FILES = ['spec.ts', 'executor.ts', 'exec-main.ts'];
// The step executor runs inside the container as TypeScript, so its sources are always read from src/prove (shipped with the package),
// also when the engine itself runs from dist/.
const HERE = fileURLToPath(new URL('../../src/prove/', import.meta.url));
const PG_IMAGE = 'postgres:16-alpine';
const PG_USER = '70:70';
const clip = (s: string, n = 600): string => { const t = s.trim().replace(/\s+/g, ' '); return t.length <= n ? t : '…' + t.slice(t.length - n); };
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// ---- commands, as pure functions so they can be tested without a runtime --------------------------------------------------------
// A Python app runs in a Python image that also holds the node binary, because the step executor and the health probe are Node scripts
// that run inside the sandbox. The binary is copied from the same image the Node recipe uses, at build time, so nothing else is fetched.
export const NODE_IMAGE = 'node:22-slim';
export function dockerfile(r: Recipe): string {
  const py = r.stack === 'python-flask';
  return [
    ...(py ? [`FROM ${NODE_IMAGE} AS node`] : []),
    `FROM ${r.base_image}`,
    ...(py ? ['COPY --from=node /usr/local/bin/node /usr/local/bin/node', 'ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 HOME=/tmp'] : []),
    'WORKDIR /app', 'COPY . /app', ...(r.install ? [`RUN ${r.install.join(' ')}`] : []), `USER ${APP_USER}`, '',
  ].join('\n');
}
export const buildArgs = (tag: string, runId: string, ctx: string): string[] => ['build', '--label', `${LABEL}=${runId}`, '--tag', tag, '--file', join(ctx, 'Dockerfile.hullproof'), ctx];

export interface RunSpecArgs { name: string; runId: string; image: string; network: string; user: string; tmpfs: string[]; env: Record<string, string>; limits: Limits; cmd: string[] }
export function runArgs(a: RunSpecArgs): string[] {
  const args = [
    'run', '--detach', '--init', '--name', a.name, '--label', `${LABEL}=${a.runId}`,
    '--network', a.network, '--read-only', '--user', a.user, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--pids-limit', String(a.limits.pids), '--memory', a.limits.memory, '--memory-swap', a.limits.memory, '--cpus', a.limits.cpus,
    '--ulimit', 'nofile=1024:1024', '--ulimit', 'core=0',
    ...a.tmpfs.flatMap((t) => ['--tmpfs', t]),
    ...Object.entries(a.env).flatMap(([k, v]) => ['--env', `${k}=${v}`]),
    a.image, ...a.cmd,
  ];
  assertSafeRunArgs(args.slice(0, args.length - 1 - a.cmd.length), a.network);
  return args;
}

const FORBIDDEN = new Set(['--privileged', '-v', '--volume', '--volumes-from', '--mount', '-p', '--publish', '-P', '--publish-all', '--device', '--cap-add', '--pid', '--ipc', '--uts', '--userns', '--add-host', '--env-file', '--cgroupns', '--group-add', '--sysctl']);
// Refuses anything that would weaken the sandbox. `head` is the argument list up to, and not including, the image name. The builder
// calls this on its own output; tests call it on bad input.
export function assertSafeRunArgs(head: string[], allowedNetwork: string): void {
  const bad: string[] = [];
  const val = (flag: string): string | undefined => { const i = head.indexOf(flag); return i >= 0 ? head[i + 1] : undefined; };
  for (const a of head) if (FORBIDDEN.has(a) || /^--(?:privileged|volume|mount|publish|device|cap-add|pid|ipc|uts|userns|add-host|env-file)=/.test(a)) bad.push(a);
  if (head.some((a) => /unconfined/.test(a))) bad.push('unconfined security option');
  if (!head.includes('--read-only')) bad.push('missing --read-only');
  if (val('--cap-drop') !== 'ALL') bad.push('capabilities are not all dropped');
  if (!head.some((a, i) => a === '--security-opt' && head[i + 1] === 'no-new-privileges')) bad.push('missing no-new-privileges');
  for (const f of ['--pids-limit', '--memory', '--cpus']) if (!val(f)) bad.push(`missing ${f}`);
  const user = val('--user');
  if (!user || /^(?:0|root)(?::|$)/.test(user)) bad.push('the container would run as root');
  const net = val('--network');
  if (net !== 'none' && net !== allowedNetwork) bad.push(`network ${net ?? 'default'} is not none or the internal network`);
  if (net !== 'none' && !/^hp-prove-net-/.test(net ?? '')) bad.push('a network other than none must be a hullproof internal network');
  if (bad.length) throw new Error(`unsafe container arguments refused: ${bad.join(', ')}`);
}

const healthScript = (port: number, path: string): string => `fetch('http://127.0.0.1:${port}${path}',{signal:AbortSignal.timeout(2000)}).then(r=>process.exit(r.status<500?0:2),()=>process.exit(1))`;

export class ContainerRunner implements Runner {
  readonly name = 'container';
  private readonly rt: ContainerRuntime;
  private readonly o: { sleepMs?: number };
  constructor(rt: ContainerRuntime, o: { sleepMs?: number } = {}) { this.rt = rt; this.o = o; }

  async available(): Promise<{ ok: true } | { ok: false; reason: string }> {
    const r = await this.rt.run(['info'], { timeoutMs: 20_000 });
    if (r.code === 0) return { ok: true };
    const missing = /not found|ENOENT/.test(r.stderr);
    return { ok: false, reason: missing ? `no container runtime: ${this.rt.bin} was not found. Install one, for example: brew install colima docker, then colima start.` : `the container runtime is not running (${clip(r.stderr, 160) || 'no answer'}). For Colima run: colima start.` };
  }

  async prepare(req: PrepareRequest): Promise<PrepareResult> {
    const runId = randomBytes(5).toString('hex');
    const image = `hullproof-prove-${runId}`;
    mkdirSync(join(req.copyDir, '.hullproof-exec'), { recursive: true });
    for (const f of EXEC_FILES) copyFileSync(join(HERE, f), join(req.copyDir, '.hullproof-exec', f));
    writeFileSync(join(req.copyDir, 'Dockerfile.hullproof'), dockerfile(req.recipe));
    const b = await this.rt.run(buildArgs(image, runId, req.copyDir), { timeoutMs: 600_000 });
    if (b.code !== 0) { await this.rt.run(['rmi', '-f', image]); return { ok: false, code: 'build_failed', reason: `the image did not build${b.timedOut ? ' in time' : ''}: ${clip(b.stderr || b.stdout)}` }; }
    return { ok: true, prepared: new ContainerPrepared(this.rt, runId, image, req, this.o.sleepMs ?? 500) };
  }
}

class ContainerPrepared implements Prepared {
  private n = 0;
  private readonly live = new Set<ContainerInstance>();
  private readonly rt: ContainerRuntime;
  private readonly runId: string;
  private readonly image: string;
  private readonly req: PrepareRequest;
  private readonly pause: number;
  constructor(rt: ContainerRuntime, runId: string, image: string, req: PrepareRequest, pause: number) { this.rt = rt; this.runId = runId; this.image = image; this.req = req; this.pause = pause; }

  async start(): Promise<StartResult> {
    const { recipe, limits } = this.req;
    const id = `${this.runId}-${++this.n}`;
    const name = `hp-prove-${id}`;
    const inst = new ContainerInstance(this.rt, name, recipe, limits);
    this.live.add(inst);
    const fail = async (code: 'start_failed' | 'health_failed' | 'build_failed', reason: string): Promise<StartResult> => { const logs = await this.rt.run(['logs', '--tail', '15', name]); await inst.stop(); this.live.delete(inst); return { ok: false, code, reason: `${reason}${logs.stdout + logs.stderr ? `. Last output: ${clip(logs.stdout + ' ' + logs.stderr, 400)}` : ''}` }; };
    const data = (s: string): string => s.replace(/\{DATA\}/g, '/data');
    let network = 'none';
    const env: Record<string, string> = {};
    const tmpfs = ['/tmp:rw,noexec,nosuid,nodev,size=64m'];
    if (recipe.data_store.kind === 'sqlite') tmpfs.push(`/data:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001`);
    if (recipe.data_store.kind === 'postgres') {
      network = `hp-prove-net-${id}`;
      const pg = `hp-prove-pg-${id}`;
      const net = await this.rt.run(['network', 'create', '--internal', '--label', `${LABEL}=${this.runId}`, network]);
      if (net.code !== 0) { this.live.delete(inst); return { ok: false, code: 'start_failed', reason: `the internal network could not be created: ${clip(net.stderr)}` }; }
      inst.network = network;
      inst.extra.push(pg);
      const pgRun = await this.rt.run(runArgs({ name: pg, runId: this.runId, image: PG_IMAGE, network, user: PG_USER, tmpfs: ['/var/lib/postgresql/data:rw,nosuid,nodev,size=128m,uid=70,gid=70', '/var/run/postgresql:rw,nosuid,nodev,size=8m,uid=70,gid=70', '/tmp:rw,nosuid,nodev,size=32m'], env: { POSTGRES_PASSWORD: 'dummy', POSTGRES_DB: 'app' }, limits, cmd: [] }));
      if (pgRun.code !== 0) return fail('start_failed', `Postgres did not start: ${clip(pgRun.stderr)}`);
      let up = false;
      for (let t = Date.now(); Date.now() - t < limits.healthMs && !up; await this.sleep()) up = (await this.rt.run(['exec', pg, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'app'], { timeoutMs: 5000 })).code === 0;
      if (!up) return fail('health_failed', 'Postgres did not become ready in time');
      for (const f of [...recipe.data_store.migrations, ...(recipe.data_store.seed_sql ? [recipe.data_store.seed_sql] : [])]) {
        const sql = readFileSync(join(this.req.sourceDir, f), 'utf8');
        const r = await this.rt.run(['exec', '-i', pg, 'psql', '-v', 'ON_ERROR_STOP=1', '-q', '-U', 'postgres', '-d', 'app'], { input: sql, timeoutMs: 60_000 });
        if (r.code !== 0) return fail('start_failed', `${f} did not apply: ${clip(r.stderr, 300)}`);
      }
      env.__PGURL = `postgres://postgres:dummy@${pg}:5432/app`;
    }
    for (const [k, v] of Object.entries(recipe.env)) env[k] = data(v).replace(/\{PGURL\}/g, env.__PGURL ?? '');
    delete env.__PGURL;
    const script = `${recipe.seed ? recipe.seed + ' && ' : ''}exec ${recipe.start}`;
    const run = await this.rt.run(runArgs({ name, runId: this.runId, image: this.image, network, user: APP_USER, tmpfs, env, limits, cmd: ['sh', '-c', script] }));
    if (run.code !== 0) return fail('start_failed', `the container did not start: ${clip(run.stderr)}`);
    for (let t = Date.now(); Date.now() - t < limits.healthMs; await this.sleep()) {
      const h = await this.rt.run(['exec', name, 'node', '-e', healthScript(recipe.port, recipe.health_path)], { timeoutMs: 6000 });
      if (h.code === 0) { inst.arm(); return { ok: true, instance: inst }; }
      const st = await this.rt.run(['inspect', '--format', '{{.State.Running}}', name]);
      if (st.stdout.trim() === 'false') return fail('start_failed', 'the app stopped before it answered (the seed step or the start command failed)');
    }
    return fail('health_failed', `the app did not answer on ${recipe.health_path} within ${Math.round(limits.healthMs / 1000)} seconds`);
  }
  private sleep(): Promise<void> { return sleep(this.pause); }

  async dispose(): Promise<Teardown> {
    for (const i of this.live) await i.stop();
    await this.rt.run(['rmi', '-f', this.image]);
    const left: string[] = [];
    for (const [what, args] of [['container', ['ps', '-a', '-q']], ['image', ['images', '-q']], ['network', ['network', 'ls', '-q']], ['volume', ['volume', 'ls', '-q']]] as const) {
      const r = await this.rt.run([...args, '--filter', `label=${LABEL}=${this.runId}`]);
      for (const l of r.stdout.split('\n').map((x) => x.trim()).filter(Boolean)) left.push(`${what} ${l}`);
    }
    return { left_behind: left };
  }
}

class ContainerInstance implements Instance {
  readonly baseUrl: string;
  network: string | null = null;
  readonly extra: string[] = [];
  private stopped = false;
  private timer: NodeJS.Timeout | null = null;
  private readonly rt: ContainerRuntime;
  private readonly name: string;
  private readonly recipe: Recipe;
  private readonly limits: Limits;
  constructor(rt: ContainerRuntime, name: string, recipe: Recipe, limits: Limits) {
    this.rt = rt; this.name = name; this.recipe = recipe; this.limits = limits;
    this.baseUrl = `http://127.0.0.1:${recipe.port}`;
  }
  arm(): void { this.timer = setTimeout(() => { void this.stop(); }, this.limits.instanceMs); this.timer.unref(); }

  async exec(cmd: string[], o: { input?: string; timeoutMs?: number } = {}): Promise<Exec> {
    if (this.stopped) return { code: null, stdout: '', stderr: 'the instance time limit was reached or it was stopped', timedOut: false };
    const ms = o.timeoutMs ?? this.limits.execMs;
    // `timeout -s KILL` inside the container ends the process there. Killing the docker client alone would leave it running.
    return this.rt.run(['exec', '-i', this.name, 'timeout', '-s', 'KILL', String(Math.max(1, Math.ceil(ms / 1000))), ...cmd], { input: o.input, timeoutMs: ms + 10_000 });
  }

  async runSpec(spec: import('../types/index.ts').Spec): Promise<SpecRun> {
    assertSandboxTarget(this.baseUrl, this.recipe.port);
    const r = await this.exec(['node', '--experimental-strip-types', `${EXEC_DIR}/exec-main.ts`, this.baseUrl], { input: JSON.stringify(spec) });
    if (r.timedOut || r.code === 137) return { ok: false, reason: 'the step executor ran past the time limit and was killed' };
    const line = r.stdout.trim().split('\n').pop() ?? '';
    try {
      const j = JSON.parse(line) as { ok: boolean; error?: string; outcome?: SpecRun extends { ok: true; outcome: infer O } ? O : never; detail?: string; steps?: import('../types/index.ts').StepRecord[] };
      if (!j.ok) return { ok: false, reason: j.error ?? 'the step executor failed' };
      return { ok: true, outcome: j.outcome!, detail: j.detail ?? '', steps: j.steps ?? [] };
    } catch { return { ok: false, reason: `the step executor gave no result (${clip(r.stderr, 200) || 'no output'})` }; }
  }

  async stop(): Promise<Teardown> {
    if (this.timer) clearTimeout(this.timer);
    this.stopped = true;
    for (const c of [this.name, ...this.extra]) await this.rt.run(['rm', '-f', '--volumes', c]);
    if (this.network) await this.rt.run(['network', 'rm', this.network]);
    return { left_behind: [] };
  }
}
