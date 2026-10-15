// Shared by the proof sandbox tests: a fake HTTP app, a fake container runtime that records every command, and small spec builders.
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Spec, SpecStep } from '../../src/types/index.ts';
import type { ContainerRuntime } from '../../src/prove/container.ts';
import { executeSpec } from '../../src/prove/executor.ts';
import type { Exec } from '../../src/prove/runner.ts';
import { validateSpec } from '../../src/prove/spec.ts';

// A tiny notes API with the same planted flaw as the fixture, switchable. Tokens are random on purpose.
export async function fakeApp(mode: 'vulnerable' | 'fixed' = 'vulnerable'): Promise<{ port: number; close(): Promise<void>; hits: string[] }> {
  const notes = new Map([[1, { id: 1, owner: 'alice', body: 'CANARY-ALICE-1' }], [2, { id: 2, owner: 'bob', body: 'CANARY-BOB-1' }]]);
  const tokens = new Map<string, string>();
  const hits: string[] = [];
  const server: Server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const send = (n: number, o: unknown): void => { res.statusCode = n; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
      const body = raw ? JSON.parse(raw) as Record<string, string> : {};
      const user = tokens.get(String(req.headers.authorization ?? '').replace('Bearer ', ''));
      if (req.url === '/health') return send(200, { ok: true });
      if (req.method === 'POST' && req.url === '/api/login') {
        if (!['alice', 'bob'].includes(body.user) || body.password !== `${body.user}-pass`) return send(401, { error: 'no' });
        const token = [...Array(24)].map(() => Math.floor(Math.random() * 16).toString(16)).join('') + 'abcdef0123456789';
        tokens.set(token, body.user);
        return send(200, { token, user: body.user });
      }
      const m = /^\/api\/notes\/(\d+)$/.exec(req.url ?? '');
      if (req.method === 'GET' && m) {
        if (!user) return send(401, { error: 'sign in' });
        const n = notes.get(Number(m[1]));
        if (!n || (mode === 'fixed' && n.owner !== user)) return send(404, { error: 'not found' });
        return send(200, n);
      }
      send(404, { error: 'not found' });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { port: (server.address() as AddressInfo).port, hits, close: () => new Promise((r) => { server.close(() => r()); server.closeAllConnections(); }) };
}

const login = (who: string): SpecStep => ({ id: `login_${who}`, phase: 'setup', actor: 'anon', method: 'POST', path: '/api/login', body: { user: who, password: `${who}-pass` }, captures: [{ name: `${who}_token`, from: 'json', path: 'token' }], assert: [{ kind: 'status', op: 'eq', value: 200 }] });

export function idorSpec(over: Partial<Spec> = {}): Spec {
  return {
    schema_version: '1.0.0', spec_id: 'idor_read', title: 'bob reads the note of alice', claim: 'A signed in user can read the note of another user by id.', lead_key: null,
    target: { entry_point: 'server.js:10:http_route:GET:/api/notes/:id:-', file: 'server.js', line: 11 }, requirement_ids: ['SEC-AUTHZ-003'],
    actors: { anon: {}, alice: { headers: { authorization: 'Bearer {{alice_token}}' } }, bob: { headers: { authorization: 'Bearer {{bob_token}}' } } },
    steps: [login('alice'), login('bob'),
      { id: 'own', phase: 'control', actor: 'alice', method: 'GET', path: '/api/notes/1', assert: [{ kind: 'status', op: 'eq', value: 200 }, { kind: 'json', path: 'body', op: 'eq', value: 'CANARY-ALICE-1' }] },
      { id: 'other', phase: 'attack', actor: 'bob', method: 'GET', path: '/api/notes/1', assert: [{ kind: 'status', op: 'eq', value: 200 }, { kind: 'json', path: 'body', op: 'eq', value: 'CANARY-ALICE-1' }] }],
    expect: { outcome: 'flaw_present' }, ...over,
  };
}
export const asValid = (s: unknown): Spec => { const v = validateSpec(s); if (!v.ok) throw new Error(v.errors.join('; ')); return v.spec; };

export interface FakeScript { infoOk?: boolean; buildOk?: boolean; runOk?: boolean; healthAfter?: number; appPort?: number; leftovers?: Record<string, string[]>; notRunningAfterRun?: boolean }
export class FakeRuntime implements ContainerRuntime {
  readonly bin = 'fake-docker';
  readonly calls: string[][] = [];
  readonly inputs: string[] = [];
  private health = 0;
  readonly script: FakeScript;
  constructor(script: FakeScript = {}) { this.script = script; }
  private ok(stdout = ''): Exec { return { code: 0, stdout, stderr: '', timedOut: false }; }
  async run(args: string[], o: { input?: string } = {}): Promise<Exec> {
    this.calls.push(args);
    if (o.input !== undefined) this.inputs.push(o.input);
    const s = this.script;
    const [cmd] = args;
    if (cmd === 'info') return s.infoOk === false ? { code: 1, stdout: '', stderr: 'Cannot connect to the Docker daemon', timedOut: false } : this.ok('ok');
    if (cmd === 'build') return s.buildOk === false ? { code: 1, stdout: '', stderr: 'npm ERR! 404 not found', timedOut: false } : this.ok();
    if (cmd === 'run') return s.runOk === false ? { code: 125, stdout: '', stderr: 'docker: Error response from daemon', timedOut: false } : this.ok('containerid');
    if (cmd === 'inspect') return this.ok(s.notRunningAfterRun ? 'false' : 'true');
    if (cmd === 'logs') return this.ok('Error: listen EADDRINUSE');
    if (cmd === 'exec') {
      if (args.includes('exec-main.ts') || args.some((a) => a.endsWith('exec-main.ts'))) {
        const url = args[args.length - 1];
        const v = validateSpec(JSON.parse(o.input ?? '{}'));
        if (!v.ok) return this.ok(JSON.stringify({ ok: false, error: 'invalid spec' }) + '\n');
        const r = await executeSpec(v.spec, { baseUrl: url.replace(/:\d+$/, `:${s.appPort}`) });
        return this.ok(JSON.stringify({ ok: true, ...r }) + '\n');
      }
      if (args.some((a) => a.startsWith('fetch('))) { this.health++; return { code: this.health > (s.healthAfter ?? 0) ? 0 : 1, stdout: '', stderr: '', timedOut: false }; }
      return this.ok();
    }
    if (cmd === 'ps' || cmd === 'images' || cmd === 'network' || cmd === 'volume') {
      const kind = cmd === 'ps' ? 'container' : cmd === 'images' ? 'image' : cmd === 'network' ? 'network' : 'volume';
      if (cmd === 'network' && args[1] !== 'ls') return this.ok();
      return this.ok((s.leftovers?.[kind] ?? []).join('\n'));
    }
    return this.ok();
  }
  find(cmd: string): string[][] { return this.calls.filter((c) => c[0] === cmd); }
}
