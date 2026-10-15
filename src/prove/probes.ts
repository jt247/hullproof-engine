// Escape attempts. Each probe is a short script run inside a started sandbox instance with the same limits as the app. The sandbox
// has held when every probe reports ok. They are the exit test of step 4a and `hullproof prove --self-test` runs them on demand.
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Recipe } from '../types/index.ts';
import type { Instance } from './runner.ts';

export interface ProbeResult { name: string; ok: boolean; detail: string }

const NET = `
const net=require('net'),dns=require('dns');
const conn=(h,p)=>new Promise(r=>{const s=net.connect({host:h,port:p,timeout:3000});s.on('connect',()=>{s.destroy();r(true)});s.on('error',()=>r(false));s.on('timeout',()=>{s.destroy();r(false)})});
(async()=>{const o={};o.tcp_cloudflare=await conn('1.1.1.1',443);o.tcp_google=await conn('8.8.8.8',53);o.dns=await new Promise(r=>dns.lookup('example.com',e=>r(!e)));
o.fetch=await fetch('http://example.com',{signal:AbortSignal.timeout(3000)}).then(()=>true,()=>false);console.log(JSON.stringify(o));})()`;
const FILES = `
const fs=require('fs');const out={};
for(const p of [process.argv[1],'/Users','/host','/mnt/host','/var/run/docker.sock','/run/docker.sock','/root/.ssh']){try{fs.readFileSync(p);out[p]='READ';}catch(e){try{const l=fs.readdirSync(p);out[p]='LISTED:'+l.length;}catch(e2){out[p]=e2.code;}}}
console.log(JSON.stringify(out))`;
const WRITES = `
const fs=require('fs');const out={};
for(const p of ['/app/hp_probe','/etc/hp_probe','/usr/hp_probe','/hp_probe','/tmp/hp_probe']){try{fs.writeFileSync(p,'x');out[p]='WROTE';}catch(e){out[p]=e.code;}}
out.uid=process.getuid();console.log(JSON.stringify(out))`;
const FORK = `
const {spawn}=require('child_process'),fs=require('fs');let refused=0,peak=0;const kids=[];
const rd=(f)=>{try{return fs.readFileSync(f,'utf8').trim()}catch{return null}};
const cur=()=>Number(rd('/sys/fs/cgroup/pids.current')||rd('/sys/fs/cgroup/pids/pids.current')||0);
const max=rd('/sys/fs/cgroup/pids.max')||rd('/sys/fs/cgroup/pids/pids.max');
const go=async()=>{for(let i=0;i<400;i++){const k=spawn(process.execPath,['-e','setTimeout(()=>{},60000)'],{stdio:'ignore'});k.on('error',()=>refused++);kids.push(k);peak=Math.max(peak,cur());await new Promise(r=>setTimeout(r,8));}
await new Promise(r=>setTimeout(r,800));console.log(JSON.stringify({attempted:400,refused,peak_processes:peak,limit:max}));kids.forEach(k=>{try{k.kill('SIGKILL')}catch{}});process.exit(0);};go()`;
const MEM = `const a=[];try{for(let i=0;i<64;i++)a.push(Buffer.alloc(64*1024*1024,1));console.log('ALLOCATED');}catch(e){console.log('REFUSED');}`;

const j = (s: string): Record<string, unknown> => { try { return JSON.parse(s.trim().split('\n').pop() ?? '{}') as Record<string, unknown>; } catch { return {}; } };

export async function runEscapeProbes(inst: Instance, hostMarker: string): Promise<ProbeResult[]> {
  const out: ProbeResult[] = [];
  const net = j((await inst.exec(['node', '-e', NET], { timeoutMs: 30_000 })).stdout);
  out.push({ name: 'network call to the internet', ok: Object.keys(net).length === 4 && Object.values(net).every((v) => v === false), detail: JSON.stringify(net) });
  const files = j((await inst.exec(['node', '-e', FILES, hostMarker], { timeoutMs: 15_000 })).stdout);
  out.push({ name: 'host file read', ok: Object.keys(files).length > 0 && Object.values(files).every((v) => v === 'ENOENT' || v === 'EACCES'), detail: JSON.stringify(files) });
  const w = j((await inst.exec(['node', '-e', WRITES], { timeoutMs: 15_000 })).stdout);
  const ro = ['/app/hp_probe', '/etc/hp_probe', '/usr/hp_probe', '/hp_probe'].every((p) => w[p] === 'EROFS' || w[p] === 'EACCES');
  out.push({ name: 'write to the root filesystem, and run as root', ok: ro && typeof w.uid === 'number' && w.uid !== 0, detail: JSON.stringify(w) });
  const fork = j((await inst.exec(['node', '-e', FORK], { timeoutMs: 40_000 })).stdout);
  const alive = (await inst.exec(['node', '-e', 'console.log(1)'], { timeoutMs: 15_000 })).code === 0;
  out.push({ name: 'fork bomb', ok: typeof fork.peak_processes === 'number' && fork.peak_processes > 0 && fork.peak_processes <= Number(fork.limit) && alive, detail: `${JSON.stringify(fork)}; sandbox still answers: ${alive}` });
  const t0 = Date.now();
  const loop = await inst.exec(['node', '-e', 'while(true){}'], { timeoutMs: 3000 });
  const after = (await inst.exec(['node', '-e', 'console.log(1)'], { timeoutMs: 15_000 })).code === 0;
  out.push({ name: 'long loop', ok: (loop.timedOut || loop.code === 137) && Date.now() - t0 < 30_000 && after, detail: `ended after ${Date.now() - t0} ms with code ${loop.code}; sandbox still answers: ${after}` });
  const mem = await inst.exec(['node', '-e', MEM], { timeoutMs: 30_000 });
  out.push({ name: 'memory limit', ok: !mem.stdout.includes('ALLOCATED') && (await inst.exec(['node', '-e', 'console.log(1)'], { timeoutMs: 15_000 })).code === 0, detail: `exit code ${mem.code}` });
  return out;
}

// A small app and a recipe for `hullproof prove --self-test`: it needs nothing installed and reads nothing from the user's repository.
export function selfTestApp(): { dir: string; recipe: Recipe; marker: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), 'hp-selftest-'));
  const outside = mkdtempSync(join(tmpdir(), 'hp-marker-'));
  const marker = join(outside, `secret-${randomBytes(4).toString('hex')}.txt`);
  writeFileSync(marker, 'HOST-SECRET-MARKER');
  mkdirSync(join(dir, 'app'), { recursive: true });
  writeFileSync(join(dir, 'server.js'), "require('http').createServer((q,s)=>{s.setHeader('content-type','application/json');s.end(JSON.stringify({ok:true}))}).listen(3000);\n");
  writeFileSync(join(dir, 'package.json'), '{"name":"hp-selftest","version":"0.0.0","main":"server.js"}\n');
  const recipe: Recipe = { schema_version: '1.0.0', stack: 'node-express', base_image: 'node:22-slim', install: null, vendored_modules: false, seed: null, start: 'node server.js', port: 3000, port_from_env: false, health_path: '/', data_store: { kind: 'none' }, env: {}, notes: [] };
  return { dir, recipe, marker, cleanup: () => { rmSync(dir, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); } };
}
