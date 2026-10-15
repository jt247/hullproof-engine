// Runs inside the sandbox: `node --experimental-strip-types /hp/exec-main.ts http://127.0.0.1:PORT` with a spec as JSON on standard
// input. Prints one JSON line: the outcome, the detail and the redacted step records. Refuses any address but the sandbox's own loopback.
import { executeSpec } from './executor.ts';
import { validateSpec } from './spec.ts';

const chunks: Buffer[] = [];
for await (const c of process.stdin) chunks.push(c as Buffer);
try {
  const v = validateSpec(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  if (!v.ok) { process.stdout.write(JSON.stringify({ ok: false, error: `invalid spec: ${v.errors.join('; ')}` }) + '\n'); process.exit(0); }
  const r = await executeSpec(v.spec, { baseUrl: process.argv[2] ?? '' });
  process.stdout.write(JSON.stringify({ ok: true, ...r }) + '\n');
} catch (e) {
  process.stdout.write(JSON.stringify({ ok: false, error: (e as Error).message.slice(0, 300) }) + '\n');
}
process.exit(0);
