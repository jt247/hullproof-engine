// The stdio loop of `hullproof mcp`. One JSON-RPC message per line on stdin, one per line on stdout, nothing else on stdout. Logs go to
// stderr. Messages are handled one at a time, in order. A line longer than MAX_LINE is answered with an error and dropped. The server
// exits when stdin closes.
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import { handle, newState, parseLine, type Response, ERR } from './protocol.ts';
import type { ToolHost } from './protocol.ts';

export const MAX_LINE = 1_048_576;

export async function serve(input: Readable, output: Writable, host: ToolHost): Promise<void> {
  const state = newState();
  const send = (r: Response): void => { output.write(JSON.stringify(r) + '\n'); };
  const rl = createInterface({ input, crlfDelay: Infinity });
  let queue = Promise.resolve();
  for await (const line of rl) {
    queue = queue.then(async () => {
      if (line.trim() === '') return;
      if (line.length > MAX_LINE) { send({ jsonrpc: '2.0', id: null, error: { code: ERR.invalidRequest, message: `Invalid Request: the message is longer than ${MAX_LINE} characters` } }); return; }
      const p = parseLine(line);
      if ('error' in p) { send(p.error); return; }
      try {
        const r = await handle(p.msg, state, host);
        if (r) send(r);
      } catch (e) {
        const id = (p.msg as { id?: unknown }).id;
        send({ jsonrpc: '2.0', id: typeof id === 'string' || typeof id === 'number' ? id : null, error: { code: ERR.internal, message: `Internal error: ${(e as Error).message.slice(0, 200)}` } });
      }
    });
  }
  await queue;
}
