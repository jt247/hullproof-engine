// MCP conformance tests for the message layer of `hullproof mcp`: initialize, tools/list, tools/call, errors and malformed input,
// for the legacy handshake (2025-11-25 and earlier) and the modern stateless form (2026-07-28). The server core is driven in process
// with a stub tool host; the stdio process is tested at the end. Spec pages: see src/mcp/protocol.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { handle, INSTRUCTIONS, LEGACY_VERSIONS, MODERN_VERSION, newState, parseLine, SUPPORTED_VERSIONS, type ToolHost } from '../src/mcp/protocol.ts';
import { MAX_LINE, serve } from '../src/mcp/server.ts';

const host: ToolHost = {
  tools: () => [{ name: 'echo', title: 'Echo', description: 'Echo', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } }],
  call: async (name, args) => {
    if (args.boom) throw new Error('exploded');
    return { text: `echo ${JSON.stringify(args)}`, structured: { args }, isError: args.bad === true };
  },
};

// Sends lines through the real stdio loop and returns the parsed lines it wrote.
async function session(lines: string[]): Promise<any[]> {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  output.on('data', (c) => chunks.push(String(c)));
  const done = serve(input, output, host);
  for (const l of lines) input.write(l + '\n');
  input.end();
  await done;
  return chunks.join('').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}
const req = (id: unknown, method: string, params?: unknown): string => JSON.stringify({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
const META = { 'io.modelcontextprotocol/protocolVersion': MODERN_VERSION, 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': { name: 't', version: '1' } };
const INIT = (v: string) => req(1, 'initialize', { protocolVersion: v, capabilities: {}, clientInfo: { name: 't', version: '1' } });

test('legacy: initialize echoes every supported version and answers an unknown one with our latest', async () => {
  for (const v of LEGACY_VERSIONS) {
    const [r] = await session([INIT(v)]);
    assert.equal(r.id, 1);
    assert.equal(r.result.protocolVersion, v);
    assert.deepEqual(r.result.capabilities, { tools: { listChanged: false } });
    assert.equal(r.result.serverInfo.name, 'hullproof');
    assert.equal(r.result.instructions, INSTRUCTIONS);
  }
  const [odd] = await session([INIT('1999-01-01')]);
  assert.equal(odd.result.protocolVersion, LEGACY_VERSIONS[0]);
});

test('legacy: initialize needs protocolVersion, capabilities and clientInfo', async () => {
  const bad = [{ capabilities: {}, clientInfo: {} }, { protocolVersion: '2025-11-25', clientInfo: {} }, { protocolVersion: '2025-11-25', capabilities: {} }, { protocolVersion: 5, capabilities: {}, clientInfo: {} }];
  for (const p of bad) {
    const [r] = await session([req(1, 'initialize', p)]);
    assert.equal(r.error.code, -32602, JSON.stringify(p));
  }
});

test('legacy: nothing but ping works before initialize; after it tools/list and tools/call work', async () => {
  const out = await session([req(1, 'ping'), req(2, 'tools/list'), req(3, 'tools/call', { name: 'echo' }), INIT('2025-11-25'), JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }), req(4, 'tools/list'), req(5, 'tools/call', { name: 'echo', arguments: { a: 1 } })]);
  assert.deepEqual(out[0], { jsonrpc: '2.0', id: 1, result: {} });
  assert.equal(out[1].error.code, -32600);
  assert.match(out[1].error.message, /initialize/);
  assert.equal(out[2].error.code, -32600);
  assert.equal(out[3].result.protocolVersion, '2025-11-25');
  // the notification gets no answer, so the next line is the tools/list answer
  assert.equal(out[4].id, 4);
  assert.equal(out[4].result.tools[0].name, 'echo');
  assert.equal(out[4].result.resultType, undefined, 'legacy results carry no resultType');
  assert.deepEqual(out[5].result.content, [{ type: 'text', text: 'echo {"a":1}' }]);
  assert.equal(out[5].result.isError, false);
  assert.deepEqual(out[5].result.structuredContent, { args: { a: 1 } });
  assert.equal(out.length, 6);
});

test('modern: server/discover describes the server, and tools/list and tools/call need no handshake', async () => {
  const out = await session([req('d', 'server/discover', { _meta: META }), req(2, 'tools/list', { _meta: META }), req(3, 'tools/call', { name: 'echo', arguments: { x: 'y' }, _meta: META })]);
  const d = out[0].result;
  assert.equal(out[0].id, 'd');
  assert.equal(d.resultType, 'complete');
  assert.deepEqual(d.supportedVersions, SUPPORTED_VERSIONS);
  assert.ok(d.supportedVersions.includes('2026-07-28') && d.supportedVersions.includes('2025-11-25'));
  assert.deepEqual(d.capabilities, { tools: { listChanged: false } });
  assert.equal(d._meta['io.modelcontextprotocol/serverInfo'].name, 'hullproof');
  assert.equal(typeof d.ttlMs, 'number');
  assert.ok(['public', 'private'].includes(d.cacheScope));
  const l = out[1].result;
  assert.equal(l.resultType, 'complete');
  assert.equal(l.tools[0].name, 'echo');
  assert.equal(typeof l.ttlMs, 'number');
  assert.ok(['public', 'private'].includes(l.cacheScope));
  const c = out[2].result;
  assert.equal(c.resultType, 'complete');
  assert.equal(c.content[0].text, 'echo {"x":"y"}');
  assert.equal(c._meta['io.modelcontextprotocol/serverInfo'].version.length > 0, true);
});

test('modern: a missing required _meta field is -32602, an unsupported version is -32022 with the supported list', async () => {
  const noCaps = { 'io.modelcontextprotocol/protocolVersion': MODERN_VERSION };
  const [a] = await session([req(1, 'tools/list', { _meta: noCaps })]);
  assert.equal(a.error.code, -32602);
  const [b] = await session([req(2, 'tools/list', { _meta: { ...META, 'io.modelcontextprotocol/protocolVersion': '1900-01-01' } })]);
  assert.equal(b.error.code, -32022);
  assert.deepEqual(b.error.data, { supported: SUPPORTED_VERSIONS, requested: '1900-01-01' });
  const [c] = await session([req(3, 'tools/list', { _meta: { ...META, 'io.modelcontextprotocol/protocolVersion': 7 } })]);
  assert.equal(c.error.code, -32022);
  // A legacy version number in the modern field is not a modern request.
  const [d] = await session([req(4, 'tools/list', { _meta: { ...META, 'io.modelcontextprotocol/protocolVersion': '2025-11-25' } })]);
  assert.equal(d.error.code, -32022);
  // server/discover without _meta cannot be a modern probe: a legacy server style error, which tells the client to fall back to initialize.
  const [e] = await session([req(5, 'server/discover')]);
  assert.ok(e.error.code === -32600 && e.error.code !== -32022);
});

test('modern: methods the server does not have are -32601', async () => {
  const [r] = await session([req(1, 'resources/list', { _meta: META })]);
  assert.equal(r.error.code, -32601);
  const [p] = await session([INIT('2025-11-25')].concat(req(2, 'prompts/list')));
  assert.equal(p.result.protocolVersion, '2025-11-25');
});

test('errors: parse error, non objects, batches, bad envelopes, unknown methods and tools, bad params', async () => {
  const out = await session([
    '{not json', '"a string"', '5', '[{"jsonrpc":"2.0","id":1,"method":"ping"}]',
    JSON.stringify({ id: 1, method: 'ping' }),                                       // no jsonrpc
    JSON.stringify({ jsonrpc: '2.0', id: 2 }),                                       // no method
    JSON.stringify({ jsonrpc: '2.0', id: {}, method: 'ping' }),                      // bad id
    JSON.stringify({ jsonrpc: '2.0', id: null, method: 'ping' }),                    // null id on a request
    INIT('2025-11-25'),
    req(3, 'frobnicate'), req(4, 'tools/list', [1]), req(5, 'tools/call', { name: 7 }), req(6, 'tools/call', { name: 'nope' }), req(7, 'tools/call', { name: 'echo', arguments: [] }),
  ]);
  const codes = out.map((o) => o.error?.code);
  assert.deepEqual(codes.slice(0, 3), [-32700, -32600, -32600]);
  assert.equal(out[0].id, null);
  assert.equal(codes[3], -32600);            // batch
  assert.equal(codes[4], -32600);
  assert.equal(codes[5], -32600);
  assert.equal(codes[6], -32600);
  assert.equal(codes[7], -32600);
  assert.equal(out[8].result.protocolVersion, '2025-11-25');
  assert.deepEqual(codes.slice(9), [-32601, -32602, -32602, -32602, -32602]);
  assert.match(out[12].error.message, /Unknown tool: nope/);
});

test('a tool that throws is an isError result, not a protocol error; tool errors keep the session alive', async () => {
  const out = await session([INIT('2025-11-25'), req(2, 'tools/call', { name: 'echo', arguments: { boom: true } }), req(3, 'tools/call', { name: 'echo', arguments: { bad: true } }), req(4, 'ping')]);
  assert.equal(out[1].result.isError, true);
  assert.match(out[1].result.content[0].text, /exploded/);
  assert.equal(out[2].result.isError, true);
  assert.deepEqual(out[3], { jsonrpc: '2.0', id: 4, result: {} });
});

test('framing: blank lines are ignored, one line per answer, a line over the limit is refused and the server goes on', async () => {
  const long = '{"jsonrpc":"2.0","id":9,"method":"ping","params":{"pad":"' + 'x'.repeat(MAX_LINE) + '"}}';
  const out = await session(['', '   ', long, req(1, 'ping')]);
  assert.equal(out.length, 2);
  assert.equal(out[0].error.code, -32600);
  assert.equal(out[0].id, null);
  assert.deepEqual(out[1], { jsonrpc: '2.0', id: 1, result: {} });
  // Responses from the client are ignored, and string ids are echoed as strings.
  const o2 = await session([JSON.stringify({ jsonrpc: '2.0', id: 'x', result: {} }), req('abc', 'ping')]);
  assert.deepEqual(o2, [{ jsonrpc: '2.0', id: 'abc', result: {} }]);
});

test('parseLine and handle are pure: the same message gives the same answer', async () => {
  const p = parseLine(req(1, 'ping'));
  assert.ok('msg' in p);
  const a = await handle((p as { msg: unknown }).msg, newState(), host);
  const b = await handle((p as { msg: unknown }).msg, newState(), host);
  assert.deepEqual(a, b);
});

test('the process: only JSON-RPC on stdout, logs on stderr, and it exits 0 when stdin closes', async () => {
  const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
  const repo = fileURLToPath(new URL('./fixtures/scanners/app/', import.meta.url));
  const child = spawn(process.execPath, [cli, 'mcp', repo], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { err += c; });
  child.stdin.write(INIT('2025-11-25') + '\n' + req(2, 'tools/list') + '\n');
  child.stdin.end();
  const code: number = await new Promise((res) => child.on('close', res));
  assert.equal(code, 0);
  assert.match(err, /hullproof mcp: serving/);
  const lines = out.split('\n').filter(Boolean);
  assert.equal(lines.length, 2);
  for (const l of lines) assert.equal(JSON.parse(l).jsonrpc, '2.0');
  assert.deepEqual(JSON.parse(lines[1]).result.tools.map((t: { name: string }) => t.name),
    ['list_requirements', 'get_requirement', 'get_checklist', 'get_gate_verdict', 'get_findings', 'get_report', 'explain_finding']);
});
