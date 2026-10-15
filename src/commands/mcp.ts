// hullproof mcp: the MCP server over stdio. Read tools always; run_scan only with --allow-run.
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { HullproofTools } from '../mcp/tools.ts';
import { serve } from '../mcp/server.ts';
import type { Edition } from '../report/kit.ts';

export interface McpOptions { repo: string; kit: string | null; edition: Edition | null; allowRun: boolean; log?: (s: string) => void }

export async function mcpCommand(o: McpOptions): Promise<number> {
  const log = o.log ?? ((s: string) => process.stderr.write(s + '\n'));
  const repo = resolve(o.repo);
  if (!existsSync(repo)) { log(`hullproof mcp: ${repo} does not exist`); return 2; }
  const tools = new HullproofTools({ repo, kit: o.kit, edition: o.edition, allowRun: o.allowRun, log });
  log(`hullproof mcp: serving ${repo} on stdio (run_scan ${o.allowRun ? 'on' : 'off'})`);
  await serve(process.stdin, process.stdout, tools);
  return 0;
}
