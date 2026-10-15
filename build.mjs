#!/usr/bin/env node
// Builds dist/: the compiled JavaScript the npm package runs. tsc emits it (no bundler, no runtime dependency), then the JSON data
// files that sit next to the sources are copied, and the entry file is made executable. dist/ mirrors src/ so every path the sources
// compute from import.meta.url (checks/, detectors/, rules/, schemas/) lands on the same folder in both.
import { chmodSync, cpSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./', import.meta.url));
const tsc = join(root, 'node_modules/typescript/bin/tsc');
rmSync(join(root, 'dist'), { recursive: true, force: true });
const r = spawnSync(process.execPath, [tsc, '-p', join(root, 'tsconfig.build.json')], { stdio: 'inherit', cwd: root });
if (r.status !== 0) process.exit(r.status ?? 1);
cpSync(join(root, 'src/mapping/maps'), join(root, 'dist/mapping/maps'), { recursive: true });
chmodSync(join(root, 'dist/cli.js'), 0o755);
process.stderr.write("hullproof build: wrote dist/\n");
