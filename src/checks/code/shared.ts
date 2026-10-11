// Shared helpers for the TypeScript checks: which files are server request handlers, and small text scanners.
import type { CheckContext } from '../context.ts';

// Server side request handlers across common stacks. Stack specific globs are marked by the framework they serve.
export const HANDLER_GLOBS = [
  '**/app/**/route.{ts,js,mjs,tsx,jsx}',            // Next.js App Router
  '**/pages/api/**/*.{ts,js,mjs}',                   // Next.js Pages Router
  '**/app/actions/**/*.{ts,js}',                     // Next.js Server Actions folder
  '**/api/**/*.{ts,js,mjs,py,go,php,rb}',            // Vercel and Netlify functions, generic api folders
  '**/routes/**/*.{ts,js,mjs,py,php,rb}',            // Express, Remix, SvelteKit, FastAPI routers, Laravel routes
  '**/routers/**/*.py', '**/views.py', '**/views/**/*.py', '**/app.py', '**/main.py', // Django, Flask, FastAPI
  '**/controllers/**/*.{ts,js,rb,php}', 'app/Http/Controllers/**/*.php', // Rails, Laravel, Nest, Adonis
  '**/*Controller.{java,kt,cs}',                     // Spring, ASP.NET
  '**/handlers/**/*.{go,ts,js}', '**/*handler*.go', // Go
  'supabase/functions/**/*.ts', 'netlify/functions/**/*.{ts,js}', 'functions/**/*.{ts,js,py}', // edge and cloud functions
  '**/server/**/*.{ts,js}', '**/hooks.server.{ts,js}', '**/+server.{ts,js}', '**/+page.server.{ts,js}',
];
export const NOT_HANDLER = ['**/*.test.*', '**/*.spec.*', '**/__tests__/**', '**/test/**', '**/tests/**', '**/*.d.ts'];

// Handler files, without browser only modules ("use client").
export function handlerFiles(ctx: CheckContext): string[] {
  return ctx.select(HANDLER_GLOBS, NOT_HANDLER).filter((f) => !/^\s*["']use client["']/.test(ctx.text(f)));
}

// The index just past the bracket that closes the one at `open`, or -1. Skips string literals and comments, roughly.
export function closeOf(text: string, open: number): number {
  const pair: Record<string, string> = { '(': ')', '{': '}', '[': ']' };
  const stack: string[] = [];
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++;
      continue;
    }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { const e = text.indexOf('*/', i + 2); i = e < 0 ? text.length : e + 1; continue; }
    if (pair[c]) stack.push(pair[c]);
    else if (c === stack[stack.length - 1]) { stack.pop(); if (stack.length === 0) return i + 1; }
  }
  return -1;
}

// The body of the `if` whose keyword starts at `at`: a braced block, an indented Python block, or the rest of the statement.
export function ifBody(text: string, at: number): string {
  const py = /^if\s+[^\n(]*:\s*(#.*)?$/m.exec(text.slice(at, text.indexOf('\n', at) < 0 ? text.length : text.indexOf('\n', at)));
  if (py) {
    const lineEnd = text.indexOf('\n', at);
    const lineStart = text.lastIndexOf('\n', at) + 1;
    const indent = /^\s*/.exec(text.slice(lineStart))![0].length;
    const rest = text.slice(lineEnd + 1).split('\n');
    const body: string[] = [];
    for (const l of rest) { if (l.trim() === '') continue; if (/^\s*/.exec(l)![0].length <= indent) break; body.push(l); }
    return text.slice(at, lineEnd) + '\n' + body.join('\n');
  }
  const paren = text.indexOf('(', at);
  const condEnd = paren < 0 ? -1 : closeOf(text, paren);
  if (condEnd < 0) return text.slice(at, at + 200);
  const after = text.slice(condEnd).search(/\S/);
  const start = condEnd + (after < 0 ? 0 : after);
  if (text[start] === '{') { const e = closeOf(text, start); return text.slice(at, e < 0 ? start + 400 : e); }
  const end = text.slice(start).search(/[;\n]/);
  return text.slice(at, end < 0 ? text.length : start + end + 1);
}

// A statement that stops the request: return, throw, raise, abort, or an explicit 4xx or 5xx response.
export const EXITS = /\b(return|throw|raise|abort|panic|exit|die)\b|\bstatus\(\s*[45]\d\d|\bhttp\.Error\b|res\.sendStatus\(\s*[45]/;
