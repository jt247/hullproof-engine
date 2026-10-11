// Fixture for rules/semgrep/taint-javascript.yaml (Next.js and TypeScript Node). Written for the Hullproof Engine.
// Each "ruleid" line must match and each "ok" line must not, checked by semgrep --test in test/rules.test.ts.
import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';

const pool = new Pool();
declare const prisma: any;
declare function sql(strings: TemplateStringsArray, ...values: unknown[]): unknown;

// ---- SQL injection, CWE-89 ----

export async function GET(request: NextRequest) {
  const id = request.nextUrl.searchParams.get('id');
  // ruleid: hullproof-taint-js-sql-injection
  const a = await pool.query(`SELECT * FROM orders WHERE id = '${id}'`);
  // ok: hullproof-taint-js-sql-injection
  const b = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
  // ruleid: hullproof-taint-js-sql-injection
  const c = await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${id}'`);
  // ok: hullproof-taint-js-sql-injection
  const d = await pool.query(sql`SELECT * FROM orders WHERE id = ${id}`);
  return NextResponse.json({ a, b, c, d });
}

// ---- XSS, CWE-79 ----

export async function POST(request: Request) {
  const body = await request.json();
  // ruleid: hullproof-taint-js-xss
  return new Response('<p>' + body.name + '</p>', { status: 200, headers: { 'Content-Type': 'text/html' } });
}

export async function OPTIONS(request: Request) {
  const body = await request.json();
  // ok: hullproof-taint-js-xss
  return new Response(JSON.stringify({ name: body.name }), { headers: { 'Content-Type': 'application/json' } });
}

export default function Page({ searchParams }: { searchParams: { q: string } }) {
  // ok: hullproof-taint-js-xss
  const text = <p>{searchParams.q}</p>;
  // ruleid: hullproof-taint-js-xss
  const raw = <div dangerouslySetInnerHTML={{ __html: searchParams.q }} />;
  return <div>{text}{raw}</div>;
}

// ---- Command injection, CWE-78 ----

export async function PUT(request: NextRequest) {
  const { branch } = await request.json();
  // ruleid: hullproof-taint-js-command-injection
  exec(`git checkout ${branch}`);
  // ok: hullproof-taint-js-command-injection
  exec('git status');
  return NextResponse.json({ ok: true });
}

// ---- Path traversal, CWE-22 ----

export async function PATCH(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('doc') ?? '';
  // ruleid: hullproof-taint-js-path-traversal
  const text = await readFile('/srv/docs/' + name, 'utf8');
  // ok: hullproof-taint-js-path-traversal
  const fixed = await readFile('/srv/docs/index.md', 'utf8');
  return NextResponse.json({ text, fixed });
}

// ---- SSRF, CWE-918 ----

export async function DELETE(request: NextRequest) {
  const target = request.nextUrl.searchParams.get('url') ?? '';
  // ruleid: hullproof-taint-js-ssrf
  const r = await fetch(target);
  // ok: hullproof-taint-js-ssrf
  const s = await fetch(`https://api.example.com/lookup/${encodeURIComponent(target)}`);
  return NextResponse.json({ r: r.status, s: s.status });
}
