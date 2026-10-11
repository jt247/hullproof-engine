import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function POST(req: Request) {
  const body = await req.json();
  db.prepare('INSERT INTO notes (title, owner_id) VALUES (?, ?)').run(body.title, body.owner);
  return NextResponse.json({ ok: true });
}
