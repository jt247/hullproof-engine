import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const body = await req.json();
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(body.role, body.id);
  return NextResponse.json({ ok: true });
}
