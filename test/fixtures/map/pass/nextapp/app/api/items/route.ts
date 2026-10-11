import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

export async function GET(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const limit = Math.min(Number(new URL(req.url).searchParams.get('limit') ?? 50), 100);
  const rows = db.prepare('SELECT id, name FROM items WHERE owner_id = ? LIMIT ?').all(user.id, limit);
  return NextResponse.json(rows);
}
