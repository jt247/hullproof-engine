import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

export async function GET() {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const rows = db.prepare('SELECT id, email FROM users WHERE id = ?').all(user.id);
  return NextResponse.json(rows);
}
