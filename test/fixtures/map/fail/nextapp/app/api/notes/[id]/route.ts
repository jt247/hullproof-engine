import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  db.prepare('DELETE FROM notes WHERE id = ?').run(params.id);
  return NextResponse.json({ ok: true });
}
