import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const r = db.prepare('DELETE FROM notes WHERE id = ? AND owner_id = ?').run(params.id, user.id);
  return r.changes ? NextResponse.json({ ok: true }) : NextResponse.json({ error: 'not found' }, { status: 404 });
}
