import { NextResponse } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

const Create = z.object({ title: z.string().min(1).max(200) });

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const parsed = Create.safeParse(await req.json());
  if (!parsed.success) return NextResponse.json({ error: 'bad' }, { status: 400 });
  db.prepare('INSERT INTO notes (title, owner_id) VALUES (?, ?)').run(parsed.data.title, user.id);
  return NextResponse.json({ ok: true });
}
