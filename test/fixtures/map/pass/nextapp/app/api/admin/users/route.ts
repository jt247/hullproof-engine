import { NextResponse } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';
import { auditLog } from '@/lib/audit';

const SetRole = z.object({ id: z.string(), role: z.enum(['member', 'admin']) });

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  if (user.role !== 'admin') return NextResponse.json({ error: 'forbidden' }, { status: 403 });
  const parsed = SetRole.safeParse(await req.json());
  if (!parsed.success) return NextResponse.json({ error: 'bad' }, { status: 400 });
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(parsed.data.role, parsed.data.id);
  auditLog({ actor: user.id, action: 'set_role', target: parsed.data.id });
  return NextResponse.json({ ok: true });
}
