import { z } from 'zod';
import { db } from '../../lib/db';
import { verifyToken } from '../../lib/auth';

const Body = z.object({ title: z.string().min(1).max(200) });

export async function POST(request: Request) {
  const user = await verifyToken(request.headers.get('authorization'));
  if (!user) return new Response('unauthorized', { status: 401 });
  const body = Body.parse(await request.json());
  await db.insert('notes', { title: body.title, owner_id: user.id });
  return Response.json({ ok: true });
}
