import { db } from '../../lib/db';

export async function POST(request: Request) {
  const body = await request.json();
  await db.insert('notes', { title: body.title, owner_id: body.owner });
  return Response.json({ ok: true });
}
