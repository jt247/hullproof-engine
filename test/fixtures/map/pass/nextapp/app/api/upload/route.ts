import { NextResponse } from 'next/server';
import { writeFile } from 'node:fs/promises';
import { currentUser } from '@/lib/session';

const MAX_BYTES = 5 * 1024 * 1024;
const ALLOWED_TYPES = ['image/png', 'image/jpeg'];

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const form = await req.formData();
  const file = form.get('file') as File;
  if (file.size > MAX_BYTES) return NextResponse.json({ error: 'too large' }, { status: 413 });
  if (!ALLOWED_TYPES.includes(file.type)) return NextResponse.json({ error: 'type not allowed' }, { status: 415 });
  await writeFile(`uploads/${crypto.randomUUID()}`, Buffer.from(await file.arrayBuffer()));
  return NextResponse.json({ ok: true });
}
