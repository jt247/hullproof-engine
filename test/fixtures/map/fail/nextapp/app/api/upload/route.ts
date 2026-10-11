import { NextResponse } from 'next/server';
import { writeFile } from 'node:fs/promises';
import { currentUser } from '@/lib/session';

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const form = await req.formData();
  const file = form.get('file') as File;
  await writeFile(`uploads/${user.id}-${file.name}`, Buffer.from(await file.arrayBuffer()));
  return NextResponse.json({ ok: true });
}
