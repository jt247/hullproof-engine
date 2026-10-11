import { NextResponse } from 'next/server';
import { z } from 'zod';
import { currentUser } from '@/lib/session';

const ALLOWED_HOSTS = new Set(['example.com', 'docs.example.com']);

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const { url } = z.object({ url: z.string().url() }).parse(await req.json());
  if (!ALLOWED_HOSTS.has(new URL(url).hostname)) return NextResponse.json({ error: 'host not allowed' }, { status: 400 });
  const page = await fetch(url);
  return NextResponse.json({ text: await page.text() });
}
