import { NextResponse } from 'next/server';
import { currentUser } from '@/lib/session';

export async function POST(req: Request) {
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: 'sign in' }, { status: 401 });
  const { url } = await req.json();
  const page = await fetch(url);
  return NextResponse.json({ text: await page.text() });
}
