import { NextResponse } from 'next/server';
import { signIn } from '@/lib/auth';

export async function POST(req: Request) {
  const { email, password, next } = await req.json();
  const ok = await signIn(email, password);
  if (!ok) return NextResponse.json({ error: 'wrong' }, { status: 401 });
  return NextResponse.json({ ok: true, redirect: next ?? '/dashboard' });
}
