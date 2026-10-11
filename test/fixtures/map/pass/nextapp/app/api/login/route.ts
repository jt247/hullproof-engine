import { NextResponse } from 'next/server';
import { z } from 'zod';
import { signIn } from '@/lib/auth';
import { rateLimit } from '@/lib/rate-limit';

const Body = z.object({ email: z.string().email(), password: z.string().max(128), next: z.string().optional() });

export async function POST(req: Request) {
  const limited = await rateLimit(req, 'login');
  if (limited) return NextResponse.json({ error: 'slow down' }, { status: 429 });
  const { email, password, next } = Body.parse(await req.json());
  const ok = await signIn(email, password);
  if (!ok) return NextResponse.json({ error: 'wrong' }, { status: 401 });
  const target = next && next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard';
  return NextResponse.json({ ok: true, redirect: target });
}
